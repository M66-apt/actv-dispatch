/**
 * Angthong Cable TV — Cloudflare Pages Function
 * Handles all /api/* routes → D1 database (angthong-db)
 *
 * Auth: every request (except the public ones below) needs
 *       Authorization: Bearer <token>   (token comes from a login endpoint)
 *
 * Public:
 *   GET    /api/staff                      names for the login screen
 *   GET    /api/roles                      role names (perms only when signed in)
 *   POST   /api/staff/:id/login   { pin }  -> { token, user, perms, isDefault }
 *   POST   /api/auth/admin        { pin }  -> { token, user, perms }
 *   PUT    /api/staff/:id/pin     { oldPin, newPin }   (needs the old PIN)
 *
 * Signed in (permission in brackets):
 *   POST   /api/auth/logout
 *   GET    /api/jobs            [jobs.view]  (comm.* only → own jobs)
 *   POST   /api/jobs            [jobs.create]
 *   PUT    /api/jobs/:id        [jobs.edit] full · [jobs.upload] files · [jobs.verify] checks/status
 *   DELETE /api/jobs/:id        [jobs.delete]
 *   GET    /api/sales           [sales.view] (comm.* only → own sales)
 *   POST   /api/sales           [sales.create]
 *   PUT    /api/sales/:id       [sales.edit] full · [sales.upload] receipt only
 *   DELETE /api/sales/:id       [sales.delete]
 *   GET    /api/roles
 * Admin only:
 *   POST/PUT/DELETE /api/staff[/:id] · PUT /api/staff/:id/pin {reset:true,newPin}
 *   POST/PUT/DELETE /api/roles[/:id]
 *   PUT    /api/auth/admin-pin  { oldPin, newPin }
 *   GET    /api/logs?limit&offset&actor&entity&q&month
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function nowLocal() {
  return new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' }).replace(' ', 'T');
}

function safeJSON(str, fallback) {
  try { return JSON.parse(str); } catch { return fallback; }
}

// ════════════════════════════════════════════════════════════════
// PERMISSIONS
// ════════════════════════════════════════════════════════════════
const ALL_PERMS = [
  'jobs.view', 'jobs.create', 'jobs.edit', 'jobs.delete', 'jobs.upload', 'jobs.verify',
  'sales.view', 'sales.create', 'sales.edit', 'sales.delete', 'sales.upload',
  'comm.view', 'comm.all',
];
// Same as what non-admin staff could do before permissions existed
const DEFAULT_STAFF_PERMS = ['jobs.view', 'jobs.upload', 'jobs.verify', 'sales.view', 'sales.upload', 'comm.view', 'comm.all'];
const DEFAULT_ROLES = [
  ['technician', 'ช่างเทคนิค'],
  ['sale', 'พนักงานขาย'],
  ['lead', 'หัวหน้า'],
];
const SESSION_HOURS = 24;
const DEFAULT_PIN = '1234';

// ── Schema upgrades (run once per worker, safe to repeat) ─────────────────────
let colsReady = false;
async function ensureCols(env) {
  if (colsReady) return;
  const run = async (sql) => { try { await env.DB.prepare(sql).run(); } catch (e) { /* exists */ } };
  await run(`ALTER TABLE staff ADD COLUMN pin_hash TEXT`);
  await run(`ALTER TABLE jobs  ADD COLUMN receipt_at TEXT`);
  await run(`ALTER TABLE jobs  ADD COLUMN done_at TEXT`);
  await run(`ALTER TABLE sales ADD COLUMN receipt_at TEXT`);
  await run(`CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, label TEXT NOT NULL, perms TEXT DEFAULT '[]', sort INTEGER DEFAULT 0)`);
  await run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, staff_id TEXT, name TEXT, role TEXT, created_at TEXT, expires_at TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, actor TEXT, actor_role TEXT,
    action TEXT, entity TEXT, entity_id TEXT, label TEXT, changes TEXT, ip TEXT)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity, entity_id)`);
  // seed roles once
  const c = await env.DB.prepare(`SELECT COUNT(*) AS n FROM roles`).first();
  if (!c?.n) {
    for (const [i, [id, label]] of DEFAULT_ROLES.entries()) {
      await env.DB.prepare(`INSERT OR IGNORE INTO roles (id,label,perms,sort) VALUES (?,?,?,?)`)
        .bind(id, label, JSON.stringify(DEFAULT_STAFF_PERMS), i).run();
    }
  }
  // Backfill commission dates for rows that existed before these columns
  await env.DB.prepare(`UPDATE jobs SET receipt_at = substr(updated_at,1,10)
    WHERE receipt_at IS NULL AND COALESCE(receipt_data,'') <> ''`).run();
  await env.DB.prepare(`UPDATE jobs SET done_at = COALESCE(NULLIF(completion_date,''), substr(updated_at,1,10))
    WHERE done_at IS NULL AND status = 'done'`).run();
  await env.DB.prepare(`UPDATE sales SET receipt_at = substr(updated_at,1,10)
    WHERE receipt_at IS NULL AND COALESCE(receipt_data,'') <> ''`).run();
  colsReady = true;
}

// ── Sessions ──────────────────────────────────────────────────────────────────
function newToken() {
  const b = new Uint8Array(24); crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function createSession(env, { staffId = null, name, role }) {
  const token = newToken();
  const now = new Date();
  const exp = new Date(now.getTime() + SESSION_HOURS * 3600e3).toISOString();
  await env.DB.prepare(`INSERT INTO sessions (token,staff_id,name,role,created_at,expires_at) VALUES (?,?,?,?,?,?)`)
    .bind(token, staffId, name, role, now.toISOString(), exp).run();
  // housekeeping
  await env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(now.toISOString()).run();
  return token;
}
async function permsForRole(env, role) {
  if (role === 'admin') return new Set(ALL_PERMS);
  const r = await env.DB.prepare(`SELECT perms FROM roles WHERE id=?`).bind(role).first();
  return new Set(safeJSON(r?.perms, []).filter(p => ALL_PERMS.includes(p)));
}
async function getMe(request, env) {
  const h = request.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) return null;
  const s = await env.DB.prepare(`SELECT * FROM sessions WHERE token=?`).bind(token).first();
  if (!s || s.expires_at < new Date().toISOString()) return null;
  let name = s.name, role = s.role;
  if (s.staff_id) { // pick up renames / role changes immediately
    const st = await env.DB.prepare(`SELECT name, role FROM staff WHERE id=?`).bind(s.staff_id).first();
    if (!st) return null; // staff deleted → session dead
    name = st.name; role = st.role || 'technician';
  }
  const perms = await permsForRole(env, role);
  return { token, staffId: s.staff_id, name, role, isAdmin: role === 'admin', perms, can: p => perms.has(p) };
}
function deny(me, msg = 'ไม่มีสิทธิ์ทำรายการนี้') {
  return me ? json({ error: msg }, 403) : json({ error: 'กรุณาเข้าสู่ระบบ', auth: true }, 401);
}

// ── PIN helpers ───────────────────────────────────────────────────────────────
async function sha(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const hashPin = (id, pin) => sha(`actv:${id}:${pin}`);
async function checkPin(row, pin) {
  if (!row) return false;
  if (!row.pin_hash) return String(pin) === DEFAULT_PIN;
  return (await hashPin(row.id, String(pin))) === row.pin_hash;
}
// 5 wrong PINs in 15 minutes → locked for the rest of that window
async function tooManyFails(env, entityId) {
  const t = new Date(Date.now() - 15 * 60e3).toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' });
  const r = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE action='login_fail' AND entity_id=? AND at >= ?`)
    .bind(entityId, t).first();
  return (r?.n ?? 0) >= 5;
}

// ── Audit log ─────────────────────────────────────────────────────────────────
async function audit(env, request, me, action, entity, entityId, label, changes) {
  try {
    await env.DB.prepare(`INSERT INTO audit_log (at,actor,actor_role,action,entity,entity_id,label,changes,ip) VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(
        new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' }),
        me?.name ?? '—', me?.role ?? '', action, entity, entityId ?? '', label ?? '',
        changes ? JSON.stringify(changes) : null,
        request.headers.get('CF-Connecting-IP') || ''
      ).run();
  } catch (e) { console.error('audit failed', e); }
}
const FILE_FIELDS = new Set(['receiptData', 'jobFormData']);
function fileState(v) { return v ? 'มีไฟล์' : 'ไม่มีไฟล์'; }
// returns [{f, from, to}] for fields that changed
function diff(oldObj, newObj, fields) {
  const out = [];
  for (const f of fields) {
    let a = oldObj?.[f], b = newObj?.[f];
    if (FILE_FIELDS.has(f)) {
      if (!!a === !!b && (!a || a === b)) continue;
      out.push({ f, from: fileState(a), to: a && b && a !== b ? 'แนบไฟล์ใหม่' : fileState(b) });
      continue;
    }
    const norm = v => (v === null || v === undefined) ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
    if (norm(a) !== norm(b)) out.push({ f, from: a ?? '', to: b ?? '' });
  }
  return out;
}
function snapshot(obj, fields) {
  const o = {};
  for (const f of fields) o[f] = FILE_FIELDS.has(f) ? fileState(obj?.[f]) : obj?.[f];
  return o;
}
const JOB_FIELDS = ['jobNumber', 'reportDate', 'customer', 'phone', 'details', 'dueDate', 'techReport', 'status',
  'assignees', 'completionDate', 'serviceFee', 'verify', 'receiptData', 'jobFormData'];
const SALE_FIELDS = ['saleDate', 'customer', 'phone', 'details', 'amount', 'commType', 'staff', 'receiptData'];

// ════════════════════════════════════════════════════════════════
// ROUTER
// ════════════════════════════════════════════════════════════════
export async function onRequest(context) {
  const { request, env, params } = context;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const route = params.route || [];
  const resource = route[0];
  const id = route[1];
  const sub = route[2];
  const method = request.method;

  try {
    await ensureCols(env);

    // ── Public endpoints ────────────────────────────────────────
    if (resource === 'staff' && !id && method === 'GET') return await getStaff(env, await getMe(request, env));
    if (resource === 'staff' && id && sub === 'login' && method === 'POST') return await staffLogin(id, request, env);
    if (resource === 'staff' && id && sub === 'pin' && method === 'PUT') return await staffSetPin(id, request, env, await getMe(request, env));
    if (resource === 'auth' && id === 'admin' && method === 'POST') return await adminLogin(request, env);
    if (resource === 'roles' && !id && method === 'GET') return await getRoles(env, await getMe(request, env));

    // ── Everything else needs a session ─────────────────────────
    const me = await getMe(request, env);
    if (!me) return deny(null);

    if (resource === 'auth') {
      if (id === 'logout' && method === 'POST') {
        await env.DB.prepare(`DELETE FROM sessions WHERE token=?`).bind(me.token).run();
        return json({ ok: true });
      }
      if (id === 'me' && method === 'GET') return json({ user: { name: me.name, role: me.role, id: me.staffId }, perms: [...me.perms] });
      if (id === 'admin-pin' && method === 'PUT') return me.isAdmin ? await adminSetPin(request, env, me) : deny(me);
    }

    if (resource === 'jobs') {
      if (!id) {
        if (method === 'GET') return await getJobs(env, me);
        if (method === 'POST') return me.can('jobs.create') ? await createJob(request, env, me) : deny(me);
      } else {
        if (method === 'PUT') return await updateJob(id, request, env, me);
        if (method === 'DELETE') return me.can('jobs.delete') ? await deleteJob(id, request, env, me) : deny(me);
      }
    }

    if (resource === 'sales') {
      if (!id) {
        if (method === 'GET') return await getSales(env, me);
        if (method === 'POST') return me.can('sales.create') ? await createSale(request, env, me) : deny(me);
      } else {
        if (method === 'PUT') return await updateSale(id, request, env, me);
        if (method === 'DELETE') return me.can('sales.delete') ? await deleteSale(id, request, env, me) : deny(me);
      }
    }

    if (resource === 'roles') {
      if (!me.isAdmin) return deny(me);
      if (!id && method === 'POST') return await createRole(request, env, me);
      if (id && method === 'PUT') return await updateRole(id, request, env, me);
      if (id && method === 'DELETE') return await deleteRole(id, request, env, me);
    }

    if (resource === 'staff') {
      if (!me.isAdmin) return deny(me);
      if (!id && method === 'POST') return await createStaff(request, env, me);
      if (id && !sub && method === 'PUT') return await updateStaff(id, request, env, me);
      if (id && !sub && method === 'DELETE') return await deleteStaff(id, request, env, me);
    }

    if (resource === 'logs' && method === 'GET') return me.isAdmin ? await getLogs(request, env) : deny(me);

    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: err.message ?? 'Internal error' }, 500);
  }
}

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════
async function staffLogin(id, request, env) {
  const { pin } = await request.json();
  const row = await env.DB.prepare(`SELECT id, name, role, pin_hash FROM staff WHERE id=?`).bind(id).first();
  if (!row) return json({ ok: false, error: 'ไม่พบพนักงาน' }, 404);
  const who = { name: row.name, role: row.role };
  if (await tooManyFails(env, id)) return json({ ok: false, error: 'ใส่รหัสผิดหลายครั้ง กรุณารอ 15 นาที' }, 429);
  if (!(await checkPin(row, pin))) {
    await audit(env, request, who, 'login_fail', 'auth', id, row.name);
    return json({ ok: false, error: 'รหัสผ่านไม่ถูกต้อง' }, 401);
  }
  const role = row.role || 'technician';
  const token = await createSession(env, { staffId: row.id, name: row.name, role });
  await audit(env, request, who, 'login', 'auth', id, row.name);
  return json({
    ok: true, token, isDefault: !row.pin_hash,
    staff: { id: row.id, name: row.name, role }, user: { id: row.id, name: row.name, role },
    perms: [...(await permsForRole(env, role))],
  });
}

async function adminLogin(request, env) {
  const { pin } = await request.json();
  const who = { name: 'แอดมิน', role: 'admin' };
  if (await tooManyFails(env, 'admin')) return json({ ok: false, error: 'ใส่ PIN ผิดหลายครั้ง กรุณารอ 15 นาที' }, 429);
  const s = await env.DB.prepare(`SELECT value FROM settings WHERE key='admin_pin_hash'`).first();
  const ok = s?.value ? (await hashPin('admin', String(pin))) === s.value : String(pin) === DEFAULT_PIN;
  if (!ok) {
    await audit(env, request, who, 'login_fail', 'auth', 'admin', 'แอดมิน');
    return json({ ok: false, error: 'PIN ไม่ถูกต้อง' }, 401);
  }
  const token = await createSession(env, { name: 'แอดมิน', role: 'admin' });
  await audit(env, request, who, 'login', 'auth', 'admin', 'แอดมิน');
  return json({ ok: true, token, isDefault: !s?.value, user: { name: 'แอดมิน', role: 'admin' }, perms: ALL_PERMS });
}

async function adminSetPin(request, env, me) {
  const { oldPin, newPin } = await request.json();
  if (!/^\d{4}$/.test(String(newPin ?? ''))) return json({ ok: false, error: 'PIN ต้องเป็นตัวเลข 4 หลัก' }, 400);
  const s = await env.DB.prepare(`SELECT value FROM settings WHERE key='admin_pin_hash'`).first();
  const ok = s?.value ? (await hashPin('admin', String(oldPin))) === s.value : String(oldPin) === DEFAULT_PIN;
  if (!ok) return json({ ok: false, error: 'PIN เดิมไม่ถูกต้อง' }, 401);
  await env.DB.prepare(`INSERT INTO settings (key,value) VALUES ('admin_pin_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
    .bind(await hashPin('admin', String(newPin))).run();
  await audit(env, request, me, 'pin_change', 'auth', 'admin', 'Admin PIN');
  return json({ ok: true });
}

// ════════════════════════════════════════════════════════════════
// JOBS
// ════════════════════════════════════════════════════════════════
function parseJob(row) {
  if (!row) return null;
  return {
    ...row,
    assignees: safeJSON(row.assignees, []),
    verify: safeJSON(row.verify, { v1: false, v2: false, v3: false, v4: false, v5: false }),
    serviceFee: row.service_fee ?? 0,
    reportDate: row.report_date,
    jobNumber: row.job_number,
    techReport: row.tech_report,
    dueDate: row.due_date,
    completionDate: row.completion_date,
    receiptData: row.receipt_data ?? '',
    receiptName: row.receipt_name ?? '',
    jobFormData: row.job_form_data ?? '',
    jobFormName: row.job_form_name ?? '',
    receiptAt: row.receipt_at ?? '',
    doneAt: row.done_at ?? '',
  };
}

// Server decides the commission dates — first receipt attach / first time done.
async function stampJob(env, id) {
  const today = nowLocal().slice(0, 10);
  await env.DB.prepare(`UPDATE jobs SET
      receipt_at = CASE WHEN COALESCE(receipt_data,'') = '' THEN NULL ELSE COALESCE(receipt_at, ?) END,
      done_at    = CASE WHEN status = 'done' THEN COALESCE(done_at, ?) ELSE NULL END
    WHERE id = ?`).bind(today, today, id).run();
}

async function getJobs(env, me) {
  const { results } = await env.DB.prepare(`SELECT * FROM jobs ORDER BY created_at DESC`).all();
  let jobs = results.map(parseJob);
  if (!me.can('jobs.view')) {
    if (!me.can('comm.view') && !me.can('comm.all')) return deny(me);
    jobs = jobs.filter(j => (j.assignees || []).includes(me.name)); // own jobs only (for own commission)
  }
  return json({ jobs });
}

// normalise either camelCase or snake_case input into the camelCase job shape
function jobFromBody(body) {
  return {
    reportDate: body.reportDate ?? body.report_date ?? '',
    jobNumber: body.jobNumber ?? body.job_number ?? '',
    customer: body.customer,
    phone: body.phone ?? '',
    details: body.details ?? '',
    dueDate: body.due ?? body.dueDate ?? body.due_date ?? '',
    techReport: body.techReport ?? body.tech_report ?? '',
    status: body.status ?? 'pending',
    assignees: body.assignees ?? [],
    completionDate: body.completionDate ?? body.completion_date ?? '',
    serviceFee: body.serviceFee ?? body.service_fee ?? 0,
    receiptData: body.receiptData ?? body.receipt_data ?? '',
    receiptName: body.receiptName ?? body.receipt_name ?? '',
    jobFormData: body.jobFormData ?? body.job_form_data ?? '',
    jobFormName: body.jobFormName ?? body.job_form_name ?? '',
    verify: body.verify ?? { v1: false, v2: false, v3: false, v4: false, v5: false },
  };
}

async function createJob(request, env, me) {
  const b = jobFromBody(await request.json());
  const id = uid();
  const now = nowLocal();
  await env.DB.prepare(`
    INSERT INTO jobs
      (id, report_date, job_number, customer, phone, details, due_date,
       tech_report, status, assignees, completion_date, service_fee,
       receipt_data, receipt_name, job_form_data, job_form_name, verify,
       created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    id, b.reportDate || now.slice(0, 10), b.jobNumber, b.customer, b.phone, b.details, b.dueDate,
    b.techReport, b.status, JSON.stringify(b.assignees), b.completionDate, b.serviceFee,
    b.receiptData, b.receiptName, b.jobFormData, b.jobFormName, JSON.stringify(b.verify), now, now
  ).run();
  await stampJob(env, id);
  const job = parseJob(await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first());
  await audit(env, request, me, 'create', 'job', id, `${job.jobNumber || '—'} · ${job.customer}`, snapshot(job, JOB_FIELDS));
  return json({ job }, 201);
}

async function updateJob(id, request, env, me) {
  const canEdit = me.can('jobs.edit'), canUp = me.can('jobs.upload'), canVer = me.can('jobs.verify');
  if (!canEdit && !canUp && !canVer) return deny(me);
  const old = parseJob(await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first());
  if (!old) return json({ error: 'ไม่พบงาน' }, 404);
  const inc = jobFromBody(await request.json());
  let b;
  if (canEdit) b = inc;
  else {
    // restricted users: start from the stored job and only take the fields they may change
    b = { ...old };
    const filesChanged = inc.jobFormData !== old.jobFormData || inc.receiptData !== old.receiptData;
    if (canUp) {
      b.receiptData = inc.receiptData; b.receiptName = inc.receiptName;
      b.jobFormData = inc.jobFormData; b.jobFormName = inc.jobFormName;
    }
    // closing a job when its job sheet is uploaded counts as part of uploading
    if (canVer || (canUp && filesChanged)) {
      b.status = inc.status; b.verify = inc.verify; b.completionDate = inc.completionDate;
    }
  }
  await env.DB.prepare(`
    UPDATE jobs SET
      report_date=?, job_number=?, customer=?, phone=?, details=?,
      due_date=?, tech_report=?, status=?, assignees=?, completion_date=?,
      service_fee=?, receipt_data=?, receipt_name=?, job_form_data=?,
      job_form_name=?, verify=?, updated_at=?
    WHERE id=?
  `).bind(
    b.reportDate ?? '', b.jobNumber ?? '', b.customer, b.phone ?? '', b.details ?? '',
    b.dueDate ?? '', b.techReport ?? '', b.status ?? 'pending', JSON.stringify(b.assignees ?? []), b.completionDate ?? '',
    b.serviceFee ?? 0, b.receiptData ?? '', b.receiptName ?? '', b.jobFormData ?? '',
    b.jobFormName ?? '', JSON.stringify(b.verify ?? {}), nowLocal(), id
  ).run();
  await stampJob(env, id);
  const job = parseJob(await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first());
  const ch = diff(old, job, JOB_FIELDS);
  if (ch.length) await audit(env, request, me, 'update', 'job', id, `${job.jobNumber || '—'} · ${job.customer}`, ch);
  return json({ job });
}

async function deleteJob(id, request, env, me) {
  const old = parseJob(await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first());
  await env.DB.prepare(`DELETE FROM jobs WHERE id=?`).bind(id).run();
  if (old) await audit(env, request, me, 'delete', 'job', id, `${old.jobNumber || '—'} · ${old.customer}`, snapshot(old, JOB_FIELDS));
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// SALES
// ════════════════════════════════════════════════════════════════
function parseSale(row) {
  if (!row) return null;
  return {
    ...row,
    commType: row.comm_type,
    receiptData: row.receipt_data ?? '',
    receiptName: row.receipt_name ?? '',
    saleDate: row.sale_date,
    receiptAt: row.receipt_at ?? '',
  };
}
async function stampSale(env, id) {
  const today = nowLocal().slice(0, 10);
  await env.DB.prepare(`UPDATE sales SET
      receipt_at = CASE WHEN COALESCE(receipt_data,'') = '' THEN NULL ELSE COALESCE(receipt_at, ?) END
    WHERE id = ?`).bind(today, id).run();
}
function saleFromBody(body) {
  return {
    saleDate: body.date ?? body.saleDate ?? body.sale_date ?? '',
    customer: body.customer,
    phone: body.phone ?? '',
    details: body.details ?? '',
    amount: body.amount ?? 0,
    commType: body.commType ?? body.comm_type ?? 'project',
    staff: body.staff ?? '',
    receiptData: body.receiptData ?? body.receipt_data ?? '',
    receiptName: body.receiptName ?? body.receipt_name ?? '',
  };
}

async function getSales(env, me) {
  const { results } = await env.DB.prepare(`SELECT * FROM sales ORDER BY sale_date DESC, created_at DESC`).all();
  let sales = results.map(parseSale);
  if (!me.can('sales.view')) {
    if (!me.can('comm.view') && !me.can('comm.all')) return deny(me);
    sales = sales.filter(s => s.staff === me.name);
  }
  return json({ sales });
}

async function createSale(request, env, me) {
  const b = saleFromBody(await request.json());
  const id = uid();
  const now = nowLocal();
  await env.DB.prepare(`
    INSERT INTO sales
      (id, sale_date, customer, phone, details, amount, comm_type,
       staff, receipt_data, receipt_name, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(id, b.saleDate || now.slice(0, 10), b.customer, b.phone, b.details, b.amount, b.commType,
    b.staff, b.receiptData, b.receiptName, now, now).run();
  await stampSale(env, id);
  const sale = parseSale(await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first());
  await audit(env, request, me, 'create', 'sale', id, `${sale.customer} · ${sale.staff || '—'}`, snapshot(sale, SALE_FIELDS));
  return json({ sale }, 201);
}

async function updateSale(id, request, env, me) {
  const canEdit = me.can('sales.edit'), canUp = me.can('sales.upload');
  if (!canEdit && !canUp) return deny(me);
  const old = parseSale(await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first());
  if (!old) return json({ error: 'ไม่พบรายการ' }, 404);
  const inc = saleFromBody(await request.json());
  const b = canEdit ? inc : { ...old, receiptData: inc.receiptData, receiptName: inc.receiptName };
  await env.DB.prepare(`
    UPDATE sales SET
      sale_date=?, customer=?, phone=?, details=?, amount=?,
      comm_type=?, staff=?, receipt_data=?, receipt_name=?, updated_at=?
    WHERE id=?
  `).bind(b.saleDate ?? '', b.customer, b.phone ?? '', b.details ?? '', b.amount ?? 0,
    b.commType ?? 'project', b.staff ?? '', b.receiptData ?? '', b.receiptName ?? '', nowLocal(), id).run();
  await stampSale(env, id);
  const sale = parseSale(await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first());
  const ch = diff(old, sale, SALE_FIELDS);
  if (ch.length) await audit(env, request, me, 'update', 'sale', id, `${sale.customer} · ${sale.staff || '—'}`, ch);
  return json({ sale });
}

async function deleteSale(id, request, env, me) {
  const old = parseSale(await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first());
  await env.DB.prepare(`DELETE FROM sales WHERE id=?`).bind(id).run();
  if (old) await audit(env, request, me, 'delete', 'sale', id, `${old.customer} · ${old.staff || '—'}`, snapshot(old, SALE_FIELDS));
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// STAFF
// ════════════════════════════════════════════════════════════════
async function getStaff(env, me) {
  const { results } = await env.DB.prepare(
    `SELECT id, name, role, created_at, (pin_hash IS NULL) AS default_pin FROM staff ORDER BY name`
  ).all();
  // who still has the default PIN is only shown to admins
  if (!me?.isAdmin) results.forEach(r => delete r.default_pin);
  return json({ staff: results });
}

async function staffSetPin(id, request, env, me) {
  const body = await request.json();
  const newPin = String(body.newPin ?? '');
  if (!/^\d{4,6}$/.test(newPin)) return json({ ok: false, error: 'รหัสต้องเป็นตัวเลข 4-6 หลัก' }, 400);
  const row = await env.DB.prepare(`SELECT id, name, pin_hash FROM staff WHERE id=?`).bind(id).first();
  if (!row) return json({ ok: false, error: 'ไม่พบพนักงาน' }, 404);
  if (body.reset) {
    if (!me?.isAdmin) return deny(me, 'เฉพาะแอดมินเท่านั้นที่ตั้งรหัสให้ผู้อื่นได้');
  } else if (!(await checkPin(row, body.oldPin))) {
    return json({ ok: false, error: 'รหัสเดิมไม่ถูกต้อง' }, 401);
  }
  const h = newPin === DEFAULT_PIN && body.reset ? null : await hashPin(id, newPin);
  await env.DB.prepare(`UPDATE staff SET pin_hash=? WHERE id=?`).bind(h, id).run();
  await audit(env, request, body.reset ? me : { name: row.name, role: '' }, body.reset ? 'pin_reset' : 'pin_change', 'staff', id, row.name,
    body.reset ? [{ f: 'pin', from: '', to: h ? 'ตั้งรหัสใหม่' : 'รีเซ็ตเป็น 1234' }] : null);
  return json({ ok: true, isDefault: !h });
}

async function createStaff(request, env, me) {
  const body = await request.json();
  const name = String(body.name ?? '').trim();
  if (!name) return json({ error: 'กรุณากรอกชื่อ' }, 400);
  const id = uid();
  const role = body.role ?? 'technician';
  await env.DB.prepare(`INSERT INTO staff (id, name, role) VALUES (?,?,?)`).bind(id, name, role).run();
  await audit(env, request, me, 'create', 'staff', id, name, { name, role });
  return json({ id, name, role }, 201);
}

async function updateStaff(id, request, env, me) {
  const body = await request.json();
  const row = await env.DB.prepare(`SELECT id, name, role FROM staff WHERE id=?`).bind(id).first();
  if (!row) return json({ error: 'ไม่พบพนักงาน' }, 404);
  const name = String(body.name ?? row.name).trim();
  const role = String(body.role ?? row.role).trim() || 'technician';
  if (!name) return json({ error: 'กรุณากรอกชื่อ' }, 400);
  if (name !== row.name) {
    const dup = await env.DB.prepare(`SELECT id FROM staff WHERE name=? AND id<>?`).bind(name, id).first();
    if (dup) return json({ error: `มีพนักงานชื่อ "${name}" อยู่แล้ว` }, 409);
  }
  const stmts = [env.DB.prepare(`UPDATE staff SET name=?, role=? WHERE id=?`).bind(name, role, id)];
  let jobsChanged = 0, salesChanged = 0;
  if (name !== row.name) {
    // jobs.assignees is a JSON array of names, sales.staff is a name → rename everywhere
    const { results } = await env.DB.prepare(`SELECT id, assignees FROM jobs WHERE assignees LIKE ?`)
      .bind(`%${JSON.stringify(row.name).slice(1, -1)}%`).all();
    for (const j of results) {
      const arr = safeJSON(j.assignees, []);
      if (!arr.includes(row.name)) continue;
      stmts.push(env.DB.prepare(`UPDATE jobs SET assignees=? WHERE id=?`)
        .bind(JSON.stringify(arr.map(a => (a === row.name ? name : a))), j.id));
      jobsChanged++;
    }
    const c = await env.DB.prepare(`SELECT COUNT(*) AS n FROM sales WHERE staff=?`).bind(row.name).first();
    salesChanged = c?.n ?? 0;
    stmts.push(env.DB.prepare(`UPDATE sales SET staff=? WHERE staff=?`).bind(name, row.name));
  }
  await env.DB.batch(stmts);
  const ch = diff(row, { name, role }, ['name', 'role']);
  if (ch.length) await audit(env, request, me, 'update', 'staff', id, name, ch);
  return json({ ok: true, staff: { id, name, role }, oldName: row.name, jobsChanged, salesChanged });
}

async function deleteStaff(id, request, env, me) {
  const row = await env.DB.prepare(`SELECT id, name, role FROM staff WHERE id=?`).bind(id).first();
  await env.DB.prepare(`DELETE FROM staff WHERE id=?`).bind(id).run();
  await env.DB.prepare(`DELETE FROM sessions WHERE staff_id=?`).bind(id).run();
  if (row) await audit(env, request, me, 'delete', 'staff', id, row.name, { name: row.name, role: row.role });
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// ROLES
// ════════════════════════════════════════════════════════════════
async function getRoles(env, me) {
  const { results } = await env.DB.prepare(`SELECT id, label, perms FROM roles ORDER BY sort, label`).all();
  // before login only the names are needed (login screen)
  if (!me) return json({ roles: results.map(r => ({ id: r.id, label: r.label })) });
  return json({ roles: results.map(r => ({ id: r.id, label: r.label, perms: safeJSON(r.perms, []) })), allPerms: ALL_PERMS });
}
const cleanPerms = p => [...new Set((Array.isArray(p) ? p : []).filter(x => ALL_PERMS.includes(x)))];

async function createRole(request, env, me) {
  const body = await request.json();
  const label = String(body.label ?? '').trim();
  if (!label) return json({ error: 'กรุณากรอกชื่อบทบาท' }, 400);
  const dup = await env.DB.prepare(`SELECT id FROM roles WHERE label=?`).bind(label).first();
  if (dup) return json({ error: 'มีบทบาทนี้แล้ว' }, 409);
  const id = 'r_' + uid();
  const perms = body.perms ? cleanPerms(body.perms) : ['jobs.view', 'sales.view'];
  const m = await env.DB.prepare(`SELECT COALESCE(MAX(sort),0)+1 AS s FROM roles`).first();
  await env.DB.prepare(`INSERT INTO roles (id,label,perms,sort) VALUES (?,?,?,?)`).bind(id, label, JSON.stringify(perms), m?.s ?? 0).run();
  await audit(env, request, me, 'create', 'role', id, label, { label, perms });
  return json({ role: { id, label, perms } }, 201);
}

async function updateRole(id, request, env, me) {
  const body = await request.json();
  const row = await env.DB.prepare(`SELECT id, label, perms FROM roles WHERE id=?`).bind(id).first();
  if (!row) return json({ error: 'ไม่พบบทบาท' }, 404);
  const label = String(body.label ?? row.label).trim() || row.label;
  const perms = body.perms ? cleanPerms(body.perms) : safeJSON(row.perms, []);
  await env.DB.prepare(`UPDATE roles SET label=?, perms=? WHERE id=?`).bind(label, JSON.stringify(perms), id).run();
  const before = safeJSON(row.perms, []);
  const ch = [];
  if (label !== row.label) ch.push({ f: 'label', from: row.label, to: label });
  const added = perms.filter(p => !before.includes(p)), removed = before.filter(p => !perms.includes(p));
  if (added.length) ch.push({ f: 'perms+', from: '', to: added.join(', ') });
  if (removed.length) ch.push({ f: 'perms-', from: removed.join(', '), to: '' });
  if (ch.length) await audit(env, request, me, 'update', 'role', id, label, ch);
  return json({ role: { id, label, perms } });
}

async function deleteRole(id, request, env, me) {
  const row = await env.DB.prepare(`SELECT id, label FROM roles WHERE id=?`).bind(id).first();
  if (!row) return json({ error: 'ไม่พบบทบาท' }, 404);
  const used = await env.DB.prepare(`SELECT COUNT(*) AS n FROM staff WHERE role=?`).bind(id).first();
  if (used?.n) return json({ error: `มีพนักงาน ${used.n} คนใช้บทบาทนี้อยู่ — เปลี่ยนบทบาทของพนักงานก่อน` }, 409);
  await env.DB.prepare(`DELETE FROM roles WHERE id=?`).bind(id).run();
  await audit(env, request, me, 'delete', 'role', id, row.label);
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// AUDIT LOG
// ════════════════════════════════════════════════════════════════
async function getLogs(request, env) {
  const u = new URL(request.url);
  const limit = Math.min(200, Math.max(1, +u.searchParams.get('limit') || 100));
  const offset = Math.max(0, +u.searchParams.get('offset') || 0);
  const where = [], args = [];
  const actor = u.searchParams.get('actor'); if (actor) { where.push('actor=?'); args.push(actor); }
  const entity = u.searchParams.get('entity'); if (entity) { where.push('entity=?'); args.push(entity); }
  const eid = u.searchParams.get('entityId'); if (eid) { where.push('entity_id=?'); args.push(eid); }
  const action = u.searchParams.get('action'); if (action) { where.push('action=?'); args.push(action); }
  const month = u.searchParams.get('month'); if (month) { where.push('at LIKE ?'); args.push(month + '%'); }
  const q = u.searchParams.get('q'); if (q) { where.push('(label LIKE ? OR actor LIKE ? OR changes LIKE ?)'); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log ${w}`).bind(...args).first();
  const { results } = await env.DB.prepare(`SELECT * FROM audit_log ${w} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .bind(...args, limit, offset).all();
  const actors = await env.DB.prepare(`SELECT DISTINCT actor FROM audit_log ORDER BY actor`).all();
  return json({
    logs: results.map(r => ({ ...r, changes: safeJSON(r.changes, null) })),
    total: total?.n ?? 0, actors: actors.results.map(a => a.actor),
  });
}
