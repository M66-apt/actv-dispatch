/**
 * Angthong Cable TV — Cloudflare Pages Function
 * Handles all /api/* routes → D1 database (angthong-db)
 *
 * Routes:
 *   GET    /api/jobs
 *   POST   /api/jobs
 *   PUT    /api/jobs/:id
 *   DELETE /api/jobs/:id
 *   GET    /api/sales
 *   POST   /api/sales
 *   PUT    /api/sales/:id
 *   DELETE /api/sales/:id
 *   GET    /api/staff
 *   POST   /api/staff
 *   PUT    /api/staff/:id         { name, role }  (rename cascades to jobs/sales)
 *   DELETE /api/staff/:id
 *   POST   /api/staff/:id/login   { pin }                -> { ok, isDefault }
 *   PUT    /api/staff/:id/pin     { oldPin, newPin }     (staff changes own)
 *                                  { reset:true, newPin } (admin sets / resets)
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

// ── Schema upgrades (run once per worker, safe to repeat) ─────────────────────
let colsReady = false;
async function ensureCols(env) {
  if (colsReady) return;
  const add = async (sql) => { try { await env.DB.prepare(sql).run(); } catch (e) { /* column exists */ } };
  await add(`ALTER TABLE staff ADD COLUMN pin_hash TEXT`);
  await add(`ALTER TABLE jobs  ADD COLUMN receipt_at TEXT`);   // date receipt was first attached
  await add(`ALTER TABLE jobs  ADD COLUMN done_at TEXT`);      // date status became 'done'
  await add(`ALTER TABLE sales ADD COLUMN receipt_at TEXT`);
  // Backfill rows that existed before these columns (best guess = last update)
  await env.DB.prepare(`UPDATE jobs SET receipt_at = substr(updated_at,1,10)
    WHERE receipt_at IS NULL AND COALESCE(receipt_data,'') <> ''`).run();
  await env.DB.prepare(`UPDATE jobs SET done_at = COALESCE(NULLIF(completion_date,''), substr(updated_at,1,10))
    WHERE done_at IS NULL AND status = 'done'`).run();
  await env.DB.prepare(`UPDATE sales SET receipt_at = substr(updated_at,1,10)
    WHERE receipt_at IS NULL AND COALESCE(receipt_data,'') <> ''`).run();
  colsReady = true;
}

// Server decides the commission dates — first receipt attach / first time done.
async function stampJob(env, id) {
  const today = nowLocal().slice(0, 10);
  await env.DB.prepare(`UPDATE jobs SET
      receipt_at = CASE WHEN COALESCE(receipt_data,'') = '' THEN NULL ELSE COALESCE(receipt_at, ?) END,
      done_at    = CASE WHEN status = 'done' THEN COALESCE(done_at, ?) ELSE NULL END
    WHERE id = ?`).bind(today, today, id).run();
}
async function stampSale(env, id) {
  const today = nowLocal().slice(0, 10);
  await env.DB.prepare(`UPDATE sales SET
      receipt_at = CASE WHEN COALESCE(receipt_data,'') = '' THEN NULL ELSE COALESCE(receipt_at, ?) END
    WHERE id = ?`).bind(today, id).run();
}

// ── Parse DB rows (JSON columns back to objects) ──────────────────────────────
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

function safeJSON(str, fallback) {
  try { return JSON.parse(str); } catch { return fallback; }
}

// ── ROUTER ────────────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env, params } = context;

  // Preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const route = params.route || [];
  const resource = route[0];
  const id = route[1];
  const method = request.method;

  try {
    await ensureCols(env);
    await ensureCols(env);
    // ── JOBS ──────────────────────────────────────────────────────────────
    if (resource === 'jobs') {
      if (!id) {
        if (method === 'GET') return await getJobs(env);
        if (method === 'POST') return await createJob(request, env);
      } else {
        if (method === 'PUT')    return await updateJob(id, request, env);
        if (method === 'DELETE') return await deleteJob(id, env);
      }
    }

    // ── SALES ─────────────────────────────────────────────────────────────
    if (resource === 'sales') {
      if (!id) {
        if (method === 'GET')  return await getSales(env);
        if (method === 'POST') return await createSale(request, env);
      } else {
        if (method === 'PUT')    return await updateSale(id, request, env);
        if (method === 'DELETE') return await deleteSale(id, env);
      }
    }

    // ── STAFF ─────────────────────────────────────────────────────────────
    if (resource === 'staff') {
      if (!id) {
        if (method === 'GET')  return await getStaff(env);
        if (method === 'POST') return await createStaff(request, env);
      } else {
        const sub = route[2];
        if (sub === 'login' && method === 'POST') return await staffLogin(id, request, env);
        if (sub === 'pin'   && method === 'PUT')  return await staffSetPin(id, request, env);
        if (!sub && method === 'PUT')    return await updateStaff(id, request, env);
        if (!sub && method === 'DELETE') return await deleteStaff(id, env);
      }
    }

    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: err.message ?? 'Internal error' }, 500);
  }
}

// ════════════════════════════════════════════════════════════════
// JOBS
// ════════════════════════════════════════════════════════════════
async function getJobs(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM jobs ORDER BY created_at DESC`
  ).all();
  return json({ jobs: results.map(parseJob) });
}

async function createJob(request, env) {
  const body = await request.json();
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
    id,
    body.reportDate ?? body.report_date ?? now.slice(0,10),
    body.jobNumber  ?? body.job_number  ?? '',
    body.customer,
    body.phone      ?? '',
    body.details    ?? '',
    body.due        ?? body.due_date    ?? '',
    body.techReport ?? body.tech_report ?? '',
    body.status     ?? 'pending',
    JSON.stringify(body.assignees ?? []),
    body.completionDate ?? body.completion_date ?? '',
    body.serviceFee     ?? body.service_fee     ?? 0,
    body.receiptData    ?? body.receipt_data    ?? '',
    body.receiptName    ?? body.receipt_name    ?? '',
    body.jobFormData    ?? body.job_form_data   ?? '',
    body.jobFormName    ?? body.job_form_name   ?? '',
    JSON.stringify(body.verify ?? { v1:false, v2:false, v3:false, v4:false, v5:false }),
    now, now
  ).run();

  await stampJob(env, id);
  const row = await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first();
  return json({ job: parseJob(row) }, 201);
}

async function updateJob(id, request, env) {
  const body = await request.json();
  const now = nowLocal();

  await env.DB.prepare(`
    UPDATE jobs SET
      report_date=?, job_number=?, customer=?, phone=?, details=?,
      due_date=?, tech_report=?, status=?, assignees=?, completion_date=?,
      service_fee=?, receipt_data=?, receipt_name=?, job_form_data=?,
      job_form_name=?, verify=?, updated_at=?
    WHERE id=?
  `).bind(
    body.reportDate     ?? body.report_date     ?? '',
    body.jobNumber      ?? body.job_number      ?? '',
    body.customer,
    body.phone          ?? '',
    body.details        ?? '',
    body.due            ?? body.due_date        ?? '',
    body.techReport     ?? body.tech_report     ?? '',
    body.status         ?? 'pending',
    JSON.stringify(body.assignees ?? []),
    body.completionDate ?? body.completion_date ?? '',
    body.serviceFee     ?? body.service_fee     ?? 0,
    body.receiptData    ?? body.receipt_data    ?? '',
    body.receiptName    ?? body.receipt_name    ?? '',
    body.jobFormData    ?? body.job_form_data   ?? '',
    body.jobFormName    ?? body.job_form_name   ?? '',
    JSON.stringify(body.verify ?? { v1:false, v2:false, v3:false, v4:false, v5:false }),
    now, id
  ).run();

  await stampJob(env, id);
  const row = await env.DB.prepare(`SELECT * FROM jobs WHERE id=?`).bind(id).first();
  return json({ job: parseJob(row) });
}

async function deleteJob(id, env) {
  await env.DB.prepare(`DELETE FROM jobs WHERE id=?`).bind(id).run();
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// SALES
// ════════════════════════════════════════════════════════════════
async function getSales(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM sales ORDER BY sale_date DESC, created_at DESC`
  ).all();
  return json({ sales: results.map(parseSale) });
}

async function createSale(request, env) {
  const body = await request.json();
  const id = uid();
  const now = nowLocal();

  await env.DB.prepare(`
    INSERT INTO sales
      (id, sale_date, customer, phone, details, amount, comm_type,
       staff, receipt_data, receipt_name, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    id,
    body.date        ?? body.sale_date  ?? now.slice(0,10),
    body.customer,
    body.phone       ?? '',
    body.details     ?? '',
    body.amount      ?? 0,
    body.commType    ?? body.comm_type  ?? 'project',
    body.staff       ?? '',
    body.receiptData ?? body.receipt_data ?? '',
    body.receiptName ?? body.receipt_name ?? '',
    now, now
  ).run();

  await stampSale(env, id);
  const row = await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first();
  return json({ sale: parseSale(row) }, 201);
}

async function updateSale(id, request, env) {
  const body = await request.json();
  const now = nowLocal();

  await env.DB.prepare(`
    UPDATE sales SET
      sale_date=?, customer=?, phone=?, details=?, amount=?,
      comm_type=?, staff=?, receipt_data=?, receipt_name=?, updated_at=?
    WHERE id=?
  `).bind(
    body.date        ?? body.sale_date  ?? '',
    body.customer,
    body.phone       ?? '',
    body.details     ?? '',
    body.amount      ?? 0,
    body.commType    ?? body.comm_type  ?? 'project',
    body.staff       ?? '',
    body.receiptData ?? body.receipt_data ?? '',
    body.receiptName ?? body.receipt_name ?? '',
    now, id
  ).run();

  await stampSale(env, id);
  const row = await env.DB.prepare(`SELECT * FROM sales WHERE id=?`).bind(id).first();
  return json({ sale: parseSale(row) });
}

async function deleteSale(id, env) {
  await env.DB.prepare(`DELETE FROM sales WHERE id=?`).bind(id).run();
  return json({ success: true });
}

// ════════════════════════════════════════════════════════════════
// STAFF
// ════════════════════════════════════════════════════════════════
const DEFAULT_PIN = '1234';
const ensurePinCol = ensureCols;
async function hashPin(id, pin) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`actv:${id}:${pin}`));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function checkPin(row, pin) {
  if (!row) return false;
  if (!row.pin_hash) return String(pin) === DEFAULT_PIN;
  return (await hashPin(row.id, String(pin))) === row.pin_hash;
}

async function getStaff(env) {
  await ensurePinCol(env);
  const { results } = await env.DB.prepare(
    `SELECT id, name, role, created_at, (pin_hash IS NULL) AS default_pin FROM staff ORDER BY name`
  ).all();
  return json({ staff: results });
}

async function staffLogin(id, request, env) {
  await ensurePinCol(env);
  const { pin } = await request.json();
  const row = await env.DB.prepare(`SELECT id, name, role, pin_hash FROM staff WHERE id=?`).bind(id).first();
  if (!row) return json({ ok: false, error: 'ไม่พบพนักงาน' }, 404);
  if (!(await checkPin(row, pin))) return json({ ok: false, error: 'รหัสผ่านไม่ถูกต้อง' }, 401);
  return json({ ok: true, isDefault: !row.pin_hash, staff: { id: row.id, name: row.name, role: row.role } });
}

async function staffSetPin(id, request, env) {
  await ensurePinCol(env);
  const body = await request.json();
  const newPin = String(body.newPin ?? '');
  if (!/^\d{4,6}$/.test(newPin)) return json({ ok: false, error: 'รหัสต้องเป็นตัวเลข 4-6 หลัก' }, 400);
  const row = await env.DB.prepare(`SELECT id, pin_hash FROM staff WHERE id=?`).bind(id).first();
  if (!row) return json({ ok: false, error: 'ไม่พบพนักงาน' }, 404);
  if (!body.reset && !(await checkPin(row, body.oldPin))) return json({ ok: false, error: 'รหัสเดิมไม่ถูกต้อง' }, 401);
  const h = newPin === DEFAULT_PIN && body.reset ? null : await hashPin(id, newPin);
  await env.DB.prepare(`UPDATE staff SET pin_hash=? WHERE id=?`).bind(h, id).run();
  return json({ ok: true, isDefault: !h });
}

async function createStaff(request, env) {
  const body = await request.json();
  const id = uid();
  await env.DB.prepare(
    `INSERT INTO staff (id, name, role) VALUES (?,?,?)`
  ).bind(id, body.name, body.role ?? 'technician').run();
  return json({ id, name: body.name, role: body.role ?? 'technician' }, 201);
}

async function updateStaff(id, request, env) {
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
      const next = arr.map(a => (a === row.name ? name : a));
      stmts.push(env.DB.prepare(`UPDATE jobs SET assignees=? WHERE id=?`).bind(JSON.stringify(next), j.id));
      jobsChanged++;
    }
    const c = await env.DB.prepare(`SELECT COUNT(*) AS n FROM sales WHERE staff=?`).bind(row.name).first();
    salesChanged = c?.n ?? 0;
    stmts.push(env.DB.prepare(`UPDATE sales SET staff=? WHERE staff=?`).bind(name, row.name));
  }
  await env.DB.batch(stmts);
  return json({ ok: true, staff: { id, name, role }, oldName: row.name, jobsChanged, salesChanged });
}

async function deleteStaff(id, env) {
  await env.DB.prepare(`DELETE FROM staff WHERE id=?`).bind(id).run();
  return json({ success: true });
}
