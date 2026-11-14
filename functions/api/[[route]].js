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
 *   DELETE /api/staff/:id
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
        if (method === 'DELETE') return await deleteStaff(id, env);
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
async function getStaff(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM staff ORDER BY name`
  ).all();
  return json({ staff: results });
}

async function createStaff(request, env) {
  const body = await request.json();
  const id = uid();
  await env.DB.prepare(
    `INSERT INTO staff (id, name, role) VALUES (?,?,?)`
  ).bind(id, body.name, body.role ?? 'technician').run();
  return json({ id, name: body.name }, 201);
}

async function deleteStaff(id, env) {
  await env.DB.prepare(`DELETE FROM staff WHERE id=?`).bind(id).run();
  return json({ success: true });
}
