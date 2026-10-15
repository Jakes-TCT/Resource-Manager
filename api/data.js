const c = require('../lib/core');
const { sql } = c;
const ID = /^[A-Za-z0-9_.-]{1,64}$/;
const ROLES = ['admin', 'manager', 'contributor'];

async function snapshot(u, ok) {
  const out = {};
  if (ok) {
    for (const r of await sql`select coll, id, data from docs where coll <> 'log'`) (out[r.coll] = out[r.coll] || {})[r.id] = r.data;
    if (u.role === 'admin') {
      out.log = {};
      for (const r of await sql`select id, data from docs where coll='log' order by (data->>'at')::bigint desc limit 300`) out.log[r.id] = r.data;
    }
  }
  const rows = ok && u.role === 'admin'
    ? await sql`select id, username, name, job_title, status, role, created from app_users`
    : [u];
  out.users = {};
  for (const x of rows) out.users[x.id] = { name: x.name, jobTitle: x.job_title, email: x.username, status: x.status, role: x.role, requested: Number(x.created), n: Number(x.created) };
  return out;
}

async function apply(u, ops) {
  const stmts = [], userOps = [];
  for (const op of ops) {
    const { coll } = op, id = String(op.id || '');
    if (!ID.test(id)) throw c.http(400, 'Bad id');
    if (coll === 'log') {
      if (op.op !== 'set' || (await sql`select 1 from docs where coll='log' and id=${id}`).length) throw c.http(403, 'The log is append-only');
      const d = { at: Date.now(), by: u.id, byName: u.name, role: u.role, text: String((op.data && op.data.text) || '').slice(0, 500) };
      stmts.push(sql`insert into docs(coll, id, data) values('log', ${id}, ${JSON.stringify(d)}::jsonb)`);
      continue;
    }
    if (coll === 'users') {
      if (u.role !== 'admin' || op.op !== 'set') throw c.http(403, 'Only admins can manage users');
      userOps.push({ id, data: op.data || {} });
      continue;
    }
    if (!c.COLLS.includes(coll)) throw c.http(400, 'Unknown collection');
    const prev = (await sql`select data from docs where coll=${coll} and id=${id}`)[0];
    const old = prev ? prev.data : null;
    if (op.op === 'delete') {
      if (!c.perm(u.role, coll, 'delete', old, null)) throw c.http(403, 'Your role does not allow deleting this');
      stmts.push(sql`delete from docs where coll=${coll} and id=${id}`);
      continue;
    }
    const nu = op.data;
    if (op.op !== 'set' || !nu || typeof nu !== 'object' || Array.isArray(nu) || JSON.stringify(nu).length > 20000) throw c.http(400, 'Bad data');
    delete nu.id;
    if (!c.perm(u.role, coll, 'set', old, nu)) throw c.http(403, 'Your role does not allow this change');
    stmts.push(sql`insert into docs(coll, id, data) values(${coll}, ${id}, ${JSON.stringify(nu)}::jsonb)
      on conflict (coll, id) do update set data = excluded.data`);
  }
  if (userOps.length) {
    const admins = new Set((await sql`select id from app_users where role='admin' and status='approved'`).map((r) => r.id));
    for (const { id, data } of userOps) {
      if (!(await sql`select 1 from app_users where id=${id}`).length) throw c.http(404, 'Unknown user');
      const st = ['approved', 'pending', 'declined'].includes(data.status) ? data.status : null;
      const rl = ROLES.includes(data.role) ? data.role : null;
      if (!st || (st === 'approved' && !rl)) throw c.http(400, 'Bad user data');
      if (st === 'approved' && rl === 'admin') admins.add(id); else admins.delete(id);
      stmts.push(sql`update app_users set status=${st}, role=${st === 'approved' ? rl : null} where id=${id}`);
    }
    if (!admins.size) throw c.http(400, 'There must be at least one admin');
  }
  if (stmts.length) await sql.transaction(stmts);
}

module.exports = async (req, res) => {
  try {
    await c.ensure();
    const u = await c.sessionUser(req);
    if (!u) throw c.http(401, 'Not signed in');
    const ok = u.status === 'approved' && !!u.role;
    if (req.method === 'GET') {
      const rev = await c.getRev();
      if (String(rev) === String(req.query.rev)) return res.json({ changed: false, rev });
      return res.json({ changed: true, rev, data: await snapshot(u, ok) });
    }
    if (req.method === 'POST') {
      if (!c.sameType(req)) throw c.http(415, 'JSON only');
      if (!ok) throw c.http(403, 'Your account has not been approved yet');
      const ops = (req.body || {}).ops;
      if (!Array.isArray(ops) || !ops.length || ops.length > 50) throw c.http(400, 'Bad request');
      await apply(u, ops);
      await c.bump();
      return res.json({ ok: true });
    }
    throw c.http(405, 'Method not allowed');
  } catch (e) { c.fail(res, e); }
};
