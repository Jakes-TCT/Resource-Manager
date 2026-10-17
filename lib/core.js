const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

// ---- database (lazy so a missing DATABASE_URL gives a clear error) ----
let _sql;
const getSql = () => _sql || (_sql = neon(process.env.DATABASE_URL));
const sql = (...a) => getSql()(...a);
sql.transaction = (x) => getSql().transaction(x);

let ready;
function ensure() {
  return ready || (ready = (async () => {
    await sql`create table if not exists app_users(
      id text primary key, username text unique not null, pass text not null,
      name text, job_title text, status text not null default 'pending', role text,
      created bigint not null, fails int not null default 0, locked_until bigint not null default 0)`;
    await sql`create table if not exists docs(
      coll text not null, id text not null, data jsonb not null, primary key(coll, id))`;
    await sql`create table if not exists meta(k text primary key, v bigint not null)`;
    await sql`alter table app_users add column if not exists seen bigint not null default 0`;
    await sql`insert into meta(k, v) values('rev', 1) on conflict do nothing`;
  })().catch((e) => { ready = null; throw e; }));
}
const getRev = async () => Number((await sql`select v from meta where k='rev'`)[0].v);
const bump = async () => { await sql`update meta set v = v + 1 where k='rev'`; };

// ---- errors ----
const http = (code, msg) => Object.assign(new Error(msg), { code });
const sameType = (req) => (req.headers['content-type'] || '').includes('application/json');
const fail = (res, e) => {
  if (!e.code) console.error(e);
  res.status(e.code || 500).json({ error: e.code ? e.message : 'Server error' });
};

// ---- passwords (scrypt, built into Node) ----
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? no(e) : ok(k))));
async function hash(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
}
async function verify(pw, stored) {
  const [s, h] = String(stored).split(':');
  if (!s || !h) return false;
  const k = await scrypt(pw, Buffer.from(s, 'hex'));
  const x = Buffer.from(h, 'hex');
  return k.length === x.length && crypto.timingSafeEqual(k, x);
}

// ---- sessions (signed cookie) ----
const secret = () => {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) throw new Error('SESSION_SECRET is not set');
  return s;
};
const mac = (p) => crypto.createHmac('sha256', secret()).update(p).digest('base64url');
function sign(uid) {
  const p = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + 7 * 864e5 })).toString('base64url');
  return p + '.' + mac(p);
}
function unsign(t) {
  if (!t || !t.includes('.')) return null;
  const [p, m] = t.split('.');
  const a = Buffer.from(m || ''), b = Buffer.from(mac(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > Date.now() ? o.u : null; }
  catch (e) { return null; }
}
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';')
  .map((s) => s.trim().split('=')).filter((a) => a[0]).map(([k, ...v]) => [k, v.join('=')]));
async function sessionUser(req) {
  const uid = unsign(cookies(req).sid);
  if (!uid) return null;
  return (await sql`select id, username, name, job_title, status, role, created, seen from app_users where id=${uid}`)[0] || null;
}
const setCookie = (res, uid) => res.setHeader('Set-Cookie', `sid=${sign(uid)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`);
const clearCookie = (res) => res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
const ADMINS = () => (process.env.ADMIN_USERNAMES || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
async function presence(u, ok) {
  if (!ok) return [];
  const now = Date.now();
  if (now - Number(u.seen || 0) > 20000) await sql`update app_users set seen=${now} where id=${u.id}`;
  return (await sql`select id, name from app_users where seen > ${now - 60000} and status='approved'`).map((r) => ({ id: r.id, name: r.name }));
}
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, jobTitle: u.job_title, status: u.status, role: u.role });

// ---- role permissions for planner data (enforced on the server) ----
const COLLS = ['clients', 'projects', 'people', 'allocs', 'holidays'];
const CONTRIB = { allocs: ['person', 'start', 'end', 'comment'], projects: ['start', 'end'] };
const IGNORE = ['hist']; // server-managed change history
const changed = (a, b) => {
  const ks = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
  return [...ks].filter((k) => !IGNORE.includes(k) && JSON.stringify((a || {})[k]) !== JSON.stringify((b || {})[k]));
};
const LABEL = { hrs: 'hours per day', status: 'status', comment: 'comment', person: 'resource', proj: 'project', name: 'name', clientId: 'client', ownerId: 'owner', code: 'project code', stage: 'stage', billable: 'billing', notes: 'notes', color: 'colour', leave: 'time-off setting' };
function describeChange(coll, prev, nu) {
  if (!prev) return 'created';
  const ks = changed(prev, nu);
  if (!ks.length) return null;
  const parts = []; let dates = false;
  for (const k of ks) {
    if (k === 'hrs') parts.push('hours per day from ' + prev.hrs + 'h to ' + nu.hrs + 'h');
    else if (k === 'status') parts.push('status to ' + (nu.status || 'confirmed'));
    else if (k === 'start' || k === 'end') { if (!dates) { dates = true; parts.push((coll === 'projects' ? 'timeline' : 'dates') + ' to ' + (nu.start || '?') + ' \u2013 ' + (nu.end || '?')); } }
    else parts.push(LABEL[k] || k);
  }
  return 'changed ' + parts.join(', ');
}
function perm(role, coll, kind, prev, nu) {
  if (!COLLS.includes(coll)) return false;
  if (role === 'admin') return true;
  if (kind === 'delete') return role === 'manager' && coll === 'allocs';
  if (role === 'manager') return coll !== 'holidays' && !(coll === 'projects' && !prev && (!nu.clientId || nu.leave));
  if (role === 'contributor') return !!prev && !!CONTRIB[coll] && changed(prev, nu).every((k) => CONTRIB[coll].includes(k));
  return false;
}

module.exports = { presence, describeChange, sql, ensure, getRev, bump, http, sameType, fail, hash, verify, setCookie, clearCookie, sessionUser, ADMINS, pub, perm, COLLS };
