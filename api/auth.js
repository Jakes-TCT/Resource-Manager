const c = require('../lib/core');
const { sql } = c;

module.exports = async (req, res) => {
  try {
    await c.ensure();
    if (req.method !== 'POST') throw c.http(405, 'POST only');
    if (!c.sameType(req)) throw c.http(415, 'JSON only');
    const b = req.body || {};

    if (b.action === 'me') {
      const u = await c.sessionUser(req);
      if (!u) throw c.http(401, 'Not signed in');
      return res.json({ user: c.pub(u) });
    }
    if (b.action === 'logout') { c.clearCookie(res); return res.json({ ok: true }); }

    if (b.action === 'reset-request') {
      const username = String(b.username || '').trim().toLowerCase();
      const user = (await sql`select id from app_users where username=${username} and status='approved'`)[0];
      const token = require('crypto').randomBytes(32).toString('hex'), digest = require('crypto').createHash('sha256').update(token).digest('hex'), now = Date.now();
      if (user) {
        const recent = await sql`select id from password_resets where user_id=${user.id} and created > ${now-15*60000}`;
        if (recent.length < 3) {
          await sql`insert into password_resets(id,user_id,token_hash,status,created,expires) values(${require('crypto').randomBytes(12).toString('hex')},${user.id},${digest},'pending',${now},${now+24*3600000})`;
          await c.bump();
        }
      }
      return res.json({ token, status: 'pending' });
    }
    if (b.action === 'reset-status' || b.action === 'reset-complete') {
      if (!/^[a-f0-9]{64}$/.test(String(b.token || ''))) throw c.http(400, 'Invalid reset request');
      const digest = require('crypto').createHash('sha256').update(b.token).digest('hex'), now = Date.now();
      if (b.action === 'reset-status') {
        const request = (await sql`select status from password_resets where token_hash=${digest} and expires > ${now}`)[0];
        return res.json({ status: request ? request.status : 'unavailable' });
      }
      const password = String(b.password || '');
      if (password.length < 8 || password.length > 200) throw c.http(400, 'Password must be 8 to 200 characters');
      const encoded = await c.hash(password);
      const updated = await sql`with consumed as (delete from password_resets r where token_hash=${digest} and status='approved' and expires > ${now} and exists(select 1 from app_users u where u.id=r.user_id and u.status='approved') returning user_id) update app_users set pass=${encoded}, fails=0, locked_until=0, auth_version=auth_version+1 where id in (select user_id from consumed) returning id`;
      if (!updated.length) throw c.http(403, 'Reset has not been approved, has expired or was already used');
      await sql`delete from password_resets where user_id=${updated[0].id}`;
      await c.bump();
      return res.json({ ok: true });
    }

    const username = String(b.username || '').trim().toLowerCase();
    const password = String(b.password || '');

    if (b.action === 'signup') {
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw c.http(400, 'Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore.');
      if (password.length < 8 || password.length > 200) throw c.http(400, 'Password must be at least 8 characters.');
      const name = String(b.name || '').trim().slice(0, 80) || username;
      const jobTitle = String(b.jobTitle || '').trim().slice(0, 80);
      if ((await sql`select 1 from app_users where username=${username}`).length) throw c.http(409, 'That username is already taken.');
      const id = require('crypto').randomBytes(9).toString('hex');
      const admin = c.ADMINS().includes(username);
      await sql`insert into app_users(id, username, pass, name, job_title, status, role, created)
        values(${id}, ${username}, ${await c.hash(password)}, ${name}, ${jobTitle}, ${admin ? 'approved' : 'pending'}, ${admin ? 'admin' : null}, ${Date.now()})`;
      await c.bump();
      c.setCookie(res, id);
      return res.json({ user: c.pub((await sql`select id, username, name, job_title, status, role from app_users where id=${id}`)[0]) });
    }

    if (b.action === 'login') {
      const bad = c.http(401, 'Wrong username or password.');
      const u = (await sql`select * from app_users where username=${username}`)[0];
      if (!u) throw bad;
      if (Number(u.locked_until) > Date.now()) throw c.http(429, 'Too many attempts. Try again in a few minutes.');
      if (!(await c.verify(password, u.pass))) {
        const fails = u.fails + 1;
        await sql`update app_users set fails=${fails >= 5 ? 0 : fails}, locked_until=${fails >= 5 ? Date.now() + 15 * 60000 : 0} where id=${u.id}`;
        throw bad;
      }
      await sql`update app_users set fails=0, locked_until=0 where id=${u.id}`;
      if (c.ADMINS().includes(username) && (u.role !== 'admin' || u.status !== 'approved')) {
        await sql`update app_users set role='admin', status='approved' where id=${u.id}`;
        u.role = 'admin'; u.status = 'approved';
        await c.bump();
      }
      c.setCookie(res, u.id, Number(u.auth_version || 0));
      return res.json({ user: c.pub(u) });
    }
    throw c.http(400, 'Unknown action');
  } catch (e) { c.fail(res, e); }
};
