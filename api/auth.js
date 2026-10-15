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
      c.setCookie(res, u.id);
      return res.json({ user: c.pub(u) });
    }
    throw c.http(400, 'Unknown action');
  } catch (e) { c.fail(res, e); }
};
