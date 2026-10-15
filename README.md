# Capacity planner: Vercel version

A web app with a username and password login page, a shared database, and Admin / Manager / Contributor roles enforced on the server.

## What is in this folder
- `public/index.html`: the planner (the web page)
- `api/auth.js`: sign up, log in, log out
- `api/data.js`: reads and saves planner data, and checks each person's role
- `lib/core.js`: shared code (password hashing, sessions, role rules)
- `seed.sql`: optional. Loads the clients, projects, team and bookings from the Claude version
- `package.json`, `vercel.json`: settings

## Deploy
1. Create a GitHub repository and upload everything in this folder (keep the folder structure). A private repository is fine.
2. At vercel.com choose Add New > Project, import the repository, set Framework Preset to "Other", leave the build settings empty, and click Deploy.
3. In the Vercel project open the Storage tab, create a Neon (Postgres) database and connect it to the project. Then open Settings > Environment Variables and check that `DATABASE_URL` exists. If the variable has a different name, add `DATABASE_URL` with the same value.
4. Still in Environment Variables, add:
   - `SESSION_SECRET`: a long random text, at least 32 characters (a password generator works).
   - `ADMIN_USERNAMES`: the usernames that become Admins when they sign up, separated by commas, for example `jakes,zelda`.
5. Go to Deployments, open the latest one, and choose Redeploy so the new settings apply.
6. Open your site and choose Create account. Sign up as `jakes` and `zelda` (or your chosen names). They become Admins immediately. Everyone else who signs up waits until an Admin approves them under Users (top bar) and picks their role.
7. Optional: to bring in your existing data, open the site once (this creates the tables), then paste the contents of `seed.sql` into the Neon SQL editor and run it, then refresh the site.

To run it on your own computer first: install Node, then run `npm install -g vercel` and `vercel dev` in this folder.

## Roles (checked on the server, not just hidden in the page)
- Admin: everything, including users and roles, deleting, "Time off and other" items, public holidays and the activity log.
- Manager: add and edit clients, projects, team members and bookings; delete bookings; cannot delete anything else.
- Contributor: move bookings, change project dates by dragging, and edit comments. Nothing else.

## Good to know
- Changes from other people appear within about 5 seconds.
- The activity log is written by the server with the real user name and cannot be edited or deleted.
- There is no "forgot password" yet. To reset someone, delete their row in Neon (`delete from app_users where username = 'name';`) and have them sign up again for approval.
- Five wrong passwords lock an account for 15 minutes.
- Vercel's free Hobby plan is for personal, non-commercial use. Company use needs a paid plan, or another host that runs Node functions.
