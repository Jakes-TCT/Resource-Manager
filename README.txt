View Only role update

Replace these files in your project, keeping the folder structure:
  api/data.js
  lib/core.js
  public/index.html

Keep your existing api/auth.js and other project files. No database migration or environment changes are needed.
Deploy the files together. Then use Settings > Users to assign View Only.

Approved View Only users can read the board and use local view controls, including expand/collapse. The server rejects all POST /api/data requests for this role, including board edits, activity log writes and account changes. Login/logout and presence still work.
