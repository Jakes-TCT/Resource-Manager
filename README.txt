Flux account management update - 2026.11.06-r4

Replace all four files together, preserving these folders:
  public/index.html
  api/auth.js
  api/data.js
  lib/core.js

Redeploy. No new environment variables or email provider are needed. The app creates its new password-reset table and session-version column automatically on the first request. Existing accounts and passwords are retained.

Only approved Admin users can change roles, remove other accounts or approve/decline password resets. Removal deletes the login account and its reset requests, retaining team resources, projects and booking history. Admins cannot remove their own account, and at least one approved Admin must remain.

Forgot password: enter username, then keep the reset page open (or return to Forgot password in the same browser tab). Admins see pending requests and a count on Users. Confirm the request with the user before approving it. Requests expire after 24 hours. Once approved, the requesting browser has 15 minutes to set a password of 8 to 200 characters. Reset tokens are single-use; only token hashes are stored on the server. Successful resets invalidate old login sessions.
