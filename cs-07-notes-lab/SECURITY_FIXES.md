# Security fixes

Each fix has a regression test in `tests/test_regressions.py`. On branch
`cs-07-vulnerable` 9 of 10 tests fail; on the fixed code all 10 pass.

## 1. SQL injection (login and search)
**Before:** `f"SELECT id FROM users WHERE username = '{username}' AND password_hash = '{pw}'"`
and the same pattern in search. `victim' --` logged in without a password; a crafted `q`
returned other users' notes.
**After:** placeholders (`WHERE username = ?`, `LIKE ? ESCAPE '\'`) with `%`, `_` and `\`
escaped in the search term. Login fetches the row by username and verifies the hash in
Python, using a dummy hash for unknown users so timing doesn't reveal accounts.
**Tests:** `test_sqli_login_cannot_bypass_password`, `test_sqli_search_cannot_read_other_users_notes`.

## 2. Stored XSS
**Before:** `{{ note['body']|safe }}` rendered stored HTML and script.
**After:** autoescaping (no `|safe`) plus a Content-Security-Policy of
`default-src 'self'; script-src 'self'; style-src 'self'; ...` so an escaping slip would
still not run inline script. Also `nosniff`, `Referrer-Policy: same-origin`, `no-store`.
**Test:** `test_stored_xss_is_escaped_and_csp_set`.

## 3. CSRF
**Before:** any site could make a logged-in browser POST (create, delete, logout).
**After:** a per-session random token, required on every POST via a `before_request` hook
(form field or `X-CSRF-Token` header, constant-time compare, 400 otherwise). Session cookie
is `SameSite=Lax` and `HttpOnly` (and `Secure` when `NOTES_LAB_HTTPS=1`).
**Tests:** `test_csrf_*`, `test_session_cookie_is_samesite_lax_and_httponly`.

## 4. IDOR
**Before:** `/note/<id>` and `/note/<id>/delete` trusted the id alone, so any user could
read or delete any note.
**After:** queries include `AND owner_id = ?`; other users' ids give 404 (same as a
missing note, so ids can't be probed).
**Test:** `test_idor_cannot_read_or_delete_another_users_note`.

## 5. Weak password hashing
**Before:** unsalted MD5, so equal passwords had equal hashes and cracking was instant.
**After:** werkzeug `generate_password_hash` (salted scrypt) and `check_password_hash`;
minimum password length 8.
**Test:** `test_passwords_use_a_salted_slow_hash`.

## Extra: hard-coded session key
**Before:** `SECRET_KEY = "dev"` let anyone forge session cookies.
**After:** random `secrets.token_hex(32)` per start, or `NOTES_LAB_SECRET_KEY`.
Login also calls `session.clear()` to prevent session fixation.
**Test:** `test_secret_key_is_not_the_hardcoded_dev_value`.

## Not addressed (lab scope)
- No rate limiting or lockout on login or registration.
- No HTTPS; run behind TLS and set `NOTES_LAB_HTTPS=1` for any real use.
- Username enumeration via the "Username taken" message on register.
