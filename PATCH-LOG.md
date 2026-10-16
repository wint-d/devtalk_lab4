# DevTalk — Patch Log (Lab 5)

Secure-coding fixes for the vulnerabilities documented in the Lab 4 Vulnerability
Log. For each patch: the Lab 4 finding, OWASP class, location, the exploit re-run
before the fix, the root cause, the fix applied, the result after the fix (with
screenshot evidence), and a normal-use regression check.

Environment: PHP 8.3, SQLite, server run with `composer start`
(`php -S localhost:8000 -t public`). The database is rebuilt with
`composer reset-db` where a patch changes how data is stored.

## Patch #1: Parameterize login & hash passwords (A05 Injection - SQLi / A02)

- **Lab 4 finding:** #1 (SQL injection — login)
- **OWASP:** A05 Injection (SQLi); also A02 (plaintext password storage)
- **Location:** `public/login.php` line 10 (old concatenated query);
  `public/register.php`; `database/build_db.php`
- **Exploit re-run (pre-fix):** `POST /login.php` with
  `username=admin'--` and a wrong password returned `302 -> index.php`
  and the session was authenticated as user id 1 (admin). The old query
  `SELECT * FROM users WHERE username = '$username' AND password = '$password'`
  let `admin'--` comment out the password check.
- **Root cause:** user input concatenated directly into the SQL string, and
  passwords stored/compared in plaintext — so the query decided authentication.
- **Fix:** replaced the query with a prepared statement that selects by
  `username = ?` only, then verifies the password in PHP with
  `password_verify()` against a stored hash. `register.php` now stores
  `password_hash()`, and `build_db.php` seeds hashed passwords. Added
  `session_regenerate_id(true)` on login/registration, and replaced the
  error block (which echoed the raw query and PDO exception) with a generic
  "Invalid username or password." message that is HTML-escaped.
- **Result (post-fix):** the same payload now stays on the login page,
  unauthenticated, showing "Invalid username or password."
  Screenshot: `docs/screenshots/patch-1-login-sqli-blocked.png`
- **Normal use:** `alice` / `password123` logs in and is redirected to the
  homepage as user id 2 (verified).

## Patch #2: Parameterize search query (A05 Injection - SQLi)

- **Lab 4 finding:** #1 (SQL injection — search)
- **OWASP:** A05 Injection (SQLi)
- **Location:** `public/search.php` line 10 (old concatenated `LIKE '%$q%'`)
- **Exploit re-run (pre-fix):** `GET /search.php?q=` with
  `zzz' UNION SELECT id, username, password FROM users --` rendered the
  users table — every plaintext password (`Sup3rSecret!`, `password123`,
  `hunter2`, `letmein2024`) appeared in the results list.
- **Root cause:** the search term was concatenated into the SQL string, so a
  crafted `q` could close the `LIKE` literal and append a `UNION SELECT`.
- **Fix:** replaced the query with a prepared statement using bound `LIKE ?`
  parameters (`'%' . $q . '%'` passed as data). Also removed the query text
  and raw exception from the error message. (Passwords are now hashed by
  Patch #1, so even a future leak would not expose plaintext.)
- **Result (post-fix):** the same payload returns "No matches found" — the
  UNION string is treated as a literal search term.
  Screenshot: `docs/screenshots/patch-2-search-sqli-blocked.png`
- **Normal use:** searching `CSS` still returns "Favourite CSS layout tricks?"
  (verified).
