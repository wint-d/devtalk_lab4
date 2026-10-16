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

## Patch #3: Validate image-fetch URL (A01 Broken Access Control - SSRF)

- **Lab 4 finding:** #2 (SSRF)
- **OWASP:** A01 Broken Access Control (SSRF)
- **Location:** `public/fetch_image.php` line 15 (`file_get_contents($url, ...)`
  on raw `$_GET['url']`)
- **Exploit re-run (pre-fix):** `GET /fetch_image.php?url=../src/config.php`
  returned the contents of `src/config.php` (revealing `DB_PATH`,
  `forum.sqlite`, upload paths); `url=file:///etc/passwd` and
  `url=http://127.0.0.1:8000/...` likewise let the server read local files /
  reach internal services.
- **Root cause:** the server fetched any attacker-supplied URL with no scheme
  restriction, no destination-address check, and followed redirects.
- **Fix:** (1) require an absolute `http`/`https` URL via `parse_url` — this
  rejects `file://`, `php://`, and relative paths like `../src/config.php`;
  (2) resolve the host and reject loopback/private/reserved IPs with
  `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`; (3) disable redirect
  following (`follow_location=0`, `max_redirects=0`); (4) serve the response
  only if its detected MIME type is `image/*`. Error messages are generic.
- **Residual risk:** DNS rebinding (host resolves to a public IP at check time,
  a private IP at fetch time) is not fully closed by this check; a production
  fix would pin the validated IP for the actual connection.
- **Result (post-fix):** `url=../src/config.php` returns `400 Invalid URL.`;
  `file://` returns 400; loopback returns 400 "Refusing to fetch a private or
  local address." Screenshot: `docs/screenshots/patch-3-ssrf-blocked.png`
- **Normal use:** a real external image URL (`https://httpbin.org/image/png`)
  still previews — returns `200` with `Content-Type: image/png` (verified).

## Patch #4: Scope bio update to the logged-in user (A01 Broken Access Control - IDOR)

- **Lab 4 finding:** #3 (IDOR — profile bio)
- **OWASP:** A01 Broken Access Control (IDOR)
- **Location:** `public/profile.php` lines 6-10 (UPDATE used `$_POST['user_id']`)
- **Exploit re-run (pre-fix):** logged in as `alice`, `POST /profile.php`
  with `user_id=1` and `bio=PWNED_BY_ALICE` overwrote the admin's bio.
- **Root cause:** the update trusted the `user_id` supplied in the request
  instead of binding the action to the authenticated user.
- **Fix:** the update now always targets `$_SESSION['user_id']`; the posted
  `user_id` is ignored and the hidden field removed. The "Update bio" form is
  only rendered on the viewer's own profile
  (`$me['id'] === $profile['id']`).
- **Result (post-fix):** the same request no longer changes the admin bio —
  it edits alice's own row instead; the admin profile still shows
  "Site administrator. Please be respectful."
  Screenshot: `docs/screenshots/patch-4-bio-idor-blocked.png`
- **Normal use:** alice can still update her own bio (verified).
