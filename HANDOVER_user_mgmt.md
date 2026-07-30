# PQC-Monitor — User Management Enhancements: Implementation Handover

Status: **design locked, not yet built.** This document is self-sufficient to
implement from in a later session together with the `pqc-monitor` source tree.

## Decisions locked (from Javier)
- Forgotten-password reset **by email**, mailer **optional**, supporting either a
  **local MTA** or an **authenticated SMTP relay** (Gmail / Proton-Bridge-style).
- **2FA optional for all users**, TOTP (authenticator apps).
- Recommended split into two independently deployable phases along a risk
  boundary. Phase 1 does **not** touch the login flow; Phase 2 does.

## Why two phases
The auth path is security-critical and Javier validates on the live server
between sessions. Phase 1 (mailer + reset) can be deployed and its mail delivery
verified against real relay credentials before the riskier Phase 2 (2FA login
flow) lands on top of a validated base.

---

## Current state (verified against the tree, do not assume — re-read on start)

Files: `auth/store.py` (all `password_hash` access, PBKDF2-SHA256 600k),
`auth/middleware.py` (sessions, `current_user()`, decorators, `AuthProvider`
ABC), `auth/models.py` (User, roles, permissions), `auth/auth_routes.py`
(`/login`, `/logout`, `/change-password` — already requires current password),
`admin/routes.py` (`_ADMIN_HTML` panel + user CRUD API; `POST /admin/api/users/<uid>/password`
is the admin reset, correctly no old-password), `app_factory.py` (blueprint
wiring, session cookie flags, `secret_key`).

Key facts that constrain the design:
- **Schema version is 17.** Add new migrations as **v18, v19** at the END of
  `MIGRATIONS` in `data/migrations.py` — never edit existing entries. Runner:
  `apply_migrations()` is idempotent and tolerates "column already present".
- Auth tables evolve through `data/migrations.py` now (that is where
  `user_organisations` v-tables were added), **not** through
  `AuthStore._init_schema`. New **columns on `users`** MUST be added by an
  `ALTER TABLE users ADD COLUMN` migration — `CREATE TABLE IF NOT EXISTS` in
  `_init_schema` cannot add columns to an existing table. New **tables** may be
  added in the migration AND (defensively) as `CREATE TABLE IF NOT EXISTS` in
  `AuthStore._init_schema`, so AuthStore is self-sufficient regardless of init
  order. `Database()` (which runs migrations) is constructed at startup before
  AuthStore serves requests.
- Sessions: signed cookie, `HttpOnly`, `SameSite=Lax`, `Secure` when HTTPS,
  8h. `current_user()` reloads the user each request and drops the session if
  `is_active` is false. There is **no server-side session id** to revoke
  individual sessions today.
- **No SMTP/email code exists anywhere.** No CSRF tokens. No email-format
  validation. Login IP rate-limiter is per-process in-memory. `secret_key`
  falls back to a per-process random value if unset (multi-worker hazard).
- Secrets policy (memory): relay password lives in **`.env`**, which is in the
  `PROTECTED` array in `deploy.sh` (must remain `config/config.yaml`, `.env`,
  `.venv/` only). Never commit credentials to `config.yaml`.

---

# PHASE 1 — Mailer + forgotten-password reset

## 1. Config (config.yaml + .env)
New optional `mail` section. Absent/`enabled: false` ⇒ self-service reset routes
return a generic "if the address exists, a link was sent" response but send
nothing (admin-mediated reset still works).

```yaml
mail:
  enabled: false            # master switch
  mode: "local"             # "local" | "relay"
  from_addr: "pqc-monitor@localhost"
  # local mode: connect to a local MTA, no auth/TLS
  local_host: "127.0.0.1"
  local_port: 25
  # relay mode: authenticated submission
  relay_host: "smtp.gmail.com"
  relay_port: 587
  relay_security: "starttls"   # "starttls" (587) | "ssl" (465) | "none"
  relay_username: "you@gmail.com"
  # relay_password comes from env PQC_MAIL_PASSWORD (see .env), never yaml
  timeout_seconds: 10
reset:
  token_ttl_minutes: 45
  base_url: "https://pqc-monitor.ddns.net"   # for building absolute reset links
```
`.env`: `PQC_MAIL_PASSWORD=...`. Loader reads `relay_password` from
`os.environ["PQC_MAIL_PASSWORD"]`.

Relay caveats to document for the operator:
- **Gmail** needs an *app password* (2FA on the Google account), host
  `smtp.gmail.com`, `587/starttls` or `465/ssl`.
- **Proton** has no direct SMTP; it requires **Proton Mail Bridge** (paid),
  which exposes a local authenticated SMTP endpoint — configure that as a relay
  (`relay_host: 127.0.0.1`, Bridge's port, Bridge username/password). The
  generic relay config covers this without special-casing.

## 2. New module `auth/mailer.py`
Single responsibility: send a plaintext+HTML email. Pure stdlib `smtplib` +
`email.message.EmailMessage` (no new dependency).

```
class Mailer:
    def __init__(self, cfg: dict)                # the merged 'mail' config
    @property
    def enabled(self) -> bool
    def send(self, to_addr, subject, text_body, html_body=None) -> bool
```
- `mode == "local"`: `SMTP(local_host, local_port, timeout)`, no auth, no TLS.
- `mode == "relay"` + `starttls`: `SMTP(host, port)`, `ehlo`, `starttls()`,
  `login()`.
- `mode == "relay"` + `ssl`: `SMTP_SSL(host, port)`.
- On any failure: log a warning, return `False` — **never raise into the
  request path** (a reset request must not 500). If `not enabled`, return
  `False` immediately.
- Provide a `--selftest` style helper or a `scripts/mail_selftest.py` so Javier
  can verify relay creds server-side before wiring the UI.

Wire a `Mailer` instance into `app.config["MAILER"]` in `app_factory.create_app`
(like `AUTH_STORE`).

## 3. Schema — migration v18 (`data/migrations.py`)
```sql
-- v18: password reset + account hardening
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,          -- sha256 hex of the raw token; raw never stored
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,                    -- NULL until consumed (single-use)
    request_ip  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_prt_token ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_prt_user  ON password_reset_tokens(user_id);
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
```
Also add the two `CREATE TABLE IF NOT EXISTS` for reset tokens to
`AuthStore._init_schema` defensively. Add the reset table create there too.

## 4. AuthStore methods (`auth/store.py`)
```
get_user_by_email(email) -> Optional[User]
create_reset_token(user_id, ttl_minutes, request_ip) -> str   # returns RAW token
consume_reset_token(raw_token) -> Optional[int]               # user_id if valid+unused+unexpired; marks used
purge_expired_reset_tokens()                                  # housekeeping, call opportunistically
```
- Token: `secrets.token_urlsafe(32)`. Store only `sha256(raw)`. Lookup by hash.
- `consume_` is atomic: verify unused + `expires_at > now`, set `used_at`,
  return user_id. Invalidate all other outstanding tokens for that user on
  successful consume.
- Email validation helper `_valid_email(s)` (simple RFC-lite regex). Enforce in
  `create_user`, `update_user`, and the email-change path.

## 5. Routes (`auth/auth_routes.py`, public — no `@require_auth`)
- `GET /forgot` → request form (username or email).
- `POST /forgot` → always render the same generic success ("If that account
  exists, a reset link has been sent."). If mail enabled and user found: create
  token, build `f"{base_url}/reset/{raw}"`, `MAILER.send(...)`. Rate-limit by IP
  **and** by account (reuse/extend the login limiter; note it is per-process).
  Audit `password_reset_requested`.
- `GET /reset/<token>` → validate token exists+unexpired (don't consume yet);
  render new-password form or an "invalid/expired" page.
- `POST /reset/<token>` → re-validate, enforce policy (≥10, confirm match),
  `consume_reset_token`, `store.set_password`, clear `must_change_password`.
  **Do not auto-login.** Redirect to `/login` with a success flash. Audit
  `password_reset_completed`.

Enumeration/abuse defenses: identical response + timing whether or not the
account exists; generic errors; single-use, short-TTL, hashed tokens; rate
limiting; all events audited.

## 6. Templates
Reuse the dark card style from `_LOGIN_HTML`. Three small templates: forgot
request, reset form, and the email body (text + minimal HTML). Add a
"Forgot password?" link on the login page.

## 7. Admin improvement (small, include here)
Extend `POST /admin/api/users/<uid>/password` to optionally set
`must_change_password=1` (or generate a temp password). Enforce
`must_change_password` at login: after a successful auth, if the flag is set,
redirect to `/change-password` before granting normal access.

## 8. Cross-cutting hardening to fold into Phase 1 (low risk, high value)
- Email-format validation (above).
- `secret_key`: hard-fail at startup in production if unset, instead of a random
  per-process fallback (breaks multi-worker sessions).
- Constant-time auth: in `AuthStore.authenticate`, when the user is absent, run a
  dummy `check_password_hash` against a throwaway hash to flatten timing /
  reduce username enumeration.
- CSRF: optional but recommended. Cheapest path given JSON APIs — enforce a
  custom header (e.g. `X-Requested-With`) + `Content-Type: application/json`
  check on state-changing admin/auth endpoints, or add per-session tokens.

## 9. Testing checklist (Phase 1)
- `scripts/mail_selftest.py` sends via local + relay (starttls & ssl).
- Token: unknown token, expired token, reused token, valid token → each path.
- `/forgot` returns identical output for existing vs non-existing account.
- Reset does not log the user in; `must_change_password` cleared.
- Migration v18 applies cleanly on a copy of the prod DB; re-run is a no-op.
- `python3 -m py_compile` on every changed `.py`.

## 10. File inventory (Phase 1)
- NEW `auth/mailer.py`, `scripts/mail_selftest.py`
- MOD `data/migrations.py` (v18), `auth/store.py`, `auth/auth_routes.py`,
  `admin/routes.py` (temp-pw + must_change enforcement), `app_factory.py`
  (Mailer wiring, secret_key hardening), `config/config.yaml.example`,
  `.env.example`, `requirements.txt` (none new for mailer).

---

# PHASE 2 — 2FA (TOTP), optional per user

## 1. Dependency
`pyotp` (pure-Python) added to `requirements.txt`. **No** server-side QR
dependency: render the `otpauth://` URI as a QR **client-side** in the browser
(small JS lib or inline), and always show the manual base32 secret as fallback.

## 2. Schema — migration v19
```sql
-- v19: TOTP 2FA
ALTER TABLE users ADD COLUMN totp_secret     TEXT;      -- encrypted at rest, see below
ALTER TABLE users ADD COLUMN totp_enabled    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_confirmed_at TEXT;
CREATE TABLE IF NOT EXISTS backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,           -- werkzeug hash of a one-time code
    used_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_backup_user ON backup_codes(user_id);
```
Secret at rest: encrypt `totp_secret` with a key derived from the app secret
(e.g. Fernet). Document the key-management caveat: DB and key on the same host
means encryption protects against DB-copy leakage, not host compromise. If a
crypto dependency is unwanted, store the base32 secret plaintext and document the
trade-off explicitly — Javier to decide.

## 3. AuthStore methods
```
begin_totp_enrollment(user_id) -> str          # generate+store secret (disabled), return base32
confirm_totp(user_id, code) -> bool            # verify code, set enabled + confirmed_at, generate backup codes
disable_totp(user_id)                          # clear secret/enabled, delete backup codes
verify_totp(user_id, code) -> bool             # pyotp.TOTP(secret).verify(code, valid_window=1)
consume_backup_code(user_id, code) -> bool     # match a hash, mark used
generate_backup_codes(user_id, n=10) -> list[str]  # returns RAW codes once
```
Rate-limit OTP verification (per user + per IP) and reuse the account-lockout
counters so brute force is bounded.

## 4. Enrollment flow (authenticated, self-service)
On a profile/security page:
1. **Begin** → `begin_totp_enrollment`, show QR (otpauth URI) + manual secret.
2. **Confirm** → user enters a code; `confirm_totp` enables 2FA and reveals
   **backup codes once** (display + downloadable). Audit `2fa_enabled`.
3. **Disable** → require re-auth (current password AND/OR a current OTP);
   `disable_totp`. Audit `2fa_disabled`.

## 5. Login flow change (the delicate part)
Modify `auth_bp.login`:
1. Verify username+password as today.
2. If the user has `totp_enabled`: **do not** call `login_user()` yet. Set a
   short-lived pending marker in the session (e.g. `session["pending_2fa_uid"]`,
   with a timestamp; never expose role/identity until step 3) and render an OTP
   entry page.
3. `POST /login/2fa` → verify TOTP or a backup code for the pending uid; on
   success `login_user()` and clear the pending marker; on failure increment the
   OTP rate-limit/lockout. Enforce a pending-state timeout (e.g. 5 min).
Keep the existing IP login rate-limiter in front of step 1. "Remember this
device" is **out of scope** for v1 (document as a future option).

## 6. Admin support
Admin endpoint to **disable/reset 2FA** for a locked-out user
(`POST /admin/api/users/<uid>/2fa/disable`), audited. Admins never see secrets.
Optionally surface a "2FA: on/off" column in the users table.

## 7. Self-service email change
Add `PATCH /app/api/me` (or a profile page): require current password, validate
format, enforce uniqueness (already `UNIQUE NOCASE`). If Phase 1's mailer is
enabled, prefer double-opt-in (email a confirmation link to the NEW address
before committing) — otherwise commit immediately with an audit
`email_changed`. Can ship in Phase 1 or 2; recommend Phase 2 to keep Phase 1
purely reset-focused.

## 8. Templates
2FA setup page (QR + secret + confirm), login OTP page, backup-codes display.

## 9. Testing checklist (Phase 2)
- Enroll → confirm with a `pyotp` time-based code (freeze/normalize time in
  tests), wrong code rejected, backup code single-use.
- Login: no-2FA user unchanged; 2FA user blocked until valid OTP; pending state
  times out; OTP brute force locks out.
- Admin disable-2FA restores password-only login.
- Migration v19 applies on a prod DB copy; re-run no-op.
- `py_compile` all changed files.

## 10. File inventory (Phase 2)
- MOD `data/migrations.py` (v19), `auth/store.py`, `auth/models.py` (User: 2fa
  fields + `to_dict`), `auth/auth_routes.py` (login flow + `/login/2fa`),
  `app_routes.py` (profile/security page, email change), `admin/routes.py`
  (disable-2fa, users column), `requirements.txt` (`pyotp`),
  `config`/templates as needed.

---

# Rollout & safety notes
- Apply migrations against a **copy** of the live DB first; both v18 and v19 are
  additive (new tables + `ADD COLUMN` with defaults) so they are safe on the
  populated prod DB, but verify re-run idempotency.
- Deliver each phase as Javier expects: ready-to-deploy files in a zip, every
  `.py` `py_compile`-clean, with a conventional-commit message file.
- Keep relay credentials in `.env` only; confirm `deploy.sh` `PROTECTED` still
  lists exactly `config/config.yaml`, `.env`, `.venv/`.
- Suggested HANDOVER.md updates: add these two phases under §10 backlog and the
  hardening items (secret_key, CSRF, constant-time auth) under §11 prevention.

# Open decisions to confirm before building
1. Phase 1 config **key names / structure** above — accept or adjust.
2. **Reset token TTL** (default 45 min) and whether reset should also invalidate
   the user's existing sessions.
3. Whether to include the **CSRF** hardening in Phase 1 or defer.
4. Phase 2: **encrypt `totp_secret`** (add Fernet) vs store plaintext with a
   documented trade-off.
5. Where **email change** lands (Phase 1 vs 2).
