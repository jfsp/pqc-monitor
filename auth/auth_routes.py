#!/usr/bin/env python3
"""
PQC-Monitor: Auth Routes Blueprint
Handles /login, /logout, /change-password.
Kept deliberately thin — all business logic is in AuthStore.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import time

from flask import (
    Blueprint, request, redirect, url_for,
    render_template_string, session, current_app, jsonify
)

from auth.middleware import (
    login_user, logout_user, current_user,
    require_auth, _get_client_ip, _audit
)
from auth.csrf import issue_token

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth_bp", __name__)


def _get_version() -> str:
    try:
        from version import VERSION
        return VERSION
    except Exception:
        return ""

# Simple in-memory rate limiter: (ip, minute_bucket) → attempt count
_login_attempts: dict[tuple, int] = {}
_MAX_PER_MINUTE = 10


def _rate_limited(ip: str) -> bool:
    bucket = (ip, int(time.time() // 60))
    _login_attempts[bucket] = _login_attempts.get(bucket, 0) + 1
    # Clean up old buckets
    current_min = int(time.time() // 60)
    for key in list(_login_attempts):
        if key[1] < current_min - 2:
            del _login_attempts[key]
    return _login_attempts[bucket] > _MAX_PER_MINUTE


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("app_bp.dashboard_home"))

    error = None
    next_url = request.args.get("next", "")

    if request.method == "POST":
        ip = _get_client_ip()
        if _rate_limited(ip):
            error = "Too many login attempts. Please wait a minute."
            logger.warning(f"Rate limit hit on /login from {ip}")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            provider = current_app.config.get("AUTH_PROVIDER")
            user = provider.authenticate(username, password) if provider else None

            if user:
                login_user(user)
                _audit("login", resource="", detail=f"ip={ip}")
                logger.info(f"Login OK: {username} from {ip}")

                # Forced password change (admin-set temp password / reset policy)
                if getattr(user, "must_change_password", False):
                    return redirect(url_for("auth_bp.change_password"))

                # Build a safe redirect target.
                # next_url may be an absolute URL (e.g. http://host/app/) when
                # the middleware redirected to /login?next=<absolute>.  Extract
                # the path+query portion and validate it is on this host.
                safe_next = url_for("app_bp.dashboard_home")
                if next_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(next_url)
                    if parsed.scheme:
                        # Absolute URL — keep only the path (drop scheme+host)
                        path_only = parsed.path or "/"
                        if parsed.query:
                            path_only += "?" + parsed.query
                    else:
                        path_only = next_url
                    # Allow only relative paths that don't start with //
                    if path_only.startswith("/") and not path_only.startswith("//"):
                        safe_next = path_only

                return redirect(safe_next)
            else:
                error = "Invalid username or password."
                store = current_app.config.get("AUTH_STORE")
                if store:
                    store.log(
                        user_id=None,
                        username=username or "unknown",
                        action="login_failed",
                        ip_address=ip,
                        user_agent=request.headers.get("User-Agent", "")[:256],
                        detail="bad credentials",
                    )
                logger.warning(f"Login failed: {username} from {ip}")

    return render_template_string(_LOGIN_HTML, error=error, next_url=next_url,
                                   version=_get_version(),
                                   csrf_token=issue_token())


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@require_auth
def logout():
    _audit("logout")
    logout_user()
    return redirect(url_for("auth_bp.login"))


# ── Change password ───────────────────────────────────────────────────────────

@auth_bp.route("/change-password", methods=["GET", "POST"])
@require_auth
def change_password():
    user = current_user()
    error = None
    success = None

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        provider = current_app.config.get("AUTH_PROVIDER")
        store    = current_app.config.get("AUTH_STORE")

        if not provider.authenticate(user.username, current_pw):
            error = "Current password is incorrect."
        elif len(new_pw) < 10:
            error = "New password must be at least 10 characters."
        elif new_pw != confirm_pw:
            error = "New passwords do not match."
        else:
            store.set_password(user.id, new_pw)
            # set_password bumps session_epoch (killing all sessions). Re-issue
            # the current device's session so the user stays logged in here,
            # while any OTHER active sessions are invalidated.
            refreshed = store.get_user_by_id(user.id)
            if refreshed:
                login_user(refreshed)
            _audit("password_changed", detail="self-service")
            success = "Password changed successfully."

    return render_template_string(
        _CHANGE_PW_HTML, user=user, error=error, success=success,
        csrf_token=issue_token()
    )


# ── Forgot / reset password ───────────────────────────────────────────────────

_GENERIC_FORGOT_MSG = ("If an account matches that identifier, a password "
                       "reset link has been sent.")


@auth_bp.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    error = None
    message = None

    if request.method == "POST":
        ip = _get_client_ip()
        if _rate_limited(ip):
            error = "Too many requests. Please wait a minute."
        else:
            identifier = request.form.get("identifier", "").strip()
            store  = current_app.config.get("AUTH_STORE")
            mailer = current_app.config.get("MAILER")

            # Look up by username first, then email. Response is generic either
            # way so the form never reveals whether an account exists.
            user = None
            if store and identifier:
                user = (store.get_user_by_username(identifier)
                        or store.get_user_by_email(identifier))

            if user and user.is_active and mailer and mailer.enabled:
                ttl = int(current_app.config.get("RESET_TOKEN_TTL_MIN", 45))
                raw = store.create_reset_token(user.id, ttl_minutes=ttl,
                                               request_ip=ip)
                base = (current_app.config.get("RESET_BASE_URL")
                        or request.host_url).rstrip("/")
                link = f"{base}{url_for('auth_bp.reset_password', token=raw)}"
                subject = "PQC-Monitor password reset"
                text = (
                    f"A password reset was requested for your PQC-Monitor "
                    f"account ({user.username}).\n\n"
                    f"Reset your password (link valid for {ttl} minutes, "
                    f"single use):\n{link}\n\n"
                    f"If you did not request this, ignore this email; your "
                    f"password will not change.\n"
                )
                html = (
                    f"<p>A password reset was requested for your PQC-Monitor "
                    f"account (<strong>{user.username}</strong>).</p>"
                    f"<p><a href=\"{link}\">Reset your password</a> "
                    f"(valid {ttl} minutes, single use).</p>"
                    f"<p>If you did not request this, ignore this email.</p>"
                )
                mailer.send(user.email, subject, text, html)
                store.log(user_id=user.id, username=user.username,
                          action="password_reset_requested",
                          ip_address=ip, detail="link emailed")
            elif user and store:
                # Mailer disabled or off: record the attempt, send nothing.
                store.log(user_id=user.id, username=user.username,
                          action="password_reset_requested",
                          ip_address=ip, detail="mailer disabled")

            message = _GENERIC_FORGOT_MSG

    return render_template_string(_FORGOT_HTML, error=error, message=message,
                                  version=_get_version(),
                                  csrf_token=issue_token())


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    store = current_app.config.get("AUTH_STORE")
    error = None

    if request.method == "POST":
        new_pw     = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if len(new_pw) < 10:
            error = "New password must be at least 10 characters."
        elif new_pw != confirm_pw:
            error = "Passwords do not match."
        else:
            uid = store.consume_reset_token(token) if store else None
            if not uid:
                error = "This reset link is invalid or has expired."
            else:
                # set_password bumps session_epoch, invalidating any existing
                # sessions for this user. The user is NOT auto-logged-in.
                store.set_password(uid, new_pw)
                u = store.get_user_by_id(uid)
                store.log(user_id=uid,
                          username=(u.username if u else "unknown"),
                          action="password_reset_completed",
                          ip_address=_get_client_ip())
                return render_template_string(
                    _RESET_DONE_HTML, version=_get_version())

    # GET (or POST error): only show the form if the token is still valid.
    valid = bool(store and store.peek_reset_token(token))
    return render_template_string(_RESET_HTML, token=token, valid=valid,
                                  error=error, version=_get_version(),
                                  csrf_token=issue_token())


# ── HTML Templates ────────────────────────────────────────────────────────────

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Sign In</title>
<style>
:root {
  --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a;
  --accent:#00d4ff; --text:#e2e8f0; --muted:#64748b;
  --error:#ef4444; --font:'Inter',system-ui,sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:var(--font);
       display:flex; align-items:center; justify-content:center;
       min-height:100vh; }
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:16px; padding:2.5rem; width:100%; max-width:400px; }
.logo { text-align:center; margin-bottom:2rem; }
.logo h1 { font-family:'Space Mono',monospace; color:var(--accent);
           font-size:1.5rem; letter-spacing:.05em; }
.logo p { color:var(--muted); font-size:.82rem; margin-top:.35rem; }
label { display:block; color:var(--muted); font-size:.78rem;
        text-transform:uppercase; letter-spacing:.05em; margin-bottom:.4rem; }
input[type=text], input[type=password] {
  width:100%; background:rgba(255,255,255,.05);
  border:1px solid var(--border); color:var(--text);
  padding:.7rem 1rem; border-radius:8px; font-size:.9rem;
  margin-bottom:1.25rem; outline:none; transition:border-color .2s;
}
input:focus { border-color:var(--accent); }
button {
  width:100%; background:var(--accent); color:#0a0e1a;
  border:none; padding:.75rem; border-radius:8px; font-weight:700;
  font-size:.95rem; cursor:pointer; transition:background .2s;
}
button:hover { background:#33ddff; }
.error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3);
         color:var(--error); padding:.7rem 1rem; border-radius:8px;
         font-size:.83rem; margin-bottom:1rem; }
footer { text-align:center; color:var(--muted); font-size:.7rem;
         margin-top:1.5rem; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>PQC-Monitor</h1>
    <p>Post-Quantum Cryptography Readiness Platform</p>
  </div>
  {% if error %}
  <div class="error">{{ error }}</div>
  {% endif %}
  <form method="post">
    <input type="hidden" name="next" value="{{ next_url }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username"
           autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"
           autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div style="text-align:center;margin-top:1rem">
    <a href="/forgot" style="color:var(--accent);font-size:.8rem">Forgot password?</a>
  </div>
  <footer>PQC-Monitor v{{ version }} &nbsp;·&nbsp; GPL-3.0 &nbsp;·&nbsp; AI-assisted</footer>
</div>
</body>
</html>"""


_CHANGE_PW_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Change Password — PQC-Monitor</title>
<style>
:root { --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a;
        --accent:#00d4ff; --text:#e2e8f0; --muted:#64748b;
        --error:#ef4444; --ok:#22c55e; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif;
       display:flex; align-items:center; justify-content:center; min-height:100vh; }
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:12px; padding:2rem; width:100%; max-width:400px; }
h2 { margin-bottom:1.5rem; font-size:1.1rem; color:var(--accent); }
label { display:block; font-size:.78rem; color:var(--muted); margin-bottom:.3rem; }
input { width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border);
        color:var(--text); padding:.65rem .9rem; border-radius:8px;
        font-size:.88rem; margin-bottom:1rem; outline:none; }
input:focus { border-color:var(--accent); }
button { width:100%; background:var(--accent); color:#0a0e1a; border:none;
         padding:.7rem; border-radius:8px; font-weight:700; cursor:pointer; }
.msg { padding:.7rem 1rem; border-radius:8px; font-size:.83rem; margin-bottom:1rem; }
.error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3); color:var(--error); }
.ok    { background:rgba(34,197,94,.1);  border:1px solid rgba(34,197,94,.3);  color:var(--ok); }
a { color:var(--accent); font-size:.82rem; display:block; margin-top:1rem; text-align:center; }
</style>
</head>
<body>
<div class="card">
  <h2>Change Password</h2>
  {% if error %}<div class="msg error">{{ error }}</div>{% endif %}
  {% if success %}<div class="msg ok">{{ success }}</div>{% endif %}
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label>Current password</label>
    <input type="password" name="current_password" required>
    <label>New password (min 10 characters)</label>
    <input type="password" name="new_password" required>
    <label>Confirm new password</label>
    <input type="password" name="confirm_password" required>
    <button type="submit">Update Password</button>
  </form>
  <a href="/app">← Back to Dashboard</a>
</div>
</body>
</html>"""


# ── Forgot / reset templates (reuse the login card styling) ───────────────────

_FORGOT_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Forgot Password</title>
<style>
:root { --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a; --accent:#00d4ff;
        --text:#e2e8f0; --muted:#64748b; --error:#ef4444; --ok:#22c55e; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif;
       display:flex; align-items:center; justify-content:center; min-height:100vh; }
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:16px; padding:2.5rem; width:100%; max-width:400px; }
h1 { font-family:'Space Mono',monospace; color:var(--accent); font-size:1.3rem;
     text-align:center; margin-bottom:.4rem; }
p.sub { color:var(--muted); font-size:.82rem; text-align:center; margin-bottom:1.5rem; }
label { display:block; color:var(--muted); font-size:.78rem; text-transform:uppercase;
        letter-spacing:.05em; margin-bottom:.4rem; }
input { width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border);
        color:var(--text); padding:.7rem 1rem; border-radius:8px; font-size:.9rem;
        margin-bottom:1.25rem; outline:none; }
input:focus { border-color:var(--accent); }
button { width:100%; background:var(--accent); color:#0a0e1a; border:none;
         padding:.75rem; border-radius:8px; font-weight:700; cursor:pointer; }
.msg { padding:.7rem 1rem; border-radius:8px; font-size:.83rem; margin-bottom:1rem; }
.error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3); color:var(--error); }
.ok    { background:rgba(34,197,94,.1);  border:1px solid rgba(34,197,94,.3);  color:var(--ok); }
a { color:var(--accent); font-size:.8rem; display:block; margin-top:1rem; text-align:center; }
footer { text-align:center; color:var(--muted); font-size:.7rem; margin-top:1.5rem; }
</style></head><body>
<div class="card">
  <h1>PQC-Monitor</h1>
  <p class="sub">Reset your password</p>
  {% if error %}<div class="msg error">{{ error }}</div>{% endif %}
  {% if message %}<div class="msg ok">{{ message }}</div>{% endif %}
  {% if not message %}
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label>Username or email</label>
    <input type="text" name="identifier" autocomplete="username" autofocus required>
    <button type="submit">Send reset link</button>
  </form>
  {% endif %}
  <a href="/login">← Back to sign in</a>
  <footer>PQC-Monitor v{{ version }}</footer>
</div></body></html>"""


_RESET_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Set New Password</title>
<style>
:root { --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a; --accent:#00d4ff;
        --text:#e2e8f0; --muted:#64748b; --error:#ef4444; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif;
       display:flex; align-items:center; justify-content:center; min-height:100vh; }
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:16px; padding:2.5rem; width:100%; max-width:400px; }
h1 { font-family:'Space Mono',monospace; color:var(--accent); font-size:1.3rem;
     text-align:center; margin-bottom:1.5rem; }
label { display:block; color:var(--muted); font-size:.78rem; text-transform:uppercase;
        letter-spacing:.05em; margin-bottom:.4rem; }
input { width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border);
        color:var(--text); padding:.7rem 1rem; border-radius:8px; font-size:.9rem;
        margin-bottom:1.25rem; outline:none; }
input:focus { border-color:var(--accent); }
button { width:100%; background:var(--accent); color:#0a0e1a; border:none;
         padding:.75rem; border-radius:8px; font-weight:700; cursor:pointer; }
.msg { padding:.7rem 1rem; border-radius:8px; font-size:.83rem; margin-bottom:1rem; }
.error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3); color:var(--error); }
a { color:var(--accent); font-size:.8rem; display:block; margin-top:1rem; text-align:center; }
</style></head><body>
<div class="card">
  <h1>Set new password</h1>
  {% if error %}<div class="msg error">{{ error }}</div>{% endif %}
  {% if valid %}
  <form method="post" action="/reset/{{ token }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label>New password (min 10 characters)</label>
    <input type="password" name="new_password" autocomplete="new-password" required>
    <label>Confirm new password</label>
    <input type="password" name="confirm_password" autocomplete="new-password" required>
    <button type="submit">Update password</button>
  </form>
  {% else %}
  <div class="msg error">This reset link is invalid or has expired.</div>
  <a href="/forgot">Request a new link</a>
  {% endif %}
  <a href="/login">← Back to sign in</a>
</div></body></html>"""


_RESET_DONE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Password Updated</title>
<style>
:root { --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a; --accent:#00d4ff;
        --text:#e2e8f0; --muted:#64748b; --ok:#22c55e; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif;
       display:flex; align-items:center; justify-content:center; min-height:100vh; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:16px;
        padding:2.5rem; width:100%; max-width:400px; text-align:center; }
h1 { color:var(--ok); font-size:1.2rem; margin-bottom:1rem; }
p { color:var(--muted); font-size:.85rem; margin-bottom:1.5rem; }
a { color:#0a0e1a; background:var(--accent); text-decoration:none; padding:.7rem 1.2rem;
    border-radius:8px; font-weight:700; font-size:.9rem; }
</style></head><body>
<div class="card">
  <h1>✓ Password updated</h1>
  <p>Your password has been changed and all existing sessions were signed out.
     Please sign in with your new password.</p>
  <a href="/login">Sign in</a>
</div></body></html>"""
