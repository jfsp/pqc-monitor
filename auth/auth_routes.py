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
                                   version=_get_version())


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
            _audit("password_changed", detail="self-service")
            success = "Password changed successfully."

    return render_template_string(
        _CHANGE_PW_HTML, user=user, error=error, success=success
    )


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
    <label for="username">Username</label>
    <input type="text" id="username" name="username"
           autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"
           autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
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
