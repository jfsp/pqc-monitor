#!/usr/bin/env python3
"""
PQC-Monitor: Admin Blueprint
Provides /admin/* routes for user management, domain-list assignment,
and audit log viewing.  Access restricted to ROLE_ADMIN.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging

from flask import (
    Blueprint, jsonify, request, render_template_string,
    current_app, redirect, url_for
)

from auth.middleware import require_admin, current_user, _audit
from auth.models import ROLE_ADMIN, ROLE_ANALYST, ALL_ROLES

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


def _store():
    return current_app.config["AUTH_STORE"]

def _db():
    return current_app.config["PQC_DB"]


# ── Admin SPA shell ───────────────────────────────────────────────────────────

@admin_bp.route("/")
@admin_bp.route("/<path:_>")
@require_admin
def admin_shell(_=None):
    """Serve the admin single-page application."""
    from version import VERSION
    user = current_user()
    return render_template_string(_ADMIN_HTML, user=user, version=VERSION)


# ── User API ──────────────────────────────────────────────────────────────────

@admin_bp.route("/api/users")
@require_admin
def api_list_users():
    users = _store().list_users()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/api/users", methods=["POST"])
@require_admin
def api_create_user():
    data = request.get_json() or {}
    required = ("username", "email", "password", "role")
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"{f} is required"}), 400
    if data["role"] not in ALL_ROLES:
        return jsonify({"error": "invalid role"}), 400
    try:
        user = _store().create_user(
            username=data["username"],
            email=data["email"],
            password=data["password"],
            role=data["role"],
            full_name=data.get("full_name", ""),
            created_by=current_user().id,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"error": "Username or email already exists"}), 409
        return jsonify({"error": str(e)}), 500
    _audit("user.created", resource=user.username,
           detail=f"role={user.role}")
    return jsonify(user.to_dict()), 201


@admin_bp.route("/api/users/<int:uid>")
@require_admin
def api_get_user(uid):
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user.to_dict())


@admin_bp.route("/api/users/<int:uid>", methods=["PATCH"])
@require_admin
def api_update_user(uid):
    data = request.get_json() or {}
    # Prevent admin from accidentally removing their own admin role
    me = current_user()
    if uid == me.id and data.get("role") == ROLE_ANALYST:
        return jsonify({"error": "Cannot demote your own account"}), 400
    try:
        user = _store().update_user(uid, **{
            k: data[k] for k in ("email","full_name","role","is_active") if k in data
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not user:
        return jsonify({"error": "not found"}), 404
    _audit("user.updated", resource=user.username,
           detail=json.dumps({k: data[k] for k in data if k != "password"}))
    return jsonify(user.to_dict())


@admin_bp.route("/api/users/<int:uid>/password", methods=["POST"])
@require_admin
def api_reset_password(uid):
    data = request.get_json() or {}
    new_pw = data.get("password", "")
    if len(new_pw) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    _store().set_password(uid, new_pw)
    _audit("user.password_reset", resource=user.username)
    return jsonify({"ok": True})


@admin_bp.route("/api/users/<int:uid>", methods=["DELETE"])
@require_admin
def api_delete_user(uid):
    me = current_user()
    if uid == me.id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    _store().delete_user(uid)
    _audit("user.deleted", resource=user.username)
    return jsonify({"ok": True})


# ── Domain-list assignment API ────────────────────────────────────────────────

@admin_bp.route("/api/users/<int:uid>/domain-lists")
@require_admin
def api_get_user_domain_lists(uid):
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    db   = _db()
    all_lists = db.get_domain_lists()
    assigned  = set(user.domain_list_ids)
    for dl in all_lists:
        dl["assigned"] = dl["id"] in assigned
    return jsonify(all_lists)


@admin_bp.route("/api/users/<int:uid>/domain-lists", methods=["PUT"])
@require_admin
def api_set_user_domain_lists(uid):
    data = request.get_json() or {}
    ids  = data.get("domain_list_ids", [])
    if not isinstance(ids, list):
        return jsonify({"error": "domain_list_ids must be a list"}), 400
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    _store().set_domain_lists(uid, ids, granted_by=current_user().id)
    _audit("user.domain_lists_updated",
           resource=user.username, detail=f"lists={ids}")
    return jsonify({"ok": True, "domain_list_ids": ids})


# ── Domain lists (admin view of all lists) ────────────────────────────────────

@admin_bp.route("/api/domain-lists")
@require_admin
def api_admin_domain_lists():
    db    = _db()
    store = _store()
    users = store.list_users()
    # Use full fetch to get domains_json so we can report domain count
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT id, name, query, created_at, updated_at, domains_json "
            "FROM domain_lists ORDER BY created_at DESC"
        ).fetchall()
    import json as _json
    lists = []
    for row in rows:
        d = dict(row)
        try:
            d["domain_count"] = len(_json.loads(d.get("domains_json") or "[]"))
        except Exception:
            d["domain_count"] = 0
        d.pop("domains_json", None)   # don't send full list in index
        d["user_count"] = sum(1 for u in users if d["id"] in u.domain_list_ids)
        lists.append(d)
    return jsonify(lists)


@admin_bp.route("/api/domain-lists/<int:list_id>")
@require_admin
def api_get_domain_list(list_id):
    dl = _db().get_domain_list_full(list_id)
    if not dl:
        return jsonify({"error": "not found"}), 404
    return jsonify(dl)


@admin_bp.route("/api/domain-lists", methods=["POST"])
@require_admin
def api_create_domain_list():
    data    = request.get_json() or {}
    name    = (data.get("name") or "").strip()
    domains = data.get("domains") or []
    query   = (data.get("query") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not isinstance(domains, list):
        return jsonify({"error": "domains must be a list"}), 400
    domains = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    list_id = _db().save_domain_list(name, domains, query)
    _audit("domain_list.created", resource=name,
           detail=f"{len(domains)} domains")
    return jsonify({"id": list_id, "name": name,
                    "domains": domains, "count": len(domains)}), 201


@admin_bp.route("/api/domain-lists/<int:list_id>", methods=["PATCH"])
@require_admin
def api_update_domain_list(list_id):
    data    = request.get_json() or {}
    name    = data.get("name")
    query   = data.get("query")
    domains = data.get("domains")
    if domains is not None:
        if not isinstance(domains, list):
            return jsonify({"error": "domains must be a list"}), 400
        domains = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    ok = _db().update_domain_list(list_id, name=name, domains=domains, query=query)
    if not ok:
        return jsonify({"error": "not found"}), 404
    _audit("domain_list.updated", resource=str(list_id),
           detail=f"domains={len(domains) if domains is not None else '?'}")
    return jsonify({"ok": True})


@admin_bp.route("/api/domain-lists/<int:list_id>", methods=["DELETE"])
@require_admin
def api_delete_domain_list(list_id):
    dl = _db().get_domain_list_full(list_id)
    if not dl:
        return jsonify({"error": "not found"}), 404
    _db().delete_domain_list(list_id)
    _audit("domain_list.deleted", resource=dl.get("name", str(list_id)))
    return jsonify({"ok": True})


@admin_bp.route("/api/domains/known")
@require_admin
def api_known_domains():
    """All distinct domains that have assessment data — for the list editor picker."""
    return jsonify(_db().get_all_known_domains())


# ── Audit log ─────────────────────────────────────────────────────────────────

@admin_bp.route("/api/audit-log")
@require_admin
def api_audit_log():
    limit   = min(int(request.args.get("limit", 200)), 1000)
    user_id = request.args.get("user_id")
    events  = _store().get_audit_log(
        limit=limit,
        user_id=int(user_id) if user_id else None
    )
    return jsonify([e.to_dict() for e in events])


# ── Current-user info (used by app SPA) ───────────────────────────────────────

@admin_bp.route("/api/me")
@require_admin
def api_me():
    return jsonify(current_user().to_dict())


# ── Admin SPA HTML ────────────────────────────────────────────────────────────

_ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Admin</title>
<style>
:root {
  --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a;
  --accent:#00d4ff; --accent2:#7c3aed; --text:#e2e8f0;
  --muted:#64748b; --critical:#ef4444; --ready:#22c55e;
  --weak:#f97316; --moderate:#eab308;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text);
       font-family:'Inter',system-ui,sans-serif; min-height:100vh; }

/* Header */
.hdr { background:linear-gradient(135deg,#0f1629,#1a1040);
       border-bottom:1px solid var(--border); height:60px;
       display:flex; align-items:center; justify-content:space-between;
       padding:0 1.5rem; }
.logo { font-family:'Space Mono',monospace; color:var(--accent);
        font-size:1rem; letter-spacing:.05em; }
.logo em { color:var(--accent2); font-style:normal; }
.hdr-right { display:flex; gap:.75rem; align-items:center; }
.hdr-right a { color:var(--muted); font-size:.82rem; text-decoration:none; }
.hdr-right a:hover { color:var(--accent); }

/* Layout */
.layout { display:flex; min-height:calc(100vh - 60px); }
.sidebar { width:220px; background:var(--panel); border-right:1px solid var(--border);
           padding:1.25rem 0; flex-shrink:0; }
.sidebar a {
  display:flex; align-items:center; gap:.6rem;
  padding:.65rem 1.25rem; color:var(--muted); font-size:.85rem;
  text-decoration:none; transition:all .15s; border-left:3px solid transparent;
}
.sidebar a:hover, .sidebar a.active {
  color:var(--text); background:rgba(0,212,255,.07);
  border-left-color:var(--accent);
}
.sidebar .section-label {
  color:var(--muted); font-size:.68rem; text-transform:uppercase;
  letter-spacing:.08em; padding:.75rem 1.25rem .35rem;
}
.main { flex:1; padding:1.75rem; overflow-y:auto; }

/* Page heading */
.page-hdr { display:flex; align-items:center; justify-content:space-between;
            margin-bottom:1.5rem; }
.page-title { font-size:1.1rem; font-weight:600; }

/* Card */
.card { background:var(--panel); border:1px solid var(--border);
        border-radius:12px; overflow:hidden; margin-bottom:1.5rem; }
.card-hdr { padding:.9rem 1.25rem; border-bottom:1px solid var(--border);
            display:flex; align-items:center; justify-content:space-between; }
.card-title { font-family:'Space Mono',monospace; font-size:.8rem;
              color:var(--accent); text-transform:uppercase; letter-spacing:.08em; }
.card-body { padding:1.25rem; }

/* Table */
.tbl { width:100%; border-collapse:collapse; font-size:.83rem; }
.tbl th { text-align:left; padding:.5rem .75rem; color:var(--muted);
          font-size:.7rem; text-transform:uppercase; letter-spacing:.05em;
          border-bottom:1px solid var(--border); font-weight:500; }
.tbl td { padding:.6rem .75rem; border-bottom:1px solid rgba(30,45,74,.5); }
.tbl tr:last-child td { border-bottom:none; }
.tbl tr:hover td { background:rgba(0,212,255,.03); }

/* Badges */
.badge { display:inline-block; padding:.15rem .55rem; border-radius:4px;
         font-size:.7rem; font-weight:600; }
.badge-admin    { background:rgba(124,58,237,.2); color:#a78bfa; }
.badge-analyst  { background:rgba(0,212,255,.1);  color:var(--accent); }
.badge-active   { background:rgba(34,197,94,.1);  color:var(--ready); }
.badge-inactive { background:rgba(100,116,139,.1);color:var(--muted); }

/* Buttons */
.btn { background:var(--accent); color:#0a0e1a; border:none; padding:.5rem 1.1rem;
       border-radius:8px; font-weight:600; cursor:pointer; font-size:.83rem;
       transition:all .15s; }
.btn:hover { background:#33ddff; }
.btn-sm { padding:.3rem .7rem; font-size:.75rem; }
.btn-outline { background:transparent; border:1px solid var(--accent);
               color:var(--accent); }
.btn-danger  { background:var(--critical); color:#fff; }
.btn-ghost   { background:transparent; border:1px solid var(--border);
               color:var(--muted); }
.btn-ghost:hover { border-color:var(--accent); color:var(--accent); }

/* Form */
.form-grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
.form-group { display:flex; flex-direction:column; gap:.35rem; }
.form-group label { font-size:.75rem; color:var(--muted);
                    text-transform:uppercase; letter-spacing:.04em; }
input[type=text], input[type=email], input[type=password], select {
  background:rgba(255,255,255,.05); border:1px solid var(--border);
  color:var(--text); padding:.6rem .85rem; border-radius:8px; font-size:.875rem;
  outline:none; transition:border-color .2s;
}
input:focus, select:focus { border-color:var(--accent); }
select option { background:var(--panel); }
.form-actions { display:flex; gap:.75rem; justify-content:flex-end;
                margin-top:1.25rem; }

/* Modal */
.modal-bg { display:none; position:fixed; inset:0; background:rgba(0,0,0,.6);
            z-index:100; align-items:center; justify-content:center; }
.modal-bg.open { display:flex; }
.modal { background:var(--panel); border:1px solid var(--border); border-radius:16px;
         padding:1.75rem; width:100%; max-width:520px; max-height:85vh;
         overflow-y:auto; }
.modal h3 { margin-bottom:1.25rem; font-size:1rem; color:var(--accent); }

/* Alert */
.alert { padding:.65rem 1rem; border-radius:8px; font-size:.82rem;
         margin-bottom:1rem; display:none; }
.alert.show { display:block; }
.alert-ok    { background:rgba(34,197,94,.1);  border:1px solid rgba(34,197,94,.3);  color:var(--ready); }
.alert-error { background:rgba(239,68,68,.1);  border:1px solid rgba(239,68,68,.3);  color:var(--critical); }

/* Checkbox list */
.check-list { max-height:220px; overflow-y:auto; border:1px solid var(--border);
              border-radius:8px; padding:.5rem; }
.check-item { display:flex; align-items:center; gap:.6rem; padding:.4rem .5rem;
              border-radius:6px; font-size:.83rem; cursor:pointer; }
.check-item:hover { background:rgba(0,212,255,.05); }
.check-item input { width:auto; margin:0; }

/* Audit table */
.action-login  { color:var(--ready); }
.action-logout { color:var(--muted); }
.action-failed { color:var(--critical); }
.action-other  { color:var(--accent); }

/* Views */
.view { display:none; }
.view.active { display:block; }
</style>
</head>
<body>

<div class="hdr">
  <div class="logo">PQC<em>-</em>Monitor <span style="color:var(--muted);font-size:.75rem;margin-left:.5rem">Administration &nbsp;v{{ version }}</span></div>
  <div class="hdr-right">
    <span style="color:var(--text);font-size:.83rem">{{ user.username }}</span>
    <a href="/app">↗ Dashboard</a>
    <a href="/change-password">Password</a>
    <a href="/logout">Sign out</a>
  </div>
</div>

<div class="layout">
  <nav class="sidebar">
    <div class="section-label">Management</div>
    <a href="#" onclick="showView('users')"    class="active" id="nav-users">👤 Users</a>
    <a href="#" onclick="showView('lists')"    id="nav-lists">📋 Domain Lists</a>
    <div class="section-label">Monitoring</div>
    <a href="#" onclick="showView('audit')"    id="nav-audit">📜 Audit Log</a>
  </nav>

  <div class="main">

    <!-- ── Users view ── -->
    <div id="view-users" class="view active">
      <div class="page-hdr">
        <div class="page-title">User Management</div>
        <button class="btn" onclick="openCreateUser()">+ New User</button>
      </div>
      <div id="users-alert" class="alert"></div>
      <div class="card">
        <div class="card-hdr"><div class="card-title">Users</div>
          <button class="btn-ghost btn-sm" onclick="loadUsers()">↻ Refresh</button>
        </div>
        <div class="card-body" style="padding:0">
          <table class="tbl">
            <thead><tr>
              <th>Username</th><th>Full Name</th><th>Email</th>
              <th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th>
            </tr></thead>
            <tbody id="users-tbody">
              <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Domain lists view ── -->
    <div id="view-lists" class="view">
      <div class="page-hdr">
        <div class="page-title">Domain Lists</div>
        <button class="btn" onclick="openCreateList()">+ New List</button>
      </div>
      <div id="lists-alert" class="alert"></div>
      <div class="card">
        <div class="card-hdr">
          <div class="card-title">All Domain Lists</div>
          <button class="btn-ghost btn-sm" onclick="loadDomainLists()">↻ Refresh</button>
        </div>
        <div class="card-body" style="padding:0">
          <table class="tbl">
            <thead><tr>
              <th>ID</th><th>Name</th><th>Query</th><th>Domains</th>
              <th>Updated</th><th>Users</th><th>Actions</th>
            </tr></thead>
            <tbody id="lists-tbody">
              <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Audit log view ── -->
    <div id="view-audit" class="view">
      <div class="page-hdr">
        <div class="page-title">Audit Log</div>
        <button class="btn-ghost btn-sm" onclick="loadAudit()">↻ Refresh</button>
      </div>
      <div class="card">
        <div class="card-body" style="padding:0">
          <table class="tbl">
            <thead><tr>
              <th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>IP</th><th>Detail</th>
            </tr></thead>
            <tbody id="audit-tbody">
              <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div><!-- /main -->
</div><!-- /layout -->

<!-- ── Create / Edit User Modal ── -->
<div class="modal-bg" id="modal-user">
  <div class="modal">
    <h3 id="modal-user-title">New User</h3>
    <div id="modal-alert" class="alert"></div>
    <div class="form-grid">
      <div class="form-group">
        <label>Username *</label>
        <input type="text" id="f-username" autocomplete="off">
      </div>
      <div class="form-group">
        <label>Full Name</label>
        <input type="text" id="f-fullname">
      </div>
      <div class="form-group">
        <label>Email *</label>
        <input type="email" id="f-email">
      </div>
      <div class="form-group">
        <label>Role *</label>
        <select id="f-role">
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div class="form-group">
        <label id="f-pw-label">Password * (min 10 chars)</label>
        <input type="password" id="f-password" autocomplete="new-password">
      </div>
      <div class="form-group">
        <label>Status</label>
        <select id="f-active">
          <option value="1">Active</option>
          <option value="0">Disabled</option>
        </select>
      </div>
    </div>
    <div class="form-group" style="margin-top:1rem" id="f-domain-lists-group">
      <label>Assigned Domain Lists (Analyst only)</label>
      <div class="check-list" id="f-domain-lists"></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-user')">Cancel</button>
      <button class="btn" id="modal-user-submit" onclick="submitUserModal()">Create User</button>
    </div>
  </div>
</div>

<!-- ── Reset Password Modal ── -->
<div class="modal-bg" id="modal-reset-pw">
  <div class="modal">
    <h3>Reset Password — <span id="reset-username"></span></h3>
    <div class="form-group" style="margin-bottom:1rem">
      <label>New Password (min 10 chars)</label>
      <input type="password" id="reset-pw-input" autocomplete="new-password">
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-reset-pw')">Cancel</button>
      <button class="btn" onclick="submitResetPw()">Set Password</button>
    </div>
  </div>
</div>

<!-- ── Domain List Editor Modal ── -->
<div class="modal-bg" id="modal-list-editor">
  <div class="modal" style="max-width:780px">
    <h3 id="modal-list-title">New Domain List</h3>
    <div id="modal-list-alert" class="alert"></div>

    <div class="form-grid" style="margin-bottom:1rem">
      <div class="form-group">
        <label>List Name *</label>
        <input type="text" id="fl-name" placeholder="e.g. Spain Finance">
      </div>
      <div class="form-group">
        <label>Query / Description</label>
        <input type="text" id="fl-query" placeholder="e.g. financial institutions in Spain">
      </div>
    </div>

    <!-- Domain picker: two-pane -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem">

      <!-- Left: known domains from DB -->
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem">
          <label style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">
            Known Domains (from scan data)
          </label>
          <span id="known-count" style="font-size:.7rem;color:var(--muted)"></span>
        </div>
        <input type="text" id="fl-search" placeholder="Filter domains…"
               style="margin-bottom:.4rem;width:100%;font-size:.8rem"
               oninput="filterKnown()">
        <div class="check-list" id="fl-known-list" style="max-height:260px">
          <div style="color:var(--muted);font-size:.8rem;padding:.5rem">Loading…</div>
        </div>
        <div style="margin-top:.4rem;display:flex;gap:.5rem">
          <button class="btn-ghost btn-sm" onclick="selectAllVisible()">Select all visible</button>
          <button class="btn-ghost btn-sm" onclick="clearKnownSelection()">Clear</button>
        </div>
      </div>

      <!-- Right: current list members -->
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem">
          <label style="font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">
            In This List
          </label>
          <span id="list-member-count" style="font-size:.7rem;color:var(--muted)"></span>
        </div>

        <!-- Free-text add -->
        <div style="display:flex;gap:.4rem;margin-bottom:.4rem">
          <input type="text" id="fl-add-input"
                 placeholder="Type or paste domain(s)…"
                 style="flex:1;font-size:.8rem"
                 onkeydown="if(event.key==='Enter'){addFreeText();event.preventDefault()}">
          <button class="btn btn-sm" onclick="addFreeText()">Add</button>
        </div>
        <div style="font-size:.7rem;color:var(--muted);margin-bottom:.4rem">
          Comma- or newline-separated bulk paste accepted
        </div>

        <!-- Member list -->
        <div id="fl-member-list"
             style="max-height:260px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:.4rem">
          <div style="color:var(--muted);font-size:.8rem;padding:.5rem">No domains yet</div>
        </div>
        <div style="margin-top:.4rem;display:flex;justify-content:space-between;align-items:center">
          <button class="btn-ghost btn-sm" onclick="clearAllMembers()">Clear all</button>
          <button class="btn-ghost btn-sm" onclick="sortMembers()">A→Z sort</button>
        </div>
      </div>
    </div>

    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-list-editor')">Cancel</button>
      <button class="btn" id="modal-list-submit" onclick="submitListModal()">Create List</button>
    </div>
  </div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let _editUserId = null;
let _resetUserId = null;
let _allDomainLists = [];

// ── Navigation ────────────────────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  document.getElementById('nav-' + name)?.classList.add('active');
  if (name === 'users')  loadUsers();
  if (name === 'lists')  loadDomainLists();
  if (name === 'audit')  loadAudit();
}

// ── Users ─────────────────────────────────────────────────────────────────────
async function loadUsers() {
  const r = await fetch('/admin/api/users');
  const users = await r.json();
  const tbody = document.getElementById('users-tbody');
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted)">No users yet.</td></tr>';
    return;
  }
  tbody.innerHTML = users.map(u => `<tr>
    <td style="font-family:monospace;font-size:.82rem">${u.username}</td>
    <td>${u.full_name||'—'}</td>
    <td style="color:var(--muted);font-size:.78rem">${u.email}</td>
    <td><span class="badge badge-${u.role}">${u.role}</span></td>
    <td><span class="badge ${u.is_active ? 'badge-active' : 'badge-inactive'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
    <td style="color:var(--muted);font-size:.75rem">${(u.last_login||'Never').slice(0,16)}</td>
    <td>
      <button class="btn btn-outline btn-sm" onclick="openEditUser(${u.id})">Edit</button>
      <button class="btn btn-ghost btn-sm" onclick="openResetPw(${u.id},'${u.username}')">Password</button>
      <button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id},'${u.username}')">Delete</button>
    </td>
  </tr>`).join('');
}

function openCreateUser() {
  _editUserId = null;
  document.getElementById('modal-user-title').textContent = 'New User';
  document.getElementById('modal-user-submit').textContent = 'Create User';
  document.getElementById('f-pw-label').textContent = 'Password * (min 10 chars)';
  ['f-username','f-fullname','f-email','f-password'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('f-role').value = 'analyst';
  document.getElementById('f-active').value = '1';
  document.getElementById('f-username').disabled = false;
  hideAlert('modal-alert');
  loadDomainListCheckboxes(null);
  document.getElementById('modal-user').classList.add('open');
}

async function openEditUser(uid) {
  _editUserId = uid;
  const r = await fetch(`/admin/api/users/${uid}`);
  const u = await r.json();
  document.getElementById('modal-user-title').textContent = `Edit User: ${u.username}`;
  document.getElementById('modal-user-submit').textContent = 'Save Changes';
  document.getElementById('f-pw-label').textContent = 'New Password (leave blank to keep)';
  document.getElementById('f-username').value = u.username;
  document.getElementById('f-username').disabled = true;
  document.getElementById('f-fullname').value = u.full_name || '';
  document.getElementById('f-email').value = u.email;
  document.getElementById('f-role').value = u.role;
  document.getElementById('f-active').value = u.is_active ? '1' : '0';
  document.getElementById('f-password').value = '';
  hideAlert('modal-alert');
  loadDomainListCheckboxes(u);
  document.getElementById('modal-user').classList.add('open');
}

async function loadDomainListCheckboxes(user) {
  const container = document.getElementById('f-domain-lists');
  const r = await fetch('/admin/api/domain-lists');
  _allDomainLists = await r.json();
  const assigned = new Set((user?.domain_list_ids) || []);
  const role = document.getElementById('f-role').value;
  document.getElementById('f-domain-lists-group').style.display =
    (role === 'analyst') ? 'block' : 'none';
  container.innerHTML = _allDomainLists.map(dl =>
    `<label class="check-item">
      <input type="checkbox" value="${dl.id}" ${assigned.has(dl.id) ? 'checked' : ''}>
      <span>${dl.name}</span>
      <span style="color:var(--muted);font-size:.72rem;margin-left:auto">#${dl.id}</span>
    </label>`
  ).join('') || '<div style="color:var(--muted);font-size:.82rem;padding:.5rem">No domain lists yet. Create one via the Scanner.</div>';
}

document.getElementById('f-role')?.addEventListener('change', () => {
  const role = document.getElementById('f-role').value;
  document.getElementById('f-domain-lists-group').style.display =
    role === 'analyst' ? 'block' : 'none';
});

async function submitUserModal() {
  const username  = document.getElementById('f-username').value.trim();
  const email     = document.getElementById('f-email').value.trim();
  const fullname  = document.getElementById('f-fullname').value.trim();
  const role      = document.getElementById('f-role').value;
  const active    = document.getElementById('f-active').value === '1';
  const password  = document.getElementById('f-password').value;

  const selectedLists = [...document.querySelectorAll('#f-domain-lists input:checked')]
    .map(cb => parseInt(cb.value));

  if (_editUserId) {
    // Update existing
    const body = { email, full_name: fullname, role, is_active: active };
    const r = await fetch(`/admin/api/users/${_editUserId}`, {
      method:'PATCH', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.error) { showAlert('modal-alert', d.error, 'error'); return; }

    // Reset password if provided
    if (password) {
      const pr = await fetch(`/admin/api/users/${_editUserId}/password`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({password})
      });
      const pd = await pr.json();
      if (pd.error) { showAlert('modal-alert', pd.error, 'error'); return; }
    }

    // Update domain lists
    await fetch(`/admin/api/users/${_editUserId}/domain-lists`, {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({domain_list_ids: selectedLists})
    });

    closeModal('modal-user');
    showPageAlert('users-alert', 'User updated successfully.', 'ok');
    loadUsers();
  } else {
    // Create new
    if (!password) { showAlert('modal-alert', 'Password is required for new users.', 'error'); return; }
    const r = await fetch('/admin/api/users', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username, email, password, role, full_name: fullname})
    });
    const d = await r.json();
    if (d.error) { showAlert('modal-alert', d.error, 'error'); return; }

    // Assign domain lists
    if (selectedLists.length) {
      await fetch(`/admin/api/users/${d.id}/domain-lists`, {
        method:'PUT', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({domain_list_ids: selectedLists})
      });
    }
    closeModal('modal-user');
    showPageAlert('users-alert', `User "${username}" created.`, 'ok');
    loadUsers();
  }
}

async function deleteUser(uid, username) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  const r = await fetch(`/admin/api/users/${uid}`, {method:'DELETE'});
  const d = await r.json();
  if (d.error) { showPageAlert('users-alert', d.error, 'error'); return; }
  showPageAlert('users-alert', `User "${username}" deleted.`, 'ok');
  loadUsers();
}

function openResetPw(uid, username) {
  _resetUserId = uid;
  document.getElementById('reset-username').textContent = username;
  document.getElementById('reset-pw-input').value = '';
  document.getElementById('modal-reset-pw').classList.add('open');
}

async function submitResetPw() {
  const pw = document.getElementById('reset-pw-input').value;
  if (pw.length < 10) { alert('Password must be at least 10 characters.'); return; }
  const r = await fetch(`/admin/api/users/${_resetUserId}/password`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pw})
  });
  const d = await r.json();
  closeModal('modal-reset-pw');
  if (d.ok) showPageAlert('users-alert', 'Password reset successfully.', 'ok');
  else showPageAlert('users-alert', d.error || 'Error resetting password.', 'error');
}

// ── Domain Lists ──────────────────────────────────────────────────────────────

let _editListId   = null;
let _listMembers  = [];
let _knownDomains = [];

async function loadDomainLists() {
  const r = await fetch('/admin/api/domain-lists');
  const lists = await r.json();
  const tbody = document.getElementById('lists-tbody');
  if (!lists.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No domain lists yet. Click + New List to create one.</td></tr>';
    return;
  }
  tbody.innerHTML = lists.map(dl => `<tr>
    <td style="font-family:monospace;font-size:.82rem">#${dl.id}</td>
    <td style="font-weight:500">${esc(dl.name)}</td>
    <td style="color:var(--muted);font-size:.78rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(dl.query||'')}">${esc(dl.query||'—')}</td>
    <td style="font-family:monospace;font-size:.78rem;text-align:center">${dl.domain_count ?? 0}</td>
    <td style="color:var(--muted);font-size:.75rem">${(dl.updated_at||dl.created_at||'').slice(0,10)||'—'}</td>
    <td style="text-align:center"><span style="color:var(--accent)">${dl.user_count||0}</span></td>
    <td>
      <button class="btn btn-outline btn-sm" onclick="openEditList(${dl.id})">Edit</button>
      <button class="btn btn-danger btn-sm"  onclick="deleteList(${dl.id},'${esc(dl.name)}')">Delete</button>
    </td>
  </tr>`).join('');
}

async function openCreateList() {
  _editListId = null;
  _listMembers = [];
  document.getElementById('modal-list-title').textContent  = 'New Domain List';
  document.getElementById('modal-list-submit').textContent = 'Create List';
  document.getElementById('fl-name').value   = '';
  document.getElementById('fl-query').value  = '';
  document.getElementById('fl-search').value = '';
  document.getElementById('fl-add-input').value = '';
  hideAlert('modal-list-alert');
  await _loadKnownDomains();
  _renderMembers();
  document.getElementById('modal-list-editor').classList.add('open');
}

async function openEditList(listId) {
  _editListId = listId;
  const r  = await fetch(`/admin/api/domain-lists/${listId}`);
  const dl = await r.json();
  if (dl.error) { showPageAlert('lists-alert', dl.error, 'error'); return; }
  document.getElementById('modal-list-title').textContent  = `Edit List: ${esc(dl.name)}`;
  document.getElementById('modal-list-submit').textContent = 'Save Changes';
  document.getElementById('fl-name').value   = dl.name  || '';
  document.getElementById('fl-query').value  = dl.query || '';
  document.getElementById('fl-search').value = '';
  document.getElementById('fl-add-input').value = '';
  _listMembers = [...(dl.domains || [])];
  hideAlert('modal-list-alert');
  await _loadKnownDomains();
  _renderMembers();
  document.getElementById('modal-list-editor').classList.add('open');
}

async function _loadKnownDomains() {
  try {
    const r = await fetch('/admin/api/domains/known');
    _knownDomains = await r.json();
  } catch(e) { _knownDomains = []; }
  const el = document.getElementById('known-count');
  if (el) el.textContent = `${_knownDomains.length} available`;
  _renderKnown('');
}

function _renderKnown(filter) {
  const container = document.getElementById('fl-known-list');
  if (!container) return;
  const f     = (filter || '').toLowerCase();
  const shown = f ? _knownDomains.filter(d => d.toLowerCase().includes(f)) : _knownDomains;
  if (!shown.length) {
    container.innerHTML = `<div style="color:var(--muted);font-size:.8rem;padding:.5rem">${
      f ? 'No matching domains' : 'No scan data yet — add domains manually on the right'}</div>`;
    return;
  }
  const memberSet = new Set(_listMembers);
  container.innerHTML = shown.map(d => `<label class="check-item" title="${esc(d)}">
    <input type="checkbox" value="${esc(d)}" ${memberSet.has(d) ? 'checked' : ''}
           onchange="toggleKnown('${esc(d)}',this.checked)">
    <span style="font-family:monospace;font-size:.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d)}</span>
  </label>`).join('');
}

function filterKnown() {
  _renderKnown(document.getElementById('fl-search').value);
}

function toggleKnown(domain, checked) {
  if (checked) { if (!_listMembers.includes(domain)) _listMembers.push(domain); }
  else { _listMembers = _listMembers.filter(d => d !== domain); }
  _renderMembers();
}

function selectAllVisible() {
  const f = (document.getElementById('fl-search').value || '').toLowerCase();
  const shown = f ? _knownDomains.filter(d => d.toLowerCase().includes(f)) : _knownDomains;
  shown.forEach(d => { if (!_listMembers.includes(d)) _listMembers.push(d); });
  _renderMembers();
  _renderKnown(document.getElementById('fl-search').value);
}

function clearKnownSelection() {
  const f = (document.getElementById('fl-search').value || '').toLowerCase();
  const shown = new Set(f ? _knownDomains.filter(d => d.toLowerCase().includes(f)) : _knownDomains);
  _listMembers = _listMembers.filter(d => !shown.has(d));
  _renderMembers();
  _renderKnown(document.getElementById('fl-search').value);
}

function addFreeText() {
  const input = document.getElementById('fl-add-input');
  const added = input.value.split(/[\n,\s]+/)
    .map(s => s.trim().toLowerCase())
    .filter(s => s.length > 2 && s.includes('.'));
  added.forEach(d => { if (!_listMembers.includes(d)) _listMembers.push(d); });
  input.value = '';
  _renderMembers();
  _renderKnown(document.getElementById('fl-search').value);
}

function removeMember(domain) {
  _listMembers = _listMembers.filter(d => d !== domain);
  _renderMembers();
  _renderKnown(document.getElementById('fl-search').value);
}

function clearAllMembers() {
  if (!_listMembers.length) return;
  if (!confirm('Remove all domains from this list?')) return;
  _listMembers = [];
  _renderMembers();
  _renderKnown(document.getElementById('fl-search').value);
}

function sortMembers() { _listMembers.sort(); _renderMembers(); }

function _renderMembers() {
  const container = document.getElementById('fl-member-list');
  const countEl   = document.getElementById('list-member-count');
  if (countEl) countEl.textContent = `${_listMembers.length} domain${_listMembers.length !== 1 ? 's' : ''}`;
  if (!container) return;
  if (!_listMembers.length) {
    container.innerHTML = '<div style="color:var(--muted);font-size:.8rem;padding:.5rem">No domains yet</div>';
    return;
  }
  container.innerHTML = _listMembers.map(d => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:.3rem .4rem;border-radius:5px;gap:.5rem"
         onmouseover="this.style.background='rgba(0,212,255,.05)'" onmouseout="this.style.background=''">
      <span style="font-family:monospace;font-size:.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1" title="${esc(d)}">${esc(d)}</span>
      <button onclick="removeMember('${esc(d)}')"
              style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:.9rem;padding:0 .25rem;flex-shrink:0;line-height:1"
              onmouseover="this.style.color='var(--critical)'" onmouseout="this.style.color='var(--muted)'" title="Remove">✕</button>
    </div>`).join('');
}

async function submitListModal() {
  const name  = document.getElementById('fl-name').value.trim();
  const query = document.getElementById('fl-query').value.trim();
  if (!name) { showAlert('modal-list-alert', 'List name is required.', 'error'); return; }
  if (!_listMembers.length && !confirm('Save list with no domains? You can add them later.')) return;

  const body = JSON.stringify({ name, query, domains: _listMembers });
  if (_editListId) {
    const r = await fetch(`/admin/api/domain-lists/${_editListId}`, {
      method:'PATCH', headers:{'Content-Type':'application/json'}, body
    });
    const d = await r.json();
    if (d.error) { showAlert('modal-list-alert', d.error, 'error'); return; }
    closeModal('modal-list-editor');
    showPageAlert('lists-alert', `List "${name}" updated — ${_listMembers.length} domains.`, 'ok');
  } else {
    const r = await fetch('/admin/api/domain-lists', {
      method:'POST', headers:{'Content-Type':'application/json'}, body
    });
    const d = await r.json();
    if (d.error) { showAlert('modal-list-alert', d.error, 'error'); return; }
    closeModal('modal-list-editor');
    showPageAlert('lists-alert', `List "${name}" created — ${_listMembers.length} domains.`, 'ok');
  }
  loadDomainLists();
  // refresh user-modal domain picker if it's open
  if (document.getElementById('modal-user').classList.contains('open'))
    loadDomainListCheckboxes(null);
}

async function deleteList(listId, name) {
  if (!confirm(`Delete list "${name}"?\nUser assignments for this list will be removed. Scan data is not affected.`)) return;
  const r = await fetch(`/admin/api/domain-lists/${listId}`, { method:'DELETE' });
  const d = await r.json();
  if (d.error) { showPageAlert('lists-alert', d.error, 'error'); return; }
  showPageAlert('lists-alert', `List "${name}" deleted.`, 'ok');
  loadDomainLists();
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
async function loadAudit() {
  const r = await fetch('/admin/api/audit-log?limit=300');
  const events = await r.json();
  const tbody = document.getElementById('audit-tbody');
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">No audit events yet.</td></tr>';
    return;
  }
  const actionClass = a =>
    a.includes('login_failed') ? 'action-failed' :
    a.includes('login')        ? 'action-login'  :
    a.includes('logout')       ? 'action-logout' : 'action-other';

  tbody.innerHTML = events.map(e => `<tr>
    <td style="font-size:.75rem;color:var(--muted)">${(e.timestamp||'').slice(0,19)}</td>
    <td style="font-size:.8rem">${e.username}</td>
    <td class="${actionClass(e.action)}" style="font-size:.78rem">${e.action}</td>
    <td style="font-size:.78rem;color:var(--muted)">${e.resource||'—'}</td>
    <td style="font-size:.75rem;color:var(--muted)">${e.ip_address||'—'}</td>
    <td style="font-size:.75rem;color:var(--muted)">${e.detail||'—'}</td>
  </tr>`).join('');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function showAlert(id, msg, type) {
  const el = document.getElementById(id);
  el.textContent = msg; el.className = `alert show alert-${type}`;
}
function hideAlert(id) { document.getElementById(id).classList.remove('show'); }
function showPageAlert(id, msg, type) {
  showAlert(id, msg, type);
  setTimeout(() => hideAlert(id), 4000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadUsers();
</script>
<footer style="text-align:center;padding:1.25rem;color:var(--muted);font-size:.7rem;border-top:1px solid var(--border);margin-top:2rem">
  PQC-Monitor v{{ version }} &nbsp;·&nbsp; GPL-3.0-or-later &nbsp;·&nbsp; AI-assisted (Claude/Anthropic)
</footer>
</body>
</html>
"""
