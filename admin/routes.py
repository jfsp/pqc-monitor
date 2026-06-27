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
from auth.models import ROLE_ADMIN, ROLE_COMMUNITY_MANAGER, ROLE_ANALYST, ALL_ROLES

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


def _store():
    return current_app.config["AUTH_STORE"]

def _db():
    return current_app.config["PQC_DB"]


# ── Admin SPA shell ───────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# Community CRUD API
# ══════════════════════════════════════════════════════════════════════════════

@admin_bp.route("/api/communities")
@require_admin
def api_list_communities():
    db = _db()
    communities = db.get_communities()
    for c in communities:
        c["orgs"] = db.get_community_orgs(c["id"])
    return jsonify(communities)


@admin_bp.route("/api/communities", methods=["POST"])
@require_admin
def api_create_community():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    me = current_user()
    db = _db()
    try:
        cid = db.create_community(
            name=name,
            description=data.get("description", ""),
            created_by=me.id
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 409
    org_ids = [int(x) for x in data.get("org_ids", []) if str(x).isdigit()]
    if org_ids:
        db.set_community_orgs(cid, org_ids, added_by=me.id)
    _audit("community.created", resource=name)
    c = db.get_community(cid)
    c["orgs"] = db.get_community_orgs(cid)
    return jsonify(c), 201


@admin_bp.route("/api/communities/<int:cid>")
@require_admin
def api_get_community(cid):
    db = _db()
    c  = db.get_community(cid)
    if not c:
        return jsonify({"error": "not found"}), 404
    c["orgs"] = db.get_community_orgs(cid)
    return jsonify(c)


@admin_bp.route("/api/communities/<int:cid>", methods=["PATCH"])
@require_admin
def api_update_community(cid):
    data = request.get_json() or {}
    db   = _db()
    ok   = db.update_community(cid, **{
        k: data[k] for k in ("name", "description") if k in data
    })
    if not ok:
        return jsonify({"error": "not found"}), 404
    if "org_ids" in data:
        me = current_user()
        db.set_community_orgs(
            cid,
            [int(x) for x in data["org_ids"] if str(x).isdigit()],
            added_by=me.id
        )
    _audit("community.updated", resource=str(cid))
    c = db.get_community(cid)
    c["orgs"] = db.get_community_orgs(cid)
    return jsonify(c)


@admin_bp.route("/api/communities/<int:cid>", methods=["DELETE"])
@require_admin
def api_delete_community(cid):
    db = _db()
    if not db.delete_community(cid):
        return jsonify({"error": "not found"}), 404
    _audit("community.deleted", resource=str(cid))
    return jsonify({"deleted": cid})


@admin_bp.route("/api/users/<int:uid>/communities", methods=["PUT"])
@require_admin
def api_set_user_communities(uid):
    """Replace a user's community assignments. Auto-promotes analyst→community_manager."""
    data         = request.get_json() or {}
    community_ids = [int(x) for x in data.get("community_ids", []) if str(x).isdigit()]
    me   = current_user()
    store = current_app.config["AUTH_STORE"]
    store.set_user_communities(uid, community_ids, granted_by=me.id)
    _audit("user.communities_updated", resource=str(uid),
           detail=f"communities={community_ids}")
    return jsonify({"ok": True, "community_ids": community_ids})


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


# ── Organisation CRUD ─────────────────────────────────────────────────────────

@admin_bp.route("/api/organisations")
@require_admin
def api_list_orgs():
    return jsonify(_db().get_organisations())


@admin_bp.route("/api/organisations", methods=["POST"])
@require_admin
def api_create_org():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        org_id = _db().create_organisation(
            name=name,
            sector=data.get("sector", ""),
            region=data.get("region", ""),
            description=data.get("description", ""),
            country_code=data.get("country_code", ""),
            country=data.get("country", ""),
            created_by=current_user().id,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    _audit("org.created", resource=name)
    return jsonify(_db().get_organisation(org_id)), 201


@admin_bp.route("/api/organisations/<int:org_id>")
@require_admin
def api_get_org(org_id):
    org = _db().get_organisation(org_id)
    if not org:
        return jsonify({"error": "not found"}), 404
    org["domains"] = _db().get_org_domains(org_id)
    return jsonify(org)


@admin_bp.route("/api/organisations/<int:org_id>", methods=["PATCH"])
@require_admin
def api_update_org(org_id):
    data = request.get_json() or {}
    ok   = _db().update_organisation(org_id, **{
        k: data[k] for k in ("name", "sector", "region", "description",
                              "country_code", "country") if k in data
    })
    if not ok:
        return jsonify({"error": "not found"}), 404
    _audit("org.updated", resource=str(org_id))
    return jsonify(_db().get_organisation(org_id))


@admin_bp.route("/api/organisations/<int:org_id>", methods=["DELETE"])
@require_admin
def api_delete_org(org_id):
    org = _db().get_organisation(org_id)
    if not org:
        return jsonify({"error": "not found"}), 404
    _db().delete_organisation(org_id)
    _audit("org.deleted", resource=org.get("name", str(org_id)))
    return jsonify({"ok": True})


@admin_bp.route("/api/organisations/<int:org_id>/domains", methods=["PUT"])
@require_admin
def api_set_org_domains(org_id):
    """Replace all domain assignments for an org."""
    data    = request.get_json() or {}
    domains = data.get("domains", [])
    if not isinstance(domains, list):
        return jsonify({"error": "domains must be a list"}), 400
    _db().set_org_domains(org_id, domains, assigned_by=current_user().id)
    _audit("org.domains_updated", resource=str(org_id),
           detail=f"{len(domains)} domains")
    return jsonify({"ok": True, "domain_count": len(domains)})


@admin_bp.route("/api/users/<int:uid>/orgs")
@require_admin
def api_get_user_orgs(uid):
    user = _store().get_user_by_id(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    orgs = _db().get_organisations()
    for o in orgs:
        o["assigned"] = o["id"] in user.org_ids
    return jsonify(orgs)


@admin_bp.route("/api/users/<int:uid>/orgs", methods=["PUT"])
@require_admin
def api_set_user_orgs(uid):
    data    = request.get_json() or {}
    org_ids = data.get("org_ids", [])
    if not isinstance(org_ids, list):
        return jsonify({"error": "org_ids must be a list"}), 400
    _store().set_user_orgs(uid, org_ids, granted_by=current_user().id)
    _audit("user.orgs_updated", resource=str(uid),
           detail=f"org_ids={org_ids}")
    return jsonify({"ok": True, "org_ids": org_ids})


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
.badge-analyst            { background:rgba(0,212,255,.1);  color:var(--accent); }
.badge-community_manager  { background:rgba(168,85,247,.15); color:#c084fc; }
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
    <a href="#" onclick="showView('orgs')"         id="nav-orgs">🏢 Organisations</a>
    <a href="#" onclick="showView('communities')"  id="nav-communities">🌐 Communities</a>
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

    <!-- ── Organisations view ── -->
    <div id="view-orgs" class="view">
      <div class="page-hdr">
        <div class="page-title">Organisations</div>
        <button class="btn-primary btn-sm" onclick="openCreateOrg()">+ New Organisation</button>
      </div>
      <div id="orgs-alert"></div>
      <div class="card">
        <div class="card-body" style="padding:0">
          <table class="tbl" id="tbl-orgs">
            <thead><tr><th>#</th><th>Name</th><th>Sector</th><th>Region</th><th>Country</th><th>Domains</th><th>Actions</th></tr></thead>
            <tbody id="tbody-orgs"></tbody>
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
          <option value="community_manager">Community Manager</option>
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
    <div class="form-group" style="margin-top:1rem" id="f-user-orgs-group">
      <label>Assigned Organisations</label>
      <div class="check-list" id="f-user-orgs"></div>
    </div>
    <div class="form-group" style="margin-top:1rem" id="f-user-communities-group">
      <label>Assigned Communities <span style="color:var(--muted);font-size:.75rem">(auto-promotes to Community Manager)</span></label>
      <div class="check-list" id="f-user-communities"></div>
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
  if (name === 'orgs')   loadOrgs();
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
  loadOrgCheckboxes(null);
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
  loadOrgCheckboxes(u);
  loadCommunityCheckboxes(u);
  document.getElementById('modal-user').classList.add('open');
}

async function loadDomainListCheckboxes(user) {
  const container = document.getElementById('f-domain-lists');
  const r = await fetch('/admin/api/domain-lists');
  _allDomainLists = await r.json();
  const assigned = new Set((user?.domain_list_ids) || []);
  const role = document.getElementById('f-role').value;
  document.getElementById('f-domain-lists-group').style.display =
    (role === 'analyst' || role === 'community_manager') ? 'block' : 'none';
  container.innerHTML = _allDomainLists.map(dl =>
    `<label class="check-item">
      <input type="checkbox" value="${dl.id}" ${assigned.has(dl.id) ? 'checked' : ''}>
      <span>${dl.name}</span>
      <span style="color:var(--muted);font-size:.72rem;margin-left:auto">#${dl.id}</span>
    </label>`
  ).join('') || '<div style="color:var(--muted);font-size:.82rem;padding:.5rem">No domain lists yet. Create one via the Scanner.</div>';
}

async function loadOrgCheckboxes(user) {
  const container = document.getElementById('f-user-orgs');
  if (!container) return;
  const r = await fetch('/admin/api/organisations');
  const orgs = await r.json();
  const assigned = new Set((user?.org_ids) || []);
  const role = document.getElementById('f-role').value;
  document.getElementById('f-user-orgs-group').style.display =
    (role === 'analyst' || role === 'community_manager') ? 'block' : 'none';
  container.innerHTML = orgs.map(o =>
    `<label class="check-item">
      <input type="checkbox" value="${o.id}" ${assigned.has(o.id) ? 'checked' : ''}>
      <span>${esc(o.name)}</span>
      <span style="color:var(--muted);font-size:.72rem;margin-left:auto">${o.region||''}</span>
    </label>`
  ).join('') || '<div style="color:var(--muted);font-size:.82rem;padding:.5rem">No organisations yet.</div>';
}

async function loadCommunityCheckboxes(user) {
  const container = document.getElementById('f-user-communities');
  if (!container) return;
  const r = await fetch('/admin/api/communities');
  const communities = await r.json();
  const assigned = new Set((user?.community_ids) || []);
  const role = document.getElementById('f-role').value;
  document.getElementById('f-user-communities-group').style.display =
    (role === 'community_manager') ? 'block' : 'none';
  container.innerHTML = communities.map(c =>
    `<label class="check-item">
      <input type="checkbox" value="${c.id}" ${assigned.has(c.id) ? 'checked' : ''}>
      <span>${esc(c.name)}</span>
      <span style="color:var(--muted);font-size:.72rem;margin-left:auto">${c.org_count||0} orgs</span>
    </label>`
  ).join('') || '<div style="color:var(--muted);font-size:.82rem;padding:.5rem">No communities yet.</div>';
}

document.getElementById('f-role')?.addEventListener('change', () => {
  const role = document.getElementById('f-role').value;
  const showAnalyst   = (role === 'analyst' || role === 'community_manager') ? 'block' : 'none';
  const showCommunity = (role === 'community_manager') ? 'block' : 'none';
  document.getElementById('f-domain-lists-group').style.display = showAnalyst;
  document.getElementById('f-user-orgs-group').style.display    = showAnalyst;
  document.getElementById('f-user-communities-group').style.display = showCommunity;
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

    // Update org assignments
    const selectedOrgs = [...document.querySelectorAll('#f-user-orgs input:checked')]
      .map(cb => parseInt(cb.value));
    await fetch(`/admin/api/users/${_editUserId}/orgs`, {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({org_ids: selectedOrgs})
    });

    // Update community assignments
    const selectedCommunities = [...document.querySelectorAll('#f-user-communities input:checked')]
      .map(cb => parseInt(cb.value));
    await fetch(`/admin/api/users/${_editUserId}/communities`, {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({community_ids: selectedCommunities})
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

    // Assign orgs
    const newOrgs = [...document.querySelectorAll('#f-user-orgs input:checked')]
      .map(cb => parseInt(cb.value));
    if (newOrgs.length) {
      await fetch(`/admin/api/users/${d.id}/orgs`, {
        method:'PUT', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({org_ids: newOrgs})
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

// ── Organisations ─────────────────────────────────────────────────────────────
let _editOrgId = null;

async function loadOrgs() {
  const r = await fetch('/admin/api/organisations');
  const orgs = await r.json();
  const tbody = document.getElementById('tbody-orgs');
  if (!tbody) return;
  tbody.innerHTML = orgs.map(o => `<tr>
    <td style="color:var(--muted);font-size:.78rem">#${o.id}</td>
    <td><strong>${esc(o.name)}</strong></td>
    <td style="color:var(--muted)">${esc(o.sector||'—')}</td>
    <td style="color:var(--muted)">${esc(o.region||'—')}</td>
    <td style="color:var(--muted)">${o.country_code ? `<span title="${esc(o.country||'')}">${esc(o.country_code)}</span>` : '—'}</td>
    <td><span style="background:rgba(0,212,255,.1);color:var(--accent);padding:.1rem .45rem;border-radius:3px;font-size:.75rem">${o.domain_count||0} domains</span></td>
    <td>
      <button class="btn btn-outline btn-sm" onclick="openEditOrg(${o.id})">Edit</button>
      <button class="btn btn-outline btn-sm" onclick="openOrgDomains(${o.id},'${esc(o.name)}')">Domains</button>
      <button class="btn btn-danger btn-sm" onclick="deleteOrg(${o.id},'${esc(o.name)}')">Delete</button>
    </td>
  </tr>`).join('') || '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:1.5rem">No organisations yet.</td></tr>';
}

function openCreateOrg() {
  _editOrgId = null;
  document.getElementById('modal-org-title').textContent = 'New Organisation';
  document.getElementById('modal-org-submit').textContent = 'Create';
  ['f-org-name','f-org-sector','f-org-region','f-org-country-code','f-org-country','f-org-desc'].forEach(id =>
    document.getElementById(id).value = '');
  hideAlert('modal-org-alert');
  document.getElementById('modal-org').classList.add('open');
}

async function openEditOrg(orgId) {
  _editOrgId = orgId;
  const r = await fetch(`/admin/api/organisations/${orgId}`);
  const o = await r.json();
  document.getElementById('modal-org-title').textContent = `Edit: ${o.name}`;
  document.getElementById('modal-org-submit').textContent = 'Save';
  document.getElementById('f-org-name').value         = o.name   || '';
  document.getElementById('f-org-sector').value       = o.sector || '';
  document.getElementById('f-org-region').value       = o.region || '';
  document.getElementById('f-org-country-code').value = o.country_code || '';
  document.getElementById('f-org-country').value      = o.country || '';
  document.getElementById('f-org-desc').value         = o.description || '';
  hideAlert('modal-org-alert');
  document.getElementById('modal-org').classList.add('open');
}

function syncCountryName() {
  const sel = document.getElementById('f-org-country-code');
  const inp = document.getElementById('f-org-country');
  if (!sel || !inp) return;
  const opt = sel.options[sel.selectedIndex];
  if (opt && opt.value) {
    // Extract display name from option text: "ES – Spain" → "Spain"
    const parts = opt.text.split('–');
    inp.value = parts.length > 1 ? parts[1].trim() : opt.text.trim();
  } else {
    inp.value = '';
  }
}

async function submitOrgModal() {
  const body = {
    name:         document.getElementById('f-org-name').value.trim(),
    sector:       document.getElementById('f-org-sector').value.trim(),
    region:       document.getElementById('f-org-region').value.trim(),
    country_code: document.getElementById('f-org-country-code').value.trim(),
    country:      document.getElementById('f-org-country').value.trim(),
    description:  document.getElementById('f-org-desc').value.trim(),
  };
  if (!body.name) { showAlert('modal-org-alert','Name is required.','error'); return; }
  const url    = _editOrgId ? `/admin/api/organisations/${_editOrgId}` : '/admin/api/organisations';
  const method = _editOrgId ? 'PATCH' : 'POST';
  const r = await fetch(url, { method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const d = await r.json();
  if (d.error) { showAlert('modal-org-alert', d.error, 'error'); return; }
  closeModal('modal-org');
  showPageAlert('orgs-alert', _editOrgId ? 'Organisation updated.' : 'Organisation created.', 'ok');
  loadOrgs();
}


// ── Community management ──────────────────────────────────────────────────────

let _editCommunityId = null;

async function loadCommunities() {
  const r = await fetch('/admin/api/communities');
  const communities = await r.json();
  const tbody = document.getElementById('communities-tbody');
  if (!tbody) return;
  tbody.innerHTML = communities.map(c => `
    <tr>
      <td style="color:var(--muted)">#${c.id}</td>
      <td><strong>${esc(c.name)}</strong></td>
      <td style="color:var(--muted)">${esc(c.description||'')}</td>
      <td style="text-align:center">
        <span style="background:rgba(14,165,233,.1);color:#38bdf8;padding:.15rem .5rem;border-radius:4px;font-size:.78rem">
          ${c.org_count||0} orgs
        </span>
      </td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick="openEditCommunity(${c.id})">Edit</button>
        <button class="btn btn-sm btn-ghost" style="color:#ef4444"
                onclick="deleteCommunity(${c.id}, '${esc(c.name)}')">Delete</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">No communities yet.</td></tr>';
}

async function openNewCommunity() {
  _editCommunityId = null;
  document.getElementById('modal-community-title').textContent = 'New Community';
  document.getElementById('modal-community-submit').textContent = 'Create';
  document.getElementById('f-comm-name').value = '';
  document.getElementById('f-comm-desc').value = '';
  await loadCommOrgCheckboxes(null);
  document.getElementById('modal-community').classList.add('open');
}

async function openEditCommunity(cid) {
  _editCommunityId = cid;
  const r = await fetch(`/admin/api/communities/${cid}`);
  const c = await r.json();
  document.getElementById('modal-community-title').textContent = `Edit: ${c.name}`;
  document.getElementById('modal-community-submit').textContent = 'Save';
  document.getElementById('f-comm-name').value = c.name || '';
  document.getElementById('f-comm-desc').value = c.description || '';
  const assignedIds = new Set((c.orgs||[]).map(o => o.id));
  await loadCommOrgCheckboxes(assignedIds);
  document.getElementById('modal-community').classList.add('open');
}

async function loadCommOrgCheckboxes(assignedIds) {
  const container = document.getElementById('f-comm-orgs');
  const r = await fetch('/admin/api/organisations');
  const orgs = await r.json();
  container.innerHTML = orgs.map(o =>
    `<label class="check-item">
      <input type="checkbox" value="${o.id}" ${assignedIds && assignedIds.has(o.id) ? 'checked' : ''}>
      <span>${esc(o.name)}</span>
      <span style="color:var(--muted);font-size:.72rem;margin-left:auto">${o.region||''}</span>
    </label>`
  ).join('') || '<div style="color:var(--muted);font-size:.82rem;padding:.5rem">No organisations yet.</div>';
}

async function submitCommunityModal() {
  const name = document.getElementById('f-comm-name').value.trim();
  if (!name) { showAlert('modal-community-alert', 'Name is required.', 'error'); return; }
  const desc    = document.getElementById('f-comm-desc').value.trim();
  const org_ids = [...document.querySelectorAll('#f-comm-orgs input:checked')]
    .map(cb => parseInt(cb.value));
  const body   = { name, description: desc, org_ids };
  const url    = _editCommunityId ? `/admin/api/communities/${_editCommunityId}` : '/admin/api/communities';
  const method = _editCommunityId ? 'PATCH' : 'POST';
  const r = await fetch(url, { method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const d = await r.json();
  if (d.error) { showAlert('modal-community-alert', d.error, 'error'); return; }
  closeModal('modal-community');
  showPageAlert('communities-alert', _editCommunityId ? 'Community updated.' : 'Community created.', 'ok');
  loadCommunities();
}

async function deleteCommunity(cid, name) {
  if (!confirm(`Delete community "${name}"? This will remove all org and user assignments.`)) return;
  const r = await fetch(`/admin/api/communities/${cid}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.error) { showPageAlert('communities-alert', d.error, 'error'); return; }
  showPageAlert('communities-alert', 'Community deleted.', 'ok');
  loadCommunities();
}

async function openOrgDomains(orgId, orgName) {
  const r = await fetch(`/admin/api/organisations/${orgId}`);
  const o = await r.json();
  document.getElementById('modal-org-domains-title').textContent = `Domains: ${orgName}`;
  document.getElementById('f-org-domains').value = (o.domains || []).join('\n');
  document.getElementById('modal-org-domains').dataset.orgId = orgId;
  hideAlert('modal-org-domains-alert');
  document.getElementById('modal-org-domains').classList.add('open');
}

async function submitOrgDomains() {
  const orgId   = document.getElementById('modal-org-domains').dataset.orgId;
  const raw     = document.getElementById('f-org-domains').value;
  const domains = raw.split(/[\n,]+/).map(d => d.trim().toLowerCase()).filter(Boolean);
  const r = await fetch(`/admin/api/organisations/${orgId}/domains`, {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({domains})
  });
  const d = await r.json();
  if (d.error) { showAlert('modal-org-domains-alert', d.error, 'error'); return; }
  closeModal('modal-org-domains');
  showPageAlert('orgs-alert', `${domains.length} domains assigned.`, 'ok');
  loadOrgs();
}

async function deleteOrg(orgId, name) {
  if (!confirm(`Delete organisation "${name}"?\nUser and domain assignments will be removed. Scan data is not affected.`)) return;
  await fetch(`/admin/api/organisations/${orgId}`, {method:'DELETE'});
  showPageAlert('orgs-alert', 'Organisation deleted.', 'ok');
  loadOrgs();
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadUsers();
</script>

<!-- Org create/edit modal -->
<div class="modal-bg" id="modal-org">
  <div class="modal">
    <div class="modal-hdr">
      <span id="modal-org-title">Organisation</span>
      <button class="btn-ghost btn-sm" onclick="closeModal('modal-org')">✕</button>
    </div>
    <div class="modal-body">
      <div id="modal-org-alert" class="alert"></div>
      <label>Name *</label>
      <input type="text" id="f-org-name" placeholder="e.g. Banco Santander" style="width:100%;margin-bottom:.75rem">
      <label>Sector</label>
      <input type="text" id="f-org-sector" placeholder="e.g. Financial Services" style="width:100%;margin-bottom:.75rem">
      <label>Region</label>
      <input type="text" id="f-org-region" placeholder="e.g. EU, Spain, LATAM" style="width:100%;margin-bottom:.75rem">
      <label>Country Code (ISO 3166-1 alpha-2)</label>
      <select id="f-org-country-code" onchange="syncCountryName()" style="width:100%;background:var(--input-bg,var(--panel));border:1px solid var(--border);color:var(--text);padding:.3rem .5rem;border-radius:4px;margin-bottom:.75rem">
        <option value="">— Select country —</option>
        <option value="AD">AD – Andorra</option><option value="AE">AE – United Arab Emirates</option>
        <option value="AF">AF – Afghanistan</option><option value="AG">AG – Antigua and Barbuda</option>
        <option value="AL">AL – Albania</option><option value="AM">AM – Armenia</option>
        <option value="AO">AO – Angola</option><option value="AR">AR – Argentina</option>
        <option value="AT">AT – Austria</option><option value="AU">AU – Australia</option>
        <option value="AZ">AZ – Azerbaijan</option><option value="BA">BA – Bosnia and Herzegovina</option>
        <option value="BB">BB – Barbados</option><option value="BD">BD – Bangladesh</option>
        <option value="BE">BE – Belgium</option><option value="BF">BF – Burkina Faso</option>
        <option value="BG">BG – Bulgaria</option><option value="BH">BH – Bahrain</option>
        <option value="BI">BI – Burundi</option><option value="BJ">BJ – Benin</option>
        <option value="BN">BN – Brunei</option><option value="BO">BO – Bolivia</option>
        <option value="BR">BR – Brazil</option><option value="BS">BS – Bahamas</option>
        <option value="BT">BT – Bhutan</option><option value="BW">BW – Botswana</option>
        <option value="BY">BY – Belarus</option><option value="BZ">BZ – Belize</option>
        <option value="CA">CA – Canada</option><option value="CD">CD – DR Congo</option>
        <option value="CF">CF – Central African Republic</option><option value="CG">CG – Congo</option>
        <option value="CH">CH – Switzerland</option><option value="CI">CI – Côte d'Ivoire</option>
        <option value="CL">CL – Chile</option><option value="CM">CM – Cameroon</option>
        <option value="CN">CN – China</option><option value="CO">CO – Colombia</option>
        <option value="CR">CR – Costa Rica</option><option value="CU">CU – Cuba</option>
        <option value="CV">CV – Cape Verde</option><option value="CY">CY – Cyprus</option>
        <option value="CZ">CZ – Czechia</option><option value="DE">DE – Germany</option>
        <option value="DJ">DJ – Djibouti</option><option value="DK">DK – Denmark</option>
        <option value="DM">DM – Dominica</option><option value="DO">DO – Dominican Republic</option>
        <option value="DZ">DZ – Algeria</option><option value="EC">EC – Ecuador</option>
        <option value="EE">EE – Estonia</option><option value="EG">EG – Egypt</option>
        <option value="ER">ER – Eritrea</option><option value="ES">ES – Spain</option>
        <option value="ET">ET – Ethiopia</option><option value="FI">FI – Finland</option>
        <option value="FJ">FJ – Fiji</option><option value="FR">FR – France</option>
        <option value="GA">GA – Gabon</option><option value="GB">GB – United Kingdom</option>
        <option value="GD">GD – Grenada</option><option value="GE">GE – Georgia</option>
        <option value="GH">GH – Ghana</option><option value="GM">GM – Gambia</option>
        <option value="GN">GN – Guinea</option><option value="GQ">GQ – Equatorial Guinea</option>
        <option value="GR">GR – Greece</option><option value="GT">GT – Guatemala</option>
        <option value="GW">GW – Guinea-Bissau</option><option value="GY">GY – Guyana</option>
        <option value="HN">HN – Honduras</option><option value="HR">HR – Croatia</option>
        <option value="HT">HT – Haiti</option><option value="HU">HU – Hungary</option>
        <option value="ID">ID – Indonesia</option><option value="IE">IE – Ireland</option>
        <option value="IL">IL – Israel</option><option value="IN">IN – India</option>
        <option value="IQ">IQ – Iraq</option><option value="IR">IR – Iran</option>
        <option value="IS">IS – Iceland</option><option value="IT">IT – Italy</option>
        <option value="JM">JM – Jamaica</option><option value="JO">JO – Jordan</option>
        <option value="JP">JP – Japan</option><option value="KE">KE – Kenya</option>
        <option value="KG">KG – Kyrgyzstan</option><option value="KH">KH – Cambodia</option>
        <option value="KI">KI – Kiribati</option><option value="KM">KM – Comoros</option>
        <option value="KN">KN – Saint Kitts and Nevis</option><option value="KP">KP – North Korea</option>
        <option value="KR">KR – South Korea</option><option value="KW">KW – Kuwait</option>
        <option value="KZ">KZ – Kazakhstan</option><option value="LA">LA – Laos</option>
        <option value="LB">LB – Lebanon</option><option value="LC">LC – Saint Lucia</option>
        <option value="LI">LI – Liechtenstein</option><option value="LK">LK – Sri Lanka</option>
        <option value="LR">LR – Liberia</option><option value="LS">LS – Lesotho</option>
        <option value="LT">LT – Lithuania</option><option value="LU">LU – Luxembourg</option>
        <option value="LV">LV – Latvia</option><option value="LY">LY – Libya</option>
        <option value="MA">MA – Morocco</option><option value="MC">MC – Monaco</option>
        <option value="MD">MD – Moldova</option><option value="ME">ME – Montenegro</option>
        <option value="MG">MG – Madagascar</option><option value="MH">MH – Marshall Islands</option>
        <option value="MK">MK – North Macedonia</option><option value="ML">ML – Mali</option>
        <option value="MM">MM – Myanmar</option><option value="MN">MN – Mongolia</option>
        <option value="MR">MR – Mauritania</option><option value="MT">MT – Malta</option>
        <option value="MU">MU – Mauritius</option><option value="MV">MV – Maldives</option>
        <option value="MW">MW – Malawi</option><option value="MX">MX – Mexico</option>
        <option value="MY">MY – Malaysia</option><option value="MZ">MZ – Mozambique</option>
        <option value="NA">NA – Namibia</option><option value="NE">NE – Niger</option>
        <option value="NG">NG – Nigeria</option><option value="NI">NI – Nicaragua</option>
        <option value="NL">NL – Netherlands</option><option value="NO">NO – Norway</option>
        <option value="NP">NP – Nepal</option><option value="NR">NR – Nauru</option>
        <option value="NZ">NZ – New Zealand</option><option value="OM">OM – Oman</option>
        <option value="PA">PA – Panama</option><option value="PE">PE – Peru</option>
        <option value="PG">PG – Papua New Guinea</option><option value="PH">PH – Philippines</option>
        <option value="PK">PK – Pakistan</option><option value="PL">PL – Poland</option>
        <option value="PT">PT – Portugal</option><option value="PW">PW – Palau</option>
        <option value="PY">PY – Paraguay</option><option value="QA">QA – Qatar</option>
        <option value="RO">RO – Romania</option><option value="RS">RS – Serbia</option>
        <option value="RU">RU – Russia</option><option value="RW">RW – Rwanda</option>
        <option value="SA">SA – Saudi Arabia</option><option value="SB">SB – Solomon Islands</option>
        <option value="SC">SC – Seychelles</option><option value="SD">SD – Sudan</option>
        <option value="SE">SE – Sweden</option><option value="SG">SG – Singapore</option>
        <option value="SI">SI – Slovenia</option><option value="SK">SK – Slovakia</option>
        <option value="SL">SL – Sierra Leone</option><option value="SM">SM – San Marino</option>
        <option value="SN">SN – Senegal</option><option value="SO">SO – Somalia</option>
        <option value="SR">SR – Suriname</option><option value="SS">SS – South Sudan</option>
        <option value="ST">ST – São Tomé and Príncipe</option><option value="SV">SV – El Salvador</option>
        <option value="SY">SY – Syria</option><option value="SZ">SZ – Eswatini</option>
        <option value="TD">TD – Chad</option><option value="TG">TG – Togo</option>
        <option value="TH">TH – Thailand</option><option value="TJ">TJ – Tajikistan</option>
        <option value="TL">TL – Timor-Leste</option><option value="TM">TM – Turkmenistan</option>
        <option value="TN">TN – Tunisia</option><option value="TO">TO – Tonga</option>
        <option value="TR">TR – Turkey</option><option value="TT">TT – Trinidad and Tobago</option>
        <option value="TV">TV – Tuvalu</option><option value="TZ">TZ – Tanzania</option>
        <option value="UA">UA – Ukraine</option><option value="UG">UG – Uganda</option>
        <option value="US">US – United States</option><option value="UY">UY – Uruguay</option>
        <option value="UZ">UZ – Uzbekistan</option><option value="VA">VA – Vatican City</option>
        <option value="VC">VC – Saint Vincent and the Grenadines</option><option value="VE">VE – Venezuela</option>
        <option value="VN">VN – Vietnam</option><option value="VU">VU – Vanuatu</option>
        <option value="WS">WS – Samoa</option><option value="YE">YE – Yemen</option>
        <option value="ZA">ZA – South Africa</option><option value="ZM">ZM – Zambia</option>
        <option value="ZW">ZW – Zimbabwe</option>
      </select>
      <label>Country (display name)</label>
      <input type="text" id="f-org-country" placeholder="Auto-filled or enter manually" style="width:100%;margin-bottom:.75rem">
      <label>Description</label>
      <input type="text" id="f-org-desc" placeholder="Optional notes" style="width:100%;margin-bottom:.75rem">
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-org')">Cancel</button>
      <button class="btn" id="modal-org-submit" onclick="submitOrgModal()">Create</button>
    </div>
  </div>
</div>

<!-- Org domain assignment modal -->
<div class="modal-bg" id="modal-org-domains" data-org-id="">
  <div class="modal">
    <div class="modal-hdr">
      <span id="modal-org-domains-title">Assign Domains</span>
      <button class="btn-ghost btn-sm" onclick="closeModal('modal-org-domains')">✕</button>
    </div>
    <div class="modal-body">
      <div id="modal-org-domains-alert" class="alert"></div>
      <label>Domains (one per line or comma-separated)</label>
      <textarea id="f-org-domains" rows="10"
        style="width:100%;background:var(--input-bg);border:1px solid var(--border);color:var(--text);padding:.5rem;border-radius:4px;font-family:monospace;font-size:.82rem;margin-top:.4rem;resize:vertical"
        placeholder="example.com&#10;mail.example.com&#10;api.example.com"></textarea>
      <div style="color:var(--muted);font-size:.75rem;margin-top:.4rem">
        Domains can belong to only one organisation. Assigning here replaces any previous assignment.
      </div>
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-org-domains')">Cancel</button>
      <button class="btn" onclick="submitOrgDomains()">Save Domains</button>
    </div>
  </div>
</div>


  <!-- ── Communities view ── -->
  <div id="view-communities" class="view" style="display:none">
    <div class="page-hdr">
      <div>
        <h2>Communities</h2>
        <p class="page-sub">Group organisations into communities and assign users to them.</p>
      </div>
      <button class="btn" onclick="openNewCommunity()">+ New Community</button>
    </div>
    <div id="communities-alert" class="alert" style="display:none"></div>
    <table class="data-table" id="communities-table">
      <thead><tr>
        <th>#</th><th>Name</th><th>Description</th>
        <th style="text-align:center">Orgs</th><th>Actions</th>
      </tr></thead>
      <tbody id="communities-tbody"></tbody>
    </table>
  </div>

  <!-- ── Community modal ── -->
  <div class="modal-bg" id="modal-community">
    <div class="modal" style="width:560px;max-height:90vh;overflow-y:auto">
      <div class="modal-header">
        <span id="modal-community-title">New Community</span>
        <button class="btn-ghost btn-sm" onclick="closeModal('modal-community')">✕</button>
      </div>
      <div id="modal-community-alert" class="alert"></div>
      <div class="form-group">
        <label>Name *</label>
        <input type="text" id="f-comm-name" placeholder="e.g. Spanish Banking Sector"
               style="width:100%;background:var(--panel);border:1px solid var(--border);color:var(--text);padding:.3rem .5rem;border-radius:4px">
      </div>
      <div class="form-group">
        <label>Description</label>
        <input type="text" id="f-comm-desc" placeholder="Optional description"
               style="width:100%;background:var(--panel);border:1px solid var(--border);color:var(--text);padding:.3rem .5rem;border-radius:4px">
      </div>
      <div class="form-group">
        <label>Member Organisations</label>
        <div class="check-list" id="f-comm-orgs"
             style="max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;padding:.4rem"></div>
      </div>
      <div class="form-actions">
        <button class="btn btn-ghost" onclick="closeModal('modal-community')">Cancel</button>
        <button class="btn" id="modal-community-submit" onclick="submitCommunityModal()">Create</button>
      </div>
    </div>
  </div>

<footer style="text-align:center;padding:1.25rem;color:var(--muted);font-size:.7rem;border-top:1px solid var(--border);margin-top:2rem">
  PQC-Monitor v{{ version }} &nbsp;·&nbsp; GPL-3.0-or-later &nbsp;·&nbsp; AI-assisted (Claude/Anthropic)
</footer>
</body>
</html>
"""
