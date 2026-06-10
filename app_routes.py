#!/usr/bin/env python3
"""
PQC-Monitor: Analyst App Blueprint
Serves the main dashboard SPA at /app/* and wraps all existing
/api/* routes with authentication and domain-scoping.

Admins see everything. Analysts see only domains from their assigned lists.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sys

from flask import (
    Blueprint, jsonify, request, render_template_string,
    current_app, redirect, url_for, Response
)

from auth.middleware import (
    require_auth, current_user, filter_assessments,
    scope_domains, _audit
)
from auth.models import ROLE_ADMIN

logger = logging.getLogger(__name__)
app_bp = Blueprint("app_bp", __name__, url_prefix="/app")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _db():
    return current_app.config["PQC_DB"]

def _orchestrator():
    return current_app.config["ORCHESTRATOR"]

def _discovery():
    return current_app.config["DISCOVERY"]


# ── Root redirect ─────────────────────────────────────────────────────────────

@app_bp.route("/")
@require_auth
def dashboard_home():
    user = current_user()
    dashboard_content = current_app.config.get("DASHBOARD_BODY", "")
    return render_template_string(
        _APP_SHELL,
        user=user,
        is_admin=user.is_admin,
        dashboard_content=dashboard_content,
    )


# ── Protected API wrappers ────────────────────────────────────────────────────
# Each endpoint mirrors the unprotected ones in dashboard/app.py but adds
# auth + domain scoping.  The original create_app() routes are NOT registered
# when using this blueprint — see the new create_app() in app_factory.py.

@app_bp.route("/api/summary")
@require_auth
def api_summary():
    db   = _db()
    user = current_user()
    stats = db.get_summary_stats()
    runs  = db.list_runs(5)
    # For analysts: recalculate stats over their visible domains only
    if not user.is_admin:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        assessments = db.get_latest_assessments()
        visible = [a for a in assessments if a.get("domain") in allowed]
        scores  = [a.get("score", 0) for a in visible]
        stats = {
            "total_domains":   len(visible),
            "avg_score":       round(sum(scores)/len(scores), 1) if scores else 0,
            "critical_count":  sum(1 for a in visible if a.get("level") == "critical"),
            "weak_count":      sum(1 for a in visible if a.get("level") == "weak"),
            "moderate_count":  sum(1 for a in visible if a.get("level") == "moderate"),
            "ready_count":     sum(1 for a in visible if a.get("level") == "ready"),
            "pqc_count":       sum(1 for a in visible if a.get("has_pqc")),
        }
    return jsonify({"stats": stats, "recent_runs": runs})


@app_bp.route("/api/assessments")
@require_auth
def api_assessments():
    db     = _db()
    user   = current_user()
    run_id = request.args.get("run_id")
    all_   = db.get_latest_assessments(run_id)
    return jsonify(filter_assessments(all_, user))


@app_bp.route("/api/domain/<domain>")
@require_auth
def api_domain_detail(domain):
    db   = _db()
    user = current_user()
    if not user.is_admin:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        if domain not in allowed:
            return jsonify({"error": "forbidden"}), 403
    _audit("view_domain", resource=domain)
    history = db.get_domain_history(domain)
    scans   = db.get_domain_scans(domain)
    return jsonify({"domain": domain, "history": history, "scans": scans[:5]})


@app_bp.route("/api/trends")
@require_auth
def api_trends():
    return jsonify(_db().get_sector_trends())


@app_bp.route("/api/runs")
@require_auth
def api_runs():
    return jsonify(_db().list_runs(20))


@app_bp.route("/api/domain-lists")
@require_auth
def api_domain_lists():
    db   = _db()
    user = current_user()
    if user.is_admin:
        return jsonify(db.get_domain_lists())
    # Analyst: only their assigned lists
    store = current_app.config["AUTH_STORE"]
    assigned_ids = set(user.domain_list_ids)
    all_lists = db.get_domain_lists()
    return jsonify([dl for dl in all_lists if dl["id"] in assigned_ids])


@app_bp.route("/api/discover", methods=["POST"])
@require_auth
def api_discover():
    if not current_user().can("scan.run"):
        return jsonify({"error": "forbidden"}), 403
    data       = request.get_json() or {}
    query      = data.get("query", "")
    max_domains = int(data.get("max_domains", 50))
    validate   = data.get("validate", True)
    if not query:
        return jsonify({"error": "query is required"}), 400
    result = _discovery().discover(query, max_domains, validate)
    return jsonify(result)


@app_bp.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    if not current_user().can("scan.run"):
        return jsonify({"error": "forbidden"}), 403
    data    = request.get_json() or {}
    domains = data.get("domains", [])
    if not domains:
        return jsonify({"error": "domains list is required"}), 400
    _audit("scan.run", resource=",".join(domains[:5]),
           detail=f"{len(domains)} domains")
    try:
        run_id = _orchestrator().scan_domains(
            domains,
            sector=data.get("sector", ""),
            region=data.get("region", ""),
            use_shodan=data.get("use_shodan", False),
        )
        return jsonify({"run_id": run_id, "status": "completed",
                        "domains_scanned": len(domains)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app_bp.route("/api/reassess", methods=["POST"])
@require_auth
def api_reassess():
    if not current_user().can("scan.run"):
        return jsonify({"error": "forbidden"}), 403
    data   = request.get_json() or {}
    run_id = data.get("run_id")
    if not run_id:
        return jsonify({"error": "run_id is required"}), 400
    try:
        new_id = _orchestrator().reassess_run(run_id, data.get("guidelines"))
        return jsonify({"new_run_id": new_id, "status": "completed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app_bp.route("/api/save-domains", methods=["POST"])
@require_auth
def api_save_domains():
    if not current_user().can("domain_list.manage"):
        return jsonify({"error": "forbidden"}), 403
    data    = request.get_json() or {}
    name    = data.get("name", "unnamed")
    domains = data.get("domains", [])
    query   = data.get("query", "")
    list_id = _db().save_domain_list(name, domains, query)
    return jsonify({"list_id": list_id, "count": len(domains)})


# ── CT endpoints (scoped) ─────────────────────────────────────────────────────

@app_bp.route("/api/ct/stats")
@require_auth
def api_ct_stats():
    return jsonify(_db().get_ct_stats())


@app_bp.route("/api/ct/summaries")
@require_auth
def api_ct_summaries():
    user   = current_user()
    domain = request.args.get("domain") or None
    if domain and not user.is_admin:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        if domain not in allowed:
            return jsonify({"error": "forbidden"}), 403
    rows = _db().get_ct_summaries(domain=domain, limit=100)
    if not user.is_admin and not domain:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        rows = [r for r in rows if r.get("domain") in allowed]
    return jsonify(rows)


@app_bp.route("/api/ct/certificates")
@require_auth
def api_ct_certificates():
    user   = current_user()
    domain = request.args.get("domain") or None
    if domain and not user.is_admin:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        if domain not in allowed:
            return jsonify({"error": "forbidden"}), 403
    certs = _db().get_ct_pqc_certificates(domain=domain, limit=200)
    if not user.is_admin and not domain:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        certs = [c for c in certs if c.get("domain") in allowed]
    return jsonify(certs)


@app_bp.route("/api/ct/timeline")
@require_auth
def api_ct_timeline():
    return jsonify(_db().get_ct_timeline())


@app_bp.route("/api/ct/monitor", methods=["POST"])
@require_auth
def api_ct_monitor():
    if not current_user().can("ct.run"):
        return jsonify({"error": "forbidden"}), 403
    data      = request.get_json() or {}
    domains   = data.get("domains", [])
    fetch_pem = data.get("fetch_pem", False)
    max_certs = int(data.get("max_certs", 100))
    if not domains:
        return jsonify({"error": "domains list required"}), 400
    from ct.ct_monitor import monitor_domains
    db = _db()
    summaries = monitor_domains(domains, fetch_pem=fetch_pem,
                                max_certs_per_domain=max_certs)
    for s in summaries:
        db.save_ct_summary(s.to_dict())
    return jsonify({
        "domains_processed":  len(summaries),
        "pqc_certs_found":    sum(s.pqc_certs_found for s in summaries),
        "hybrid_certs_found": sum(s.hybrid_certs_found for s in summaries),
    })


# ── Roadmap endpoints (scoped) ────────────────────────────────────────────────

@app_bp.route("/api/roadmap/stats")
@require_auth
def api_roadmap_stats():
    return jsonify(_db().get_roadmap_stats())


@app_bp.route("/api/roadmap")
@require_auth
def api_roadmap():
    user   = current_user()
    db     = _db()
    run_id = request.args.get("run_id") or None
    domain = request.args.get("domain") or None
    from roadmap.generator import generate_sector_roadmap, generate_domain_roadmap
    stored = db.get_roadmaps(run_id=run_id, domain=domain)
    if stored:
        return jsonify(filter_assessments(stored, user))
    assessments = filter_assessments(db.get_latest_assessments(run_id), user)
    if domain:
        assessments = [a for a in assessments if a.get("domain") == domain]
    if not assessments:
        return jsonify([])
    if domain and len(assessments) == 1:
        return jsonify([generate_domain_roadmap(assessments[0]).to_dict()])
    sr = generate_sector_roadmap(assessments)
    return jsonify(sr.domains)


@app_bp.route("/api/roadmap/domain/<domain_name>")
@require_auth
def api_roadmap_domain(domain_name):
    user = current_user()
    if not user.is_admin:
        allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
        if domain_name not in allowed:
            return jsonify({"error": "forbidden"}), 403
    db = _db()
    from roadmap.generator import generate_domain_roadmap
    stored = db.get_roadmaps(domain=domain_name)
    if stored:
        return jsonify(stored[0])
    assessments = db.get_latest_assessments()
    a = next((x for x in assessments if x.get("domain") == domain_name), None)
    if not a:
        return jsonify({"error": "domain not found"}), 404
    return jsonify(generate_domain_roadmap(a).to_dict())


@app_bp.route("/api/roadmap/generate", methods=["POST"])
@require_auth
def api_roadmap_generate():
    if not current_user().can("roadmap.generate"):
        return jsonify({"error": "forbidden"}), 403
    data   = request.get_json() or {}
    run_id = data.get("run_id") or None
    save   = data.get("save", False)
    db     = _db()
    from roadmap.generator import generate_domain_roadmap, generate_sector_roadmap
    assessments = filter_assessments(db.get_latest_assessments(run_id), current_user())
    if not assessments:
        return jsonify({"error": "no assessment data"}), 400
    if run_id:
        for a in assessments:
            extra = db.get_domain_extra(a.get("domain", ""), run_id)
            cdn = extra.get("cdn", {})
            if cdn.get("detected"):
                a["cdn_name"] = cdn.get("cdn_name", "")
    generated = 0
    for a in assessments:
        dr = generate_domain_roadmap(a)
        if save:
            db.save_roadmap(run_id or "manual", dr.to_dict())
        generated += 1
    runs = db.list_runs(50)
    run_meta = next((r for r in runs if r.get("run_id") == run_id), {})
    sr = generate_sector_roadmap(
        assessments,
        sector=run_meta.get("sector", ""),
        region=run_meta.get("region", ""),
    )
    return jsonify({
        "domains_processed": generated, "saved": save,
        "avg_current_score": sr.avg_current_score,
        "critical_domains":  sr.critical_domains,
        "total_effort_min":  sr.total_effort_days_min,
        "total_effort_max":  sr.total_effort_days_max,
    })


# ── Export (scoped) ───────────────────────────────────────────────────────────

@app_bp.route("/api/export")
@require_auth
def api_export():
    if not current_user().can("report.export"):
        return jsonify({"error": "forbidden"}), 403
    fmt    = request.args.get("format", "csv")
    run_id = request.args.get("run_id") or None
    from reports.report_generator import export_csv, export_json, export_text_report
    _audit("report.export", detail=f"format={fmt}")
    if fmt == "json":
        content  = export_json(_db(), run_id)
        mimetype = "application/json"
        filename = "pqc_report.json"
    elif fmt == "text":
        content  = export_text_report(_db(), run_id)
        mimetype = "text/plain"
        filename = "pqc_report.txt"
    else:
        content  = export_csv(_db(), run_id)
        mimetype = "text/csv"
        filename = "pqc_report.csv"
    return Response(
        content, mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ── Schedules ─────────────────────────────────────────────────────────────────

@app_bp.route("/api/schedules")
@require_auth
def api_schedules():
    from scheduler.scan_scheduler import ScanScheduler
    sched = ScanScheduler(_orchestrator(), _db())
    return jsonify(sched.list_schedules())


@app_bp.route("/api/schedules", methods=["POST"])
@require_auth
def api_add_schedule():
    if not current_user().can("schedule.manage"):
        return jsonify({"error": "forbidden"}), 403
    data           = request.get_json() or {}
    domain_list_id = data.get("domain_list_id")
    interval_days  = int(data.get("interval_days", 90))
    name           = data.get("name", "unnamed")
    sector         = data.get("sector", "")
    region         = data.get("region", "")
    if not domain_list_id:
        return jsonify({"error": "domain_list_id required"}), 400
    from scheduler.scan_scheduler import ScanScheduler
    sched    = ScanScheduler(_orchestrator(), _db())
    sched_id = sched.add_schedule(name, domain_list_id, interval_days,
                                   sector=sector, region=region)
    return jsonify({"schedule_id": sched_id})


# ── Current user info ─────────────────────────────────────────────────────────

@app_bp.route("/api/me")
@require_auth
def api_me():
    return jsonify(current_user().to_dict())


# ── App shell HTML ─────────────────────────────────────────────────────────────
# Injects the original dashboard but with an auth header and user context.
# The JS fetch() calls use /app/api/* automatically because they are relative.

_APP_SHELL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor</title>
<!-- The dashboard CSS/JS is injected inline via the original DASHBOARD_HTML template
     which is rendered from within the create_app factory.  Here we provide the
     outer authenticated shell only. -->
<style>
:root { --bg:#0a0e1a; --panel:#0f1629; --border:#1e2d4a; --accent:#00d4ff;
        --accent2:#7c3aed; --text:#e2e8f0; --muted:#64748b; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text);
       font-family:'Inter',system-ui,sans-serif; }
.top-bar {
  background:linear-gradient(135deg,#0f1629,#1a1040);
  border-bottom:1px solid var(--border);
  height:48px; display:flex; align-items:center;
  justify-content:space-between; padding:0 1.25rem;
  position:sticky; top:0; z-index:50;
}
.top-bar .brand { font-family:'Space Mono',monospace; color:var(--accent);
                  font-size:.95rem; letter-spacing:.05em; }
.top-bar .brand em { color:var(--accent2); font-style:normal; }
.top-bar .user-bar { display:flex; align-items:center; gap:1rem; font-size:.8rem; }
.top-bar .user-bar .username { color:var(--text); }
.top-bar .user-bar .role-badge {
  background:rgba(124,58,237,.2); color:#a78bfa;
  padding:.15rem .5rem; border-radius:4px; font-size:.7rem;
}
.top-bar .user-bar .role-badge.admin { background:rgba(239,68,68,.15); color:#fca5a5; }
.top-bar .user-bar a { color:var(--muted); text-decoration:none; }
.top-bar .user-bar a:hover { color:var(--accent); }
.scope-banner {
  background:rgba(0,212,255,.06); border-bottom:1px solid rgba(0,212,255,.15);
  padding:.4rem 1.25rem; font-size:.75rem; color:var(--muted);
  display:none;
}
.scope-banner.show { display:block; }
</style>
</head>
<body>
<div class="top-bar">
  <div class="brand">PQC<em>-</em>Monitor</div>
  <div class="user-bar">
    {% if is_admin %}
    <a href="/admin">Admin Panel</a>
    {% endif %}
    <span class="username">{{ user.username }}</span>
    <span class="role-badge {% if user.role == 'admin' %}admin{% endif %}">{{ user.role }}</span>
    <a href="/change-password">Password</a>
    <a href="/logout">Sign out</a>
  </div>
</div>
{% if not is_admin %}
<div class="scope-banner show" id="scope-banner">
  Viewing: domains from your assigned lists only
</div>
{% endif %}

<!-- The original dashboard HTML is rendered below this point.
     All its fetch() calls go to /app/api/* because the page is at /app/ -->
<div id="pqc-dashboard-root"></div>

<script>
// Rewrite the dashboard's API base to /app/api instead of /api
// This is done by intercepting fetch before the dashboard JS loads.
const _origFetch = window.fetch;
window.fetch = function(url, opts) {
  if (typeof url === 'string' && url.startsWith('/api/')) {
    url = '/app' + url;
  }
  return _origFetch.call(this, url, opts);
};
</script>

<!-- Dashboard SPA content injected here -->
{{ dashboard_content | safe }}

</body>
</html>"""
