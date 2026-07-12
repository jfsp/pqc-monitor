#!/usr/bin/env python3
"""
PQC-Monitor: Dashboard Backend (Flask)
REST API + web UI for the PQC readiness dashboard.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, request, render_template_string
try:
    from flask_cors import CORS
    _HAS_CORS = True
except ImportError:
    _HAS_CORS = False

from data.database import Database
from scanner.orchestrator import ScanOrchestrator
from domain_discovery.domain_finder import DomainDiscovery

logger = logging.getLogger(__name__)


def create_app(config: dict = None) -> Flask:
    cfg = config or {}
    app = Flask(__name__)
    app.secret_key = cfg.get("secret_key", "pqcmonitor-dev-key")
    if _HAS_CORS:
        CORS(app)

    db_path = cfg.get("db_path", "data/pqc_monitor.db")
    db = Database(db_path)

    orchestrator = ScanOrchestrator(cfg)
    discovery = DomainDiscovery(
        anthropic_api_key=cfg.get("anthropic_api_key", ""),
        model=cfg.get("model", "claude-sonnet-4-20250514")
    )

    # ─── API Routes ──────────────────────────────────────────────

    @app.route("/api/summary")
    def api_summary():
        stats = db.get_summary_stats()
        runs = db.list_runs(5)
        return jsonify({"stats": stats, "recent_runs": runs})

    @app.route("/api/assessments")
    def api_assessments():
        run_id = request.args.get("run_id")
        assessments = db.get_latest_assessments(run_id)
        return jsonify(assessments)

    @app.route("/api/domain/<domain>")
    def api_domain_detail(domain):
        history = db.get_domain_history(domain)
        latest_scans = db.get_domain_scans(domain)
        extra = db.get_latest_domain_extra(
            domain, data_types=["cipher_enum", "chain", "cdn", "ssllabs", "group_enum"])
        return jsonify({"domain": domain, "history": history,
                        "scans": latest_scans[:5], "extra": extra})

    @app.route("/api/trends")
    def api_trends():
        trends = db.get_sector_trends()
        return jsonify(trends)

    @app.route("/api/runs")
    def api_runs():
        runs = db.list_runs(20)
        return jsonify(runs)

    @app.route("/api/domain-lists")
    def api_domain_lists():
        lists = db.get_domain_lists()
        return jsonify(lists)

    @app.route("/api/discover", methods=["POST"])
    def api_discover():
        data = request.get_json()
        query = data.get("query", "")
        max_domains = int(data.get("max_domains", 50))
        validate = data.get("validate", True)

        if not query:
            return jsonify({"error": "query is required"}), 400

        result = discovery.discover(query, max_domains, validate)
        return jsonify(result)

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json()
        domains = data.get("domains", [])
        sector = data.get("sector", "")
        region = data.get("region", "")
        use_shodan = data.get("use_shodan", False)

        if not domains:
            return jsonify({"error": "domains list is required"}), 400

        try:
            run_id = orchestrator.scan_domains(
                domains, sector=sector, region=region, use_shodan=use_shodan
            )
            return jsonify({"run_id": run_id, "status": "completed",
                            "domains_scanned": len(domains)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/reassess", methods=["POST"])
    def api_reassess():
        data = request.get_json()
        run_id = data.get("run_id")
        guideline_ids = data.get("guidelines")

        if not run_id:
            return jsonify({"error": "run_id is required"}), 400

        try:
            new_run_id = orchestrator.reassess_run(run_id, guideline_ids)
            return jsonify({"new_run_id": new_run_id, "status": "completed"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ct/stats")
    def api_ct_stats():
        return jsonify(db.get_ct_stats())

    @app.route("/api/ct/summaries")
    def api_ct_summaries():
        domain = request.args.get("domain") or None
        return jsonify(db.get_ct_summaries(domain=domain, limit=100))

    @app.route("/api/ct/certificates")
    def api_ct_certificates():
        domain = request.args.get("domain") or None
        return jsonify(db.get_ct_pqc_certificates(domain=domain, limit=200))

    @app.route("/api/ct/timeline")
    def api_ct_timeline():
        return jsonify(db.get_ct_timeline())

    @app.route("/api/ct/monitor", methods=["POST"])
    def api_ct_monitor():
        data     = request.get_json() or {}
        domains  = data.get("domains", [])
        fetch_pem = data.get("fetch_pem", False)   # default False: faster, no PEM download
        max_certs = int(data.get("max_certs", 100))

        if not domains:
            return jsonify({"error": "domains list required"}), 400

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from ct.ct_monitor import monitor_domains
        summaries = monitor_domains(domains, fetch_pem=fetch_pem,
                                    max_certs_per_domain=max_certs)
        saved = 0
        for s in summaries:
            db.save_ct_summary(s.to_dict())
            saved += 1
        return jsonify({
            "domains_processed": saved,
            "pqc_certs_found":   sum(s.pqc_certs_found for s in summaries),
            "hybrid_certs_found": sum(s.hybrid_certs_found for s in summaries),
        })

    def api_export():
        fmt    = request.args.get("format", "csv")
        run_id = request.args.get("run_id") or None
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from reports.report_generator import export_csv, export_json, export_text_report

        if fmt == "json":
            content  = export_json(db, run_id)
            mimetype = "application/json"
            filename = "pqc_report.json"
        elif fmt == "text":
            content  = export_text_report(db, run_id)
            mimetype = "text/plain"
            filename = "pqc_report.txt"
        else:
            content  = export_csv(db, run_id)
            mimetype = "text/csv"
            filename = "pqc_report.csv"

        from flask import Response
        return Response(
            content,
            mimetype=mimetype,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    @app.route("/api/roadmap/stats")
    def api_roadmap_stats():
        return jsonify(db.get_roadmap_stats())

    @app.route("/api/roadmap")
    def api_roadmap():
        run_id = request.args.get("run_id") or None
        domain = request.args.get("domain") or None
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from roadmap.generator import generate_sector_roadmap, generate_domain_roadmap

        # Try stored roadmaps first
        stored = db.get_roadmaps(run_id=run_id, domain=domain)
        if stored:
            return jsonify(stored)

        # Generate on-the-fly from assessments
        assessments = db.get_latest_assessments(run_id)
        if domain:
            assessments = [a for a in assessments if a.get("domain") == domain]
        if not assessments:
            return jsonify([])

        if domain and len(assessments) == 1:
            dr = generate_domain_roadmap(assessments[0])
            return jsonify([dr.to_dict()])

        sector_roadmap = generate_sector_roadmap(assessments)
        # Return per-domain list for table rendering
        return jsonify(sector_roadmap.domains)

    @app.route("/api/roadmap/domain/<domain_name>")
    def api_roadmap_domain(domain_name):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from roadmap.generator import generate_domain_roadmap

        stored = db.get_roadmaps(domain=domain_name)
        if stored:
            return jsonify(stored[0])

        assessments = db.get_latest_assessments()
        a = next((x for x in assessments if x.get("domain") == domain_name), None)
        if not a:
            return jsonify({"error": "domain not found"}), 404

        dr = generate_domain_roadmap(a)
        return jsonify(dr.to_dict())

    @app.route("/api/roadmap/generate", methods=["POST"])
    def api_roadmap_generate():
        data   = request.get_json() or {}
        run_id = data.get("run_id") or None
        save   = data.get("save", False)
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from roadmap.generator import generate_domain_roadmap, generate_sector_roadmap

        assessments = db.get_latest_assessments(run_id)
        if not assessments:
            return jsonify({"error": "no assessment data"}), 400

        # Enrich with CDN info
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
            "domains_processed": generated,
            "saved": save,
            "avg_current_score": sr.avg_current_score,
            "critical_domains": sr.critical_domains,
            "total_effort_min": sr.total_effort_days_min,
            "total_effort_max": sr.total_effort_days_max,
        })


    def api_schedules():
        from scheduler.scan_scheduler import ScanScheduler
        sched = ScanScheduler(orchestrator, db)
        return jsonify(sched.list_schedules())

    @app.route("/api/schedules", methods=["POST"])
    def api_add_schedule():
        data           = request.get_json()
        domain_list_id = data.get("domain_list_id")
        interval_days  = int(data.get("interval_days", 90))
        name           = data.get("name", "unnamed")
        sector         = data.get("sector", "")
        region         = data.get("region", "")
        if not domain_list_id:
            return jsonify({"error": "domain_list_id required"}), 400
        from scheduler.scan_scheduler import ScanScheduler
        sched    = ScanScheduler(orchestrator, db)
        sched_id = sched.add_schedule(name, domain_list_id, interval_days,
                                      sector=sector, region=region)
        return jsonify({"schedule_id": sched_id})

    @app.route("/api/save-domains", methods=["POST"])
    def api_save_domains():
        data = request.get_json()
        name = data.get("name", "unnamed")
        domains = data.get("domains", [])
        query = data.get("query", "")
        list_id = db.save_domain_list(name, domains, query)
        return jsonify({"list_id": list_id, "count": len(domains)})

    # ─── Main Dashboard UI ───────────────────────────────────────

    @app.route("/")
    @app.route("/dashboard")
    def dashboard():
        from version import VERSION
        return render_template_string(DASHBOARD_HTML, version=VERSION)

    return app


# ──────────────────────────────────────────────────────────────────────────────
# Embedded Dashboard HTML/CSS/JS
# ──────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC-Monitor — Post-Quantum Cryptography Readiness</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root {
  --bg: #0a0e1a;
  --panel: #0f1629;
  --border: #1e2d4a;
  --accent: #00d4ff;
  --accent2: #7c3aed;
  --critical: #ef4444;
  --weak: #f97316;
  --moderate: #eab308;
  --ready: #22c55e;
  --text: #e2e8f0;
  --muted: #64748b;
  --font-mono: 'Space Mono', monospace;
  --font-sans: 'Inter', sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font-sans); min-height: 100vh; }

/* ─── Header ─── */
.header {
  background: linear-gradient(135deg, #0f1629 0%, #1a1040 100%);
  border-bottom: 1px solid var(--border);
  padding: 0 1.5rem;
  display: flex; align-items: center; justify-content: space-between;
  height: 56px; gap: 1rem;
}
.logo { font-family: var(--font-mono); font-size: 1.1rem; color: var(--accent); letter-spacing: 0.05em; flex-shrink: 0; }
.logo span { color: var(--accent2); }
.header-nav { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.nav-btn {
  background: transparent; border: 1px solid var(--border);
  color: var(--muted); padding: 0.4rem 1rem; border-radius: 6px;
  cursor: pointer; font-size: 0.8rem; font-family: var(--font-sans);
  transition: all 0.2s;
}
.nav-btn.active, .nav-btn:hover {
  border-color: var(--accent); color: var(--accent); background: rgba(0,212,255,0.07);
}

/* ─── Layout ─── */
.main { max-width: 1400px; margin: 0 auto; padding: 2rem; }

/* ─── Summary cards ─── */
.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}
.stat-card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; padding: 1.25rem; text-align: center;
  transition: border-color 0.2s;
}
.stat-card:hover { border-color: var(--accent); }
.stat-val { font-family: var(--font-mono); font-size: 2rem; font-weight: 700; }
.stat-label { color: var(--muted); font-size: 0.75rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.05em; }
.val-critical { color: var(--critical); }
.val-weak     { color: var(--weak); }
.val-moderate { color: var(--moderate); }
.val-ready    { color: var(--ready); }
.val-na       { color: var(--muted); }
.val-accent   { color: var(--accent); }

/* ─── Panels ─── */
.panels { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
@media (max-width: 900px) { .panels { grid-template-columns: 1fr; } }
.panel {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden;
}
.panel-header {
  padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
.panel-title { font-family: var(--font-mono); font-size: 0.85rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.1em; }
.panel-body { padding: 1.5rem; }

/* ─── Domain Table ─── */
.domain-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.domain-table th {
  text-align: left; padding: 0.5rem 0.75rem;
  color: var(--muted); font-weight: 500; text-transform: uppercase;
  font-size: 0.7rem; letter-spacing: 0.05em; border-bottom: 1px solid var(--border);
}
.domain-table td { padding: 0.6rem 0.75rem; border-bottom: 1px solid rgba(30,45,74,0.5); }
.domain-table tr:hover td { background: rgba(0,212,255,0.03); }
.domain-table tr:last-child td { border-bottom: none; }
.domain-link { color: var(--text); text-decoration: none; font-family: var(--font-mono); font-size: 0.8rem; }
.domain-link:hover { color: var(--accent); }

/* ─── Score badge ─── */
.score-badge {
  display: inline-flex; align-items: center; justify-content: center;
  width: 40px; height: 24px; border-radius: 4px; font-family: var(--font-mono);
  font-size: 0.75rem; font-weight: 700;
}
.score-critical { background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }
.score-weak     { background: rgba(249,115,22,0.15); color: var(--weak); border: 1px solid rgba(249,115,22,0.3); }
.score-moderate { background: rgba(234,179,8,0.15); color: var(--moderate); border: 1px solid rgba(234,179,8,0.3); }
.score-ready    { background: rgba(34,197,94,0.15); color: var(--ready); border: 1px solid rgba(34,197,94,0.3); }
.score-na       { background: rgba(100,116,139,0.12); color: var(--muted); border: 1px solid rgba(100,116,139,0.25); }

.level-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px;
}
.dot-critical { background: var(--critical); box-shadow: 0 0 6px var(--critical); }
.dot-weak     { background: var(--weak); box-shadow: 0 0 6px var(--weak); }
.dot-moderate { background: var(--moderate); box-shadow: 0 0 6px var(--moderate); }
.dot-ready    { background: var(--ready); box-shadow: 0 0 6px var(--ready); }
.dot-na       { background: var(--muted); box-shadow: none; }

/* ─── Forms & Controls ─── */
.form-row { display: flex; gap: 0.75rem; margin-bottom: 1rem; align-items: flex-start; flex-wrap: wrap; }
input[type=text], textarea, select {
  background: rgba(255,255,255,0.05); border: 1px solid var(--border);
  color: var(--text); padding: 0.6rem 0.9rem; border-radius: 8px;
  font-family: var(--font-sans); font-size: 0.875rem; outline: none;
  transition: border-color 0.2s;
}
input[type=text]:focus, textarea:focus { border-color: var(--accent); }
textarea { resize: vertical; min-height: 80px; width: 100%; font-family: var(--font-mono); font-size: 0.8rem; }
.btn {
  background: var(--accent); color: #0a0e1a; border: none;
  padding: 0.6rem 1.25rem; border-radius: 8px; font-weight: 600;
  cursor: pointer; font-size: 0.875rem; transition: all 0.2s; white-space: nowrap;
}
.btn:hover { background: #33ddff; transform: translateY(-1px); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
.btn-outline {
  background: transparent; border: 1px solid var(--accent);
  color: var(--accent); padding: 0.5rem 1rem; border-radius: 8px;
  cursor: pointer; font-size: 0.8rem; transition: all 0.2s;
}
.btn-outline:hover { background: rgba(0,212,255,0.1); }
.btn-danger { background: var(--critical); }

/* ─── Views ─── */
.view { display: none; }
.view.active { display: block; }
.stat-card-filter { cursor: pointer; transition: transform .12s, box-shadow .12s; }
.stat-card-filter:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,.25); }
.stat-card-filter.filter-active { outline: 2px solid var(--accent); outline-offset: 2px; }
.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
.sortable:hover { color: var(--accent); }
.sort-icon { font-size: .65rem; margin-left: .2rem; color: var(--accent); }

/* ─── Progress / alerts ─── */
.alert {
  padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem;
  font-size: 0.875rem; display: none;
}
.alert.show { display: block; }
.alert-info  { background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.3); color: var(--accent); }
.alert-error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: var(--critical); }
.alert-ok    { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: var(--ready); }

/* ─── Findings list ─── */
.finding {
  padding: 0.6rem 0.9rem; border-radius: 8px; margin-bottom: 0.5rem;
  font-size: 0.8rem; border-left: 3px solid;
}
.finding-critical { background: rgba(239,68,68,0.08); border-color: var(--critical); }
.finding-high     { background: rgba(249,115,22,0.08); border-color: var(--weak); }
.finding-medium   { background: rgba(234,179,8,0.08);  border-color: var(--moderate); }
.finding-low, .finding-info { background: rgba(0,212,255,0.05); border-color: var(--muted); }
.finding-rec { color: var(--muted); font-size: 0.75rem; margin-top: 0.25rem; }

/* ─── Chart containers ─── */
.chart-wrap { position: relative; height: 220px; }

/* ─── Loader ─── */
.loader {
  display: inline-block; width: 16px; height: 16px;
  border: 2px solid var(--border); border-top-color: var(--accent);
  border-radius: 50%; animation: spin 0.6s linear infinite; vertical-align: middle; margin-right: 6px;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ─── Domains textarea results ─── */
.domain-tags { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem; }
.domain-tag {
  background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.2);
  color: var(--accent); padding: 0.2rem 0.6rem; border-radius: 4px;
  font-family: var(--font-mono); font-size: 0.72rem;
}

.full-width { grid-column: 1 / -1; }
.pqc-pill {
  display: inline-flex; align-items: center; gap: 4px;
  background: rgba(124,58,237,0.15); border: 1px solid rgba(124,58,237,0.3);
  color: #a78bfa; padding: 0.15rem 0.5rem; border-radius: 4px;
  font-size: 0.7rem; font-family: var(--font-mono);
}
.tls-pill {
  display: inline-flex; background: rgba(0,212,255,0.08);
  border: 1px solid rgba(0,212,255,0.2); color: var(--accent);
  padding: 0.15rem 0.5rem; border-radius: 4px;
  font-size: 0.7rem; font-family: var(--font-mono);
}

footer {
  text-align: center; color: var(--muted); font-size: 0.7rem;
  padding: 2rem; border-top: 1px solid var(--border); margin-top: 2rem;
}
</style>
</head>
<body>

<div class="header">
  <div class="logo">PQC<span>-</span>Monitor <span style="font-size:0.7rem;color:var(--muted)">v{{ version }}</span></div>
  <div style="display:flex;align-items:center;gap:.75rem">
    {% if user is defined %}
    {% if user.role == 'admin' %}<a href="/admin" style="color:var(--muted);font-size:.78rem;text-decoration:none" onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--muted)'">Admin Panel</a>{% endif %}
    <span style="color:var(--text);font-size:.8rem">{{ user.username }}</span>
    <span style="background:rgba({% if user.role == 'admin' %}239,68,68{% else %}124,58,237{% endif %},.2);color:{% if user.role == 'admin' %}#fca5a5{% else %}#a78bfa{% endif %};padding:.15rem .5rem;border-radius:4px;font-size:.7rem">{{ user.role }}</span>
    <a href="/change-password" style="color:var(--muted);font-size:.78rem;text-decoration:none" onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--muted)'">Password</a>
    <a href="/logout" style="color:var(--muted);font-size:.78rem;text-decoration:none" onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--muted)'">Sign out</a>
    {% endif %}
  </div>
  <div class="header-nav">
    <button class="nav-btn active" onclick="showView('dashboard',this)">Dashboard</button>
    {% if can_view_group_report %}<button class="nav-btn" onclick="showView('group_report',this); grInit()">Group Report</button>{% endif %}
    {% if user.is_admin %}<button class="nav-btn" onclick="showView('domains',this)">Domain Discovery</button>{% endif %}
    {% if user.is_admin %}<button class="nav-btn" onclick="showView('scan',this)">Scan</button>{% endif %}
    <button class="nav-btn" onclick="showView('trends',this)">Trends</button>
    <button class="nav-btn" onclick="showView('ct',this)">CT Monitor</button>
    <button class="nav-btn" onclick="showView('roadmap',this)">Roadmap</button>
    <button class="nav-btn" onclick="showView('settings',this)">Settings</button>
  </div>
</div>
{% if user is defined and not user.is_admin %}
<div style="background:rgba(0,212,255,.06);border-bottom:1px solid rgba(0,212,255,.15);padding:.35rem 2rem;font-size:.74rem;color:var(--muted)">
  Viewing domains from your assigned lists only
</div>
{% endif %}

<div class="main">

  <!-- ═══ DASHBOARD VIEW ═══ -->
  <div id="view-dashboard" class="view active">
    <div id="stats-grid" class="stats-grid">
      <div class="stat-card"><div class="stat-val val-accent" id="stat-total">—</div><div class="stat-label">Domains Monitored</div></div>
      <div class="stat-card"><div class="stat-val val-accent" id="stat-avg">—</div><div class="stat-label">Avg PQC Score</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-critical" onclick="setFilter('critical')" title="Click to filter by Critical"><div class="stat-val val-critical" id="stat-critical">—</div><div class="stat-label">Critical</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-weak"     onclick="setFilter('weak')"     title="Click to filter by Weak"><div class="stat-val val-weak" id="stat-weak">—</div><div class="stat-label">Weak</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-moderate" onclick="setFilter('moderate')" title="Click to filter by Moderate"><div class="stat-val val-moderate" id="stat-moderate">—</div><div class="stat-label">Moderate</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-ready"    onclick="setFilter('ready')"    title="Click to filter by PQC-Ready"><div class="stat-val val-ready" id="stat-ready">—</div><div class="stat-label">PQC-Ready</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-na"       onclick="setFilter('na')"       title="Click to filter by N/A (no TLS)"><div class="stat-val val-na" id="stat-na">—</div><div class="stat-label">No TLS</div></div>
      <div class="stat-card stat-card-filter" id="filter-card-pqc"      onclick="setFilter('pqc')"      title="Click to filter PQC Detected"><div class="stat-val" id="stat-pqc" style="color:#a78bfa">—</div><div class="stat-label">PQC Detected</div></div>
      <div class="stat-card"><div class="stat-val" id="stat-ct-pqc" style="color:#22c55e">—</div><div class="stat-label">PQC Certs (CT)</div></div>
      <div class="stat-card"><div class="stat-val" id="stat-p1-actions" style="color:var(--critical)">—</div><div class="stat-label">Urgent Actions</div></div>
    </div>

    <div class="panels">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Readiness Distribution</div>
        </div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartDist"></canvas></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">TLS Version Coverage</div>
        </div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartTLS"></canvas></div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Domain Assessments
          <span id="filter-badge" style="display:none;margin-left:.6rem;background:rgba(0,212,255,.15);color:var(--accent);padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-family:var(--font-sans)"></span>
        </div>
        <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
          <select id="filter-org" onchange="applyDropdownFilters()"
            style="background:var(--panel);border:1px solid var(--border);color:var(--text);padding:.25rem .5rem;border-radius:4px;font-size:.78rem">
            <option value="">All Organisations</option>
          </select>
          <select id="filter-region" onchange="applyDropdownFilters()"
            style="background:var(--panel);border:1px solid var(--border);color:var(--text);padding:.25rem .5rem;border-radius:4px;font-size:.78rem">
            <option value="">All Regions</option>
          </select>
          <select id="filter-country" onchange="applyDropdownFilters()"
            style="background:var(--panel);border:1px solid var(--border);color:var(--text);padding:.25rem .5rem;border-radius:4px;font-size:.78rem">
            <option value="">All Countries</option>
          </select>
          <button class="btn-outline" id="btn-clear-filter" style="display:none" onclick="setFilter(null)">✕ Clear filter</button>
          <button class="btn-outline" onclick="loadAssessments()">↻ Refresh</button>
        </div>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table" id="domain-table">
          <thead>
            <tr>
              <th class="sortable" onclick="sortBy('domain')"   id="th-domain">Domain <span class="sort-icon" id="si-domain"></span></th>
              <th class="sortable" onclick="sortBy('score')"    id="th-score">Score <span class="sort-icon" id="si-score">▲</span></th>
              <th class="sortable" onclick="sortBy('level')"    id="th-level">Level <span class="sort-icon" id="si-level"></span></th>
              <th>TLS</th>
              <th class="sortable" onclick="sortBy('key_type')" id="th-key_type">Key <span class="sort-icon" id="si-key_type"></span></th>
              <th class="sortable" onclick="sortBy('has_pqc')"  id="th-has_pqc">PQC <span class="sort-icon" id="si-has_pqc"></span></th>
              <th class="sortable" onclick="sortBy('findings')" id="th-findings">Findings <span class="sort-icon" id="si-findings"></span></th>
            </tr>
          </thead>
          <tbody id="domain-tbody">
            <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No scan data yet. Run a scan first.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Domain detail modal -->
    <div id="domain-detail" style="display:none;margin-top:1.5rem">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title" id="detail-title">Domain Detail</div>
          <button class="btn-outline" onclick="document.getElementById('domain-detail').style.display='none'">✕ Close</button>
        </div>
        <div class="panel-body" id="detail-body"></div>
      </div>
    </div>
  </div>

  <!-- ═══ DOMAIN FULL TLS DETAIL VIEW (drill-down, no nav tab) ═══ -->
  <div id="view-domain-full" class="view">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title" id="df-title">TLS Details</div>
        <button class="btn-outline" onclick="closeDomainFull()">← Back</button>
      </div>
      <div class="panel-body" id="df-body"></div>
    </div>
  </div>

  <!-- ═══ DOMAIN DISCOVERY VIEW ═══ -->
  <div id="view-domains" class="view">
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header"><div class="panel-title">Natural Language Domain Discovery</div></div>
      <div class="panel-body">
        <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem">
          Describe a sector and region in plain language. The AI will generate a list of domains to monitor.
        </p>
        <div class="form-row">
          <input type="text" id="discovery-query" placeholder='e.g. "financial institutions in Spain" or "healthcare providers in Germany"' style="flex:1;min-width:280px">
          <input type="number" id="discovery-max" placeholder="Max domains" value="30" style="width:130px">
          <button class="btn" onclick="discoverDomains()">Discover</button>
        </div>
        <div id="discovery-alert" class="alert"></div>
        <div id="discovery-result" style="display:none">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem">
            <div>
              <span style="color:var(--muted);font-size:0.8rem">Found </span>
              <span id="discovery-count" style="color:var(--accent);font-weight:600"></span>
              <span style="color:var(--muted);font-size:0.8rem"> domains</span>
              <span id="discovery-source" style="color:var(--muted);font-size:0.75rem;margin-left:0.5rem"></span>
            </div>
            <div style="display:flex;gap:0.5rem">
              <button class="btn-outline" onclick="scanDiscoveredDomains()">Scan These Domains</button>
              <button class="btn-outline" onclick="saveDomainList()">Save List</button>
            </div>
          </div>
          <div id="discovery-tags" class="domain-tags"></div>
          <div style="margin-top:1rem">
            <div style="color:var(--muted);font-size:0.75rem;margin-bottom:0.3rem">NOTES</div>
            <div id="discovery-notes" style="color:var(--text);font-size:0.82rem"></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><div class="panel-title">Saved Domain Lists</div></div>
      <div class="panel-body">
        <div id="domain-lists-body" style="color:var(--muted);font-size:0.85rem">Loading...</div>
      </div>
    </div>
  </div>

  <!-- ═══ SCAN VIEW ═══ -->
  <div id="view-scan" class="view">
    <div class="panels">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Manual Scan</div></div>
        <div class="panel-body">
          <div style="color:var(--muted);font-size:0.8rem;margin-bottom:1rem">Enter domains to scan (one per line):</div>
          <textarea id="scan-domains" placeholder="example.com&#10;bank.es&#10;healthcare.de"></textarea>
          <div class="form-row" style="margin-top:0.75rem">
            <input type="text" id="scan-sector" placeholder="Sector (optional)" style="flex:1">
            <input type="text" id="scan-region" placeholder="Region (optional)" style="flex:1">
          </div>
          <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem">
            <label style="display:flex;align-items:center;gap:0.5rem;font-size:0.85rem;cursor:pointer">
              <input type="checkbox" id="scan-shodan" style="width:auto"> Use Shodan API
            </label>
          </div>
          <button class="btn" id="btn-scan" onclick="startScan()">Start Scan</button>
          <div id="scan-alert" class="alert" style="margin-top:1rem"></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><div class="panel-title">Re-Assessment</div></div>
        <div class="panel-body">
          <p style="color:var(--muted);font-size:0.82rem;margin-bottom:1rem">
            Re-evaluate existing scan data against updated guidelines without re-scanning.
          </p>
          <div class="form-row">
            <select id="reassess-run" style="flex:1">
              <option value="">Select a scan run...</option>
            </select>
            <button class="btn btn-outline" onclick="startReassess()">Re-Assess</button>
          </div>
          <div style="font-size:0.8rem;color:var(--muted);margin-top:0.5rem">
            Guidelines: <span style="color:var(--text)">NIST SP 800-131Ar3, BSI TR-02102-1, CCN-STIC-221</span>
          </div>
          <div id="reassess-alert" class="alert" style="margin-top:1rem"></div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><div class="panel-title">Scan History</div></div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table">
          <thead><tr><th>Run ID</th><th>Started</th><th>Sector</th><th>Region</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody id="runs-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- Export panel -->
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header"><div class="panel-title">Export Results</div></div>
      <div class="panel-body">
        <p style="color:var(--muted);font-size:0.82rem;margin-bottom:1rem">
          Download assessment data for reporting, compliance review, or further analysis.
        </p>
        <div class="form-row">
          <select id="export-run" style="width:200px">
            <option value="">All runs (latest per domain)</option>
          </select>
          <button class="btn-outline" onclick="doExport('csv')">⬇ CSV</button>
          <button class="btn-outline" onclick="doExport('json')">⬇ JSON</button>
          <button class="btn-outline" onclick="doExport('text')">⬇ Text Report</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ TRENDS VIEW ═══ -->
  <div id="view-trends" class="view">
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header"><div class="panel-title">Score Trend Over Time</div></div>
      <div class="panel-body">
        <div class="chart-wrap" style="height:280px"><canvas id="chartTrend"></canvas></div>
        <p id="trend-empty" style="color:var(--muted);text-align:center;font-size:0.85rem;margin-top:1rem;display:none">
          Run at least 2 scans to see trends. Schedule periodic scans every 90 days.
        </p>
      </div>
    </div>
    <div class="panels">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Readiness Level Changes</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartLevels"></canvas></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">PQC Adoption Rate</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartPQC"></canvas></div>
        </div>
      </div>
    </div>

    <!-- Domain history chart -->
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header">
        <div class="panel-title">Per-Domain Score History</div>
      </div>
      <div class="panel-body">
        <div class="form-row" style="margin-bottom:1rem">
          <select id="history-domain-sel" style="flex:1;max-width:360px" onchange="loadDomainHistory(this.value)">
            <option value="">Select a domain…</option>
          </select>
        </div>
        <div class="chart-wrap" style="height:220px"><canvas id="chartDomainHistory"></canvas></div>
        <div id="domain-history-empty" style="color:var(--muted);font-size:.82rem;margin-top:.5rem;display:none">
          No history available for this domain yet.
        </div>
      </div>
    </div>

    <!-- Schedules -->
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header">
        <div class="panel-title">Periodic Scan Schedules</div>
        <button class="btn-outline" onclick="loadSchedules()">↻ Refresh</button>
      </div>
      <div class="panel-body">
        <p style="color:var(--muted);font-size:.82rem;margin-bottom:1rem">
          Schedules run automatically at the configured interval.
          Add new ones from the CLI: <code style="color:var(--accent)">pqc_monitor.py schedule --domains FILE --interval 90d</code>
        </p>
        <div id="schedules-body" style="color:var(--muted)">Loading…</div>
      </div>
    </div>
  </div>  <!-- /view-trends -->


  <!-- ═══ CT MONITOR VIEW ═══ -->
  <div id="view-ct" class="view">

    <!-- Summary cards -->
    <div class="stats-grid" style="margin-bottom:1.5rem">
      <div class="stat-card"><div class="stat-val val-accent"  id="ct-stat-domains">—</div><div class="stat-label">Domains Monitored</div></div>
      <div class="stat-card"><div class="stat-val val-accent"  id="ct-stat-total">—</div><div class="stat-label">Total Certs</div></div>
      <div class="stat-card"><div class="stat-val val-ready"   id="ct-stat-pqc">—</div><div class="stat-label">PQC Certs Found</div></div>
      <div class="stat-card"><div class="stat-val" style="color:#a78bfa" id="ct-stat-hybrid">—</div><div class="stat-label">Hybrid Certs</div></div>
      <div class="stat-card"><div class="stat-val val-moderate" id="ct-stat-domains-pqc">—</div><div class="stat-label">Domains with PQC</div></div>
    </div>

    <!-- Run CT monitor -->
    {% if user.is_admin %}
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header"><div class="panel-title">Run CT Monitor</div></div>
      <div class="panel-body">
        <p style="color:var(--muted);font-size:0.82rem;margin-bottom:1rem">
          Query crt.sh Certificate Transparency logs for monitored domains.
          Detects PQC and hybrid certificates using OID classification.
          No active scanning — passive CT log analysis only.
        </p>
        <div class="form-row">
          <textarea id="ct-domains" placeholder="example.com&#10;bank.es&#10;healthcare.de" style="flex:1;min-height:80px"></textarea>
        </div>
        <div class="form-row" style="align-items:center">
          <label style="display:flex;align-items:center;gap:0.5rem;font-size:0.85rem;cursor:pointer">
            <input type="checkbox" id="ct-fetch-pem" style="width:auto">
            Download PEM for full OID inspection
            <span style="color:var(--muted);font-size:0.75rem">(slower — required to detect PQC OIDs directly)</span>
          </label>
        </div>
        <button class="btn" id="btn-ct-run" onclick="runCTMonitor()">Run CT Monitor</button>
        <div id="ct-run-alert" class="alert" style="margin-top:1rem"></div>
      </div>
    </div>
    {% endif %}

    <!-- OID registry info -->
    <div class="panels" style="margin-bottom:1.5rem">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">PQC Certificate Timeline</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartCTTimeline"></canvas></div>
          <p id="ct-timeline-empty" style="color:var(--muted);font-size:0.82rem;text-align:center;margin-top:0.5rem;display:none">
            No CT data yet. Run the CT monitor first.
          </p>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">PQC Algorithm Distribution</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartCTAlgos"></canvas></div>
        </div>
      </div>
    </div>

    <!-- Domain CT summary table -->
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header">
        <div class="panel-title">Domain CT Summary</div>
        <button class="btn-outline" onclick="loadCTSummaries()">↻ Refresh</button>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Queried</th>
              <th>Total Certs</th>
              <th>PQC Certs</th>
              <th>Hybrid</th>
              <th>Algorithms</th>
              <th>Issuers</th>
            </tr>
          </thead>
          <tbody id="ct-summary-tbody">
            <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">
              No CT data. Enter domains above and click Run CT Monitor.
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PQC certificates detail table -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">PQC &amp; Hybrid Certificates Detected</div>
        <div style="font-size:0.75rem;color:var(--muted)">Source: crt.sh CT aggregator</div>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table" id="ct-certs-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Subject CN</th>
              <th>Issuer</th>
              <th>Signature Algorithm</th>
              <th>PQC Algorithms</th>
              <th>Type</th>
              <th>Not Before</th>
              <th>Expiry</th>
            </tr>
          </thead>
          <tbody id="ct-certs-tbody">
            <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:1.5rem">
              No PQC certificates found yet.
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- OID Reference -->
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header"><div class="panel-title">PQC OID Registry (monitored)</div></div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table">
          <thead><tr><th>OID</th><th>Algorithm</th><th>Type</th><th>Standard</th></tr></thead>
          <tbody>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.6.1.4.1.2.267.12.4.4</td><td>ML-DSA-44</td><td>Signature</td><td>FIPS 204</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.6.1.4.1.2.267.12.6.5</td><td>ML-DSA-65</td><td>Signature</td><td>FIPS 204</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.6.1.4.1.2.267.12.8.7</td><td>ML-DSA-87</td><td>Signature</td><td>FIPS 204</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.6.1.4.1.22554.5.6.2</td><td>ML-KEM-768</td><td>KEM / SPKI</td><td>FIPS 203</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.9999.3.6</td><td>Falcon-512</td><td>Signature</td><td>NIST Round 3</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.9999.3.9</td><td>Falcon-1024</td><td>Signature</td><td>NIST Round 3</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">1.3.9999.6.4.13</td><td>SLH-DSA-SHA2-128s</td><td>Signature</td><td>FIPS 205</td></tr>
            <tr><td style="font-family:var(--font-mono);font-size:.72rem">2.16.840.1.114027.80.8.1.x</td><td>Composite-ML-DSA-*</td><td>Hybrid Sig</td><td>draft-ounsworth</td></tr>
          </tbody>
        </table>
        <div style="padding:1rem;color:var(--muted);font-size:0.75rem">
          OID assignments are from IETF drafts and NIST FIPS 203/204/205. Experimental
          OID prefix 1.3.9999.* is used in pre-standard deployments. Registry is updated
          as standards are finalised — see <code>ct/ct_monitor.py</code>.
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ ROADMAP VIEW ═══ -->
  <div id="view-roadmap" class="view">

    <!-- Summary cards -->
    <div class="stats-grid" style="margin-bottom:1.5rem">
      <div class="stat-card"><div class="stat-val val-accent"   id="rm-stat-domains">—</div><div class="stat-label">Domains with Roadmap</div></div>
      <div class="stat-card"><div class="stat-val val-critical" id="rm-stat-p1">—</div><div class="stat-label">Phase 1 Actions</div></div>
      <div class="stat-card"><div class="stat-val val-moderate" id="rm-stat-p2">—</div><div class="stat-label">Phase 2 Actions</div></div>
      <div class="stat-card"><div class="stat-val" style="color:#a78bfa" id="rm-stat-p3">—</div><div class="stat-label">Phase 3 (PQC) Actions</div></div>
      <div class="stat-card"><div class="stat-val val-muted"    id="rm-stat-effort" style="color:var(--muted);font-size:1.2rem">—</div><div class="stat-label">Est. Effort Range</div></div>
    </div>

    <!-- Generate / controls -->
    {% if user.is_admin %}
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header"><div class="panel-title">Generate Roadmap</div></div>
      <div class="panel-body">
        <p style="color:var(--muted);font-size:.82rem;margin-bottom:1rem">
          Generates a phased PQC migration plan from existing scan data.
          No additional scanning required.
        </p>
        <div class="form-row">
          <select id="rm-run-sel" style="flex:1;max-width:320px">
            <option value="">Latest assessment per domain</option>
          </select>
          <label style="display:flex;align-items:center;gap:.5rem;font-size:.85rem;cursor:pointer">
            <input type="checkbox" id="rm-save" style="width:auto"> Save to database
          </label>
          <button class="btn" id="btn-rm-gen" onclick="generateRoadmap()">Generate Roadmap</button>
        </div>
        <div id="rm-alert" class="alert" style="margin-top:.75rem"></div>
      </div>
    </div>
    {% endif %}

    <!-- Phase timeline chart + effort bar chart -->
    <div class="panels" style="margin-bottom:1.5rem">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Score Projection by Phase</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartRmScores"></canvas></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Effort Distribution (person-days)</div></div>
        <div class="panel-body">
          <div class="chart-wrap"><canvas id="chartRmEffort"></canvas></div>
        </div>
      </div>
    </div>

    <!-- Domain roadmap table -->
    <div class="panel" style="margin-bottom:1.5rem">
      <div class="panel-header">
        <div class="panel-title">Domain Migration Plans</div>
        <button class="btn-outline" onclick="loadRoadmapTable()">↻ Refresh</button>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table">
          <thead>
            <tr>
              <th>Domain</th><th>Score Now</th><th>→ Phase 1</th><th>→ Phase 2</th><th>→ Phase 3</th>
              <th>P1 Actions</th><th>P2 Actions</th><th>P3 Actions</th>
              <th>Effort</th><th>Est. Completion</th>
            </tr>
          </thead>
          <tbody id="rm-domain-tbody">
            <tr><td colspan="10" style="text-align:center;color:var(--muted);padding:2rem">
              Click Generate Roadmap to create migration plans.
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Domain detail drawer -->
    <div id="rm-domain-detail" style="display:none">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title" id="rm-detail-title">Action Plan</div>
          <button class="btn-outline" onclick="document.getElementById('rm-domain-detail').style.display='none'">✕ Close</button>
        </div>
        <div class="panel-body" id="rm-detail-body"></div>
      </div>
    </div>

    <!-- Phase reference -->
    <div class="panel">
      <div class="panel-header"><div class="panel-title">Phase Reference</div></div>
      <div class="panel-body" style="padding:0">
        <table class="domain-table">
          <thead><tr><th>Phase</th><th>Horizon</th><th>Focus</th><th>Regulatory Anchor</th></tr></thead>
          <tbody>
            <tr>
              <td><span class="score-badge score-critical">P1</span></td>
              <td style="font-size:.78rem;color:var(--muted)">Now → 6 months</td>
              <td style="font-size:.82rem">Disable broken crypto: TLS ≤1.1, RC4, DES, NULL, SHA-1 certs, RSA&lt;2048</td>
              <td style="font-size:.75rem;color:var(--muted)">Already non-compliant with NIST/BSI/CCN today</td>
            </tr>
            <tr>
              <td><span class="score-badge score-weak">P2</span></td>
              <td style="font-size:.78rem;color:var(--muted)">6 → 18 months</td>
              <td style="font-size:.82rem">Enable TLS 1.3, ECDHE-only, RSA ≥ 3072, HSTS, CAA records</td>
              <td style="font-size:.75rem;color:var(--muted)">BSI TR-02102-1: RSA ≥ 3000 bits from 2026</td>
            </tr>
            <tr>
              <td><span class="score-badge score-moderate">P3</span></td>
              <td style="font-size:.78rem;color:var(--muted)">18 → 48 months</td>
              <td style="font-size:.82rem">Deploy ML-KEM hybrid key exchange, plan ML-DSA cert migration, audit app-level crypto</td>
              <td style="font-size:.75rem;color:var(--muted)">NIST SP 800-131Ar3: PQC transition required by 2030</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ═══ SETTINGS VIEW ═══ -->
  <!-- ══ Group Report ═══════════════════════════════════════════════════════ -->
  {% if can_view_group_report %}
  <div id="view-group_report" class="view">
    <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:1.25rem">
      <select id="gr-view-by" onchange="grSwitchViewBy()"
        style="background:var(--panel);border:1px solid var(--border);color:var(--text);
               padding:.3rem .6rem;border-radius:4px;font-size:.82rem">
        <option value="community">By Community</option>
        <option value="region">By Region</option>
        <option value="country">By Country</option>
      </select>
      <select id="gr-group-sel" onchange="grLoadReport()"
        style="background:var(--panel);border:1px solid var(--border);color:var(--text);
               padding:.3rem .6rem;border-radius:4px;font-size:.82rem;min-width:200px">
        <option value="">— Select —</option>
      </select>
      <select id="gr-country-filter" onchange="grApplyFilters()"
        style="display:none;background:var(--panel);border:1px solid var(--border);
               color:var(--text);padding:.3rem .6rem;border-radius:4px;font-size:.82rem">
        <option value="">All Countries</option>
      </select>
      <div style="margin-left:auto;display:flex;gap:.5rem">
        <button class="btn" id="gr-btn-csv" onclick="grExportCSV()" disabled
          style="font-size:.78rem;padding:.25rem .75rem">⬇ CSV</button>
        <button class="btn" id="gr-btn-pdf" onclick="grExportPDF()" disabled
          style="font-size:.78rem;padding:.25rem .75rem">⬇ PDF</button>
      </div>
    </div>
    <div id="gr-summary"
      style="display:none;background:rgba(14,165,233,.06);border-left:3px solid var(--accent);
             padding:.75rem 1rem;border-radius:0 6px 6px 0;font-size:.82rem;
             line-height:1.6;margin-bottom:1.25rem"></div>
    <!-- Charts row -->
    <div id="gr-charts" style="display:none;display:flex;gap:1.5rem;margin-bottom:1.25rem;flex-wrap:wrap">
      <div style="flex:1;min-width:280px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem">
        <div style="font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.75rem">Readiness Distribution</div>
        <svg id="gr-donut" width="100%" viewBox="0 0 220 160" style="display:block"></svg>
      </div>
      <div style="flex:2;min-width:320px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem">
        <div style="font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.75rem">Score by Organisation</div>
        <svg id="gr-bars" width="100%" style="display:block"></svg>
      </div>
    </div>

    <table class="data-table" id="gr-table" style="display:none">
      <thead><tr id="gr-thead-row">
        <th onclick="grSort('name')" style="cursor:pointer" title="Sort by name">Organisation <span class="gr-sort-ind" data-col="name"></span></th>
        <th onclick="grSort('country_code')" style="cursor:pointer" title="Sort by country">CC <span class="gr-sort-ind" data-col="country_code"></span></th>
        <th>Sector</th>
        <th onclick="grSort('domain_count')" style="text-align:right;cursor:pointer" title="Sort by domains">Domains <span class="gr-sort-ind" data-col="domain_count"></span></th>
        <th onclick="grSort('avg_score')" style="text-align:right;cursor:pointer" title="Sort by score">Score <span class="gr-sort-ind" data-col="avg_score"></span></th>
        <th onclick="grSort('level')" style="cursor:pointer" title="Sort by level">Level <span class="gr-sort-ind" data-col="level"></span></th>
        <th onclick="grSort('critical')" style="text-align:right;cursor:pointer" title="Critical">Crit <span class="gr-sort-ind" data-col="critical"></span></th>
        <th onclick="grSort('weak')" style="text-align:right;cursor:pointer" title="Weak">Weak <span class="gr-sort-ind" data-col="weak"></span></th>
        <th onclick="grSort('moderate')" style="text-align:right;cursor:pointer" title="Moderate">Mod <span class="gr-sort-ind" data-col="moderate"></span></th>
        <th onclick="grSort('ready')" style="text-align:right;cursor:pointer" title="Ready">Ready <span class="gr-sort-ind" data-col="ready"></span></th>
        <th onclick="grSort('no_tls')" style="text-align:right;cursor:pointer" title="No TLS">NTLS <span class="gr-sort-ind" data-col="no_tls"></span></th>
        <th onclick="grSort('pqc_count')" style="text-align:right;cursor:pointer" title="PQC detected">PQC <span class="gr-sort-ind" data-col="pqc_count"></span></th>
      </tr></thead>
      <tbody id="gr-tbody"></tbody>
    </table>
    <div id="gr-empty" style="text-align:center;padding:3rem;color:var(--muted);font-size:.88rem">
      Select a community or region above to load the report.
    </div>
  </div>
  {% endif %}

  <div id="view-settings" class="view">
    <div class="panel">
      <div class="panel-header"><div class="panel-title">Guidelines in Use</div></div>
      <div class="panel-body">
        <table class="domain-table">
          <thead><tr><th>ID</th><th>Name</th><th>Version</th><th>Published</th><th>Source</th></tr></thead>
          <tbody>
            <tr><td><code>nist_800_131a</code></td><td>NIST SP 800-131Ar3</td><td>r3-ipd-2024</td><td>2024-10</td><td><a href="https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd" target="_blank" style="color:var(--accent)">↗ NIST</a></td></tr>
            <tr><td><code>bsi_tr02102</code></td><td>BSI TR-02102-1</td><td>2026-01</td><td>2026-01</td><td><a href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf" target="_blank" style="color:var(--accent)">↗ BSI</a></td></tr>
            <tr><td><code>ccn_stic_221</code></td><td>CCN-STIC-221</td><td>2023</td><td>2023</td><td><a href="https://www.ccn-cert.cni.es" target="_blank" style="color:var(--accent)">↗ CCN</a></td></tr>
          </tbody>
        </table>
        <div style="margin-top:1rem;color:var(--muted);font-size:0.8rem">
          To update guidelines, edit the JSON files in <code style="color:var(--accent)">guidelines/</code> directory,
          then use Re-Assessment to apply new rules to existing scan data.
        </div>
      </div>
    </div>
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header"><div class="panel-title">PQC Readiness Score Guide</div></div>
      <div class="panel-body">
        <table class="domain-table">
          <thead><tr><th>Score</th><th>Level</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td><span class="score-badge score-critical">0–25</span></td><td><span class="level-dot dot-critical"></span>Critical</td><td style="color:var(--muted)">Broken/deprecated algorithms in use (MD5, RC4, DES, RSA-1024, SHA-1 signing)</td></tr>
            <tr><td><span class="score-badge score-weak">26–50</span></td><td><span class="level-dot dot-weak"></span>Weak</td><td style="color:var(--muted)">Acceptable today but not PQC-ready (RSA-2048, TLS 1.2 only, no forward secrecy)</td></tr>
            <tr><td><span class="score-badge score-moderate">51–75</span></td><td><span class="level-dot dot-moderate"></span>Moderate</td><td style="color:var(--muted)">Good classical crypto with TLS 1.3 and ECDHE, but no PQC elements yet</td></tr>
            <tr><td><span class="score-badge score-ready">76–100</span></td><td><span class="level-dot dot-ready"></span>Ready</td><td style="color:var(--muted)">PQC algorithms present (ML-KEM, ML-DSA) or fully prepared for transition</td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel" style="margin-top:1.5rem">
      <div class="panel-header"><div class="panel-title">About PQC-Monitor</div></div>
      <div class="panel-body" style="color:var(--muted);font-size:0.85rem;line-height:1.6">
        <p><strong style="color:var(--text)">Version:</strong>
          <span style="font-family:var(--font-mono);color:var(--accent)">v{{ version }}</span>
        </p>
        <p style="margin-top:0.5rem">PQC-Monitor is open-source software licensed under the GNU GPL v3.</p>
        <p style="margin-top:0.5rem"><strong style="color:var(--text)">AI-assisted development notice:</strong>
        This software was created with assistance from Claude (Anthropic). All code is provided as-is.</p>
        <p style="margin-top:0.5rem"><strong style="color:var(--text)">Disclaimer:</strong>
        For research and informational purposes only. Non-intrusive passive scanning only.
        Users are responsible for ensuring they have authorisation to scan target systems.</p>
      </div>
    </div>
  </div>

</div>

<footer>
  PQC-Monitor v{{ version }} &nbsp;·&nbsp; GPL-3.0 &nbsp;·&nbsp; AI-assisted (Claude/Anthropic) &nbsp;·&nbsp;
  Non-intrusive cryptographic posture assessment
</footer>

<script>
// ─── State ───────────────────────────────────────────────────────────────────
let discoveredDomains = [];
let charts = {};
let _allAssessments  = [];   // full unfiltered dataset
let _activeFilter    = null; // 'critical'|'weak'|'moderate'|'ready'|'pqc'|null
let _orgsCache       = [];   // populated by loadAssessments
let _activeOrg       = '';
let _activeRegion    = '';
let _activeCountry   = '';
let _sortCol         = 'score';
let _sortDir         = 'asc'; // 'asc'|'desc'

// ─── Navigation ──────────────────────────────────────────────────────────────
function showView(name, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const viewEl = document.getElementById('view-' + name);
  if (viewEl) viewEl.classList.add('active');
  const navTarget = btn || (typeof event !== 'undefined' ? event.target : null);
  if (navTarget && navTarget.classList) navTarget.classList.add('active');
  if (name === 'dashboard') { loadSummary(); loadAssessments(); }
  if (name === 'trends')    { loadTrends(); populateDomainSelector(); loadSchedules(); }
  if (name === 'scan')      { loadRuns(); }
  if (name === 'domains')   { loadDomainLists(); }
  if (name === 'ct')        { loadCTStats(); loadCTSummaries(); loadCTPQCCerts(); loadCTTimeline(); }
  if (name === 'roadmap')   { loadRoadmapStats(); loadRoadmapTable(); populateRoadmapRunSel(); }
  if (name === 'settings')  { renderSettingsVersion(); }
}

// ─── Summary ─────────────────────────────────────────────────────────────────
async function loadSummary() {
  const r = await fetch('/api/summary');
  const d = await r.json();
  const s = d.stats || {};
  document.getElementById('stat-total').textContent    = s.total_domains ?? '0';
  document.getElementById('stat-avg').textContent      = s.avg_score ?? '0';
  document.getElementById('stat-critical').textContent = s.critical_count ?? '0';
  document.getElementById('stat-weak').textContent     = s.weak_count ?? '0';
  document.getElementById('stat-moderate').textContent = s.moderate_count ?? '0';
  document.getElementById('stat-ready').textContent    = s.ready_count ?? '0';
  document.getElementById('stat-pqc').textContent      = s.pqc_count ?? '0';
  document.getElementById('stat-na').textContent       = s.na_count ?? '0';

  renderDistChart(s);
  // Also pull CT stats for the dashboard card
  fetch('/api/ct/stats').then(r=>r.json()).then(cs => {
    const el = document.getElementById('stat-ct-pqc');
    if (el) el.textContent = cs.total_pqc ?? '0';
  }).catch(()=>{});
}

function renderDistChart(s) {
  const ctx = document.getElementById('chartDist')?.getContext('2d');
  if (!ctx || typeof Chart === 'undefined') return;
  if (charts.dist) charts.dist.destroy();
  charts.dist = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'Weak', 'Moderate', 'Ready'],
      datasets: [{
        data: [s.critical_count||0, s.weak_count||0, s.moderate_count||0, s.ready_count||0],
        backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'],
        borderWidth: 0, hoverOffset: 4
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#e2e8f0', font: { size: 11 } } } },
      cutout: '65%'
    }
  });
}

// ─── Assessments table ───────────────────────────────────────────────────────

async function loadAssessments(runId) {
  const url = runId ? `/api/assessments?run_id=${runId}` : '/api/assessments';
  const [r, orgsR] = await Promise.all([
    fetch(url),
    fetch('/api/organisations').catch(() => ({ json: () => [] }))
  ]);
  const data = await r.json();
  _orgsCache = await orgsR.json().catch(() => []);
  _allAssessments = data;
  _activeFilter   = null;
  _activeOrg      = '';
  _activeRegion   = '';
  _activeCountry  = '';
  populateOrgDropdown();
  populateRegionDropdown();
  populateCountryDropdown();
  updateFilterUI();
  applyFilterAndSort();
  renderTLSChart(data);
}

function populateOrgDropdown() {
  const sel = document.getElementById('filter-org');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">All Organisations</option>' +
    _orgsCache.map(o => `<option value="${o.id}" ${current == o.id ? 'selected' : ''}>${esc(o.name)}</option>`).join('');
}

function populateRegionDropdown() {
  const sel = document.getElementById('filter-region');
  if (!sel) return;
  const regions = [...new Set(_orgsCache.map(o => o.region).filter(Boolean))].sort();
  const current = sel.value;
  sel.innerHTML = '<option value="">All Regions</option>' +
    regions.map(r => `<option value="${r}" ${current === r ? 'selected' : ''}>${r}</option>`).join('');
}

function populateCountryDropdown() {
  const sel = document.getElementById('filter-country');
  if (!sel) return;
  // Build list from orgs that have a country_code; display as "CC – Country"
  const seen = new Map();
  _orgsCache.forEach(o => {
    if (o.country_code) seen.set(o.country_code, o.country || o.country_code);
  });
  const entries = [...seen.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  const current = sel.value;
  sel.innerHTML = '<option value="">All Countries</option>' +
    entries.map(([cc, name]) =>
      `<option value="${cc}" ${current === cc ? 'selected' : ''}>${cc}–${esc(name)}</option>`
    ).join('');
}

function applyDropdownFilters() {
  _activeOrg     = document.getElementById('filter-org')?.value     || '';
  _activeRegion  = document.getElementById('filter-region')?.value  || '';
  _activeCountry = document.getElementById('filter-country')?.value || '';
  applyFilterAndSort();
}

function setFilter(level) {
  if (_activeFilter === level) {
    _activeFilter = null;  // toggle off
  } else {
    _activeFilter = level;
  }
  updateFilterUI();
  applyFilterAndSort();
}

function updateFilterUI() {
  // Stat card highlight
  document.querySelectorAll('.stat-card-filter').forEach(c => c.classList.remove('filter-active'));
  const badge  = document.getElementById('filter-badge');
  const clearBtn = document.getElementById('btn-clear-filter');
  if (_activeFilter) {
    const card = document.getElementById('filter-card-' + _activeFilter);
    if (card) card.classList.add('filter-active');
    if (badge)   { badge.textContent = 'Filtered: ' + (_activeFilter === 'na' ? 'No TLS' : ucfirst(_activeFilter)); badge.style.display = ''; }
    if (clearBtn) clearBtn.style.display = '';
  } else {
    if (badge)   badge.style.display = 'none';
    if (clearBtn) clearBtn.style.display = 'none';
  }
  // Sort icon indicators
  ['domain','score','level','key_type','has_pqc','findings'].forEach(col => {
    const si = document.getElementById('si-' + col);
    if (!si) return;
    if (col === _sortCol) {
      si.textContent = _sortDir === 'asc' ? '▲' : '▼';
    } else {
      si.textContent = '';
    }
  });
}

function sortBy(col) {
  if (_sortCol === col) {
    _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _sortCol = col;
    _sortDir = col === 'domain' ? 'asc' : 'asc';
  }
  updateFilterUI();
  applyFilterAndSort();
}

function applyFilterAndSort() {
  const LEVEL_ORDER = { critical: 0, weak: 1, moderate: 2, ready: 3, na: 4 };

  // Filter
  let items = _allAssessments.slice();
  if (_activeFilter === 'pqc') {
    items = items.filter(a => a.has_pqc);
  } else if (_activeFilter) {
    items = items.filter(a => (a.level || '').toLowerCase() === _activeFilter);
  }

  // Org filter (client-side using cached org→domain mapping)
  if (_activeOrg) {
    const orgId = parseInt(_activeOrg);
    const org = _orgsCache.find(o => o.id === orgId);
    // Ask server to give us org-filtered data
    // For instant client-side filtering, we rely on the domain_org_id field
    // that the server now attaches (or fall back to refetch)
    items = items.filter(a => a.org_id == orgId);
  }

  // Region filter (via org metadata)
  if (_activeRegion) {
    const domainsByRegion = new Set(
      _orgsCache
        .filter(o => o.region === _activeRegion)
        .flatMap(o => o.domains || [])
    );
    if (domainsByRegion.size > 0) {
      items = items.filter(a => domainsByRegion.has(a.domain));
    }
  }

  // Country filter (via org country_code)
  if (_activeCountry) {
    const domainsByCountry = new Set(
      _orgsCache
        .filter(o => (o.country_code || '').toUpperCase() === _activeCountry.toUpperCase())
        .flatMap(o => o.domains || [])
    );
    if (domainsByCountry.size > 0) {
      items = items.filter(a => domainsByCountry.has(a.domain));
    }
  }

  // Sort
  items.sort((a, b) => {
    let av, bv;
    if (_sortCol === 'domain') {
      av = (a.domain || '').toLowerCase();
      bv = (b.domain || '').toLowerCase();
    } else if (_sortCol === 'score') {
      // na-level domains (no TLS) sort after all scored domains
      const aIsNA = (a.level || '') === 'na';
      const bIsNA = (b.level || '') === 'na';
      if (aIsNA && !bIsNA) return 1;
      if (!aIsNA && bIsNA) return -1;
      av = a.score ?? -1;
      bv = b.score ?? -1;
    } else if (_sortCol === 'level') {
      av = LEVEL_ORDER[a.level] ?? 99;
      bv = LEVEL_ORDER[b.level] ?? 99;
    } else if (_sortCol === 'key_type') {
      av = (a.key_type || '').toLowerCase();
      bv = (b.key_type || '').toLowerCase();
    } else if (_sortCol === 'has_pqc') {
      av = a.has_pqc ? 1 : 0;
      bv = b.has_pqc ? 1 : 0;
    } else if (_sortCol === 'findings') {
      const fa = tryJSON(a.findings_json) || [];
      const fb = tryJSON(b.findings_json) || [];
      av = fa.filter(f => f.severity === 'critical').length * 100 +
           fa.filter(f => f.severity === 'high').length;
      bv = fb.filter(f => f.severity === 'critical').length * 100 +
           fb.filter(f => f.severity === 'high').length;
    } else {
      av = a[_sortCol] ?? '';
      bv = b[_sortCol] ?? '';
    }
    if (av < bv) return _sortDir === 'asc' ? -1 : 1;
    if (av > bv) return _sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  renderAssessments(items);
}

function renderAssessments(items) {
  const tbody = document.getElementById('domain-tbody');
  const total = _allAssessments.length;
  if (!total) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No assessment data. Run a scan first.</td></tr>';
    return;
  }
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No domains match the current filter. <a href="#" onclick="setFilter(null);return false" style="color:var(--accent)">Clear filter</a></td></tr>`;
    return;
  }
  tbody.innerHTML = items.map(a => {
    const lc = a.level || 'na';
    const isNA = lc === 'na';
    const tlsArr = tryJSON(a.tls_versions) || [];
    const findings = tryJSON(a.findings_json) || [];
    const critCount = findings.filter(f=>f.severity==='critical').length;
    const highCount = findings.filter(f=>f.severity==='high').length;
    return `<tr>
      <td><a class="domain-link" href="#" onclick="showDomainDetail('${a.domain}');return false">${a.domain}</a></td>
      <td>${isNA ? '<span class="score-badge score-na">N/A</span>' : `<span class="score-badge score-${lc}">${a.score??'?'}</span>`}</td>
      <td><span class="level-dot dot-${lc}"></span>${isNA ? '<span style="color:var(--muted)">No TLS</span>' : ucfirst(lc)}</td>
      <td>${tlsArr.map(t=>`<span class="tls-pill">${t}</span>`).join(' ')}</td>
      <td style="font-family:var(--font-mono);font-size:0.75rem">${a.key_type||'—'}</td>
      <td>${a.has_pqc ? '<span class="pqc-pill">✓ PQC</span>' : '<span style="color:var(--muted);font-size:0.75rem">—</span>'}</td>
      <td style="font-size:0.75rem">
        ${isNA ? '<span style="color:var(--muted);font-size:0.75rem">—</span>' : (
          critCount ? `<span style="color:var(--critical)">${critCount} crit</span> ` : '') +
          (highCount ? `<span style="color:var(--weak)">${highCount} high</span>` : '') +
          (!critCount && !highCount ? '<span style="color:var(--ready)">✓</span>' : ''
        )}
      </td>
    </tr>`;
  }).join('');
}

function renderTLSChart(items) {
  const tlsCounts = {};
  items.forEach(a => {
    (tryJSON(a.tls_versions)||[]).forEach(v => { tlsCounts[v] = (tlsCounts[v]||0) + 1; });
  });
  const labels = Object.keys(tlsCounts);
  const values = labels.map(k => tlsCounts[k]);
  const ctx = document.getElementById('chartTLS')?.getContext('2d');
  if (!ctx || typeof Chart === 'undefined') return;
  if (charts.tls) charts.tls.destroy();
  charts.tls = new Chart(ctx, {
    type: 'bar',
    data: {
      labels, datasets: [{
        label: 'Domains', data: values,
        backgroundColor: labels.map(l => l==='TLSv1.3'?'#22c55e':l==='TLSv1.2'?'#eab308':l==='TLSv1.1'?'#f97316':'#ef4444'),
        borderRadius: 4, borderWidth: 0
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,0.5)' } },
        y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,0.5)' } }
      }
    }
  });
}

// Cipher security-level → colour
function cipherLevelColor(lvl) {
  return { recommended:'var(--ready)', acceptable:'var(--accent)',
           deprecated:'#f59e0b', disallowed:'var(--critical)' }[lvl] || 'var(--muted)';
}
// SSL Labs grade → colour
function sslLabsGradeColor(g) {
  if (!g) return 'var(--muted)';
  if (g.startsWith('A')) return 'var(--ready)';
  if (g === 'B') return '#f59e0b';
  if (g === 'C') return '#fb923c';
  return 'var(--critical)';
}
function sslLabsBadge(sl, domain) {
  const url = (sl && sl.report_url) || `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}`;
  if (!sl || !sl.grade) {
    return `<div style="font-size:.8rem;margin-top:.25rem">SSL Labs: <span style="color:var(--muted)">no report</span>
      <a href="${url}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.72rem;margin-left:.4rem">open ssllabs.com ↗</a></div>`;
  }
  return `<div style="font-size:.8rem;margin-top:.25rem">SSL Labs:
    <span style="background:rgba(255,255,255,.06);border:1px solid ${sslLabsGradeColor(sl.grade)};color:${sslLabsGradeColor(sl.grade)};padding:.05rem .45rem;border-radius:4px;font-family:var(--font-mono);font-weight:700">${sl.grade}</span>
    <a href="${url}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.72rem;margin-left:.4rem">full report ↗</a>
    ${sl.test_time?`<span style="color:var(--muted);font-size:.7rem;margin-left:.4rem">(${sl.test_time.slice(0,10)})</span>`:''}</div>`;
}

let _detailDomain     = null;   // domain currently shown in modal / full view
let _detailData       = null;   // cached /api/domain response
let _detailAssessment = null;   // cached latest assessment row

async function showDomainDetail(domain) {
  const r = await fetch(`/api/domain/${encodeURIComponent(domain)}`);
  const d = await r.json();
  _detailDomain = domain;
  _detailData   = d;
  const history = d.history || [];
  const latest = history[history.length - 1] || {};
  const enumData = (d.extra||{}).cipher_enum || null;
  const ssllabs  = (d.extra||{}).ssllabs || null;

  document.getElementById('detail-title').textContent = `Domain: ${domain}`;
  const body = document.getElementById('detail-body');

  // Get latest findings
  const assessments = await (await fetch(`/api/assessments`)).json();
  const a = assessments.find(x => x.domain === domain) || {};
  _detailAssessment = a;
  const findings = tryJSON(a.findings_json) || [];

  const allCiphers = tryJSON(a.cipher_suites) || [];
  const enumCount  = enumData ? (enumData.supported_ciphers||[]).length : 0;
  const cipherSummary = enumData ? `
    <div style="font-size:.8rem;margin-top:.25rem">Ciphers accepted: <span style="color:var(--text)">${enumCount}</span>
      <span style="font-size:.72rem;margin-left:.35rem">
        ${enumData.recommended_count?`<span style="color:${cipherLevelColor('recommended')}">${enumData.recommended_count} recommended</span>`:''}
        ${enumData.acceptable_count?` · <span style="color:${cipherLevelColor('acceptable')}">${enumData.acceptable_count} acceptable</span>`:''}
        ${enumData.deprecated_count?` · <span style="color:${cipherLevelColor('deprecated')}">${enumData.deprecated_count} deprecated</span>`:''}
        ${enumData.disallowed_count?` · <span style="color:${cipherLevelColor('disallowed')}">${enumData.disallowed_count} disallowed</span>`:''}
      </span>
    </div>` : `
    <div style="font-size:.8rem;margin-top:.25rem">Ciphers: <span style="color:var(--text)">${allCiphers.slice(0,3).join(', ')||'—'}${allCiphers.length>3?` (+${allCiphers.length-3} more)`:''}</span></div>`;

  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">
      <div>
        <div style="color:var(--muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem">Score</div>
        <div style="font-family:var(--font-mono);font-size:2.5rem;color:${levelColor(a.level)}">${a.level === 'na' ? 'N/A' : (a.score??'—')}</div>
        <div style="color:${levelColor(a.level)};font-size:.85rem;margin-top:.25rem">${a.level === 'na' ? 'No TLS Service' : ucfirst(a.level||'')}</div>
      </div>
      <div>
        <div style="color:var(--muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem">Details</div>
        <div style="font-size:.8rem">TLS: <span style="color:var(--accent)">${(tryJSON(a.tls_versions)||[]).join(', ')||'—'}</span></div>
        ${cipherSummary}
        <div style="font-size:.8rem;margin-top:.25rem">PQC: <span style="${a.has_pqc?'color:#a78bfa':'color:var(--muted)'}">${a.has_pqc?'Detected':'Not detected'}</span></div>
        ${a.cert_expiry_days!=null?`<div style="font-size:.8rem;margin-top:.25rem">Cert expires: <span style="color:${a.cert_expiry_days<30?'var(--critical)':'var(--text)'}">${a.cert_expiry_days} days</span></div>`:''}
        ${sslLabsBadge(ssllabs, domain)}
        <button class="btn-outline" style="margin-top:.7rem;font-size:.75rem" onclick="showDomainFull()">Full TLS Details →</button>
      </div>
    </div>
    <div style="color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem">Findings (${findings.length})</div>
    ${findings.length ? findings.map(f => `
      <div class="finding finding-${f.severity}">
        <strong style="font-size:.8rem">[${f.severity?.toUpperCase()}] ${f.category?.toUpperCase()}</strong>
        — ${f.message}
        ${f.recommendation?`<div class="finding-rec">→ ${f.recommendation}</div>`:''}
        ${f.guideline?`<div style="color:var(--muted);font-size:.7rem;margin-top:.2rem">${f.guideline}</div>`:''}
      </div>
    `).join('') : '<div style="color:var(--ready)">✓ No significant findings</div>'}
  `;
  document.getElementById('domain-detail').style.display = 'block';
  document.getElementById('domain-detail').scrollIntoView({ behavior: 'smooth' });
}

// ─── Full TLS detail view (drill-down) ──────────────────────────────────────
const CAN_SCAN = {{ 'true' if is_admin else 'false' }};
const _CIPHER_LEVEL_ORDER = { recommended:0, acceptable:1, deprecated:2, disallowed:3 };
const _PQC_GROUP_RE = /mlkem|kyber|ml-kem|frodo|ntru|sntrup/i;
function _isPqcGroup(g){ return !!g && _PQC_GROUP_RE.test(g); }
let _sslLabsPollTimer = null;

function closeDomainFull() {
  if (_sslLabsPollTimer) { clearTimeout(_sslLabsPollTimer); _sslLabsPollTimer = null; }
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-dashboard').classList.add('active');
}

function showDomainFull() {
  if (!_detailDomain) return;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-domain-full').classList.add('active');
  document.getElementById('df-title').textContent = `TLS Details: ${_detailDomain}`;
  renderDomainFull();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function renderDomainFull() {
  const d        = _detailData || {};
  const a        = _detailAssessment || {};
  const extra    = d.extra || {};
  const enumData = extra.cipher_enum || null;
  const chain    = extra.chain || null;
  const ssllabs  = extra.ssllabs || null;
  const body     = document.getElementById('df-body');

  // ── Cipher table ──
  let cipherHtml;
  if (enumData && (enumData.supported_ciphers||[]).length) {
    const rows = [...enumData.supported_ciphers].sort((x, y) => {
      const lv = (_CIPHER_LEVEL_ORDER[x.security_level]??9) - (_CIPHER_LEVEL_ORDER[y.security_level]??9);
      if (lv) return lv;
      if (x.tls_version !== y.tls_version) return x.tls_version < y.tls_version ? 1 : -1;
      return (y.bits||0) - (x.bits||0);
    }).map(c => `
      <tr>
        <td style="font-family:var(--font-mono);font-size:.74rem">${c.iana_name || c.openssl_name}</td>
        <td>${c.tls_version||''}</td>
        <td>${c.bits||''}</td>
        <td style="font-size:.74rem;color:var(--muted)">${c.category||''}</td>
        <td><span style="color:${cipherLevelColor(c.security_level)};font-weight:600;font-size:.74rem">${(c.security_level||'').toUpperCase()}</span></td>
      </tr>`).join('');
    cipherHtml = `
      <table class="data-table" style="margin-bottom:1.5rem">
        <thead><tr><th>Cipher suite (IANA)</th><th>Protocol</th><th>Bits</th><th>Category</th><th>Assessment</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="color:var(--muted);font-size:.7rem;margin-bottom:1.5rem">
        Enumerated ${enumData.timestamp?enumData.timestamp.slice(0,19).replace('T',' '):''} UTC
        · TLS 1.3: ${enumData.tls13_supported?'yes':'no'} · TLS 1.2: ${enumData.tls12_supported?'yes':'no'}
        · Note: active enumeration probes a curated suite list; extremely rare suites may not be covered.
      </div>`;
  } else {
    const allCiphers = tryJSON(a.cipher_suites) || [];
    cipherHtml = allCiphers.length ? `
      <div style="font-size:.8rem;margin-bottom:1.5rem">${allCiphers.map(c=>`<div style="font-family:var(--font-mono);font-size:.74rem">${c}</div>`).join('')}</div>
      <div style="color:var(--muted);font-size:.72rem;margin-bottom:1.5rem">No cipher enumeration data for this domain — re-scan with cipher_enum enabled for the full accepted-suite list.</div>`
      : `<div style="color:var(--muted);font-size:.8rem;margin-bottom:1.5rem">No cipher data available. Re-scan this domain.</div>`;
  }

  // ── Chain summary ──
  const chainHtml = chain ? `
    <div style="font-size:.8rem;margin-bottom:1.5rem">
      Chain length: <span style="color:var(--text)">${chain.chain_length??'—'}</span>
      · Complete: <span style="color:${chain.chain_complete?'var(--ready)':'var(--critical)'}">${chain.chain_complete?'yes':'no'}</span>
      ${chain.root_ca?` · Root: <span style="color:var(--text)">${chain.root_ca}</span>`:''}
    </div>` : '';

  // ── SSL Labs panel ──
  const slUrl = (ssllabs && ssllabs.report_url) || `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(_detailDomain)}`;
  const slEndpoints = (ssllabs && ssllabs.endpoints || []).map(e => `
      <div style="font-size:.76rem;margin-top:.25rem">
        <span style="font-family:var(--font-mono)">${e.ip}</span> —
        <span style="color:${sslLabsGradeColor(e.grade)};font-weight:700">${e.grade||'?'}</span>
        ${e.has_warnings?'<span style="color:#f59e0b;font-size:.7rem;margin-left:.3rem">warnings</span>':''}
      </div>`).join('');
  const slHtml = `
    <div style="color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem">Qualys SSL Labs</div>
    <div id="df-ssllabs">
      ${ssllabs && ssllabs.grade ? `
        <div style="font-size:.9rem">Grade:
          <span style="background:rgba(255,255,255,.06);border:1px solid ${sslLabsGradeColor(ssllabs.grade)};color:${sslLabsGradeColor(ssllabs.grade)};padding:.1rem .6rem;border-radius:4px;font-family:var(--font-mono);font-weight:700;font-size:1.05rem">${ssllabs.grade}</span>
          <a href="${slUrl}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.76rem;margin-left:.6rem">full report on ssllabs.com ↗</a>
        </div>
        ${slEndpoints}
        <div style="color:var(--muted);font-size:.7rem;margin-top:.4rem">
          Assessed ${ssllabs.test_time?ssllabs.test_time.slice(0,19).replace('T',' ')+' UTC':'—'}
          · engine ${ssllabs.engine_version||'?'} · criteria ${ssllabs.criteria_version||'?'}
          · grade is informational only (not part of the PQC score)
        </div>`
      : `<div style="color:var(--muted);font-size:.8rem">No SSL Labs report stored for this domain.
          <a href="${slUrl}" target="_blank" rel="noopener" style="color:var(--accent)">check ssllabs.com ↗</a></div>`}
      ${CAN_SCAN ? `<button class="btn-outline" style="margin-top:.7rem;font-size:.75rem" id="df-ssllabs-btn" onclick="refreshSSLLabs()">Request fresh SSL Labs assessment</button>
        <span id="df-ssllabs-status" style="color:var(--muted);font-size:.72rem;margin-left:.6rem"></span>` : ''}
    </div>`;

  const ge = extra.group_enum || null;
  const geHtml = ge && ge.success ? `
    <div style="font-size:.8rem;margin-bottom:1rem">
      Key-exchange groups <span style="color:var(--muted);font-size:.72rem">(offered by server — client-independent)</span>:
      ${(ge.offered_groups||[]).map(g=>`<span style="font-family:var(--font-mono);font-size:.72rem;padding:.1rem .4rem;margin-right:.3rem;border-radius:3px;background:rgba(255,255,255,.06);color:${_isPqcGroup(g)?'#a78bfa':'var(--text)'};border:1px solid ${_isPqcGroup(g)?'#a78bfa':'transparent'}">${g}</span>`).join('') || '<span style="color:var(--muted)">none</span>'}
      ${(ge.pqc_groups||[]).length ? `<div style="color:#a78bfa;font-size:.75rem;margin-top:.4rem">✓ Post-quantum key exchange offered${ge.hybrid_only?' (hybrid)':' — pure ML-KEM, hybrid preferred'}</div>` : '<div style="color:var(--muted);font-size:.75rem;margin-top:.4rem">No post-quantum group offered</div>'}
    </div>` : '';

  body.innerHTML = `
    <div style="font-size:.8rem;margin-bottom:1rem">TLS protocols: <span style="color:var(--accent)">${(tryJSON(a.tls_versions)||[]).join(', ')||'—'}</span></div>
    ${geHtml}
    <div style="color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem">Accepted cipher suites</div>
    ${cipherHtml}
    ${chainHtml ? `<div style="color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem">Certificate chain</div>${chainHtml}` : ''}
    ${slHtml}`;
}

async function refreshSSLLabs() {
  const btn = document.getElementById('df-ssllabs-btn');
  const st  = document.getElementById('df-ssllabs-status');
  if (!_detailDomain || !btn) return;
  btn.disabled = true;
  st.textContent = 'requesting…';
  try {
    const r = await fetch(`/api/ssllabs/${encodeURIComponent(_detailDomain)}/refresh`, { method: 'POST' });
    const d = await r.json();
    if (d.status === 'unavailable') { st.textContent = d.error || 'SSL Labs not configured'; return; }
    if (d.status === 'rate_limited') { st.textContent = 'rate limited by SSL Labs — try again later'; btn.disabled = false; return; }
    _pollSSLLabs(0);
  } catch (e) {
    st.textContent = 'request failed'; btn.disabled = false;
  }
}

async function _pollSSLLabs(attempt) {
  const st = document.getElementById('df-ssllabs-status');
  if (!st) return; // view was closed
  if (attempt > 40) { st.textContent = 'timed out — check ssllabs.com directly'; return; }
  try {
    const r = await fetch(`/api/ssllabs/${encodeURIComponent(_detailDomain)}`);
    const d = await r.json();
    if (d.status === 'READY' && d.report) {
      st.textContent = '';
      _detailData.extra = _detailData.extra || {};
      _detailData.extra.ssllabs = d.report;
      renderDomainFull();
      return;
    }
    if (d.status === 'ERROR') { st.textContent = 'SSL Labs assessment failed'; return; }
    st.textContent = `SSL Labs: ${d.status||'…'} (assessments take 60+ s)`;
  } catch (e) { /* transient — keep polling */ }
  _sslLabsPollTimer = setTimeout(() => _pollSSLLabs(attempt + 1), attempt < 3 ? 5000 : 10000);
}

// ─── Domain Discovery ────────────────────────────────────────────────────────
async function discoverDomains() {
  const query = document.getElementById('discovery-query').value.trim();
  if (!query) return;
  const max = parseInt(document.getElementById('discovery-max').value) || 30;

  showAlert('discovery-alert', 'Discovering domains...', 'info');

  try {
    const r = await fetch('/api/discover', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ query, max_domains: max, validate: false })
    });
    const d = await r.json();

    if (d.error) { showAlert('discovery-alert', d.error, 'error'); return; }

    discoveredDomains = d.domains || [];
    hideAlert('discovery-alert');
    document.getElementById('discovery-result').style.display = 'block';
    document.getElementById('discovery-count').textContent = discoveredDomains.length;
    document.getElementById('discovery-source').textContent = `(${d.source||''})`;
    document.getElementById('discovery-notes').textContent = d.notes || '';
    document.getElementById('discovery-tags').innerHTML =
      discoveredDomains.map(d => `<span class="domain-tag">${d}</span>`).join('');
  } catch(e) {
    showAlert('discovery-alert', 'Discovery failed: ' + e.message, 'error');
  }
}

function scanDiscoveredDomains() {
  if (!discoveredDomains.length) return;
  document.getElementById('scan-domains').value = discoveredDomains.join('\n');
  showView2('scan');
}

async function saveDomainList() {
  if (!discoveredDomains.length) return;
  const query = document.getElementById('discovery-query').value;
  const name = prompt('Name for this domain list:', query.slice(0,40));
  if (!name) return;
  await fetch('/api/save-domains', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ name, domains: discoveredDomains, query })
  });
  alert('Domain list saved.');
  loadDomainLists();
}

async function loadDomainLists() {
  const r = await fetch('/api/domain-lists');
  const lists = await r.json();
  const el = document.getElementById('domain-lists-body');
  if (!lists.length) {
    el.innerHTML = '<div style="color:var(--muted)">No saved domain lists yet.</div>';
    return;
  }
  el.innerHTML = `<table class="domain-table">
    <thead><tr><th>ID</th><th>Name</th><th>Query</th><th>Created</th></tr></thead>
    <tbody>${lists.map(l=>`<tr>
      <td style="font-family:var(--font-mono)">#${l.id}</td>
      <td>${l.name}</td>
      <td style="color:var(--muted);font-size:.78rem">${l.query||'—'}</td>
      <td style="color:var(--muted);font-size:.78rem">${l.created_at?.slice(0,10)||''}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

// ─── Scanning ────────────────────────────────────────────────────────────────
async function startScan() {
  const raw = document.getElementById('scan-domains').value.trim();
  const domains = raw.split('\n').map(d=>d.trim()).filter(Boolean);
  if (!domains.length) { showAlert('scan-alert','Enter at least one domain','error'); return; }

  const sector = document.getElementById('scan-sector').value;
  const region = document.getElementById('scan-region').value;
  const use_shodan = document.getElementById('scan-shodan').checked;

  const btn = document.getElementById('btn-scan');
  btn.disabled = true; btn.innerHTML = '<span class="loader"></span>Scanning...';
  showAlert('scan-alert', `Scanning ${domains.length} domains. This may take a moment...`, 'info');

  try {
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ domains, sector, region, use_shodan })
    });
    const d = await r.json();
    if (d.error) { showAlert('scan-alert', d.error, 'error'); return; }
    showAlert('scan-alert', `✓ Scan complete! run_id=${d.run_id}. ${d.domains_scanned} domains scanned.`, 'ok');
    loadRuns();
  } catch(e) {
    showAlert('scan-alert', 'Scan failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Start Scan';
  }
}

async function loadRuns() {
  const r = await fetch('/api/runs');
  const runs = await r.json();
  const tbody = document.getElementById('runs-tbody');
  const sel = document.getElementById('reassess-run');

  tbody.innerHTML = runs.map(run => `<tr>
    <td style="font-family:var(--font-mono)">${run.run_id}</td>
    <td style="font-size:.78rem;color:var(--muted)">${run.started_at?.slice(0,16)||''}</td>
    <td>${run.sector||'—'}</td>
    <td>${run.region||'—'}</td>
    <td><span style="color:${run.status==='completed'?'var(--ready)':run.status==='failed'?'var(--critical)':'var(--moderate)'}">${run.status}</span></td>
    <td><button class="btn-outline" onclick="loadAssessments('${run.run_id}');showView2('dashboard')">View</button></td>
  </tr>`).join('') || '<tr><td colspan="6" style="color:var(--muted);padding:1rem">No runs yet</td></tr>';

  sel.innerHTML = '<option value="">Select a scan run...</option>' +
    runs.map(r => `<option value="${r.run_id}">${r.run_id} — ${r.started_at?.slice(0,10)||''} (${r.status})</option>`).join('');

  // Also populate export run selector
  const exportSel = document.getElementById('export-run');
  if (exportSel) {
    exportSel.innerHTML = '<option value="">All runs (latest per domain)</option>' +
      runs.map(r => `<option value="${r.run_id}">${r.run_id} — ${r.started_at?.slice(0,10)||''}</option>`).join('');
  }
}

async function startReassess() {
  const run_id = document.getElementById('reassess-run').value;
  if (!run_id) return;
  showAlert('reassess-alert', 'Re-assessing...', 'info');
  const r = await fetch('/api/reassess', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ run_id })
  });
  const d = await r.json();
  if (d.error) { showAlert('reassess-alert', d.error, 'error'); return; }
  showAlert('reassess-alert', `✓ Re-assessment complete. new_run_id=${d.new_run_id}`, 'ok');
  loadRuns();
}

// ─── Trends ──────────────────────────────────────────────────────────────────
async function loadTrends() {
  const r = await fetch('/api/trends');
  const trends = await r.json();

  if (trends.length < 2) {
    document.getElementById('trend-empty').style.display = 'block';
  }

  const labels = trends.map(t => t.started_at?.slice(0,10) || '');
  const avgScores = trends.map(t => Math.round(t.avg_score || 0));

  // Score trend
  const ctx1 = document.getElementById('chartTrend').getContext('2d');
  if (charts.trend) charts.trend.destroy();
  charts.trend = new Chart(ctx1, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Avg PQC Score', data: avgScores,
        borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.1)',
        tension: 0.3, fill: true, pointRadius: 5
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,0.5)' } },
        y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,0.5)' } }
      },
      plugins: { legend: { labels: { color: '#e2e8f0' } } }
    }
  });

  // Levels stacked
  const ctx2 = document.getElementById('chartLevels').getContext('2d');
  if (charts.levels) charts.levels.destroy();
  charts.levels = new Chart(ctx2, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label:'Critical', data:trends.map(t=>t.critical_count||0), backgroundColor:'#ef4444' },
        { label:'Weak',     data:trends.map(t=>t.weak_count||0),     backgroundColor:'#f97316' },
        { label:'Moderate', data:trends.map(t=>t.moderate_count||0), backgroundColor:'#eab308' },
        { label:'Ready',    data:trends.map(t=>t.ready_count||0),    backgroundColor:'#22c55e' },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false, scales: {
        x: { stacked: true, ticks:{color:'#64748b'}, grid:{color:'rgba(30,45,74,.5)'} },
        y: { stacked: true, ticks:{color:'#64748b'}, grid:{color:'rgba(30,45,74,.5)'} }
      },
      plugins: { legend: { labels: { color: '#e2e8f0', font:{size:10} } } }
    }
  });

  // PQC adoption
  const ctx3 = document.getElementById('chartPQC').getContext('2d');
  if (charts.pqc) charts.pqc.destroy();
  charts.pqc = new Chart(ctx3, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label:'Domains with PQC', data:trends.map(t=>t.pqc_count||0),
        borderColor:'#a78bfa', backgroundColor:'rgba(124,58,237,0.1)',
        tension:0.3, fill:true, pointRadius:5
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      scales:{
        x:{ticks:{color:'#64748b'},grid:{color:'rgba(30,45,74,.5)'}},
        y:{ticks:{color:'#64748b'},grid:{color:'rgba(30,45,74,.5)'}}
      },
      plugins:{legend:{labels:{color:'#e2e8f0'}}}
    }
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function showView2(name) {
  // Same as showView but used programmatically (no click event to reference).
  const btn = [...document.querySelectorAll('.nav-btn')]
    .find(b => b.getAttribute('onclick')?.includes("'" + name + "'"));
  showView(name, btn || null);
}

function showAlert(id, msg, type) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = `alert show alert-${type}`;
}
function hideAlert(id) {
  document.getElementById(id).classList.remove('show');
}
function tryJSON(v) {
  if (!v) return null;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch { return null; }
}
function ucfirst(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function scoreClass(s) {
  if (s <= 25) return 'critical'; if (s <= 50) return 'weak';
  if (s <= 75) return 'moderate'; return 'ready';
}
function levelColor(l) {
  if (l==='critical') return 'var(--critical)';
  if (l==='weak') return 'var(--weak)';
  if (l==='moderate') return 'var(--moderate)';
  if (l==='na') return 'var(--muted)';
  return 'var(--ready)';
}

// ─── CT Monitor ──────────────────────────────────────────────────────────────

async function loadCTStats() {
  const r = await fetch('/api/ct/stats');
  const s = await r.json();
  const set = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val ?? '0'; };
  set('ct-stat-domains',     s.domains_monitored);
  set('ct-stat-total',       s.total_certs);
  set('ct-stat-pqc',         s.total_pqc);
  set('ct-stat-hybrid',      s.total_hybrid);
  set('ct-stat-domains-pqc', s.domains_with_pqc);
  // Also update main dashboard CT card
  const dashCard = document.getElementById('stat-ct-pqc');
  if (dashCard) dashCard.textContent = s.total_pqc ?? '0';
}

async function loadCTSummaries() {
  const r = await fetch('/api/ct/summaries');
  const rows = await r.json();
  const tbody = document.getElementById('ct-summary-tbody');
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No CT data. Run CT monitor first.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(s => {
    const algos = Array.isArray(s.pqc_algorithms) ? s.pqc_algorithms : tryJSON(s.pqc_algorithms) || [];
    const issuers = Array.isArray(s.pqc_issuers) ? s.pqc_issuers : tryJSON(s.pqc_issuers) || [];
    const hasPQC = s.pqc_certs > 0;
    return `<tr>
      <td><span class="domain-link" style="cursor:default;font-family:var(--font-mono);font-size:.8rem">${s.domain}</span></td>
      <td style="color:var(--muted);font-size:.75rem">${(s.queried_at||'').slice(0,16)}</td>
      <td style="font-family:var(--font-mono)">${s.total_certs||0}</td>
      <td>${hasPQC ? `<span class="pqc-pill">✓ ${s.pqc_certs}</span>` : '<span style="color:var(--muted)">0</span>'}</td>
      <td>${s.hybrid_certs > 0 ? `<span style="color:#a78bfa;font-family:var(--font-mono)">${s.hybrid_certs}</span>` : '—'}</td>
      <td style="font-size:.75rem">${algos.slice(0,2).join(', ')||'—'}</td>
      <td style="font-size:.75rem;color:var(--muted)">${issuers.slice(0,1).join('')||'—'}</td>
    </tr>`;
  }).join('');
}

async function loadCTPQCCerts() {
  const r = await fetch('/api/ct/certificates');
  const certs = await r.json();
  const tbody = document.getElementById('ct-certs-tbody');
  if (!tbody) return;
  if (!certs.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:1.5rem">No PQC certificates found.</td></tr>';
    return;
  }
  tbody.innerHTML = certs.map(c => {
    const algos = Array.isArray(c.pqc_algorithms) ? c.pqc_algorithms : tryJSON(c.pqc_algorithms) || [];
    const typeTag = c.is_hybrid
      ? '<span style="background:rgba(124,58,237,.2);color:#a78bfa;padding:.1rem .4rem;border-radius:4px;font-size:.7rem">Hybrid</span>'
      : '<span class="pqc-pill">Pure PQC</span>';
    const expColor = c.days_to_expiry < 30 ? 'var(--critical)' : c.days_to_expiry < 90 ? 'var(--weak)' : 'var(--text)';
    return `<tr>
      <td style="font-family:var(--font-mono);font-size:.78rem">${c.domain}</td>
      <td style="font-size:.78rem">${c.subject_cn||'—'}</td>
      <td style="font-size:.75rem;color:var(--muted)">${c.issuer_cn||'—'}</td>
      <td style="font-family:var(--font-mono);font-size:.72rem">${c.signature_algorithm_name||c.signature_algorithm_oid||'—'}</td>
      <td style="font-size:.75rem">${algos.join(', ')||'—'}</td>
      <td>${typeTag}</td>
      <td style="font-size:.75rem;color:var(--muted)">${(c.not_before||'').slice(0,10)||'—'}</td>
      <td style="font-size:.75rem;color:${expColor}">${c.days_to_expiry != null ? c.days_to_expiry+'d' : '—'}</td>
    </tr>`;
  }).join('');
}

async function loadCTTimeline() {
  const r = await fetch('/api/ct/timeline');
  const rows = await r.json();
  const empty = document.getElementById('ct-timeline-empty');
  if (!rows.length) { if(empty) empty.style.display='block'; return; }
  if(empty) empty.style.display='none';

  const labels = rows.map(r => r.month);
  const pqc    = rows.map(r => r.pqc_total || 0);
  const hybrid = rows.map(r => r.hybrid_total || 0);

  const ctx = document.getElementById('chartCTTimeline')?.getContext('2d');
  if (!ctx || typeof Chart === 'undefined') return;
  if (charts.ctTimeline) charts.ctTimeline.destroy();
  charts.ctTimeline = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Pure PQC',   data: pqc,    backgroundColor: '#22c55e', borderRadius: 3 },
        { label: 'Hybrid',     data: hybrid,  backgroundColor: '#a78bfa', borderRadius: 3 },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { stacked: true, ticks:{color:'#64748b'}, grid:{color:'rgba(30,45,74,.5)'} },
        y: { stacked: true, ticks:{color:'#64748b'}, grid:{color:'rgba(30,45,74,.5)'} }
      },
      plugins: { legend: { labels: { color: '#e2e8f0', font:{size:11} } } }
    }
  });

  // Algorithm distribution doughnut from latest summaries
  const sr = await fetch('/api/ct/summaries');
  const summaries = await sr.json();
  const algoCounts = {};
  summaries.forEach(s => {
    const algos = Array.isArray(s.pqc_algorithms) ? s.pqc_algorithms : tryJSON(s.pqc_algorithms) || [];
    algos.forEach(a => { algoCounts[a] = (algoCounts[a]||0) + (s.pqc_certs||1); });
  });
  const algoLabels = Object.keys(algoCounts);
  const algoVals   = Object.values(algoCounts);
  const algoColors = ['#22c55e','#a78bfa','#00d4ff','#f97316','#eab308','#ef4444'];

  const ctx2 = document.getElementById('chartCTAlgos')?.getContext('2d');
  if (ctx2 && algoLabels.length && typeof Chart !== 'undefined') {
    if (charts.ctAlgos) charts.ctAlgos.destroy();
    charts.ctAlgos = new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: algoLabels,
        datasets: [{ data: algoVals, backgroundColor: algoColors, borderWidth: 0, hoverOffset: 4 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '60%',
        plugins: { legend: { position:'right', labels:{ color:'#e2e8f0', font:{size:10} } } }
      }
    });
  }
}

async function runCTMonitor() {
  const raw     = document.getElementById('ct-domains')?.value.trim() || '';
  const domains = raw.split('\n').map(d => d.trim()).filter(Boolean);
  if (!domains.length) { showAlert('ct-run-alert','Enter at least one domain','error'); return; }

  const fetchPem = document.getElementById('ct-fetch-pem')?.checked || false;
  const btn = document.getElementById('btn-ct-run');
  if (btn) { btn.disabled=true; btn.innerHTML='<span class="loader"></span>Querying CT logs…'; }
  showAlert('ct-run-alert',
    `Querying crt.sh for ${domains.length} domain(s)${fetchPem ? ' (PEM download enabled — may be slow)' : ''}…`,
    'info');

  try {
    const r = await fetch('/api/ct/monitor', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ domains, fetch_pem: fetchPem, max_certs: 100 })
    });
    const d = await r.json();
    if (d.error) { showAlert('ct-run-alert', d.error, 'error'); return; }
    showAlert('ct-run-alert',
      `✓ Done. ${d.domains_processed} domains processed. `+
      `PQC certs: ${d.pqc_certs_found}. Hybrid certs: ${d.hybrid_certs_found}.`,
      'ok');
    loadCTStats(); loadCTSummaries(); loadCTPQCCerts(); loadCTTimeline();
  } catch(e) {
    showAlert('ct-run-alert', 'CT monitor failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled=false; btn.textContent='Run CT Monitor'; }
  }
}

// ─── Roadmap ──────────────────────────────────────────────────────────────────

async function loadRoadmapStats() {
  const r = await fetch('/api/roadmap/stats');
  const s = await r.json();
  const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v??'0'; };
  set('rm-stat-domains', s.domains);
  set('rm-stat-p1',  s.total_p1_items);
  set('rm-stat-p2',  s.total_p2_items);
  set('rm-stat-p3',  s.total_p3_items);
  const emin = s.total_effort_min || 0, emax = s.total_effort_max || 0;
  set('rm-stat-effort', emin && emax ? `${emin}–${emax}d` : '—');
  // Update main dashboard urgent actions card
  const uc = document.getElementById('stat-p1-actions');
  if (uc) uc.textContent = s.domains_need_p1 ?? '0';
}

async function populateRoadmapRunSel() {
  const r = await fetch('/api/runs');
  const runs = await r.json();
  const sel = document.getElementById('rm-run-sel');
  if (!sel) return;
  const extra = runs.map(r => `<option value="${r.run_id}">${r.run_id} — ${(r.started_at||'').slice(0,10)} (${r.status})</option>`).join('');
  sel.innerHTML = '<option value="">Latest assessment per domain</option>' + extra;
  // Also populate the reassess run selector in scan view
  const expSel = document.getElementById('export-run');
  if (expSel) expSel.innerHTML = '<option value="">All runs (latest per domain)</option>' + extra;
}

async function loadRoadmapTable() {
  const run_id = document.getElementById('rm-run-sel')?.value || '';
  const url = '/api/roadmap' + (run_id ? `?run_id=${run_id}` : '');
  const r = await fetch(url);
  const domains = await r.json();
  renderRoadmapTable(domains);
  renderRoadmapCharts(domains);
}

function renderRoadmapTable(domains) {
  const tbody = document.getElementById('rm-domain-tbody');
  if (!tbody) return;
  if (!domains.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:2rem">No roadmap data. Click Generate Roadmap.</td></tr>';
    return;
  }
  tbody.innerHTML = domains.map(d => {
    const lc = (d.current_level === 'na') ? 'na' : scoreClass(d.current_score || 0);
    const s1c = scoreClass(d.score_after_phase1 || d.score_p1 || 0);
    const s2c = scoreClass(d.score_after_phase2 || d.score_p2 || 0);
    const emin = d.effort_days_min || d.effort_min || 0;
    const emax = d.effort_days_max || d.effort_max || 0;
    const p1 = d.phase1_items || 0;
    const p2 = d.phase2_items || 0;
    const p3 = d.phase3_items || 0;
    const completion = (d.estimated_completion || d.est_completion || '').slice(0,10);
    return `<tr>
      <td><a class="domain-link" href="#" onclick="showRoadmapDetail('${d.domain}');return false">${d.domain}</a></td>
      <td><span class="score-badge score-${lc}">${d.current_score??'?'}</span></td>
      <td><span class="score-badge score-${s1c}">${d.score_after_phase1||d.score_p1||'?'}</span></td>
      <td><span class="score-badge score-${s2c}">${d.score_after_phase2||d.score_p2||'?'}</span></td>
      <td><span class="score-badge score-ready">${d.score_after_phase3||d.score_p3||100}</span></td>
      <td style="text-align:center">${p1 ? `<span style="color:var(--critical);font-weight:600">${p1}</span>` : '—'}</td>
      <td style="text-align:center">${p2 ? `<span style="color:var(--moderate)">${p2}</span>` : '—'}</td>
      <td style="text-align:center">${p3 ? `<span style="color:#a78bfa">${p3}</span>` : '—'}</td>
      <td style="font-size:.75rem;font-family:var(--font-mono)">${emin}–${emax}d</td>
      <td style="font-size:.75rem;color:var(--muted)">${completion||'—'}</td>
    </tr>`;
  }).join('');
}

function renderRoadmapCharts(domains) {
  if (!domains.length) return;
  const labels = domains.slice(0,12).map(d => d.domain.replace(/\..+/, '…'));

  // Score progression chart
  const ctx1 = document.getElementById('chartRmScores')?.getContext('2d');
  if (ctx1 && typeof Chart !== 'undefined') {
    if (charts.rmScores) charts.rmScores.destroy();
    charts.rmScores = new Chart(ctx1, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Current',  data: domains.slice(0,12).map(d=>d.current_score||0), backgroundColor:'#ef4444' },
          { label: '→ Phase 1',data: domains.slice(0,12).map(d=>d.score_after_phase1||d.score_p1||0), backgroundColor:'#f97316' },
          { label: '→ Phase 2',data: domains.slice(0,12).map(d=>d.score_after_phase2||d.score_p2||0), backgroundColor:'#eab308' },
          { label: '→ Phase 3',data: domains.slice(0,12).map(d=>d.score_after_phase3||d.score_p3||100), backgroundColor:'#22c55e' },
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        scales:{
          x:{ticks:{color:'#64748b'},grid:{color:'rgba(30,45,74,.5)'}},
          y:{min:0,max:100,ticks:{color:'#64748b'},grid:{color:'rgba(30,45,74,.5)'}}
        },
        plugins:{legend:{labels:{color:'#e2e8f0',font:{size:10}}}}
      }
    });
  }

  // Effort distribution doughnut
  const effortByPhase = {p1:0, p2:0, p3:0};
  domains.forEach(d => {
    // Approximate by item count ratio
    const total = (d.phase1_items||0)+(d.phase2_items||0)+(d.phase3_items||0)||1;
    const emax = d.effort_days_max||d.effort_max||0;
    effortByPhase.p1 += Math.round((d.phase1_items||0)/total * emax);
    effortByPhase.p2 += Math.round((d.phase2_items||0)/total * emax);
    effortByPhase.p3 += Math.round((d.phase3_items||0)/total * emax);
  });
  const ctx2 = document.getElementById('chartRmEffort')?.getContext('2d');
  if (ctx2 && typeof Chart !== 'undefined') {
    if (charts.rmEffort) charts.rmEffort.destroy();
    charts.rmEffort = new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: ['Phase 1 (Immediate)', 'Phase 2 (Classical)', 'Phase 3 (PQC)'],
        datasets: [{ data:[effortByPhase.p1,effortByPhase.p2,effortByPhase.p3],
          backgroundColor:['#ef4444','#eab308','#a78bfa'], borderWidth:0, hoverOffset:4 }]
      },
      options: {
        responsive:true, maintainAspectRatio:false, cutout:'60%',
        plugins:{legend:{position:'right',labels:{color:'#e2e8f0',font:{size:10}}}}
      }
    });
  }
}

async function showRoadmapDetail(domain) {
  const r = await fetch(`/api/roadmap/domain/${encodeURIComponent(domain)}`);
  const d = await r.json();
  if (d.error) return;

  document.getElementById('rm-detail-title').textContent = `Action Plan: ${domain}`;
  const body = document.getElementById('rm-detail-body');

  const items = d.items_json || d.items || [];
  const phases = ['phase1_immediate','phase2_classical_hardening','phase3_pqc_transition'];
  const phaseLabels = {
    'phase1_immediate':           '🔴 Phase 1 — Immediate Remediation',
    'phase2_classical_hardening': '🟡 Phase 2 — Classical Hardening',
    'phase3_pqc_transition':      '🟣 Phase 3 — PQC Transition',
  };
  const effortColor = {low:'var(--ready)', medium:'var(--moderate)', high:'var(--weak)'};

  let html = `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem">`;
  for (const ph of phases) {
    const phItems = items.filter(i=>(i.phase||'')==ph);
    const label = phaseLabels[ph]||ph;
    const emin = phItems.reduce((s,i)=>s+(i.effort_days_min||0),0);
    const emax = phItems.reduce((s,i)=>s+(i.effort_days_max||0),0);
    html += `<div style="background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:8px;padding:1rem">
      <div style="font-size:.78rem;color:var(--muted);margin-bottom:.5rem">${label}</div>
      <div style="font-family:var(--font-mono);font-size:1.5rem;color:var(--text)">${phItems.length}</div>
      <div style="font-size:.72rem;color:var(--muted);margin-top:.25rem">${emin}–${emax} person-days</div>
    </div>`;
  }
  html += `</div>`;

  if (d.cdn_note) {
    html += `<div style="background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.3);border-radius:8px;padding:.75rem;margin-bottom:1rem;font-size:.82rem;color:var(--moderate)">${d.cdn_note}</div>`;
  }

  let currentPhase = null;
  for (const item of items) {
    const ph = item.phase || '';
    if (ph !== currentPhase) {
      currentPhase = ph;
      html += `<div style="margin:1.5rem 0 .5rem;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)">${phaseLabels[ph]||ph}</div>`;
    }
    const ec = effortColor[item.effort] || 'var(--text)';
    const refs = (item.guideline_refs||[]).join(', ');
    html += `<div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:.75rem">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.5rem">
        <div style="font-weight:600;font-size:.85rem">${item.action||''}</div>
        <span style="background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:4px;padding:.1rem .5rem;font-size:.7rem;color:${ec};font-family:var(--font-mono);white-space:nowrap">${(item.effort||'').toUpperCase()} ${item.effort_days_min||0}–${item.effort_days_max||0}d</span>
      </div>
      <div style="font-size:.78rem;color:var(--muted);margin-bottom:.5rem">Target: <span style="color:var(--text)">${item.target_date||'—'}</span>${refs?` &nbsp;·&nbsp; ${refs}`:''}</div>
      <div style="font-size:.78rem;margin-bottom:.35rem">
        <span style="color:var(--muted)">Now: </span>${item.current_state||'—'}
      </div>
      <div style="font-size:.78rem;margin-bottom:.5rem">
        <span style="color:var(--ready)">→ </span>${item.target_state||'—'}
      </div>
      <div style="font-size:.76rem;color:var(--muted);line-height:1.5">${item.detail||''}</div>
    </div>`;
  }

  body.innerHTML = html;
  document.getElementById('rm-domain-detail').style.display = 'block';
  document.getElementById('rm-domain-detail').scrollIntoView({behavior:'smooth'});
}

async function generateRoadmap() {
  const run_id = document.getElementById('rm-run-sel')?.value || null;
  const save   = document.getElementById('rm-save')?.checked || false;
  const btn = document.getElementById('btn-rm-gen');
  if (btn) { btn.disabled=true; btn.innerHTML='<span class="loader"></span>Generating…'; }
  showAlert('rm-alert','Generating roadmaps from assessment data…','info');

  try {
    const r = await fetch('/api/roadmap/generate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({run_id, save})
    });
    const d = await r.json();
    if (d.error) { showAlert('rm-alert', d.error, 'error'); return; }
    showAlert('rm-alert',
      `✓ Roadmaps generated for ${d.domains_processed} domains. `+
      `Avg score: ${d.avg_current_score}. `+
      `Total effort: ${d.total_effort_min}–${d.total_effort_max} person-days.`+
      (d.critical_domains?.length ? ` ⚠ ${d.critical_domains.length} critical domains.` : ''),
      'ok');
    loadRoadmapStats();
    loadRoadmapTable();
  } catch(e) {
    showAlert('rm-alert','Generation failed: '+e.message,'error');
  } finally {
    if (btn) { btn.disabled=false; btn.textContent='Generate Roadmap'; }
  }
}

// ─── Export ──────────────────────────────────────────────────────────────────
function doExport(fmt) {
  const runId = document.getElementById('export-run')?.value || '';
  const url = `/api/export?format=${fmt}${runId ? '&run_id='+runId : ''}`;
  window.location.href = url;
}

// ─── Domain History Chart ─────────────────────────────────────────────────────
async function loadDomainHistory(domain) {
  if (!domain) return;
  const r = await fetch(`/api/domain/${encodeURIComponent(domain)}`);
  const d = await r.json();
  const history = d.history || [];
  const empty = document.getElementById('domain-history-empty');
  if (!history.length) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  const labels = history.map(h => (h.assessed_at || '').slice(0, 10));
  const scores = history.map(h => h.score || 0);
  const ctx = document.getElementById('chartDomainHistory').getContext('2d');
  if (charts.domainHistory) charts.domainHistory.destroy();
  charts.domainHistory = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: domain,
        data: scores,
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.1)',
        tension: 0.3, fill: true, pointRadius: 5
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,.5)' } },
        y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: 'rgba(30,45,74,.5)' } }
      },
      plugins: { legend: { labels: { color: '#e2e8f0' } } }
    }
  });
}

async function populateDomainSelector() {
  const r = await fetch('/api/assessments');
  const assessments = await r.json();
  const sel = document.getElementById('history-domain-sel');
  if (!sel) return;
  assessments.forEach(a => {
    const opt = document.createElement('option');
    opt.value = a.domain;
    opt.textContent = a.domain;
    sel.appendChild(opt);
  });
}

// ─── Schedules ────────────────────────────────────────────────────────────────
async function loadSchedules() {
  const r = await fetch('/api/schedules');
  const schedules = await r.json();
  const el = document.getElementById('schedules-body');
  if (!el) return;
  if (!schedules.length) {
    el.innerHTML = '<div style="color:var(--muted)">No schedules configured.</div>';
    return;
  }
  el.innerHTML = `<table class="domain-table">
    <thead><tr><th>#</th><th>Name</th><th>Interval</th><th>Next Run</th><th>Last Run</th><th>Status</th></tr></thead>
    <tbody>${schedules.map(s => `<tr>
      <td style="font-family:var(--font-mono)">${s.id}</td>
      <td>${s.name||'—'}</td>
      <td>${s.interval_days}d</td>
      <td style="color:var(--muted);font-size:.78rem">${(s.next_run||'').slice(0,16)||'—'}</td>
      <td style="color:var(--muted);font-size:.78rem">${(s.last_run||'').slice(0,16)||'never'}</td>
      <td><span style="color:${s.enabled?'var(--ready)':'var(--muted)'}">${s.enabled?'active':'paused'}</span></td>
    </tr>`).join('')}</tbody>
  </table>`;
}

// ─── Settings ────────────────────────────────────────────────────────────────

function renderSettingsVersion() {
  // Settings view is static HTML — just ensure it's visible (nothing async needed)
  // The {{ version }} is already rendered server-side.
}

// ─── Init ────────────────────────────────────────────────────────────────────
loadSummary();
loadAssessments();
loadRoadmapStats();


// ── Group Report ──────────────────────────────────────────────────────────────

let _grReport    = null;
let _grFiltered  = [];
let _grSortCol   = null;
let _grSortAsc   = true;

const GR_LEVEL_COLOURS = {
  Critical: '#ef4444', Weak: '#f97316',
  Moderate: '#eab308', Ready: '#22c55e', 'N/A': '#6b7280'
};
const GR_LEVEL_ORDER = { 'critical': 0, 'weak': 1, 'moderate': 2, 'ready': 3, 'na': 4 };

function grLevel(score) {
  if (score == null) return 'N/A';
  if (score < 30)   return 'Critical';
  if (score < 55)   return 'Weak';
  if (score < 75)   return 'Moderate';
  return 'Ready';
}

async function grInit() { await grSwitchViewBy(); }

async function grSwitchViewBy() {
  const viewBy = document.getElementById('gr-view-by')?.value || 'community';
  const sel    = document.getElementById('gr-group-sel');
  if (!sel) return;
  sel.innerHTML = '<option value="">— loading… —</option>';
  _grReport = null;
  grClearTable();
  document.getElementById('gr-btn-csv').disabled = true;
  document.getElementById('gr-btn-pdf').disabled = true;

  if (viewBy === 'community') {
    const r = await fetch('/app/api/communities');
    const items = await r.json().catch(() => []);
    sel.innerHTML = '<option value="">— Select Community —</option>' +
      items.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
  } else if (viewBy === 'region') {
    const r = await fetch('/app/api/regions');
    const items = await r.json().catch(() => []);
    sel.innerHTML = '<option value="">— Select Region —</option>' +
      items.map(rg => `<option value="${esc(rg)}">${esc(rg)}</option>`).join('');
  } else {
    const r = await fetch('/app/api/countries');
    const items = await r.json().catch(() => []);
    sel.innerHTML = '<option value="">— Select Country —</option>' +
      items.map(c => `<option value="${esc(c.country_code)}">${esc(c.country_code)} – ${esc(c.country||c.country_code)}</option>`).join('');
  }
}

async function grLoadReport() {
  const viewBy = document.getElementById('gr-view-by')?.value || 'community';
  const val    = document.getElementById('gr-group-sel')?.value;
  if (!val) { grClearTable(); return; }

  const url = viewBy === 'community'
    ? `/app/api/communities/${val}/report`
    : viewBy === 'region'
    ? `/app/api/regions/${encodeURIComponent(val)}/report`
    : `/app/api/countries/${encodeURIComponent(val)}/report`;

  const r = await fetch(url);
  if (!r.ok) { console.error('Group report fetch failed', r.status); return; }
  _grReport   = await r.json();
  _grFiltered = _grReport.organisations || [];
  _grSortCol  = null;
  _grSortAsc  = true;

  // Country filter — only when >1 distinct country
  const countries = [...new Set(_grFiltered.map(o => o.country_code).filter(Boolean))].sort();
  const cf = document.getElementById('gr-country-filter');
  if (countries.length > 1) {
    cf.innerHTML = '<option value="">All Countries</option>' +
      countries.map(cc => {
        const name = (_grFiltered.find(o => o.country_code === cc)||{}).country || cc;
        return `<option value="${cc}">${cc}${name ? ' – ' + esc(name) : ''}</option>`;
      }).join('');
    cf.style.display = '';
  } else {
    cf.style.display = 'none';
    cf.value = '';
  }

  grRenderTable();
  grRenderCharts();
  document.getElementById('gr-btn-csv').disabled = false;
  document.getElementById('gr-btn-pdf').disabled = false;
}

function grApplyFilters() {
  if (!_grReport) return;
  const cc = document.getElementById('gr-country-filter')?.value || '';
  _grFiltered = cc
    ? (_grReport.organisations||[]).filter(o => (o.country_code||'') === cc)
    : (_grReport.organisations||[]);
  _grSortCol = null; _grSortAsc = true;
  grRenderTable();
  grRenderCharts();
}

function grSort(col) {
  if (_grSortCol === col) {
    _grSortAsc = !_grSortAsc;
  } else {
    _grSortCol = col;
    _grSortAsc = col === 'name' || col === 'country_code';  // text cols default asc
  }
  const asc = _grSortAsc;
  _grFiltered = [..._grFiltered].sort((a, b) => {
    let va = a[col], vb = b[col];
    if (col === 'level') {
      va = GR_LEVEL_ORDER[grLevel(a.avg_score).toLowerCase()] ?? 99;
      vb = GR_LEVEL_ORDER[grLevel(b.avg_score).toLowerCase()] ?? 99;
    }
    if (va == null) va = asc ? Infinity : -Infinity;
    if (vb == null) vb = asc ? Infinity : -Infinity;
    if (typeof va === 'string') return asc ? va.localeCompare(vb) : vb.localeCompare(va);
    return asc ? va - vb : vb - va;
  });
  // Update sort indicators
  document.querySelectorAll('.gr-sort-ind').forEach(el => {
    el.textContent = el.dataset.col === col ? (asc ? ' ▲' : ' ▼') : '';
  });
  grRenderTable();
}

function grRenderTable() {
  const tbody = document.getElementById('gr-tbody');
  const table = document.getElementById('gr-table');
  const empty = document.getElementById('gr-empty');
  const sumEl = document.getElementById('gr-summary');

  if (!_grFiltered.length) {
    table.style.display = 'none'; empty.style.display = ''; sumEl.style.display = 'none';
    return;
  }

  sumEl.textContent = _grReport.summary || '';
  sumEl.style.display = '';

  tbody.innerHTML = _grFiltered.map(o => {
    const lvl    = grLevel(o.avg_score);
    const colour = GR_LEVEL_COLOURS[lvl] || '#6b7280';
    const score  = o.avg_score != null ? o.avg_score.toFixed(1) : 'N/A';
    return `<tr>
      <td><strong>${esc(o.name||'')}</strong></td>
      <td style="color:var(--muted)">${esc(o.country_code||'')}</td>
      <td style="color:var(--muted)">${esc(o.sector||'')}</td>
      <td style="text-align:right">${o.domain_count||0}</td>
      <td style="text-align:right">${score}</td>
      <td><span style="background:${colour}20;color:${colour};padding:.15rem .45rem;border-radius:3px;font-size:.74rem;font-weight:600">${lvl}</span></td>
      <td style="text-align:right;color:#ef4444">${o.critical||0}</td>
      <td style="text-align:right;color:#f97316">${o.weak||0}</td>
      <td style="text-align:right;color:#eab308">${o.moderate||0}</td>
      <td style="text-align:right;color:#22c55e">${o.ready||0}</td>
      <td style="text-align:right;color:var(--muted)">${o.no_tls||0}</td>
      <td style="text-align:right;color:#38bdf8">${o.pqc_count||0}</td>
    </tr>`;
  }).join('');

  // Totals
  const tot = {
    domain_count: _grFiltered.reduce((s,o)=>s+(o.domain_count||0),0),
    avg_score: (() => { const sc=_grFiltered.filter(o=>o.avg_score!=null); return sc.length ? sc.reduce((s,o)=>s+o.avg_score,0)/sc.length : null; })(),
    critical: _grFiltered.reduce((s,o)=>s+(o.critical||0),0),
    weak:     _grFiltered.reduce((s,o)=>s+(o.weak||0),0),
    moderate: _grFiltered.reduce((s,o)=>s+(o.moderate||0),0),
    ready:    _grFiltered.reduce((s,o)=>s+(o.ready||0),0),
    no_tls:   _grFiltered.reduce((s,o)=>s+(o.no_tls||0),0),
    pqc_count:_grFiltered.reduce((s,o)=>s+(o.pqc_count||0),0),
  };
  const tlvl   = grLevel(tot.avg_score);
  const tcolor = GR_LEVEL_COLOURS[tlvl] || '#6b7280';
  const tscore = tot.avg_score != null ? tot.avg_score.toFixed(1) : 'N/A';
  tbody.innerHTML += `<tr style="border-top:2px solid var(--border);font-weight:600">
    <td>Totals</td><td></td><td></td>
    <td style="text-align:right">${tot.domain_count}</td>
    <td style="text-align:right">${tscore}</td>
    <td><span style="background:${tcolor}20;color:${tcolor};padding:.15rem .45rem;border-radius:3px;font-size:.74rem;font-weight:600">${tlvl}</span></td>
    <td style="text-align:right;color:#ef4444">${tot.critical}</td>
    <td style="text-align:right;color:#f97316">${tot.weak}</td>
    <td style="text-align:right;color:#eab308">${tot.moderate}</td>
    <td style="text-align:right;color:#22c55e">${tot.ready}</td>
    <td style="text-align:right;color:var(--muted)">${tot.no_tls}</td>
    <td style="text-align:right;color:#38bdf8">${tot.pqc_count}</td>
  </tr>`;

  table.style.display = '';
  empty.style.display = 'none';
}

// ── Group Report Charts ────────────────────────────────────────────────────────

function grRenderCharts() {
  if (!_grFiltered.length) {
    document.getElementById('gr-charts').style.display = 'none';
    return;
  }
  document.getElementById('gr-charts').style.display = 'flex';
  grRenderDonut();
  grRenderBars();
}

function grRenderDonut() {
  const svg = document.getElementById('gr-donut');
  if (!svg) return;
  const W = 220, H = 160, cx = 80, cy = 80, R = 60, r = 36;

  // Count orgs by level
  const counts = { Critical: 0, Weak: 0, Moderate: 0, Ready: 0, 'N/A': 0 };
  _grFiltered.forEach(o => { const l = grLevel(o.avg_score); counts[l] = (counts[l]||0)+1; });
  const total = _grFiltered.length;
  const slices = Object.entries(counts).filter(([,v])=>v>0);

  let angle = -Math.PI / 2;
  let paths = '';
  let legend = '';
  let ly = 28;
  slices.forEach(([lvl, cnt]) => {
    const sweep = (cnt / total) * 2 * Math.PI;
    const x1 = cx + R * Math.cos(angle), y1 = cy + R * Math.sin(angle);
    angle += sweep;
    const x2 = cx + R * Math.cos(angle), y2 = cy + R * Math.sin(angle);
    const xi1 = cx + r * Math.cos(angle - sweep), yi1 = cy + r * Math.sin(angle - sweep);
    const xi2 = cx + r * Math.cos(angle),          yi2 = cy + r * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    const col = GR_LEVEL_COLOURS[lvl] || '#6b7280';
    paths += `<path d="M${xi1},${yi1} L${x1},${y1} A${R},${R} 0 ${large},1 ${x2},${y2} L${xi2},${yi2} A${r},${r} 0 ${large},0 ${xi1},${yi1} Z" fill="${col}" opacity="0.85">
      <title>${lvl}: ${cnt}</title></path>`;
    legend += `<rect x="150" y="${ly-8}" width="9" height="9" fill="${col}" rx="2"/>
      <text x="162" y="${ly}" fill="#94a3b8" font-size="10">${lvl} (${cnt})</text>`;
    ly += 18;
  });

  // Centre text
  paths += `<text x="${cx}" y="${cy-4}" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="600">${total}</text>
    <text x="${cx}" y="${cy+13}" text-anchor="middle" fill="#64748b" font-size="9">orgs</text>`;

  svg.innerHTML = `<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">${paths}${legend}</svg>`;
}

function grRenderBars() {
  const svg = document.getElementById('gr-bars');
  if (!svg) return;
  const data  = [..._grFiltered].sort((a,b) => (b.avg_score??-1)-(a.avg_score??-1));
  const n     = data.length;
  const PAD_L = 12, PAD_R = 8, PAD_T = 10, BAR_H = 18, GAP = 4;
  const W     = 500;
  const H     = PAD_T + n * (BAR_H + GAP);

  let rows = '';
  data.forEach((o, i) => {
    const y      = PAD_T + i * (BAR_H + GAP);
    const score  = o.avg_score ?? 0;
    const col    = GR_LEVEL_COLOURS[grLevel(o.avg_score)] || '#6b7280';
    const bw     = Math.max(2, ((W - PAD_L - PAD_R - 60) * score) / 100);
    const label  = (o.name||'').slice(0, 22);
    rows += `
      <text x="${PAD_L}" y="${y + BAR_H - 5}" fill="#94a3b8" font-size="9.5" font-family="system-ui">${esc(label)}</text>
      <rect x="${PAD_L + 60}" y="${y+2}" width="${bw}" height="${BAR_H-4}" fill="${col}" opacity="0.8" rx="3">
        <title>${o.name}: ${o.avg_score != null ? o.avg_score.toFixed(1) : 'N/A'}</title>
      </rect>
      <text x="${PAD_L + 64 + bw}" y="${y + BAR_H - 5}" fill="${col}" font-size="9" font-family="monospace">${o.avg_score != null ? o.avg_score.toFixed(0) : 'N/A'}</text>`;
  });

  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('height', H);
  svg.innerHTML = rows;
}

function grClearTable() {
  const tbody = document.getElementById('gr-tbody');
  if (tbody) tbody.innerHTML = '';
  const table = document.getElementById('gr-table');
  if (table) table.style.display = 'none';
  const empty = document.getElementById('gr-empty');
  if (empty) empty.style.display = '';
  const sum = document.getElementById('gr-summary');
  if (sum) sum.style.display = 'none';
  const charts = document.getElementById('gr-charts');
  if (charts) charts.style.display = 'none';
}

function grExportCSV() {
  const viewBy = document.getElementById('gr-view-by')?.value || 'community';
  const val    = document.getElementById('gr-group-sel')?.value;
  if (!val) return;
  const url = viewBy === 'community'
    ? `/app/api/communities/${val}/report.csv`
    : viewBy === 'region'
    ? `/app/api/regions/${encodeURIComponent(val)}/report.csv`
    : `/app/api/countries/${encodeURIComponent(val)}/report.csv`;
  window.location = url;
}

function grExportPDF() {
  const viewBy = document.getElementById('gr-view-by')?.value || 'community';
  const val    = document.getElementById('gr-group-sel')?.value;
  if (!val) return;
  const url = viewBy === 'community'
    ? `/app/api/communities/${val}/report.pdf`
    : viewBy === 'region'
    ? `/app/api/regions/${encodeURIComponent(val)}/report.pdf`
    : `/app/api/countries/${encodeURIComponent(val)}/report.pdf`;
  window.location = url;
}

</script>
</body>
</html>
"""


if __name__ == "__main__":
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")
    config = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            raw = yaml.safe_load(f)
        config = {
            "db_path": raw.get("database", {}).get("path", "data/pqc_monitor.db"),
            "secret_key": raw.get("dashboard", {}).get("secret_key", "dev"),
            "anthropic_api_key": raw.get("ai", {}).get("anthropic_api_key", ""),
            "shodan_api_key": raw.get("shodan", {}).get("api_key", ""),
            **raw.get("scanning", {})
        }

    app = create_app(config)
    host = raw.get("dashboard", {}).get("host", "127.0.0.1") if config else "127.0.0.1"
    port = raw.get("dashboard", {}).get("port", 5000) if config else 5000
    app.run(host=host, port=port, debug=False)
