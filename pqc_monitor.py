#!/usr/bin/env python3
"""
PQC-Monitor: Main CLI Entry Point
Post-Quantum Cryptography readiness monitor for web services.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)

DISCLAIMER: Non-intrusive passive scanning only. Users must have proper
authorisation before scanning any systems. For research purposes only.
"""

import sys
import os
import logging
import click
import yaml

# ─── Setup paths ─────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from scanner.orchestrator import ScanOrchestrator
from domain_discovery.domain_finder import DomainDiscovery
from data.database import Database

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None


# ─── Config loading ──────────────────────────────────────────────────────────

def load_config(config_path: str = None) -> dict:
    path = config_path or os.path.join(ROOT, "config", "config.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    return {
        "db_path": raw.get("database", {}).get("path", "data/pqc_monitor.db"),
        "secret_key": raw.get("dashboard", {}).get("secret_key", "dev"),
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY",
                              raw.get("ai", {}).get("anthropic_api_key", "")),
        "model": raw.get("ai", {}).get("model", "claude-sonnet-4-20250514"),
        "shodan_api_key": os.environ.get("SHODAN_API_KEY",
                           raw.get("shodan", {}).get("api_key", "")),
        "ports": raw.get("scanning", {}).get("ports", [443, 8443, 465, 993, 636]),
        "timeout": raw.get("scanning", {}).get("timeout", 10),
        "max_workers": raw.get("scanning", {}).get("max_workers", 20),
        "guidelines": raw.get("guidelines", {}).get("active",
                      ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"]),
        "guidelines_dir": os.path.join(ROOT, "guidelines"),
        "dashboard_host": raw.get("dashboard", {}).get("host", "127.0.0.1"),
        "dashboard_port": raw.get("dashboard", {}).get("port", 5000),
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

DISCLAIMER = """
⚠️  PQC-MONITOR DISCLAIMER
Non-intrusive passive scanning only. Ensure you have authorisation
before scanning any systems. For research purposes only. GPL-3.0.
"""

@click.group()
@click.option("--config", default=None, help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def cli(ctx, config, verbose):
    """PQC-Monitor: Post-Quantum Cryptography Readiness Scanner"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.argument("query")
@click.option("--max-domains", "-n", default=50, help="Maximum domains to return")
@click.option("--no-validate", is_flag=True, help="Skip DNS validation")
@click.option("--output", "-o", default=None, help="Save domains to file")
@click.pass_context
def discover(ctx, query, max_domains, no_validate, output):
    """Discover domains for a sector/region using natural language.

    Examples:
      pqc_monitor.py discover "financial institutions in Spain"
      pqc_monitor.py discover "healthcare providers in Germany" -n 30 -o domains.txt
    """
    print(DISCLAIMER)
    cfg = ctx.obj["config"]
    d = DomainDiscovery(
        anthropic_api_key=cfg.get("anthropic_api_key", ""),
        model=cfg.get("model", "claude-sonnet-4-20250514")
    )

    click.echo(f"🔍 Discovering domains for: {query!r}")
    result = d.discover(query, max_domains, validate=not no_validate)

    click.echo(f"\n✅ Found {len(result['domains'])} domains (source: {result.get('source','?')})")
    click.echo(f"   {result.get('query_interpreted','')}")
    if result.get("notes"):
        click.echo(f"   Note: {result['notes']}")
    click.echo("")

    for domain in result["domains"]:
        click.echo(f"  {domain}")

    if output:
        d.save_domain_list(result["domains"], output)
        click.echo(f"\n💾 Saved to {output}")

    # Save to DB
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    db.save_domain_list(query[:60], result["domains"], query)


@cli.command()
@click.option("--domains", "-d", default=None, help="File with domains (one per line)")
@click.option("--domain", multiple=True, help="Individual domain(s) to scan")
@click.option("--sector", default="", help="Sector name")
@click.option("--region", default="", help="Region name")
@click.option("--shodan", is_flag=True, help="Use Shodan API if available")
@click.pass_context
def scan(ctx, domains, domain, sector, region, shodan):
    """Scan domains for cryptographic posture and PQC readiness.

    Examples:
      pqc_monitor.py scan --domains domains.txt
      pqc_monitor.py scan --domain example.com --domain bank.es
    """
    print(DISCLAIMER)
    cfg = ctx.obj["config"]

    domain_list = list(domain)
    if domains:
        with open(domains) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domain_list.append(line)

    if not domain_list:
        click.echo("❌ No domains specified. Use --domains FILE or --domain DOMAIN", err=True)
        sys.exit(1)

    click.echo(f"🔬 Scanning {len(domain_list)} domains...")
    orchestrator = ScanOrchestrator(cfg)

    completed = 0
    def progress(done, total, current_domain):
        click.echo(f"  [{done}/{total}] {current_domain}")

    run_id = orchestrator.scan_domains(
        domain_list, sector=sector, region=region,
        use_shodan=shodan, progress_callback=progress
    )

    click.echo(f"\n✅ Scan complete. run_id={run_id}")
    click.echo(f"   Launch dashboard to view results: pqc_monitor.py dashboard")

    # Print summary
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    assessments = db.get_latest_assessments(run_id)
    if assessments:
        click.echo(f"\n{'Domain':<35} {'Score':>5} {'Level':<10} PQC")
        click.echo("-" * 60)
        for a in sorted(assessments, key=lambda x: x.get("score", 0)):
            pqc = "✓" if a.get("has_pqc") else " "
            click.echo(f"{a['domain']:<35} {a.get('score',0):>5} {a.get('level','')::<10} {pqc}")


@cli.command()
@click.pass_context
def dashboard(ctx):
    """Launch the web dashboard (with RBAC).

    Opens on http://localhost:5000 by default.
    Default admin credentials: admin / changeme123 — change on first login.
    """
    cfg = ctx.obj["config"]
    from app_factory import create_app

    app = create_app(cfg)
    host = cfg.get("dashboard_host", "127.0.0.1")
    port = cfg.get("dashboard_port", 5000)

    click.echo(f"🚀 Dashboard starting at http://{host}:{port}")
    click.echo("   RBAC enabled — login at /login")
    click.echo("   Default admin: username=admin  password=changeme123")
    click.echo("   ⚠  Change the default password immediately!")
    click.echo("   Press Ctrl+C to stop")
    app.run(host=host, port=port, debug=False)


@cli.command()
@click.option("--domains", "-d", required=True, help="Domain list file")
@click.option("--interval", default="90d", help="Scan interval (e.g. 90d, 30d)")
@click.option("--sector", default="")
@click.option("--region", default="")
@click.option("--name", default="", help="Schedule name")
@click.pass_context
def schedule(ctx, domains, interval, sector, region, name):
    """Add a periodic scan schedule."""
    cfg = ctx.obj["config"]
    with open(domains) as f:
        domain_list = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    days = int(interval.rstrip("d"))
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    list_id = db.save_domain_list(name or domains, domain_list)

    from scanner.orchestrator import ScanOrchestrator
    from scheduler.scan_scheduler import ScanScheduler
    orch = ScanOrchestrator(cfg)
    sched = ScanScheduler(orch, db)
    sched_id = sched.add_schedule(
        name=name or f"auto-{sector}-{region}",
        domain_list_id=list_id,
        interval_days=days,
        sector=sector, region=region
    )
    click.echo(f"✅ Schedule #{sched_id} added: every {days} days")


@cli.command()
@click.argument("run_id")
@click.option("--guidelines", "-g", multiple=True,
              help="Guideline IDs to use (default: all)")
@click.pass_context
def reassess(ctx, run_id, guidelines):
    """Re-assess a previous scan run against (updated) guidelines.

    Example:
      pqc_monitor.py reassess abc12345
      pqc_monitor.py reassess abc12345 -g nist_800_131a -g bsi_tr02102
    """
    cfg = ctx.obj["config"]
    orch = ScanOrchestrator(cfg)
    gids = list(guidelines) or None
    new_run_id = orch.reassess_run(run_id, gids)
    click.echo(f"✅ Re-assessment complete. new_run_id={new_run_id}")


@cli.command()
@click.pass_context
def list_runs(ctx):
    """List recent scan runs."""
    cfg = ctx.obj["config"]
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    runs = db.list_runs(20)
    if not runs:
        click.echo("No scan runs found.")
        return
    click.echo(f"\n{'Run ID':<12} {'Started':<22} {'Sector':<15} {'Status':<12}")
    click.echo("-" * 65)
    for r in runs:
        click.echo(f"{r['run_id']:<12} {r['started_at'][:19]:<22} "
                   f"{r.get('sector',''):<15} {r['status']:<12}")


@cli.command("export")
@click.option("--format", "fmt", type=click.Choice(["csv", "json", "text"]),
              default="csv", show_default=True, help="Output format")
@click.option("--run-id", default=None, help="Limit to a specific scan run")
@click.option("--output", "-o", default=None,
              help="Output file path (default: stdout)")
@click.pass_context
def export_cmd(ctx, fmt, run_id, output):
    """Export assessment results to CSV, JSON, or plain text.

    Examples:
      pqc_monitor.py export --format csv -o results.csv
      pqc_monitor.py export --format json --run-id abc12345 -o run.json
      pqc_monitor.py export --format text
    """
    cfg = ctx.obj["config"]
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    sys.path.insert(0, ROOT)
    from reports.report_generator import export_csv, export_json, export_text_report

    if fmt == "csv":
        content = export_csv(db, run_id)
    elif fmt == "json":
        content = export_json(db, run_id)
    else:
        content = export_text_report(db, run_id)

    if output:
        import os as _os
        _os.makedirs(_os.path.dirname(_os.path.abspath(output)), exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"✅ Exported {fmt.upper()} to {output}")
    else:
        click.echo(content, nl=False)


@cli.command("report")
@click.option("--run-id", default=None, help="Specific scan run (default: latest per domain)")
@click.option("--output", "-o", default="data/report.txt",
              show_default=True, help="Output file path")
@click.pass_context
def report_cmd(ctx, run_id, output):
    """Generate a full text readiness report.

    Example:
      pqc_monitor.py report -o reports/spain-finance-2026-Q1.txt
    """
    cfg = ctx.obj["config"]
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    from reports.report_generator import export_text_report, save_report
    content = export_text_report(db, run_id)
    save_report(content, output, label="Report")
    click.echo(f"✅ Report written to {output}")
    # Print first 20 lines as preview
    for line in content.split("\n")[:20]:
        click.echo(line)
    click.echo("  ...")


@cli.command("ct-monitor")
@click.option("--domains", "-d", default=None,
              help="File with domains (one per line)")
@click.option("--domain", multiple=True,
              help="Individual domain(s)")
@click.option("--fetch-pem", is_flag=True, default=False,
              help="Download PEM for full OID inspection (slower, required for PQC detection)")
@click.option("--max-certs", default=100, show_default=True,
              help="Max certificates to inspect per domain")
@click.option("--output", "-o", default=None,
              help="Save JSON results to file")
@click.pass_context
def ct_monitor_cmd(ctx, domains, domain, fetch_pem, max_certs, output):
    """Query Certificate Transparency logs for PQC certificate deployments.

    Searches crt.sh for certificates issued to the specified domains and
    classifies them using a registry of known PQC algorithm OIDs:
    ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon, composite/hybrid schemes.

    No active scanning — passive CT log analysis only.

    Examples:
      pqc_monitor.py ct-monitor --domain example.com
      pqc_monitor.py ct-monitor --domains domains.txt --fetch-pem
      pqc_monitor.py ct-monitor --domain bancosantander.es -o ct_results.json
    """
    print(DISCLAIMER)
    cfg = ctx.obj["config"]
    sys.path.insert(0, ROOT)
    from ct.ct_monitor import monitor_domains
    from data.database import Database
    import json as _json

    domain_list = list(domain)
    if domains:
        with open(domains) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domain_list.append(line)

    if not domain_list:
        click.echo("❌ No domains specified. Use --domains FILE or --domain DOMAIN", err=True)
        sys.exit(1)

    click.echo(f"🔍 Querying CT logs for {len(domain_list)} domain(s)...")
    if fetch_pem:
        click.echo("   PEM download enabled — inspecting certificate OIDs directly")
    else:
        click.echo("   PEM download disabled — OID detection from metadata only")
        click.echo("   Use --fetch-pem for full PQC OID detection")

    summaries = monitor_domains(domain_list, fetch_pem=fetch_pem,
                                max_certs_per_domain=max_certs)

    # Persist to DB
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    for s in summaries:
        db.save_ct_summary(s.to_dict())

    # Print summary table
    click.echo(f"\n{'Domain':<40} {'Total':>6} {'PQC':>5} {'Hybrid':>7}  Algorithms")
    click.echo("-" * 80)
    total_pqc = 0
    for s in summaries:
        algos = ", ".join(s.pqc_algorithms_seen[:2]) if s.pqc_algorithms_seen else "—"
        pqc_marker = " ✓" if s.pqc_certs_found else "  "
        click.echo(
            f"{s.domain:<40} {s.total_certs_found:>6} "
            f"{s.pqc_certs_found:>4}{pqc_marker} "
            f"{s.hybrid_certs_found:>6}   {algos}"
        )
        total_pqc += s.pqc_certs_found

    click.echo(f"\n✅ Total PQC certificates found: {total_pqc}")
    if total_pqc == 0:
        click.echo("   No PQC certificates detected in CT logs yet.")
        if not fetch_pem:
            click.echo("   Try --fetch-pem for full OID-level inspection.")

    if output:
        results = [s.to_dict() for s in summaries]
        with open(output, "w") as f:
            import json as _json2
            _json2.dump(results, f, indent=2, default=str)
        click.echo(f"💾 Results saved to {output}")


@cli.command("roadmap")
@click.option("--run-id", default=None,
              help="Specific scan run (default: latest per domain)")
@click.option("--domain", default=None,
              help="Generate roadmap for a single domain only")
@click.option("--format", "fmt",
              type=click.Choice(["text", "json"]), default="text",
              show_default=True)
@click.option("--output", "-o", default=None,
              help="Write to file (default: stdout)")
@click.option("--save", is_flag=True, default=False,
              help="Persist roadmap to database")
@click.pass_context
def roadmap_cmd(ctx, run_id, domain, fmt, output, save):
    """Generate a prioritised PQC migration roadmap from assessment data.

    Produces a phased action plan:
      Phase 1 — Immediate Remediation   (current non-compliance, ≤ 6 months)
      Phase 2 — Classical Hardening     (best-practice posture, ≤ 2026)
      Phase 3 — PQC Transition          (ML-KEM / ML-DSA deployment, ≤ 2030)

    Examples:
      pqc_monitor.py roadmap
      pqc_monitor.py roadmap --domain bancosantander.es --format text
      pqc_monitor.py roadmap --run-id abc12345 --format json -o roadmap.json --save
    """
    cfg = ctx.obj["config"]
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    sys.path.insert(0, ROOT)
    from roadmap.generator import (
        generate_domain_roadmap, generate_sector_roadmap,
        render_roadmap_text, render_sector_roadmap_text,
    )
    import json as _json

    assessments = db.get_latest_assessments(run_id)
    if domain:
        assessments = [a for a in assessments if a.get("domain") == domain]
        if not assessments:
            click.echo(f"❌ No assessment data found for domain: {domain}", err=True)
            sys.exit(1)

    if not assessments:
        click.echo("❌ No assessment data. Run a scan first.", err=True)
        sys.exit(1)

    # Fetch CDN info from domain_extra to enrich assessments
    if run_id:
        for a in assessments:
            extra = db.get_domain_extra(a.get("domain", ""), run_id)
            cdn = extra.get("cdn", {})
            if cdn.get("detected"):
                a["cdn_name"] = cdn.get("cdn_name", "")

    if domain and len(assessments) == 1:
        # Single domain roadmap
        dr = generate_domain_roadmap(assessments[0])
        if save:
            db.save_roadmap(run_id or "manual", dr.to_dict())
            click.echo(f"✅ Roadmap saved to database for {domain}")
        if fmt == "json":
            content = _json.dumps(dr.to_dict(), indent=2, default=str)
        else:
            content = render_roadmap_text(dr)
    else:
        # Sector-level roadmap
        runs = db.list_runs(50)
        run_meta = next((r for r in runs if r.get("run_id") == run_id), {})
        sr = generate_sector_roadmap(
            assessments,
            sector=run_meta.get("sector", ""),
            region=run_meta.get("region", ""),
        )
        if save:
            for a in assessments:
                dr = generate_domain_roadmap(a)
                db.save_roadmap(run_id or "manual", dr.to_dict())
            click.echo(f"✅ {len(assessments)} roadmaps saved to database")
        if fmt == "json":
            content = _json.dumps(sr.to_dict(), indent=2, default=str)
        else:
            content = render_sector_roadmap_text(sr)

    if output:
        import os as _os
        _os.makedirs(_os.path.dirname(_os.path.abspath(output)), exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"💾 Roadmap written to {output}")
    else:
        click.echo(content, nl=False)


@cli.command("list-schedules")
@click.pass_context
def list_schedules(ctx):
    """List all configured periodic scan schedules."""
    cfg = ctx.obj["config"]
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM scheduled_scans").fetchall()
    if not rows:
        click.echo("No schedules configured.")
        click.echo("Add one with: pqc_monitor.py schedule --domains FILE --interval 90d")
        return
    click.echo(f"\n{'#':<4} {'Name':<25} {'Interval':>10} {'Next run':<22} {'Last run':<22} En")
    click.echo("-" * 90)
    for r in rows:
        r = dict(r)
        enabled = "✓" if r.get("enabled") else "✗"
        click.echo(
            f"{r['id']:<4} {r.get('name',''):<25} {r.get('interval_days',90):>8}d  "
            f"{(r.get('next_run') or '')[:19]:<22} {(r.get('last_run') or 'never')[:19]:<22} {enabled}"
        )


if __name__ == "__main__":
    cli()

