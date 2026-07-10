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

    raw_db_path = raw.get("database", {}).get("path", "data/pqc_monitor.db")
    # Resolve relative paths against the app root so they are CWD-independent.
    # Absolute paths (e.g. /var/lib/pqc-monitor/...) are left unchanged.
    db_path = raw_db_path if os.path.isabs(raw_db_path) \
              else os.path.join(ROOT, raw_db_path)

    return {
        "db_path": db_path,
        "secret_key": raw.get("dashboard", {}).get("secret_key", "dev"),
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY",
                              raw.get("ai", {}).get("anthropic_api_key", "")),
        "model": raw.get("ai", {}).get("model", "claude-sonnet-4-20250514"),
        "shodan_api_key": os.environ.get("SHODAN_API_KEY",
                           raw.get("shodan", {}).get("api_key", "")),
        "ports": raw.get("scanning", {}).get("ports", [443, 8443, 465, 993, 995, 636]),
        "use_starttls": raw.get("scanning", {}).get("use_starttls", True),
        "timeout": raw.get("scanning", {}).get("timeout", 10),
        "max_workers": raw.get("scanning", {}).get("max_workers", 20),
        "guidelines": raw.get("guidelines", {}).get("active",
                      ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"]),
        "guidelines_dir": os.path.join(ROOT, "guidelines"),
        "dashboard_host": raw.get("dashboard", {}).get("host", "127.0.0.1"),
        "dashboard_port": raw.get("dashboard", {}).get("port", 5000),
        # Set https_enabled: true in config.yaml only when TLS is terminated
        # by a reverse proxy. Must be false when running over plain HTTP.
        "https_enabled": raw.get("dashboard", {}).get("https_enabled", False),
        # DNS enumeration options
        "dnsdumpster_api_key": os.environ.get(
            "PQC_DNSDUMPSTER_KEY",
            raw.get("dns_enumeration", {}).get("dnsdumpster_api_key", "")
        ),
        "dns_use_wordlist": raw.get("dns_enumeration", {}).get("use_wordlist", True),
        "dns_use_ct":       raw.get("dns_enumeration", {}).get("use_ct", True),
        # SSL Labs API v4 (requires one-time registration; email is the auth header)
        "ssllabs_email":   os.environ.get(
            "PQC_SSLLABS_EMAIL",
            raw.get("ssllabs", {}).get("email", "")
        ),
        "ssllabs_enabled": raw.get("ssllabs", {}).get("enabled", True),
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
@click.version_option(prog_name="PQC-Monitor",
                      version=open(os.path.join(ROOT, "VERSION")).read().strip()
                      if os.path.exists(os.path.join(ROOT, "VERSION")) else "unknown")
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
@click.option("--region", default="", help="Region label (e.g. Europe). Auto-inferred from ccTLD if omitted.")
@click.option("--country-code", "country_code", default="",
              help="ISO 3166-1 alpha-2 country code (e.g. ES). Auto-inferred from ccTLD if omitted.")
@click.option("--country", default="", help="Country display name (e.g. Spain). Auto-filled when country-code is inferred.")
@click.option("--shodan", is_flag=True, help="Use Shodan API if available")
@click.option("--dns-enumerate", "dns_enumerate", is_flag=True,
              help="Run DNS deep-dive enumeration before scanning (CT SANs, "
                   "wordlist, DNSDumpster if key configured)")
@click.option("--skip-scanned", "skip_scanned", is_flag=True,
              help="Skip domains that already have an assessment in the database. "
                   "Use --force to override.")
@click.option("--force", is_flag=True,
              help="Force re-scan of all domains even if already assessed "
                   "(overrides --skip-scanned).")
@click.pass_context
def scan(ctx, domains, domain, sector, region, country_code, country,
         shodan, dns_enumerate, skip_scanned, force):
    """Scan domains for cryptographic posture and PQC readiness.

    Examples:
      pqc_monitor.py scan --domains domains.txt
      pqc_monitor.py scan --domain example.com --domain bank.es
      pqc_monitor.py scan --domains list.txt --skip-scanned
      pqc_monitor.py scan --domains list.txt --skip-scanned --force
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

    # ── Skip already-scanned domains ──────────────────────────────────────────
    if skip_scanned and not force:
        _check_db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
        already_assessed = _check_db.get_assessed_domains(domain_list)
        if already_assessed:
            skipped = sorted(already_assessed)
            click.echo(
                f"⏭️  Skipping {len(skipped)} already-assessed domain(s) "
                f"(use --force to re-scan):"
            )
            for d in skipped:
                click.echo(f"     {d}")
            domain_list = [d for d in domain_list if d not in already_assessed]
            if not domain_list:
                click.echo("✅ All domains already assessed. Nothing to scan.")
                return
    elif force and skip_scanned:
        click.echo("⚠️  --force overrides --skip-scanned: scanning all domains.")

    click.echo(f"🔬 Scanning {len(domain_list)} domains...")
    orchestrator = ScanOrchestrator(cfg)

    # ── Optional DNS deep-dive before scanning ─────────────────────────────
    if dns_enumerate:
        from scanner.dns_enumerator import (
            enumerate_domain, is_dnsdumpster_quota_exhausted, DnsDumpsterQuotaError
        )
        from data.database import Database as _DB
        dd_key  = cfg.get("dnsdumpster_api_key", "")
        use_wl  = cfg.get("dns_use_wordlist", True)
        use_ct  = cfg.get("dns_use_ct", True)
        use_dd  = bool(dd_key)
        click.echo(f"🔍 DNS enumeration (CT={'on' if use_ct else 'off'}, "
                   f"wordlist={'on' if use_wl else 'off'}, "
                   f"dnsdumpster={'on' if use_dd else 'off — no key'})...")
        discovered: set = set(domain_list)
        dd_quota_warned = False
        for dom in list(domain_list):
            try:
                result = enumerate_domain(
                    dom,
                    use_wordlist=use_wl,
                    use_ct=use_ct,
                    use_dnsdumpster=use_dd,
                    dnsdumpster_api_key=dd_key,
                )
                # Surface quota exhaustion the first time it occurs
                if use_dd and is_dnsdumpster_quota_exhausted() and not dd_quota_warned:
                    click.echo(
                        "  ⚠️  DNSDumpster daily quota exceeded — "
                        "passive DNS fallback active for remaining domains",
                        err=True
                    )
                    dd_quota_warned = True
                new_hosts = [
                    c["host"] for c in result.tls_candidates
                    if c["host"] not in discovered
                ]
                if new_hosts:
                    click.echo(f"  {dom}: +{len(new_hosts)} new hosts "
                               f"({len(result.subdomains)} subdomains found)")
                    discovered.update(new_hosts)
                else:
                    click.echo(f"  {dom}: no new hosts beyond input list")
                if result.errors:
                    for err in result.errors:
                        click.echo(f"  ⚠️  {err}", err=True)
            except Exception as exc:
                click.echo(f"  ⚠️  DNS enumeration failed for {dom}: {exc}", err=True)
        domain_list = sorted(discovered)
        click.echo(f"  → {len(domain_list)} total hosts to scan after enumeration")

    # Geo inference: fill country/region from ccTLDs when not explicitly set
    from data.geo_inference import infer_and_fill
    geo = infer_and_fill(domain_list, country_code=country_code,
                         country=country, region=region)
    click.echo(geo.message)
    country_code = geo.country_code
    country      = geo.country
    region       = geo.region or region   # keep explicit region if inference skipped

    completed = 0
    def progress(done, total, current_domain):
        click.echo(f"  [{done}/{total}] {current_domain}")

    run_id = orchestrator.scan_domains(
        domain_list, sector=sector, region=region,
        country_code=country_code, country=country,
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
@click.option("--region", default="", help="Region label. Auto-inferred from ccTLD if omitted.")
@click.option("--country-code", "country_code", default="",
              help="ISO 3166-1 alpha-2 country code. Auto-inferred from ccTLD if omitted.")
@click.option("--country", default="", help="Country display name.")
@click.option("--name", default="", help="Schedule name")
@click.pass_context
def schedule(ctx, domains, interval, sector, region, country_code, country, name):
    """Add a periodic scan schedule."""
    cfg = ctx.obj["config"]
    with open(domains) as f:
        domain_list = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    days = int(interval.rstrip("d"))
    db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    list_id = db.save_domain_list(name or domains, domain_list)

    # Geo inference: fill country/region from ccTLDs when not explicitly set
    from data.geo_inference import infer_and_fill
    geo = infer_and_fill(domain_list, country_code=country_code,
                         country=country, region=region)
    click.echo(geo.message)
    country_code = geo.country_code
    country      = geo.country
    region       = geo.region or region

    from scanner.orchestrator import ScanOrchestrator
    from scheduler.scan_scheduler import ScanScheduler
    orch = ScanOrchestrator(cfg)
    sched = ScanScheduler(orch, db)
    sched_id = sched.add_schedule(
        name=name or f"auto-{sector}-{region or country_code}",
        domain_list_id=list_id,
        interval_days=days,
        sector=sector, region=region,
        country_code=country_code, country=country,
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
    click.echo(f"\n{'Run ID':<12} {'Started':<22} {'Sector':<15} {'Country':<6} {'Region':<12} {'Status':<12}")
    click.echo("-" * 85)
    for r in runs:
        cc = r.get("country_code", "") or ""
        click.echo(f"{r['run_id']:<12} {r['started_at'][:19]:<22} "
                   f"{r.get('sector',''):<15} {cc:<6} "
                   f"{r.get('region',''):<12} {r['status']:<12}")


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


@cli.command("scheduler-daemon")
@click.pass_context
def scheduler_daemon(ctx):
    """Run the periodic scan scheduler as a long-lived daemon process.

    This is the entry point used by the pqc-monitor-scheduler systemd service.
    The process blocks until interrupted (SIGTERM/SIGINT), running configured
    periodic scans in background threads.

    To add schedules use:
      pqc_monitor.py schedule --domains FILE --interval 90d
    """
    import time
    import signal
    cfg = ctx.obj["config"]
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))

    from scanner.orchestrator import ScanOrchestrator
    from scheduler.scan_scheduler import ScanScheduler

    orch  = ScanOrchestrator(cfg)
    sched = ScanScheduler(orch, db)

    if not sched.scheduler:
        click.echo("❌ APScheduler is not installed. Run: pip install apscheduler",
                   err=True)
        sys.exit(1)

    from version import VERSION
    click.echo(f"PQC-Monitor v{VERSION} scheduler starting")
    click.echo(f"Database: {cfg.get('db_path', 'data/pqc_monitor.db')}")

    schedules = sched.list_schedules()
    if schedules:
        click.echo(f"Loaded {len(schedules)} schedule(s):")
        for s in schedules:
            click.echo(f"  #{s['id']} {s['name']}: every {s['interval_days']}d")
    else:
        click.echo("No schedules configured yet. Add with: pqc_monitor.py schedule …")

    sched.start()
    click.echo("Scheduler running. Press Ctrl+C or send SIGTERM to stop.")

    # Block until signal
    stop_event = {"flag": False}
    def _handle_signal(sig, frame):
        click.echo(f"Signal {sig} received, shutting down…")
        stop_event["flag"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    try:
        while not stop_event["flag"]:
            time.sleep(5)
    finally:
        sched.stop()
        click.echo("Scheduler stopped.")



# ══════════════════════════════════════════════════════════════════════════════
# Community CLI commands
# ══════════════════════════════════════════════════════════════════════════════

@cli.group("community")
def community_grp():
    """Manage communities (groups of organisations)."""


@community_grp.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Optional description")
@click.pass_context
def community_create(ctx, name, description):
    """Create a new community."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    cid = db.create_community(name=name, description=description)
    click.echo(f"✅ Community #{cid} created: {name}")


@community_grp.command("list")
@click.pass_context
def community_list(ctx):
    """List all communities."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    communities = db.get_communities()
    if not communities:
        click.echo("No communities found.")
        return
    click.echo(f"\n{'ID':<6} {'Name':<30} {'Orgs':<6} Description")
    click.echo("-" * 70)
    for c in communities:
        click.echo(f"{c['id']:<6} {c['name']:<30} {c.get('org_count',0):<6} {c.get('description','')}")


@community_grp.command("add-org")
@click.argument("community_id", type=int)
@click.argument("org_id", type=int)
@click.pass_context
def community_add_org(ctx, community_id, org_id):
    """Add an organisation to a community."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    c   = db.get_community(community_id)
    if not c:
        click.echo(f"❌ Community #{community_id} not found.", err=True)
        raise SystemExit(1)
    org = db.get_organisation(org_id)
    if not org:
        click.echo(f"❌ Organisation #{org_id} not found.", err=True)
        raise SystemExit(1)
    current_orgs = [o["id"] for o in db.get_community_orgs(community_id)]
    if org_id not in current_orgs:
        db.set_community_orgs(community_id, current_orgs + [org_id])
    click.echo("Organisation #{} added to community: {}".format(org_id, c['name']))


@community_grp.command("remove-org")
@click.argument("community_id", type=int)
@click.argument("org_id", type=int)
@click.pass_context
def community_remove_org(ctx, community_id, org_id):
    """Remove an organisation from a community."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    c   = db.get_community(community_id)
    if not c:
        click.echo(f"❌ Community #{community_id} not found.", err=True)
        raise SystemExit(1)
    current_orgs = [o["id"] for o in db.get_community_orgs(community_id)]
    if org_id not in current_orgs:
        click.echo("Organisation #{} is not in community: {}".format(org_id, c['name']))
        return
    db.set_community_orgs(community_id, [oid for oid in current_orgs if oid != org_id])
    click.echo("Organisation #{} removed from community: {}".format(org_id, c['name']))


@community_grp.command("assign-user")
@click.argument("community_id", type=int)
@click.argument("username")
@click.pass_context
def community_assign_user(ctx, community_id, username):
    """Assign a user to a community (auto-promotes analyst → community_manager)."""
    cfg   = ctx.obj or {}
    db    = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    from auth.store import AuthStore
    store = AuthStore(cfg.get("db_path", "data/pqc_monitor.db"))
    c     = db.get_community(community_id)
    if not c:
        click.echo(f"❌ Community #{community_id} not found.", err=True)
        raise SystemExit(1)
    user = store.get_user_by_username(username)
    if not user:
        click.echo(f"❌ User '{username}' not found.", err=True)
        raise SystemExit(1)
    current = [comm["id"] for comm in db.get_user_communities(user.id)]
    if community_id not in current:
        current.append(community_id)
    store.set_user_communities(user.id, current)
    user_after = store.get_user_by_id(user.id)
    click.echo(f"✅ User '{username}' assigned to community (role: {user_after.role})")


@community_grp.command("report")
@click.argument("community_id", type=int)
@click.option("--format", "fmt", default="text",
              type=click.Choice(["text", "json", "csv"]),
              help="Output format (default: text)")
@click.option("--output", "-o", default=None, help="Write to file instead of stdout")
@click.pass_context
def community_report(ctx, community_id, fmt, output):
    """Generate a PQC-readiness report for a community."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    c   = db.get_community(community_id)
    if not c:
        click.echo(f"❌ Community #{community_id} not found.", err=True)
        raise SystemExit(1)
    from reports.community_report import build_report, export_text, export_csv
    import json as _json
    rows   = db.get_community_aggregate(community_id)
    report = build_report(c["name"], "Community", rows)
    if fmt == "json":
        out = _json.dumps(report, indent=2, default=str)
    elif fmt == "csv":
        out = export_csv(report)
    else:
        out = export_text(report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(out)
        click.echo(f"✅ Report saved to {output}")
    else:
        click.echo(out)


@community_grp.command("region-report")
@click.argument("region")
@click.option("--format", "fmt", default="text",
              type=click.Choice(["text", "json", "csv"]),
              help="Output format (default: text)")
@click.option("--output", "-o", default=None, help="Write to file instead of stdout")
@click.pass_context
def region_report_cmd(ctx, region, fmt, output):
    """Generate a PQC-readiness report for a region."""
    cfg = ctx.obj or {}
    db  = Database(cfg.get("db_path", "data/pqc_monitor.db"))
    from reports.community_report import build_report, export_text, export_csv
    import json as _json
    rows   = db.get_region_aggregate(region)
    if not rows:
        click.echo(f"⚠ No organisations found in region '{region}'.")
        return
    report = build_report(region, "Region", rows)
    if fmt == "json":
        out = _json.dumps(report, indent=2, default=str)
    elif fmt == "csv":
        out = export_csv(report)
    else:
        out = export_text(report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(out)
        click.echo(f"✅ Report saved to {output}")
    else:
        click.echo(out)

if __name__ == "__main__":
    cli()

