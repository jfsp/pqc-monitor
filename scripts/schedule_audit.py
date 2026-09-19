#!/usr/bin/env python3
"""
PQC-Monitor: Schedule audit (standalone CLI)

Reports which periodic scan schedules exist, which domains they cover, and
which assessed domains are in no enabled schedule — i.e. which domains are
never rescanned. Optionally creates/refreshes the auto-managed schedules.

    python3 scripts/schedule_audit.py
    python3 scripts/schedule_audit.py --db /var/lib/pqc-monitor/pqc_monitor.db
    python3 scripts/schedule_audit.py --create-monthly --dry-run
    python3 scripts/schedule_audit.py --create-monthly
    python3 scripts/schedule_audit.py --create-monthly --interval-days 7
    python3 scripts/schedule_audit.py --create-monthly --refresh-dns

--create-monthly (idempotent) creates or refreshes three auto-managed
schedules:

  All Domains — monthly (auto)            serviceable domains (TLS found)
  No-TLS Domains — monthly rescan (auto)  level="na" domains that still
                                          resolve (A/AAAA), so services that
                                          come online are detected
  SSL Labs sweep — weekly (auto)          throttled SSL Labs collection
                                          (--no-ssllabs to skip,
                                          --sweep-interval-days to change)

Both domain lists are reconciled again by the scheduler right before every
run. Domains with no DNS name or no A/AAAA record are recorded as
"unresolvable" (dns_status) and not scanned; they are re-checked in DNS each
cycle. --refresh-dns runs that DNS check now (a few minutes for thousands of
names) so the no-TLS list is accurate before the first run. --include-na
puts na domains back into the main schedule and skips the no-TLS schedule.

The audit itself is read-only; only --create-monthly / --refresh-dns write.
The scheduler re-reads schedules every minute — no restart needed.

Exit codes:
    0  every assessed domain is covered by an enabled schedule, no problems
    1  coverage gaps or schedule problems were found
    2  the database could not be opened

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from scheduler.schedule_audit import (audit_schedules,             # noqa: E402
                                      ensure_auto_schedules,
                                      DEFAULT_INTERVAL_DAYS)


def _load_db_path(args) -> str:
    """Resolve the DB path: --db > config.yaml (database.path) > env > default."""
    if args.db:
        return args.db

    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(ROOT, config_path)
    if os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
            raw = cfg.get("database", {}).get("path")
            if raw:
                return raw if os.path.isabs(raw) else os.path.join(ROOT, raw)
        except Exception:
            pass

    env = os.environ.get("PQC_DB_PATH")
    if env:
        return env
    return os.path.join(ROOT, "data", "pqc_monitor.db")


def _print_report(report, action, dns=None):
    print(f"PQC-Monitor schedule audit \u2014 {report['generated_at']}")
    print("")
    print("Schedules")
    if not report["schedules"]:
        print("  (none configured \u2014 nothing is rescanned automatically)")
    for sc in report["schedules"]:
        state = "enabled" if sc["enabled"] else "DISABLED"
        print(f"  [{sc['id']}] {sc['name']}  ({state}, {sc.get('kind', 'scan')}, "
              f"every {sc['interval_days']}d)")
        if sc.get("kind") == "ssllabs_sweep":
            print("      targets: serviceable HTTPS domains without a fresh report")
        else:
            print(f"      list: {sc['list_name'] or '<missing>'} "
                  f"({sc['domain_count']} domain(s))")
        print(f"      last: {sc['last_run'] or 'never'}   "
              f"next: {sc['next_run'] or 'unknown'}")
        for problem in sc["problems"]:
            print(f"      ! {problem}")

    cov = report["coverage"]
    pct = "n/a" if cov is None else f"{cov * 100:.0f}%"
    scope = "known" if report.get("include_na") else "serviceable"
    print("")
    print("Coverage")
    print(f"  {len(report['covered'])} of {report['known_domains']} {scope} "
          f"domain(s) covered ({pct})")
    if report.get("na_excluded"):
        print(f"  no-service (na): {report['na_excluded']} "
              f"(of {report['known_total']} known) — "
              f"{report.get('na_covered', 0)} in a rescan schedule, "
              f"{report.get('na_unresolvable', 0)} unresolvable (not scanned)")
    if report["uncovered"]:
        shown = ", ".join(report["uncovered"][:15])
        more = ("" if len(report["uncovered"]) <= 15
                else f" (+{len(report['uncovered']) - 15} more)")
        print(f"  never rescanned: {shown}{more}")
    if report["duplicated"]:
        print(f"  in multiple schedules: {len(report['duplicated'])} domain(s)")

    if report["problems"]:
        print("")
        print("Problems")
        for problem in report["problems"]:
            print(f"  ! {problem}")
    if report["recommendations"]:
        print("")
        print("Recommendations")
        for rec in report["recommendations"]:
            print(f"  -> {rec}")

    if dns:
        print("")
        print(f"DNS check of {dns['na']} no-TLS domain(s)")
        for k, v in sorted(dns["by_status"].items()):
            print(f"  {k:<12} {v}")

    if action:
        main = action["main"]
        print("")
        print("Would apply" if action["dry_run"] else "Applied")
        print(f"  main list       {main['list_action']} "
              f"({main['domains']} domain(s), +{len(main['added'])} "
              f"/ -{len(main['removed'])})")
        print(f"  main schedule   {main['schedule_action']}")
        for sid, old, new in action.get("repaired_next_run", []):
            print(f"  next_run fixed  #{sid}: {str(old)[:19]} -> {new[:19]} "
                  f"(was never advanced after its last run)")
        na = action.get("na") or {}
        if na:
            extra = (f" ({na['domains']} resolvable of {na['na_total']} no-TLS)"
                     if "domains" in na else "")
            print(f"  no-TLS list     {na['list_action']}{extra}")
            print(f"  no-TLS schedule {na['schedule_action']}")
        if action.get("ssllabs"):
            print(f"  SSL Labs sweep  {action['ssllabs']['schedule_action']} "
                  f"(every {action['ssllabs']['interval_days']}d)")
        for note in main.get("notes", []):
            print(f"  note            {note}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit and repair PQC-Monitor scan schedules.")
    ap.add_argument("--db", help="Path to pqc_monitor.db")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--json", action="store_true", help="Machine-readable")
    ap.add_argument("--create-monthly", action="store_true",
                    help="Create/refresh the auto-managed monthly schedule "
                         "covering every assessed domain")
    ap.add_argument("--interval-days", type=int,
                    default=DEFAULT_INTERVAL_DAYS,
                    help=f"Interval for --create-monthly "
                         f"(default {DEFAULT_INTERVAL_DAYS} = monthly)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what --create-monthly would change, then exit")
    ap.add_argument("--sweep-interval-days", type=int, default=7,
                    help="Interval of the SSL Labs sweep schedule (default 7)")
    ap.add_argument("--no-ssllabs", action="store_true",
                    help="Do not create/refresh the SSL Labs sweep schedule")
    ap.add_argument("--refresh-dns", action="store_true",
                    help="Re-check DNS for all no-TLS domains now and store "
                         "the result (resolvable / nxdomain / no_address)")
    ap.add_argument("--include-na", action="store_true",
                    help="Include no-service (level=na) domains in the target "
                         "set (default: exclude them)")
    args = ap.parse_args()

    db_path = _load_db_path(args)
    if not os.path.exists(db_path):
        print(f"database not found: {db_path}", file=sys.stderr)
        return 2
    try:
        from data.database import Database
        db = Database(db_path)
    except Exception as exc:
        print(f"cannot open database: {exc}", file=sys.stderr)
        return 2

    action = None
    dns = None
    if args.refresh_dns and not args.dry_run:
        from scheduler.schedule_audit import na_rescan_targets
        dns = na_rescan_targets(db, refresh_dns=True)
    if args.create_monthly:
        action = ensure_auto_schedules(
            db, args.interval_days,
            sweep_interval_days=args.sweep_interval_days,
            dry_run=args.dry_run, include_na=args.include_na,
            ssllabs=not args.no_ssllabs)

    report = audit_schedules(db, include_na=args.include_na)
    if args.json:
        payload = {"audit": report}
        if action:
            payload["action"] = action
        if dns:
            payload["dns"] = {"by_status": dns["by_status"], "na": dns["na"]}
        print(json.dumps(payload, indent=2))
    else:
        _print_report(report, action, dns)

    return 1 if (report["uncovered"] or report["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
