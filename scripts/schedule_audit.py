#!/usr/bin/env python3
"""
PQC-Monitor: Schedule audit (standalone CLI)

Reports which periodic scan schedules exist, which domains they cover, and
which assessed domains are in no enabled schedule — i.e. which domains are
never rescanned. Optionally creates/refreshes a single auto-managed monthly
schedule covering every assessed domain.

    python3 scripts/schedule_audit.py
    python3 scripts/schedule_audit.py --db /var/lib/pqc-monitor/pqc_monitor.db
    python3 scripts/schedule_audit.py --create-monthly --dry-run
    python3 scripts/schedule_audit.py --create-monthly
    python3 scripts/schedule_audit.py --create-monthly --interval-days 7

--create-monthly maintains ONE auto-managed domain list holding every
SERVICEABLE assessed domain, driven by ONE monthly schedule. It is idempotent,
so it is safe to run from cron to keep coverage complete as new domains are
assessed. Domains whose latest level is "na" (no reachable TLS service, e.g.
DMARC/DKIM-only DNS) are excluded by default, since scanning them just burns
connect timeouts to reconfirm there is nothing to grade. Pass --include-na to
scan them anyway; a domain that later gains a service is picked up
automatically on the next run.

The audit itself is read-only; only --create-monthly writes (to domain_lists
and scheduled_scans). PQC-Monitor's scheduler loads schedules once at daemon
start, so after a write you must restart it:

    sudo systemctl restart pqc-monitor-scheduler

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
                                      create_monthly_all_domains,
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


def _print_report(report, action):
    print(f"PQC-Monitor schedule audit \u2014 {report['generated_at']}")
    print("")
    print("Schedules")
    if not report["schedules"]:
        print("  (none configured \u2014 nothing is rescanned automatically)")
    for sc in report["schedules"]:
        state = "enabled" if sc["enabled"] else "DISABLED"
        print(f"  [{sc['id']}] {sc['name']}  ({state}, every "
              f"{sc['interval_days']}d)")
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
        print(f"  no-service (na) excluded: {report['na_excluded']} "
              f"(of {report['known_total']} known)")
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

    if action:
        print("")
        print("Would apply" if action["dry_run"] else "Applied")
        print(f"  list      {action['list_action']} "
              f"({action['domains']} domain(s))")
        print(f"  schedule  {action['schedule_action']}")
        if action["added"]:
            print(f"  added     {len(action['added'])}")
        if action["removed"]:
            print(f"  removed   {len(action['removed'])}")
        for note in action["notes"]:
            print(f"  note      {note}")


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
    if args.create_monthly:
        action = create_monthly_all_domains(
            db, args.interval_days, dry_run=args.dry_run,
            include_na=args.include_na)

    report = audit_schedules(db, include_na=args.include_na)
    if args.json:
        payload = {"audit": report}
        if action:
            payload["action"] = action
        print(json.dumps(payload, indent=2))
    else:
        _print_report(report, action)

    return 1 if (report["uncovered"] or report["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
