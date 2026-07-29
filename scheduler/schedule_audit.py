#!/usr/bin/env python3
"""
PQC-Monitor: Schedule audit logic.

Pure(ish) functions that inspect and repair periodic scan coverage. Kept
separate from ScanScheduler so the audit can run in a throwaway process
(e.g. from cron) without pulling in APScheduler or registering live jobs.

Two entry points:

    audit_schedules(db)                       -> read-only coverage report
    create_monthly_all_domains(db, interval)  -> idempotent auto-schedule

The auto-schedule model mirrors SEE-Monitor: exactly ONE auto-managed domain
list, driven by exactly ONE schedule. Re-running is safe — it reconciles the
list against the current set of target domains and leaves an already-correct
schedule untouched (so next_run is not pushed forward on every cron tick).

no-service (level="na") domains
-------------------------------
Domains whose latest assessment is level="na" have no reachable TLS service
(e.g. DMARC/DKIM-only DNS records). A live scan of such a domain is the
WORST-case unit of work: ~13 TCP connect attempts (7 direct + 6 STARTTLS
ports) that each sit until timeout, plus DNS lookups — all to reconfirm that
there is nothing to grade. By default these are excluded from the auto
schedule and from coverage-gap detection. Pass include_na=True to keep them.
A domain that gains a service later is simply picked up again on the next
reconcile, because selection is by CURRENT latest level, not a static list.

IMPORTANT: PQC-Monitor's ScanScheduler loads schedules only once, at daemon
start (_load_saved_schedules). There is no live reload. After a write here the
caller must restart the scheduler service for the change to take effect:

    sudo systemctl restart pqc-monitor-scheduler

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
from datetime import datetime, timezone, timedelta

# Monthly by design: PQC posture changes on the timescale of TLS stack /
# CA rollouts, not days. Override via --interval-days on the CLI.
DEFAULT_INTERVAL_DAYS = 30

AUTO_LIST_NAME = "All Domains (auto)"
AUTO_SCHEDULE_NAME = "All Domains \u2014 monthly (auto)"

# Latest-assessment level that means "no reachable TLS service".
NA_LEVEL = "na"

RESTART_HINT = ("scheduler must be restarted to pick this up: "
                "sudo systemctl restart pqc-monitor-scheduler")

# Default per-scan config, matching what ScanScheduler._run_scheduled_scan reads.
_DEFAULT_CONFIG = {
    "use_shodan":   False,
    "sector":       "",
    "region":       "",
    "country_code": "",
    "country":      "",
}


def _now():
    return datetime.now(timezone.utc)


def _now_iso():
    return _now().isoformat()


def _parse_iso(value):
    """Best-effort ISO-8601 parse; returns an aware datetime or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _read_scheduled_scans(db):
    """Raw rows from scheduled_scans as dicts, id-ordered."""
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scheduled_scans ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def _resolve_list(db, list_id):
    """Return (name, domains) for a domain list id, or (None, [])."""
    if list_id is None:
        return None, []
    full = db.get_domain_list_full(list_id)
    if not full:
        return None, []
    return full.get("name"), list(full.get("domains") or [])


def _known_by_service(db):
    """
    Classify every known domain by its latest assessment level.

    Returns (serviceable, na) as two sets of domain strings, where a domain is
    "na" only if its most recent assessment level is exactly NA_LEVEL. A blank
    or unknown level counts as serviceable (bias toward scanning rather than
    silently dropping). Uses the same latest-per-domain pattern as
    Database.get_latest_assessments, scoped to domain+level to avoid the org
    joins (which can duplicate rows).
    """
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT a.domain AS domain, a.level AS level "
            "FROM assessments a "
            "INNER JOIN ("
            "    SELECT domain, MAX(assessed_at) AS max_ts "
            "    FROM assessments GROUP BY domain"
            ") latest ON a.domain = latest.domain "
            "        AND a.assessed_at = latest.max_ts"
        ).fetchall()

    serviceable, na = set(), set()
    for r in rows:
        domain = r["domain"]
        if (r["level"] or "").strip().lower() == NA_LEVEL:
            na.add(domain)
        else:
            serviceable.add(domain)
    # A tie at max_ts could place a domain in both; serviceable wins.
    na -= serviceable
    return serviceable, na


def _target_domains(db, include_na):
    """The set of domains the auto schedule should cover."""
    serviceable, na = _known_by_service(db)
    return (serviceable | na) if include_na else serviceable


# ─── Audit ────────────────────────────────────────────────────────────────

def audit_schedules(db, include_na: bool = False) -> dict:
    """
    Read-only coverage report. Never writes.

    Coverage is measured against TARGET domains: serviceable domains only by
    default, or all known domains when include_na=True. na (no-service)
    domains excluded from the target are reported separately for visibility
    and are never counted as gaps. A domain is "covered" if it appears in the
    list of at least one ENABLED schedule pointing at a valid, non-empty list.
    """
    serviceable, na = _known_by_service(db)
    target = (serviceable | na) if include_na else serviceable
    now = _now()

    schedules = []
    covered_union = set()
    domain_schedule_count = {}

    for row in _read_scheduled_scans(db):
        enabled = bool(row.get("enabled", 1))
        list_id = row.get("domain_list_id")
        list_name, domains = _resolve_list(db, list_id)
        domain_set = set(domains)

        problems = []
        if list_id is None or (list_name is None and not domains):
            problems.append("references a missing domain list")
        elif not domains:
            problems.append("domain list is empty")

        next_dt = _parse_iso(row.get("next_run"))
        if enabled and not row.get("next_run"):
            problems.append("no next_run set")
        elif (enabled and next_dt and next_dt < now
              and not row.get("last_run")):
            problems.append("next_run is in the past and has never run "
                            "(scheduler may not be running)")

        if enabled and domain_set:
            covered_union |= domain_set
            for d in domain_set:
                domain_schedule_count[d] = domain_schedule_count.get(d, 0) + 1

        schedules.append({
            "id":            row.get("id"),
            "name":          row.get("name"),
            "enabled":       enabled,
            "interval_days": row.get("interval_days"),
            "list_id":       list_id,
            "list_name":     list_name,
            "domain_count":  len(domains),
            "last_run":      row.get("last_run"),
            "next_run":      row.get("next_run"),
            "problems":      problems,
        })

    covered = target & covered_union
    uncovered = sorted(target - covered_union)
    # Duplicates limited to target domains so na noise doesn't inflate the count.
    duplicated = sorted(d for d, n in domain_schedule_count.items()
                        if n > 1 and d in target)
    coverage = (len(covered) / len(target)) if target else None

    problems = []
    if target and not any(s["enabled"] for s in schedules):
        problems.append("no enabled schedule exists \u2014 nothing is "
                        "rescanned automatically")
    elif target and not (target & covered_union):
        problems.append("enabled schedule(s) exist but cover no target domain")

    recommendations = []
    if not schedules:
        recommendations.append("no schedules configured; run --create-monthly")
    if uncovered:
        recommendations.append(
            f"{len(uncovered)} target domain(s) are never rescanned; run "
            f"--create-monthly to cover them")
    if duplicated:
        recommendations.append(
            f"{len(duplicated)} domain(s) are in multiple schedules; consider "
            f"consolidating to avoid redundant scans")

    return {
        "generated_at":   _now_iso(),
        "known_domains":  len(target),          # domains in scope for coverage
        "known_total":    len(serviceable | na),
        "na_excluded":    0 if include_na else len(na),
        "include_na":     include_na,
        "schedules":      schedules,
        "coverage":       coverage,
        "covered":        sorted(covered),
        "uncovered":      uncovered,
        "duplicated":     duplicated,
        "problems":       problems,
        "recommendations": recommendations,
    }


# ─── Repair: single auto-managed monthly schedule ───────────────────────────

def _find_auto_list_id(db):
    for row in db.get_domain_lists():
        if row.get("name") == AUTO_LIST_NAME:
            return row.get("id")
    return None


def _find_auto_schedule(db, auto_list_id):
    """
    Locate the auto schedule by name, or failing that by the list it drives.
    Returns the raw row dict, or None.
    """
    for row in _read_scheduled_scans(db):
        if row.get("name") == AUTO_SCHEDULE_NAME:
            return row
    if auto_list_id is not None:
        for row in _read_scheduled_scans(db):
            if row.get("domain_list_id") == auto_list_id:
                return row
    return None


def create_monthly_all_domains(db, interval_days: int = DEFAULT_INTERVAL_DAYS,
                               dry_run: bool = False,
                               include_na: bool = False) -> dict:
    """
    Create or refresh the single auto-managed monthly schedule covering every
    TARGET domain. Idempotent.

    Target = serviceable domains only (default), or all known domains when
    include_na=True. Because selection is by current latest level, na domains
    that were previously in the list are reconciled OUT, and any domain that
    gains a service is reconciled back IN, on the next run.

    - The domain list is reconciled to the current target set (added/removed).
    - The schedule is created if absent; if present it is enabled and its
      interval corrected, but next_run is left alone when nothing else changed.
    - With dry_run=True nothing is written; the returned dict describes what
      would happen.
    """
    serviceable, na = _known_by_service(db)
    target = sorted((serviceable | na) if include_na else serviceable)
    notes = []
    if not include_na and na:
        notes.append(f"{len(na)} no-service (na) domain(s) excluded")

    # ── Reconcile the domain list ──────────────────────────────────────────
    auto_list_id = _find_auto_list_id(db)
    if auto_list_id is None:
        list_action = "create"
        added, removed = list(target), []
    else:
        _, existing = _resolve_list(db, auto_list_id)
        cur, new = set(existing), set(target)
        added = sorted(new - cur)
        removed = sorted(cur - new)
        list_action = "update" if (added or removed) else "unchanged"

    # ── Decide schedule action (needs a list id, which may not exist in dry) ─
    sched_row = _find_auto_schedule(db, auto_list_id)
    if sched_row is None:
        schedule_action = "create"
    else:
        needs_change = (not bool(sched_row.get("enabled", 1))
                        or sched_row.get("interval_days") != interval_days
                        or sched_row.get("domain_list_id") != auto_list_id)
        schedule_action = "update" if needs_change else "unchanged"

    if not target:
        notes.append("no target domains; auto list will be empty")

    # ── Dry run: report and stop ──────────────────────────────────────────
    if dry_run:
        if list_action != "unchanged" or schedule_action != "unchanged":
            notes.append(RESTART_HINT)
        return {
            "dry_run":         True,
            "list_action":     list_action,
            "schedule_action": schedule_action,
            "domains":         len(target),
            "added":           added,
            "removed":         removed,
            "notes":           notes,
        }

    # ── Apply: domain list ────────────────────────────────────────────────
    if list_action == "create":
        auto_list_id = db.save_domain_list(
            AUTO_LIST_NAME, target,
            query="auto-managed: serviceable assessed domains")
    elif list_action == "update":
        db.update_domain_list(auto_list_id, domains=target)

    # ── Apply: schedule ───────────────────────────────────────────────────
    # Re-resolve in case the schedule was found only by (now-created) list id.
    sched_row = _find_auto_schedule(db, auto_list_id)

    if sched_row is None:
        next_run = (_now() + timedelta(days=interval_days)).isoformat()
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO scheduled_scans "
                "(name, domain_list_id, interval_days, next_run, last_run, "
                " enabled, config_json, sector, region) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (AUTO_SCHEDULE_NAME, auto_list_id, interval_days, next_run,
                 None, 1, json.dumps(_DEFAULT_CONFIG), "", ""),
            )
        schedule_action = "create"
    else:
        interval_changed = sched_row.get("interval_days") != interval_days
        needs_change = (not bool(sched_row.get("enabled", 1))
                        or interval_changed
                        or sched_row.get("domain_list_id") != auto_list_id)
        if needs_change:
            # Only reset next_run when the interval actually changed; otherwise
            # keep the existing cadence so re-runs don't drift the schedule.
            if interval_changed or not sched_row.get("next_run"):
                next_run = (_now() + timedelta(days=interval_days)).isoformat()
            else:
                next_run = sched_row.get("next_run")
            with db._connect() as conn:
                conn.execute(
                    "UPDATE scheduled_scans SET domain_list_id=?, "
                    "interval_days=?, enabled=1, next_run=? WHERE id=?",
                    (auto_list_id, interval_days, next_run, sched_row["id"]),
                )
            schedule_action = "update"
        else:
            schedule_action = "unchanged"

    if list_action != "unchanged" or schedule_action != "unchanged":
        notes.append(RESTART_HINT)

    return {
        "dry_run":         False,
        "list_action":     list_action,
        "schedule_action": schedule_action,
        "domains":         len(target),
        "added":           added,
        "removed":         removed,
        "notes":           notes,
    }
