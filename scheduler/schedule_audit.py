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
list holding every assessed domain, driven by exactly ONE schedule. Re-running
is safe — it reconciles the list against the current set of known domains and
leaves an already-correct schedule untouched (so next_run is not pushed forward
on every cron tick).

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


# ─── Audit ────────────────────────────────────────────────────────────────

def audit_schedules(db) -> dict:
    """
    Read-only coverage report. Never writes.

    A "known" domain is any distinct domain in the assessments table
    (db.get_all_known_domains()). A domain is "covered" if it appears in the
    list of at least one ENABLED schedule that points at a valid, non-empty
    domain list.
    """
    known = set(db.get_all_known_domains())
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

    covered = known & covered_union
    uncovered = sorted(known - covered_union)
    duplicated = sorted(d for d, n in domain_schedule_count.items() if n > 1)
    coverage = (len(covered) / len(known)) if known else None

    problems = []
    if known and not any(s["enabled"] for s in schedules):
        problems.append("no enabled schedule exists \u2014 nothing is "
                        "rescanned automatically")
    elif known and not covered_union:
        problems.append("enabled schedule(s) exist but cover no known domain")

    recommendations = []
    if not schedules:
        recommendations.append("no schedules configured; run --create-monthly")
    if uncovered:
        recommendations.append(
            f"{len(uncovered)} known domain(s) are never rescanned; run "
            f"--create-monthly to cover them")
    if duplicated:
        recommendations.append(
            f"{len(duplicated)} domain(s) are in multiple schedules; consider "
            f"consolidating to avoid redundant scans")

    return {
        "generated_at":  _now_iso(),
        "known_domains": len(known),
        "schedules":     schedules,
        "coverage":      coverage,
        "covered":       sorted(covered),
        "uncovered":     uncovered,
        "duplicated":    duplicated,
        "problems":      problems,
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
                               dry_run: bool = False) -> dict:
    """
    Create or refresh the single auto-managed monthly schedule covering every
    known (assessed) domain. Idempotent.

    - The domain list is reconciled to the current known set (added/removed).
    - The schedule is created if absent; if present it is enabled and its
      interval corrected, but next_run is left alone when nothing else changed.
    - With dry_run=True nothing is written; the returned dict describes what
      would happen.
    """
    known = sorted(set(db.get_all_known_domains()))
    notes = []

    # ── Reconcile the domain list ──────────────────────────────────────────
    auto_list_id = _find_auto_list_id(db)
    if auto_list_id is None:
        list_action = "create"
        added, removed = list(known), []
    else:
        _, existing = _resolve_list(db, auto_list_id)
        cur, new = set(existing), set(known)
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

    if not known:
        notes.append("no assessed domains yet; auto list will be empty")

    # ── Dry run: report and stop ──────────────────────────────────────────
    if dry_run:
        if list_action != "unchanged" or schedule_action != "unchanged":
            notes.append(RESTART_HINT)
        return {
            "dry_run":         True,
            "list_action":     list_action,
            "schedule_action": schedule_action,
            "domains":         len(known),
            "added":           added,
            "removed":         removed,
            "notes":           notes,
        }

    # ── Apply: domain list ────────────────────────────────────────────────
    if list_action == "create":
        auto_list_id = db.save_domain_list(
            AUTO_LIST_NAME, known,
            query="auto-managed: every assessed domain")
    elif list_action == "update":
        db.update_domain_list(auto_list_id, domains=known)

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
        "domains":         len(known),
        "added":           added,
        "removed":         removed,
        "notes":           notes,
    }
