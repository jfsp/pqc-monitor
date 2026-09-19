#!/usr/bin/env python3
"""
PQC-Monitor: Scan Scheduler

Runs the jobs defined in the `scheduled_scans` table.

Design (rewritten 2026-09)
──────────────────────────
The database is the single source of truth. A ticker thread re-reads
`scheduled_scans` every TICK_SECONDS and starts every enabled job whose
`next_run` has passed. There is no in-memory copy of the schedule, so:

- a restart of the daemon (deploy, reboot) does NOT reset the cadence —
  the previous APScheduler IntervalTrigger counted the interval from process
  start and ignored next_run, so restarts every < 30 days meant the monthly
  scan never ran;
- a job that became due while the daemon was down runs on the first tick;
- schedules added/edited from the UI or CLI are picked up within a minute,
  no restart needed.

When a run FINISHES (successfully or not) the row gets
last_run = now and next_run = run start + interval_days. A run killed by a
shutdown leaves next_run untouched, so it is retried on the next start
instead of being silently skipped for a month (the SSL Labs sweep resumes
where it stopped: domains with a fresh record are skipped).

Job kinds (config_json "kind"):
  scan          (default) scan the schedule's domain list. Auto-managed lists
                ("auto": serviceable | na_resolvable) are reconciled first.
  ssllabs_sweep throttled SSL Labs collection (scanner/ssllabs_sweep.py).

Scan jobs share one lock (never two scans at once); the SSL Labs sweep runs
independently of scans. Scheduled scan runs carry notes
"scheduled:#<id> <name>" so they are identifiable in Scan History.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logger = logging.getLogger(__name__)

TICK_SECONDS = 60
SCHEDULED_NOTES_PREFIX = "scheduled:"

# Kept for backwards compatibility with callers that checked it; the
# scheduler no longer depends on APScheduler.
HAS_APSCHEDULER = True


def _now():
    return datetime.now(timezone.utc)


def _parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ScanScheduler:
    """
    DB-driven job runner. Constructing it has no side effects (the web app
    instantiates it just to list/add schedules); call start() to run jobs.
    """

    def __init__(self, orchestrator, db, config: dict = None,
                 tick_seconds: int = TICK_SECONDS):
        self.orchestrator = orchestrator
        self.db = db
        self.cfg = config or {}
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._ticker = None
        self._running = {}                     # schedule_id -> Thread
        self._state_lock = threading.Lock()
        self._scan_lock = threading.Lock()     # one scan at a time

    # Backwards-compatible attribute: truthy when jobs can run.
    @property
    def scheduler(self):
        return self

    @property
    def running(self) -> bool:
        return self._ticker is not None and self._ticker.is_alive()

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self._stop.clear()
        n = self.db.mark_interrupted_runs(SCHEDULED_NOTES_PREFIX)
        if n:
            logger.warning("Marked %d scheduled run(s) left 'running' by a "
                           "previous process as 'interrupted'", n)
        self.repair_stale_next_run()
        self._ticker = threading.Thread(target=self._loop, name="sched-ticker",
                                        daemon=True)
        self._ticker.start()
        logger.info("Scheduler started (tick every %ds)", self.tick_seconds)

    def stop(self, timeout: float = 10.0):
        self._stop.set()
        if self._ticker:
            self._ticker.join(timeout=timeout)
        logger.info("Scheduler stopped")

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:           # a bad row must not kill the daemon
                logger.error("Scheduler tick failed: %s", e)
            self._stop.wait(self.tick_seconds)

    # ── Schedule maintenance ────────────────────────────────────────

    def repair_stale_next_run(self) -> int:
        """Fix next_run on rows left stale by the pre-2026-09 scheduler
        (see schedule_audit.repair_stale_next_run)."""
        from scheduler.schedule_audit import repair_stale_next_run
        fixed = repair_stale_next_run(self.db)
        for sid, old, new in fixed:
            logger.info("Schedule #%s: stale next_run %s → %s", sid, old, new)
        return len(fixed)

    def _update(self, schedule_id, **cols):
        sets = ", ".join(f"{k}=?" for k in cols)
        with self.db._connect() as conn:
            conn.execute(f"UPDATE scheduled_scans SET {sets} WHERE id=?",
                         (*cols.values(), schedule_id))

    def due_schedules(self, now=None) -> list:
        now = now or _now()
        due = []
        for row in self.list_schedules():
            if not row.get("enabled", 1):
                continue
            nxt = _parse_iso(row.get("next_run"))
            if nxt is None:
                # never scheduled: start the cadence now rather than firing
                new = now + timedelta(days=row.get("interval_days") or 30)
                self._update(row["id"], next_run=new.isoformat())
                continue
            if nxt <= now:
                due.append(row)
        return due

    def tick(self, now=None) -> list:
        """Start every due job that is not already running. Returns ids started."""
        started = []
        with self._state_lock:
            for sid, t in list(self._running.items()):
                if not t.is_alive():
                    del self._running[sid]
        for row in self.due_schedules(now):
            sid = row["id"]
            with self._state_lock:
                if sid in self._running:
                    continue
                t = threading.Thread(target=self._execute, args=(row,),
                                     name=f"sched-{sid}", daemon=True)
                self._running[sid] = t
            t.start()
            started.append(sid)
        return started

    def wait_idle(self, timeout: float = None):
        """Join all running jobs (tests / CLI run-now)."""
        with self._state_lock:
            threads = list(self._running.values())
        for t in threads:
            t.join(timeout)

    # ── Execution ───────────────────────────────────────────────────

    def _execute(self, row: dict):
        from scheduler.schedule_audit import schedule_kind, KIND_SSLLABS
        sid = row["id"]
        started = _now()
        try:
            if schedule_kind(row) == KIND_SSLLABS:
                self._run_ssllabs_sweep(row)
            else:
                # Wait for any other scan to finish (serialised), unless stopping.
                while not self._scan_lock.acquire(timeout=30):
                    if self._stop.is_set():
                        return
                try:
                    started = _now()
                    self._run_scan(row)
                finally:
                    self._scan_lock.release()
        except Exception as e:
            logger.error("Scheduled job #%s (%s) failed: %s", sid, row.get("name"), e)
        finally:
            if self._stop.is_set():
                # interrupted by shutdown: leave next_run so it re-runs on start
                logger.warning("Scheduled job #%s interrupted by shutdown; "
                               "it will run again on next start", sid)
            else:
                interval = row.get("interval_days") or 30
                self._update(sid,
                             last_run=_now().isoformat(),
                             next_run=(started + timedelta(days=interval)).isoformat())
            with self._state_lock:
                self._running.pop(sid, None)

    def _run_scan(self, row: dict):
        from scheduler.schedule_audit import row_config, reconcile_auto_list
        sid, name = row["id"], row.get("name", "")
        config = row_config(row)
        rec = reconcile_auto_list(self.db, row)
        if rec:
            logger.info("Schedule #%s: auto list reconciled — %d domain(s) "
                        "(+%d / -%d)%s", sid, len(rec["domains"]),
                        len(rec["added"]), len(rec["removed"]),
                        f", DNS {rec['dns']}" if rec.get("dns") else "")
            domains = rec["domains"]
        else:
            domains = self.db.get_domain_list_by_id(row.get("domain_list_id")) or []
        if not domains:
            logger.warning("Schedule #%s (%s): no domains to scan", sid, name)
            return
        logger.info("Running scheduled scan #%s (%s): %d domain(s)",
                    sid, name, len(domains))
        run_id = self.orchestrator.scan_domains(
            domains,
            sector=config.get("sector", ""),
            region=config.get("region", ""),
            country_code=config.get("country_code", ""),
            country=config.get("country", ""),
            use_shodan=config.get("use_shodan", False),
            notes=f"{SCHEDULED_NOTES_PREFIX}#{sid} {name}".strip(),
        )
        logger.info("Scheduled scan #%s complete: run_id=%s", sid, run_id)

    def _run_ssllabs_sweep(self, row: dict):
        from scanner.ssllabs_client import SSLLabsClient
        from scanner.ssllabs_sweep import (SSLLabsSweep, DEFAULT_CONCURRENCY,
                                           DEFAULT_MAX_AGE_DAYS)
        from scheduler.schedule_audit import row_config
        cfg = self.cfg
        if not cfg.get("ssllabs_enabled", True):
            logger.info("SSL Labs sweep #%s skipped: ssllabs.enabled is false", row["id"])
            return
        client = SSLLabsClient(cfg.get("ssllabs_email", ""))
        if not client.available and getattr(self.orchestrator, "ssllabs", None):
            client = self.orchestrator.ssllabs
        rc = row_config(row)
        interval = row.get("interval_days") or 7
        sweep = SSLLabsSweep(
            self.db, client,
            concurrency=rc.get("concurrency",
                               cfg.get("ssllabs_sweep_concurrency", DEFAULT_CONCURRENCY)),
            max_age_days=rc.get("max_age_days",
                                cfg.get("ssllabs_sweep_max_age_days",
                                        min(DEFAULT_MAX_AGE_DAYS, max(1, interval - 1)))),
            stop_event=self._stop,
        )
        logger.info("Running SSL Labs sweep #%s (%s)", row["id"], row.get("name"))
        result = sweep.run()
        logger.info("SSL Labs sweep #%s finished: %s", row["id"],
                    json.dumps(result, default=str))

    # ── CRUD (used by web app and CLI) ──────────────────────────────

    def add_schedule(self, name: str, domain_list_id: int,
                     interval_days: int = 90,
                     use_shodan: bool = False,
                     sector: str = "", region: str = "",
                     country_code: str = "", country: str = "") -> int:
        """Add a new periodic scan schedule. First run: now + interval."""
        next_run = (_now() + timedelta(days=interval_days)).isoformat()
        config = {
            "kind":         "scan",
            "use_shodan":   use_shodan,
            "sector":       sector,
            "region":       region,
            "country_code": country_code,
            "country":      country,
        }
        with self.db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans "
                "(name, domain_list_id, interval_days, next_run, config_json) "
                "VALUES (?,?,?,?,?)",
                (name, domain_list_id, interval_days, next_run, json.dumps(config))
            )
            schedule_id = cur.lastrowid
        logger.info(f"Schedule added: '{name}' every {interval_days} days "
                    f"(first run {next_run})")
        return schedule_id

    def list_schedules(self) -> list:
        with self.db._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY id").fetchall()
        return [dict(r) for r in rows]
