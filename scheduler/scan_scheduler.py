#!/usr/bin/env python3
"""
PQC-Monitor: Scan Scheduler
APScheduler-based periodic scan management (default: every 90 days).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    logger.warning("APScheduler not installed. Scheduling unavailable.")


class ScanScheduler:
    """
    Manages periodic scan jobs. Scans are stored in the DB and run
    in the background using APScheduler.
    """

    def __init__(self, orchestrator, db):
        self.orchestrator = orchestrator
        self.db = db
        self.scheduler = None

        if HAS_APSCHEDULER:
            self.scheduler = BackgroundScheduler()
            self._load_saved_schedules()

    def start(self):
        if self.scheduler:
            self.scheduler.start()
            logger.info("Scheduler started")

    def stop(self):
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Scheduler stopped")

    def add_schedule(self, name: str, domain_list_id: int,
                     interval_days: int = 90,
                     use_shodan: bool = False,
                     sector: str = "", region: str = "",
                     country_code: str = "", country: str = "") -> int:
        """Add a new periodic scan schedule."""
        import json
        next_run = (datetime.now(timezone.utc) + timedelta(days=interval_days)).isoformat()

        config = {
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

        if self.scheduler:
            self._register_job(schedule_id, name, domain_list_id,
                               interval_days, config)

        logger.info(f"Schedule added: '{name}' every {interval_days} days")
        return schedule_id

    def _register_job(self, schedule_id: int, name: str,
                      domain_list_id: int, interval_days: int, config: dict):
        if not self.scheduler:
            return
        self.scheduler.add_job(
            func=self._run_scheduled_scan,
            trigger=IntervalTrigger(days=interval_days),
            id=f"scan_{schedule_id}",
            name=name,
            kwargs={
                "schedule_id": schedule_id,
                "domain_list_id": domain_list_id,
                "config": config
            },
            replace_existing=True,
            misfire_grace_time=3600
        )

    def _run_scheduled_scan(self, schedule_id: int,
                             domain_list_id: int, config: dict):
        """Execute a scheduled scan."""
        domains = self.db.get_domain_list_by_id(domain_list_id)
        if not domains:
            logger.warning(f"No domains for schedule {schedule_id}")
            return

        logger.info(f"Running scheduled scan (schedule_id={schedule_id})")
        try:
            run_id = self.orchestrator.scan_domains(
                domains,
                sector=config.get("sector", ""),
                region=config.get("region", ""),
                country_code=config.get("country_code", ""),
                country=config.get("country", ""),
                use_shodan=config.get("use_shodan", False)
            )
            ts = datetime.now(timezone.utc).isoformat()
            with self.db._connect() as conn:
                conn.execute(
                    "UPDATE scheduled_scans SET last_run=? WHERE id=?",
                    (ts, schedule_id)
                )
            logger.info(f"Scheduled scan complete: run_id={run_id}")
        except Exception as e:
            logger.error(f"Scheduled scan {schedule_id} failed: {e}")

    def _load_saved_schedules(self):
        """Re-register saved schedules on startup."""
        if not self.scheduler:
            return
        import json
        try:
            with self.db._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM scheduled_scans WHERE enabled=1"
                ).fetchall()
            for row in rows:
                config = json.loads(row["config_json"] or "{}")
                self._register_job(
                    row["id"], row["name"],
                    row["domain_list_id"], row["interval_days"], config
                )
        except Exception as e:
            logger.error(f"Failed to load saved schedules: {e}")

    def list_schedules(self) -> list:
        with self.db._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduled_scans").fetchall()
        return [dict(r) for r in rows]
