#!/usr/bin/env python3
"""
PQC-Monitor: Backfill services_assessed and key_types in assessments
=====================================================================
Repairs the historic fallout of a write-path bug: save_assessment() in
data/database.py omitted the `services_assessed` and `key_types` columns
from its INSERT, so every assessment row ever written carried the schema
defaults (0 / NULL) even though the assessor computed real values in
memory. Fixed on 2026-07-12; this script reconstructs the historic rows
from what the scanner recorded at the time.

Reconstruction logic
────────────────────
For each assessment row (run_id, domain):

  services_assessed ← COUNT(*) of raw_scans rows for the same
                      (run_id, domain) with success=1.
                      This mirrors the assessor's counting loop, which
                      increments once per successful service result.

  key_types         ← JSON array of DISTINCT non-empty raw_scans.key_type
                      values for the same (run_id, domain, success=1),
                      sorted for determinism. Only written when the stored
                      value is NULL, '' or '[]'.

Rows with level='na' legitimately have zero successful services and are
left untouched. Rows whose raw_scans rows are missing entirely (orphaned
run data) cannot be reconstructed and are reported.

The script only ever *raises* services_assessed from 0 and only fills
*empty* key_types — it never overwrites a non-default value, so it is
safe to re-run and safe to run after the write-path fix is deployed.

Usage
─────
  python3 scripts/backfill_services_assessed.py --dry-run   # preview
  python3 scripts/backfill_services_assessed.py             # apply
  python3 scripts/backfill_services_assessed.py --db /var/lib/pqc-monitor/pqc_monitor.db

Back up first:  cp /var/lib/pqc-monitor/pqc_monitor.db{,.bak}

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger("backfill_services_assessed")


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Backfill services_assessed/key_types from raw_scans.")
    parser.add_argument("--config", help="config.yaml (to locate db_path).")
    parser.add_argument("--db", help="Override the database path directly.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report changes without writing.")
    return parser.parse_args(argv)


def resolve_db_path(args) -> str:
    if args.db:
        return args.db
    try:
        from pqc_monitor import load_config
        cfg = load_config(args.config) or {}
        if cfg.get("db_path"):
            return cfg["db_path"]
    except Exception:
        pass
    return os.path.join(ROOT, "data", "pqc_monitor.db")


def main(argv=None) -> int:
    args = _parse_args(argv)
    db_path = resolve_db_path(args)
    if not os.path.exists(db_path):
        logger.error("Database not found: %s", db_path)
        return 2

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # Per-(run, domain) reconstruction source, one pass over raw_scans.
        counts: dict[tuple, int] = {}
        keytypes: dict[tuple, set] = {}
        for r in conn.execute(
                "SELECT run_id, domain, key_type FROM raw_scans WHERE success=1"):
            key = (r["run_id"], r["domain"])
            counts[key] = counts.get(key, 0) + 1
            if r["key_type"]:
                keytypes.setdefault(key, set()).add(r["key_type"])

        svc_updates: list[tuple] = []     # (count, id)
        kt_updates: list[tuple] = []      # (json, id)
        unreconstructable = 0

        for row in conn.execute(
                "SELECT id, run_id, domain, level, services_assessed, key_types "
                "FROM assessments"):
            key = (row["run_id"], row["domain"])
            cnt = counts.get(key, 0)

            if (row["services_assessed"] or 0) == 0 and row["level"] != "na":
                if cnt > 0:
                    svc_updates.append((cnt, row["id"]))
                else:
                    unreconstructable += 1

            stored_kt = row["key_types"]
            if (stored_kt in (None, "", "[]")) and keytypes.get(key):
                kt_updates.append(
                    (json.dumps(sorted(keytypes[key])), row["id"]))

        logger.info("services_assessed to backfill: %d row(s)", len(svc_updates))
        logger.info("key_types to backfill:         %d row(s)", len(kt_updates))
        if unreconstructable:
            logger.warning(
                "%d scored row(s) have no successful raw_scans for their "
                "(run_id, domain) — cannot reconstruct; the consistency audit "
                "will keep flagging them (orphaned or inconsistent run data)",
                unreconstructable)

        if args.dry_run:
            for cnt, rid in svc_updates[:10]:
                logger.info("  would set assessments[%d].services_assessed=%d", rid, cnt)
            for kt, rid in kt_updates[:10]:
                logger.info("  would set assessments[%d].key_types=%s", rid, kt)
            if len(svc_updates) > 10 or len(kt_updates) > 10:
                logger.info("  … (truncated preview)")
            logger.info("Dry run — nothing written.")
            return 0

        with conn:
            conn.executemany(
                "UPDATE assessments SET services_assessed=? WHERE id=?", svc_updates)
            conn.executemany(
                "UPDATE assessments SET key_types=? WHERE id=?", kt_updates)
        logger.info("Backfill applied.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
