#!/usr/bin/env python3
"""
PQC-Monitor: Fix no-TLS assessments retroactively
===================================================
Finds assessments that were stored as level='critical' / score=0 due to
having no TLS service, and sets them to level='na'.

A no-TLS row is identified by ALL of the following being true:
  - level  = 'critical'
  - score  = 0
  - tls_versions  is empty  ([])
  - cipher_suites is empty  ([])
  - has_pqc = 0
  - errors_json contains "No scan data available"

This is unambiguous: a genuinely critical domain has TLS data and findings.

Usage:
  python3 scripts/fix_notls_level.py
  python3 scripts/fix_notls_level.py --config /opt/pqc-monitor/config/config.yaml
  python3 scripts/fix_notls_level.py --db /opt/pqc-monitor/data/pqc_monitor.db
  python3 scripts/fix_notls_level.py --dry-run          # preview without writing

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import logging
import os
import sqlite3
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("fix_notls_level")

# ── Argument parsing ──────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(
    description="Retroactively set level='na' for no-TLS assessments stored as critical."
)
parser.add_argument(
    "--config",
    default=None,
    help="Path to config.yaml (default: config/config.yaml relative to project root)",
)
parser.add_argument(
    "--db",
    default=None,
    help="Direct path to SQLite DB, bypasses config lookup",
)
parser.add_argument(
    "--dry-run",
    action="store_true",
    help="Print what would be changed without writing to the database",
)
args = parser.parse_args()


# ── Resolve DB path ───────────────────────────────────────────────────────────

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

def resolve_db_path() -> str:
    if args.db:
        return args.db

    config_path = args.config or os.path.join(ROOT, "config", "config.yaml")
    try:
        import yaml  # type: ignore
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        raw = cfg.get("database", {}).get("path", "data/pqc_monitor.db")
        return raw if os.path.isabs(raw) else os.path.join(ROOT, raw)
    except FileNotFoundError:
        logger.warning("Config not found at %s, falling back to default path", config_path)
    except ImportError:
        logger.warning("PyYAML not available, falling back to default DB path")

    return os.path.join(ROOT, "data", "pqc_monitor.db")


db_path = resolve_db_path()
logger.info("Using database: %s", db_path)

if not os.path.exists(db_path):
    logger.error("Database file not found: %s", db_path)
    sys.exit(1)


# ── Identify and fix rows ─────────────────────────────────────────────────────

def is_empty_json_array(value: str) -> bool:
    """True if value is NULL, empty string, or a JSON empty array."""
    if not value:
        return True
    try:
        parsed = json.loads(value)
        return isinstance(parsed, list) and len(parsed) == 0
    except (json.JSONDecodeError, TypeError):
        return False


def errors_indicate_no_scan(errors_json: str) -> bool:
    """True if errors_json contains the canonical no-scan-data message."""
    if not errors_json:
        return False
    try:
        errors = json.loads(errors_json)
        return any("No scan data available" in str(e) for e in errors)
    except (json.JSONDecodeError, TypeError):
        return False


conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

try:
    # Fetch all candidates: critical, score=0, no PQC
    candidates = conn.execute("""
        SELECT id, run_id, domain, assessed_at,
               tls_versions, cipher_suites, has_pqc, errors_json
        FROM assessments
        WHERE level = 'critical'
          AND score = 0
          AND (has_pqc = 0 OR has_pqc IS NULL)
    """).fetchall()

    logger.info("Candidate rows (critical + score=0 + no PQC): %d", len(candidates))

    to_fix = []
    for row in candidates:
        if (
            is_empty_json_array(row["tls_versions"])
            and is_empty_json_array(row["cipher_suites"])
            and errors_indicate_no_scan(row["errors_json"])
        ):
            to_fix.append(row)

    if not to_fix:
        logger.info("No rows need updating — nothing to do.")
        conn.close()
        sys.exit(0)

    # Report what we found
    print(f"\n{'─'*70}")
    print(f"  Rows to update: {len(to_fix)}")
    print(f"{'─'*70}")
    print(f"  {'ID':>6}  {'Domain':<45}  {'Run ID':<20}  Assessed")
    print(f"  {'─'*6}  {'─'*45}  {'─'*20}  {'─'*19}")
    for row in to_fix:
        print(f"  {row['id']:>6}  {row['domain']:<45}  {row['run_id']:<20}  {row['assessed_at'][:19]}")
    print(f"{'─'*70}\n")

    if args.dry_run:
        logger.info("DRY RUN — no changes written.")
        conn.close()
        sys.exit(0)

    # Apply the fix
    ids = [row["id"] for row in to_fix]
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE assessments SET level = 'na' WHERE id IN ({placeholders})",
        ids,
    )
    conn.commit()
    logger.info("Updated %d row(s): level 'critical' → 'na'.", len(to_fix))

finally:
    conn.close()
