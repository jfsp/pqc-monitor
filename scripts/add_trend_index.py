#!/usr/bin/env python3
"""
PQC-Monitor: create the covering index used by the Trends tab.

    idx_assessments_trend ON assessments(domain, assessed_at, score, level, has_pqc)

/api/trends only reads those five columns. With this index SQLite answers
from the index alone and never touches the table rows, which carry large
findings_json blobs. On a small VM this turns a disk-bound scan of the whole
table into a read of a few MB.

The application works without the index; it is just slower. Creating it
takes the database write lock for its duration (seconds to a minute on
~200k rows), so stop the services first:

    sudo systemctl stop pqc-monitor.target
    sudo -u pqcmonitor /opt/pqc-monitor/.venv/bin/python \\
        /opt/pqc-monitor/scripts/add_trend_index.py --db /var/lib/pqc-monitor/pqc_monitor.db
    sudo systemctl start pqc-monitor.target

Idempotent: re-running reports that the index already exists.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import sqlite3
import sys
import time

INDEX_NAME = "idx_assessments_trend"
INDEX_SQL = (f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON assessments"
             "(domain, assessed_at, score, level, has_pqc)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", required=True, help="path to pqc_monitor.db")
    ap.add_argument("--dry-run", action="store_true",
                    help="only report whether the index exists")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db, timeout=30)
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
        (INDEX_NAME,)).fetchone()
    rows = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
    print(f"assessments rows: {rows}")
    if exists:
        print(f"{INDEX_NAME} already exists - nothing to do")
        return 0
    if args.dry_run:
        print(f"{INDEX_NAME} missing (dry run, not created)")
        return 0
    t0 = time.time()
    conn.execute(INDEX_SQL)
    conn.commit()
    conn.execute("ANALYZE assessments")
    conn.commit()
    print(f"{INDEX_NAME} created in {time.time() - t0:.1f} s")
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT domain, assessed_at, score, level, has_pqc "
        "FROM assessments").fetchall()
    print("query plan:", "; ".join(r[-1] for r in plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
