#!/bin/bash
# Wait for the PQC-Monitor SQLite database file to appear.
# Invoked by pqc-monitor-scheduler.service ExecStartPre.
# Usage: wait-for-db.sh [db_path] [timeout_seconds]
#
# SPDX-License-Identifier: GPL-3.0-or-later

DB="${1:-/opt/pqc-monitor/data/pqc_monitor.db}"
LIMIT="${2:-60}"
waited=0

while [ ! -f "$DB" ]; do
    if [ "$waited" -ge "$LIMIT" ]; then
        echo "Timed out waiting for $DB after ${LIMIT}s" >&2
        exit 1
    fi
    [ $((waited % 10)) -eq 0 ] && \
        echo "Waiting for database $DB (${waited}s elapsed)..." >&2
    sleep 2
    waited=$((waited + 2))
done

echo "Database found at $DB after ${waited}s" >&2
