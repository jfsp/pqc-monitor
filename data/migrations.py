#!/usr/bin/env python3
"""
PQC-Monitor: Database Migrations
Applies incremental schema changes so existing databases are upgraded
without losing data.  Each migration is a (version, sql) pair; they
are applied in order and only once.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)

Usage (called automatically by Database.__init__):
    from data.migrations import apply_migrations
    apply_migrations(conn)
"""

import logging

logger = logging.getLogger(__name__)

# ── Migration registry ────────────────────────────────────────────────────────
# Each entry: (version_int, description, sql_string)
# SQL may contain multiple statements separated by semicolons.
# Add new migrations at the END of this list — never edit existing ones.

MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "Initial schema baseline",
        # The tables are created in Database._init_schema().
        # This migration just records the baseline so future migrations
        # know the starting version.
        "SELECT 1;",
    ),
    (
        2,
        "Add notes column to scan_runs",
        "ALTER TABLE scan_runs ADD COLUMN notes TEXT;",
    ),
    (
        3,
        "Add has_dane and has_dnssec columns to raw_scans",
        """ALTER TABLE raw_scans ADD COLUMN has_dane    INTEGER DEFAULT 0;
ALTER TABLE raw_scans ADD COLUMN has_dnssec  INTEGER DEFAULT 0;""",
    ),
    (
        4,
        "Add services_assessed column to assessments",
        "ALTER TABLE assessments ADD COLUMN services_assessed INTEGER DEFAULT 0;",
    ),
    (
        5,
        "Add key_types column to assessments",
        "ALTER TABLE assessments ADD COLUMN key_types TEXT;",
    ),
    (
        6,
        "Add sector and region to scheduled_scans",
        """ALTER TABLE scheduled_scans ADD COLUMN sector TEXT;
ALTER TABLE scheduled_scans ADD COLUMN region TEXT;""",
    ),
    (
        7,
        "Add Certificate Transparency tables",
        # These are full CREATE TABLE IF NOT EXISTS statements so they are safe
        # to run against any existing database version.
        """CREATE TABLE IF NOT EXISTS ct_queries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    queried_at   TEXT NOT NULL,
    total_certs  INTEGER DEFAULT 0,
    pqc_certs    INTEGER DEFAULT 0,
    hybrid_certs INTEGER DEFAULT 0,
    pqc_issuers  TEXT,
    pqc_algorithms TEXT,
    earliest_pqc_date TEXT,
    latest_pqc_date   TEXT,
    error        TEXT,
    raw_json     TEXT
);
CREATE TABLE IF NOT EXISTS ct_certificates (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id                  INTEGER,
    domain                   TEXT NOT NULL,
    queried_at               TEXT NOT NULL,
    sha256_fingerprint       TEXT,
    subject_cn               TEXT,
    issuer_cn                TEXT,
    issuer_org               TEXT,
    not_before               TEXT,
    not_after                TEXT,
    days_to_expiry           INTEGER,
    signature_algorithm_oid  TEXT,
    signature_algorithm_name TEXT,
    pubkey_algorithm_oid     TEXT,
    pubkey_algorithm_name    TEXT,
    pubkey_size_bits         INTEGER DEFAULT 0,
    is_pqc_signature         INTEGER DEFAULT 0,
    is_pqc_pubkey            INTEGER DEFAULT 0,
    is_hybrid                INTEGER DEFAULT 0,
    pqc_algorithms           TEXT,
    sans                     TEXT,
    first_seen               TEXT,
    UNIQUE(cert_id, domain) ON CONFLICT IGNORE
);
CREATE INDEX IF NOT EXISTS idx_ct_queries_domain ON ct_queries(domain);
CREATE INDEX IF NOT EXISTS idx_ct_certs_domain   ON ct_certificates(domain);
CREATE INDEX IF NOT EXISTS idx_ct_certs_pqc      ON ct_certificates(is_pqc_signature, is_pqc_pubkey)""",
    ),
    (
        8,
        "Add domain_extra table for chain analysis, cipher enum, CDN detection",
        """CREATE TABLE IF NOT EXISTS domain_extra (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    domain      TEXT NOT NULL,
    data_type   TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    json_data   TEXT NOT NULL,
    UNIQUE(run_id, domain, data_type) ON CONFLICT REPLACE
);
CREATE INDEX IF NOT EXISTS idx_domain_extra ON domain_extra(run_id, domain)""",
    ),
    (
        9,
        "Add roadmap storage tables",
        """CREATE TABLE IF NOT EXISTS roadmaps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT,
    domain       TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    current_score INTEGER DEFAULT 0,
    current_level TEXT,
    phase1_items  INTEGER DEFAULT 0,
    phase2_items  INTEGER DEFAULT 0,
    phase3_items  INTEGER DEFAULT 0,
    effort_min    INTEGER DEFAULT 0,
    effort_max    INTEGER DEFAULT 0,
    est_completion TEXT,
    score_p1      INTEGER DEFAULT 0,
    score_p2      INTEGER DEFAULT 0,
    score_p3      INTEGER DEFAULT 0,
    has_pqc       INTEGER DEFAULT 0,
    cdn_note      TEXT,
    items_json    TEXT,
    UNIQUE(run_id, domain) ON CONFLICT REPLACE
);
CREATE INDEX IF NOT EXISTS idx_roadmaps_domain ON roadmaps(domain);
CREATE INDEX IF NOT EXISTS idx_roadmaps_run    ON roadmaps(run_id)""",
    ),
]


# ── Engine ────────────────────────────────────────────────────────────────────

def _ensure_version_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT,
            applied_at  TEXT DEFAULT (datetime('now','utc'))
        )
    """)
    conn.commit()


def _current_version(conn) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version"
    ).fetchone()
    return row[0] if row else 0


def apply_migrations(conn) -> int:
    """
    Apply any pending migrations to *conn* (an open sqlite3 connection).
    Returns the new schema version number.
    """
    _ensure_version_table(conn)
    current = _current_version(conn)

    applied = 0
    for version, description, sql in MIGRATIONS:
        if version <= current:
            continue
        logger.info(f"DB migration v{version}: {description}")
        try:
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if not stmt or stmt.upper() == "SELECT 1":
                    continue
                try:
                    conn.execute(stmt)
                except Exception as col_err:
                    # SQLite <3.37 doesn't support IF NOT EXISTS on ALTER TABLE.
                    # If the column already exists, swallow the duplicate-column error.
                    msg = str(col_err).lower()
                    if "duplicate column" in msg or "already exists" in msg:
                        logger.debug(f"Migration v{version} column already present: {col_err}")
                    else:
                        raise
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, description) VALUES (?,?)",
                (version, description),
            )
            conn.commit()
            applied += 1
        except Exception as e:
            logger.error(f"Migration v{version} failed: {e}")
            conn.rollback()
            raise

    if applied:
        new_ver = _current_version(conn)
        logger.info(f"Applied {applied} migration(s). Schema now at v{new_ver}")
    return _current_version(conn)
