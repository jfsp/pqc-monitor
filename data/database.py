#!/usr/bin/env python3
"""
PQC-Monitor: Database Layer
SQLite storage for scan results, assessments, and trend tracking.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import sqlite3
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "pqc_monitor.db"
)


class Database:
    """
    SQLite-backed storage for PQC-Monitor.
    Stores raw scan data, assessments, domain lists and scan schedules.
    Designed for longitudinal tracking and re-assessment.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()
        # Apply any pending schema migrations
        try:
            from data.migrations import apply_migrations
            with self._connect() as conn:
                apply_migrations(conn)
        except Exception as e:
            logger.error(f"Migration failed — database may be on wrong schema version: {e}")
            raise
        logger.info(f"Database initialised: {db_path}")

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT UNIQUE NOT NULL,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                domain_list TEXT,       -- JSON array of domains
                sector      TEXT,
                region      TEXT,
                notes       TEXT,
                status      TEXT DEFAULT 'running'  -- running/completed/failed
            );

            CREATE TABLE IF NOT EXISTS raw_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT NOT NULL REFERENCES scan_runs(run_id),
                domain      TEXT NOT NULL,
                port        INTEGER,
                scanned_at  TEXT NOT NULL,
                success     INTEGER,
                tls_version TEXT,
                cipher_suite TEXT,
                cipher_bits INTEGER,
                key_exchange TEXT,
                key_type    TEXT,
                key_size_bits INTEGER,
                signature_algorithm TEXT,
                hash_algorithm TEXT,
                cert_expiry_days INTEGER,
                has_pqc     INTEGER DEFAULT 0,
                error       TEXT,
                raw_json    TEXT    -- full TLSProbeResult JSON
            );

            CREATE TABLE IF NOT EXISTS assessments (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id          TEXT NOT NULL REFERENCES scan_runs(run_id),
                domain          TEXT NOT NULL,
                assessed_at     TEXT NOT NULL,
                guidelines_used TEXT,   -- JSON array
                score           INTEGER,
                level           TEXT,
                findings_json   TEXT,   -- JSON array of Finding dicts
                tls_versions    TEXT,   -- JSON array
                cipher_suites   TEXT,   -- JSON array
                has_pqc         INTEGER DEFAULT 0,
                cert_expiry_days INTEGER,
                errors_json     TEXT
            );

            CREATE TABLE IF NOT EXISTS domain_lists (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                query       TEXT,
                created_at  TEXT NOT NULL,
                domains_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                domain_list_id  INTEGER REFERENCES domain_lists(id),
                interval_days   INTEGER DEFAULT 90,
                next_run        TEXT,
                last_run        TEXT,
                enabled         INTEGER DEFAULT 1,
                config_json     TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_raw_scans_domain ON raw_scans(domain);
            CREATE INDEX IF NOT EXISTS idx_raw_scans_run ON raw_scans(run_id);
            CREATE INDEX IF NOT EXISTS idx_assessments_domain ON assessments(domain);
            CREATE INDEX IF NOT EXISTS idx_assessments_run ON assessments(run_id);

            -- Certificate Transparency tables
            CREATE TABLE IF NOT EXISTS ct_queries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL,
                queried_at  TEXT NOT NULL,
                total_certs INTEGER DEFAULT 0,
                pqc_certs   INTEGER DEFAULT 0,
                hybrid_certs INTEGER DEFAULT 0,
                pqc_issuers TEXT,           -- JSON array
                pqc_algorithms TEXT,        -- JSON array
                earliest_pqc_date TEXT,
                latest_pqc_date   TEXT,
                error       TEXT,
                raw_json    TEXT            -- full CTSummary JSON
            );

            CREATE TABLE IF NOT EXISTS ct_certificates (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id                 INTEGER,              -- crt.sh ID
                domain                  TEXT NOT NULL,
                queried_at              TEXT NOT NULL,
                sha256_fingerprint      TEXT,
                subject_cn              TEXT,
                issuer_cn               TEXT,
                issuer_org              TEXT,
                not_before              TEXT,
                not_after               TEXT,
                days_to_expiry          INTEGER,
                signature_algorithm_oid TEXT,
                signature_algorithm_name TEXT,
                pubkey_algorithm_oid    TEXT,
                pubkey_algorithm_name   TEXT,
                pubkey_size_bits        INTEGER DEFAULT 0,
                is_pqc_signature        INTEGER DEFAULT 0,
                is_pqc_pubkey           INTEGER DEFAULT 0,
                is_hybrid               INTEGER DEFAULT 0,
                pqc_algorithms          TEXT,   -- JSON array
                sans                    TEXT,   -- JSON array
                first_seen              TEXT,
                UNIQUE(cert_id, domain) ON CONFLICT IGNORE
            );

            CREATE INDEX IF NOT EXISTS idx_ct_queries_domain
                ON ct_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_ct_certs_domain
                ON ct_certificates(domain);
            CREATE INDEX IF NOT EXISTS idx_ct_certs_pqc
                ON ct_certificates(is_pqc_signature, is_pqc_pubkey);

            -- Enrichment data from chain analysis, cipher enum, CDN detection
            CREATE TABLE IF NOT EXISTS domain_extra (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT NOT NULL REFERENCES scan_runs(run_id),
                domain      TEXT NOT NULL,
                data_type   TEXT NOT NULL,  -- 'chain' | 'cipher_enum' | 'cdn'
                recorded_at TEXT NOT NULL,
                json_data   TEXT NOT NULL,
                UNIQUE(run_id, domain, data_type) ON CONFLICT REPLACE
            );
            CREATE INDEX IF NOT EXISTS idx_domain_extra
                ON domain_extra(run_id, domain);
            """)

    # ─── Scan Runs ───────────────────────────────────────────────

    def create_run(self, domains: list, sector: str = "", region: str = "",
                   country_code: str = "", country: str = "",
                   notes: str = "") -> str:
        import uuid
        run_id = str(uuid.uuid4())[:8]
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_runs "
                "(run_id, started_at, domain_list, sector, region, country_code, country, notes) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (run_id, ts, json.dumps(domains), sector, region,
                 country_code, country, notes)
            )
        return run_id

    def finish_run(self, run_id: str, status: str = "completed"):
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET finished_at=?, status=? WHERE run_id=?",
                (ts, status, run_id)
            )

    def list_runs(self, limit: int = 20) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── Raw Scans ────────────────────────────────────────────────

    def save_scan_result(self, run_id: str, result: dict):
        cert = result.get("certificate") or {}
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO raw_scans
                (run_id, domain, port, scanned_at, success, tls_version, cipher_suite,
                 cipher_bits, key_exchange, key_type, key_size_bits, signature_algorithm,
                 hash_algorithm, cert_expiry_days, has_pqc, error, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                run_id,
                result.get("domain", ""),
                result.get("port", 0),
                result.get("timestamp", datetime.now(timezone.utc).isoformat()),
                1 if result.get("success") else 0,
                result.get("tls_version", ""),
                result.get("cipher_suite", ""),
                result.get("cipher_bits", 0),
                result.get("key_exchange", ""),
                cert.get("key_type", ""),
                cert.get("key_size_bits", 0),
                cert.get("signature_algorithm", ""),
                cert.get("hash_algorithm", ""),
                cert.get("days_to_expiry"),
                1 if (result.get("has_pqc_kem") or result.get("has_pqc_sig")
                      or result.get("has_pqc")) else 0,
                result.get("error", ""),
                json.dumps(result)
            ))

    def get_domain_scans(self, domain: str, run_id: str = None) -> list:
        with self._connect() as conn:
            if run_id:
                rows = conn.execute(
                    "SELECT raw_json FROM raw_scans WHERE domain=? AND run_id=?",
                    (domain, run_id)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT raw_json FROM raw_scans WHERE domain=? ORDER BY scanned_at DESC",
                    (domain,)
                ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows if r["raw_json"]]

    # ─── Assessments ─────────────────────────────────────────────

    def save_assessment(self, run_id: str, assessment: dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO assessments
                (run_id, domain, assessed_at, guidelines_used, score, level,
                 findings_json, tls_versions, cipher_suites, has_pqc,
                 cert_expiry_days, errors_json, service_type)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                run_id,
                assessment.get("domain", ""),
                assessment.get("assessment_timestamp", datetime.now(timezone.utc).isoformat()),
                json.dumps(assessment.get("guidelines_used", [])),
                assessment.get("score", 0),
                assessment.get("level", ""),
                json.dumps(assessment.get("findings", [])),
                json.dumps(assessment.get("tls_versions_found", [])),
                json.dumps(assessment.get("cipher_suites_found", [])),
                1 if assessment.get("has_pqc") else 0,
                assessment.get("certificate_expiry_days"),
                json.dumps(assessment.get("errors", [])),
                assessment.get("service_type"),
            ))

    def get_latest_assessments(self, run_id: str = None,
                                org_id: int = None) -> list:
        """Get the most recent assessment per domain, optionally filtered by org."""
        if org_id is not None:
            return self.get_assessments_by_org(org_id, run_id=run_id)
        with self._connect() as conn:
            if run_id:
                rows = conn.execute("""
                    SELECT a.*, o.id as org_id, o.name as org_name, o.region as org_region
                    FROM assessments a
                    LEFT JOIN domain_organisations do2 ON do2.domain = a.domain
                    LEFT JOIN organisations o ON o.id = do2.org_id
                    WHERE a.run_id=?
                    ORDER BY a.domain
                """, (run_id,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT a.*, o.id as org_id, o.name as org_name, o.region as org_region
                    FROM assessments a
                    INNER JOIN (
                        SELECT domain, MAX(assessed_at) as max_ts
                        FROM assessments GROUP BY domain
                    ) latest ON a.domain=latest.domain AND a.assessed_at=latest.max_ts
                    LEFT JOIN domain_organisations do2 ON do2.domain = a.domain
                    LEFT JOIN organisations o ON o.id = do2.org_id
                    ORDER BY a.score ASC
                """).fetchall()
        return [self._parse_assessment_row(r) for r in rows]

    def get_assessed_domains(self, domains: list) -> set:
        """
        Return the subset of *domains* that already have at least one
        assessment record in the database.  Used by the CLI --skip-scanned
        flag to skip re-scanning domains with existing results.
        """
        if not domains:
            return set()
        placeholders = ",".join("?" * len(domains))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT DISTINCT domain FROM assessments WHERE domain IN ({placeholders})",
                domains
            ).fetchall()
        return {r["domain"] for r in rows}

    def get_assessments_by_service_type(
        Both run_id and service_type are optional filters.
        service_type=None returns all; service_type='web_primary' returns only those rows.
        """
        clauses = []
        params: list = []
        if run_id:
            clauses.append("run_id=?")
            params.append(run_id)
        if service_type:
            clauses.append("service_type=?")
            params.append(service_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM assessments {where} ORDER BY domain",
                params,
            ).fetchall()
        return [self._parse_assessment_row(r) for r in rows]

    def get_domain_history(self, domain: str) -> list:
        """Get all assessment records for a domain (for trend charts)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain, assessed_at, score, level, has_pqc, "
                "tls_versions, cipher_suites FROM assessments "
                "WHERE domain=? ORDER BY assessed_at ASC",
                (domain,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_sector_trends(self) -> list:
        """Aggregate scores per scan run for trend charts."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT
                    sr.run_id,
                    sr.started_at,
                    sr.sector,
                    sr.region,
                    COUNT(a.domain) as domain_count,
                    AVG(a.score) as avg_score,
                    SUM(CASE WHEN a.level='critical' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN a.level='weak' THEN 1 ELSE 0 END) as weak_count,
                    SUM(CASE WHEN a.level='moderate' THEN 1 ELSE 0 END) as moderate_count,
                    SUM(CASE WHEN a.level='ready' THEN 1 ELSE 0 END) as ready_count,
                    SUM(a.has_pqc) as pqc_count
                FROM scan_runs sr
                JOIN assessments a ON sr.run_id = a.run_id
                WHERE sr.status='completed'
                GROUP BY sr.run_id
                ORDER BY sr.started_at ASC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_summary_stats(self) -> dict:
        """Summary statistics for the dashboard."""
        with self._connect() as conn:
            latest = conn.execute("""
                SELECT a.*, sr.sector, sr.region FROM assessments a
                INNER JOIN (
                    SELECT domain, MAX(assessed_at) as max_ts
                    FROM assessments GROUP BY domain
                ) latest ON a.domain=latest.domain AND a.assessed_at=latest.max_ts
                JOIN scan_runs sr ON a.run_id=sr.run_id
            """).fetchall()

        rows = [dict(r) for r in latest]
        if not rows:
            return {}

        # na-level rows (no TLS service) are excluded from scoring and level counts
        scored_rows = [r for r in rows if r.get("level") != "na"]
        scores = [r.get("score", 0) for r in scored_rows]
        return {
            "total_domains": len(rows),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "critical_count": sum(1 for r in scored_rows if r.get("level") == "critical"),
            "weak_count": sum(1 for r in scored_rows if r.get("level") == "weak"),
            "moderate_count": sum(1 for r in scored_rows if r.get("level") == "moderate"),
            "ready_count": sum(1 for r in scored_rows if r.get("level") == "ready"),
            "pqc_count": sum(1 for r in rows if r.get("has_pqc")),
            "na_count": sum(1 for r in rows if r.get("level") == "na"),
        }

    def _parse_assessment_row(self, row) -> dict:
        d = dict(row)
        for field in ("guidelines_used", "findings_json", "tls_versions",
                      "cipher_suites", "errors_json"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d

    # ─── Domain Lists ─────────────────────────────────────────────

    def save_domain_list(self, name: str, domains: list, query: str = "") -> int:
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO domain_lists (name, query, created_at, domains_json) "
                "VALUES (?,?,?,?)",
                (name, query, ts, json.dumps(domains))
            )
        return cur.lastrowid

    def get_domain_lists(self) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, query, created_at FROM domain_lists ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_domain_list_by_id(self, list_id: int) -> Optional[list]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT domains_json FROM domain_lists WHERE id=?", (list_id,)
            ).fetchone()
        if row:
            return json.loads(row["domains_json"])
        return None

    def get_domain_list_full(self, list_id: int) -> Optional[dict]:
        """Return full domain list record including the domains_json array."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_lists WHERE id=?", (list_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["domains"] = json.loads(d.get("domains_json") or "[]")
        except Exception:
            d["domains"] = []
        return d

    def update_domain_list(self, list_id: int, name: str = None,
                            domains: list = None, query: str = None) -> bool:
        """Update name, query, and/or domains of an existing domain list."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_lists WHERE id=?", (list_id,)
            ).fetchone()
            if not row:
                return False
            current = dict(row)
            new_name    = name    if name    is not None else current["name"]
            new_query   = query   if query   is not None else current.get("query", "")
            new_domains = json.dumps(domains) if domains is not None \
                          else current["domains_json"]
            conn.execute(
                "UPDATE domain_lists SET name=?, query=?, domains_json=?, updated_at=? "
                "WHERE id=?",
                (new_name, new_query, new_domains, ts, list_id)
            )
        return True

    def delete_domain_list(self, list_id: int) -> bool:
        """
        Delete a domain list and its user assignments.
        Returns False if the list doesn't exist.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM domain_lists WHERE id=?", (list_id,)
            ).fetchone()
            if not row:
                return False
            # Cascade: remove user assignments first (FK may not enforce)
            conn.execute(
                "DELETE FROM user_domain_lists WHERE domain_list_id=?", (list_id,)
            )
            conn.execute("DELETE FROM domain_lists WHERE id=?", (list_id,))
        return True

    def get_all_known_domains(self) -> list[str]:
        """
        Return every distinct domain that has ever been assessed, sorted.
        Used to populate the domain picker when editing a domain list.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT domain FROM assessments ORDER BY domain"
            ).fetchall()
        return [r["domain"] for r in rows]

    # ─── Organisations ────────────────────────────────────────────

    def create_organisation(self, name: str, sector: str = "",
                             region: str = "", description: str = "",
                             country_code: str = "", country: str = "",
                             created_by: int = None) -> int:
        """Create a new organisation. Returns new org id."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO organisations (name, sector, region, description, "
                "country_code, country, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
                (name.strip(), sector, region, description, country_code, country, ts, created_by)
            )
        return cur.lastrowid

    def get_organisations(self) -> list[dict]:
        """Return all organisations with their domain counts and domain lists."""
        with self._connect() as conn:
            org_rows = conn.execute("""
                SELECT o.*,
                       COUNT(DISTINCT do2.domain) as domain_count
                FROM organisations o
                LEFT JOIN domain_organisations do2 ON do2.org_id = o.id
                GROUP BY o.id
                ORDER BY o.name
            """).fetchall()
        orgs = []
        for row in org_rows:
            d = dict(row)
            d["domains"] = self.get_org_domains(d["id"])
            orgs.append(d)
        return orgs

    def get_organisation(self, org_id: int) -> Optional[dict]:
        """Return a single organisation record or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM organisations WHERE id=?", (org_id,)
            ).fetchone()
        return dict(row) if row else None

    def update_organisation(self, org_id: int, **fields) -> bool:
        """Update name, sector, region, country_code, country, or description. Returns False if not found."""
        allowed = {"name", "sector", "region", "description", "country_code", "country"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return True
        cols = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [org_id]
        with self._connect() as conn:
            cur = conn.execute(f"UPDATE organisations SET {cols} WHERE id=?", vals)
        return cur.rowcount > 0

    def delete_organisation(self, org_id: int) -> bool:
        """Delete org and cascade to domain/user assignments."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM organisations WHERE id=?", (org_id,)
            ).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM organisations WHERE id=?", (org_id,))
        return True

    # ─── Communities ──────────────────────────────────────────────

    def create_community(self, name: str, description: str = "",
                          created_by: int = None) -> int:
        """Create a new community. Returns new community id."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO communities (name, description, created_at, created_by) "
                "VALUES (?,?,?,?)",
                (name.strip(), description, ts, created_by)
            )
        return cur.lastrowid

    def get_communities(self) -> list[dict]:
        """Return all communities with org counts."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT c.*,
                       COUNT(DISTINCT co.org_id) as org_count
                FROM communities c
                LEFT JOIN community_organisations co ON co.community_id = c.id
                GROUP BY c.id
                ORDER BY c.name
            """).fetchall()
        return [dict(r) for r in rows]

    def get_community(self, community_id: int) -> Optional[dict]:
        """Return a single community or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM communities WHERE id=?", (community_id,)
            ).fetchone()
        return dict(row) if row else None

    def update_community(self, community_id: int, **fields) -> bool:
        """Update name or description. Returns False if not found."""
        allowed = {"name", "description"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return True
        cols = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [community_id]
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE communities SET {cols} WHERE id=?", vals
            )
        return cur.rowcount > 0

    def delete_community(self, community_id: int) -> bool:
        """Delete community and cascade to org/user assignments."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM communities WHERE id=?", (community_id,)
            ).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM communities WHERE id=?", (community_id,))
        return True

    def set_community_orgs(self, community_id: int, org_ids: list[int],
                            added_by: int = None):
        """Replace all org assignments for a community atomically."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM community_organisations WHERE community_id=?",
                (community_id,)
            )
            for oid in org_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO community_organisations "
                    "(community_id, org_id, added_at, added_by) VALUES (?,?,?,?)",
                    (community_id, oid, ts, added_by)
                )

    def get_community_orgs(self, community_id: int) -> list[dict]:
        """Return all organisations in a community with full org data."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT o.*,
                       COUNT(DISTINCT do2.domain) as domain_count
                FROM organisations o
                JOIN community_organisations co ON co.org_id = o.id
                LEFT JOIN domain_organisations do2 ON do2.org_id = o.id
                WHERE co.community_id = ?
                GROUP BY o.id
                ORDER BY o.name
            """, (community_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_community_domains(self, community_id: int) -> list[str]:
        """Return flat sorted list of all domains in a community (via orgs)."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT do2.domain
                FROM community_organisations co
                JOIN domain_organisations do2 ON do2.org_id = co.org_id
                WHERE co.community_id = ?
                ORDER BY do2.domain
            """, (community_id,)).fetchall()
        return [r["domain"] for r in rows]

    def get_user_communities(self, user_id: int) -> list[dict]:
        """Return all communities assigned to a user."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT c.*
                FROM communities c
                JOIN user_communities uc ON uc.community_id = c.id
                WHERE uc.user_id = ?
                ORDER BY c.name
            """, (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def set_user_communities(self, user_id: int, community_ids: list[int],
                              granted_by: int = None):
        """Replace all community assignments for a user atomically."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM user_communities WHERE user_id=?", (user_id,)
            )
            for cid in community_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO user_communities "
                    "(user_id, community_id, granted_at, granted_by) VALUES (?,?,?,?)",
                    (user_id, cid, ts, granted_by)
                )

    def get_community_aggregate(self, community_id: int) -> dict:
        """
        Return per-org PQC readiness summary for a community.
        Each entry: org metadata + domain_count, avg_score, level counts, pqc_count.
        """
        orgs = self.get_community_orgs(community_id)
        return self._build_group_aggregate(orgs)

    def get_country_aggregate(self, country_code: str,
                               allowed_org_ids: set = None) -> list:
        """
        Return per-org PQC readiness summary for all orgs with the given
        ISO 3166-1 alpha-2 country_code (case-insensitive).
        If allowed_org_ids is provided, only those orgs are included
        (used to scope results for community managers).
        """
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT o.*,
                       COUNT(DISTINCT do2.domain) as domain_count
                FROM organisations o
                LEFT JOIN domain_organisations do2 ON do2.org_id = o.id
                WHERE UPPER(o.country_code) = UPPER(?)
                GROUP BY o.id
                ORDER BY o.name
            """, (country_code,)).fetchall()
        orgs = [dict(r) for r in rows]
        if allowed_org_ids is not None:
            orgs = [o for o in orgs if o["id"] in allowed_org_ids]
        return self._build_group_aggregate(orgs)

    def get_countries(self) -> list[dict]:
        """Return distinct country_code + country pairs from organisations."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT country_code, country
                FROM organisations
                WHERE country_code IS NOT NULL AND TRIM(country_code) != ''
                ORDER BY country_code
            """).fetchall()
        return [dict(r) for r in rows]

    def get_region_aggregate(self, region: str,
                              allowed_org_ids: set = None) -> list:
        """
        Return per-org PQC readiness summary for all orgs in a region.
        If allowed_org_ids is provided, only those orgs are included
        (used to scope results for community managers).
        """
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT o.*,
                       COUNT(DISTINCT do2.domain) as domain_count
                FROM organisations o
                LEFT JOIN domain_organisations do2 ON do2.org_id = o.id
                WHERE LOWER(o.region) = LOWER(?)
                GROUP BY o.id
                ORDER BY o.name
            """, (region,)).fetchall()
        orgs = [dict(r) for r in rows]
        if allowed_org_ids is not None:
            orgs = [o for o in orgs if o["id"] in allowed_org_ids]
        return self._build_group_aggregate(orgs)

    def _build_group_aggregate(self, orgs: list[dict]) -> dict:
        """Build aggregate stats across a list of orgs."""
        result = []
        for org in orgs:
            domains = self.get_org_domains(org["id"])
            if not domains:
                result.append({**org, "avg_score": None, "critical": 0,
                                "weak": 0, "moderate": 0, "ready": 0,
                                "no_tls": 0, "pqc_count": 0})
                continue
            placeholders = ",".join("?" * len(domains))
            with self._connect() as conn:
                rows = conn.execute(f"""
                    SELECT a.score, a.level, a.has_pqc
                    FROM assessments a
                    INNER JOIN (
                        SELECT domain, MAX(assessed_at) as max_ts
                        FROM assessments GROUP BY domain
                    ) latest ON a.domain=latest.domain AND a.assessed_at=latest.max_ts
                    WHERE a.domain IN ({placeholders})
                """, domains).fetchall()
            assessed = [dict(r) for r in rows]
            scored   = [r for r in assessed if r.get("level") != "na"]
            avg_score = round(sum(r["score"] for r in scored) / len(scored), 1)                         if scored else None
            result.append({
                **org,
                "avg_score":  avg_score,
                "critical":   sum(1 for r in scored if r["level"] == "critical"),
                "weak":       sum(1 for r in scored if r["level"] == "weak"),
                "moderate":   sum(1 for r in scored if r["level"] == "moderate"),
                "ready":      sum(1 for r in scored if r["level"] == "ready"),
                "no_tls":     sum(1 for r in assessed if r.get("level") == "na"),
                "pqc_count":  sum(1 for r in assessed if r.get("has_pqc")),
            })
        return result

    # ─── Domain ↔ Org assignments ──────────────────────────────────

    def set_org_domains(self, org_id: int, domains: list[str],
                        assigned_by: int = None):
        """Replace all domain assignments for an org atomically."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM domain_organisations WHERE org_id=?", (org_id,)
            )
            for domain in domains:
                conn.execute(
                    "INSERT OR IGNORE INTO domain_organisations "
                    "(domain, org_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
                    (domain.lower().strip(), org_id, ts, assigned_by)
                )

    def get_org_domains(self, org_id: int) -> list[str]:
        """Return all domains assigned to an org."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain FROM domain_organisations WHERE org_id=? ORDER BY domain",
                (org_id,)
            ).fetchall()
        return [r["domain"] for r in rows]

    def get_domain_org(self, domain: str) -> Optional[dict]:
        """Return the org a domain belongs to (first if multiple), or None."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT o.* FROM organisations o
                JOIN domain_organisations do2 ON do2.org_id = o.id
                WHERE do2.domain = ?
                ORDER BY o.name LIMIT 1
            """, (domain,)).fetchone()
        return dict(row) if row else None

    def get_assessments_by_org(self, org_id: int,
                                run_id: str = None) -> list[dict]:
        """Return latest assessments for all domains in an org."""
        domains = self.get_org_domains(org_id)
        if not domains:
            return []
        placeholders = ",".join("?" * len(domains))
        with self._connect() as conn:
            if run_id:
                rows = conn.execute(
                    f"SELECT * FROM assessments WHERE run_id=? "
                    f"AND domain IN ({placeholders}) ORDER BY domain",
                    [run_id] + domains
                ).fetchall()
            else:
                rows = conn.execute(f"""
                    SELECT a.* FROM assessments a
                    INNER JOIN (
                        SELECT domain, MAX(assessed_at) as max_ts
                        FROM assessments GROUP BY domain
                    ) latest ON a.domain=latest.domain AND a.assessed_at=latest.max_ts
                    WHERE a.domain IN ({placeholders})
                    ORDER BY a.score ASC
                """, domains).fetchall()
        return [self._parse_assessment_row(r) for r in rows]

    # ─── User ↔ Org assignments ────────────────────────────────────

    def set_user_orgs(self, user_id: int, org_ids: list[int],
                      granted_by: int = None):
        """Replace all org assignments for a user atomically."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM user_organisations WHERE user_id=?", (user_id,)
            )
            for oid in org_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO user_organisations "
                    "(user_id, org_id, granted_at, granted_by) VALUES (?,?,?,?)",
                    (user_id, oid, ts, granted_by)
                )

    def get_user_org_ids(self, user_id: int) -> list[int]:
        """Return org IDs assigned to a user."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT org_id FROM user_organisations WHERE user_id=?",
                (user_id,)
            ).fetchall()
        return [r["org_id"] for r in rows]

    def get_org_domains_for_user(self, user_id: int) -> list[str]:
        """
        Return the flat list of domains the user can access via their org
        assignments. Used by the RBAC scoping layer.
        """
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT do2.domain
                FROM user_organisations uo
                JOIN domain_organisations do2 ON do2.org_id = uo.org_id
                WHERE uo.user_id = ?
                ORDER BY do2.domain
            """, (user_id,)).fetchall()
        return [r["domain"] for r in rows]

    # ─── Enrichment data (chain / cipher_enum / cdn) ──────────────

    def save_domain_extra(self, run_id: str, domain: str,
                           data_type: str, data: dict):
        """Store chain analysis, cipher enumeration, or CDN detection results."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO domain_extra "
                "(run_id, domain, data_type, recorded_at, json_data) "
                "VALUES (?,?,?,?,?)",
                (run_id, domain, data_type, ts, json.dumps(data, default=str))
            )

    def get_domain_extra(self, domain: str, run_id: str) -> dict:
        """
        Return enrichment data for a domain/run as a dict keyed by data_type.
        E.g. {"chain": {...}, "cipher_enum": {...}, "cdn": {...}}
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data_type, json_data FROM domain_extra "
                "WHERE run_id=? AND domain=?",
                (run_id, domain)
            ).fetchall()
        result = {}
        for row in rows:
            try:
                result[row["data_type"]] = json.loads(row["json_data"])
            except Exception:
                result[row["data_type"]] = {}
        return result

    # ─── Certificate Transparency ─────────────────────────────────

    def save_ct_summary(self, summary: dict):
        """Persist a CTSummary and its individual certificate records."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO ct_queries
                (domain, queried_at, total_certs, pqc_certs, hybrid_certs,
                 pqc_issuers, pqc_algorithms, earliest_pqc_date, latest_pqc_date,
                 error, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                summary.get("domain", ""),
                summary.get("queried_at", datetime.now(timezone.utc).isoformat()),
                summary.get("total_certs_found", 0),
                summary.get("pqc_certs_found", 0),
                summary.get("hybrid_certs_found", 0),
                json.dumps(summary.get("pqc_issuers", [])),
                json.dumps(summary.get("pqc_algorithms_seen", [])),
                summary.get("earliest_pqc_cert_date", ""),
                summary.get("latest_pqc_cert_date", ""),
                summary.get("error", ""),
                json.dumps(summary),
            ))

            for cert in summary.get("certificates", []):
                conn.execute("""
                    INSERT OR IGNORE INTO ct_certificates
                    (cert_id, domain, queried_at, sha256_fingerprint,
                     subject_cn, issuer_cn, issuer_org,
                     not_before, not_after, days_to_expiry,
                     signature_algorithm_oid, signature_algorithm_name,
                     pubkey_algorithm_oid, pubkey_algorithm_name, pubkey_size_bits,
                     is_pqc_signature, is_pqc_pubkey, is_hybrid,
                     pqc_algorithms, sans, first_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    cert.get("cert_id"),
                    cert.get("domain", ""),
                    cert.get("queried_at", ""),
                    cert.get("sha256_fingerprint", ""),
                    cert.get("subject_cn", ""),
                    cert.get("issuer_cn", ""),
                    cert.get("issuer_org", ""),
                    cert.get("not_before", ""),
                    cert.get("not_after", ""),
                    cert.get("days_to_expiry"),
                    cert.get("signature_algorithm_oid", ""),
                    cert.get("signature_algorithm_name", ""),
                    cert.get("pubkey_algorithm_oid", ""),
                    cert.get("pubkey_algorithm_name", ""),
                    cert.get("pubkey_size_bits", 0),
                    1 if cert.get("is_pqc_signature") else 0,
                    1 if cert.get("is_pqc_pubkey") else 0,
                    1 if cert.get("is_hybrid") else 0,
                    json.dumps(cert.get("pqc_algorithms", [])),
                    json.dumps(cert.get("sans", [])),
                    cert.get("first_seen", ""),
                ))

    def get_ct_summaries(self, domain: str = None, limit: int = 50) -> list:
        """Return CT query summaries, optionally filtered by domain."""
        with self._connect() as conn:
            if domain:
                rows = conn.execute(
                    "SELECT * FROM ct_queries WHERE domain=? ORDER BY queried_at DESC LIMIT ?",
                    (domain, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ct_queries ORDER BY queried_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            for f in ("pqc_issuers", "pqc_algorithms"):
                if isinstance(d.get(f), str):
                    try:
                        d[f] = json.loads(d[f])
                    except Exception:
                        d[f] = []
            results.append(d)
        return results

    def get_ct_pqc_certificates(self, domain: str = None, limit: int = 200) -> list:
        """Return all PQC or hybrid certificates, optionally for one domain."""
        with self._connect() as conn:
            if domain:
                rows = conn.execute("""
                    SELECT * FROM ct_certificates
                    WHERE domain=? AND (is_pqc_signature=1 OR is_pqc_pubkey=1)
                    ORDER BY not_before DESC LIMIT ?
                """, (domain, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM ct_certificates
                    WHERE is_pqc_signature=1 OR is_pqc_pubkey=1
                    ORDER BY not_before DESC LIMIT ?
                """, (limit,)).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            for f in ("pqc_algorithms", "sans"):
                if isinstance(d.get(f), str):
                    try:
                        d[f] = json.loads(d[f])
                    except Exception:
                        d[f] = []
            results.append(d)
        return results

    def get_ct_timeline(self) -> list:
        """
        Aggregate PQC certificate counts by month for the timeline chart.
        Returns rows of (month, pqc_count, hybrid_count, classical_count).
        """
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT
                    strftime('%Y-%m', queried_at) as month,
                    SUM(pqc_certs)    as pqc_total,
                    SUM(hybrid_certs) as hybrid_total,
                    SUM(total_certs)  as all_total
                FROM ct_queries
                GROUP BY month
                ORDER BY month ASC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_ct_stats(self) -> dict:
        """High-level CT statistics for dashboard summary cards."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(DISTINCT domain)                          as domains_monitored,
                    SUM(total_certs)                                as total_certs,
                    SUM(pqc_certs)                                  as total_pqc,
                    SUM(hybrid_certs)                               as total_hybrid,
                    COUNT(DISTINCT CASE WHEN pqc_certs > 0
                          THEN domain END)                          as domains_with_pqc
                FROM ct_queries
            """).fetchone()
        return dict(row) if row else {}

    # ─── Roadmap storage ──────────────────────────────────────────

    def save_roadmap(self, run_id: str, roadmap: dict):
        """Persist a DomainRoadmap dict to the roadmaps table."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO roadmaps
                (run_id, domain, generated_at, current_score, current_level,
                 phase1_items, phase2_items, phase3_items,
                 effort_min, effort_max, est_completion,
                 score_p1, score_p2, score_p3,
                 has_pqc, cdn_note, items_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                run_id,
                roadmap.get("domain", ""),
                roadmap.get("generated_at", ts),
                roadmap.get("current_score", 0),
                roadmap.get("current_level", ""),
                roadmap.get("phase1_items", 0),
                roadmap.get("phase2_items", 0),
                roadmap.get("phase3_items", 0),
                roadmap.get("total_effort_days_min", 0),
                roadmap.get("total_effort_days_max", 0),
                roadmap.get("estimated_completion", ""),
                roadmap.get("score_after_phase1", 0),
                roadmap.get("score_after_phase2", 0),
                roadmap.get("score_after_phase3", 0),
                1 if roadmap.get("has_pqc") else 0,
                roadmap.get("cdn_note", ""),
                json.dumps(roadmap.get("items", [])),
            ))

    def get_roadmaps(self, run_id: str = None, domain: str = None) -> list:
        """Retrieve stored roadmaps, optionally filtered."""
        with self._connect() as conn:
            if domain:
                rows = conn.execute(
                    "SELECT * FROM roadmaps WHERE domain=? ORDER BY generated_at DESC",
                    (domain,)
                ).fetchall()
            elif run_id:
                rows = conn.execute(
                    "SELECT * FROM roadmaps WHERE run_id=? ORDER BY current_score ASC",
                    (run_id,)
                ).fetchall()
            else:
                # Latest roadmap per domain
                rows = conn.execute("""
                    SELECT r.* FROM roadmaps r
                    INNER JOIN (
                        SELECT domain, MAX(generated_at) as max_ts
                        FROM roadmaps GROUP BY domain
                    ) latest ON r.domain=latest.domain AND r.generated_at=latest.max_ts
                    ORDER BY r.current_score ASC
                """).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            if isinstance(d.get("items_json"), str):
                try:
                    d["items_json"] = json.loads(d["items_json"])
                except Exception:
                    d["items_json"] = []
            results.append(d)
        return results

    def get_roadmap_stats(self) -> dict:
        """Summary statistics for roadmap dashboard card."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(DISTINCT domain)                              as domains,
                    SUM(phase1_items)                                   as total_p1_items,
                    SUM(phase2_items)                                   as total_p2_items,
                    SUM(phase3_items)                                   as total_p3_items,
                    SUM(effort_min)                                     as total_effort_min,
                    SUM(effort_max)                                     as total_effort_max,
                    COUNT(DISTINCT CASE WHEN phase1_items>0 THEN domain END) as domains_need_p1,
                    COUNT(DISTINCT CASE WHEN has_pqc=1 THEN domain END) as domains_pqc_ready
                FROM (
                    SELECT r.* FROM roadmaps r
                    INNER JOIN (
                        SELECT domain, MAX(generated_at) as max_ts
                        FROM roadmaps GROUP BY domain
                    ) latest ON r.domain=latest.domain AND r.generated_at=latest.max_ts
                )
            """).fetchone()
        return dict(row) if row else {}
