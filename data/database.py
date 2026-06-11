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
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.db_path = db_path
        self._init_schema()
        # Apply any pending schema migrations
        try:
            from data.migrations import apply_migrations
            with self._connect() as conn:
                apply_migrations(conn)
        except Exception as e:
            logger.debug(f"Migrations skipped: {e}")
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
                   notes: str = "") -> str:
        import uuid
        run_id = str(uuid.uuid4())[:8]
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_runs (run_id, started_at, domain_list, sector, region, notes) "
                "VALUES (?,?,?,?,?,?)",
                (run_id, ts, json.dumps(domains), sector, region, notes)
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
                 cert_expiry_days, errors_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
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
                json.dumps(assessment.get("errors", []))
            ))

    def get_latest_assessments(self, run_id: str = None) -> list:
        """Get the most recent assessment per domain."""
        with self._connect() as conn:
            if run_id:
                rows = conn.execute(
                    "SELECT * FROM assessments WHERE run_id=? ORDER BY domain",
                    (run_id,)
                ).fetchall()
            else:
                rows = conn.execute("""
                    SELECT a.* FROM assessments a
                    INNER JOIN (
                        SELECT domain, MAX(assessed_at) as max_ts
                        FROM assessments GROUP BY domain
                    ) latest ON a.domain=latest.domain AND a.assessed_at=latest.max_ts
                    ORDER BY score ASC
                """).fetchall()
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

        scores = [r.get("score", 0) for r in rows]
        return {
            "total_domains": len(rows),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "critical_count": sum(1 for r in rows if r.get("level") == "critical"),
            "weak_count": sum(1 for r in rows if r.get("level") == "weak"),
            "moderate_count": sum(1 for r in rows if r.get("level") == "moderate"),
            "ready_count": sum(1 for r in rows if r.get("level") == "ready"),
            "pqc_count": sum(1 for r in rows if r.get("has_pqc")),
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
