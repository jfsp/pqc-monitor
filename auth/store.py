#!/usr/bin/env python3
"""
PQC-Monitor: Auth Store
SQLite-backed user persistence, password hashing, and audit logging.

Designed to be the ONLY place that touches password_hash values.
All passwords are Werkzeug PBKDF2-SHA256 hashes (600 000 iterations).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from werkzeug.security import generate_password_hash, check_password_hash

from auth.models import User, AuditEvent, ROLE_ADMIN, ROLE_ANALYST, ALL_ROLES

logger = logging.getLogger(__name__)


class AuthStore:
    """
    Manages users, domain-list assignments, and the audit log.
    Uses the same SQLite database as the rest of PQC-Monitor so there
    is a single file to back up.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()
        self._ensure_default_admin()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'analyst',
                full_name     TEXT DEFAULT '',
                is_active     INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL,
                last_login    TEXT,
                failed_logins INTEGER DEFAULT 0,
                locked_until  TEXT
            );

            CREATE TABLE IF NOT EXISTS user_domain_lists (
                user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                domain_list_id INTEGER NOT NULL REFERENCES domain_lists(id) ON DELETE CASCADE,
                granted_at     TEXT NOT NULL,
                granted_by     INTEGER REFERENCES users(id),
                PRIMARY KEY (user_id, domain_list_id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                username    TEXT NOT NULL,
                action      TEXT NOT NULL,
                resource    TEXT DEFAULT '',
                ip_address  TEXT DEFAULT '',
                user_agent  TEXT DEFAULT '',
                timestamp   TEXT NOT NULL,
                detail      TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_audit_user
                ON audit_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_log(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_user_domain_lists_user
                ON user_domain_lists(user_id);
            """)

    def _ensure_default_admin(self):
        """Create the default admin account if no users exist."""
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            self.create_user(
                username="admin",
                email="admin@localhost",
                password="changeme123",
                role=ROLE_ADMIN,
                full_name="System Administrator",
            )
            logger.warning(
                "Default admin created: username=admin password=changeme123 — "
                "CHANGE THIS IMMEDIATELY in production."
            )

    # ── User CRUD ─────────────────────────────────────────────────────────────

    def create_user(self, username: str, email: str, password: str,
                    role: str = ROLE_ANALYST,
                    full_name: str = "",
                    created_by: int = None) -> User:
        if role not in ALL_ROLES:
            raise ValueError(f"Invalid role: {role!r}")
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters")

        ts = datetime.now(timezone.utc).isoformat()
        pw_hash = generate_password_hash(password)

        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, role, "
                "full_name, is_active, created_at) VALUES (?,?,?,?,?,1,?)",
                (username.strip(), email.strip().lower(),
                 pw_hash, role, full_name, ts)
            )
            user_id = cur.lastrowid

        logger.info(f"User created: {username} role={role} by={created_by}")
        return self.get_user_by_id(user_id)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id=?", (user_id,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? COLLATE NOCASE",
                (username.strip(),)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[User]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY username"
            ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def update_user(self, user_id: int, **fields) -> Optional[User]:
        """
        Update allowed user fields. Password is updated separately.
        Allowed: email, full_name, role, is_active.
        """
        allowed = {"email", "full_name", "role", "is_active"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_user_by_id(user_id)
        if "role" in updates and updates["role"] not in ALL_ROLES:
            raise ValueError(f"Invalid role: {updates['role']!r}")

        cols = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [user_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE users SET {cols} WHERE id=?", vals)
        return self.get_user_by_id(user_id)

    def set_password(self, user_id: int, new_password: str):
        if len(new_password) < 10:
            raise ValueError("Password must be at least 10 characters")
        pw_hash = generate_password_hash(new_password)
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL "
                "WHERE id=?", (pw_hash, user_id)
            )

    def delete_user(self, user_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))

    def _row_to_user(self, row) -> User:
        d = dict(row)
        # Load assigned domain list IDs
        with self._connect() as conn:
            dl_rows = conn.execute(
                "SELECT domain_list_id FROM user_domain_lists WHERE user_id=?",
                (d["id"],)
            ).fetchall()
        dl_ids = [r["domain_list_id"] for r in dl_rows]
        return User(
            id=d["id"],
            username=d["username"],
            email=d["email"],
            role=d["role"],
            full_name=d.get("full_name", ""),
            is_active=bool(d.get("is_active", True)),
            created_at=d.get("created_at", ""),
            last_login=d.get("last_login") or "",
            password_hash=d["password_hash"],
            domain_list_ids=dl_ids,
        )

    # ── Authentication ────────────────────────────────────────────────────────

    MAX_FAILED_ATTEMPTS = 10
    LOCKOUT_MINUTES     = 15

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Validate credentials. Returns User on success, None on failure.
        Tracks failed attempts and enforces account lockout.
        """
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not user.is_active:
            return None

        with self._connect() as conn:
            row = conn.execute(
                "SELECT failed_logins, locked_until FROM users WHERE id=?",
                (user.id,)
            ).fetchone()

        failed = row["failed_logins"] or 0
        locked_until = row["locked_until"]
        now = datetime.now(timezone.utc).isoformat()

        if locked_until and locked_until > now:
            logger.warning(f"Login blocked (locked): {username}")
            return None

        if not check_password_hash(user.password_hash, password):
            new_failed = failed + 1
            if new_failed >= self.MAX_FAILED_ATTEMPTS:
                from datetime import timedelta
                until = (datetime.now(timezone.utc) +
                         timedelta(minutes=self.LOCKOUT_MINUTES)).isoformat()
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                        (new_failed, until, user.id)
                    )
                logger.warning(f"Account locked after {new_failed} failures: {username}")
            else:
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE users SET failed_logins=? WHERE id=?",
                        (new_failed, user.id)
                    )
            return None

        # Success — reset failure counter and record last login
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_logins=0, locked_until=NULL, last_login=? WHERE id=?",
                (ts, user.id)
            )
        user.last_login = ts
        return user

    # ── Domain list assignment ────────────────────────────────────────────────

    def assign_domain_list(self, user_id: int, domain_list_id: int,
                            granted_by: int = None):
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO user_domain_lists "
                "(user_id, domain_list_id, granted_at, granted_by) VALUES (?,?,?,?)",
                (user_id, domain_list_id, ts, granted_by)
            )

    def revoke_domain_list(self, user_id: int, domain_list_id: int):
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM user_domain_lists WHERE user_id=? AND domain_list_id=?",
                (user_id, domain_list_id)
            )

    def set_domain_lists(self, user_id: int, domain_list_ids: list,
                          granted_by: int = None):
        """Replace a user's full domain-list assignment atomically."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM user_domain_lists WHERE user_id=?", (user_id,)
            )
            for dl_id in domain_list_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO user_domain_lists "
                    "(user_id, domain_list_id, granted_at, granted_by) VALUES (?,?,?,?)",
                    (user_id, dl_id, ts, granted_by)
                )

    def get_user_domains(self, user_id: int) -> list[str]:
        """
        Return the flat list of domain strings accessible to a user,
        derived from all their assigned domain lists.
        """
        import json
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT dl.domains_json
                FROM user_domain_lists udl
                JOIN domain_lists dl ON dl.id = udl.domain_list_id
                WHERE udl.user_id = ?
            """, (user_id,)).fetchall()
        domains: list[str] = []
        seen: set[str] = set()
        for row in rows:
            try:
                for d in json.loads(row["domains_json"]):
                    if d not in seen:
                        seen.add(d)
                        domains.append(d)
            except Exception:
                pass
        return domains

    # ── Audit log ─────────────────────────────────────────────────────────────

    def log(self, user_id: Optional[int], username: str, action: str,
            resource: str = "", ip_address: str = "",
            user_agent: str = "", detail: str = ""):
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(user_id, username, action, resource, ip_address, "
                "user_agent, timestamp, detail) VALUES (?,?,?,?,?,?,?,?)",
                (user_id, username, action, resource,
                 ip_address[:128], user_agent[:256], ts, detail[:512])
            )

    def get_audit_log(self, limit: int = 200,
                       user_id: int = None) -> list[AuditEvent]:
        with self._connect() as conn:
            if user_id:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE user_id=? "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (user_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
        return [AuditEvent(**dict(r)) for r in rows]
