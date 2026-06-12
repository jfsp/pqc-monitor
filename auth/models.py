#!/usr/bin/env python3
"""
PQC-Monitor: Auth Models
User, Role, and Session dataclasses.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Roles ─────────────────────────────────────────────────────────────────────

ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ALL_ROLES    = (ROLE_ADMIN, ROLE_ANALYST)

# ── Permissions per role ──────────────────────────────────────────────────────
# Each permission is checked in the decorator/helper; new perms can be added here.

PERMISSIONS = {
    ROLE_ADMIN: {
        "user.manage",          # create / edit / delete users
        "user.view",            # list all users
        "domain_list.manage",   # create / edit / delete domain lists
        "domain_list.view_all", # see every domain list (no scoping)
        "scan.run",             # trigger scans
        "scan.view_all",        # see all scan runs
        "schedule.manage",      # add / remove schedules
        "ct.run",               # trigger CT monitoring
        "roadmap.generate",     # generate roadmaps
        "report.export",        # download reports
        "admin.panel",          # access the /admin section
        "audit.view",           # read audit log
        "settings.manage",      # system configuration
        "org.manage",           # create / edit / delete organisations
        "org.view_all",         # see all organisations and their members
    },
    ROLE_ANALYST: {
        "domain_list.view_own", # see only assigned domain lists
        "scan.view_own",        # see scan results for assigned domains only
        "ct.view_own",          # CT data for assigned domains
        "roadmap.view_own",     # roadmaps for assigned domains
        "report.export",        # download reports (scoped to own domains)
        "org.view_own",         # see own org assignments only
    },
}


def has_permission(role: str, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, set())


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class User:
    id: int
    username: str
    email: str
    role: str                           # ROLE_ADMIN | ROLE_ANALYST
    full_name: str = ""
    is_active: bool = True
    created_at: str = ""
    last_login: str = ""
    domain_list_ids: list = field(default_factory=list)  # assigned list IDs
    org_ids: list         = field(default_factory=list)  # assigned org IDs

    # Never serialise password_hash outside auth layer
    password_hash: str = field(default="", repr=False)

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    def can(self, perm: str) -> bool:
        return has_permission(self.role, perm)

    def to_dict(self, include_sensitive: bool = False) -> dict:
        d = {
            "id":              self.id,
            "username":        self.username,
            "email":           self.email,
            "role":            self.role,
            "full_name":       self.full_name,
            "is_active":       self.is_active,
            "created_at":      self.created_at,
            "last_login":      self.last_login,
            "domain_list_ids": self.domain_list_ids,
            "org_ids":         self.org_ids,
        }
        if include_sensitive:
            d["password_hash"] = self.password_hash
        return d


@dataclass
class AuditEvent:
    id: int
    user_id: int
    username: str
    action: str          # login / logout / login_failed / view_domain / export / etc.
    resource: str        # domain name, list id, endpoint, etc.
    ip_address: str
    user_agent: str
    timestamp: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
