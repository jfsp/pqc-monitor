#!/usr/bin/env python3
"""
PQC-Monitor: Auth Middleware
Flask decorators for session management, role enforcement,
and domain-scope filtering.  Also defines the AuthProvider
interface so SAML can be plugged in later without changing
any route code.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import functools
import logging
from typing import Optional, Callable

from flask import (
    session, request, redirect, url_for,
    jsonify, g, current_app
)

from auth.models import User, ROLE_ADMIN, ROLE_COMMUNITY_MANAGER, ROLE_ANALYST

logger = logging.getLogger(__name__)

# Session key names
SESSION_USER_ID  = "pqc_uid"
SESSION_USERNAME = "pqc_uname"
SESSION_ROLE     = "pqc_role"

# How long a browser session is valid (seconds).
# Flask's permanent_session_lifetime is set on the app.
SESSION_LIFETIME_SECONDS = 8 * 3600   # 8 hours


# ── AuthProvider interface ────────────────────────────────────────────────────
# Implement this ABC to add SAML, OIDC, or LDAP without touching route code.

class AuthProvider:
    """
    Abstract authentication provider.
    LocalAuthProvider (below) uses the AuthStore.
    A future SAMLAuthProvider would parse the SAML assertion here.
    """

    def authenticate(self, username: str, password: str) -> Optional[User]:
        raise NotImplementedError

    def get_user(self, user_id: int) -> Optional[User]:
        raise NotImplementedError


class LocalAuthProvider(AuthProvider):
    """Username + password via AuthStore."""

    def __init__(self, store):
        self._store = store

    def authenticate(self, username: str, password: str) -> Optional[User]:
        return self._store.authenticate(username, password)

    def get_user(self, user_id: int) -> Optional[User]:
        return self._store.get_user_by_id(user_id)


# ── Session helpers ───────────────────────────────────────────────────────────

def login_user(user: User):
    """Write user identity into the signed Flask session cookie."""
    session.clear()
    session.permanent = True
    session[SESSION_USER_ID]  = user.id
    session[SESSION_USERNAME] = user.username
    session[SESSION_ROLE]     = user.role


def logout_user():
    session.clear()


def current_user() -> Optional[User]:
    """
    Return the authenticated User for the current request, or None.
    Caches result in Flask's `g` so the DB is only hit once per request.
    """
    if hasattr(g, "_pqc_user"):
        return g._pqc_user

    user_id = session.get(SESSION_USER_ID)
    if not user_id:
        g._pqc_user = None
        return None

    provider: AuthProvider = current_app.config.get("AUTH_PROVIDER")
    if not provider:
        g._pqc_user = None
        return None

    user = provider.get_user(user_id)
    if not user or not user.is_active:
        session.clear()
        g._pqc_user = None
        return None

    g._pqc_user = user
    return user


def _get_client_ip() -> str:
    """Best-effort client IP, respecting X-Forwarded-For from a trusted proxy."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _audit(action: str, resource: str = "", detail: str = ""):
    """Write an audit event using the AuthStore attached to the app."""
    try:
        store = current_app.config.get("AUTH_STORE")
        if not store:
            return
        user = current_user()
        store.log(
            user_id=user.id if user else None,
            username=user.username if user else "anonymous",
            action=action,
            resource=resource,
            ip_address=_get_client_ip(),
            user_agent=request.headers.get("User-Agent", "")[:256],
            detail=detail,
        )
    except Exception as e:
        logger.debug(f"Audit log error: {e}")


# ── Decorators ────────────────────────────────────────────────────────────────

def require_auth(f: Callable) -> Callable:
    """
    Require a valid, active session.
    Returns 401 JSON for API routes (/api/, /admin/api/, /app/api/),
    redirects to /login otherwise.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            path = request.path
            if "/api/" in path:
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("auth_bp.login", next=request.url))
        return f(*args, **kwargs)
    return wrapper


def require_role(*roles: str) -> Callable:
    """
    Require that the authenticated user has one of the given roles.
    Returns 403 JSON for API paths, redirects for HTML pages.
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            user = current_user()
            if user.role not in roles:
                if "/api/" in request.path:
                    return jsonify({"error": "forbidden"}), 403
                return redirect(url_for("app_bp.dashboard_home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_admin(f: Callable) -> Callable:
    return require_role(ROLE_ADMIN)(f)


def require_community_manager(f: Callable) -> Callable:
    """Allow admin and community_manager roles."""
    return require_role(ROLE_ADMIN, ROLE_COMMUNITY_MANAGER)(f)


def scope_domains(domains: list[str], user: User) -> list[str]:
    """
    Filter a domain list to those the user is allowed to see.
    Admins see everything; analysts see only their assigned domains.
    """
    if user.is_admin:
        return domains
    allowed = set(
        current_app.config["AUTH_STORE"].get_user_domains(user.id)
    )
    return [d for d in domains if d in allowed]


def filter_assessments(assessments: list, user: User) -> list:
    """Filter an assessment list to the user's visible domains."""
    if user.is_admin:
        return assessments
    allowed = set(
        current_app.config["AUTH_STORE"].get_user_domains(user.id)
    )
    return [a for a in assessments if a.get("domain", "") in allowed]
