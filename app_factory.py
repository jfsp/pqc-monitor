#!/usr/bin/env python3
"""
PQC-Monitor: Application Factory (with RBAC)
Creates the Flask application with:
  - Auth blueprint  (/login, /logout, /change-password)
  - Admin blueprint (/admin/*)
  - App blueprint   (/app/* — analyst dashboard)
  - Redirect /  →  /login
  - Security headers middleware
  - Session configuration for internet-facing deployment

The original dashboard/app.py create_app() is no longer the entry point.
Use this factory instead.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import os
import sys
from datetime import timedelta

from flask import Flask, redirect, url_for, after_this_request, request

sys.path.insert(0, os.path.dirname(__file__))

from auth.store    import AuthStore
from auth.middleware import LocalAuthProvider, SESSION_LIFETIME_SECONDS
from auth.auth_routes import auth_bp
from admin.routes  import admin_bp
from app_routes    import app_bp

from data.database import Database
from scanner.orchestrator import ScanOrchestrator
from domain_discovery.domain_finder import DomainDiscovery

# Pull the dashboard HTML body from the old app so we reuse it
from dashboard.app import DASHBOARD_HTML

logger = logging.getLogger(__name__)


def create_app(config: dict = None) -> Flask:
    cfg = config or {}

    # ── Flask setup ───────────────────────────────────────────────────────────
    app = Flask(__name__)

    secret = cfg.get("secret_key", os.environ.get("PQC_SECRET_KEY", ""))
    if not secret or secret == "pqcmonitor-dev-key":
        import secrets as _sec
        secret = _sec.token_hex(32)
        logger.warning(
            "No SECRET_KEY configured — generated a random one. "
            "Set PQC_SECRET_KEY environment variable for persistence."
        )
    app.secret_key = secret

    # Session security — internet-facing
    app.config.update(
        SESSION_COOKIE_SECURE   = cfg.get("cookie_secure", True),
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",
        PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_LIFETIME_SECONDS),
    )

    # ── Database ──────────────────────────────────────────────────────────────
    db_path = cfg.get("db_path", "data/pqc_monitor.db")
    db      = Database(db_path)
    app.config["PQC_DB"] = db

    # ── Auth store + provider ─────────────────────────────────────────────────
    store    = AuthStore(db_path)
    provider = LocalAuthProvider(store)
    app.config["AUTH_STORE"]    = store
    app.config["AUTH_PROVIDER"] = provider

    # ── Scan orchestrator + discovery ─────────────────────────────────────────
    orchestrator = ScanOrchestrator(cfg)
    discovery    = DomainDiscovery(
        anthropic_api_key=cfg.get("anthropic_api_key", ""),
        model=cfg.get("model", "claude-sonnet-4-20250514"),
    )
    app.config["ORCHESTRATOR"] = orchestrator
    app.config["DISCOVERY"]    = discovery

    # ── Dashboard body pre-extracted ─────────────────────────────────────────
    app.config["DASHBOARD_BODY"] = _extract_body(DASHBOARD_HTML)

    # ── Blueprints ────────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(app_bp)

    # ── Root redirect ─────────────────────────────────────────────────────────
    @app.route("/")
    def root():
        return redirect(url_for("auth_bp.login"))

    # ── Security headers (internet-facing) ────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"
        # CSP — allow Chart.js and Google Fonts loaded by the dashboard
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        # HSTS — only set when cookie_secure is True
        if cfg.get("cookie_secure", True):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    logger.info("PQC-Monitor application factory initialised (RBAC enabled)")
    return app


def _extract_body(html: str) -> str:
    """
    Extract just the dashboard's <body> content (excluding outer structural
    tags) so it can be embedded inside the authenticated app shell.
    The dashboard HTML uses inline CSS/JS — we strip the outer <html>,
    <head>, <body> open/close and return the interior.
    """
    import re
    # Remove DOCTYPE and html/head tags
    body = re.sub(r"<!DOCTYPE[^>]*>", "", html, flags=re.IGNORECASE)
    body = re.sub(r"<html[^>]*>|</html>", "", body, flags=re.IGNORECASE)
    # Remove the <head>...</head> block entirely
    body = re.sub(r"<head>.*?</head>", "", body, flags=re.DOTALL | re.IGNORECASE)
    # Remove <body...> open and </body>
    body = re.sub(r"<body[^>]*>|</body>", "", body, flags=re.IGNORECASE)
    return body.strip()
