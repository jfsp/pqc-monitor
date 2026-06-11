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

from flask import Flask, redirect, url_for, request, jsonify

sys.path.insert(0, os.path.dirname(__file__))

from auth.store    import AuthStore
from auth.middleware import LocalAuthProvider, SESSION_LIFETIME_SECONDS

from data.database import Database
from scanner.orchestrator import ScanOrchestrator
from domain_discovery.domain_finder import DomainDiscovery

logger = logging.getLogger(__name__)


def create_app(config: dict = None) -> Flask:
    cfg = config or {}

    # Import blueprint modules inside create_app and reload them so that each
    # call gets fresh Blueprint instances. This is required for test isolation —
    # Flask raises AssertionError if the same Blueprint object is registered on
    # two different app instances.
    import importlib
    import auth.auth_routes as _auth_mod
    import admin.routes     as _admin_mod
    import app_routes       as _app_mod
    for _mod in (_auth_mod, _admin_mod, _app_mod):
        importlib.reload(_mod)
    from auth.auth_routes import auth_bp
    from admin.routes     import admin_bp
    from app_routes       import app_bp

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

    # ── Session security ──────────────────────────────────────────────────────
    # cookie_secure must be False when running over plain HTTP.
    # Set https_enabled: true in config.yaml (or pass cookie_secure: true)
    # only when a TLS-terminating reverse proxy is in front.
    https_enabled = cfg.get("https_enabled", cfg.get("cookie_secure", False))

    app.config.update(
        SESSION_COOKIE_SECURE   = https_enabled,
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

    # ── Blueprints ────────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(app_bp)

    # ── Root redirect ─────────────────────────────────────────────────────────
    @app.route("/")
    def root():
        return redirect(url_for("auth_bp.login"))

    # ── Version endpoint ──────────────────────────────────────────────────────
    from version import VERSION
    app.config["PQC_VERSION"] = VERSION

    @app.route("/api/version")
    def api_version():
        return jsonify({"version": VERSION, "name": "PQC-Monitor"})

    # ── Security headers (internet-facing) ────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        if https_enabled:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    logger.info("PQC-Monitor v%s application factory initialised (RBAC enabled)", VERSION)
    return app
