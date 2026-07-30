#!/usr/bin/env python3
"""
PQC-Monitor: CSRF protection

Defence-in-depth against cross-site request forgery, layered on top of the
existing SameSite=Lax session cookie:

  1. Server-rendered forms (login, change-password, forgot, reset) carry a
     synchronizer token from the session; it is validated on POST.
  2. JSON/fetch API calls (the SPA and admin panel) are validated by a strict
     same-origin check on the Origin/Referer header. This needs no per-fetch
     token plumbing, so it protects the entire existing API surface without
     touching any client code.

A request passes if EITHER a valid form token is present OR it is same-origin.
Unsafe methods with neither are rejected 403. Safe methods pass through.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlparse

from flask import session, request, jsonify, current_app

_SESSION_KEY = "pqc_csrf"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def issue_token() -> str:
    """Return the session CSRF token, creating one if absent."""
    token = session.get(_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_SESSION_KEY] = token
    return token


def _token_ok() -> bool:
    expected = session.get(_SESSION_KEY)
    if not expected:
        return False
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return bool(sent) and hmac.compare_digest(str(expected), str(sent))


def same_origin() -> bool:
    """True if the request's Origin (or Referer) host matches the served host."""
    host = request.host  # host[:port] as seen after ProxyFix
    origin = request.headers.get("Origin")
    if origin:
        return urlparse(origin).netloc == host
    referer = request.headers.get("Referer")
    if referer:
        return urlparse(referer).netloc == host
    # No Origin and no Referer on a state-changing request: fail closed.
    return False


def csrf_protect():
    """Flask before_request hook. Register app-wide in create_app()."""
    if current_app.config.get("TESTING"):
        return None
    if request.method in _SAFE_METHODS:
        return None
    if _token_ok() or same_origin():
        return None
    if "/api/" in request.path:
        return jsonify({"error": "CSRF validation failed"}), 403
    return ("CSRF validation failed", 403)


def csrf_field() -> str:
    """Hidden input for inclusion in server-rendered forms."""
    return f'<input type="hidden" name="csrf_token" value="{issue_token()}">'
