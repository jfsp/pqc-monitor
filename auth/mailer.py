#!/usr/bin/env python3
"""
PQC-Monitor: Mailer

Optional outbound email for password-reset links. Supports two modes:

  local  — connect to a local MTA (e.g. 127.0.0.1:25), no auth, no TLS
  relay  — authenticated submission to an external relay
           (Gmail app-password, Proton Mail Bridge, etc.) over STARTTLS or SSL

Pure standard library (smtplib + email.message) — no new dependency. Failures
never raise into the request path: send() logs and returns False so a reset
request can never 500. The relay password is read from the PQC_MAIL_PASSWORD
environment variable and is never taken from config.yaml.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class Mailer:
    """Send plaintext (+optional HTML) email per the 'mail' config section."""

    def __init__(self, cfg: dict | None):
        self._cfg = cfg or {}

    # ── Config accessors ─────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return bool(self._cfg.get("enabled", False))

    @property
    def mode(self) -> str:
        return (self._cfg.get("mode") or "local").lower()

    @property
    def from_addr(self) -> str:
        return self._cfg.get("from_addr") or "pqc-monitor@localhost"

    @property
    def timeout(self) -> int:
        try:
            return int(self._cfg.get("timeout_seconds", 10))
        except (TypeError, ValueError):
            return 10

    # ── Public API ───────────────────────────────────────────────────────────

    def send(self, to_addr: str, subject: str,
             text_body: str, html_body: str | None = None) -> bool:
        if not self.enabled:
            logger.info("Mailer disabled; not sending to %s", to_addr)
            return False
        if not to_addr:
            return False

        msg = EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(text_body)
        if html_body:
            msg.add_alternative(html_body, subtype="html")

        try:
            if self.mode == "relay":
                self._send_relay(msg)
            else:
                self._send_local(msg)
            logger.info("Mail sent to %s (mode=%s)", to_addr, self.mode)
            return True
        except Exception as exc:                       # noqa: BLE001
            logger.warning("Mail send failed (mode=%s): %s", self.mode, exc)
            return False

    # ── Transports ───────────────────────────────────────────────────────────

    def _send_local(self, msg: EmailMessage):
        host = self._cfg.get("local_host", "127.0.0.1")
        port = int(self._cfg.get("local_port", 25))
        with smtplib.SMTP(host, port, timeout=self.timeout) as s:
            s.send_message(msg)

    def _send_relay(self, msg: EmailMessage):
        host = self._cfg.get("relay_host", "")
        port = int(self._cfg.get("relay_port", 587))
        security = (self._cfg.get("relay_security") or "starttls").lower()
        username = self._cfg.get("relay_username", "")
        password = self._cfg.get("relay_password", "")  # injected from env by loader

        if security == "ssl":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=self.timeout,
                                  context=context) as s:
                if username:
                    s.login(username, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=self.timeout) as s:
                s.ehlo()
                if security == "starttls":
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if username:
                    s.login(username, password)
                s.send_message(msg)
