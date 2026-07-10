#!/usr/bin/env python3
"""
PQC-Monitor: Qualys SSL Labs API v4 client

Retrieves SSL Labs assessment reports for scanned domains.

Design decisions (v1.9.0)
─────────────────────────
- During scan runs only CACHED results are fetched (`fromCache=on`) —
  triggering a fresh SSL Labs assessment takes 60+ seconds per host and
  the API enforces strict concurrency limits, which makes it unusable
  inline for multi-domain runs.
- Fresh assessments are requested ON DEMAND from the domain detail view
  (`startNew=on`, `publish=off`), then polled by the UI.
- The SSL Labs grade is DISPLAY ONLY — it does not feed the PQC score.

API notes
─────────
- API v4 requires a one-time registration (organisational email); the
  registered email is sent as an `email` HTTP header on every call.
  Register once with:  register_email(first, last, org, email)
- v3 was deprecated on 2023-12-31.
- Rate limiting: 429 = client cool-off, 529 = service overloaded.
- Results are computed by Qualys servers, not locally.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

API_BASE = "https://api.ssllabs.com/api/v4"
PUBLIC_REPORT_URL = "https://www.ssllabs.com/ssltest/analyze.html?d={host}"

# Worst-first ordering for aggregating multi-endpoint grades
_GRADE_ORDER = ["M", "T", "F", "E", "D", "C", "B", "A-", "A", "A+"]


def worst_grade(grades: list[str]) -> str:
    """Return the worst grade in a list (M/T worst … A+ best)."""
    ranked = [g for g in grades if g in _GRADE_ORDER]
    if not ranked:
        return grades[0] if grades else ""
    return min(ranked, key=_GRADE_ORDER.index)


class SSLLabsClient:
    """
    Thin client for the SSL Labs Assessment API v4.

    Parameters
    ----------
    email     Registered organisational email (v4 auth header).
              Empty string disables the client.
    timeout   Per-request HTTP timeout in seconds.
    """

    def __init__(self, email: str = "", timeout: float = 15.0,
                 api_base: str = API_BASE):
        self.email    = (email or "").strip()
        self.timeout  = timeout
        self.api_base = api_base.rstrip("/")

    @property
    def available(self) -> bool:
        return bool(self.email)

    # ── HTTP layer ────────────────────────────────────────────────

    def _get(self, path: str, params: dict) -> tuple[int, Optional[dict]]:
        """GET helper. Returns (status_code, json_or_None). Never raises."""
        try:
            resp = requests.get(
                f"{self.api_base}/{path}",
                params=params,
                headers={"email": self.email},
                timeout=self.timeout,
            )
            try:
                body = resp.json()
            except ValueError:
                body = None
            return resp.status_code, body
        except requests.RequestException as e:
            logger.debug(f"SSL Labs request failed ({path}): {e}")
            return 0, None

    # ── Public API ────────────────────────────────────────────────

    def info(self) -> Optional[dict]:
        """GET /info — engine version, rate-limit state. None on failure."""
        code, body = self._get("info", {})
        return body if code == 200 else None

    def get_cached(self, host: str, max_age_hours: int = 168) -> Optional[dict]:
        """
        Retrieve a cached report only — never triggers a new assessment.
        Used inline during scan runs. Returns a summary dict, or None if
        no cached report exists / the API is unavailable.
        """
        if not self.available:
            return None
        code, body = self._get("analyze", {
            "host": host,
            "fromCache": "on",
            "maxAge": max_age_hours,
            "all": "done",
        })
        if code != 200 or not body:
            if code in (429, 529):
                logger.warning(f"SSL Labs rate-limited ({code}) for {host}")
            return None
        if body.get("status") != "READY":
            return None  # cache miss or assessment in progress elsewhere
        return self.summarize(host, body)

    def start_assessment(self, host: str) -> tuple[str, Optional[dict]]:
        """
        Request a FRESH assessment (startNew=on, publish=off).
        Returns (status, summary_or_None). status is the SSL Labs
        assessment status (DNS/IN_PROGRESS/READY/ERROR) or
        'unavailable' / 'rate_limited'.
        """
        if not self.available:
            return "unavailable", None
        code, body = self._get("analyze", {
            "host": host,
            "startNew": "on",
            "publish": "off",
            "all": "done",
        })
        if code in (429, 529):
            return "rate_limited", None
        if code != 200 or not body:
            return "error", None
        status = body.get("status", "ERROR")
        return status, self.summarize(host, body) if status == "READY" else None

    def poll(self, host: str) -> tuple[str, Optional[dict]]:
        """
        Poll a running assessment (no startNew — returns current state).
        Returns (status, summary_or_None); summary only when READY.
        """
        if not self.available:
            return "unavailable", None
        code, body = self._get("analyze", {"host": host, "all": "done"})
        if code in (429, 529):
            return "rate_limited", None
        if code != 200 or not body:
            return "error", None
        status = body.get("status", "ERROR")
        if status == "READY":
            return status, self.summarize(host, body)
        return status, None

    # ── Report summarisation ──────────────────────────────────────

    @staticmethod
    def summarize(host: str, report: dict) -> dict:
        """
        Reduce a full SSL Labs Host report to what PQC-Monitor stores in
        domain_extra['ssllabs'].
        """
        endpoints = report.get("endpoints") or []
        ep_out = []
        for ep in endpoints:
            ep_out.append({
                "ip": ep.get("ipAddress", ""),
                "grade": ep.get("grade", ""),
                "grade_trust_ignored": ep.get("gradeTrustIgnored", ""),
                "has_warnings": bool(ep.get("hasWarnings")),
                "is_exceptional": bool(ep.get("isExceptional")),
                "status": ep.get("statusMessage", ""),
            })
        grades = [e["grade"] for e in ep_out if e["grade"]]
        test_time = report.get("testTime")
        if isinstance(test_time, (int, float)) and test_time > 0:
            test_time_iso = datetime.fromtimestamp(
                test_time / 1000, tz=timezone.utc).isoformat()
        else:
            test_time_iso = None
        return {
            "host": host,
            "status": report.get("status", ""),
            "grade": worst_grade(grades),
            "grades": grades,
            "endpoints": ep_out,
            "engine_version": report.get("engineVersion", ""),
            "criteria_version": report.get("criteriaVersion", ""),
            "test_time": test_time_iso,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "report_url": PUBLIC_REPORT_URL.format(host=host),
        }


def register_email(first_name: str, last_name: str, organization: str,
                   email: str, timeout: float = 15.0) -> tuple[bool, str]:
    """
    One-time SSL Labs API v4 registration helper.
    Note: free-mail providers (Gmail/Yahoo/Hotmail) are rejected by Qualys.
    """
    try:
        resp = requests.post(
            f"{API_BASE}/register",
            json={"firstName": first_name, "lastName": last_name,
                  "email": email, "organization": organization},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return True, "registered"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except requests.RequestException as e:
        return False, str(e)
