#!/usr/bin/env python3
"""
PQC-Monitor: score-only reassessment of stored scan data (no network).

One implementation shared by every reassessment path:
  * Orchestrator.reassess_run()  — POST /app/api/reassess, `pqc_monitor.py
    reassess <run_id>` and the legacy dashboard
  * scripts/reassess_all.py      — score-only mode

What is re-scored for a domain
──────────────────────────────
The raw probe results and enrichment blobs of ONE probed run — the "source
run" — never a mix of runs:

  * reassess_run(X): run X when X probed the domain; otherwise (X was itself a
    score-only reassessment, which has no raw scans) the domain's newest
    probed run at or before X started, else its newest probed run.
  * reassess_all: the domain's newest probed run.

Enrichment (chain / cipher_enum / cdn / group_enum) comes from the source run
only, exactly what the scan itself had. group_enum is always passed: it is the authoritative PQC grading basis, and
leaving it out regrades every domain on the "negotiated" basis (has_pqc
False). The chain / cipher-enum / CDN findings that the scan pipeline adds
at scan time are rebuilt from the blobs.

History: before 2026-10-16 the in-app path omitted group_enum and the extra
findings, and both paths fed the assessor failed probes (in-app) or every
probe of every run (reassess_all: averaged historical scores in and took the
certificate expiry of the OLDEST scan).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
from dataclasses import fields, MISSING
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

EXTRA_TYPES = ("chain", "cipher_enum", "cdn", "group_enum")


def _ts(value) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── Blob → dataclass (for the *_findings helpers) ────────────────────────────

def _empty_for(field):
    """Best-effort empty value for a required dataclass field lacking a default."""
    t = field.type
    ts = t if isinstance(t, str) else getattr(t, "__name__", str(t))
    if "bool" in ts:
        return False
    if "int" in ts:
        return 0
    if "float" in ts:
        return 0.0
    if "list" in ts:
        return []
    if "dict" in ts:
        return {}
    return ""


def reconstruct(cls, blob: dict):
    """
    Build a dataclass instance from a stored dict, keeping only declared
    fields (drops _recorded_at/_run_id provenance and schema-drift extras).
    Missing required fields get empty defaults so construction never raises.
    """
    allowed, required = {}, []
    for f in fields(cls):
        allowed[f.name] = f
        if f.default is MISSING and f.default_factory is MISSING:  # type: ignore[attr-defined]
            required.append(f.name)
    kwargs = {k: v for k, v in (blob or {}).items() if k in allowed}
    for name in required:
        kwargs.setdefault(name, _empty_for(allowed[name]))
    return cls(**kwargs)


def rebuild_extra_findings(extra: dict) -> list:
    """The cipher-enum / chain / CDN findings the scan pipeline adds at scan
    time, regenerated from stored blobs."""
    out: list = []
    cenum, chain, cdn = extra.get("cipher_enum"), extra.get("chain"), extra.get("cdn")
    if cenum:
        try:
            from scanner.cipher_enum import CipherEnumResult, cipher_enum_findings
            out += cipher_enum_findings(reconstruct(CipherEnumResult, cenum))
        except Exception as e:
            logger.debug("cipher_enum_findings rebuild failed: %s", e)
    if chain:
        try:
            from scanner.chain_validator import ChainAnalysis, chain_findings
            out += chain_findings(reconstruct(ChainAnalysis, chain))
        except Exception as e:
            logger.debug("chain_findings rebuild failed: %s", e)
    if cdn:
        try:
            from scanner.cdn_detector import CDNDetectionResult, cdn_findings
            out += cdn_findings(reconstruct(CDNDetectionResult, cdn))
        except Exception as e:
            logger.debug("cdn_findings rebuild failed: %s", e)
    return out


# ── Source selection ─────────────────────────────────────────────────────────

def source_run(db, domain: str, run_id: Optional[str] = None,
               as_of=None) -> Optional[str]:
    """The probed run whose data is re-scored (see module docstring)."""
    runs = db.probed_runs_for(domain)            # [(run_id, last scanned_at)] newest first
    if not runs:
        return None
    if run_id and any(r == run_id for r, _ in runs):
        return run_id
    limit = _ts(as_of)
    if limit is not None:
        for r, seen in runs:
            st = _ts(seen)
            if st is not None and st <= limit:
                return r
    return runs[0][0]


def _service_type(scans: list, previous: Optional[str]) -> Optional[str]:
    if previous:
        return previous
    from scanner.orchestrator import _port_to_service_type
    ports = sorted({s.get("port") for s in scans
                    if isinstance(s, dict) and s.get("success") and s.get("port")})
    if not ports:
        return None
    return _port_to_service_type(443 if 443 in ports else ports[0])


def reassess_domain(db, assessor, domain: str, *, run_id: Optional[str] = None,
                    as_of=None, service_type: Optional[str] = None):
    """
    Re-score one domain from stored data. Returns a DomainAssessment (level
    "na" when the source run has no successful handshake, or the domain was
    never probed). No network traffic.
    """
    src = source_run(db, domain, run_id=run_id, as_of=as_of)
    # Only completed handshakes are scored, as in the scan pipeline (failed
    # probes would only add "Port N: timeout" noise to errors_json).
    scans = [s for s in (db.get_domain_scans(domain, src) if src else [])
             if isinstance(s, dict) and (s.get("success") or s.get("source") == "shodan")]
    if not scans:
        return assessor.assess_domain(domain, [], service_type=service_type)
    # Blobs of the same run only: the scan pipeline stores them in the run
    # that probed, and taking a type from another run would mix states again
    # (e.g. a later group_enum turning an old run's reassessment PQC-ready).
    extra = {k: v for k, v in db.get_domain_extra(domain, src).items()
             if k in EXTRA_TYPES}
    return assessor.assess_domain(
        domain, scans,
        chain_analysis=extra.get("chain"),
        cipher_enum=extra.get("cipher_enum"),
        cdn_result=extra.get("cdn"),
        group_enum=extra.get("group_enum"),
        extra_findings=rebuild_extra_findings(extra),
        service_type=_service_type(scans, service_type),
    )
