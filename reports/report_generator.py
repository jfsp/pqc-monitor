#!/usr/bin/env python3
"""
PQC-Monitor: Report Generator
Produces CSV, JSON and plain-text summary reports from assessment data.
Designed to be called from the CLI and the dashboard export endpoint.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_assessments(db, run_id: Optional[str] = None, domains=None) -> list:
    """Latest assessment per domain (or of one run). `domains` (iterable)
    restricts the rows — callers pass the requesting user's visible domains;
    None means all (admin, CLI)."""
    rows = db.get_latest_assessments(run_id)
    if domains is not None:
        allowed = {d.lower() for d in domains if d}
        rows = [r for r in rows if (r.get("domain") or "").lower() in allowed]
    # One row per domain: the org LEFT JOIN repeats domains in several orgs.
    seen, unique = set(), []
    for r in rows:
        key = (r.get("domain"), r.get("id"))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    rows = unique
    # Ensure JSON fields are parsed
    for row in rows:
        for field in ("findings_json", "tls_versions", "cipher_suites",
                      "guidelines_used", "errors_json", "key_types"):
            if isinstance(row.get(field), str):
                try:
                    row[field] = json.loads(row[field])
                except Exception:
                    row[field] = []
    return rows


def _summary(rows: list) -> dict:
    """Summary block computed from the exported rows (same rules as
    Database.get_summary_stats: na rows count as domains, not as scores)."""
    if not rows:
        return {}
    scored = [r for r in rows if r.get("level") != "na"]
    scores = [r.get("score", 0) or 0 for r in scored]
    return {
        "total_domains":  len(rows),
        "avg_score":      round(sum(scores) / len(scores), 1) if scores else 0,
        "critical_count": sum(1 for r in scored if r.get("level") == "critical"),
        "weak_count":     sum(1 for r in scored if r.get("level") == "weak"),
        "moderate_count": sum(1 for r in scored if r.get("level") == "moderate"),
        "ready_count":    sum(1 for r in scored if r.get("level") == "ready"),
        "pqc_count":      sum(1 for r in rows if r.get("has_pqc")),
        "na_count":       sum(1 for r in rows if r.get("level") == "na"),
    }


def _run_meta(db, run_id: Optional[str]) -> dict:
    if not run_id:
        return {}
    try:
        return db.get_run(run_id) or {}
    except Exception:
        return {}


def _level_emoji(level: str) -> str:
    return {"critical": "🔴", "weak": "🟠", "moderate": "🟡", "ready": "🟢"}.get(level, "⚪")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CSV Export ────────────────────────────────────────────────────────────────

CSV_COLUMNS = [
    "domain", "score", "level", "has_pqc",
    "tls_versions", "cipher_suites", "key_types",
    "cert_expiry_days", "assessed_at", "guidelines_used",
    "critical_findings", "high_findings", "medium_findings",
    "finding_messages",
]


def export_csv(db, run_id: Optional[str] = None, domains=None) -> str:
    """
    Return assessment results as a UTF-8 CSV string.
    Suitable for writing to a file or returning as an HTTP response.
    domains: optional scope (the requesting user's visible domains).
    """
    rows = _load_assessments(db, run_id, domains)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()

    for a in rows:
        findings = a.get("findings_json") or []
        crit = sum(1 for f in findings
                   if (f.get("severity") if isinstance(f, dict) else "") == "critical")
        high = sum(1 for f in findings
                   if (f.get("severity") if isinstance(f, dict) else "") == "high")
        med  = sum(1 for f in findings
                   if (f.get("severity") if isinstance(f, dict) else "") == "medium")
        messages = " | ".join(
            f.get("message", "") for f in findings if isinstance(f, dict)
        )

        tls = a.get("tls_versions") or []
        ciphers = a.get("cipher_suites") or []
        guidelines = a.get("guidelines_used") or []
        key_types = a.get("key_types") or []

        writer.writerow({
            "domain":           a.get("domain", ""),
            "score":            a.get("score", 0),
            "level":            a.get("level", ""),
            "has_pqc":          "yes" if a.get("has_pqc") else "no",
            "tls_versions":     "; ".join(tls if isinstance(tls, list) else []),
            "cipher_suites":    "; ".join(ciphers if isinstance(ciphers, list) else []),
            "key_types":        "; ".join(key_types if isinstance(key_types, list) else []),
            "cert_expiry_days": a.get("cert_expiry_days", ""),
            "assessed_at":      (a.get("assessed_at") or "")[:19],
            "guidelines_used":  "; ".join(guidelines if isinstance(guidelines, list) else []),
            "critical_findings": crit,
            "high_findings":    high,
            "medium_findings":  med,
            "finding_messages": messages,
        })

    return buf.getvalue()


# ── JSON Export ───────────────────────────────────────────────────────────────

def export_json(db, run_id: Optional[str] = None, pretty: bool = True,
                domains=None) -> str:
    """
    Return assessment results as a JSON string.
    Includes metadata envelope for traceability.
    domains: optional scope (the requesting user's visible domains); the
    summary is then computed over the exported rows only.
    """
    rows = _load_assessments(db, run_id, domains)
    run_meta = _run_meta(db, run_id)

    payload = {
        "export_metadata": {
            "generated_at": _utcnow(),
            "run_id": run_id,
            "run_started_at": run_meta.get("started_at", ""),
            "sector": run_meta.get("sector", ""),
            "region": run_meta.get("region", ""),
            "tool": "PQC-Monitor v1.0",
            "license": "GPL-3.0-or-later",
            "ai_assisted": True,
        },
        "summary": db.get_summary_stats() if domains is None and not run_id
                   else _summary(rows),
        "assessments": rows,
    }
    indent = 2 if pretty else None
    return json.dumps(payload, indent=indent, default=str)


# ── Text Summary Report ───────────────────────────────────────────────────────

def export_text_report(db, run_id: Optional[str] = None, domains=None) -> str:
    """
    Return a human-readable plain-text report suitable for printing
    or including in an e-mail.
    domains: optional scope (the requesting user's visible domains); the
    summary is computed over those rows and the all-domains trend section
    is left out.
    """
    rows = _load_assessments(db, run_id, domains)
    scoped = domains is not None
    stats = _summary(rows) if (scoped or run_id) else db.get_summary_stats()
    trends = [] if scoped else db.get_sector_trends()
    run_meta = _run_meta(db, run_id)

    lines = []
    sep = "─" * 72

    lines += [
        "╔══════════════════════════════════════════════════════════════════════╗",
        "║         PQC-Monitor — Post-Quantum Cryptography Readiness Report     ║",
        "╚══════════════════════════════════════════════════════════════════════╝",
        "",
        f"  Generated : {_utcnow()}",
        f"  Run ID    : {run_id or '(latest per domain)'}",
        f"  Sector    : {run_meta.get('sector', 'N/A')}",
        f"  Region    : {run_meta.get('region', 'N/A')}",
        "",
        "  ⚠️  DISCLAIMER: Non-intrusive passive scanning only. AI-assisted.",
        "      For research purposes. Verify findings with qualified professionals.",
        "",
        sep,
        "  SUMMARY",
        sep,
    ]

    if stats:
        lines += [
            f"  Domains assessed : {stats.get('total_domains', 0)}",
            f"  Average score    : {stats.get('avg_score', 0):.1f} / 100",
            f"  🔴 Critical      : {stats.get('critical_count', 0)}",
            f"  🟠 Weak          : {stats.get('weak_count', 0)}",
            f"  🟡 Moderate      : {stats.get('moderate_count', 0)}",
            f"  🟢 Ready         : {stats.get('ready_count', 0)}",
            f"  ✦  PQC detected  : {stats.get('pqc_count', 0)}",
        ]
    lines.append("")

    # ── Trend summary ────────────────────────────────────────────
    if len(trends) >= 2:
        lines += [sep, "  TREND (last scans)", sep]
        for t in trends[-4:]:
            date = (t.get("started_at") or "")[:10]
            avg = t.get("avg_score", 0)
            pqc = t.get("pqc_count", 0)
            n   = t.get("domain_count", 0)
            bar = "█" * int(avg / 10)
            lines.append(f"  {date}  {bar:<10}  avg={avg:4.1f}  domains={n}  pqc={pqc}")
        lines.append("")

    # ── Per-domain results ────────────────────────────────────────
    lines += [sep, "  DOMAIN ASSESSMENTS", sep]
    sorted_rows = sorted(rows, key=lambda r: r.get("score", 0))

    for a in sorted_rows:
        domain  = a.get("domain", "")
        score   = a.get("score", 0)
        level   = a.get("level", "")
        has_pqc = a.get("has_pqc", False)
        expiry  = a.get("cert_expiry_days")
        tls_ver = a.get("tls_versions") or []
        if isinstance(tls_ver, str):
            try:
                tls_ver = json.loads(tls_ver)
            except Exception:
                tls_ver = [tls_ver]

        pqc_tag = "  [PQC]" if has_pqc else ""
        exp_tag = f"  [expires {expiry}d]" if expiry is not None and expiry < 60 else ""
        tls_tag = f"  [{', '.join(tls_ver)}]" if tls_ver else ""

        lines.append(
            f"  {_level_emoji(level)} {score:>3}  {domain:<40}{pqc_tag}{exp_tag}{tls_tag}"
        )

        findings = a.get("findings_json") or []
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except Exception:
                findings = []

        crit_high = [f for f in findings if isinstance(f, dict)
                     and f.get("severity") in ("critical", "high")]
        for f in crit_high[:3]:   # cap at 3 per domain
            sev = f.get("severity", "").upper()
            msg = f.get("message", "")
            rec = f.get("recommendation", "")
            lines.append(f"       [{sev}] {msg}")
            if rec:
                lines.append(f"         → {rec}")

    lines.append("")
    lines += [
        sep,
        "  GUIDELINES APPLIED",
        sep,
        "  • NIST SP 800-131Ar3 (Oct 2024)  — https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd",
        "  • BSI TR-02102-1 (2026-01)        — https://www.bsi.bund.de/TG02102",
        "  • CCN-STIC-221 (2023)             — https://www.ccn-cert.cni.es",
        "",
        "  READINESS SCALE",
        "  🔴 0–25   Critical  : Broken/deprecated algorithms in active use",
        "  🟠 26–50  Weak      : Below recommended minimums, no PQC",
        "  🟡 51–75  Moderate  : Good classical crypto, PQC migration pending",
        "  🟢 76–100 Ready     : PQC algorithms present or transition complete",
        "",
        sep,
        "  PQC-Monitor v1.0  |  GPL-3.0-or-later  |  AI-assisted (Claude/Anthropic)",
        sep,
    ]

    return "\n".join(lines) + "\n"


# ── File helpers ──────────────────────────────────────────────────────────────

def save_report(content: str, path: str, label: str = "report"):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.info(f"{label} written to {path} ({len(content)} bytes)")
