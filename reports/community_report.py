#!/usr/bin/env python3
"""
PQC-Monitor: Community & Region Report Generator

Produces aggregate PQC-readiness reports across a group of organisations,
grouped either by community membership or by region label.

Output formats: dict (for API/dashboard), CSV, plain text, PDF (weasyprint).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── Aggregate helpers ──────────────────────────────────────────────────────────

def _level_badge(score: Optional[float]) -> str:
    if score is None:
        return "N/A"
    if score < 30:
        return "Critical"
    if score < 55:
        return "Weak"
    if score < 75:
        return "Moderate"
    return "Ready"


def _executive_summary(group_name: str, group_type: str,
                        rows: list[dict], totals: dict) -> str:
    """Generate a one-paragraph executive summary from aggregate stats."""
    n_orgs  = len(rows)
    n_ready = sum(1 for r in rows if (r.get("avg_score") or 0) >= 75)
    n_crit  = sum(1 for r in rows if 0 < (r.get("avg_score") or 100) < 30)
    pqc     = totals.get("pqc_count", 0)
    domains = totals.get("domain_count", 0)
    avg     = totals.get("avg_score")
    avg_str = f"{avg:.1f}/100" if avg is not None else "N/A"

    lines = [
        f"This report covers the PQC cryptographic readiness of {n_orgs} "
        f"organisation{'s' if n_orgs != 1 else ''} within the "
        f"{group_type} \"{group_name}\", assessed across {domains} monitored "
        f"domain{'s' if domains != 1 else ''}.",
    ]
    lines.append(
        f"The aggregate average PQC-Monitor score is {avg_str}. "
        f"{n_ready} of {n_orgs} organisations have reached PQC-ready status "
        f"(score ≥ 75), while {n_crit} present critical cryptographic risk "
        f"(score < 30)."
    )
    if pqc:
        lines.append(
            f"Post-quantum cryptography has been detected in {pqc} domain "
            f"assessment{'s' if pqc != 1 else ''}, indicating early adoption "
            f"of ML-KEM or ML-DSA within the group."
        )
    else:
        lines.append(
            "No post-quantum cryptography has been detected in any assessed "
            "domain. Migration planning should be initiated as a priority."
        )
    return " ".join(lines)


def _totals(rows: list[dict]) -> dict:
    scored = [r for r in rows if r.get("avg_score") is not None]
    return {
        "domain_count": sum(r.get("domain_count", 0) for r in rows),
        "avg_score":    round(sum(r["avg_score"] for r in scored) / len(scored), 1)
                        if scored else None,
        "critical":     sum(r.get("critical", 0) for r in rows),
        "weak":         sum(r.get("weak", 0) for r in rows),
        "moderate":     sum(r.get("moderate", 0) for r in rows),
        "ready":        sum(r.get("ready", 0) for r in rows),
        "no_tls":       sum(r.get("no_tls", 0) for r in rows),
        "pqc_count":    sum(r.get("pqc_count", 0) for r in rows),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def build_report(group_name: str, group_type: str,
                 rows: list[dict]) -> dict:
    """
    Build a structured report dict from a list of org aggregate rows.

    group_type: "Community" | "Region"
    Returns dict suitable for JSON serialisation and PDF/CSV rendering.
    """
    totals  = _totals(rows)
    summary = _executive_summary(group_name, group_type, rows, totals)
    return {
        "group_name":  group_name,
        "group_type":  group_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary":     summary,
        "totals":      totals,
        "organisations": rows,
    }


def export_csv(report: dict) -> str:
    """Render report as CSV string."""
    out = io.StringIO()
    w   = csv.writer(out)
    w.writerow([
        f"{report['group_type']} Report: {report['group_name']}",
        f"Generated: {report['generated_at'][:19]}Z",
    ])
    w.writerow([])
    w.writerow([
        "Organisation", "Country", "Sector", "Domains",
        "Avg Score", "Level", "Critical", "Weak", "Moderate", "Ready",
        "No TLS", "PQC Domains",
    ])
    for r in report["organisations"]:
        w.writerow([
            r.get("name", ""),
            r.get("country", "") or r.get("country_code", "") or "",
            r.get("sector", ""),
            r.get("domain_count", 0),
            f"{r['avg_score']:.1f}" if r.get("avg_score") is not None else "N/A",
            _level_badge(r.get("avg_score")),
            r.get("critical", 0),
            r.get("weak", 0),
            r.get("moderate", 0),
            r.get("ready", 0),
            r.get("no_tls", 0),
            r.get("pqc_count", 0),
        ])
    t = report["totals"]
    w.writerow([
        "TOTALS", "", "",
        t.get("domain_count", 0),
        f"{t['avg_score']:.1f}" if t.get("avg_score") is not None else "N/A",
        _level_badge(t.get("avg_score")),
        t.get("critical", 0),
        t.get("weak", 0),
        t.get("moderate", 0),
        t.get("ready", 0),
        t.get("no_tls", 0),
        t.get("pqc_count", 0),
    ])
    return out.getvalue()


def export_text(report: dict) -> str:
    """Render report as plain text."""
    lines = []
    sep   = "=" * 72
    lines.append(sep)
    lines.append(f"PQC-MONITOR — {report['group_type'].upper()} REPORT")
    lines.append(f"{report['group_type']}: {report['group_name']}")
    lines.append(f"Generated: {report['generated_at'][:19]}Z")
    lines.append(sep)
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(report["summary"])
    lines.append("")
    lines.append("ORGANISATION BREAKDOWN")
    lines.append("-" * 40)
    col = "{:<28} {:>3} {:>7} {:>5} {:>4} {:>4} {:>4} {:>5} {:>4} {:>4}"
    lines.append(col.format(
        "Organisation", "CC", "Score", "Level",
        "Crit", "Weak", "Mod", "Ready", "NTLS", "PQC"
    ))
    lines.append("-" * 72)
    for r in report["organisations"]:
        sc = f"{r['avg_score']:.0f}" if r.get("avg_score") is not None else "N/A"
        lines.append(col.format(
            (r.get("name", ""))[:28],
            (r.get("country_code", "") or "")[:3],
            sc,
            _level_badge(r.get("avg_score"))[:5],
            r.get("critical", 0),
            r.get("weak", 0),
            r.get("moderate", 0),
            r.get("ready", 0),
            r.get("no_tls", 0),
            r.get("pqc_count", 0),
        ))
    t = report["totals"]
    lines.append("-" * 72)
    sc = f"{t['avg_score']:.0f}" if t.get("avg_score") is not None else "N/A"
    lines.append(col.format(
        "TOTALS", "",
        sc, _level_badge(t.get("avg_score"))[:5],
        t.get("critical", 0), t.get("weak", 0),
        t.get("moderate", 0), t.get("ready", 0),
        t.get("no_tls", 0), t.get("pqc_count", 0),
    ))
    lines.append("")
    return "\n".join(lines)


def export_pdf(report: dict) -> bytes:
    """
    Render report as PDF bytes using weasyprint.
    Raises ImportError if weasyprint is not installed.
    """
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise ImportError(
            "weasyprint is required for PDF export. "
            "Install with: pip install weasyprint"
        )

    LEVEL_COLOURS = {
        "Critical": "#ef4444",
        "Weak":     "#f97316",
        "Moderate": "#eab308",
        "Ready":    "#22c55e",
        "N/A":      "#6b7280",
    }

    def _score_cell(score):
        lvl   = _level_badge(score)
        colour = LEVEL_COLOURS.get(lvl, "#6b7280")
        val    = f"{score:.0f}" if score is not None else "N/A"
        return (
            f'<td class="num">{val}</td>'
            f'<td><span class="badge" style="background:{colour}20;'
            f'color:{colour}">{lvl}</span></td>'
        )

    rows_html = ""
    for r in report["organisations"]:
        sc = r.get("avg_score")
        rows_html += (
            f"<tr>"
            f"<td>{r.get('name','')}</td>"
            f"<td>{r.get('country_code','') or ''}</td>"
            f"<td>{r.get('sector','')}</td>"
            f'<td class="num">{r.get("domain_count",0)}</td>'
            + _score_cell(sc) +
            f'<td class="num">{r.get("critical",0)}</td>'
            f'<td class="num">{r.get("weak",0)}</td>'
            f'<td class="num">{r.get("moderate",0)}</td>'
            f'<td class="num">{r.get("ready",0)}</td>'
            f'<td class="num">{r.get("no_tls",0)}</td>'
            f'<td class="num">{r.get("pqc_count",0)}</td>'
            f"</tr>\n"
        )

    t  = report["totals"]
    ts = t.get("avg_score")
    totals_html = (
        f"<tr class='totals-row'>"
        f"<td><strong>Totals</strong></td>"
        f"<td></td><td></td>"
        f'<td class="num"><strong>{t.get("domain_count",0)}</strong></td>'
        + _score_cell(ts) +
        f'<td class="num"><strong>{t.get("critical",0)}</strong></td>'
        f'<td class="num"><strong>{t.get("weak",0)}</strong></td>'
        f'<td class="num"><strong>{t.get("moderate",0)}</strong></td>'
        f'<td class="num"><strong>{t.get("ready",0)}</strong></td>'
        f'<td class="num"><strong>{t.get("no_tls",0)}</strong></td>'
        f'<td class="num"><strong>{t.get("pqc_count",0)}</strong></td>'
        f"</tr>"
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4 landscape; margin: 1.5cm; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10px;
          color: #1e293b; }}
  .header {{ border-bottom: 3px solid #0ea5e9; padding-bottom: 10px;
             margin-bottom: 16px; }}
  .header h1 {{ font-size: 18px; margin: 0 0 4px 0; color: #0369a1; }}
  .header .meta {{ font-size: 9px; color: #64748b; }}
  .summary {{ background: #f0f9ff; border-left: 4px solid #0ea5e9;
              padding: 10px 14px; margin-bottom: 16px;
              font-size: 9.5px; line-height: 1.6; border-radius: 0 4px 4px 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 9px; }}
  th {{ background: #0369a1; color: #fff; padding: 5px 6px;
        text-align: left; font-weight: 600; white-space: nowrap; }}
  td {{ padding: 4px 6px; border-bottom: 1px solid #e2e8f0; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{ padding: 2px 6px; border-radius: 3px; font-size: 8px;
            font-weight: 600; white-space: nowrap; }}
  .totals-row td {{ border-top: 2px solid #0369a1; background: #eff6ff; }}
  .footer {{ margin-top: 12px; font-size: 8px; color: #94a3b8;
             border-top: 1px solid #e2e8f0; padding-top: 6px; }}
</style>
</head>
<body>
<div class="header">
  <h1>PQC-Monitor — {report['group_type']} Report: {report['group_name']}</h1>
  <div class="meta">Generated: {report['generated_at'][:19]}Z &nbsp;|&nbsp;
  PQC-Monitor v1.6.0 &nbsp;|&nbsp; Confidential</div>
</div>
<div class="summary">{report['summary']}</div>
<table>
  <thead>
    <tr>
      <th>Organisation</th><th>CC</th><th>Sector</th>
      <th class="num">Domains</th><th class="num">Score</th><th>Level</th>
      <th class="num">Critical</th><th class="num">Weak</th>
      <th class="num">Moderate</th><th class="num">Ready</th>
      <th class="num">No TLS</th><th class="num">PQC</th>
    </tr>
  </thead>
  <tbody>
    {rows_html}
    {totals_html}
  </tbody>
</table>
<div class="footer">
  This report is generated automatically by PQC-Monitor. Scores reflect the
  latest assessment per domain. Post-quantum cryptography detection is based on
  certificate OID inspection and TLS extension analysis.
</div>
</body>
</html>"""

    return HTML(string=html).write_pdf()
