#!/usr/bin/env python3
"""
PQC-Monitor: Fix malformed MX host entries in stored DNS enumeration data
=========================================================================
Older scans stored MX values verbatim, e.g. "5 SMTP.domain.com" — which is
not a hostname (it carries the MX *priority*, a mail-routing preference that
is irrelevant as a TLS scan target) and often the wrong case / a trailing
dot. This script repairs those entries in-place inside the `dns_enum`
enrichment blobs in `domain_extra`.

Affected fields inside each `dns_enum` blob:
  - mx_hosts[]                      "5 SMTP.x.com"      → "smtp.x.com"
  - subdomains[]                    (MX hosts are also added here)
  - tls_candidates[].host           (scan targets built from MX hosts)

What it does
────────────
  - Strips a leading numeric priority to a bare FQDN.
  - Lower-cases and removes trailing dots.
  - Drops entries that are not valid hostnames (e.g. a lone "5", or "." from
    a null-MX "0 ."), and de-duplicates.
  - Rewrites the blob only if something actually changed.

It does NOT re-run DNS or touch the network. Old raw scans are untouched.

Usage
─────
  python3 scripts/fix_mx_entries.py --dry-run          # preview changes
  python3 scripts/fix_mx_entries.py                    # apply
  python3 scripts/fix_mx_entries.py --config /opt/pqc-monitor/config/config.yaml
  python3 scripts/fix_mx_entries.py --db /var/lib/pqc-monitor/pqc_monitor.db

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger("fix_mx_entries")


# ── Normaliser (kept self-contained so the script has no import-time deps
#    on dnspython, which scanner.dns_enumerator pulls in) ───────────────────────

def normalise_mx_host(value: str) -> str:
    """Bare-FQDN form of an MX value, dropping priority. '' if not a host."""
    if not value:
        return ""
    token = value.strip()
    parts = token.split()
    if len(parts) >= 2 and parts[0].isdigit():
        token = parts[-1]
    elif len(parts) == 1 and parts[0].isdigit():
        return ""
    else:
        token = parts[-1] if parts else token
    host = token.rstrip(".").lower()
    if "." not in host or " " in host:
        return ""
    if not all(c.isalnum() or c in "-._" for c in host):
        return ""
    return host


def _looks_malformed(value: str) -> bool:
    """True if the stored value differs from its normalised form."""
    return value != normalise_mx_host(value)


# ── Args ──────────────────────────────────────────────────────────────────────

def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Repair malformed MX entries in stored dns_enum blobs.")
    parser.add_argument("--config", help="config.yaml (to locate db_path).")
    parser.add_argument("--db", help="Override the database path directly.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report changes without writing.")
    return parser.parse_args(argv)


def resolve_db_path(args) -> str:
    if args.db:
        return args.db
    try:
        from pqc_monitor import load_config
        cfg = load_config(args.config) or {}
        if cfg.get("db_path"):
            return cfg["db_path"]
    except Exception as e:
        logger.debug("load_config failed: %s", e)
    return os.path.join(ROOT, "data", "pqc_monitor.db")

def _clean_host_list(values, drop_invalid=True):
    """Normalise a list of host strings; return (new_list, changed)."""
    out, seen, changed = [], set(), False
    for v in values or []:
        n = normalise_mx_host(v)
        if not n:
            # Not a host: drop it (e.g. a lone priority, or ".").
            if v:  # something was there and we're removing it
                changed = True
            continue
        if n != v:
            changed = True
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out, changed


def repair_blob(blob: dict) -> tuple[dict, list]:
    """Repair a dns_enum blob in place. Returns (blob, list-of-change-notes)."""
    notes = []

    # mx_hosts
    if isinstance(blob.get("mx_hosts"), list):
        new_mx, changed = _clean_host_list(blob["mx_hosts"])
        if changed:
            notes.append(f"mx_hosts: {blob['mx_hosts']} → {new_mx}")
            blob["mx_hosts"] = new_mx

    # Build the set of normalised MX hosts to also fix in subdomains/candidates
    mx_set = set(blob.get("mx_hosts", []))

    # subdomains: normalise any entry that carries a priority prefix
    if isinstance(blob.get("subdomains"), list):
        new_subs, seen, changed = [], set(), False
        for s in blob["subdomains"]:
            n = normalise_mx_host(s) if _looks_malformed(s) else s.rstrip(".").lower()
            if not n or "." not in n:
                if _looks_malformed(s):
                    changed = True
                    continue
                n = s  # leave non-MX odd values alone
            if n != s:
                changed = True
            if n not in seen:
                seen.add(n)
                new_subs.append(n)
        if changed:
            notes.append(f"subdomains: {len(blob['subdomains'])}→{len(new_subs)} entries")
            blob["subdomains"] = new_subs

    # tls_candidates: fix .host on any candidate whose host is malformed
    if isinstance(blob.get("tls_candidates"), list):
        cand_changed = False
        cleaned = []
        seen_keys = set()
        for c in blob["tls_candidates"]:
            if not isinstance(c, dict):
                cleaned.append(c)
                continue
            host = c.get("host", "")
            if _looks_malformed(host):
                n = normalise_mx_host(host)
                if not n:
                    cand_changed = True
                    continue  # drop candidate with unusable host
                c["host"] = n
                cand_changed = True
            key = (c.get("host"), c.get("port"))
            if key in seen_keys:
                cand_changed = True
                continue
            seen_keys.add(key)
            cleaned.append(c)
        if cand_changed:
            notes.append(f"tls_candidates: {len(blob['tls_candidates'])}→{len(cleaned)} entries")
            blob["tls_candidates"] = cleaned

    return blob, notes


# ── Main pass ─────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    args = _parse_args(argv)
    db_path = resolve_db_path(args)
    if not os.path.exists(db_path):
        logger.error("Database not found: %s", db_path)
        return 1

    logger.info("Database: %s", db_path)
    logger.info("Mode: %s", "DRY-RUN (no writes)" if args.dry_run else "APPLY")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT rowid AS rid, run_id, domain, json_data FROM domain_extra "
        "WHERE data_type='dns_enum'"
    ).fetchall()

    logger.info("Scanning %d dns_enum blob(s)…", len(rows))

    fixed = 0
    for row in rows:
        try:
            blob = json.loads(row["json_data"])
        except Exception:
            continue
        if not isinstance(blob, dict):
            continue

        repaired, notes = repair_blob(blob)
        if not notes:
            continue

        fixed += 1
        logger.info("• %s (run %s)", row["domain"], row["run_id"])
        for n in notes:
            logger.info("    %s", n)

        if not args.dry_run:
            conn.execute(
                "UPDATE domain_extra SET json_data=? WHERE rowid=?",
                (json.dumps(repaired), row["rid"])
            )

    if args.dry_run:
        logger.info("DRY-RUN complete — %d blob(s) would be repaired. No writes.",
                    fixed)
    else:
        conn.commit()
        logger.info("Done — repaired %d blob(s).", fixed)

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
