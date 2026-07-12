#!/usr/bin/env python3
"""
PQC-Monitor: Reassess all existing domains
===========================================
Regenerates assessments for every domain already in the database so that
existing rows pick up the v1.9.0 fixes:

  - the FULL enumerated cipher set is merged into assessments.cipher_suites
  - CIPHER_ENUM / chain / CDN findings that NAME the specific offending
    suites are regenerated from the stored enrichment blobs

Two modes
─────────
  score-only  (default) : NO network traffic. Re-runs the assessor against
                          the stored raw scans + cipher_enum/chain/cdn blobs.
                          This is all that is needed for the v1.9.0 bug fixes,
                          because the enrichment data is already on disk.
                          CPU: light. Traffic: zero. API calls: zero.

  --rescan              : full network rescan per domain (TLS probe + cipher
                          enumeration + chain + CDN + cached SSL Labs). Use
                          ONLY for domains whose cipher_enum blob is missing.
                          CPU: heavy (cipher enum is ~5-15 s/domain). Traffic:
                          dozens of TCP connections per domain.

Resource controls
─────────────────
  --workers N       parallelism (default 2; keep low on a small VM)
  --sleep SECONDS   delay between domains/batches (default 0 score-only,
                    2.0 with --rescan, to spread out traffic)
  --limit N         process at most N domains (smoke-test / staged rollout)
  --only-missing    only domains that LACK a cipher_enum blob
                    (with --rescan: rescans just the gaps; without: skips
                    domains that already have full data)
  --dry-run         report what would happen; write nothing

The script writes ONE new scan_run tagged "reassess-all (<mode>)" and stores
the regenerated assessment per domain against it, exactly like the built-in
per-run reassess. Old rows are left intact (history is preserved); the
dashboard shows the newest per domain.

Usage
─────
  # Recommended first step — no traffic, fixes the two bugs on existing data:
  python3 scripts/reassess_all.py --config /opt/pqc-monitor/config/config.yaml

  # Preview only:
  python3 scripts/reassess_all.py --dry-run

  # Fill genuinely-missing cipher data (network), gently:
  python3 scripts/reassess_all.py --rescan --only-missing --workers 2 --sleep 3

  # Stage on 20 domains first:
  python3 scripts/reassess_all.py --rescan --only-missing --limit 20

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import sys
import time

# Make the app package importable when run from anywhere
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("reassess_all")


# ── Argument parsing ──────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(
    description="Reassess all existing domains (score-only by default; "
                "--rescan for a network rescan).",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("--config", help="Path to config.yaml (for db_path, "
                                      "guidelines, SSL Labs email).")
parser.add_argument("--db", help="Override the database path directly.")
parser.add_argument("--rescan", action="store_true",
                    help="Full network rescan (heavy). Default is score-only, "
                         "no traffic.")
parser.add_argument("--only-missing", action="store_true",
                    help="Only domains lacking a cipher_enum enrichment blob.")
parser.add_argument("--only-missing-groups", action="store_true",
                    help="Only domains lacking a group_enum blob — i.e. those "
                         "whose PQC status predates offered-group detection. "
                         "Use with --rescan to correct historical PQC values.")
parser.add_argument("--workers", type=int, default=2,
                    help="Parallel workers (default 2; keep low on small VMs).")
parser.add_argument("--sleep", type=float, default=None,
                    help="Delay in seconds between units of work "
                         "(default 0 score-only, 2.0 with --rescan).")
parser.add_argument("--limit", type=int, default=0,
                    help="Process at most N domains (0 = all).")
parser.add_argument("--dry-run", action="store_true",
                    help="Report only; write nothing.")
args = parser.parse_args()

if args.sleep is None:
    args.sleep = 2.0 if args.rescan else 0.0

# On a rescan a high worker count multiplies both CPU and outbound
# connections; cap it defensively and warn.
if args.rescan and args.workers > 4:
    logger.warning("Capping --workers to 4 for --rescan (was %d) to limit "
                   "CPU and outbound traffic on the host.", args.workers)
    args.workers = 4


# ── Config / DB resolution ────────────────────────────────────────────────────

def load_cfg():
    """Load app config via the standard loader, honouring --config/--db."""
    cfg = {}
    try:
        from pqc_monitor import load_config
        cfg = load_config(args.config) or {}
    except Exception as e:
        logger.debug("load_config failed (%s); falling back to defaults", e)
    if args.db:
        cfg["db_path"] = args.db
    if not cfg.get("db_path"):
        cfg["db_path"] = os.path.join(ROOT, "data", "pqc_monitor.db")
    return cfg


cfg = load_cfg()
db_path = cfg["db_path"]

if not os.path.exists(db_path):
    logger.error("Database not found: %s", db_path)
    sys.exit(1)

from data.database import Database                      # noqa: E402
from scanner.crypto_assessor import CryptoAssessor      # noqa: E402
from scanner.cipher_enum import cipher_enum_findings    # noqa: E402
from scanner.chain_validator import chain_findings      # noqa: E402
from scanner.cdn_detector import cdn_findings           # noqa: E402

db = Database(db_path)
guideline_ids = cfg.get("guidelines",
                        ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"])
guidelines_dir = cfg.get("guidelines_dir", os.path.join(ROOT, "guidelines"))


# ── Target selection ──────────────────────────────────────────────────────────

def all_domains() -> list[str]:
    """Distinct domains that have at least one assessment."""
    rows = db.get_latest_assessments()   # newest per domain
    return sorted({r.get("domain", "") for r in rows if r.get("domain")})


def latest_extra(domain: str) -> dict:
    """Latest enrichment blobs across all runs for a domain."""
    return db.get_latest_domain_extra(
        domain, data_types=["cipher_enum", "chain", "cdn", "group_enum"])


domains = all_domains()
if not domains:
    logger.error("No assessed domains found in %s", db_path)
    sys.exit(1)

# Filter to missing-cipher-data domains if requested
if args.only_missing_groups:
    before = len(domains)
    keep = []
    for domain in domains:
        extra = _extra(domain)
        if not extra.get("group_enum"):
            keep.append(domain)
    domains = keep
    logger.info("--only-missing-groups: %d of %d domains lack group_enum data "
                "(their PQC status is unreliable)", len(domains), before)
    if not args.rescan:
        logger.warning("--only-missing-groups without --rescan does nothing useful: "
                       "group_enum data can only be produced by a network rescan.")

if args.only_missing:
    filtered = []
    for d in domains:
        extra = latest_extra(d)
        ce = extra.get("cipher_enum")
        has_enum = bool(ce and ce.get("supported_ciphers"))
        if not has_enum:
            filtered.append(d)
    logger.info("--only-missing: %d of %d domains lack cipher_enum data",
                len(filtered), len(domains))
    domains = filtered

if not domains:
    logger.info("Nothing to do — no domains match the selection.")
    sys.exit(0)

if args.limit and args.limit < len(domains):
    domains = domains[:args.limit]
    logger.info("--limit: processing first %d domains", len(domains))

mode = "rescan" if args.rescan else "score-only"
logger.info("Mode: %s | domains: %d | workers: %d | sleep: %.1fs | dry-run: %s",
            mode, len(domains), args.workers, args.sleep, args.dry_run)

if args.dry_run:
    for d in domains[:50]:
        logger.info("  would reassess: %s", d)
    if len(domains) > 50:
        logger.info("  ... and %d more", len(domains) - 50)
    logger.info("Dry run complete. No changes written.")
    sys.exit(0)


# ── Reassessment run ──────────────────────────────────────────────────────────

new_run_id = db.create_run(
    domains,
    notes=f"reassess-all ({mode})",
)
logger.info("Created reassessment run_id=%s", new_run_id)

# One assessor shared across score-only work (read-only, thread-safe:
# assess_domain builds a fresh DomainAssessment each call and only reads
# the loaded guideline dicts).
assessor = CryptoAssessor(guideline_ids, guidelines_dir)

_counts = {"ok": 0, "na": 0, "error": 0}


def _score_only(domain: str):
    """Reassess a single domain from stored data. No network."""
    raw_scans = db.get_domain_scans(domain)          # newest-first, all runs

    # If every stored scan for this domain failed (no successful TLS
    # handshake on any port/run), the host has no reachable TLS. Write a
    # fresh na assessment so the newest row is correct — don't skip, or a
    # stale (possibly wrong) row would remain the latest for this domain.
    # assess_domain([]) yields exactly the canonical na result.
    if raw_scans and not any(
        s.get("success") or s.get("source") == "shodan" for s in raw_scans
    ):
        na = assessor.assess_domain(domain, [])   # → score 0, level na, no findings
        db.save_assessment(new_run_id, na.to_dict())
        _counts["na"] += 1
        logger.info("○ %s (no reachable TLS — recorded na)", domain)
        return "na"

    extra     = latest_extra(domain)
    chain     = extra.get("chain")
    cenum     = extra.get("cipher_enum")
    genum     = extra.get("group_enum")
    cdn       = extra.get("cdn")

    # Rebuild the "extra findings" that are normally produced at scan time,
    # so the v1.9.0 named-cipher findings (and chain/CDN findings) reappear
    # on reassessed rows. Each helper takes its dataclass, so reconstruct
    # from the stored dict, coercing away provenance/unknown keys.
    extra_findings = []
    if cenum:
        try:
            from scanner.cipher_enum import CipherEnumResult
            extra_findings += cipher_enum_findings(
                _reconstruct(CipherEnumResult, cenum))
        except Exception as e:
            logger.debug("%s: cipher_enum_findings rebuild failed: %s", domain, e)
    if chain:
        try:
            from scanner.chain_validator import ChainAnalysis
            extra_findings += chain_findings(_reconstruct(ChainAnalysis, chain))
        except Exception as e:
            logger.debug("%s: chain_findings rebuild failed: %s", domain, e)
    if cdn:
        try:
            from scanner.cdn_detector import CDNDetectionResult
            extra_findings += cdn_findings(_reconstruct(CDNDetectionResult, cdn))
        except Exception as e:
            logger.debug("%s: cdn_findings rebuild failed: %s", domain, e)

    assessment = assessor.assess_domain(
        domain, raw_scans,
        chain_analysis=chain,
        cipher_enum=cenum,
        group_enum=genum,
        cdn_result=cdn,
        extra_findings=extra_findings,
    )
    db.save_assessment(new_run_id, assessment.to_dict())


def _reconstruct(cls, blob: dict):
    """
    Build a dataclass instance from a stored dict, keeping only fields the
    class declares. Drops provenance keys (_recorded_at/_run_id from
    get_latest_domain_extra) and any schema-drift extras so construction
    never raises. Missing fields fall back to the dataclass defaults.
    """
    from dataclasses import fields, MISSING
    allowed, required_no_default = {}, []
    for f in fields(cls):
        allowed[f.name] = f
        if f.default is MISSING and f.default_factory is MISSING:  # type: ignore[attr-defined]
            required_no_default.append(f.name)
    kwargs = {k: v for k, v in blob.items() if k in allowed}
    # Provide empty defaults for any required field the blob lacks, so we
    # never crash on an older/partial blob.
    for name in required_no_default:
        kwargs.setdefault(name, _empty_for(allowed[name]))
    return cls(**kwargs)


def _empty_for(field):
    """Best-effort empty value for a required dataclass field lacking a default."""
    t = field.type
    ts = t if isinstance(t, str) else getattr(t, "__name__", str(t))
    if "bool" in ts:  return False
    if "int" in ts:   return 0
    if "float" in ts: return 0.0
    if "list" in ts:  return []
    if "dict" in ts:  return {}
    return ""


def _rescan(domain: str):
    """Full network rescan for one domain via the orchestrator pipeline."""
    # Imported lazily so score-only runs don't construct network clients.
    orch = _orchestrator()
    orch._scan_domain(domain, new_run_id, use_shodan=False)


_ORCH = None


def _orchestrator():
    global _ORCH
    if _ORCH is None:
        from scanner.orchestrator import ScanOrchestrator
        # Reuse app config so ports/timeout/SSL-Labs email are honoured, but
        # point it at the same DB and this run.
        _ORCH = ScanOrchestrator(cfg)
    return _ORCH


def _process(domain: str):
    try:
        if args.rescan:
            _rescan(domain)
            _counts["ok"] += 1
            logger.info("✓ %s", domain)
        else:
            status = _score_only(domain)   # "na" (already logged) or None
            if status != "na":
                _counts["ok"] += 1
                logger.info("✓ %s", domain)
    except Exception as e:
        _counts["error"] += 1
        logger.warning("✗ %s — %s", domain, e)
    finally:
        if args.sleep:
            time.sleep(args.sleep)


start = time.time()
try:
    if args.workers <= 1:
        for d in domains:
            _process(d)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            list(ex.map(_process, domains))
    db.finish_run(new_run_id, "completed")
except KeyboardInterrupt:
    logger.warning("Interrupted — marking run as partial.")
    db.finish_run(new_run_id, "partial")
    sys.exit(130)

elapsed = time.time() - start
logger.info("Done in %.1fs — ok=%d na=%d error=%d | run_id=%s",
            elapsed, _counts["ok"], _counts["na"], _counts["error"], new_run_id)
logger.info("The dashboard now shows the reassessed results (newest per domain).")
