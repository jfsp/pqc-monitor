#!/usr/bin/env python3
"""
PQC-Monitor: Bulk Organisation Assignment by TLD
=================================================
Given an organisation name (created or updated), a region, a sector, and a
TLD pattern, this script finds every domain in the database that matches the
pattern and assigns it to the organisation.

Matching rule
-------------
A domain D matches TLD pattern T when:
  - D == T  (exact match — the apex domain itself)
  - D ends with ".<T>"  (any subdomain of T at any depth)

Example:
  --tld bde.es  matches  bde.es, www.bde.es, api.bde.es, mail.bde.es

Domain sources searched (union, deduplicated):
  1. assessments table  — every domain ever scanned
  2. domain_lists table — every domain in any saved list

The organisation is created if it does not already exist.
If it exists, --sector and --region update it (unless --no-update is passed).
Existing domain assignments for the org are PRESERVED; new matches are added.

Usage examples
--------------
  # Dry run — show what would be assigned without writing anything
  python3 scripts/bulk_org_assign.py \\
      --tld bde.es \\
      --org "Banco de España" \\
      --sector "Financial Services" \\
      --region "EU/Spain" \\
      --dry-run

  # Live run with default config
  python3 scripts/bulk_org_assign.py \\
      --tld bde.es \\
      --org "Banco de España" \\
      --sector "Financial Services" \\
      --region "EU/Spain"

  # Multiple TLDs for the same org in one command
  python3 scripts/bulk_org_assign.py \\
      --tld bde.es --tld bancodeespana.es \\
      --org "Banco de España" \\
      --sector "Financial Services" \\
      --region "EU/Spain"

  # Custom config / db path
  python3 scripts/bulk_org_assign.py \\
      --config /etc/pqc-monitor/config.yaml \\
      --tld example.com --org "Example Corp"

  # Do not update sector/region if org already exists
  python3 scripts/bulk_org_assign.py \\
      --tld example.com --org "Example Corp" --no-update

Exit codes
----------
  0  success (even if 0 new domains were added)
  1  error (bad arguments, DB failure, etc.)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import os
import sys

# Allow running from the project root or the scripts/ subdirectory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── Helpers ───────────────────────────────────────────────────────────────────

def matches_tld(domain: str, tld: str) -> bool:
    """Return True if *domain* is *tld* or a subdomain of *tld*."""
    domain = domain.lower().strip()
    tld    = tld.lower().strip().lstrip("*").lstrip(".")
    return domain == tld or domain.endswith(f".{tld}")


def collect_all_domains(db) -> set[str]:
    """
    Return every distinct domain string in the database, from both:
      - assessments (every domain ever scanned)
      - domain_lists (every domain in any saved list, whether scanned or not)
    """
    domains: set[str] = set()

    # Source 1: assessments
    for d in db.get_all_known_domains():
        domains.add(d.lower().strip())

    # Source 2: domain_lists (domains_json is a JSON array of strings)
    with db._connect() as conn:
        rows = conn.execute("SELECT domains_json FROM domain_lists").fetchall()
    for row in rows:
        try:
            for d in json.loads(row["domains_json"]):
                domains.add(d.lower().strip())
        except Exception:
            pass

    return domains


def get_or_create_org(db, name: str, sector: str, region: str,
                       description: str, no_update: bool, dry_run: bool) -> tuple[int, bool]:
    """
    Return (org_id, created).
    If the org exists and no_update is False, patch sector/region.
    """
    with db._connect() as conn:
        row = conn.execute(
            "SELECT * FROM organisations WHERE name=? COLLATE NOCASE",
            (name.strip(),)
        ).fetchone()

    if row:
        org_id  = row["id"]
        created = False
        if not no_update and not dry_run:
            updates = {}
            if sector and sector != row["sector"]:
                updates["sector"] = sector
            if region and region != row["region"]:
                updates["region"] = region
            if description and description != row["description"]:
                updates["description"] = description
            if updates:
                db.update_organisation(org_id, **updates)
        return org_id, created

    # Create new
    if not dry_run:
        org_id = db.create_organisation(
            name=name,
            sector=sector,
            region=region,
            description=description,
        )
    else:
        org_id = -1   # sentinel for dry run
    return org_id, True


def add_domains_to_org(db, org_id: int, new_domains: list[str], dry_run: bool) -> int:
    """
    Merge *new_domains* into the org's existing assignments without removing
    anything (additive, not replace).  Returns count of actually-new domains.
    """
    existing = set(db.get_org_domains(org_id)) if org_id != -1 else set()
    to_add   = [d for d in new_domains if d not in existing]
    if to_add and not dry_run:
        merged = sorted(existing | set(to_add))
        db.set_org_domains(org_id, merged)
    return len(to_add)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bulk-assign domains matching a TLD pattern to an organisation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("SPDX-License-Identifier")[0].strip(),
    )
    parser.add_argument(
        "--tld", metavar="TLD", action="append", required=True,
        help="TLD/apex domain to match (e.g. bde.es). Repeat for multiple.",
    )
    parser.add_argument("--org",    required=True, help="Organisation name (created if absent)")
    parser.add_argument("--sector", default="",    help="Sector label (e.g. 'Financial Services')")
    parser.add_argument("--region", default="",    help="Region label (e.g. 'EU/Spain')")
    parser.add_argument("--description", default="", help="Optional free-text description")
    parser.add_argument(
        "--no-update", action="store_true",
        help="Do not update sector/region/description if the org already exists",
    )
    parser.add_argument(
        "--dry-run", "-n", action="store_true",
        help="Show what would happen without writing to the database",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to config.yaml (default: config/config.yaml relative to project root)",
    )
    parser.add_argument(
        "--db", default=None,
        help="Direct path to the SQLite database file (overrides config)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print every matched domain",
    )
    args = parser.parse_args()

    # ── Load config / open DB ─────────────────────────────────────────────────
    try:
        from pqc_monitor import load_config
        cfg = load_config(args.config)
    except Exception as e:
        print(f"ERROR: Could not load config: {e}", file=sys.stderr)
        return 1

    db_path = args.db or cfg.get("db_path", os.path.join(ROOT, "data", "pqc_monitor.db"))
    if not os.path.exists(db_path):
        print(f"ERROR: Database not found: {db_path}", file=sys.stderr)
        print("  Use --db to specify a path, or --config to point at your config.yaml",
              file=sys.stderr)
        return 1

    try:
        from data.database import Database
        db = Database(db_path)
    except Exception as e:
        print(f"ERROR: Could not open database: {e}", file=sys.stderr)
        return 1

    # ── Normalise TLDs ────────────────────────────────────────────────────────
    tlds = [t.lower().strip().lstrip("*.").rstrip(".") for t in args.tld]
    for t in tlds:
        if not t or "." not in t:
            print(f"ERROR: '{t}' does not look like a valid TLD (needs at least one dot)",
                  file=sys.stderr)
            return 1

    # ── Collect all known domains ─────────────────────────────────────────────
    print(f"{'[DRY RUN] ' if args.dry_run else ''}Collecting domains from database...")
    all_domains = collect_all_domains(db)
    print(f"  {len(all_domains)} unique domains in database")

    # ── Match against each TLD ────────────────────────────────────────────────
    matched: set[str] = set()
    for tld in tlds:
        hits = {d for d in all_domains if matches_tld(d, tld)}
        print(f"  TLD '{tld}': {len(hits)} match(es)")
        if args.verbose:
            for h in sorted(hits):
                print(f"    {h}")
        matched |= hits

    if not matched:
        print("No domains matched. Nothing to do.")
        print("Tip: run a scan first to populate the assessments table,")
        print("     or add domains via the dashboard → Scanner → Domain Lists.")
        return 0

    print(f"  Total matched (union): {len(matched)} domain(s)")

    # ── Get or create organisation ────────────────────────────────────────────
    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}Organisation: {args.org!r}")
    try:
        org_id, created = get_or_create_org(
            db, args.org, args.sector, args.region,
            args.description, args.no_update, args.dry_run,
        )
    except Exception as e:
        print(f"ERROR: Could not get/create organisation: {e}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"  Would {'create' if created else 'update'} organisation {args.org!r}")
        if args.sector:
            print(f"  sector    : {args.sector}")
        if args.region:
            print(f"  region    : {args.region}")
    else:
        action = "Created" if created else "Found existing"
        print(f"  {action} organisation (id={org_id})")
        if args.sector:
            print(f"  sector    : {args.sector}")
        if args.region:
            print(f"  region    : {args.region}")

    # ── Assign domains ────────────────────────────────────────────────────────
    matched_sorted = sorted(matched)
    try:
        n_new = add_domains_to_org(db, org_id, matched_sorted, args.dry_run)
    except Exception as e:
        print(f"ERROR: Could not assign domains: {e}", file=sys.stderr)
        return 1

    already = len(matched) - n_new
    if args.dry_run:
        print(f"\n[DRY RUN] Would add {n_new} new domain(s) "
              f"({already} already assigned)")
        print("Re-run without --dry-run to apply changes.")
    else:
        print(f"\n✅ Done: {n_new} new domain(s) added, {already} already assigned")
        if args.verbose and n_new:
            print("  Newly assigned:")
            existing_before = set(db.get_org_domains(org_id)) - set(matched_sorted)
            for d in matched_sorted:
                if d not in existing_before:
                    print(f"    + {d}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
