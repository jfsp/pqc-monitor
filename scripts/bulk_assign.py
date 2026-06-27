#!/usr/bin/env python3
"""
PQC-Monitor: Bulk organisation assignment tool
===============================================
Given a list of organisation names (from a file or stdin), this script:

  - Sets a region on each matched organisation
  - Creates a community (if it doesn't exist) and adds orgs to it
  - Both operations are optional and can be combined

Usage examples
--------------
# Set region for orgs listed in a file:
    python3 scripts/bulk_assign.py --region Europe --file orgs.txt

# Create/add to community:
    python3 scripts/bulk_assign.py --community "Spanish Banking" --file orgs.txt

# Both at once:
    python3 scripts/bulk_assign.py --region Europe --community "EU Finance" --file orgs.txt

# Read org names from stdin (one per line):
    echo -e "Banco Santander\\nBBVA\\nCaixaBank" | python3 scripts/bulk_assign.py --region Europe

# Dry-run (see what would change without writing):
    python3 scripts/bulk_assign.py --region Europe --file orgs.txt --dry-run

Input format
------------
One organisation name per line. Lines starting with # are comments.
Blank lines are ignored. Names are matched case-insensitively and
whitespace-trimmed. Partial matches are NOT performed — names must
match exactly (after trim + case fold).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import os
import sys

# Allow running from the project root or from scripts/
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


def _load_config(config_path: str = None) -> dict:
    """Load PQC-Monitor config.yaml to find the DB path."""
    import yaml
    paths = [
        config_path,
        "/etc/pqc-monitor/config.yaml",
        os.path.join(_ROOT, "config", "config.yaml"),
        os.path.join(_ROOT, "config.yaml"),
    ]
    for p in paths:
        if p and os.path.exists(p):
            with open(p) as f:
                return yaml.safe_load(f) or {}
    return {}


def _read_names(file_path: str = None) -> list[str]:
    """Read organisation names from a file or stdin."""
    if file_path:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
    else:
        if sys.stdin.isatty():
            print("Reading org names from stdin (one per line, Ctrl-D when done):",
                  file=sys.stderr)
        lines = sys.stdin.readlines()

    names = []
    for line in lines:
        name = line.strip()
        if name and not name.startswith("#"):
            names.append(name)
    return names


def _match_orgs(all_orgs: list[dict], names: list[str]) -> tuple[list[dict], list[str]]:
    """Case-insensitive exact match of org names. Returns (matched, unmatched)."""
    index = {o["name"].strip().lower(): o for o in all_orgs}
    matched   = []
    unmatched = []
    for name in names:
        org = index.get(name.strip().lower())
        if org:
            matched.append(org)
        else:
            unmatched.append(name)
    return matched, unmatched


def main():
    parser = argparse.ArgumentParser(
        description="Bulk-assign region and/or community to PQC-Monitor organisations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("SPDX")[0].strip(),
    )
    parser.add_argument("--region", "-r", metavar="REGION",
                        help="Region label to set on matched orgs (e.g. 'Europe')")
    parser.add_argument("--community", "-c", metavar="COMMUNITY",
                        help="Community name to create (if absent) and add matched orgs to")
    parser.add_argument("--file", "-f", metavar="FILE",
                        help="File with org names (default: stdin)")
    parser.add_argument("--db", metavar="DB_PATH",
                        help="Path to pqc_monitor.db (auto-detected from config.yaml if omitted)")
    parser.add_argument("--config", metavar="CONFIG",
                        help="Path to config.yaml (default: auto-detect)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Show what would change without writing anything")
    args = parser.parse_args()

    if not args.region and not args.community:
        parser.error("At least one of --region or --community is required")

    # ── Resolve DB path ───────────────────────────────────────────────────────
    db_path = args.db
    if not db_path:
        cfg = _load_config(args.config)
        db_path = cfg.get("db_path") or "/var/lib/pqc-monitor/pqc_monitor.db"

    if not os.path.exists(db_path):
        print(f"✗ Database not found: {db_path}", file=sys.stderr)
        print("  Use --db to specify the path or --config to point to config.yaml",
              file=sys.stderr)
        sys.exit(1)

    # ── Load DB ───────────────────────────────────────────────────────────────
    from data.database import Database
    db = Database(db_path)

    # ── Read and match org names ──────────────────────────────────────────────
    names = _read_names(args.file)
    if not names:
        print("✗ No organisation names provided.", file=sys.stderr)
        sys.exit(1)

    all_orgs = db.get_organisations()
    matched, unmatched = _match_orgs(all_orgs, names)

    print(f"\nOrganisation matching")
    print(f"  Input:     {len(names)} name(s)")
    print(f"  Matched:   {len(matched)}")
    print(f"  Unmatched: {len(unmatched)}")

    if unmatched:
        print("\n⚠ Unmatched names (will be skipped):")
        for n in unmatched:
            print(f"    - {n!r}")

    if not matched:
        print("\n✗ No organisations matched — nothing to do.")
        sys.exit(0)

    print()

    # ── Dry run: show plan ────────────────────────────────────────────────────
    if args.dry_run:
        print("DRY RUN — no changes will be written\n")

    # ── Apply region ──────────────────────────────────────────────────────────
    if args.region:
        changed = 0
        skipped = 0
        print(f"Region: setting '{args.region}' on {len(matched)} org(s)…")
        for org in matched:
            old_region = org.get("region", "") or ""
            if old_region.lower() == args.region.lower():
                print(f"  ~ {org['name']} (already '{old_region}' — skip)")
                skipped += 1
                continue
            status = "(was: {!r})".format(old_region) if old_region else "(was: empty)"
            if not args.dry_run:
                db.update_organisation(org["id"], region=args.region)
            marker = "[DRY]" if args.dry_run else "✓"
            print(f"  {marker} {org['name']}  {status}")
            changed += 1
        print(f"  → {changed} updated, {skipped} skipped\n")

    # ── Apply community ───────────────────────────────────────────────────────
    if args.community:
        # Find or create community
        communities = db.get_communities()
        comm = next(
            (c for c in communities
             if c["name"].strip().lower() == args.community.strip().lower()),
            None
        )

        if comm:
            print(f"Community: found existing '{comm['name']}' (#{comm['id']})")
        else:
            print(f"Community: '{args.community}' not found — will create")
            if not args.dry_run:
                cid  = db.create_community(name=args.community)
                comm = db.get_community(cid)
                print(f"  ✓ Created community '{ comm['name']}' (#{comm['id']})")
            else:
                print(f"  [DRY] Would create community '{args.community}'")
                comm = {"id": "NEW", "name": args.community}

        # Get current org membership
        if args.dry_run or comm["id"] == "NEW":
            current_org_ids = set()
        else:
            current_org_ids = {o["id"] for o in db.get_community_orgs(comm["id"])}

        to_add   = [o for o in matched if o["id"] not in current_org_ids]
        already  = [o for o in matched if o["id"] in current_org_ids]

        print(f"\nAdding {len(to_add)} org(s) to '{comm['name']}':")
        for org in to_add:
            marker = "[DRY]" if args.dry_run else "✓"
            print(f"  {marker} {org['name']}")

        if already:
            print(f"Already in community ({len(already)} skipped):")
            for org in already:
                print(f"  ~ {org['name']}")

        if not args.dry_run and to_add and comm["id"] != "NEW":
            new_ids = list(current_org_ids) + [o["id"] for o in to_add]
            db.set_community_orgs(comm["id"], new_ids)
            print(f"\n  → {len(to_add)} org(s) added to '{comm['name']}'")
        elif not args.dry_run and to_add and comm["id"] == "NEW":
            # Community was just created above, get fresh ID
            communities = db.get_communities()
            comm = next(c for c in communities
                        if c["name"].strip().lower() == args.community.strip().lower())
            db.set_community_orgs(comm["id"], [o["id"] for o in to_add])
            print(f"\n  → {len(to_add)} org(s) added to '{comm['name']}'")

    if args.dry_run:
        print("\nDry run complete — no changes written.")
    else:
        print("\n✅ Done.")


if __name__ == "__main__":
    main()
