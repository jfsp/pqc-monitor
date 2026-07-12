#!/usr/bin/env python3
"""
PQC-Monitor: Database consistency audit (READ-ONLY)
===================================================
Scans a live pqc_monitor.db for grouping / geographic / data-quality
inconsistencies and prints a console report. It NEVER writes to the
database — it opens it in SQLite read-only mode (mode=ro). At the end it
prints *suggested* fix SQL, fully commented out, for a human to review.

Checks
──────
  A. Referential integrity   orphan rows in mapping/grant tables
  B. Unassigned              domains (from assessments ∪ raw_scans ∪
                             domain_lists) with no organisation;
                             organisations in no community
  C. Empty groups            organisations with no domains; communities
                             with no organisations; empty/broken
                             domain_lists
  D. Duplicates              domain assigned to several organisations;
                             case/trailing-dot variants of the same
                             domain across tables; identical or similar
                             organisation names; different organisations
                             sharing the same registrable domain;
                             duplicate entries inside a domain_list
  E. Geography               organisation country_code vs the ccTLDs of
                             its own domains (tld_geo.csv); region /
                             country display name vs tld_geo for that
                             code; invalid or unknown country codes;
                             communities mixing regions (informational)
  F. Data quality            assessments with services_assessed=0 and
                             level != 'na' (the 1.9.1 invariant); level
                             outside the allowed set; score outside
                             0–100; malformed domain values (MX-priority
                             prefixes etc.); assigned domains never
                             scanned (informational)

Severities
──────────
  ERROR   broken data (orphans, invariant violations, malformed domains)
  WARN    inconsistent but functional (geo mismatches, duplicates)
  INFO    worth a look, not necessarily wrong (unassigned, empty, mixed)

Usage
─────
  python3 scripts/audit_db_consistency.py                  # config-resolved DB
  python3 scripts/audit_db_consistency.py --db /var/lib/pqc-monitor/pqc_monitor.db
  python3 scripts/audit_db_consistency.py --config /opt/pqc-monitor/config/config.yaml
  python3 scripts/audit_db_consistency.py --no-sql         # skip suggested SQL
  python3 scripts/audit_db_consistency.py --severity warn  # hide INFO findings

Exit codes: 0 = no findings, 1 = findings reported, 2 = execution error.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Geo table (reuse the app's loader; self-contained fallback) ───────────────

GENERIC_TLDS = frozenset({
    "com", "net", "org", "io", "gov", "edu", "mil", "int",
    "co", "info", "biz", "name", "pro", "aero", "coop", "museum",
    "app", "dev", "cloud", "online", "site", "web", "store",
    "tech", "digital", "global", "world",
})

def load_geo_table() -> dict[str, dict]:
    try:
        from data.geo_inference import _load_table, GENERIC_TLDS as G
        globals()["GENERIC_TLDS"] = G
        return _load_table()
    except Exception:
        pass
    table: dict[str, dict] = {}
    csv_path = os.path.join(ROOT, "data", "tld_geo.csv")
    if not os.path.exists(csv_path):
        return table
    with open(csv_path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",", 3)]
            if len(parts) == 4 and parts[0]:
                table[parts[0].lower()] = {
                    "country_code": parts[1].upper(),
                    "country": parts[2],
                    "region": parts[3],
                }
    return table

# ── Domain helpers ────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+$")

# second-level labels under ccTLDs that act as public suffixes
_CC_SLD = frozenset({"co", "com", "org", "net", "gov", "gob", "gouv",
                     "edu", "ac", "mil", "nic", "or", "ne"})

def norm_domain(value: str) -> str:
    """Lowercased, trailing-dot-stripped form. Does NOT repair malformed values."""
    return (value or "").strip().rstrip(".").lower()

def is_wellformed(value: str) -> bool:
    return bool(_DOMAIN_RE.match(norm_domain(value)))

def tld_of(domain: str) -> str:
    return norm_domain(domain).rsplit(".", 1)[-1]

def registrable(domain: str) -> str:
    """Approximate eTLD+1 (handles common ccTLD second levels like co.uk)."""
    labels = norm_domain(domain).split(".")
    if len(labels) < 2:
        return norm_domain(domain)
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _CC_SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def norm_org_name(name: str) -> str:
    """Lowercase, strip punctuation and common legal suffixes for comparison."""
    n = re.sub(r"[^\w\s]", " ", (name or "").lower())
    n = re.sub(r"\b(sa|s\s?a|plc|ltd|llc|gmbh|ag|nv|spa|inc|srl|bv|ab|as|oyj)\b", " ", n)
    return re.sub(r"\s+", " ", n).strip()

# ── Findings model ────────────────────────────────────────────────────────────

SEV_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}

@dataclass
class Finding:
    severity: str
    section: str
    message: str
    fix_sql: list[str] = field(default_factory=list)

class Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, severity: str, section: str, message: str,
            fix_sql: list[str] | None = None) -> None:
        self.findings.append(Finding(severity, section, message, fix_sql or []))

# ── DB access (read-only) ─────────────────────────────────────────────────────

def open_ro(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn

def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None

def sq(value: str) -> str:
    """SQL single-quote a string literal for the suggested-fix output."""
    return "'" + str(value).replace("'", "''") + "'"

# ── Data loading ──────────────────────────────────────────────────────────────

DOMAIN_TABLES = ["raw_scans", "assessments", "ct_queries", "ct_certificates",
                 "domain_extra", "roadmaps", "domain_organisations"]

def load_state(conn: sqlite3.Connection) -> dict:
    st: dict = {}
    st["orgs"] = {r["id"]: dict(r) for r in conn.execute(
        "SELECT id, name, sector, region, country_code, country FROM organisations")}
    st["communities"] = {r["id"]: dict(r) for r in conn.execute(
        "SELECT id, name FROM communities")}
    st["dom_org"] = [dict(r) for r in conn.execute(
        "SELECT domain, org_id FROM domain_organisations")]
    st["comm_org"] = [dict(r) for r in conn.execute(
        "SELECT community_id, org_id FROM community_organisations")]
    st["domain_lists"] = [dict(r) for r in conn.execute(
        "SELECT id, name, domains_json FROM domain_lists")]

    scanned: set[str] = set()
    raw_forms: dict[str, set[str]] = defaultdict(set)   # norm → raw variants seen
    for tbl in ("assessments", "raw_scans"):
        for (d,) in conn.execute(f"SELECT DISTINCT domain FROM {tbl}"):
            if d is None:
                continue
            scanned.add(norm_domain(d))
            raw_forms[norm_domain(d)].add(d)
    st["scanned"] = scanned

    list_domains: set[str] = set()
    st["broken_lists"] = []
    st["list_dupes"] = []
    for row in st["domain_lists"]:
        try:
            doms = json.loads(row["domains_json"] or "[]")
            assert isinstance(doms, list)
        except Exception:
            st["broken_lists"].append(row)
            continue
        if not doms:
            st["broken_lists"].append(row)
            continue
        seen: set[str] = set()
        for d in doms:
            nd = norm_domain(str(d))
            if nd in seen:
                st["list_dupes"].append((row, nd))
            seen.add(nd)
            list_domains.add(nd)
            raw_forms[nd].add(str(d))
    st["list_domains"] = list_domains
    st["raw_forms"] = raw_forms

    for row in st["dom_org"]:
        raw_forms[norm_domain(row["domain"])].add(row["domain"])

    st["universe"] = scanned | list_domains
    return st

# ── Checks ────────────────────────────────────────────────────────────────────

def check_referential(conn, st, rep: Report) -> None:
    sec = "A. Referential integrity"
    org_ids = set(st["orgs"])
    comm_ids = set(st["communities"])
    user_ids = {r[0] for r in conn.execute("SELECT id FROM users")}
    list_ids = {r["id"] for r in st["domain_lists"]}

    pairs = [
        ("domain_organisations", "org_id", org_ids),
        ("community_organisations", "org_id", org_ids),
        ("community_organisations", "community_id", comm_ids),
        ("user_organisations", "org_id", org_ids),
        ("user_organisations", "user_id", user_ids),
        ("user_communities", "community_id", comm_ids),
        ("user_communities", "user_id", user_ids),
        ("user_domain_lists", "list_id", list_ids),
        ("user_domain_lists", "user_id", user_ids),
    ]
    for tbl, col, valid in pairs:
        if not table_exists(conn, tbl):
            continue
        try:
            rows = conn.execute(f"SELECT DISTINCT {col} FROM {tbl}").fetchall()
        except sqlite3.OperationalError:
            continue  # column name differs on this schema version
        for (val,) in rows:
            if val not in valid:
                rep.add("ERROR", sec,
                        f"{tbl}.{col}={val} references a missing row",
                        [f"DELETE FROM {tbl} WHERE {col}={val};"])

def check_unassigned(conn, st, rep: Report) -> None:
    sec = "B. Unassigned"
    assigned = {norm_domain(r["domain"]) for r in st["dom_org"]}
    unassigned = sorted(st["universe"] - assigned)
    for d in unassigned:
        origin = []
        if d in st["scanned"]:
            origin.append("scans")
        if d in st["list_domains"]:
            origin.append("domain_lists")
        rep.add("INFO", sec,
                f"domain {d!r} ({'+'.join(origin)}) is not assigned to any organisation",
                [f"INSERT INTO domain_organisations(domain, org_id, assigned_at) "
                 f"VALUES({sq(d)}, /*ORG_ID*/, strftime('%Y-%m-%dT%H:%M:%fZ','now'));"])

    in_comm = {r["org_id"] for r in st["comm_org"]}
    for oid, org in sorted(st["orgs"].items()):
        if oid not in in_comm:
            rep.add("INFO", sec,
                    f"organisation [{oid}] {org['name']!r} belongs to no community",
                    [f"INSERT INTO community_organisations(community_id, org_id, added_at) "
                     f"VALUES(/*COMMUNITY_ID*/, {oid}, strftime('%Y-%m-%dT%H:%M:%fZ','now'));"])

def check_empty(conn, st, rep: Report) -> None:
    sec = "C. Empty groups"
    orgs_with_domains = {r["org_id"] for r in st["dom_org"]}
    for oid, org in sorted(st["orgs"].items()):
        if oid not in orgs_with_domains:
            rep.add("INFO", sec,
                    f"organisation [{oid}] {org['name']!r} has no domains",
                    [f"DELETE FROM organisations WHERE id={oid};  -- if truly obsolete"])
    comms_with_orgs = {r["community_id"] for r in st["comm_org"]}
    for cid, comm in sorted(st["communities"].items()):
        if cid not in comms_with_orgs:
            rep.add("INFO", sec,
                    f"community [{cid}] {comm['name']!r} has no organisations",
                    [f"DELETE FROM communities WHERE id={cid};  -- if truly obsolete"])
    for row in st["broken_lists"]:
        rep.add("WARN", sec,
                f"domain_list [{row['id']}] {row['name']!r} is empty or has invalid domains_json",
                [f"DELETE FROM domain_lists WHERE id={row['id']};  -- if truly obsolete"])

def check_duplicates(conn, st, rep: Report) -> None:
    sec = "D. Duplicates"
    # 1. same domain in several organisations
    by_domain: dict[str, list[int]] = defaultdict(list)
    for r in st["dom_org"]:
        by_domain[norm_domain(r["domain"])].append(r["org_id"])
    for d, oids in sorted(by_domain.items()):
        if len(set(oids)) > 1:
            names = ", ".join(f"[{o}] {st['orgs'].get(o, {}).get('name', '?')}"
                              for o in sorted(set(oids)))
            rep.add("WARN", sec,
                    f"domain {d!r} is assigned to multiple organisations: {names}",
                    [f"DELETE FROM domain_organisations WHERE domain={sq(d)} "
                     f"AND org_id=/*WRONG_ORG_ID*/;"])

    # 2. case / trailing-dot variants of the same domain
    for nd, forms in sorted(st["raw_forms"].items()):
        if len(forms) > 1:
            rep.add("WARN", sec,
                    f"domain {nd!r} stored under {len(forms)} raw variants: "
                    f"{sorted(forms)} — dashboard/latest-row lookups may split",
                    [f"UPDATE {t} SET domain={sq(nd)} WHERE domain IN "
                     f"({', '.join(sq(f) for f in sorted(forms) if f != nd)}); "
                     f"-- table: {t}; beware PK collisions (see fix_mx_entries.py)"
                     for t in DOMAIN_TABLES])

    # 3. identical / similar organisation names
    items = [(oid, o["name"], norm_org_name(o["name"])) for oid, o in st["orgs"].items()]
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            if not a[2] or not b[2]:
                continue
            if a[2] == b[2]:
                rep.add("WARN", sec,
                        f"organisations [{a[0]}] {a[1]!r} and [{b[0]}] {b[1]!r} "
                        f"have equivalent names",
                        [f"-- merge: UPDATE domain_organisations SET org_id={a[0]} WHERE org_id={b[0]};",
                         f"-- then:  DELETE FROM organisations WHERE id={b[0]};"])
            else:
                ratio = difflib.SequenceMatcher(None, a[2], b[2]).ratio()
                if ratio >= 0.87:
                    rep.add("WARN", sec,
                            f"organisations [{a[0]}] {a[1]!r} and [{b[0]}] {b[1]!r} "
                            f"have similar names (ratio {ratio:.2f}) — possible duplicate")

    # 4. different organisations sharing a registrable domain
    reg_orgs: dict[str, set[int]] = defaultdict(set)
    for r in st["dom_org"]:
        reg_orgs[registrable(r["domain"])].add(r["org_id"])
    for reg, oids in sorted(reg_orgs.items()):
        if len(oids) > 1:
            names = ", ".join(f"[{o}] {st['orgs'].get(o, {}).get('name', '?')}"
                              for o in sorted(oids))
            rep.add("WARN", sec,
                    f"registrable domain {reg!r} has hosts spread across "
                    f"multiple organisations: {names}")

    # 5. duplicates inside a domain_list
    for row, nd in st["list_dupes"]:
        rep.add("WARN", sec,
                f"domain_list [{row['id']}] {row['name']!r} contains {nd!r} more than once")

def check_geo(conn, st, rep: Report, geo: dict[str, dict]) -> None:
    sec = "E. Geography"
    if not geo:
        rep.add("WARN", sec, "tld_geo.csv not found — geographic checks skipped")
        return
    cc_index = {}   # country_code → geo entry (first wins)
    for entry in geo.values():
        cc_index.setdefault(entry["country_code"], entry)

    org_domains: dict[int, list[str]] = defaultdict(list)
    for r in st["dom_org"]:
        org_domains[r["org_id"]].append(norm_domain(r["domain"]))

    for oid, org in sorted(st["orgs"].items()):
        cc = (org["country_code"] or "").strip().upper()
        region = (org["region"] or "").strip()
        country = (org["country"] or "").strip()

        if cc and (len(cc) != 2 or not cc.isalpha()):
            rep.add("ERROR", sec,
                    f"organisation [{oid}] {org['name']!r} has invalid "
                    f"country_code {cc!r} (not ISO 3166-1 alpha-2)",
                    [f"UPDATE organisations SET country_code='' WHERE id={oid};"])
            continue
        if cc and cc not in cc_index:
            rep.add("WARN", sec,
                    f"organisation [{oid}] {org['name']!r}: country_code {cc!r} "
                    f"not present in tld_geo.csv — cannot cross-check")

        cctlds = sorted({tld_of(d) for d in org_domains.get(oid, [])
                         if tld_of(d) not in GENERIC_TLDS and tld_of(d) in geo})
        implied = {geo[t]["country_code"] for t in cctlds}

        if len(implied) == 1:
            (icc,) = implied
            ientry = geo[cctlds[0]]
            if cc and cc != icc:
                rep.add("WARN", sec,
                        f"organisation [{oid}] {org['name']!r}: country_code={cc} "
                        f"but its domains' ccTLD .{cctlds[0]} implies {icc} "
                        f"({ientry['country']})",
                        [f"UPDATE organisations SET country_code={sq(icc)}, "
                         f"country={sq(ientry['country'])}, region={sq(ientry['region'])} "
                         f"WHERE id={oid};"])
            elif not cc:
                rep.add("INFO", sec,
                        f"organisation [{oid}] {org['name']!r}: country_code empty "
                        f"but ccTLD .{cctlds[0]} implies {icc} ({ientry['country']})",
                        [f"UPDATE organisations SET country_code={sq(icc)}, "
                         f"country={sq(ientry['country'])}, region={sq(ientry['region'])} "
                         f"WHERE id={oid};"])
        elif len(implied) > 1 and cc:
            rep.add("INFO", sec,
                    f"organisation [{oid}] {org['name']!r}: country_code={cc} but its "
                    f"domains span several ccTLDs ({', '.join('.' + t for t in cctlds)}) "
                    f"— verify the grouping")

        if cc in cc_index:
            entry = cc_index[cc]
            if region and entry["region"] and region.lower() != entry["region"].lower():
                rep.add("WARN", sec,
                        f"organisation [{oid}] {org['name']!r}: region={region!r} but "
                        f"tld_geo maps {cc} to {entry['region']!r}",
                        [f"UPDATE organisations SET region={sq(entry['region'])} WHERE id={oid};"])
            if country and entry["country"] and country.lower() != entry["country"].lower():
                rep.add("WARN", sec,
                        f"organisation [{oid}] {org['name']!r}: country={country!r} but "
                        f"tld_geo maps {cc} to {entry['country']!r}",
                        [f"UPDATE organisations SET country={sq(entry['country'])} WHERE id={oid};"])
        if region and not cc:
            rep.add("INFO", sec,
                    f"organisation [{oid}] {org['name']!r} has region={region!r} "
                    f"but no country_code")

    # community coherence (informational)
    comm_regions: dict[int, set[str]] = defaultdict(set)
    for r in st["comm_org"]:
        org = st["orgs"].get(r["org_id"])
        if org and (org["region"] or "").strip():
            comm_regions[r["community_id"]].add(org["region"].strip())
    for cid, regions in sorted(comm_regions.items()):
        if len(regions) > 1:
            comm = st["communities"].get(cid, {"name": "?"})
            rep.add("INFO", sec,
                    f"community [{cid}] {comm['name']!r} mixes regions: "
                    f"{sorted(regions)} — fine if intentional")

def check_quality(conn, st, rep: Report) -> None:
    sec = "F. Data quality"
    # 1.9.1 invariant
    rows = conn.execute(
        "SELECT id, domain, level, score FROM assessments "
        "WHERE services_assessed=0 AND level!='na'").fetchall()
    for r in rows:
        rep.add("ERROR", sec,
                f"assessments[{r['id']}] {r['domain']!r}: services_assessed=0 but "
                f"level={r['level']!r} (score {r['score']}) — no-TLS rows must be 'na'",
                [f"DELETE FROM assessments WHERE id={r['id']}; "
                 f"-- or re-run scripts/reassess_all.py"])

    allowed = ("na", "critical", "weak", "moderate", "good", "excellent")
    ph = ",".join("?" * len(allowed))
    for r in conn.execute(
            f"SELECT id, domain, level FROM assessments WHERE level NOT IN ({ph})", allowed):
        rep.add("ERROR", sec,
                f"assessments[{r['id']}] {r['domain']!r}: unknown level {r['level']!r}")

    for r in conn.execute(
            "SELECT id, domain, score FROM assessments "
            "WHERE score IS NOT NULL AND (score < 0 OR score > 100)"):
        rep.add("ERROR", sec,
                f"assessments[{r['id']}] {r['domain']!r}: score {r['score']} out of 0–100")

    # malformed domain values anywhere domain-keyed (the MX-priority bug class)
    for tbl in DOMAIN_TABLES:
        if not table_exists(conn, tbl):
            continue
        for (d,) in conn.execute(f"SELECT DISTINCT domain FROM {tbl}"):
            if d is not None and not is_wellformed(d):
                rep.add("ERROR", sec,
                        f"{tbl}: malformed domain value {d!r}",
                        [f"-- repair with: python3 scripts/fix_mx_entries.py --dry-run"])
    for row in st["domain_lists"]:
        try:
            doms = json.loads(row["domains_json"] or "[]")
        except Exception:
            continue
        for d in doms:
            if not is_wellformed(str(d)):
                rep.add("ERROR", sec,
                        f"domain_list [{row['id']}] {row['name']!r}: malformed entry {d!r}")

    # assigned but never scanned
    assigned = {norm_domain(r["domain"]) for r in st["dom_org"]}
    for d in sorted(assigned - st["scanned"]):
        rep.add("INFO", sec, f"domain {d!r} is assigned to an organisation but has never been scanned")

# ── Output ────────────────────────────────────────────────────────────────────

def print_report(rep: Report, st: dict, min_sev: str, show_sql: bool) -> None:
    keep = [f for f in rep.findings if SEV_ORDER[f.severity] <= SEV_ORDER[min_sev]]
    keep.sort(key=lambda f: (f.section, SEV_ORDER[f.severity], f.message))

    print("=" * 78)
    print("PQC-Monitor — database consistency audit (read-only)")
    print(f"  organisations: {len(st['orgs'])}   communities: {len(st['communities'])}   "
          f"domain universe: {len(st['universe'])}   assignments: {len(st['dom_org'])}")
    print("=" * 78)

    if not keep:
        print("\nNo inconsistencies found.")
        return

    current = None
    for f in keep:
        if f.section != current:
            current = f.section
            print(f"\n{current}\n" + "-" * len(current))
        print(f"  [{f.severity:5s}] {f.message}")

    counts = defaultdict(int)
    for f in keep:
        counts[f.severity] += 1
    print("\n" + "=" * 78)
    print("Summary: " + "  ".join(f"{s}: {counts.get(s, 0)}" for s in ("ERROR", "WARN", "INFO")))

    if show_sql:
        sql = [(f.section, f.message, f.fix_sql) for f in keep if f.fix_sql]
        if sql:
            print("\nSuggested fix SQL — REVIEW BEFORE USE, everything is commented out.")
            print("-- Back up first:  cp /var/lib/pqc-monitor/pqc_monitor.db{,.bak}")
            current = None
            for section, message, stmts in sql:
                if section != current:
                    current = section
                    print(f"\n-- ── {section} " + "─" * max(0, 60 - len(section)))
                print(f"-- {message}")
                for s in stmts:
                    print(s if s.startswith("--") else f"-- {s}")

# ── Main ──────────────────────────────────────────────────────────────────────

def resolve_db_path(args) -> str:
    if args.db:
        return args.db
    try:
        from pqc_monitor import load_config
        cfg = load_config(args.config) or {}
        if cfg.get("db_path"):
            return cfg["db_path"]
    except Exception:
        pass
    return os.path.join(ROOT, "data", "pqc_monitor.db")

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only consistency audit of the PQC-Monitor database.")
    parser.add_argument("--config", help="config.yaml (to locate db_path).")
    parser.add_argument("--db", help="Override the database path directly.")
    parser.add_argument("--no-sql", action="store_true",
                        help="Do not print the suggested fix SQL block.")
    parser.add_argument("--severity", choices=("error", "warn", "info"),
                        default="info", help="Minimum severity to report (default: info).")
    args = parser.parse_args(argv)

    db_path = resolve_db_path(args)
    if not os.path.exists(db_path):
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        return 2

    try:
        conn = open_ro(db_path)
    except sqlite3.Error as exc:
        print(f"ERROR: cannot open {db_path} read-only: {exc}", file=sys.stderr)
        return 2

    try:
        for tbl in ("organisations", "communities", "domain_organisations",
                    "community_organisations", "assessments", "raw_scans",
                    "domain_lists", "users"):
            if not table_exists(conn, tbl):
                print(f"ERROR: table {tbl!r} missing — is this a PQC-Monitor DB "
                      f"at the current schema version?", file=sys.stderr)
                return 2

        st = load_state(conn)
        rep = Report()
        check_referential(conn, st, rep)
        check_unassigned(conn, st, rep)
        check_empty(conn, st, rep)
        check_duplicates(conn, st, rep)
        check_geo(conn, st, rep, load_geo_table())
        check_quality(conn, st, rep)
    finally:
        conn.close()

    print_report(rep, st, args.severity.upper(), not args.no_sql)
    return 1 if rep.findings else 0

if __name__ == "__main__":
    sys.exit(main())
