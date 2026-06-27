#!/usr/bin/env python3
"""
PQC-Monitor: Community feature tests.

Covers:
  - DB layer CRUD (communities, org assignments, user assignments)
  - Auth store: community_ids loading, set_user_communities, auto-promote
  - get_user_domains: community path adds domains additively
  - aggregate report data (build_report, export_csv, export_text)
  - API endpoints via Flask test client

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import sys
import tempfile
import unittest

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_db(path: str):
    from data.database import Database
    return Database(path)


# ══════════════════════════════════════════════════════════════════════════════
# DB-layer tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityDB(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = _make_db(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    # ── Create ────────────────────────────────────────────────────────────────

    def test_create_community(self):
        cid = self.db.create_community("Test Community", description="A test")
        self.assertIsInstance(cid, int)
        self.assertGreater(cid, 0)

    def test_get_community(self):
        cid = self.db.create_community("Alpha Community", description="Desc")
        c   = self.db.get_community(cid)
        self.assertEqual(c["name"],        "Alpha Community")
        self.assertEqual(c["description"], "Desc")

    def test_get_community_not_found(self):
        self.assertIsNone(self.db.get_community(9999))

    def test_get_communities_empty(self):
        self.assertEqual(self.db.get_communities(), [])

    def test_get_communities_lists_all(self):
        self.db.create_community("C1")
        self.db.create_community("C2")
        names = [c["name"] for c in self.db.get_communities()]
        self.assertIn("C1", names)
        self.assertIn("C2", names)

    # ── Update / Delete ───────────────────────────────────────────────────────

    def test_update_community(self):
        cid = self.db.create_community("Old Name")
        ok  = self.db.update_community(cid, name="New Name", description="Updated")
        self.assertTrue(ok)
        c = self.db.get_community(cid)
        self.assertEqual(c["name"],        "New Name")
        self.assertEqual(c["description"], "Updated")

    def test_delete_community(self):
        cid = self.db.create_community("Deletable")
        self.assertTrue(self.db.delete_community(cid))
        self.assertIsNone(self.db.get_community(cid))

    def test_delete_community_not_found(self):
        self.assertFalse(self.db.delete_community(9999))

    # ── Org assignments ───────────────────────────────────────────────────────

    def test_set_and_get_community_orgs(self):
        cid  = self.db.create_community("Banking")
        oid1 = self.db.create_organisation("Bank A")
        oid2 = self.db.create_organisation("Bank B")
        self.db.set_community_orgs(cid, [oid1, oid2])
        orgs = self.db.get_community_orgs(cid)
        org_ids = [o["id"] for o in orgs]
        self.assertIn(oid1, org_ids)
        self.assertIn(oid2, org_ids)

    def test_replace_community_orgs(self):
        cid  = self.db.create_community("Finance")
        oid1 = self.db.create_organisation("Org A")
        oid2 = self.db.create_organisation("Org B")
        self.db.set_community_orgs(cid, [oid1, oid2])
        self.db.set_community_orgs(cid, [oid2])  # remove oid1
        orgs = self.db.get_community_orgs(cid)
        self.assertEqual(len(orgs), 1)
        self.assertEqual(orgs[0]["id"], oid2)

    def test_delete_community_cascades_orgs(self):
        cid = self.db.create_community("To Delete")
        oid = self.db.create_organisation("Orphan Org")
        self.db.set_community_orgs(cid, [oid])
        self.db.delete_community(cid)
        # org still exists; only the join row is gone
        self.assertIsNotNone(self.db.get_organisation(oid))

    # ── Domain resolution via community ───────────────────────────────────────

    def test_get_community_domains(self):
        cid = self.db.create_community("Domain Test")
        oid = self.db.create_organisation("Org With Domains")
        self.db.set_community_orgs(cid, [oid])
        self.db.set_org_domains(oid, ["bank.es", "banca.es"])
        domains = self.db.get_community_domains(cid)
        self.assertIn("bank.es",  domains)
        self.assertIn("banca.es", domains)

    def test_get_community_domains_empty(self):
        cid = self.db.create_community("Empty")
        self.assertEqual(self.db.get_community_domains(cid), [])

    # ── Org count in get_communities ──────────────────────────────────────────

    def test_org_count_in_list(self):
        cid  = self.db.create_community("Count Test")
        oid1 = self.db.create_organisation("Org1")
        oid2 = self.db.create_organisation("Org2")
        self.db.set_community_orgs(cid, [oid1, oid2])
        communities = self.db.get_communities()
        c = next(x for x in communities if x["id"] == cid)
        self.assertEqual(c["org_count"], 2)


# ══════════════════════════════════════════════════════════════════════════════
# Auth store: community_ids + auto-promote
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityAuthStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        # Database must be initialised first so all migrations (incl. v17) run
        from data.database import Database
        self.db = Database(self.tmp.name)
        from auth.store import AuthStore
        self.store = AuthStore(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _create_user(self, username="testuser", role="analyst"):
        user = self.store.create_user(
            username=username, email=f"{username}@test.com",
            password="TestPass1234!", role=role
        )
        return user.id

    def test_community_ids_loaded_on_user(self):
        uid = self._create_user()
        cid = self.db.create_community("Test Community")
        self.store.set_user_communities(uid, [cid])
        user = self.store.get_user_by_id(uid)
        self.assertIn(cid, user.community_ids)

    def test_analyst_auto_promoted_to_community_manager(self):
        uid = self._create_user(role="analyst")
        cid = self.db.create_community("Promo Test")
        self.store.set_user_communities(uid, [cid])
        user = self.store.get_user_by_id(uid)
        self.assertEqual(user.role, "community_manager")

    def test_admin_not_demoted_by_community_assignment(self):
        uid = self._create_user(username="adminuser", role="admin")
        cid = self.db.create_community("Admin Community")
        self.store.set_user_communities(uid, [cid])
        user = self.store.get_user_by_id(uid)
        self.assertEqual(user.role, "admin")

    def test_community_ids_empty_by_default(self):
        uid  = self._create_user()
        user = self.store.get_user_by_id(uid)
        self.assertEqual(user.community_ids, [])

    def test_get_user_domains_includes_community_path(self):
        """Community domains are additive to direct org domains."""
        uid  = self._create_user()
        oid1 = self.db.create_organisation("Direct Org")
        oid2 = self.db.create_organisation("Community Org")
        # Direct org assignment
        self.store.set_user_orgs(uid, [oid1])
        self.db.set_org_domains(oid1, ["direct.es"])
        # Community path
        cid = self.db.create_community("Test Comm")
        self.db.set_community_orgs(cid, [oid2])
        self.db.set_org_domains(oid2, ["community.es"])
        self.store.set_user_communities(uid, [cid])
        domains = self.store.get_user_domains(uid)
        self.assertIn("direct.es",    domains)
        self.assertIn("community.es", domains)

    def test_get_user_domains_no_duplicates(self):
        """Domain appearing in both direct org and community is deduplicated."""
        uid = self._create_user()
        oid = self.db.create_organisation("Shared Org")
        self.db.set_org_domains(oid, ["shared.es"])
        self.store.set_user_orgs(uid, [oid])
        cid = self.db.create_community("Comm")
        self.db.set_community_orgs(cid, [oid])
        self.store.set_user_communities(uid, [cid])
        domains = self.store.get_user_domains(uid)
        self.assertEqual(domains.count("shared.es"), 1)


# ══════════════════════════════════════════════════════════════════════════════
# Report generation (no Flask needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityReport(unittest.TestCase):

    def _sample_rows(self):
        return [
            {"id": 1, "name": "Bank A", "country_code": "ES", "country": "Spain",
             "sector": "Finance", "region": "Europe", "domain_count": 10,
             "avg_score": 82.5, "critical": 0, "weak": 1, "moderate": 3,
             "ready": 6, "no_tls": 0, "pqc_count": 2},
            {"id": 2, "name": "Bank B", "country_code": "ES", "country": "Spain",
             "sector": "Finance", "region": "Europe", "domain_count": 5,
             "avg_score": 25.0, "critical": 3, "weak": 1, "moderate": 1,
             "ready": 0, "no_tls": 0, "pqc_count": 0},
        ]

    def test_build_report_structure(self):
        from reports.community_report import build_report
        rows   = self._sample_rows()
        report = build_report("Spanish Banks", "Community", rows)
        self.assertEqual(report["group_name"], "Spanish Banks")
        self.assertEqual(report["group_type"], "Community")
        self.assertIn("summary",       report)
        self.assertIn("totals",        report)
        self.assertIn("organisations", report)
        self.assertEqual(len(report["organisations"]), 2)

    def test_totals_calculation(self):
        from reports.community_report import build_report
        rows   = self._sample_rows()
        report = build_report("Test", "Community", rows)
        t = report["totals"]
        self.assertEqual(t["domain_count"], 15)
        self.assertEqual(t["critical"],     3)
        self.assertEqual(t["ready"],        6)
        self.assertEqual(t["pqc_count"],    2)
        self.assertAlmostEqual(t["avg_score"], (82.5 + 25.0) / 2, places=1)

    def test_export_csv_contains_headers(self):
        from reports.community_report import build_report, export_csv
        report = build_report("Test", "Community", self._sample_rows())
        csv    = export_csv(report)
        self.assertIn("Organisation", csv)
        self.assertIn("Avg Score",    csv)
        self.assertIn("Bank A",       csv)
        self.assertIn("Bank B",       csv)
        self.assertIn("TOTALS",       csv)

    def test_export_text_contains_summary(self):
        from reports.community_report import build_report, export_text
        report = build_report("Spanish Banks", "Community", self._sample_rows())
        text   = export_text(report)
        self.assertIn("Spanish Banks", text)
        self.assertIn("EXECUTIVE SUMMARY", text)
        self.assertIn("Bank A", text)

    def test_executive_summary_pqc_detected(self):
        from reports.community_report import build_report
        rows   = self._sample_rows()
        report = build_report("Test", "Community", rows)
        # pqc_count=2 so summary should mention PQC detection
        self.assertIn("post-quantum", report["summary"].lower())

    def test_executive_summary_no_pqc(self):
        from reports.community_report import build_report
        rows = self._sample_rows()
        for r in rows:
            r["pqc_count"] = 0
        report = build_report("No PQC Group", "Community", rows)
        self.assertIn("no post-quantum", report["summary"].lower())

    def test_region_report_label(self):
        from reports.community_report import build_report
        report = build_report("Europe", "Region", self._sample_rows())
        self.assertEqual(report["group_type"], "Region")
        self.assertIn("Europe", report["summary"])


# ══════════════════════════════════════════════════════════════════════════════
# DB aggregate helper
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityAggregate(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = _make_db(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_aggregate_empty_community(self):
        cid    = self.db.create_community("Empty")
        result = self.db.get_community_aggregate(cid)
        self.assertEqual(result, [])

    def test_aggregate_org_no_domains(self):
        cid = self.db.create_community("No Domains")
        oid = self.db.create_organisation("Empty Org")
        self.db.set_community_orgs(cid, [oid])
        result = self.db.get_community_aggregate(cid)
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0]["avg_score"])

    def test_region_aggregate(self):
        oid = self.db.create_organisation("EU Org", region="Europe")
        result = self.db.get_region_aggregate("Europe")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "EU Org")

    def test_region_aggregate_case_insensitive(self):
        self.db.create_organisation("EU Org2", region="Europe")
        result = self.db.get_region_aggregate("europe")
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
