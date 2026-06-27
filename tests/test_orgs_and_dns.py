#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — Organisations (T-ORG) and DNSDumpster API key

Covers:
  - Migration v14: organisations, domain_organisations, user_organisations tables
  - Organisation CRUD (database layer)
  - Domain↔org assignment + get_org_domains_for_user
  - User↔org assignment (AuthStore)
  - filter_assessments respects org-derived domain access
  - get_latest_assessments includes org_id / org_name columns
  - Admin API: /admin/api/organisations CRUD, domain and user assignment
  - App API: /app/api/assessments ?org_id= and ?region= filters
  - App API: /app/api/organisations returns org list (scoped for analysts)
  - DNSDumpster: use_dnsdumpster defaults to False in enumerate_domain
  - DNSDumpster: api_key routed to _dnsdumpster_api, no key → _dnsdumpster_scrape
  - DNS_ENUM_CONFIG wired into app from create_app
  - config.yaml dns_enumeration block loaded by load_config

All tests are fully offline.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.database import Database
from auth.store import AuthStore


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _make_db(path: str) -> Database:
    return Database(path)


def _make_app(db_path: str):
    import auth.auth_routes as _ar
    _ar._login_attempts.clear()
    from app_factory import create_app
    app = create_app({
        "db_path": db_path,
        "secret_key": "test-secret-32-chars-exactly!!!",
        "https_enabled": False,
    })
    app.config["TESTING"] = True
    return app


def _login_admin(client):
    client.post("/login", data={"username": "admin", "password": "changeme123"},
                follow_redirects=True)
    return client


def _seed_assessment(db, domain, score=60, service_type=None):
    run_id = db.create_run([domain])
    db.save_assessment(run_id, {
        "domain": domain,
        "assessment_timestamp": "2026-06-12T00:00:00+00:00",
        "guidelines_used": [],
        "score": score,
        "level": "moderate",
        "findings": [],
        "tls_versions_found": [],
        "cipher_suites_found": [],
        "has_pqc": False,
        "certificate_expiry_days": None,
        "errors": [],
        "service_type": service_type,
    })
    db.finish_run(run_id, "completed")
    return run_id


# ══════════════════════════════════════════════════════════════════
# Migration v14
# ══════════════════════════════════════════════════════════════════

class TestMigrationV14(unittest.TestCase):

    def test_tables_exist_after_migration(self):
        with tempfile.TemporaryDirectory() as td:
            db = _make_db(os.path.join(td, "test.db"))
            with db._connect() as conn:
                tables = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
            for t in ("organisations", "domain_organisations", "user_organisations"):
                self.assertIn(t, tables)

    def test_schema_version_reaches_14(self):
        with tempfile.TemporaryDirectory() as td:
            db = _make_db(os.path.join(td, "test.db"))
            with db._connect() as conn:
                v = conn.execute(
                    "SELECT MAX(version) FROM schema_version"
                ).fetchone()[0]
            self.assertGreaterEqual(v, 14)


# ══════════════════════════════════════════════════════════════════
# Database — Organisation CRUD
# ══════════════════════════════════════════════════════════════════

class TestOrgDatabaseCRUD(unittest.TestCase):

    def setUp(self):
        self.td  = tempfile.mkdtemp()
        self.db  = _make_db(os.path.join(self.td, "test.db"))

    def test_create_and_get(self):
        oid = self.db.create_organisation("Acme Bank", sector="Finance",
                                           region="EU")
        org = self.db.get_organisation(oid)
        self.assertEqual(org["name"],   "Acme Bank")
        self.assertEqual(org["sector"], "Finance")
        self.assertEqual(org["region"], "EU")

    def test_get_organisations_includes_domain_count(self):
        oid = self.db.create_organisation("Test Corp")
        self.db.set_org_domains(oid, ["a.com", "b.com"])
        orgs = self.db.get_organisations()
        match = next(o for o in orgs if o["id"] == oid)
        self.assertEqual(match["domain_count"], 2)

    def test_update_organisation(self):
        oid = self.db.create_organisation("Old Name")
        ok  = self.db.update_organisation(oid, name="New Name", region="LATAM")
        self.assertTrue(ok)
        org = self.db.get_organisation(oid)
        self.assertEqual(org["name"],   "New Name")
        self.assertEqual(org["region"], "LATAM")

    def test_create_organisation_with_country(self):
        oid = self.db.create_organisation(
            "Country Bank", sector="Finance", region="EU",
            country_code="DE", country="Germany"
        )
        org = self.db.get_organisation(oid)
        self.assertEqual(org["country_code"], "DE")
        self.assertEqual(org["country"],      "Germany")

    def test_update_organisation_country(self):
        oid = self.db.create_organisation("Multi Bank", country_code="ES", country="Spain")
        ok  = self.db.update_organisation(oid, country_code="FR", country="France")
        self.assertTrue(ok)
        org = self.db.get_organisation(oid)
        self.assertEqual(org["country_code"], "FR")
        self.assertEqual(org["country"],      "France")

    def test_country_defaults_to_empty(self):
        oid = self.db.create_organisation("No Country Corp")
        org = self.db.get_organisation(oid)
        self.assertEqual(org.get("country_code", ""), "")
        self.assertEqual(org.get("country",      ""), "")

    def test_delete_organisation(self):
        oid = self.db.create_organisation("To Delete")
        self.db.delete_organisation(oid)
        self.assertIsNone(self.db.get_organisation(oid))

    def test_delete_cascades_domain_assignments(self):
        oid = self.db.create_organisation("Cascade Test")
        self.db.set_org_domains(oid, ["x.com"])
        self.db.delete_organisation(oid)
        with self.db._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_organisations WHERE org_id=?", (oid,)
            ).fetchall()
        self.assertEqual(len(rows), 0)

    def test_update_nonexistent_returns_false(self):
        ok = self.db.update_organisation(99999, name="ghost")
        self.assertFalse(ok)

    def test_get_organisations_includes_domains_list(self):
        oid = self.db.create_organisation("With Domains")
        self.db.set_org_domains(oid, ["one.com", "two.com"])
        orgs = self.db.get_organisations()
        match = next(o for o in orgs if o["id"] == oid)
        self.assertIn("domains", match)
        self.assertIn("one.com", match["domains"])


# ══════════════════════════════════════════════════════════════════
# Database — Domain↔Org assignment
# ══════════════════════════════════════════════════════════════════

class TestDomainOrgAssignment(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.db = _make_db(os.path.join(self.td, "test.db"))
        self.oid = self.db.create_organisation("Bank A")

    def test_set_and_get_org_domains(self):
        self.db.set_org_domains(self.oid, ["alpha.com", "beta.com"])
        domains = self.db.get_org_domains(self.oid)
        self.assertEqual(sorted(domains), ["alpha.com", "beta.com"])

    def test_set_org_domains_replaces_previous(self):
        self.db.set_org_domains(self.oid, ["old.com"])
        self.db.set_org_domains(self.oid, ["new.com"])
        domains = self.db.get_org_domains(self.oid)
        self.assertNotIn("old.com", domains)
        self.assertIn("new.com", domains)

    def test_get_domain_org(self):
        self.db.set_org_domains(self.oid, ["tagged.com"])
        org = self.db.get_domain_org("tagged.com")
        self.assertIsNotNone(org)
        self.assertEqual(org["id"], self.oid)

    def test_get_domain_org_unassigned_returns_none(self):
        self.assertIsNone(self.db.get_domain_org("unassigned.com"))

    def test_get_assessments_by_org(self):
        oid2 = self.db.create_organisation("Bank B")
        self.db.set_org_domains(self.oid, ["a1.com"])
        self.db.set_org_domains(oid2,     ["b1.com"])
        _seed_assessment(self.db, "a1.com", score=70)
        _seed_assessment(self.db, "b1.com", score=40)
        rows = self.db.get_assessments_by_org(self.oid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "a1.com")

    def test_get_latest_assessments_includes_org_columns(self):
        self.db.set_org_domains(self.oid, ["tagged.com"])
        _seed_assessment(self.db, "tagged.com", score=65)
        rows = self.db.get_latest_assessments()
        match = next((r for r in rows if r["domain"] == "tagged.com"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["org_id"],   self.oid)
        self.assertEqual(match["org_name"], "Bank A")

    def test_get_latest_assessments_org_id_null_for_untagged(self):
        _seed_assessment(self.db, "untagged.com", score=50)
        rows = self.db.get_latest_assessments()
        match = next((r for r in rows if r["domain"] == "untagged.com"), None)
        self.assertIsNotNone(match)
        self.assertIsNone(match.get("org_id"))


# ══════════════════════════════════════════════════════════════════
# AuthStore — User↔Org assignment
# ══════════════════════════════════════════════════════════════════

class TestUserOrgAssignment(unittest.TestCase):

    def setUp(self):
        self.td    = tempfile.mkdtemp()
        db_path    = os.path.join(self.td, "test.db")
        self.db    = _make_db(db_path)
        self.store = AuthStore(db_path)
        self.oid   = self.db.create_organisation("Corp X")

    def _make_analyst(self):
        return self.store.create_user("analyst1", "a@test.com", "AnalystPass1!", "analyst")

    def test_set_and_load_user_org_ids(self):
        user = self._make_analyst()
        self.store.set_user_orgs(user.id, [self.oid])
        reloaded = self.store.get_user_by_id(user.id)
        self.assertIn(self.oid, reloaded.org_ids)

    def test_org_ids_in_to_dict(self):
        user = self._make_analyst()
        self.store.set_user_orgs(user.id, [self.oid])
        reloaded = self.store.get_user_by_id(user.id)
        d = reloaded.to_dict()
        self.assertIn("org_ids", d)
        self.assertIn(self.oid, d["org_ids"])

    def test_set_user_orgs_replaces_previous(self):
        oid2 = self.db.create_organisation("Corp Y")
        user = self._make_analyst()
        self.store.set_user_orgs(user.id, [self.oid])
        self.store.set_user_orgs(user.id, [oid2])
        reloaded = self.store.get_user_by_id(user.id)
        self.assertNotIn(self.oid, reloaded.org_ids)
        self.assertIn(oid2, reloaded.org_ids)

    def test_get_user_domains_includes_org_domains(self):
        self.db.set_org_domains(self.oid, ["orgdomain.com"])
        user = self._make_analyst()
        self.store.set_user_orgs(user.id, [self.oid])
        domains = self.store.get_user_domains(user.id)
        self.assertIn("orgdomain.com", domains)

    def test_get_user_domains_deduplicates(self):
        """Domain appearing in both a domain list and an org should appear once."""
        self.db.set_org_domains(self.oid, ["shared.com"])
        list_id = self.db.save_domain_list("list1", ["shared.com", "other.com"])
        user = self._make_analyst()
        self.store.set_user_orgs(user.id, [self.oid])
        self.store.set_domain_lists(user.id, [list_id])
        domains = self.store.get_user_domains(user.id)
        self.assertEqual(domains.count("shared.com"), 1)


# ══════════════════════════════════════════════════════════════════
# Admin API — Organisations
# ══════════════════════════════════════════════════════════════════

class TestAdminOrgAPI(unittest.TestCase):

    def setUp(self):
        self.td  = tempfile.mkdtemp()
        db_path  = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.db  = self.app.config["PQC_DB"]
        self.client = _login_admin(self.app.test_client())

    def test_create_org(self):
        r = self.client.post("/admin/api/organisations",
                             json={"name": "Test Org", "sector": "Finance",
                                   "region": "EU"},
                             content_type="application/json")
        self.assertEqual(r.status_code, 201)
        d = json.loads(r.data)
        self.assertEqual(d["name"], "Test Org")
        self.assertIn("id", d)

    def test_create_org_missing_name_returns_400(self):
        r = self.client.post("/admin/api/organisations", json={},
                             content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_list_orgs(self):
        self.db.create_organisation("Alpha", region="US")
        self.db.create_organisation("Beta",  region="EU")
        r = self.client.get("/admin/api/organisations")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        names = [o["name"] for o in data]
        self.assertIn("Alpha", names)
        self.assertIn("Beta",  names)

    def test_get_org_includes_domains(self):
        oid = self.db.create_organisation("With Doms")
        self.db.set_org_domains(oid, ["d1.com", "d2.com"])
        r = self.client.get(f"/admin/api/organisations/{oid}")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertIn("d1.com", d["domains"])

    def test_update_org(self):
        oid = self.db.create_organisation("Before")
        r = self.client.patch(f"/admin/api/organisations/{oid}",
                              json={"name": "After", "region": "APAC"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["name"],   "After")
        self.assertEqual(d["region"], "APAC")

    def test_create_org_with_country(self):
        r = self.client.post("/admin/api/organisations",
                             json={"name": "ISO Bank", "country_code": "ES",
                                   "country": "Spain"},
                             content_type="application/json")
        self.assertEqual(r.status_code, 201)
        d = json.loads(r.data)
        self.assertEqual(d["country_code"], "ES")
        self.assertEqual(d["country"],      "Spain")

    def test_update_org_country(self):
        oid = self.db.create_organisation("Patch Country", country_code="PT",
                                           country="Portugal")
        r = self.client.patch(f"/admin/api/organisations/{oid}",
                              json={"country_code": "IT", "country": "Italy"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["country_code"], "IT")
        self.assertEqual(d["country"],      "Italy")

    def test_list_orgs_includes_country(self):
        self.db.create_organisation("CountryAlpha", country_code="FR",
                                     country="France")
        r = self.client.get("/admin/api/organisations")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        match = next((o for o in data if o["name"] == "CountryAlpha"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["country_code"], "FR")
        self.assertEqual(match["country"],      "France")

    def test_delete_org(self):
        oid = self.db.create_organisation("To Del")
        r = self.client.delete(f"/admin/api/organisations/{oid}")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(self.db.get_organisation(oid))

    def test_set_org_domains(self):
        oid = self.db.create_organisation("Domains Test")
        r = self.client.put(f"/admin/api/organisations/{oid}/domains",
                             json={"domains": ["x.com", "y.com"]},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["domain_count"], 2)
        self.assertEqual(sorted(self.db.get_org_domains(oid)), ["x.com", "y.com"])

    def test_set_user_orgs(self):
        store = self.app.config["AUTH_STORE"]
        user  = store.create_user("analyst_org", "ao@test.com",
                                   "AnalystPass1!", "analyst")
        oid   = self.db.create_organisation("User Org Test")
        r = self.client.put(f"/admin/api/users/{user.id}/orgs",
                             json={"org_ids": [oid]},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        reloaded = store.get_user_by_id(user.id)
        self.assertIn(oid, reloaded.org_ids)

    def test_get_user_orgs(self):
        store = self.app.config["AUTH_STORE"]
        user  = store.create_user("analyst_org2", "ao2@test.com",
                                   "AnalystPass1!", "analyst")
        oid   = self.db.create_organisation("Visible Org")
        store.set_user_orgs(user.id, [oid])
        r = self.client.get(f"/admin/api/users/{user.id}/orgs")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        assigned = [o for o in data if o.get("assigned")]
        self.assertEqual(len(assigned), 1)
        self.assertEqual(assigned[0]["id"], oid)


# ══════════════════════════════════════════════════════════════════
# App API — ?org_id= and ?region= filters
# ══════════════════════════════════════════════════════════════════

class TestAssessmentsOrgFilter(unittest.TestCase):

    def setUp(self):
        self.td  = tempfile.mkdtemp()
        db_path  = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.db  = self.app.config["PQC_DB"]
        self.client = _login_admin(self.app.test_client())

        self.oid_eu = self.db.create_organisation("EU Bank",  region="EU")
        self.oid_us = self.db.create_organisation("US Bank",  region="US")
        self.db.set_org_domains(self.oid_eu, ["eu.com"])
        self.db.set_org_domains(self.oid_us, ["us.com"])
        _seed_assessment(self.db, "eu.com", score=70)
        _seed_assessment(self.db, "us.com", score=55)

    def test_filter_by_org_id(self):
        r = self.client.get(f"/app/api/assessments?org_id={self.oid_eu}")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["domain"], "eu.com")

    def test_filter_by_region(self):
        r = self.client.get("/app/api/assessments?region=US")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        domains = [d["domain"] for d in data]
        self.assertIn("us.com", domains)
        self.assertNotIn("eu.com", domains)

    def test_no_filter_returns_all(self):
        r = self.client.get("/app/api/assessments")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        domains = [d["domain"] for d in data]
        self.assertIn("eu.com", domains)
        self.assertIn("us.com", domains)

    def test_assessments_include_org_id(self):
        r = self.client.get("/app/api/assessments")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        eu_row = next(d for d in data if d["domain"] == "eu.com")
        self.assertEqual(eu_row["org_id"],   self.oid_eu)
        self.assertEqual(eu_row["org_name"], "EU Bank")


class TestAppOrgEndpoint(unittest.TestCase):

    def setUp(self):
        self.td  = tempfile.mkdtemp()
        db_path  = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.db  = self.app.config["PQC_DB"]

    def test_admin_sees_all_orgs(self):
        self.db.create_organisation("Org A")
        self.db.create_organisation("Org B")
        client = _login_admin(self.app.test_client())
        r = client.get("/app/api/organisations")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertGreaterEqual(len(data), 2)

    def test_analyst_sees_only_assigned_orgs(self):
        store = self.app.config["AUTH_STORE"]
        oid1  = self.db.create_organisation("Assigned")
        oid2  = self.db.create_organisation("Not Assigned")
        user  = store.create_user("anal_test", "at@x.com", "AnalystPass1!", "analyst")
        store.set_user_orgs(user.id, [oid1])
        client = self.app.test_client()
        client.post("/login", data={"username": "anal_test",
                                     "password": "AnalystPass1!"},
                    follow_redirects=True)
        r = client.get("/app/api/organisations")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        org_ids = [o["id"] for o in data]
        self.assertIn(oid1, org_ids)
        self.assertNotIn(oid2, org_ids)


# ══════════════════════════════════════════════════════════════════
# RBAC: analyst org scoping in filter_assessments
# ══════════════════════════════════════════════════════════════════

class TestAnalystOrgScoping(unittest.TestCase):

    def setUp(self):
        self.td    = tempfile.mkdtemp()
        db_path    = os.path.join(self.td, "test.db")
        self.app   = _make_app(db_path)
        self.db    = self.app.config["PQC_DB"]
        self.store = self.app.config["AUTH_STORE"]

    def test_analyst_sees_org_domains_via_assessments(self):
        oid   = self.db.create_organisation("Scoped Org")
        self.db.set_org_domains(oid, ["scoped.com"])
        _seed_assessment(self.db, "scoped.com")
        _seed_assessment(self.db, "other.com")

        user  = self.store.create_user("scoped_user", "su@x.com",
                                        "AnalystPass1!", "analyst")
        self.store.set_user_orgs(user.id, [oid])

        client = self.app.test_client()
        client.post("/login", data={"username": "scoped_user",
                                     "password": "AnalystPass1!"},
                    follow_redirects=True)
        r = client.get("/app/api/assessments")
        data = json.loads(r.data)
        domains = [d["domain"] for d in data]
        self.assertIn("scoped.com",  domains)
        self.assertNotIn("other.com", domains)


# ══════════════════════════════════════════════════════════════════
# DNSDumpster API key changes
# ══════════════════════════════════════════════════════════════════

class TestDNSDumpsterAPIKey(unittest.TestCase):

    def test_use_dnsdumpster_defaults_false(self):
        """enumerate_domain should NOT call DNSDumpster unless explicitly enabled."""
        from scanner.dns_enumerator import enumerate_domain
        with patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"]), \
             patch("scanner.dns_enumerator._wordlist_subdomains", return_value=[]), \
             patch("scanner.dns_enumerator._ct_sans", return_value=[]), \
             patch("scanner.dns_enumerator._dnsdumpster_subdomains") as mock_dd:
            enumerate_domain("example.com")
            mock_dd.assert_not_called()

    def test_api_key_routes_to_api_function(self):
        """When api_key provided, _dnsdumpster_api is called not _dnsdumpster_scrape."""
        from scanner.dns_enumerator import _dnsdumpster_subdomains
        with patch("scanner.dns_enumerator._dnsdumpster_api",
                   return_value=["sub.example.com"]) as mock_api, \
             patch("scanner.dns_enumerator._dnsdumpster_scrape",
                   return_value=[]) as mock_scrape:
            result = _dnsdumpster_subdomains("example.com", api_key="TESTKEY")
            mock_api.assert_called_once_with("example.com", "TESTKEY", 15)
            mock_scrape.assert_not_called()
            self.assertIn("sub.example.com", result)

    def test_no_api_key_routes_to_scrape(self):
        from scanner.dns_enumerator import _dnsdumpster_subdomains
        with patch("scanner.dns_enumerator._dnsdumpster_api") as mock_api, \
             patch("scanner.dns_enumerator._dnsdumpster_scrape",
                   return_value=[]) as mock_scrape:
            _dnsdumpster_subdomains("example.com", api_key="")
            mock_scrape.assert_called_once()
            mock_api.assert_not_called()

    def test_dns_enum_config_in_app(self):
        """DNS_ENUM_CONFIG is present in app.config after create_app."""
        with tempfile.TemporaryDirectory() as td:
            app = _make_app(os.path.join(td, "test.db"))
            self.assertIn("DNS_ENUM_CONFIG", app.config)
            cfg = app.config["DNS_ENUM_CONFIG"]
            self.assertIn("dnsdumpster_api_key", cfg)
            self.assertIn("use_wordlist", cfg)
            self.assertIn("use_ct", cfg)

    def test_api_endpoint_uses_config_defaults(self):
        """POST /api/dns-enumerate uses server config; use_dnsdumpster=False when no key."""
        with tempfile.TemporaryDirectory() as td:
            app = _make_app(os.path.join(td, "test.db"))
            client = _login_admin(app.test_client())

            from scanner.dns_enumerator import DnsEnumerationResult
            mock_result = DnsEnumerationResult(domain="example.com")

            with patch("scanner.dns_enumerator.enumerate_domain",
                       return_value=mock_result) as mock_enum:
                client.post("/app/api/dns-enumerate",
                            json={"domains": ["example.com"]},
                            content_type="application/json")
                call_kwargs = mock_enum.call_args[1]
                # No key configured → use_dnsdumpster should be False
                self.assertFalse(call_kwargs.get("use_dnsdumpster"))

    def test_load_config_reads_dns_enumeration_block(self):
        import yaml, tempfile as tf2
        cfg_content = {
            "dns_enumeration": {
                "dnsdumpster_api_key": "MY_KEY",
                "use_wordlist": False,
                "use_ct": True,
            },
            "dashboard": {"secret_key": "dev"},
            "database": {"path": "data/pqc_monitor.db"},
        }
        with tf2.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(cfg_content, f)
            fname = f.name
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from pqc_monitor import load_config
            result = load_config(fname)
            self.assertEqual(result["dnsdumpster_api_key"], "MY_KEY")
            self.assertFalse(result["dns_use_wordlist"])
            self.assertTrue(result["dns_use_ct"])
        finally:
            os.unlink(fname)

    def test_env_var_overrides_config_key(self):
        """PQC_DNSDUMPSTER_KEY env var should override config.yaml value."""
        import yaml, tempfile as tf2
        cfg_content = {
            "dns_enumeration": {"dnsdumpster_api_key": "CONFIG_KEY"},
            "dashboard": {"secret_key": "dev"},
            "database": {"path": "data/pqc_monitor.db"},
        }
        with tf2.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(cfg_content, f)
            fname = f.name
        try:
            with patch.dict(os.environ, {"PQC_DNSDUMPSTER_KEY": "ENV_KEY"}):
                from pqc_monitor import load_config
                result = load_config(fname)
                self.assertEqual(result["dnsdumpster_api_key"], "ENV_KEY")
        finally:
            os.unlink(fname)


if __name__ == "__main__":
    unittest.main(verbosity=2)
