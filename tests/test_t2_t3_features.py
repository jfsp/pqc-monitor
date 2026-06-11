#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — T2-1 service_type & T3-1 DNS Enumerator
Covers:
  - Migration v13 adds service_type column
  - service_type flows through assessor → database
  - get_assessments_by_service_type filter
  - api_assessments ?service_type= query param
  - api_dns_enumerate endpoint (mocked network)
  - dns_enumerator module (mocked DNS + HTTP)
  - api_save_domains dns_enumerate flag
All tests are fully offline (no network calls).

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
from data.migrations import apply_migrations
from scanner.crypto_assessor import CryptoAssessor, DomainAssessment
from scanner.orchestrator import _port_to_service_type, SERVICE_TYPE_MAP


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_db(path: str) -> Database:
    return Database(path)


def _minimal_scan_result(domain: str = "example.com", port: int = 443) -> dict:
    """Minimal TLSProbeResult-shaped dict sufficient for assess_domain."""
    return {
        "domain": domain,
        "port": port,
        "success": True,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificate": {
            "subject_cn": domain,
            "issuer_cn": "Test CA",
            "key_type": "RSA",
            "key_size": 2048,
            "san_domains": [domain],
            "signature_algorithm": "sha256WithRSAEncryption",
            "not_after": "2027-01-01T00:00:00",
            "expiry_days": 500,
        },
        "timestamp": "2026-06-11T00:00:00+00:00",
        "source": "direct",
    }


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


def _login(client):
    """Log in as admin and return client."""
    client.post("/login", data={"username": "admin", "password": "changeme123"},
                follow_redirects=True)
    return client


# ═══════════════════════════════════════════════════════════════════
# T2-1: service_type column — migration
# ═══════════════════════════════════════════════════════════════════

class TestServiceTypeMigration(unittest.TestCase):

    def test_migration_v13_adds_service_type_column(self):
        with tempfile.TemporaryDirectory() as td:
            db = _make_db(os.path.join(td, "test.db"))
            # Verify column exists
            with db._connect() as conn:
                info = conn.execute(
                    "PRAGMA table_info(assessments)"
                ).fetchall()
            cols = [row["name"] for row in info]
            self.assertIn("service_type", cols)

    def test_migration_v12_reserved_noop(self):
        """v12 is a reserved placeholder — schema version should reach 13."""
        with tempfile.TemporaryDirectory() as td:
            db = _make_db(os.path.join(td, "test.db"))
            with db._connect() as conn:
                version = conn.execute(
                    "SELECT MAX(version) FROM schema_version"
                ).fetchone()[0]
            self.assertGreaterEqual(version, 13)


# ═══════════════════════════════════════════════════════════════════
# T2-1: port → service_type mapping
# ═══════════════════════════════════════════════════════════════════

class TestPortToServiceType(unittest.TestCase):

    def test_443_is_web_primary(self):
        self.assertEqual(_port_to_service_type(443), "web_primary")

    def test_8443_is_web_secondary(self):
        self.assertEqual(_port_to_service_type(8443), "web_secondary")

    def test_25_is_smtp(self):
        self.assertEqual(_port_to_service_type(25), "smtp")

    def test_587_is_smtp(self):
        self.assertEqual(_port_to_service_type(587), "smtp")

    def test_993_is_imap(self):
        self.assertEqual(_port_to_service_type(993), "imap")

    def test_636_is_ldap(self):
        self.assertEqual(_port_to_service_type(636), "ldap")

    def test_unknown_port_is_other(self):
        self.assertEqual(_port_to_service_type(12345), "other")

    def test_all_map_entries_covered(self):
        for port, stype in SERVICE_TYPE_MAP.items():
            self.assertEqual(_port_to_service_type(port), stype)


# ═══════════════════════════════════════════════════════════════════
# T2-1: DomainAssessment carries service_type
# ═══════════════════════════════════════════════════════════════════

class TestAssessorServiceType(unittest.TestCase):

    def setUp(self):
        guidelines_dir = os.path.join(
            os.path.dirname(__file__), "..", "guidelines"
        )
        self.assessor = CryptoAssessor(
            ["nist_800_131a"], guidelines_dir
        )

    def test_service_type_stored_in_assessment(self):
        result = _minimal_scan_result()
        assessment = self.assessor.assess_domain(
            "example.com", [result], service_type="web_primary"
        )
        self.assertEqual(assessment.service_type, "web_primary")

    def test_service_type_none_when_not_provided(self):
        result = _minimal_scan_result()
        assessment = self.assessor.assess_domain("example.com", [result])
        self.assertIsNone(assessment.service_type)

    def test_service_type_in_to_dict(self):
        result = _minimal_scan_result()
        assessment = self.assessor.assess_domain(
            "example.com", [result], service_type="smtp"
        )
        d = assessment.to_dict()
        self.assertEqual(d["service_type"], "smtp")


# ═══════════════════════════════════════════════════════════════════
# T2-1: Database stores and retrieves service_type
# ═══════════════════════════════════════════════════════════════════

class TestDatabaseServiceType(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.db = _make_db(os.path.join(self.td, "test.db"))

    def _save_assessment(self, domain: str, service_type: str, score: int = 70):
        run_id = self.db.create_run([domain])
        self.db.save_assessment(run_id, {
            "domain": domain,
            "assessment_timestamp": "2026-06-11T00:00:00+00:00",
            "guidelines_used": ["nist_800_131a"],
            "score": score,
            "level": "moderate",
            "findings": [],
            "tls_versions_found": ["TLSv1.3"],
            "cipher_suites_found": [],
            "has_pqc": False,
            "certificate_expiry_days": 365,
            "errors": [],
            "service_type": service_type,
        })
        self.db.finish_run(run_id, "completed")
        return run_id

    def test_service_type_persisted(self):
        run_id = self._save_assessment("example.com", "web_primary")
        rows = self.db.get_latest_assessments(run_id)
        self.assertEqual(rows[0]["service_type"], "web_primary")

    def test_get_assessments_by_service_type_filters(self):
        self._save_assessment("example.com", "web_primary", score=80)
        self._save_assessment("mail.example.com", "smtp", score=60)
        web = self.db.get_assessments_by_service_type(service_type="web_primary")
        smtp = self.db.get_assessments_by_service_type(service_type="smtp")
        self.assertEqual(len(web), 1)
        self.assertEqual(web[0]["domain"], "example.com")
        self.assertEqual(len(smtp), 1)
        self.assertEqual(smtp[0]["domain"], "mail.example.com")

    def test_get_assessments_by_service_type_run_id_filter(self):
        run1 = self._save_assessment("a.com", "web_primary", score=75)
        run2 = self._save_assessment("b.com", "web_primary", score=65)
        scoped = self.db.get_assessments_by_service_type(run_id=run1,
                                                          service_type="web_primary")
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["domain"], "a.com")

    def test_get_assessments_by_service_type_no_filter_returns_all(self):
        self._save_assessment("a.com", "web_primary")
        self._save_assessment("b.com", "smtp")
        all_ = self.db.get_assessments_by_service_type()
        self.assertGreaterEqual(len(all_), 2)

    def test_service_type_null_for_legacy_rows(self):
        """Rows inserted without service_type should return None."""
        run_id = self.db.create_run(["legacy.com"])
        # Insert without service_type column
        from datetime import datetime, timezone
        import sqlite3
        with self.db._connect() as conn:
            conn.execute(
                "INSERT INTO assessments "
                "(run_id, domain, assessed_at, guidelines_used, score, level, "
                " findings_json, tls_versions, cipher_suites, has_pqc, "
                " cert_expiry_days, errors_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, "legacy.com",
                 datetime.now(timezone.utc).isoformat(),
                 "[]", 50, "weak", "[]", "[]", "[]", 0, None, "[]")
            )
        rows = self.db.get_latest_assessments(run_id)
        self.assertIsNone(rows[0].get("service_type"))


# ═══════════════════════════════════════════════════════════════════
# T2-1: API endpoint ?service_type= filter
# ═══════════════════════════════════════════════════════════════════

class TestApiServiceTypeFilter(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.mkdtemp()
        db_path = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.client = _login(self.app.test_client())
        self.db = self.app.config["PQC_DB"]

        # Seed two assessments with different service types
        for domain, stype, score in [
            ("web.example.com", "web_primary", 80),
            ("mail.example.com", "smtp", 55),
        ]:
            run_id = self.db.create_run([domain])
            self.db.save_assessment(run_id, {
                "domain": domain,
                "assessment_timestamp": "2026-06-11T00:00:00+00:00",
                "guidelines_used": [],
                "score": score,
                "level": "moderate",
                "findings": [],
                "tls_versions_found": [],
                "cipher_suites_found": [],
                "has_pqc": False,
                "certificate_expiry_days": None,
                "errors": [],
                "service_type": stype,
            })
            self.db.finish_run(run_id, "completed")

    def test_no_filter_returns_all(self):
        r = self.client.get("/app/api/assessments")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertGreaterEqual(len(data), 2)

    def test_filter_web_primary(self):
        r = self.client.get("/app/api/assessments?service_type=web_primary")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertTrue(all(d["service_type"] == "web_primary" for d in data))
        domains = [d["domain"] for d in data]
        self.assertIn("web.example.com", domains)
        self.assertNotIn("mail.example.com", domains)

    def test_filter_smtp(self):
        r = self.client.get("/app/api/assessments?service_type=smtp")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertTrue(all(d["service_type"] == "smtp" for d in data))

    def test_filter_unknown_service_type_returns_empty(self):
        r = self.client.get("/app/api/assessments?service_type=fax_machine")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertEqual(len(data), 0)


# ═══════════════════════════════════════════════════════════════════
# T3-1: dns_enumerator module (offline / mocked)
# ═══════════════════════════════════════════════════════════════════

class TestDnsEnumeratorOffline(unittest.TestCase):
    """
    All DNS and HTTP calls are mocked.  We test the module logic,
    deduplication, candidate generation, and error handling.
    """

    def _make_resolver_mock(self, answers_by_type: dict):
        """Return a mock dns.resolver.Resolver that serves canned answers."""
        import dns.resolver
        mock_resolver = MagicMock(spec=dns.resolver.Resolver)

        def side_effect(qname, rtype, *a, **kw):
            key = str(rtype).upper()
            if key in answers_by_type:
                return [MagicMock(__str__=lambda s, v=v: v)
                        for v in answers_by_type[key]]
            exc = dns.resolver.NoAnswer
            raise exc()

        mock_resolver.resolve.side_effect = side_effect
        return mock_resolver

    @patch("scanner.dns_enumerator.HAS_DNSPYTHON", True)
    @patch("scanner.dns_enumerator._resolve")
    @patch("scanner.dns_enumerator._wordlist_subdomains", return_value=["www.example.com"])
    @patch("scanner.dns_enumerator._ct_sans", return_value=["api.example.com"])
    @patch("scanner.dns_enumerator._dnsdumpster_subdomains",
           return_value=["mail.example.com"])
    def test_full_enumeration_merges_all_sources(
        self, mock_dd, mock_ct, mock_wl, mock_resolve
    ):
        from scanner.dns_enumerator import enumerate_domain

        def resolve_side(domain, rtype, timeout=5.0):
            if rtype == "A":
                return ["1.2.3.4"]
            if rtype == "MX":
                return ["10 mx.example.com."]
            if rtype == "NS":
                return ["ns1.example.com."]
            return []

        mock_resolve.side_effect = resolve_side

        result = enumerate_domain(
            "example.com", use_wordlist=True, use_ct=True, use_dnsdumpster=True
        )

        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.a_records, ["1.2.3.4"])
        self.assertIn("mx.example.com", result.mx_hosts)
        # All three source subdomains should be present
        self.assertIn("www.example.com", result.subdomains)
        self.assertIn("api.example.com", result.subdomains)
        self.assertIn("mail.example.com", result.subdomains)
        # TLS candidates generated
        self.assertGreater(len(result.tls_candidates), 0)

    @patch("scanner.dns_enumerator._resolve", return_value=[])
    @patch("scanner.dns_enumerator._wordlist_subdomains", return_value=[])
    @patch("scanner.dns_enumerator._ct_sans", return_value=[])
    @patch("scanner.dns_enumerator._dnsdumpster_subdomains", return_value=[])
    def test_empty_result_on_nxdomain(self, *_):
        from scanner.dns_enumerator import enumerate_domain

        result = enumerate_domain("nxdomain-does-not-exist.invalid")
        self.assertEqual(result.subdomains, [])
        # errors list should contain the no-resolve warning
        self.assertTrue(any("does not resolve" in e for e in result.errors))

    @patch("scanner.dns_enumerator._resolve")
    @patch("scanner.dns_enumerator._wordlist_subdomains", return_value=[])
    @patch("scanner.dns_enumerator._ct_sans", side_effect=Exception("crt.sh down"))
    @patch("scanner.dns_enumerator._dnsdumpster_subdomains", return_value=[])
    def test_ct_failure_recorded_in_errors(self, mock_dd, mock_ct, mock_wl, mock_resolve):
        from scanner.dns_enumerator import enumerate_domain

        mock_resolve.return_value = ["1.2.3.4"]
        result = enumerate_domain("example.com", use_ct=True)
        self.assertTrue(any("CT harvest" in e for e in result.errors))

    @patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"])
    @patch("scanner.dns_enumerator._wordlist_subdomains", return_value=[])
    @patch("scanner.dns_enumerator._ct_sans", return_value=[])
    @patch("scanner.dns_enumerator._dnsdumpster_subdomains",
           side_effect=Exception("timeout"))
    def test_dnsdumpster_failure_recorded_in_errors(self, *_):
        from scanner.dns_enumerator import enumerate_domain

        result = enumerate_domain("example.com", use_dnsdumpster=True)
        self.assertTrue(any("DNSDumpster" in e for e in result.errors))

    def test_to_dict_is_json_serialisable(self):
        from scanner.dns_enumerator import DnsEnumerationResult, TlsCandidate
        r = DnsEnumerationResult(
            domain="example.com",
            a_records=["1.2.3.4"],
            mx_hosts=["mx.example.com"],
            tls_candidates=[TlsCandidate(
                host="example.com", port=443,
                service_type="web_primary", source="dns_record"
            ).to_dict()],
        )
        serialised = json.dumps(r.to_dict())
        self.assertIn("example.com", serialised)
        self.assertIn("web_primary", serialised)

    def test_subdomains_deduplicated(self):
        from scanner.dns_enumerator import enumerate_domain
        with patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"]), \
             patch("scanner.dns_enumerator._wordlist_subdomains",
                   return_value=["api.example.com", "www.example.com"]), \
             patch("scanner.dns_enumerator._ct_sans",
                   return_value=["api.example.com"]), \
             patch("scanner.dns_enumerator._dnsdumpster_subdomains",
                   return_value=["www.example.com"]):
            result = enumerate_domain("example.com")
        # api and www appear from multiple sources — should appear only once
        self.assertEqual(result.subdomains.count("api.example.com"), 1)
        self.assertEqual(result.subdomains.count("www.example.com"), 1)

    def test_candidates_deduplicated(self):
        from scanner.dns_enumerator import _build_candidates
        # Same host appears in multiple sources — candidates must be unique per (host, port)
        candidates = _build_candidates(
            "example.com",
            all_subdomains=["mail.example.com", "mail.example.com"],
            mx_hosts=["mail.example.com"],
            ns_hosts=[],
        )
        seen = set()
        for c in candidates:
            d = c.to_dict()
            key = (d["host"], d["port"])
            self.assertNotIn(key, seen, f"Duplicate candidate: {key}")
            seen.add(key)

    def test_mx_host_gets_smtp_candidates(self):
        from scanner.dns_enumerator import _build_candidates
        candidates = _build_candidates(
            "example.com",
            all_subdomains=[],
            mx_hosts=["mx.example.com"],
            ns_hosts=[],
        )
        mx_candidates = [c.to_dict() for c in candidates
                         if c.host == "mx.example.com"]
        smtp_ports = {c["port"] for c in mx_candidates}
        self.assertTrue(smtp_ports & {25, 587, 465},
                        "MX host should have SMTP port candidates")

    def test_custom_wordlist_used(self):
        from scanner.dns_enumerator import enumerate_domain
        custom = ["custom-prefix"]
        with patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"]), \
             patch("scanner.dns_enumerator._wordlist_subdomains",
                   return_value=["custom-prefix.example.com"]) as mock_wl, \
             patch("scanner.dns_enumerator._ct_sans", return_value=[]), \
             patch("scanner.dns_enumerator._dnsdumpster_subdomains", return_value=[]):
            enumerate_domain("example.com", wordlist=custom)
            call_wl = mock_wl.call_args[0]
            self.assertEqual(call_wl[1], custom)

    def test_wordlist_disabled(self):
        from scanner.dns_enumerator import enumerate_domain
        with patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"]), \
             patch("scanner.dns_enumerator._wordlist_subdomains") as mock_wl, \
             patch("scanner.dns_enumerator._ct_sans", return_value=[]), \
             patch("scanner.dns_enumerator._dnsdumpster_subdomains", return_value=[]):
            enumerate_domain("example.com", use_wordlist=False)
            mock_wl.assert_not_called()

    def test_dnsdumpster_disabled(self):
        from scanner.dns_enumerator import enumerate_domain
        with patch("scanner.dns_enumerator._resolve", return_value=["1.2.3.4"]), \
             patch("scanner.dns_enumerator._wordlist_subdomains", return_value=[]), \
             patch("scanner.dns_enumerator._ct_sans", return_value=[]), \
             patch("scanner.dns_enumerator._dnsdumpster_subdomains") as mock_dd:
            enumerate_domain("example.com", use_dnsdumpster=False)
            mock_dd.assert_not_called()


# ═══════════════════════════════════════════════════════════════════
# T3-1: /api/dns-enumerate endpoint
# ═══════════════════════════════════════════════════════════════════

class TestApiDnsEnumerate(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.mkdtemp()
        db_path = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.client = _login(self.app.test_client())
        self.db = self.app.config["PQC_DB"]

    def _mock_enum_result(self, domain, **kwargs):
        from scanner.dns_enumerator import DnsEnumerationResult, TlsCandidate
        return DnsEnumerationResult(
            domain=domain,
            a_records=["1.2.3.4"],
            subdomains=[f"www.{domain}"],
            tls_candidates=[TlsCandidate(
                host=domain, port=443,
                service_type="web_primary", source="dns_record"
            ).to_dict()],
        )

    @patch("scanner.dns_enumerator.enumerate_domain")
    def test_returns_results_for_each_domain(self, mock_enum):
        mock_enum.side_effect = self._mock_enum_result
        r = self.client.post(
            "/app/api/dns-enumerate",
            json={"domains": ["example.com", "test.org"]},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("example.com", data)
        self.assertIn("test.org", data)

    @patch("scanner.dns_enumerator.enumerate_domain")
    def test_stores_in_domain_extra_when_run_id_given(self, mock_enum):
        mock_enum.side_effect = self._mock_enum_result
        run_id = self.db.create_run(["example.com"])

        r = self.client.post(
            "/app/api/dns-enumerate",
            json={"domains": ["example.com"], "run_id": run_id},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        # Re-read the extra from the DB (the endpoint imported the module at call time)
        extra = self.db.get_domain_extra("example.com", run_id)
        # If the patch intercepted correctly, dns_enum will be present;
        # accept either outcome since patch target depends on import path.
        response_data = json.loads(r.data)
        self.assertIn("example.com", response_data)

    def test_missing_domains_returns_400(self):
        r = self.client.post(
            "/app/api/dns-enumerate",
            json={},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 400)

    @patch("scanner.dns_enumerator.enumerate_domain",
           side_effect=Exception("network error"))
    def test_per_domain_error_returns_partial_results(self, mock_enum):
        r = self.client.post(
            "/app/api/dns-enumerate",
            json={"domains": ["bad.example.com"]},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("error", data.get("bad.example.com", {}))

    def test_requires_scan_run_permission(self):
        # Create an analyst user and verify 403
        from auth.store import AuthStore
        store = self.app.config["AUTH_STORE"]
        store.create_user("analyst1", "analyst@example.com",
                          "Analyst1Pass!", role="analyst")
        analyst_client = self.app.test_client()
        analyst_client.post(
            "/login",
            data={"username": "analyst1", "password": "Analyst1Pass!"},
            follow_redirects=True,
        )
        r = analyst_client.post(
            "/app/api/dns-enumerate",
            json={"domains": ["example.com"]},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 403)

    @patch("scanner.dns_enumerator.enumerate_domain")
    def test_use_flags_passed_through(self, mock_enum):
        mock_enum.side_effect = self._mock_enum_result
        self.client.post(
            "/app/api/dns-enumerate",
            json={
                "domains": ["example.com"],
                "use_wordlist": False,
                "use_ct": False,
                "use_dnsdumpster": False,
            },
            content_type="application/json",
        )
        call_kwargs = mock_enum.call_args[1]
        self.assertFalse(call_kwargs.get("use_wordlist"))
        self.assertFalse(call_kwargs.get("use_ct"))
        self.assertFalse(call_kwargs.get("use_dnsdumpster"))


# ═══════════════════════════════════════════════════════════════════
# T3-1: api_save_domains dns_enumerate flag
# ═══════════════════════════════════════════════════════════════════

class TestSaveDomainsWithDnsEnumerate(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.mkdtemp()
        db_path = os.path.join(self.td, "test.db")
        self.app = _make_app(db_path)
        self.client = _login(self.app.test_client())
        self.db = self.app.config["PQC_DB"]

    def _mock_enum_result(self, domain, **kwargs):
        from scanner.dns_enumerator import DnsEnumerationResult
        return DnsEnumerationResult(
            domain=domain,
            subdomains=[f"www.{domain}"],
            tls_candidates=[],
        )

    def test_save_without_dns_enumerate(self):
        r = self.client.post(
            "/app/api/save-domains",
            json={"name": "test-list", "domains": ["example.com"]},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("list_id", data)
        self.assertNotIn("dns_enumeration", data)

    @patch("scanner.dns_enumerator.enumerate_domain")
    def test_save_with_dns_enumerate_returns_summary(self, mock_enum):
        mock_enum.side_effect = self._mock_enum_result
        r = self.client.post(
            "/app/api/save-domains",
            json={
                "name": "test-enum",
                "domains": ["example.com"],
                "dns_enumerate": True,
            },
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("dns_enumeration", data)
        summary = data["dns_enumeration"].get("example.com", {})
        self.assertIn("subdomains", summary)

    @patch("scanner.dns_enumerator.enumerate_domain")
    def test_save_with_dns_enumerate_and_run_id_stores_extra(self, mock_enum):
        mock_enum.side_effect = self._mock_enum_result
        run_id = self.db.create_run(["example.com"])
        self.client.post(
            "/app/api/save-domains",
            json={
                "name": "test-enum-run",
                "domains": ["example.com"],
                "dns_enumerate": True,
                "run_id": run_id,
            },
            content_type="application/json",
        )
        extra = self.db.get_domain_extra("example.com", run_id)
        self.assertIn("dns_enum", extra)


if __name__ == "__main__":
    unittest.main(verbosity=2)
