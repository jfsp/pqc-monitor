#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — Certificate Transparency Monitor
Tests OID classification, certificate parsing, DB storage, and API endpoints.
All tests are fully offline — no crt.sh network calls are made.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ct.ct_monitor import (
    _classify_pqc,
    _resolve_sig_name,
    monitor_domain,
    CTCertificate,
    CTSummary,
    PQC_SIGNATURE_OIDS,
    PQC_PUBKEY_OIDS,
    EXPERIMENTAL_PQC_OID_PREFIXES,
)
from data.database import Database


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_crtsh_entry(cert_id=1001, name="test.example.com",
                      not_after=None, issuer_ca_id=1):
    if not_after is None:
        not_after = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
    return {
        "id": cert_id,
        "issuer_ca_id": issuer_ca_id,
        "name_value": name,
        "not_after": not_after,
        "entry_timestamp": "2024-01-15T10:00:00",
    }


def _make_ct_cert(domain="test.example.com", is_pqc_sig=False, is_pqc_pk=False,
                  is_hybrid=False, sig_oid="1.2.840.113549.1.1.11",
                  sig_name="sha256WithRSAEncryption",
                  pqc_algorithms=None, days_to_expiry=300):
    return CTCertificate(
        cert_id=1001,
        sha256_fingerprint="abc123",
        domain=domain,
        subject_cn=domain,
        issuer_cn="Test CA",
        issuer_org="Test Org",
        not_before="2024-01-01T00:00:00+00:00",
        not_after="2025-01-01T00:00:00+00:00",
        days_to_expiry=days_to_expiry,
        signature_algorithm_oid=sig_oid,
        signature_algorithm_name=sig_name,
        pubkey_algorithm_oid="1.2.840.113549.1.1.1",
        pubkey_algorithm_name="RSA",
        pubkey_size_bits=4096,
        is_pqc_signature=is_pqc_sig,
        is_pqc_pubkey=is_pqc_pk,
        is_hybrid=is_hybrid,
        pqc_algorithms=pqc_algorithms or [],
    )


# ── OID registry tests ────────────────────────────────────────────────────────

class TestOIDRegistry(unittest.TestCase):
    def test_ml_dsa_44_oid_present(self):
        oid = "1.3.6.1.4.1.2.267.12.4.4"
        self.assertIn(oid, PQC_SIGNATURE_OIDS)
        self.assertEqual(PQC_SIGNATURE_OIDS[oid], "ML-DSA-44")

    def test_ml_dsa_65_oid_present(self):
        self.assertIn("1.3.6.1.4.1.2.267.12.6.5", PQC_SIGNATURE_OIDS)

    def test_ml_dsa_87_oid_present(self):
        self.assertIn("1.3.6.1.4.1.2.267.12.8.7", PQC_SIGNATURE_OIDS)

    def test_slh_dsa_oids_present(self):
        slh_oids = [k for k, v in PQC_SIGNATURE_OIDS.items() if "SLH-DSA" in v]
        self.assertGreater(len(slh_oids), 4)

    def test_falcon_oids_present(self):
        falcon_oids = [k for k, v in PQC_SIGNATURE_OIDS.items() if "Falcon" in v]
        self.assertGreaterEqual(len(falcon_oids), 2)

    def test_composite_oids_present(self):
        composite_oids = [k for k, v in PQC_SIGNATURE_OIDS.items() if "Composite" in v]
        self.assertGreater(len(composite_oids), 0)

    def test_ml_kem_in_pubkey_oids(self):
        kem_oids = [k for k, v in PQC_PUBKEY_OIDS.items() if "ML-KEM" in v]
        self.assertGreaterEqual(len(kem_oids), 3)

    def test_no_classical_oids_in_pqc_registry(self):
        classical_oids = {
            "1.2.840.113549.1.1.11",  # sha256WithRSA
            "1.2.840.10045.2.1",       # EC
            "1.3.101.112",             # Ed25519
        }
        for oid in classical_oids:
            self.assertNotIn(oid, PQC_SIGNATURE_OIDS,
                             f"Classical OID {oid} should not be in PQC registry")

    def test_experimental_prefix_coverage(self):
        # All 1.3.9999.* OIDs should be caught by the prefix
        for oid in PQC_SIGNATURE_OIDS:
            if oid.startswith("1.3.9999."):
                self.assertTrue(
                    any(oid.startswith(p) for p in EXPERIMENTAL_PQC_OID_PREFIXES)
                )


# ── _classify_pqc tests ───────────────────────────────────────────────────────

class TestClassifyPQC(unittest.TestCase):
    def test_classical_cert(self):
        is_sig, is_pk, is_hybrid, algos = _classify_pqc(
            "1.2.840.113549.1.1.11",  # sha256WithRSA
            "1.2.840.113549.1.1.1",   # RSA
        )
        self.assertFalse(is_sig)
        self.assertFalse(is_pk)
        self.assertFalse(is_hybrid)
        self.assertEqual(algos, [])

    def test_ml_dsa_sig_detected(self):
        oid = "1.3.6.1.4.1.2.267.12.6.5"  # ML-DSA-65
        is_sig, is_pk, is_hybrid, algos = _classify_pqc(oid, "1.2.840.113549.1.1.1")
        self.assertTrue(is_sig)
        self.assertFalse(is_pk)
        self.assertIn("ML-DSA-65", algos)

    def test_ml_kem_pubkey_detected(self):
        oid = "1.3.6.1.4.1.22554.5.6.2"  # ML-KEM-768
        is_sig, is_pk, is_hybrid, algos = _classify_pqc(
            "1.2.840.113549.1.1.11",   # classical sig
            oid
        )
        self.assertFalse(is_sig)
        self.assertTrue(is_pk)
        self.assertIn("ML-KEM-768", algos)

    def test_composite_is_hybrid(self):
        oid = "2.16.840.1.114027.80.8.1.1"  # Composite-ML-DSA-44-RSA2048-PSS
        is_sig, is_pk, is_hybrid, algos = _classify_pqc(oid, "")
        self.assertTrue(is_sig)
        self.assertTrue(is_hybrid)
        self.assertTrue(any("Composite" in a for a in algos))

    def test_falcon_512_detected(self):
        oid = "1.3.9999.3.6"
        is_sig, _, _, algos = _classify_pqc(oid, "")
        self.assertTrue(is_sig)
        self.assertIn("Falcon-512", algos)

    def test_falcon_1024_detected(self):
        oid = "1.3.9999.3.9"
        is_sig, _, _, algos = _classify_pqc(oid, "")
        self.assertTrue(is_sig)
        self.assertIn("Falcon-1024", algos)

    def test_experimental_oid_caught(self):
        # An experimental OID in the 1.3.9999 space not in our registry
        experimental_oid = "1.3.9999.99.99.99"
        is_sig, _, _, algos = _classify_pqc(experimental_oid, "")
        self.assertTrue(is_sig, "Experimental OID prefix should be flagged as PQC")
        self.assertTrue(any("Experimental-PQC" in a for a in algos))

    def test_empty_oids_are_not_pqc(self):
        is_sig, is_pk, is_hybrid, algos = _classify_pqc("", "")
        self.assertFalse(is_sig)
        self.assertFalse(is_pk)
        self.assertEqual(algos, [])

    def test_both_sig_and_pk_pqc(self):
        sig_oid = "1.3.6.1.4.1.2.267.12.6.5"  # ML-DSA-65
        pk_oid  = "1.3.6.1.4.1.22554.5.6.2"   # ML-KEM-768
        is_sig, is_pk, _, algos = _classify_pqc(sig_oid, pk_oid)
        self.assertTrue(is_sig)
        self.assertTrue(is_pk)
        # Both algorithms should appear in list
        self.assertIn("ML-DSA-65",  algos)
        self.assertIn("ML-KEM-768", algos)

    def test_no_duplicate_algo_names(self):
        # ML-DSA-65 OID in both sig and pk fields — name should not duplicate
        oid = "1.3.6.1.4.1.2.267.12.6.5"
        _, _, _, algos = _classify_pqc(oid, oid)
        ml_dsa_count = sum(1 for a in algos if a == "ML-DSA-65")
        self.assertEqual(ml_dsa_count, 1)


# ── CTCertificate tests ───────────────────────────────────────────────────────

class TestCTCertificate(unittest.TestCase):
    def test_has_any_pqc_false_for_classical(self):
        cert = _make_ct_cert(is_pqc_sig=False, is_pqc_pk=False)
        self.assertFalse(cert.has_any_pqc)

    def test_has_any_pqc_true_for_pqc_sig(self):
        cert = _make_ct_cert(is_pqc_sig=True)
        self.assertTrue(cert.has_any_pqc)

    def test_has_any_pqc_true_for_pqc_pk(self):
        cert = _make_ct_cert(is_pqc_pk=True)
        self.assertTrue(cert.has_any_pqc)

    def test_to_dict_contains_all_fields(self):
        cert = _make_ct_cert()
        d = cert.to_dict()
        for field in ("cert_id", "domain", "issuer_cn", "is_pqc_signature",
                      "is_pqc_pubkey", "is_hybrid", "pqc_algorithms"):
            self.assertIn(field, d, f"Missing field: {field}")

    def test_hybrid_flag(self):
        cert = _make_ct_cert(is_hybrid=True, is_pqc_sig=True)
        self.assertTrue(cert.is_hybrid)
        self.assertTrue(cert.has_any_pqc)


# ── monitor_domain (mocked) tests ─────────────────────────────────────────────

class TestMonitorDomain(unittest.TestCase):
    """Tests for monitor_domain() with all HTTP calls mocked out."""

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_empty_ct_log_returns_summary(self, mock_fetch):
        mock_fetch.return_value = []
        result = monitor_domain("no-certs.example.com", fetch_pem=False)
        self.assertIsInstance(result, CTSummary)
        self.assertEqual(result.domain, "no-certs.example.com")
        self.assertIsNotNone(result.error)

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_classical_certs_counted(self, mock_fetch):
        mock_fetch.return_value = [
            _make_crtsh_entry(1001, "example.com"),
            _make_crtsh_entry(1002, "www.example.com"),
            _make_crtsh_entry(1003, "mail.example.com"),
        ]
        result = monitor_domain("example.com", fetch_pem=False)
        self.assertEqual(result.total_certs_found, 3)
        self.assertEqual(result.pqc_certs_found, 0)
        self.assertEqual(result.classical_certs_found, 3)

    @patch("ct.ct_monitor._fetch_cert_pem")
    @patch("ct.ct_monitor._fetch_cert_list")
    def test_pqc_cert_detected_via_pem(self, mock_list, mock_pem):
        """Simulate a PEM that parses to a ML-DSA-65 certificate."""
        mock_list.return_value = [_make_crtsh_entry(2001, "pqc.example.com")]

        # Mock the PEM parse result to return ML-DSA-65 OID
        with patch("ct.ct_monitor._parse_pem_certificate") as mock_parse:
            mock_parse.return_value = {
                "subject_cn":               "pqc.example.com",
                "issuer_cn":                "PQC Test CA",
                "issuer_org":               "Test Org",
                "not_before":               "2024-01-01T00:00:00+00:00",
                "not_after":                "2025-01-01T00:00:00+00:00",
                "days_to_expiry":           300,
                "signature_algorithm_oid":  "1.3.6.1.4.1.2.267.12.6.5",  # ML-DSA-65
                "signature_algorithm_name": "ML-DSA-65",
                "pubkey_algorithm_oid":     "1.3.6.1.4.1.2.267.12.6.5",
                "pubkey_algorithm_name":    "ML-DSA-65",
                "pubkey_size_bits":         2592,
                "sans":                     ["pqc.example.com"],
                "sha256_fingerprint":       "deadbeef",
            }
            mock_pem.return_value = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"

            result = monitor_domain("pqc.example.com", fetch_pem=True)

        self.assertEqual(result.pqc_certs_found, 1)
        self.assertIn("ML-DSA-65", result.pqc_algorithms_seen)

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_deduplication_by_cert_id(self, mock_fetch):
        """Duplicate cert IDs should be counted once."""
        mock_fetch.return_value = [
            _make_crtsh_entry(5000, "dup.example.com"),
            _make_crtsh_entry(5000, "dup.example.com"),   # same ID
            _make_crtsh_entry(5001, "dup.example.com"),
        ]
        result = monitor_domain("dup.example.com", fetch_pem=False)
        self.assertEqual(result.total_certs_found, 2)

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_max_certs_respected(self, mock_fetch):
        mock_fetch.return_value = [_make_crtsh_entry(i) for i in range(1000, 1050)]
        result = monitor_domain("many.example.com", fetch_pem=False, max_certs=10)
        self.assertLessEqual(len(result.certificates), 10)

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_summary_fields_populated(self, mock_fetch):
        mock_fetch.return_value = [_make_crtsh_entry(3001)]
        result = monitor_domain("fields.example.com", fetch_pem=False)
        self.assertEqual(result.domain, "fields.example.com")
        self.assertIsNotNone(result.queried_at)
        self.assertIsInstance(result.certificates, list)

    @patch("ct.ct_monitor._fetch_cert_list")
    def test_aggregates_pqc_issuers(self, mock_fetch):
        mock_fetch.return_value = [_make_crtsh_entry(4001)]
        with patch("ct.ct_monitor._fetch_cert_pem") as mock_pem:
            with patch("ct.ct_monitor._parse_pem_certificate") as mock_parse:
                mock_parse.return_value = {
                    "subject_cn": "test.example.com",
                    "issuer_cn":  "Let's Encrypt PQC R1",
                    "issuer_org": "Let's Encrypt",
                    "not_before": "2024-01-01T00:00:00+00:00",
                    "not_after":  "2025-01-01T00:00:00+00:00",
                    "days_to_expiry": 200,
                    "signature_algorithm_oid":  "1.3.6.1.4.1.2.267.12.4.4",
                    "signature_algorithm_name": "ML-DSA-44",
                    "pubkey_algorithm_oid":     "1.3.6.1.4.1.2.267.12.4.4",
                    "pubkey_algorithm_name":    "ML-DSA-44",
                    "pubkey_size_bits": 1312,
                    "sans": ["test.example.com"],
                    "sha256_fingerprint": "ff00",
                }
                mock_pem.return_value = b"fake pem"
                result = monitor_domain("test.example.com", fetch_pem=True)

        self.assertIn("Let's Encrypt PQC R1", result.pqc_issuers)


# ── Database CT storage tests ─────────────────────────────────────────────────

class TestDatabaseCT(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmpdir, "ct_test.db"))

    def _make_summary_dict(self, domain="test.com", pqc=0, hybrid=0, total=5):
        return {
            "domain": domain,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "total_certs_found": total,
            "pqc_certs_found": pqc,
            "hybrid_certs_found": hybrid,
            "classical_certs_found": total - pqc,
            "pqc_issuers": ["Test CA"] if pqc else [],
            "pqc_algorithms_seen": ["ML-DSA-65"] if pqc else [],
            "earliest_pqc_cert_date": "2024-01-01T00:00:00+00:00" if pqc else "",
            "latest_pqc_cert_date": "2024-06-01T00:00:00+00:00" if pqc else "",
            "error": "",
            "certificates": [
                {
                    "cert_id": 9001 + i,
                    "domain": domain,
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "sha256_fingerprint": f"fp{i}",
                    "subject_cn": domain,
                    "issuer_cn": "Test CA",
                    "issuer_org": "Test Org",
                    "not_before": "2024-01-01T00:00:00+00:00",
                    "not_after":  "2025-01-01T00:00:00+00:00",
                    "days_to_expiry": 200 - i,
                    "signature_algorithm_oid":  "1.3.6.1.4.1.2.267.12.6.5" if i < pqc else "1.2.840.113549.1.1.11",
                    "signature_algorithm_name": "ML-DSA-65" if i < pqc else "sha256WithRSAEncryption",
                    "pubkey_algorithm_oid": "",
                    "pubkey_algorithm_name": "RSA",
                    "pubkey_size_bits": 4096,
                    "is_pqc_signature": 1 if i < pqc else 0,
                    "is_pqc_pubkey": 0,
                    "is_hybrid": 0,
                    "pqc_algorithms": ["ML-DSA-65"] if i < pqc else [],
                    "sans": [domain],
                    "first_seen": "2024-01-01T00:00:00",
                }
                for i in range(total)
            ],
        }

    def test_save_and_retrieve_ct_summary(self):
        summary = self._make_summary_dict("bank.es", pqc=2, total=10)
        self.db.save_ct_summary(summary)
        rows = self.db.get_ct_summaries(domain="bank.es")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pqc_certs"], 2)
        self.assertEqual(rows[0]["total_certs"], 10)

    def test_save_multiple_domains(self):
        for domain in ["a.com", "b.com", "c.com"]:
            self.db.save_ct_summary(self._make_summary_dict(domain))
        rows = self.db.get_ct_summaries()
        self.assertEqual(len(rows), 3)

    def test_pqc_certificates_queryable(self):
        summary = self._make_summary_dict("pqc-bank.es", pqc=3, total=8)
        self.db.save_ct_summary(summary)
        pqc_certs = self.db.get_ct_pqc_certificates(domain="pqc-bank.es")
        self.assertEqual(len(pqc_certs), 3)
        for cert in pqc_certs:
            self.assertEqual(cert["is_pqc_signature"], 1)

    def test_classical_certs_not_in_pqc_query(self):
        summary = self._make_summary_dict("classic.es", pqc=0, total=5)
        self.db.save_ct_summary(summary)
        pqc_certs = self.db.get_ct_pqc_certificates(domain="classic.es")
        self.assertEqual(len(pqc_certs), 0)

    def test_get_ct_stats_empty(self):
        stats = self.db.get_ct_stats()
        self.assertIsInstance(stats, dict)

    def test_get_ct_stats_populated(self):
        self.db.save_ct_summary(self._make_summary_dict("alpha.es", pqc=2, total=10))
        self.db.save_ct_summary(self._make_summary_dict("beta.es",  pqc=0, total=5))
        stats = self.db.get_ct_stats()
        self.assertEqual(stats["domains_monitored"], 2)
        self.assertEqual(stats["total_certs"], 15)
        self.assertEqual(stats["total_pqc"], 2)
        self.assertEqual(stats["domains_with_pqc"], 1)

    def test_ct_timeline(self):
        self.db.save_ct_summary(self._make_summary_dict("time.es", pqc=1, total=5))
        timeline = self.db.get_ct_timeline()
        self.assertIsInstance(timeline, list)
        self.assertGreater(len(timeline), 0)
        self.assertIn("month", timeline[0])

    def test_deduplication_on_cert_id(self):
        """Same cert_id for the same domain should only be stored once."""
        summary1 = self._make_summary_dict("dup.es", pqc=1, total=1)
        summary2 = self._make_summary_dict("dup.es", pqc=1, total=1)
        # Both use cert_id 9001; second insert should be ignored
        self.db.save_ct_summary(summary1)
        self.db.save_ct_summary(summary2)
        all_certs = self.db.get_ct_pqc_certificates(domain="dup.es")
        self.assertEqual(len(all_certs), 1)

    def test_get_summaries_domain_filter(self):
        self.db.save_ct_summary(self._make_summary_dict("filter1.es"))
        self.db.save_ct_summary(self._make_summary_dict("filter2.es"))
        rows = self.db.get_ct_summaries(domain="filter1.es")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "filter1.es")

    def test_pqc_algorithms_json_parsed(self):
        summary = self._make_summary_dict("algos.es", pqc=1, total=2)
        self.db.save_ct_summary(summary)
        certs = self.db.get_ct_pqc_certificates(domain="algos.es")
        algos = certs[0].get("pqc_algorithms")
        self.assertIsInstance(algos, list)
        self.assertIn("ML-DSA-65", algos)


# ── Flask API endpoint tests ──────────────────────────────────────────────────

class TestCTAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(self.tmpdir, "api_test.db")
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from dashboard.app import create_app
        self.app = create_app({"db_path": db_path})
        self.client = self.app.test_client()
        self.db = Database(db_path)

    def _seed(self):
        from tests.test_ct import TestDatabaseCT
        helper = TestDatabaseCT()
        helper.db = self.db
        self.db.save_ct_summary(helper._make_summary_dict("api.es", pqc=2, total=8))

    def test_ct_stats_endpoint(self):
        r = self.client.get("/api/ct/stats")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("total_certs", data)

    def test_ct_summaries_endpoint(self):
        self._seed()
        r = self.client.get("/api/ct/summaries")
        self.assertEqual(r.status_code, 200)
        rows = json.loads(r.data)
        self.assertIsInstance(rows, list)
        self.assertEqual(len(rows), 1)

    def test_ct_certificates_endpoint(self):
        self._seed()
        r = self.client.get("/api/ct/certificates")
        self.assertEqual(r.status_code, 200)
        certs = json.loads(r.data)
        self.assertIsInstance(certs, list)
        self.assertEqual(len(certs), 2)

    def test_ct_timeline_endpoint(self):
        self._seed()
        r = self.client.get("/api/ct/timeline")
        self.assertEqual(r.status_code, 200)
        timeline = json.loads(r.data)
        self.assertIsInstance(timeline, list)

    def test_ct_monitor_endpoint_no_domains(self):
        r = self.client.post("/api/ct/monitor",
                             json={}, content_type="application/json")
        self.assertEqual(r.status_code, 400)

    @patch("ct.ct_monitor.monitor_domains")
    def test_ct_monitor_endpoint_with_domains(self, mock_monitor):
        mock_summary = MagicMock()
        mock_summary.pqc_certs_found = 1
        mock_summary.hybrid_certs_found = 0
        mock_summary.to_dict.return_value = {
            "domain": "mock.es",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "total_certs_found": 5,
            "pqc_certs_found": 1,
            "hybrid_certs_found": 0,
            "classical_certs_found": 4,
            "pqc_issuers": ["Mock CA"],
            "pqc_algorithms_seen": ["ML-DSA-65"],
            "earliest_pqc_cert_date": "",
            "latest_pqc_cert_date": "",
            "error": "",
            "certificates": [],
        }
        mock_monitor.return_value = [mock_summary]

        r = self.client.post("/api/ct/monitor",
                             json={"domains": ["mock.es"], "fetch_pem": False},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertEqual(data["domains_processed"], 1)
        self.assertEqual(data["pqc_certs_found"], 1)

    def test_ct_summaries_domain_filter(self):
        from tests.test_ct import TestDatabaseCT
        helper = TestDatabaseCT()
        helper.db = self.db
        self.db.save_ct_summary(helper._make_summary_dict("x.es"))
        self.db.save_ct_summary(helper._make_summary_dict("y.es"))
        r = self.client.get("/api/ct/summaries?domain=x.es")
        rows = json.loads(r.data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "x.es")


if __name__ == "__main__":
    unittest.main(verbosity=2)
