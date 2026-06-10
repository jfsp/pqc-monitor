#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — Crypto Assessor
Tests scoring logic against known-good/known-bad cipher/TLS inputs.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import sys
import os
import json
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.crypto_assessor import CryptoAssessor, Finding, score_to_level

GUIDELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "guidelines")


def _make_scan(tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
               key_type="RSA", key_size=4096, sig_alg="sha256WithRSAEncryption",
               hash_alg="SHA-256", has_pqc_kem=False, has_pqc_sig=False,
               expiry_days=180, port=443, success=True):
    return {
        "domain": "test.example.com",
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": success,
        "tls_version": tls_version,
        "cipher_suite": cipher,
        "cipher_bits": 256,
        "key_exchange": "TLS1.3",
        "has_pqc_kem": has_pqc_kem,
        "has_pqc_sig": has_pqc_sig,
        "certificate": {
            "subject_cn": "test.example.com",
            "key_type": key_type,
            "key_size_bits": key_size,
            "signature_algorithm": sig_alg,
            "hash_algorithm": hash_alg,
            "days_to_expiry": expiry_days,
            "is_self_signed": False,
        }
    }


class TestScoreToLevel(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(score_to_level(0),  "critical")
        self.assertEqual(score_to_level(25), "critical")

    def test_weak(self):
        self.assertEqual(score_to_level(26), "weak")
        self.assertEqual(score_to_level(50), "weak")

    def test_moderate(self):
        self.assertEqual(score_to_level(51), "moderate")
        self.assertEqual(score_to_level(75), "moderate")

    def test_ready(self):
        self.assertEqual(score_to_level(76),  "ready")
        self.assertEqual(score_to_level(100), "ready")


class TestCryptoAssessor(unittest.TestCase):

    def setUp(self):
        self.assessor = CryptoAssessor(
            guideline_ids=["nist_800_131a", "bsi_tr02102", "ccn_stic_221"],
            guidelines_dir=GUIDELINES_DIR
        )

    # ─── TLS version tests ────────────────────────────────────────

    def test_tls13_scores_higher_than_tls12(self):
        a13 = self.assessor.assess_domain("x.com", [_make_scan(tls_version="TLSv1.3")])
        a12 = self.assessor.assess_domain("x.com", [_make_scan(tls_version="TLSv1.2")])
        self.assertGreater(a13.score, a12.score)

    def test_tls10_has_critical_finding(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(tls_version="TLSv1.0")])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    def test_sslv3_has_critical_finding(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(tls_version="SSLv3")])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    # ─── Cipher suite tests ───────────────────────────────────────

    def test_rc4_cipher_critical(self):
        a = self.assessor.assess_domain("x.com", [
            _make_scan(cipher="TLS_RSA_WITH_RC4_128_SHA")
        ])
        # Must have a critical cipher finding
        cipher_findings = [f for f in a.findings
                           if (f.category if isinstance(f, Finding) else f.get("category")) == "cipher"]
        self.assertTrue(len(cipher_findings) > 0, "Expected cipher findings for RC4")
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in cipher_findings]
        self.assertIn("critical", severities, "RC4 cipher must produce a critical finding")

    def test_aes_gcm_scores_well(self):
        a = self.assessor.assess_domain("x.com", [
            _make_scan(cipher="TLS_AES_256_GCM_SHA384")
        ])
        # cipher-category findings should not be critical
        for f in a.findings:
            sev = f.severity if isinstance(f, Finding) else f.get("severity")
            cat = f.category if isinstance(f, Finding) else f.get("category")
            if cat == "cipher":
                self.assertNotEqual(sev, "critical")

    # ─── Key size tests ───────────────────────────────────────────

    def test_rsa_1024_is_critical(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(key_size=1024)])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    def test_rsa_2048_no_critical_key_finding(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(key_size=2048)])
        for f in a.findings:
            sev = f.severity if isinstance(f, Finding) else f.get("severity")
            cat = f.category if isinstance(f, Finding) else f.get("category")
            if cat == "key_size":
                self.assertNotEqual(sev, "critical",
                                    "RSA-2048 should not produce a critical key-size finding")

    def test_rsa_4096_good(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(key_size=4096)])
        for f in a.findings:
            cat = f.category if isinstance(f, Finding) else f.get("category")
            self.assertNotEqual(cat, "key_size",
                                "RSA-4096 should produce no key_size findings")

    # ─── Hash algorithm tests ─────────────────────────────────────

    def test_md5_cert_critical(self):
        a = self.assessor.assess_domain("x.com", [
            _make_scan(sig_alg="md5WithRSAEncryption", hash_alg="MD5")
        ])
        # should find critical hash finding
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    def test_sha1_cert_critical(self):
        a = self.assessor.assess_domain("x.com", [
            _make_scan(sig_alg="sha1WithRSAEncryption", hash_alg="SHA-1")
        ])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    def test_sha256_no_hash_finding(self):
        a = self.assessor.assess_domain("x.com", [
            _make_scan(sig_alg="sha256WithRSAEncryption", hash_alg="SHA-256")
        ])
        for f in a.findings:
            cat = f.category if isinstance(f, Finding) else f.get("category")
            sev = f.severity if isinstance(f, Finding) else f.get("severity")
            if cat == "hash":
                self.assertNotIn(sev, ("critical", "high"),
                                 "SHA-256 should not produce critical/high hash findings")

    # ─── PQC tests ────────────────────────────────────────────────

    def test_no_pqc_produces_medium_finding(self):
        a = self.assessor.assess_domain("x.com", [_make_scan()])
        categories = [f.category if isinstance(f, Finding) else f.get("category")
                      for f in a.findings]
        self.assertIn("pqc", categories)
        self.assertFalse(a.has_pqc)

    def test_pqc_detected_is_flagged(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(has_pqc_kem=True)])
        self.assertTrue(a.has_pqc)
        pqc_findings = [f for f in a.findings
                        if (f.category if isinstance(f, Finding) else f.get("category")) == "pqc"]
        self.assertTrue(len(pqc_findings) > 0)
        # PQC-detected finding should be info, not warning
        for f in pqc_findings:
            sev = f.severity if isinstance(f, Finding) else f.get("severity")
            self.assertEqual(sev, "info")

    # ─── Certificate expiry ───────────────────────────────────────

    def test_expired_cert_critical(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(expiry_days=-5)])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("critical", severities)

    def test_expiring_soon_high(self):
        a = self.assessor.assess_domain("x.com", [_make_scan(expiry_days=10)])
        severities = [f.severity if isinstance(f, Finding) else f.get("severity")
                      for f in a.findings]
        self.assertIn("high", severities)

    # ─── No scan data ─────────────────────────────────────────────

    def test_empty_scan_list(self):
        a = self.assessor.assess_domain("x.com", [])
        self.assertEqual(a.score, 0)
        self.assertEqual(a.level, "critical")

    def test_failed_scan(self):
        a = self.assessor.assess_domain("x.com", [
            {"domain": "x.com", "port": 443, "success": False,
             "error": "timeout", "timestamp": datetime.now(timezone.utc).isoformat()}
        ])
        self.assertLessEqual(a.score, 50)

    # ─── Score range ─────────────────────────────────────────────

    def test_score_always_0_to_100(self):
        for scan in [
            _make_scan(tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", key_size=4096),
            _make_scan(tls_version="SSLv3",   cipher="TLS_RSA_WITH_RC4_128_SHA", key_size=512),
            _make_scan(tls_version="TLSv1.2", has_pqc_kem=True, key_size=2048),
        ]:
            a = self.assessor.assess_domain("x.com", [scan])
            self.assertGreaterEqual(a.score, 0)
            self.assertLessEqual(a.score, 100)

    # ─── Guidelines loaded ────────────────────────────────────────

    def test_all_three_guidelines_loaded(self):
        self.assertIn("nist_800_131a", self.assessor.guidelines)
        self.assertIn("bsi_tr02102",   self.assessor.guidelines)
        self.assertIn("ccn_stic_221",  self.assessor.guidelines)

    def test_guideline_has_required_sections(self):
        for gid, g in self.assessor.guidelines.items():
            self.assertIn("tls_versions",   g, f"{gid} missing tls_versions")
            self.assertIn("cipher_suites",  g, f"{gid} missing cipher_suites")
            self.assertIn("key_sizes",      g, f"{gid} missing key_sizes")
            self.assertIn("hash_functions", g, f"{gid} missing hash_functions")


class TestDatabaseLayer(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from data.database import Database
        self.db = Database(os.path.join(self.tmpdir, "test.db"))

    def test_create_and_finish_run(self):
        run_id = self.db.create_run(["a.com", "b.com"], sector="finance", region="EU")
        self.assertIsNotNone(run_id)
        self.db.finish_run(run_id, "completed")
        runs = self.db.list_runs()
        self.assertTrue(any(r["run_id"] == run_id for r in runs))

    def test_save_and_retrieve_assessment(self):
        run_id = self.db.create_run(["test.com"])
        assessment = {
            "domain": "test.com",
            "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
            "guidelines_used": ["nist_800_131a"],
            "score": 72,
            "level": "moderate",
            "findings": [{"severity": "medium", "category": "pqc",
                           "message": "No PQC", "guideline": "all"}],
            "tls_versions_found": ["TLSv1.3"],
            "cipher_suites_found": ["TLS_AES_256_GCM_SHA384"],
            "has_pqc": False,
            "certificate_expiry_days": 200,
            "errors": []
        }
        self.db.save_assessment(run_id, assessment)
        results = self.db.get_latest_assessments(run_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["score"], 72)

    def test_domain_history_grows(self):
        for i, score in enumerate([40, 55, 68]):
            run_id = self.db.create_run(["evolving.com"])
            self.db.save_assessment(run_id, {
                "domain": "evolving.com",
                "assessment_timestamp": f"2024-0{i+1}-01T00:00:00+00:00",
                "guidelines_used": [], "score": score, "level": "moderate",
                "findings": [], "tls_versions_found": [], "cipher_suites_found": [],
                "has_pqc": False, "certificate_expiry_days": None, "errors": []
            })
            self.db.finish_run(run_id)

        history = self.db.get_domain_history("evolving.com")
        self.assertEqual(len(history), 3)
        scores = [h["score"] for h in history]
        self.assertEqual(scores, [40, 55, 68])

    def test_save_and_get_domain_list(self):
        domains = ["alpha.com", "beta.com", "gamma.com"]
        list_id = self.db.save_domain_list("test-list", domains, "test query")
        retrieved = self.db.get_domain_list_by_id(list_id)
        self.assertEqual(retrieved, domains)

    def test_summary_stats_empty(self):
        stats = self.db.get_summary_stats()
        # Should not crash on empty DB
        self.assertIsInstance(stats, dict)


class TestGuidelineJSON(unittest.TestCase):
    """Validate that all guideline JSON files are well-formed."""

    def _load(self, name):
        path = os.path.join(GUIDELINES_DIR, f"{name}.json")
        with open(path) as f:
            return json.load(f)

    def test_nist_json_valid(self):
        g = self._load("nist_800_131a")
        self.assertEqual(g["id"], "nist_800_131a")
        self.assertIn("TLSv1.3", g["tls_versions"])
        self.assertIn("RSA", g["key_sizes"])
        self.assertIn("recommended", g["cipher_suites"])

    def test_bsi_json_valid(self):
        g = self._load("bsi_tr02102")
        self.assertEqual(g["id"], "bsi_tr02102")
        self.assertIn("TLSv1.3", g["tls_versions"])
        self.assertIn("3000", str(g["key_sizes"]["RSA"]["recommended"]))

    def test_ccn_json_valid(self):
        g = self._load("ccn_stic_221")
        self.assertEqual(g["id"], "ccn_stic_221")
        self.assertIn("SHA-256", g["hash_functions"])

    def test_all_guidelines_have_pqc_section(self):
        for name in ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"]:
            g = self._load(name)
            self.assertIn("pqc_algorithms", g, f"{name} missing pqc_algorithms section")


if __name__ == "__main__":
    unittest.main(verbosity=2)
