#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — Scanner Modules
Tests for tls_probe, crypto_extractor, service_discovery, and starttls_probe.
All tests are offline (no network activity).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import sys
import os
import ssl
import socket
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.tls_probe import _infer_key_exchange, _detect_pqc
from scanner.crypto_extractor import (
    extract, extract_all, summarise_domain, CryptoFacts,
    _nearest_rsa_strength, _nearest_ecc_strength,
)
from scanner.service_discovery import _tcp_connect, _resolve_ip


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_raw(tls="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
              key_type="RSA", key_size=4096, sig_alg="sha256WithRSAEncryption",
              hash_alg="SHA-256", pqc_kem=False, pqc_sig=False,
              expiry=180, success=True, source="direct"):
    return {
        "domain": "test.example.com", "port": 443,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": success, "source": source,
        "tls_version": tls, "cipher_suite": cipher, "cipher_bits": 256,
        "key_exchange": "", "has_pqc_kem": pqc_kem, "has_pqc_sig": pqc_sig,
        "pqc_algorithms": [],
        "certificate": {
            "subject_cn": "test.example.com",
            "issuer_cn": "Test CA",
            "key_type": key_type, "key_size_bits": key_size,
            "signature_algorithm": sig_alg, "hash_algorithm": hash_alg,
            "days_to_expiry": expiry, "is_self_signed": False,
            "fingerprint_sha256": "abc123",
        }
    }


# ── tls_probe helpers ─────────────────────────────────────────────────────────

class TestInferKeyExchange(unittest.TestCase):
    def test_ecdhe(self):
        self.assertEqual(_infer_key_exchange("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), "ECDHE")

    def test_dhe(self):
        self.assertEqual(_infer_key_exchange("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"), "DHE")

    def test_tls13_cipher(self):
        # TLS 1.3 ciphers don't encode KEX in the name; fallback returns "RSA"
        # but probe passes tls_version; here we just test the function directly
        result = _infer_key_exchange("TLS_AES_256_GCM_SHA384")
        self.assertIn(result, ("RSA", "UNKNOWN", "TLS1.3", ""))

    def test_rsa_static(self):
        self.assertEqual(_infer_key_exchange("TLS_RSA_WITH_AES_256_CBC_SHA"), "RSA")


class TestDetectPQC(unittest.TestCase):
    def test_no_pqc(self):
        kem, sig, algos = _detect_pqc("TLS_AES_256_GCM_SHA384", "TLSv1.3")
        self.assertFalse(kem)
        self.assertFalse(sig)
        self.assertEqual(algos, [])

    def test_kyber_in_cipher(self):
        kem, sig, algos = _detect_pqc("X25519Kyber768", "TLSv1.3")
        self.assertTrue(kem)
        self.assertFalse(sig)

    def test_mlkem_in_cipher(self):
        kem, sig, algos = _detect_pqc("X25519MLKEM768", "TLSv1.3")
        self.assertTrue(kem)

    def test_dilithium_in_cipher(self):
        kem, sig, algos = _detect_pqc("dilithium3", "TLSv1.3")
        self.assertFalse(kem)
        self.assertTrue(sig)


# ── crypto_extractor ──────────────────────────────────────────────────────────

class TestRSAStrength(unittest.TestCase):
    def test_known_sizes(self):
        self.assertEqual(_nearest_rsa_strength(2048), 112)
        self.assertEqual(_nearest_rsa_strength(3072), 128)
        self.assertEqual(_nearest_rsa_strength(4096), 140)

    def test_below_minimum(self):
        self.assertLess(_nearest_rsa_strength(512), 80)

    def test_large_key(self):
        self.assertGreaterEqual(_nearest_rsa_strength(7680), 192)

    def test_zero(self):
        self.assertEqual(_nearest_rsa_strength(0), 0)


class TestECCStrength(unittest.TestCase):
    def test_p256(self):
        self.assertEqual(_nearest_ecc_strength(256), 128)

    def test_p384(self):
        self.assertEqual(_nearest_ecc_strength(384), 192)

    def test_small(self):
        self.assertLess(_nearest_ecc_strength(192), 128)


class TestExtract(unittest.TestCase):
    def test_failed_scan_returns_none(self):
        raw = _make_raw(success=False)
        self.assertIsNone(extract(raw))

    def test_shodan_source_always_extracted(self):
        raw = _make_raw(success=False, source="shodan")
        result = extract(raw)
        self.assertIsNotNone(result)

    def test_basic_extraction(self):
        raw = _make_raw()
        f = extract(raw)
        self.assertIsInstance(f, CryptoFacts)
        self.assertEqual(f.tls_version, "TLSv1.3")
        self.assertEqual(f.cipher_suite, "TLS_AES_256_GCM_SHA384")
        self.assertEqual(f.key_type, "RSA")
        self.assertEqual(f.key_size_bits, 4096)

    def test_strength_populated(self):
        f = extract(_make_raw(key_type="RSA", key_size=2048))
        self.assertEqual(f.key_strength_bits, 112)

    def test_ecc_extraction(self):
        f = extract(_make_raw(key_type="ECDSA", key_size=256))
        self.assertEqual(f.key_type, "ECDSA")
        self.assertEqual(f.key_strength_bits, 128)

    def test_hash_strength_sha256(self):
        f = extract(_make_raw(hash_alg="SHA-256"))
        self.assertEqual(f.hash_strength_bits, 128)

    def test_hash_strength_sha1(self):
        f = extract(_make_raw(hash_alg="SHA-1"))
        self.assertLess(f.hash_strength_bits, 100)

    def test_broken_cipher_flag(self):
        f = extract(_make_raw(cipher="TLS_RSA_WITH_RC4_128_SHA"))
        self.assertTrue(f.has_broken_cipher)

    def test_des_cipher_flag(self):
        f = extract(_make_raw(cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
        self.assertTrue(f.has_broken_cipher)

    def test_clean_cipher_no_broken_flag(self):
        f = extract(_make_raw(cipher="TLS_AES_256_GCM_SHA384"))
        self.assertFalse(f.has_broken_cipher)

    def test_weak_rsa_key_flag(self):
        f = extract(_make_raw(key_type="RSA", key_size=1024))
        self.assertTrue(f.has_weak_key)

    def test_strong_rsa_no_weak_flag(self):
        f = extract(_make_raw(key_type="RSA", key_size=2048))
        self.assertFalse(f.has_weak_key)

    def test_deprecated_hash_md5(self):
        f = extract(_make_raw(hash_alg="MD5"))
        self.assertTrue(f.has_deprecated_hash)

    def test_deprecated_hash_sha1(self):
        f = extract(_make_raw(hash_alg="SHA-1"))
        self.assertTrue(f.has_deprecated_hash)

    def test_good_hash_no_deprecated_flag(self):
        f = extract(_make_raw(hash_alg="SHA-256"))
        self.assertFalse(f.has_deprecated_hash)

    def test_old_tls_flag(self):
        f = extract(_make_raw(tls="TLSv1.0"))
        self.assertTrue(f.has_old_tls)

    def test_tls13_no_old_flag(self):
        f = extract(_make_raw(tls="TLSv1.3"))
        self.assertFalse(f.has_old_tls)

    def test_pqc_kem_detected(self):
        f = extract(_make_raw(pqc_kem=True))
        self.assertTrue(f.has_pqc_kem)
        self.assertTrue(f.is_pqc_ready)

    def test_forward_secrecy_ecdhe(self):
        raw = _make_raw(cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        f = extract(raw)
        self.assertTrue(f.has_forward_secrecy)

    def test_no_forward_secrecy_rsa_static(self):
        raw = _make_raw(tls="TLSv1.2", cipher="TLS_RSA_WITH_AES_256_GCM_SHA384")
        raw["key_exchange"] = ""   # force inference from cipher name
        f = extract(raw)
        self.assertFalse(f.has_forward_secrecy)

    def test_tls13_implicit_forward_secrecy(self):
        # TLS 1.3 always has forward secrecy; key_exchange inferred as TLS1.3
        raw = _make_raw(tls="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")
        f = extract(raw)
        self.assertTrue(f.has_forward_secrecy)

    def test_overall_strength_is_minimum(self):
        # RSA-2048 → 112 bits, SHA-1 → 69 bits; TLS 1.3 → 128; min = 69
        f = extract(_make_raw(key_type="RSA", key_size=2048, hash_alg="SHA-1", tls="TLSv1.3"))
        self.assertEqual(f.overall_strength_bits, 69)


class TestExtractAll(unittest.TestCase):
    def test_filters_failures(self):
        raws = [
            _make_raw(success=True),
            _make_raw(success=False),
            _make_raw(success=True),
        ]
        results = extract_all(raws)
        self.assertEqual(len(results), 2)

    def test_empty_input(self):
        self.assertEqual(extract_all([]), [])

    def test_none_in_list(self):
        results = extract_all([None, _make_raw(), None])
        self.assertEqual(len(results), 1)


class TestSummariseDomain(unittest.TestCase):
    def test_empty_returns_minimal(self):
        s = summarise_domain("test.com", [])
        self.assertEqual(s["services"], 0)

    def test_pqc_aggregated(self):
        facts = [
            extract(_make_raw(pqc_kem=False)),
            extract(_make_raw(pqc_kem=True)),
        ]
        s = summarise_domain("test.com", facts)
        self.assertTrue(s["has_pqc"])

    def test_broken_cipher_aggregated(self):
        facts = [extract(_make_raw(cipher="TLS_RSA_WITH_RC4_128_SHA"))]
        s = summarise_domain("test.com", facts)
        self.assertTrue(s["has_broken_cipher"])

    def test_min_expiry_picked(self):
        f1 = extract(_make_raw(expiry=300))
        f2 = extract(_make_raw(expiry=15))
        s = summarise_domain("test.com", [f1, f2])
        self.assertEqual(s["min_cert_expiry_days"], 15)

    def test_tls_versions_collected(self):
        f1 = extract(_make_raw(tls="TLSv1.3"))
        f2 = extract(_make_raw(tls="TLSv1.2"))
        s = summarise_domain("test.com", [f1, f2])
        self.assertIn("TLSv1.3", s["tls_versions"])
        self.assertIn("TLSv1.2", s["tls_versions"])


# ── service_discovery (offline) ───────────────────────────────────────────────

class TestServiceDiscovery(unittest.TestCase):
    @patch("scanner.service_discovery.socket.create_connection")
    def test_open_port_returns_service(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        ok, err = _tcp_connect("example.com", 443, timeout=1)
        self.assertTrue(ok)
        self.assertIsNone(err)

    @patch("scanner.service_discovery.socket.create_connection",
           side_effect=ConnectionRefusedError)
    def test_refused_returns_false(self, _):
        ok, err = _tcp_connect("example.com", 9999, timeout=1)
        self.assertFalse(ok)
        self.assertEqual(err, "refused")

    @patch("scanner.service_discovery.socket.create_connection",
           side_effect=socket.timeout)
    def test_timeout_returns_false(self, _):
        ok, err = _tcp_connect("example.com", 443, timeout=1)
        self.assertFalse(ok)
        self.assertEqual(err, "timeout")

    @patch("scanner.service_discovery.socket.gethostbyname", return_value="93.184.216.34")
    def test_resolve_ip(self, _):
        ip = _resolve_ip("example.com")
        self.assertEqual(ip, "93.184.216.34")

    @patch("scanner.service_discovery.socket.gethostbyname",
           side_effect=socket.gaierror)
    def test_resolve_ip_fails(self, _):
        ip = _resolve_ip("nonexistent.invalid")
        self.assertIsNone(ip)


# ── migrations ────────────────────────────────────────────────────────────────

class TestMigrations(unittest.TestCase):
    def test_migrations_apply_cleanly(self):
        import sqlite3, tempfile, os as _os
        tmp = tempfile.mktemp(suffix=".db")
        try:
            # Bootstrap schema then run migrations
            from data.database import Database
            db = Database(tmp)
            from data.migrations import apply_migrations, _current_version
            with db._connect() as conn:
                ver = _current_version(conn)
            self.assertGreater(ver, 0)
        finally:
            if _os.path.exists(tmp):
                _os.unlink(tmp)

    def test_idempotent(self):
        """Running migrations twice must not raise."""
        import sqlite3, tempfile, os as _os
        tmp = tempfile.mktemp(suffix=".db")
        try:
            from data.database import Database
            db = Database(tmp)
            from data.migrations import apply_migrations
            with db._connect() as conn:
                apply_migrations(conn)  # second run
        finally:
            if _os.path.exists(tmp):
                _os.unlink(tmp)


# ── report_generator ──────────────────────────────────────────────────────────

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        import tempfile, sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from data.database import Database
        from tests.seed_demo_data import seed_run, DOMAIN_PROFILES
        from scanner.crypto_assessor import CryptoAssessor

        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmpdir, "test.db"))
        assessor = CryptoAssessor(
            guidelines_dir=os.path.join(os.path.dirname(__file__), "..", "guidelines")
        )
        self.run_id = seed_run(
            self.db, assessor, DOMAIN_PROFILES[:5],
            sector="finance", region="Spain", days_ago=0
        )

    def test_csv_export_has_header(self):
        from reports.report_generator import export_csv
        csv = export_csv(self.db)
        self.assertIn("domain", csv)
        self.assertIn("score", csv)
        self.assertIn("level", csv)

    def test_csv_export_has_rows(self):
        from reports.report_generator import export_csv
        csv = export_csv(self.db)
        lines = [l for l in csv.strip().split("\n") if l]
        self.assertGreater(len(lines), 1)   # header + at least one data row

    def test_json_export_valid(self):
        import json
        from reports.report_generator import export_json
        raw = export_json(self.db)
        data = json.loads(raw)
        self.assertIn("export_metadata", data)
        self.assertIn("assessments", data)
        self.assertIn("summary", data)

    def test_json_has_tool_field(self):
        import json
        from reports.report_generator import export_json
        data = json.loads(export_json(self.db))
        self.assertIn("PQC-Monitor", data["export_metadata"]["tool"])

    def test_text_report_has_summary(self):
        from reports.report_generator import export_text_report
        txt = export_text_report(self.db)
        self.assertIn("SUMMARY", txt)
        self.assertIn("DOMAIN ASSESSMENTS", txt)
        self.assertIn("GUIDELINES APPLIED", txt)

    def test_text_report_has_domain_lines(self):
        from reports.report_generator import export_text_report
        txt = export_text_report(self.db)
        # Should contain at least one scored domain line
        scored_lines = [l for l in txt.split("\n")
                        if any(e in l for e in ("🔴", "🟠", "🟡", "🟢"))]
        self.assertGreater(len(scored_lines), 0)

    def test_run_specific_csv(self):
        from reports.report_generator import export_csv
        csv = export_csv(self.db, run_id=self.run_id)
        self.assertIn("domain", csv)

    def test_csv_for_missing_run_is_header_only(self):
        from reports.report_generator import export_csv
        csv = export_csv(self.db, run_id="nonexistent")
        lines = [l for l in csv.strip().split("\n") if l]
        self.assertEqual(len(lines), 1)   # header only


if __name__ == "__main__":
    unittest.main(verbosity=2)
