#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — Scan Quality Modules
Tests for chain_validator, cipher_enum, and cdn_detector.
All tests are fully offline — no network calls made.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os
import sys
import ssl
import socket
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.chain_validator import (
    _parse_cert_node, _classify_cert_node, _check_chain_continuity,
    chain_findings, ChainAnalysis, CertNode,
    _BROKEN_HASHES, _WEAK_RSA_BITS,
)
from scanner.cipher_enum import (
    _OPENSSL_TO_IANA, TLS12_CIPHER_GROUPS, TLS13_CIPHERS,
    cipher_enum_findings, CipherEnumResult,
)
from scanner.cdn_detector import (
    CDN_REGISTRY, _match_patterns, _ip_in_cdn_cidr,
    cdn_findings, CDNDetectionResult, detect_cdn,
)
from scanner.crypto_assessor import CryptoAssessor
from data.database import Database


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _make_cert_node(role="leaf", key_type="RSA", key_bits=4096,
                    hash_alg="SHA-256", sig_alg="sha256WithRSAEncryption",
                    subject_cn="example.com", issuer_cn="Test CA",
                    days_to_expiry=365, is_ca=False, is_self_signed=False,
                    position=0) -> CertNode:
    node = CertNode(
        position=position,
        role=role,
        subject_cn=subject_cn,
        subject_dn=f"CN={subject_cn}",
        issuer_cn=issuer_cn,
        issuer_dn=f"CN={issuer_cn}",
        not_before="2024-01-01T00:00:00+00:00",
        not_after=(datetime.now(timezone.utc) +
                   timedelta(days=days_to_expiry)).isoformat(),
        days_to_expiry=days_to_expiry,
        serial_number="0xdeadbeef",
        fingerprint_sha256="abc" * 20,
        key_type=key_type,
        key_size_bits=key_bits,
        signature_algorithm=sig_alg,
        hash_algorithm=hash_alg,
        is_self_signed=is_self_signed,
        is_ca=is_ca,
        path_length_constraint=None,
    )
    _classify_cert_node(node)
    return node


def _make_chain_analysis(chain_complete=True, chain_ordered=True,
                          has_broken_intermediate=False,
                          has_weak_intermediate=False,
                          has_weak_root=False,
                          has_hsts=True, hsts_max_age=31536000,
                          has_caa=True, success=True,
                          certs=None) -> ChainAnalysis:
    return ChainAnalysis(
        domain="test.example.com", port=443,
        timestamp=datetime.now(timezone.utc).isoformat(),
        success=success,
        chain_length=len(certs) if certs else 2,
        chain_complete=chain_complete,
        chain_ordered=chain_ordered,
        certs=certs or [],
        has_weak_intermediate=has_weak_intermediate,
        has_broken_intermediate=has_broken_intermediate,
        has_weak_root=has_weak_root,
        weakest_link_position=0,
        weakest_link_bits=4096,
        weakest_hash="SHA-256",
        has_hsts=has_hsts,
        hsts_max_age=hsts_max_age,
        has_expect_ct=False,
        has_caa_record=has_caa,
    )


def _make_enum_result(**kwargs) -> CipherEnumResult:
    defaults = dict(
        domain="test.example.com", port=443,
        timestamp=datetime.now(timezone.utc).isoformat(),
        success=True,
        supported_ciphers=[],
        tls13_supported=True, tls12_supported=True,
        recommended_count=3, acceptable_count=0,
        deprecated_count=0, disallowed_count=0,
        has_null_cipher=False, has_export_cipher=False,
        has_anon_cipher=False, has_rc4=False, has_3des=False,
        has_no_forward_secrecy=False,
    )
    defaults.update(kwargs)
    return CipherEnumResult(**defaults)


def _make_cdn_result(detected=False, cdn_name=None, pqc_support="n/a") -> CDNDetectionResult:
    return CDNDetectionResult(
        domain="test.example.com",
        resolved_ip="1.2.3.4",
        ptr_record=None,
        cname_chain=["test.example.com"],
        detected=detected,
        cdn_name=cdn_name,
        cdn_slug=cdn_name.lower().replace(" ", "-") if cdn_name else None,
        pqc_support=pqc_support,
        pqc_note="",
        confidence="high" if detected else "n/a",
        evidence=[],
        origin_hidden=detected,
        http_headers={},
    )


# ═══════════════════════════════════════════════════════════════════
# chain_validator tests
# ═══════════════════════════════════════════════════════════════════

class TestCertNodeClassification(unittest.TestCase):
    def test_strong_rsa_no_flags(self):
        n = _make_cert_node(key_type="RSA", key_bits=4096, hash_alg="SHA-256")
        self.assertFalse(n.weak_key)
        self.assertFalse(n.weak_hash)
        self.assertFalse(n.broken_hash)

    def test_weak_rsa_1024_flag(self):
        n = _make_cert_node(key_type="RSA", key_bits=1024)
        self.assertTrue(n.weak_key)

    def test_rsa_2048_is_weak_key(self):
        # 2048 is below _WEAK_RSA_BITS (2048 is the threshold)
        n = _make_cert_node(key_type="RSA", key_bits=2047)
        self.assertTrue(n.weak_key)

    def test_rsa_2048_exact_is_not_weak(self):
        n = _make_cert_node(key_type="RSA", key_bits=2048)
        self.assertFalse(n.weak_key)

    def test_ecdsa_256_no_weak_flag(self):
        n = _make_cert_node(key_type="ECDSA", key_bits=256)
        self.assertFalse(n.weak_key)

    def test_ecdsa_192_weak_flag(self):
        n = _make_cert_node(key_type="ECDSA", key_bits=192)
        self.assertTrue(n.weak_key)

    def test_sha1_broken_hash(self):
        n = _make_cert_node(hash_alg="SHA-1")
        self.assertTrue(n.broken_hash)
        self.assertFalse(n.weak_hash)

    def test_md5_broken_hash(self):
        n = _make_cert_node(hash_alg="MD5")
        self.assertTrue(n.broken_hash)

    def test_sha224_weak_hash(self):
        n = _make_cert_node(hash_alg="SHA-224")
        self.assertTrue(n.weak_hash)
        self.assertFalse(n.broken_hash)

    def test_sha256_no_hash_flags(self):
        n = _make_cert_node(hash_alg="SHA-256")
        self.assertFalse(n.broken_hash)
        self.assertFalse(n.weak_hash)

    def test_sha384_no_hash_flags(self):
        n = _make_cert_node(hash_alg="SHA-384")
        self.assertFalse(n.broken_hash)
        self.assertFalse(n.weak_hash)

    def test_ed25519_never_weak_key(self):
        n = _make_cert_node(key_type="Ed25519", key_bits=256)
        self.assertFalse(n.weak_key)


class TestChainContinuity(unittest.TestCase):
    def _node(self, subject, issuer, role="intermediate", position=0):
        n = _make_cert_node(subject_cn=subject, issuer_cn=issuer,
                             role=role, position=position)
        n.subject_dn = f"CN={subject}"
        n.issuer_dn  = f"CN={issuer}"
        return n

    def test_complete_ordered_chain(self):
        leaf  = self._node("leaf.example.com", "Intermediate CA", "leaf",  0)
        inter = self._node("Intermediate CA",  "Root CA",         "intermediate", 1)
        root  = self._node("Root CA",          "Root CA",         "root",  2)
        root.is_self_signed = True

        complete, ordered = _check_chain_continuity([leaf, inter, root])
        self.assertTrue(complete)
        self.assertTrue(ordered)

    def test_chain_with_gap(self):
        leaf  = self._node("leaf.example.com", "Intermediate CA", "leaf", 0)
        # Gap: leaf's issuer does not match next cert's subject
        root  = self._node("Root CA", "Root CA", "root", 1)
        complete, _ = _check_chain_continuity([leaf, root])
        self.assertFalse(complete)

    def test_single_cert_is_complete(self):
        n = self._node("self.example.com", "self.example.com", "root", 0)
        complete, ordered = _check_chain_continuity([n])
        self.assertTrue(complete)
        self.assertTrue(ordered)

    def test_empty_chain(self):
        complete, ordered = _check_chain_continuity([])
        self.assertTrue(complete)
        self.assertTrue(ordered)


class TestChainFindings(unittest.TestCase):
    def test_clean_chain_minimal_findings(self):
        a = _make_chain_analysis()
        f = chain_findings(a)
        # Only low-severity findings expected (no critical/high with clean config)
        high_critical = [x for x in f if x.get("severity") in ("critical", "high")]
        self.assertEqual(high_critical, [])

    def test_broken_intermediate_gives_critical(self):
        broken_node = _make_cert_node(
            role="intermediate", hash_alg="SHA-1",
            subject_cn="Bad CA", issuer_cn="Root CA", position=1
        )
        a = _make_chain_analysis(
            has_broken_intermediate=True,
            certs=[broken_node.to_dict()]
        )
        f = chain_findings(a)
        severities = [x["severity"] for x in f]
        self.assertIn("critical", severities)

    def test_incomplete_chain_gives_high(self):
        a = _make_chain_analysis(chain_complete=False)
        f = chain_findings(a)
        severities = [x["severity"] for x in f]
        self.assertIn("high", severities)

    def test_missing_hsts_gives_medium(self):
        a = _make_chain_analysis(has_hsts=False)
        f = chain_findings(a)
        categories = [x["category"] for x in f]
        self.assertIn("chain", categories)
        medium = [x for x in f if x["severity"] == "medium" and "HSTS" in x["message"]]
        self.assertTrue(len(medium) > 0)

    def test_short_hsts_gives_low(self):
        a = _make_chain_analysis(has_hsts=True, hsts_max_age=3600)  # 1 hour
        f = chain_findings(a)
        low = [x for x in f if x["severity"] == "low" and "max-age" in x["message"]]
        self.assertTrue(len(low) > 0)

    def test_missing_caa_gives_low(self):
        a = _make_chain_analysis(has_caa=False)
        f = chain_findings(a)
        low_caa = [x for x in f if "CAA" in x["message"]]
        self.assertTrue(len(low_caa) > 0)

    def test_no_findings_on_failure(self):
        a = _make_chain_analysis(success=False)
        a.success = False
        f = chain_findings(a)
        self.assertEqual(f, [])

    def test_expired_intermediate_critical(self):
        node = _make_cert_node(role="intermediate", days_to_expiry=-5,
                                subject_cn="expired-ca", issuer_cn="Root CA",
                                position=1)
        a = _make_chain_analysis(certs=[node.to_dict()])
        f = chain_findings(a)
        critical = [x for x in f if x["severity"] == "critical"
                    and "expired" in x["message"].lower()]
        self.assertTrue(len(critical) > 0)


# ═══════════════════════════════════════════════════════════════════
# cipher_enum tests
# ═══════════════════════════════════════════════════════════════════

class TestCipherEnumRegistry(unittest.TestCase):
    def test_all_tls13_ciphers_listed(self):
        names = [name for name, _ in TLS13_CIPHERS]
        self.assertIn("TLS_AES_256_GCM_SHA384", names)
        self.assertIn("TLS_AES_128_GCM_SHA256", names)
        self.assertIn("TLS_CHACHA20_POLY1305_SHA256", names)

    def test_dangerous_ciphers_in_groups(self):
        group_names = [g[0] for g in TLS12_CIPHER_GROUPS]
        self.assertIn("RC4-SHA", group_names)
        self.assertIn("NULL-SHA", group_names)
        self.assertIn("EXP-RC4-MD5", group_names)

    def test_iana_map_covers_key_suites(self):
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", _OPENSSL_TO_IANA)
        self.assertIn("AES256-GCM-SHA384", _OPENSSL_TO_IANA)
        self.assertIn("RC4-SHA", _OPENSSL_TO_IANA)

    def test_no_duplicate_openssl_names_in_groups(self):
        names = [g[0] for g in TLS12_CIPHER_GROUPS]
        self.assertEqual(len(names), len(set(names)), "Duplicate cipher group entries")

    def test_security_levels_valid(self):
        valid = {"recommended", "acceptable", "deprecated", "disallowed"}
        for name, cat, level in TLS12_CIPHER_GROUPS:
            self.assertIn(level, valid, f"{name} has invalid level {level!r}")


class TestCipherEnumFindings(unittest.TestCase):
    def test_clean_server_no_critical_findings(self):
        r = _make_enum_result(recommended_count=5)
        f = cipher_enum_findings(r)
        crit = [x for x in f if x["severity"] == "critical"]
        self.assertEqual(crit, [])

    def test_null_cipher_critical(self):
        r = _make_enum_result(has_null_cipher=True)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "critical" and "NULL" in x["message"] for x in f))

    def test_export_cipher_critical(self):
        r = _make_enum_result(has_export_cipher=True)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "critical" and "EXPORT" in x["message"] for x in f))

    def test_anon_cipher_critical(self):
        r = _make_enum_result(has_anon_cipher=True)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "critical" and "anonymous" in x["message"] for x in f))

    def test_rc4_critical(self):
        r = _make_enum_result(has_rc4=True)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "critical" and "RC4" in x["message"] for x in f))

    def test_3des_high(self):
        r = _make_enum_result(has_3des=True)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "high" and "3DES" in x["message"] for x in f))

    def test_no_tls13_medium_finding(self):
        r = _make_enum_result(tls13_supported=False)
        f = cipher_enum_findings(r)
        self.assertTrue(any("TLS 1.3" in x["message"] for x in f))

    def test_deprecated_ciphers_medium(self):
        r = _make_enum_result(deprecated_count=3)
        f = cipher_enum_findings(r)
        self.assertTrue(any(x["severity"] == "medium" and "deprecated" in x["message"] for x in f))

    def test_no_forward_secrecy_high(self):
        r = _make_enum_result(has_no_forward_secrecy=True, tls13_supported=False)
        f = cipher_enum_findings(r)
        self.assertTrue(any("forward secrecy" in x["message"] for x in f))


class TestCipherEnumScoring(unittest.TestCase):
    """Test that cipher enum findings affect assessor score correctly."""

    def setUp(self):
        import os as _os
        self.assessor = CryptoAssessor(
            guidelines_dir=_os.path.join(_os.path.dirname(__file__), "..", "guidelines")
        )
        self.base_scan = [{
            "domain": "x.com", "port": 443, "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256, "key_exchange": "TLS1.3",
            "has_pqc_kem": False, "has_pqc_sig": False,
            "certificate": {
                "key_type": "RSA", "key_size_bits": 4096,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hash_algorithm": "SHA-256", "days_to_expiry": 300,
                "is_self_signed": False
            }
        }]

    def test_null_cipher_lowers_score(self):
        clean = self.assessor.assess_domain("x.com", self.base_scan)
        dirty = self.assessor.assess_domain(
            "x.com", self.base_scan,
            cipher_enum=_make_enum_result(has_null_cipher=True).to_dict()
        )
        self.assertLess(dirty.score, clean.score)

    def test_rc4_lowers_score(self):
        clean = self.assessor.assess_domain("x.com", self.base_scan)
        dirty = self.assessor.assess_domain(
            "x.com", self.base_scan,
            cipher_enum=_make_enum_result(has_rc4=True).to_dict()
        )
        self.assertLess(dirty.score, clean.score)

    def test_broken_intermediate_lowers_score(self):
        clean = self.assessor.assess_domain("x.com", self.base_scan)
        dirty = self.assessor.assess_domain(
            "x.com", self.base_scan,
            chain_analysis=_make_chain_analysis(
                has_broken_intermediate=True).to_dict()
        )
        self.assertLess(dirty.score, clean.score)


# ═══════════════════════════════════════════════════════════════════
# cdn_detector tests
# ═══════════════════════════════════════════════════════════════════

class TestCDNRegistry(unittest.TestCase):
    def test_all_required_cdns_present(self):
        slugs = {c.slug for c in CDN_REGISTRY}
        for required in ("cloudflare", "fastly", "cloudfront", "akamai"):
            self.assertIn(required, slugs)

    def test_pqc_support_values_valid(self):
        valid = {"yes", "no", "partial", "unknown"}
        for profile in CDN_REGISTRY:
            self.assertIn(profile.pqc_support, valid,
                          f"{profile.name} has invalid pqc_support")

    def test_cloudflare_has_cidr_blocks(self):
        cf = next(c for c in CDN_REGISTRY if c.slug == "cloudflare")
        self.assertGreater(len(cf.cidr_blocks), 5)

    def test_cloudflare_pqc_support_yes(self):
        cf = next(c for c in CDN_REGISTRY if c.slug == "cloudflare")
        self.assertEqual(cf.pqc_support, "yes")

    def test_all_profiles_have_pqc_note(self):
        for profile in CDN_REGISTRY:
            self.assertTrue(len(profile.pqc_note) > 10,
                            f"{profile.name} has empty pqc_note")


class TestMatchPatterns(unittest.TestCase):
    def test_cloudflare_cname_match(self):
        patterns = [r"\.cloudflare\.com$", r"\.cloudflare\.net$"]
        self.assertTrue(_match_patterns("example.cloudflare.com", patterns))
        self.assertTrue(_match_patterns("example.cloudflare.net", patterns))

    def test_no_match(self):
        patterns = [r"\.cloudflare\.com$"]
        self.assertFalse(_match_patterns("example.fastly.net", patterns))

    def test_empty_value(self):
        self.assertFalse(_match_patterns("", [r"\.cloudflare\.com$"]))

    def test_empty_patterns(self):
        self.assertFalse(_match_patterns("example.com", []))

    def test_case_insensitive(self):
        self.assertTrue(_match_patterns("SERVER: CloudFlare",
                                         [r"(?i)cloudflare"]))


class TestIPInCDNCIDR(unittest.TestCase):
    def test_cloudflare_ip_detected(self):
        cf = next(c for c in CDN_REGISTRY if c.slug == "cloudflare")
        # 104.16.0.1 is in Cloudflare's 104.16.0.0/13 block
        self.assertTrue(_ip_in_cdn_cidr("104.16.0.1", cf))

    def test_non_cdn_ip_not_detected(self):
        cf = next(c for c in CDN_REGISTRY if c.slug == "cloudflare")
        self.assertFalse(_ip_in_cdn_cidr("8.8.8.8", cf))

    def test_empty_cidr_list(self):
        from scanner.cdn_detector import CDNProfile
        p = CDNProfile("Test", "test", "unknown", "", [], {}, [], [], [], [])
        self.assertFalse(_ip_in_cdn_cidr("1.2.3.4", p))

    def test_invalid_ip(self):
        cf = next(c for c in CDN_REGISTRY if c.slug == "cloudflare")
        self.assertFalse(_ip_in_cdn_cidr("not-an-ip", cf))


class TestCDNFindings(unittest.TestCase):
    def test_no_cdn_no_findings(self):
        r = _make_cdn_result(detected=False)
        f = cdn_findings(r)
        self.assertEqual(f, [])

    def test_cdn_detected_info_finding(self):
        r = _make_cdn_result(detected=True, cdn_name="Cloudflare", pqc_support="yes")
        f = cdn_findings(r)
        self.assertTrue(any(x["severity"] == "info" for x in f))

    def test_cdn_no_pqc_medium_finding(self):
        r = _make_cdn_result(detected=True, cdn_name="TestCDN", pqc_support="no")
        f = cdn_findings(r)
        self.assertTrue(any(x["severity"] == "medium" for x in f))

    def test_cdn_partial_pqc_no_medium(self):
        r = _make_cdn_result(detected=True, cdn_name="Fastly", pqc_support="partial")
        f = cdn_findings(r)
        self.assertFalse(any(x["severity"] == "medium" for x in f))


class TestDetectCDNMocked(unittest.TestCase):
    """Test the full detect_cdn() function with all I/O mocked."""

    @patch("scanner.cdn_detector._walk_cnames")
    @patch("scanner.cdn_detector._resolve_ip")
    @patch("scanner.cdn_detector._ptr_lookup")
    @patch("scanner.cdn_detector._fetch_http_headers")
    def test_cloudflare_detected_via_cname(self, mock_hdrs, mock_ptr,
                                            mock_ip, mock_cnames):
        mock_cnames.return_value = ["example.com", "example.cloudflare.com"]
        mock_ip.return_value = "104.16.0.1"
        mock_ptr.return_value = "104.16.0.1.cloudflare.net"
        mock_hdrs.return_value = {"cf-ray": "abc123-LHR"}

        result = detect_cdn("example.com", cert_sans=[])
        self.assertTrue(result.detected)
        self.assertEqual(result.cdn_slug, "cloudflare")
        self.assertEqual(result.pqc_support, "yes")

    @patch("scanner.cdn_detector._walk_cnames")
    @patch("scanner.cdn_detector._resolve_ip")
    @patch("scanner.cdn_detector._ptr_lookup")
    @patch("scanner.cdn_detector._fetch_http_headers")
    def test_fastly_detected_via_header(self, mock_hdrs, mock_ptr,
                                         mock_ip, mock_cnames):
        mock_cnames.return_value = ["example.com"]
        mock_ip.return_value = "151.101.0.1"
        mock_ptr.return_value = None
        mock_hdrs.return_value = {"x-served-by": "cache-lhr1234-LHR fastly"}

        result = detect_cdn("example.com", cert_sans=[])
        self.assertTrue(result.detected)
        self.assertEqual(result.cdn_slug, "fastly")

    @patch("scanner.cdn_detector._walk_cnames")
    @patch("scanner.cdn_detector._resolve_ip")
    @patch("scanner.cdn_detector._ptr_lookup")
    @patch("scanner.cdn_detector._fetch_http_headers")
    def test_no_cdn_when_no_signals(self, mock_hdrs, mock_ptr,
                                     mock_ip, mock_cnames):
        mock_cnames.return_value = ["origin-server.example.com"]
        mock_ip.return_value = "93.184.216.34"
        mock_ptr.return_value = None
        mock_hdrs.return_value = {"server": "Apache/2.4"}

        result = detect_cdn("origin.example.com", cert_sans=[])
        self.assertFalse(result.detected)
        self.assertIsNone(result.cdn_name)

    @patch("scanner.cdn_detector._walk_cnames")
    @patch("scanner.cdn_detector._resolve_ip")
    @patch("scanner.cdn_detector._ptr_lookup")
    @patch("scanner.cdn_detector._fetch_http_headers")
    def test_cert_san_cloudflare_detected(self, mock_hdrs, mock_ptr,
                                           mock_ip, mock_cnames):
        mock_cnames.return_value = ["example.com"]
        mock_ip.return_value = "104.21.0.1"   # Cloudflare range
        mock_ptr.return_value = None
        mock_hdrs.return_value = {}

        result = detect_cdn("example.com",
                             cert_sans=["*.cloudflare.com", "example.com"])
        self.assertTrue(result.detected)
        self.assertEqual(result.cdn_slug, "cloudflare")

    @patch("scanner.cdn_detector._walk_cnames")
    @patch("scanner.cdn_detector._resolve_ip")
    @patch("scanner.cdn_detector._ptr_lookup")
    @patch("scanner.cdn_detector._fetch_http_headers")
    def test_cdn_result_has_origin_hidden_flag(self, mock_hdrs, mock_ptr,
                                                mock_ip, mock_cnames):
        mock_cnames.return_value = ["example.cloudfront.net"]
        mock_ip.return_value = "13.32.0.1"
        mock_ptr.return_value = "server.cloudfront.net"
        mock_hdrs.return_value = {"x-amz-cf-id": "abc"}

        result = detect_cdn("example.com", cert_sans=[])
        self.assertTrue(result.origin_hidden)


# ═══════════════════════════════════════════════════════════════════
# Database domain_extra tests
# ═══════════════════════════════════════════════════════════════════

class TestDomainExtra(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmpdir, "extra_test.db"))
        self.run_id = self.db.create_run(["test.com"])

    def test_save_and_retrieve_chain(self):
        data = {"chain_length": 3, "chain_complete": True, "has_hsts": True}
        self.db.save_domain_extra(self.run_id, "test.com", "chain", data)
        extra = self.db.get_domain_extra("test.com", self.run_id)
        self.assertIn("chain", extra)
        self.assertEqual(extra["chain"]["chain_length"], 3)

    def test_save_all_three_types(self):
        self.db.save_domain_extra(self.run_id, "test.com", "chain", {"x": 1})
        self.db.save_domain_extra(self.run_id, "test.com", "cipher_enum", {"y": 2})
        self.db.save_domain_extra(self.run_id, "test.com", "cdn", {"z": 3})
        extra = self.db.get_domain_extra("test.com", self.run_id)
        self.assertIn("chain", extra)
        self.assertIn("cipher_enum", extra)
        self.assertIn("cdn", extra)

    def test_missing_domain_returns_empty(self):
        extra = self.db.get_domain_extra("nonexistent.com", self.run_id)
        self.assertEqual(extra, {})

    def test_upsert_replaces_previous(self):
        self.db.save_domain_extra(self.run_id, "test.com", "cdn", {"detected": False})
        self.db.save_domain_extra(self.run_id, "test.com", "cdn", {"detected": True})
        extra = self.db.get_domain_extra("test.com", self.run_id)
        self.assertTrue(extra["cdn"]["detected"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
