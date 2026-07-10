#!/usr/bin/env python3
"""
Tests for v1.9.0: SSL Labs client summarisation and cipher-enum findings
that name the specific suites to remove.

SPDX-License-Identifier: GPL-3.0-or-later
"""

import unittest

from scanner.ssllabs_client import SSLLabsClient, worst_grade
from scanner.cipher_enum import (
    CipherEnumResult, CipherResult, cipher_enum_findings,
)


class TestWorstGrade(unittest.TestCase):
    def test_worst_of_mixed(self):
        self.assertEqual(worst_grade(["A+", "B", "A"]), "B")
        self.assertEqual(worst_grade(["A", "F"]), "F")
        self.assertEqual(worst_grade(["T", "A+"]), "T")

    def test_single_and_empty(self):
        self.assertEqual(worst_grade(["A-"]), "A-")
        self.assertEqual(worst_grade([]), "")


class TestSummarize(unittest.TestCase):
    REPORT = {
        "status": "READY",
        "engineVersion": "2.4.0",
        "criteriaVersion": "2009q",
        "testTime": 1751980000000,
        "endpoints": [
            {"ipAddress": "192.0.2.1", "grade": "A", "hasWarnings": False,
             "statusMessage": "Ready"},
            {"ipAddress": "192.0.2.2", "grade": "B", "hasWarnings": True,
             "statusMessage": "Ready"},
        ],
    }

    def test_summary_fields(self):
        s = SSLLabsClient.summarize("example.com", self.REPORT)
        self.assertEqual(s["grade"], "B")          # worst across endpoints
        self.assertEqual(s["grades"], ["A", "B"])
        self.assertEqual(len(s["endpoints"]), 2)
        self.assertIn("ssllabs.com/ssltest/analyze.html?d=example.com",
                      s["report_url"])
        self.assertTrue(s["test_time"].startswith("2025") or
                        s["test_time"].startswith("2026"))

    def test_client_disabled_without_email(self):
        c = SSLLabsClient(email="")
        self.assertFalse(c.available)
        self.assertIsNone(c.get_cached("example.com"))
        self.assertEqual(c.start_assessment("example.com")[0], "unavailable")
        self.assertEqual(c.poll("example.com")[0], "unavailable")


def _enum_with(ciphers):
    r = CipherEnumResult(domain="x.com", port=443,
                         timestamp="2026-07-09T00:00:00+00:00", success=True)
    r.supported_ciphers = [c.__dict__ for c in ciphers]
    for c in ciphers:
        if c.security_level == "deprecated":
            r.deprecated_count += 1
        elif c.security_level == "disallowed":
            r.disallowed_count += 1
        if "RC4" in c.category:
            r.has_rc4 = True
        if "3DES" in c.category:
            r.has_3des = True
    return r


class TestCipherEnumFindingsNaming(unittest.TestCase):
    def test_deprecated_finding_lists_names(self):
        enum = _enum_with([
            CipherResult("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA",
                         "TLSv1.2", 128, "RSA-CBC", "deprecated"),
            CipherResult("CAMELLIA128-SHA", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
                         "TLSv1.2", 128, "RSA-CBC", "deprecated"),
        ])
        findings = cipher_enum_findings(enum)
        dep = [f for f in findings
               if "deprecated cipher suite" in f["message"]][0]
        self.assertIn("TLS_RSA_WITH_AES_128_CBC_SHA", dep["message"])
        self.assertIn("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", dep["message"])
        self.assertEqual(sorted(dep["ciphers"]),
                         ["TLS_RSA_WITH_AES_128_CBC_SHA",
                          "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"])

    def test_rc4_finding_lists_names(self):
        enum = _enum_with([
            CipherResult("RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA",
                         "TLSv1.2", 128, "RC4", "disallowed"),
        ])
        findings = cipher_enum_findings(enum)
        rc4 = [f for f in findings if "RC4" in f["message"]][0]
        self.assertIn("TLS_RSA_WITH_RC4_128_SHA", rc4["message"])

    def test_failed_enum_produces_no_findings(self):
        r = CipherEnumResult(domain="x.com", port=443,
                             timestamp="t", success=False)
        self.assertEqual(cipher_enum_findings(r), [])


if __name__ == "__main__":
    unittest.main()
