#!/usr/bin/env python3
"""
Tests for the MX-normalisation and SMTP/STARTTLS fixes.

SPDX-License-Identifier: GPL-3.0-or-later
"""

import unittest

from scanner.dns_enumerator import _normalise_mx_host, _build_candidates
from scanner.service_discovery import (
    STARTTLS_PORTS, STARTTLS_PROTOCOL, TLS_PORTS,
)
from scanner.starttls_probe import _PORT_PROTOCOL, probe_starttls


class TestMxNormalisation(unittest.TestCase):
    def test_priority_stripped(self):
        self.assertEqual(_normalise_mx_host("5 SMTP.domain.com"), "smtp.domain.com")
        self.assertEqual(_normalise_mx_host("10 mail.example.com."), "mail.example.com")

    def test_lone_priority_rejected(self):
        self.assertEqual(_normalise_mx_host("5"), "")

    def test_null_mx_rejected(self):
        self.assertEqual(_normalise_mx_host("0 ."), "")

    def test_plain_host_preserved(self):
        self.assertEqual(_normalise_mx_host("smtp.example.com"), "smtp.example.com")

    def test_non_fqdn_rejected(self):
        self.assertEqual(_normalise_mx_host("5 localhost"), "")

    def test_case_and_trailing_dot(self):
        self.assertEqual(_normalise_mx_host("MX.Example.COM."), "mx.example.com")


class TestCandidateBuildingFromMx(unittest.TestCase):
    def test_malformed_mx_never_becomes_candidate(self):
        cands = _build_candidates(
            "example.com",
            all_subdomains=[],
            mx_hosts=["5 smtp.example.com", "5", "0 ."],
            ns_hosts=[],
        )
        hosts = {c.host for c in cands}
        # The malformed forms must not survive; the real host must.
        self.assertIn("smtp.example.com", hosts)
        self.assertNotIn("5 smtp.example.com", hosts)
        self.assertFalse(any(" " in h for h in hosts))

    def test_smtp_ports_include_2525(self):
        cands = _build_candidates(
            "example.com", all_subdomains=[],
            mx_hosts=["smtp.example.com"], ns_hosts=[])
        ports = {c.port for c in cands if c.host == "smtp.example.com"}
        self.assertEqual(ports, {25, 587, 465, 2525})


class TestStarttlsPortCoverage(unittest.TestCase):
    def test_2525_is_a_known_starttls_smtp_port(self):
        self.assertEqual(STARTTLS_PORTS.get(2525), "submission-alt")
        self.assertEqual(STARTTLS_PROTOCOL.get(2525), "smtp")
        self.assertEqual(_PORT_PROTOCOL.get(2525), "smtp")

    def test_implicit_tls_ports_not_in_starttls(self):
        # 465/993/995 are implicit TLS — must NOT be STARTTLS-upgraded
        for p in (465, 993, 995):
            self.assertIn(p, TLS_PORTS)
            self.assertNotIn(p, STARTTLS_PORTS)

    def test_unknown_port_reports_explicit_error(self):
        # A port with no known upgrade protocol must fail loudly, not wrap
        # a plaintext socket (which would masquerade as "no TLS").
        res = probe_starttls("127.0.0.1", 9999, timeout=1)
        self.assertFalse(res["success"])
        self.assertTrue(res["error"].startswith("starttls_protocol_unknown_for_port"))


class TestMxRepairLogic(unittest.TestCase):
    """Mirror the repair-script cleaning against the same normaliser."""

    def test_clean_list_dedupes_and_drops(self):
        from scripts.fix_mx_entries import _clean_host_list, normalise_mx_host
        cleaned, changed = _clean_host_list(
            ["5 SMTP.x.com", "smtp.x.com", "5", "0 ."])
        self.assertEqual(cleaned, ["smtp.x.com"])
        self.assertTrue(changed)
        # The script's normaliser must agree with the scanner's.
        self.assertEqual(normalise_mx_host("5 SMTP.x.com"),
                         _normalise_mx_host("5 SMTP.x.com"))


if __name__ == "__main__":
    unittest.main()
