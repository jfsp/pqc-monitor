#!/usr/bin/env python3
"""
PQC-Monitor: CBOM export tests (reports/cbom.py, /app/api/organisations/<id>/cbom,
`pqc_monitor.py cbom`).

The fixture is built from the scanner's own result classes (TLSProbeResult,
CertNode, CipherEnumResult, GroupEnumResult, ChainAnalysis) over certificates
generated here, so the CBOM is tested against the exact blob shapes the scanner
stores. Schema validation runs when cyclonedx-python-lib is installed
(pip install -r requirements-dev.txt); it is skipped otherwise.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reports import cbom as C  # noqa: E402

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTO = True
except ImportError:          # pragma: no cover
    HAS_CRYPTO = False

try:
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion
    HAS_CDX = True
except ImportError:
    HAS_CDX = False

NOW = _dt.datetime.now(_dt.timezone.utc)
ORG_NAME = "Banco Ejemplo, S.A."


# ══════════════════════════════════════════════════════════════════════════════
# Fixture
# ══════════════════════════════════════════════════════════════════════════════

def _name(cn, org=None):
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "ES")]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def _cert(subject, issuer, pub, signer, serial, days, algo, ca=None, sans=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(pub).serial_number(serial)
         .not_valid_before(NOW - _dt.timedelta(days=10))
         .not_valid_after(NOW + _dt.timedelta(days=days)))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(True, ca), True)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), False)
    return b.sign(signer, algo).public_bytes(serialization.Encoding.DER)


def build_fixture(db):
    """
    Org "Banco Ejemplo" (in community "Banks") with:
      www.bank.example   TLS 1.3/1.2, X25519MLKEM768 offered, 3-cert chain,
                         enumerated suites incl. 3DES, CT certs; newest
                         assessment is a score-only reassess (no raw scans)
      mail.bank.example  SMTP STARTTLS on 25 only, RSA-2048 sha1 cert
      old.bank.example   level na, dns_status nxdomain
      new.bank.example   never assessed
    Org "Other Bank" with other.example (must never leak).
    Returns a dict of ids / fingerprints used by the assertions.
    """
    from scanner.tls_probe import TLSProbeResult, _parse_certificate
    from scanner.chain_validator import _parse_cert_node, ChainAnalysis
    from scanner.cipher_enum import CipherEnumResult, CipherResult
    from scanner.group_enum import GroupEnumResult

    root_k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    int_k = ec.generate_private_key(ec.SECP384R1())
    leaf_k = ec.generate_private_key(ec.SECP256R1())
    mail_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_n, int_n = _name("Ejemplo Root CA", "Ejemplo, Trust"), _name("Ejemplo Issuing CA", "Ejemplo, Trust")
    root = _cert(root_n, root_n, root_k.public_key(), root_k, 1, 3650, hashes.SHA384(), ca=1)
    inter = _cert(int_n, root_n, int_k.public_key(), root_k, 2, 1000, hashes.SHA256(), ca=0)
    leaf = _cert(_name("www.bank.example"), int_n, leaf_k.public_key(), int_k, 0x1A2B3C,
                 90, hashes.SHA256(),
                 sans=[x509.DNSName("www.bank.example"), x509.DNSName("bank.example"),
                       x509.IPAddress(ipaddress.ip_address("192.0.2.10"))])
    # Signed with SHA-256 here (cryptography refuses SHA-1 signing); the
    # parsed record is rewritten below to the legacy sha1WithRSAEncryption.
    mail = _cert(_name("mail.bank.example"), _name("mail.bank.example"),
                 mail_k.public_key(), mail_k, 77, 30, hashes.SHA256())

    org = db.create_organisation(ORG_NAME, sector="Banking", region="Europe",
                                 country_code="ES", country="Spain")
    other = db.create_organisation("Other Bank")
    db.set_org_domains(org, ["www.bank.example", "mail.bank.example",
                             "old.bank.example", "new.bank.example"])
    db.set_org_domains(other, ["other.example"])
    comm = db.create_community("Banks")
    db.set_community_orgs(comm, [org])

    ts = (NOW - _dt.timedelta(days=2)).isoformat()
    run = db.create_run(["www.bank.example", "mail.bank.example", "old.bank.example",
                         "other.example"])

    # www: probe on 443 (+ a failed 8443 that must be ignored)
    probe = TLSProbeResult(domain="www.bank.example", port=443, timestamp=ts, success=True,
                           tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
                           cipher_bits=256, key_exchange="TLS1.3",
                           certificate=_parse_certificate(leaf))
    db.save_scan_result(run, probe.to_dict())
    db.save_scan_result(run, TLSProbeResult(domain="www.bank.example", port=8443,
                                            timestamp=ts, success=False,
                                            error="timeout").to_dict())
    nodes = [_parse_cert_node(d, i) for i, d in enumerate((leaf, inter, root))]
    chain = ChainAnalysis(domain="www.bank.example", port=443, timestamp=ts, success=True,
                          chain_length=3, chain_complete=True,
                          certs=[n.to_dict() for n in nodes], has_hsts=True)
    db.save_domain_extra(run, "www.bank.example", "chain", chain.to_dict())
    suites = [
        CipherResult("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "TLSv1.3", 128, "TLS13", "recommended"),
        CipherResult("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256, "TLS13", "recommended"),
        CipherResult("ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                     "TLSv1.2", 128, "ECDHE-AEAD-ECDSA", "recommended"),
        CipherResult("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.2", 112,
                     "RSA-CBC", "deprecated"),
    ]
    enum = CipherEnumResult(domain="www.bank.example", port=443, timestamp=ts, success=True,
                            supported_ciphers=[s.__dict__ for s in suites],
                            tls13_supported=True, tls12_supported=True)
    db.save_domain_extra(run, "www.bank.example", "cipher_enum", enum.to_dict())
    groups = GroupEnumResult(domain="www.bank.example", port=443, timestamp=ts, success=True,
                             offered_groups=["X25519MLKEM768", "x25519", "secp256r1"],
                             has_pqc_kem=True, pqc_groups=["X25519MLKEM768"],
                             hybrid_only=True, tls13_supported=True)
    db.save_domain_extra(run, "www.bank.example", "group_enum", groups.to_dict())
    db.save_domain_extra(run, "www.bank.example", "cdn",
                         {"detected": True, "cdn_name": "ExampleCDN", "success": True})
    db.save_domain_extra(run, "www.bank.example", "ssllabs",
                         {"status": "READY", "grade": "A+", "test_time": ts})
    db.save_assessment(run, {
        "domain": "www.bank.example", "assessment_timestamp": ts, "score": 82,
        "level": "ready", "has_pqc": True, "tls_versions_found": ["TLSv1.3", "TLSv1.2"],
        "guidelines_used": ["nist_800_131a"], "service_type": "web_primary",
        "findings": [
            {"severity": "high", "category": "cipher", "guideline": "NIST SP 800-131A",
             "message": "3DES accepted", "recommendation": "Disable 3DES"},
            {"severity": "info", "category": "pqc", "guideline": "all",
             "message": "Hybrid ML-KEM offered", "recommendation": ""},
        ]})

    # mail: STARTTLS on 25, negotiated suite only, weak certificate
    mail_info = _parse_certificate(mail)
    mail_info.signature_algorithm, mail_info.hash_algorithm = "sha1WithRSAEncryption", "SHA1"
    db.save_scan_result(run, {
        "domain": "mail.bank.example", "port": 25, "timestamp": ts, "success": True,
        "source": "starttls", "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "cipher_bits": 256,
        "certificate": mail_info.__dict__})
    db.save_assessment(run, {
        "domain": "mail.bank.example", "assessment_timestamp": ts, "score": 40,
        "level": "weak", "has_pqc": False,
        "findings": [{"severity": "critical", "category": "hash",
                      "guideline": "BSI TR-02102-1", "message": "SHA-1 signature",
                      "recommendation": "Reissue with SHA-256"}]})

    # old: no TLS, DNS says NXDOMAIN
    db.save_assessment(run, {"domain": "old.bank.example", "assessment_timestamp": ts,
                             "score": 0, "level": "na", "findings": []})
    db.save_domain_extra(run, "old.bank.example", "dns_status",
                         {"status": "nxdomain", "since": "2026-09-01T00:00:00+00:00"})

    # other org (must not appear)
    db.save_scan_result(run, TLSProbeResult(domain="other.example", port=443, timestamp=ts,
                                            success=True, tls_version="TLSv1.2",
                                            cipher_suite="ECDHE-RSA-AES128-GCM-SHA256").to_dict())
    db.save_assessment(run, {"domain": "other.example", "assessment_timestamp": ts,
                             "score": 50, "level": "weak", "findings": []})
    db.finish_run(run, "completed")

    # A newer score-only reassessment of www: new run, NO raw scans.
    rerun = db.create_run(["www.bank.example"], notes="reassess")
    db.save_assessment(rerun, {
        "domain": "www.bank.example",
        "assessment_timestamp": (NOW - _dt.timedelta(days=1)).isoformat(),
        "score": 83, "level": "ready", "has_pqc": True,
        "findings": [
            {"severity": "high", "category": "cipher", "guideline": "NIST SP 800-131A",
             "message": "3DES accepted", "recommendation": "Disable 3DES"},
            {"severity": "info", "category": "pqc", "guideline": "all",
             "message": "Hybrid ML-KEM offered", "recommendation": ""},
        ]})
    db.finish_run(rerun, "completed")

    import hashlib
    leaf_fp = hashlib.sha256(leaf).hexdigest()
    fmt = "%Y-%m-%dT%H:%M:%S"
    db.save_ct_summary({"domain": "www.bank.example", "certificates": [
        {"cert_id": 111, "domain": "www.bank.example",
         "sha256_fingerprint": ":".join(leaf_fp[i:i + 2] for i in range(0, 64, 2)).upper(),
         "subject_cn": "www.bank.example", "issuer_cn": "Ejemplo Issuing CA",
         "not_before": (NOW - _dt.timedelta(days=10)).strftime(fmt),
         "not_after": (NOW + _dt.timedelta(days=90)).strftime(fmt),
         "signature_algorithm_oid": "1.2.840.10045.4.3.2",
         "signature_algorithm_name": "ecdsa-with-SHA256",
         "pubkey_algorithm_oid": "1.2.840.10045.2.1",
         "pubkey_algorithm_name": "ECDSA-secp256r1", "pubkey_size_bits": 256},
        {"cert_id": 222, "domain": "www.bank.example", "sha256_fingerprint": "ab" * 32,
         "subject_cn": "www.bank.example", "issuer_cn": "Old CA",
         "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00",
         "signature_algorithm_oid": "1.2.840.113549.1.1.11",
         "signature_algorithm_name": "sha256WithRSAEncryption",
         "pubkey_algorithm_oid": "1.2.840.113549.1.1.1",
         "pubkey_algorithm_name": "RSA", "pubkey_size_bits": 2048},
        {"cert_id": 333, "domain": "www.bank.example", "sha256_fingerprint": "cd" * 32,
         "subject_cn": "pq.bank.example", "issuer_cn": "PQ Test CA",
         "not_before": (NOW - _dt.timedelta(days=1)).strftime(fmt),
         "not_after": (NOW + _dt.timedelta(days=30)).strftime(fmt),
         "signature_algorithm_oid": "2.16.840.1.101.3.4.3.18",
         "signature_algorithm_name": "ML-DSA-65",
         "pubkey_algorithm_oid": "2.16.840.1.101.3.4.3.18",
         "pubkey_algorithm_name": "ML-DSA-65", "pubkey_size_bits": 0,
         "is_pqc_signature": True, "is_pqc_pubkey": True},
    ]})
    return {"org": org, "other": other, "community": comm, "leaf_fp": leaf_fp,
            "inter_fp": hashlib.sha256(inter).hexdigest(),
            "root_fp": hashlib.sha256(root).hexdigest(), "run": run, "rerun": rerun}


def _by_ref(bom):
    return {c["bom-ref"]: c for c in bom.get("components", [])}


def _deps(bom):
    return {d["ref"]: set(d.get("dependsOn", [])) for d in bom.get("dependencies", [])}


def _props(obj):
    out = {}
    for p in obj.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return {k: (v[0] if len(v) == 1 else v) for k, v in out.items()}


# ══════════════════════════════════════════════════════════════════════════════
# Unit: registry helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistry(unittest.TestCase):

    def test_parse_tls13_suite(self):
        p = C.parse_suite("TLS_AES_128_GCM_SHA256")
        self.assertTrue(p["tls13"])
        names = [s["name"] for s in C.suite_algorithm_specs(p)]
        self.assertEqual(names, ["AES-128-GCM", "HKDF-SHA-256"])

    def test_parse_tls12_suite_and_openssl_name(self):
        p = C.parse_suite("ECDHE-RSA-AES256-GCM-SHA384")
        self.assertEqual(p["name"], "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        names = [s["name"] for s in C.suite_algorithm_specs(p)]
        self.assertEqual(names, ["ECDHE", "RSA", "AES-256-GCM", "HMAC-SHA-384"])

    def test_rsa_key_transport_has_no_separate_auth(self):
        names = [s["name"] for s in C.suite_algorithm_specs(
            C.parse_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))]
        self.assertEqual(names, ["RSA-PKCS1-1.5", "3DES-168-CBC", "HMAC-SHA-1"])

    def test_signalling_and_unknown_suites_have_no_algorithms(self):
        for n in ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_FALLBACK_SCSV"):
            p = C.parse_suite(n)
            self.assertEqual(p["name"], n)
            self.assertEqual(C.suite_algorithm_specs(p), [])
        self.assertIsNone(C.parse_suite(""))

    def test_ccm8_and_seed_and_null(self):
        self.assertEqual(C.cipher_spec("AES_128_CCM_8")["name"], "AES-128-CCM-64")
        self.assertEqual(C.cipher_spec("SEED_CBC")["family"], "SEED")
        self.assertIsNone(C.cipher_spec("NULL"))

    def test_suite_identifiers(self):
        self.assertEqual(C.suite_identifiers("TLS_AES_256_GCM_SHA384"), ["0x13", "0x02"])
        self.assertEqual(C.suite_identifiers("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                         ["0xC0", "0x2F"])
        self.assertEqual(C.suite_identifiers("TLS_RSA_WITH_SEED_CBC_SHA"), ["0x00", "0x96"])
        self.assertEqual(C.suite_identifiers("TLS_UNKNOWN"), [])

    def test_scanner_suites_all_have_code_points(self):
        from scanner.cipher_enum import _OPENSSL_TO_IANA, TLS13_CIPHERS
        names = set(_OPENSSL_TO_IANA.values()) | {n for n, _ in TLS13_CIPHERS}
        missing = sorted(n for n in names if not C.suite_identifiers(n))
        self.assertEqual(missing, [])

    def test_hybrid_group_depends_on_parts(self):
        s = C.group_spec("X25519MLKEM768")
        self.assertEqual(s["primitive"], "kem")
        self.assertEqual(s["nistq"], 3)
        self.assertEqual(sorted(d["name"] for d in s["deps"]), ["ML-KEM-768", "x25519"])
        self.assertEqual(C.group_spec("secp384r1mlkem1024")["nistq"], 5)

    def test_classical_and_pure_pqc_groups(self):
        self.assertEqual(C.group_spec("secp256r1")["name"], "ECDH-P-256")
        self.assertEqual(C.group_spec("secp256r1")["nistq"], 0)
        self.assertEqual(C.group_spec("MLKEM1024")["name"], "ML-KEM-1024")
        self.assertEqual(C.group_spec("MLKEM1024")["oid"], "2.16.840.1.101.3.4.4.3")
        self.assertIsNone(C.group_spec("GREASE_0x0A0A"))

    def test_signature_mapping(self):
        self.assertEqual(C.signature_spec("sha256WithRSAEncryption")["name"],
                         "RSA-PKCS1-1.5-SHA-256")
        self.assertEqual(C.signature_spec("1.2.840.10045.4.3.3")["name"], "ECDSA-SHA-384")
        self.assertEqual(C.signature_spec("rsassa-pss", "SHA256")["name"], "RSA-PSS-SHA-256")
        mldsa = C.signature_spec("", sig_oid="2.16.840.1.101.3.4.3.18")
        self.assertEqual((mldsa["name"], mldsa["nistq"]), ("ML-DSA-65", 3))
        self.assertEqual(C.signature_spec("1.2.3.4")["name"], "1.2.3.4")

    def test_key_algorithms(self):
        self.assertEqual(C.key_algorithm_spec("RSA", 2048)["classical"], 112)
        self.assertEqual(C.key_algorithm_spec("RSA", 3072)["classical"], 128)
        ec256 = C.key_algorithm_spec("ECDSA", 256)
        self.assertEqual(ec256["name"], "ECDSA-P-256")
        self.assertIn(("curve-inferred-from-key-size", "true"), ec256["props"])
        self.assertEqual(C.key_algorithm_spec("ECDSA", 256, "brainpoolP256r1")["name"],
                         "ECDSA-brainpoolP256r1")

    def test_readable_dn_and_timestamps(self):
        self.assertEqual(C._readable_dn("2.5.4.6=ES,2.5.4.10=Ejemplo, Trust,2.5.4.3=CA 1"),
                         "C=ES, O=Ejemplo\\, Trust, CN=CA 1")
        self.assertEqual(C._iso("2026-01-02T03:04:05.123456+02:00"), "2026-01-02T01:04:05Z")
        self.assertEqual(C._iso("2026-01-02 03:04:05"), "2026-01-02T03:04:05Z")
        self.assertIsNone(C._iso("not a date"))

    def test_filename(self):
        self.assertEqual(C.cbom_filename({"id": 3, "name": "Banco Ñandú, S.A."},
                                         _dt.datetime(2026, 10, 16)),
                         "cbom-banco-and-s-a-20261016.cdx.json")
        self.assertEqual(C.cbom_filename({"id": 9, "name": "日本"}, _dt.datetime(2026, 1, 1)),
                         "cbom-org-9-20260101.cdx.json")

    def test_endpoint_assembly(self):
        scans = {"scans": [
            {"port": 443, "success": True, "tls_version": "TLSv1.3",
             "cipher_suite": "TLS_AES_256_GCM_SHA384"},
            {"port": 8443, "success": False, "error": "timeout"},
            {"port": 587, "success": True, "source": "starttls",
             "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256"},
        ]}
        extra = {"cipher_enum": {"success": True, "port": 443, "supported_ciphers": [
            {"iana_name": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3"},
            {"iana_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "tls_version": "TLSv1.2"}]}}
        eps = C._endpoints("h.example", scans, extra)
        self.assertEqual([e["uri"] for e in eps],
                         ["https://h.example:443", "smtp://h.example:587"])
        v = eps[0]["versions"]
        # one TLS 1.3 suite from cipher_enum = the server's preference, not a list
        self.assertEqual(v["1.3"]["source"], "server-preferred")
        self.assertEqual(v["1.2"]["source"], "enumerated")
        self.assertEqual(eps[1]["versions"]["1.2"],
                         {"suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                          "source": "negotiated"})
        self.assertTrue(eps[1]["starttls"])

    def test_bad_spec_rejected(self):
        with self.assertRaises(ValueError):
            C.build_cbom({"org": {"id": 1, "name": "x"}}, spec="1.5")


# ══════════════════════════════════════════════════════════════════════════════
# Builder over a real DB
# ══════════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestCbomBuild(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from data.database import Database
        cls.tmpdir = tempfile.mkdtemp()
        cls.db = Database(os.path.join(cls.tmpdir, "cbom.db"))
        cls.fx = build_fixture(cls.db)
        cls.org = cls.db.get_organisation(cls.fx["org"])
        cls.domains = cls.db.get_org_domains(cls.fx["org"])
        cls.bom16 = C.generate_org_cbom(cls.db, cls.org, cls.domains, spec="1.6")
        cls.bom17 = C.generate_org_cbom(cls.db, cls.org, cls.domains, spec="1.7")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # ── document level ────────────────────────────────────────────────────
    def test_header(self):
        for spec, bom in (("1.6", self.bom16), ("1.7", self.bom17)):
            self.assertEqual(bom["bomFormat"], "CycloneDX")
            self.assertEqual(bom["specVersion"], spec)
            self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
            self.assertEqual(bom["metadata"]["lifecycles"], [{"phase": "discovery"}])
            self.assertEqual(bom["metadata"]["supplier"]["name"], ORG_NAME)
            self.assertEqual(bom["metadata"]["component"]["bom-ref"], f"org/{self.fx['org']}")
            self.assertEqual(bom["compositions"][0]["aggregate"], "incomplete")
        md = _props(self.bom16["metadata"])
        self.assertEqual(md["pqc-monitor:domains-in-scope"], "4")
        self.assertEqual(md["pqc-monitor:domains-with-tls"], "2")
        self.assertEqual(md["pqc-monitor:domains-without-tls"], "1")
        self.assertEqual(md["pqc-monitor:domains-not-assessed"], "1")
        self.assertEqual(md["pqc-monitor:country-code"], "ES")

    def test_refs_unique_and_dependencies_closed(self):
        for bom in (self.bom16, self.bom17):
            refs = [c["bom-ref"] for c in bom["components"]] + \
                   [s["bom-ref"] for s in bom["services"]] + \
                   [bom["metadata"]["component"]["bom-ref"]]
            self.assertEqual(len(refs), len(set(refs)))
            known = set(refs)
            for d in bom["dependencies"]:
                self.assertIn(d["ref"], known)
                for t in d.get("dependsOn", []):
                    self.assertIn(t, known)
            # every component and service is a node of the graph
            self.assertTrue(known <= {d["ref"] for d in bom["dependencies"]})

    def test_no_other_org_data(self):
        text = json.dumps(self.bom16)
        self.assertNotIn("other.example", text)
        self.assertNotIn("Other Bank", text)

    def test_services(self):
        svcs = {s["name"]: s for s in self.bom16["services"]}
        self.assertEqual(set(svcs), {"www.bank.example", "mail.bank.example",
                                     "old.bank.example", "new.bank.example"})
        www = svcs["www.bank.example"]
        self.assertEqual(www["endpoints"], ["https://www.bank.example:443"])
        self.assertTrue(www["x-trust-boundary"])
        p = _props(www)
        self.assertEqual(p["pqc-monitor:score"], "83")          # newest assessment
        self.assertEqual(p["pqc-monitor:has-pqc"], "true")
        self.assertEqual(p["pqc-monitor:pqc-grading-basis"], "offered")
        self.assertEqual(p["pqc-monitor:pqc-groups-offered"], "X25519MLKEM768")
        self.assertEqual(p["pqc-monitor:cdn"], "ExampleCDN")
        self.assertEqual(p["pqc-monitor:ssllabs-grade"], "A+")
        self.assertEqual(p["pqc-monitor:findings:high"], "1")
        self.assertEqual(svcs["mail.bank.example"]["endpoints"], ["smtp://mail.bank.example:25"])
        self.assertEqual(_props(svcs["old.bank.example"])["pqc-monitor:dns-status"], "nxdomain")
        self.assertNotIn("endpoints", svcs["new.bank.example"])
        self.assertEqual(_props(svcs["new.bank.example"])["pqc-monitor:level"], "not assessed")

    def test_scans_come_from_latest_network_run(self):
        # newest assessment (rerun) has no raw scans; protocol data must still exist
        comps = _by_ref(self.bom16)
        self.assertIn("crypto/protocol/tls1.3@www.bank.example:443", comps)
        self.assertNotIn("crypto/protocol/tls1.3@www.bank.example:8443", comps)  # failed probe

    def test_tls13_protocol(self):
        p = _by_ref(self.bom16)["crypto/protocol/tls1.3@www.bank.example:443"]
        pp = p["cryptoProperties"]["protocolProperties"]
        self.assertEqual((pp["type"], pp["version"]), ("tls", "1.3"))
        suites = {s["name"]: s for s in pp["cipherSuites"]}
        self.assertEqual(set(suites), {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"})
        self.assertEqual(suites["TLS_AES_128_GCM_SHA256"]["identifiers"], ["0x13", "0x01"])
        self.assertIn("crypto/algorithm/aes-128-gcm", suites["TLS_AES_128_GCM_SHA256"]["algorithms"])
        self.assertIn("crypto/algorithm/x25519mlkem768", pp["cryptoRefArray"])
        self.assertIn(f"crypto/certificate/sha256:{self.fx['leaf_fp']}", pp["cryptoRefArray"])
        props = _props(p)
        self.assertEqual(props["pqc-monitor:pqc-key-exchange"], "offered")
        self.assertEqual(props["pqc-monitor:cipher-suites-source"], "enumerated")
        # 1.7: groups listed on the suites, related assets instead of cryptoRefArray
        p17 = _by_ref(self.bom17)["crypto/protocol/tls1.3@www.bank.example:443"]
        pp17 = p17["cryptoProperties"]["protocolProperties"]
        self.assertNotIn("cryptoRefArray", pp17)
        self.assertIn("X25519MLKEM768", pp17["cipherSuites"][0]["tlsGroups"])
        self.assertIn({"type": "algorithm", "ref": "crypto/algorithm/x25519mlkem768"},
                      pp17["relatedCryptographicAssets"])

    def test_tls12_and_starttls_protocols(self):
        comps = _by_ref(self.bom16)
        p12 = comps["crypto/protocol/tls1.2@www.bank.example:443"]
        names = [s["name"] for s in p12["cryptoProperties"]["protocolProperties"]["cipherSuites"]]
        self.assertIn("TLS_RSA_WITH_3DES_EDE_CBC_SHA", names)
        mail = comps["crypto/protocol/tls1.2@mail.bank.example:25"]
        mp = _props(mail)
        self.assertEqual(mp["pqc-monitor:cipher-suites-source"], "negotiated")
        self.assertEqual(mp["pqc-monitor:starttls"], "true")
        self.assertEqual(mail["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["name"],
                         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

    def test_hybrid_kem_graph_and_levels(self):
        comps, deps = _by_ref(self.bom16), _deps(self.bom16)
        hyb = comps["crypto/algorithm/x25519mlkem768"]
        ap = hyb["cryptoProperties"]["algorithmProperties"]
        self.assertEqual((ap["primitive"], ap["nistQuantumSecurityLevel"]), ("kem", 3))
        self.assertEqual(deps["crypto/algorithm/x25519mlkem768"],
                         {"crypto/algorithm/ml-kem-768", "crypto/algorithm/x25519"})
        mlkem = comps["crypto/algorithm/ml-kem-768"]
        self.assertEqual(mlkem["cryptoProperties"]["oid"], "2.16.840.1.101.3.4.4.2")
        locs = [o["location"] for o in mlkem["evidence"]["occurrences"]]
        self.assertEqual(locs, ["https://www.bank.example:443"])
        tdes = comps["crypto/algorithm/3des-168-cbc"]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(tdes["nistQuantumSecurityLevel"], 0)
        aes256 = comps["crypto/algorithm/aes-256-gcm"]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(aes256["nistQuantumSecurityLevel"], 5)

    def test_certificate_chain(self):
        comps, deps = _by_ref(self.bom16), _deps(self.bom16)
        leaf = f"crypto/certificate/sha256:{self.fx['leaf_fp']}"
        inter = f"crypto/certificate/sha256:{self.fx['inter_fp']}"
        root = f"crypto/certificate/sha256:{self.fx['root_fp']}"
        for r in (leaf, inter, root):
            self.assertIn(r, comps)
        self.assertIn(inter, deps[leaf])
        self.assertIn(root, deps[inter])
        cp = comps[leaf]["cryptoProperties"]["certificateProperties"]
        self.assertEqual(cp["subjectName"], "C=ES, CN=www.bank.example")
        self.assertEqual(cp["issuerName"], "C=ES, O=Ejemplo\\, Trust, CN=Ejemplo Issuing CA")
        self.assertEqual(cp["signatureAlgorithmRef"], "crypto/algorithm/ecdsa-sha-256")
        key = comps[cp["subjectPublicKeyRef"]]
        rp = key["cryptoProperties"]["relatedCryptoMaterialProperties"]
        self.assertEqual((rp["type"], rp["size"], rp["state"]), ("public-key", 256, "active"))
        self.assertEqual(rp["algorithmRef"], "crypto/algorithm/ecdsa-p-256")
        roles = _props(comps[root])["pqc-monitor:certificate:role"]
        self.assertEqual(roles, "root")
        # leaf seen on the endpoint AND in CT (fingerprint merge across formats)
        lp = _props(comps[leaf])
        self.assertEqual(lp["pqc-monitor:certificate:source"], "ct-log, observed")
        locs = {o["location"] for o in comps[leaf]["evidence"]["occurrences"]}
        self.assertEqual(locs, {"https://www.bank.example:443", "https://crt.sh/?id=111"})

    def test_weak_mail_certificate(self):
        comps = _by_ref(self.bom16)
        sig = comps["crypto/algorithm/rsa-pkcs1-1.5-sha-1"]
        self.assertEqual(sig["cryptoProperties"]["oid"], "1.2.840.113549.1.1.5")
        self.assertIn("crypto/algorithm/sha-1", _deps(self.bom16)["crypto/algorithm/rsa-pkcs1-1.5-sha-1"])
        self.assertIn("crypto/algorithm/rsa-2048", comps)
        self.assertEqual([o["location"] for o in sig["evidence"]["occurrences"]],
                         ["smtp://mail.bank.example:25"])

    def test_ct_certificates(self):
        comps = _by_ref(self.bom16)
        self.assertNotIn("crypto/certificate/sha256:" + "ab" * 32, comps)   # expired
        pq = comps["crypto/certificate/sha256:" + "cd" * 32]
        p = _props(pq)
        self.assertEqual(p["pqc-monitor:certificate:source"], "ct-log")
        self.assertEqual(p["pqc-monitor:certificate:pqc"], "true")
        self.assertEqual(pq["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"],
                         "crypto/algorithm/ml-dsa-65")
        self.assertEqual(comps["crypto/algorithm/ml-dsa-65"]["cryptoProperties"]
                         ["algorithmProperties"]["nistQuantumSecurityLevel"], 3)

    def test_findings_as_annotations(self):
        ann = self.bom16["annotations"]
        self.assertEqual(len(ann), 3)
        www = [a for a in ann if a["subjects"] == ["service/www.bank.example"]]
        self.assertEqual(len(www), 2)
        self.assertTrue(www[0]["text"].startswith("[HIGH] cipher (NIST SP 800-131A): 3DES accepted"))
        self.assertIn("Recommendation: Disable 3DES", www[0]["text"])
        self.assertEqual(ann[0]["annotator"]["component"]["name"], "PQC-Monitor")

    def test_v17_certificate_fields(self):
        comps = _by_ref(self.bom17)
        cp = comps[f"crypto/certificate/sha256:{self.fx['leaf_fp']}"]["cryptoProperties"]["certificateProperties"]
        self.assertEqual(cp["serialNumber"], "1A2B3C")
        self.assertEqual(cp["fingerprint"], {"alg": "SHA-256", "content": self.fx["leaf_fp"]})
        self.assertEqual(cp["certificateState"], [{"state": "active"}])
        self.assertNotIn("signatureAlgorithmRef", cp)
        types = {r["type"] for r in cp["relatedCryptographicAssets"]}
        self.assertEqual(types, {"signatureAlgorithm", "publicKey", "issuerCertificate"})
        san = [e for e in cp["certificateExtensions"]
               if e["commonExtensionName"] == "subjectAlternativeName"][0]
        self.assertEqual(san["commonExtensionValue"],
                         "DNS:www.bank.example, DNS:bank.example, IP:192.0.2.10")
        ca = comps[f"crypto/certificate/sha256:{self.fx['inter_fp']}"]["cryptoProperties"]["certificateProperties"]
        self.assertIn({"commonExtensionName": "basicConstraints",
                       "commonExtensionValue": "CA:TRUE, pathlen:0"}, ca["certificateExtensions"])
        ap = comps["crypto/algorithm/ecdsa-p-256"]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual((ap["algorithmFamily"], ap["ellipticCurve"]), ("ECDSA", "nist/P-256"))
        self.assertNotIn("curve", ap)

    def test_options_off(self):
        bom = C.generate_org_cbom(self.db, self.org, self.domains, include_findings=False,
                                  include_ct=False, include_no_tls=False)
        self.assertNotIn("annotations", bom)
        self.assertEqual({s["name"] for s in bom["services"]},
                         {"www.bank.example", "mail.bank.example"})
        self.assertNotIn("crypto/certificate/sha256:" + "cd" * 32, _by_ref(bom))
        leaf = _by_ref(bom)[f"crypto/certificate/sha256:{self.fx['leaf_fp']}"]
        self.assertEqual(_props(leaf)["pqc-monitor:certificate:source"], "observed")
        self.assertNotIn("pqc-monitor:findings", _props(bom["services"][0]))

    def test_empty_org(self):
        bom = C.generate_org_cbom(self.db, {"id": 99, "name": "Empty"}, [])
        self.assertEqual(bom["components"], [])
        self.assertNotIn("services", bom)
        self.assertEqual(bom["dependencies"], [{"ref": "org/99"}])

    def test_deterministic_apart_from_serial_and_time(self):
        a = C.generate_org_cbom(self.db, self.org, self.domains, now=NOW)
        b = C.generate_org_cbom(self.db, self.org, self.domains, now=NOW)
        a["serialNumber"] = b["serialNumber"] = "x"
        self.assertEqual(C.dumps(a), C.dumps(b))

    @unittest.skipUnless(HAS_CDX, "cyclonedx-python-lib not installed "
                                  "(pip install -r requirements-dev.txt)")
    def test_schema_valid(self):
        for spec, bom, sv in (("1.6", self.bom16, SchemaVersion.V1_6),
                              ("1.7", self.bom17, SchemaVersion.V1_7)):
            err = JsonStrictValidator(sv).validate_str(C.dumps(bom))
            self.assertIsNone(err, f"CycloneDX {spec}: {err}")
        bare = C.generate_org_cbom(self.db, self.org, self.domains, include_findings=False,
                                   include_ct=False, include_no_tls=False)
        self.assertIsNone(JsonStrictValidator(SchemaVersion.V1_6).validate_str(C.dumps(bare)))


# ══════════════════════════════════════════════════════════════════════════════
# API + RBAC
# ══════════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestCbomAPI(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        from auth.store import AuthStore
        from auth.models import ROLE_ANALYST, ROLE_COMMUNITY_MANAGER
        import auth.auth_routes as _ar
        _ar._login_attempts.clear()
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "api.db")
        self.db = Database(self.db_path)
        self.fx = build_fixture(self.db)
        self.store = AuthStore(self.db_path)
        ana = self.store.create_user("ana", "ana@e.com", "password1234", ROLE_ANALYST)
        self.store.set_user_orgs(ana.id, [self.fx["org"]])
        self.store.set_must_change_password(ana.id, False)
        cm = self.store.create_user("cm", "cm@e.com", "password1234", ROLE_COMMUNITY_MANAGER)
        self.store.set_user_communities(cm.id, [self.fx["community"]])
        self.store.set_must_change_password(cm.id, False)
        from app_factory import create_app
        self.app = create_app({"db_path": self.db_path,
                               "secret_key": "test-secret-32-chars-exactly!!!",
                               "https_enabled": False})
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _login(self, user, pw):
        self.client.post("/login", data={"username": user, "password": pw},
                         follow_redirects=True)

    def _url(self, org, q=""):
        return f"/app/api/organisations/{org}/cbom{q}"

    def test_requires_auth(self):
        self.assertEqual(self.client.get(self._url(self.fx["org"])).status_code, 401)

    def test_admin_download(self):
        self._login("admin", "changeme123")
        r = self.client.get(self._url(self.fx["org"]))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content_type.startswith("application/vnd.cyclonedx+json; version=1.6"))
        cd = r.headers["Content-Disposition"]
        self.assertRegex(cd, r'^attachment; filename="cbom-banco-ejemplo-s-a-\d{8}\.cdx\.json"$')
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        bom = json.loads(r.data)
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(len(bom["services"]), 4)
        # audited
        ev = [e for e in self.store.get_audit_log(50) if e.action == "cbom.export"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].resource, f"org:{self.fx['org']}")
        self.assertIn("spec=1.6", ev[0].detail)

    def test_admin_other_org_and_spec_and_flags(self):
        self._login("admin", "changeme123")
        bom = json.loads(self.client.get(self._url(self.fx["other"], "?spec=1.7")).data)
        self.assertEqual(bom["specVersion"], "1.7")
        self.assertEqual([s["name"] for s in bom["services"]], ["other.example"])
        bom = json.loads(self.client.get(self._url(self.fx["org"], "?findings=0&ct=no&notls=false")).data)
        self.assertNotIn("annotations", bom)
        self.assertEqual(len(bom["services"]), 2)
        self.assertEqual(self.client.get(self._url(self.fx["org"], "?spec=2.0")).status_code, 400)
        self.assertEqual(self.client.get(self._url(9999)).status_code, 404)

    def test_analyst_own_org_only(self):
        self._login("ana", "password1234")
        r = self.client.get(self._url(self.fx["org"]))
        self.assertEqual(r.status_code, 200)
        md = {p["name"]: p["value"] for p in json.loads(r.data)["metadata"]["properties"]}
        self.assertEqual(md["pqc-monitor:scope"], "organisation")
        self.assertEqual(self.client.get(self._url(self.fx["other"])).status_code, 403)
        # unknown org ids are indistinguishable from foreign ones
        self.assertEqual(self.client.get(self._url(9999)).status_code, 403)

    def test_domain_list_only_analyst_cannot_export_org(self):
        # Seeing some of an org's domains through a domain list does not make
        # the org "theirs": CBOM export needs the org assignment.
        from auth.models import ROLE_ANALYST
        bob = self.store.create_user("bob", "bob@e.com", "password1234", ROLE_ANALYST)
        self.store.set_must_change_password(bob.id, False)
        lid = self.db.save_domain_list("bob-list", ["www.bank.example"])
        self.store.assign_domain_list(bob.id, lid)
        self._login("bob", "password1234")
        self.assertEqual(self.client.get(self._url(self.fx["org"])).status_code, 403)

    def test_community_manager(self):
        self._login("cm", "password1234")
        r = self.client.get(self._url(self.fx["org"]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(json.loads(r.data)["services"]), 4)
        self.assertEqual(self.client.get(self._url(self.fx["other"])).status_code, 403)
        orgs = self.client.get("/app/api/organisations").get_json()
        self.assertEqual([o["id"] for o in orgs], [self.fx["org"]])
        self.assertEqual(orgs[0]["domain_count"], 4)
        self.assertIn("www.bank.example", orgs[0]["domains"])

    def test_dashboard_has_cbom_controls(self):
        self._login("admin", "changeme123")
        body = self.client.get("/app/").data.decode()
        self.assertIn('id="btn-org-cbom"', body)
        self.assertIn("function grExportCbom", body)
        self.assertIn("/app/api/organisations/${encodeURIComponent(orgId)}/cbom", body)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestCbomCLI(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "cli.db")
        self.fx = build_fixture(Database(self.db_path))
        self.cfg = os.path.join(self.tmpdir, "config.yaml")
        with open(self.cfg, "w") as f:
            f.write(f"database:\n  path: {self.db_path}\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *args):
        from click.testing import CliRunner
        import pqc_monitor
        return CliRunner().invoke(pqc_monitor.cli, ["--config", self.cfg, "cbom", *args])

    def test_by_name_to_file(self):
        out = os.path.join(self.tmpdir, "o", "bank.cdx.json")
        r = self._run("--org", "banco ejemplo, s.a.", "--spec", "1.7", "-o", out)
        self.assertEqual(r.exit_code, 0, r.output)
        with open(out, encoding="utf-8") as f:
            bom = json.load(f)
        self.assertEqual(bom["specVersion"], "1.7")
        self.assertEqual(len(bom["services"]), 4)

    def test_by_id_stdout_and_flags(self):
        r = self._run("--org", str(self.fx["org"]), "--no-findings", "--no-ct", "--no-notls",
                      "-o", "-")
        self.assertEqual(r.exit_code, 0, r.output)
        bom = json.loads(getattr(r, "stdout", None) or r.output)
        self.assertNotIn("annotations", bom)
        self.assertEqual(len(bom["services"]), 2)

    def test_unknown_org(self):
        r = self._run("--org", "nope")
        self.assertEqual(r.exit_code, 1)
        self.assertIn("not found", r.output)


if __name__ == "__main__":
    unittest.main()
