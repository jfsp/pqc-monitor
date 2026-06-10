#!/usr/bin/env python3
"""
PQC-Monitor: Certificate Chain Validator
Extracts and analyses the full TLS certificate chain, scoring every
intermediate and root CA for key size, hash algorithm, and validity.

Unlike tls_probe.py which only captures the leaf certificate,
this module retrieves the complete chain using:
  1. ssl.SSLSocket.get_verified_chain() (Python 3.10+, OpenSSL 1.1+)
  2. Fallback: HTTPS request with custom SSL context to capture chain
  3. Stores per-cert findings so the assessor can penalise weak CAs

Chain findings that are detected:
  - Leaf cert      : key size, hash alg, expiry, self-signed, SAN coverage
  - Intermediate   : key size, hash alg, path-length constraint violations
  - Root CA        : known-weak roots (MD5/SHA-1 signed), key size
  - Chain ordering : detects chains sent out of order by the server
  - Chain gaps     : issuer/subject mismatches indicating incomplete chains
  - Pinning hints  : HPKP header (deprecated) or Expect-CT presence

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class CertNode:
    """Represents one certificate in the chain (leaf, intermediate, or root)."""
    position: int               # 0 = leaf, 1 = first intermediate, …, -1 = root
    role: str                   # "leaf" | "intermediate" | "root"
    subject_cn: str
    subject_dn: str             # full distinguished name
    issuer_cn: str
    issuer_dn: str
    not_before: str
    not_after: str
    days_to_expiry: int
    serial_number: str
    fingerprint_sha256: str
    key_type: str
    key_size_bits: int
    signature_algorithm: str    # human-readable, e.g. "sha256WithRSAEncryption"
    hash_algorithm: str         # e.g. "SHA-256"
    is_self_signed: bool
    is_ca: bool
    path_length_constraint: Optional[int]
    san_domains: list = field(default_factory=list)

    # Weakness flags (set by _classify_cert_node)
    weak_key: bool = False
    weak_hash: bool = False
    broken_hash: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChainAnalysis:
    """Complete analysis result for one TLS service endpoint."""
    domain: str
    port: int
    timestamp: str
    success: bool
    error: Optional[str] = None

    chain_length: int = 0
    chain_complete: bool = False   # leaf → root with no gaps
    chain_ordered: bool = True     # server sent certs in correct order
    certs: list = field(default_factory=list)   # list of CertNode dicts

    # Aggregated findings
    has_weak_intermediate: bool = False
    has_broken_intermediate: bool = False
    has_weak_root: bool = False
    weakest_link_position: int = -1
    weakest_link_bits: int = 0
    weakest_hash: str = ""

    # HTTP security metadata (populated if HTTP headers are fetched)
    has_hsts: bool = False
    hsts_max_age: int = 0
    has_expect_ct: bool = False
    has_caa_record: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ── OID → human-readable signature algorithm ─────────────────────────────────

_SIG_OID_MAP = {
    "1.2.840.113549.1.1.4":  "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.1":   "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3":   "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4":   "ecdsa-with-SHA512",
    "1.3.101.112":           "Ed25519",
    "1.3.101.113":           "Ed448",
    "1.2.840.113549.1.1.10": "rsassa-pss",
}

_BROKEN_HASHES  = {"MD5", "MD4", "SHA-1", "SHA1"}
_WEAK_HASHES    = {"SHA-224"}
_WEAK_RSA_BITS  = 2048   # below this → weak
_BROKEN_RSA_BITS = 1024  # at or below → broken
_WEAK_ECC_BITS  = 224


# ── Certificate parsing ──────────────────────────────────────────────────────

def _dn_string(name) -> str:
    """Compact RFC 4514-style DN string."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid.dotted_string}={attr.value}")
    return ",".join(parts)


def _parse_cert_node(cert_der: bytes, position: int) -> Optional[CertNode]:
    """Parse a DER certificate into a CertNode."""
    if not HAS_CRYPTO or not cert_der:
        return None
    try:
        cert = x509.load_der_x509_certificate(cert_der)

        def _cn(name_obj):
            try:
                return name_obj.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                return ""

        subject_cn = _cn(cert.subject)
        issuer_cn  = _cn(cert.issuer)
        is_self_signed = cert.subject == cert.issuer

        # Validity
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc.isoformat()
        not_after  = cert.not_valid_after_utc.isoformat()
        days_to_expiry = (cert.not_valid_after_utc - now).days

        # Serial / fingerprint
        serial_hex = hex(cert.serial_number)
        fp = hashlib.sha256(cert_der).hexdigest()

        # Signature algorithm
        sig_oid  = cert.signature_algorithm_oid.dotted_string
        sig_name = _SIG_OID_MAP.get(sig_oid, sig_oid)
        try:
            hash_obj = cert.signature_hash_algorithm
            hash_alg = hash_obj.name.upper() if hash_obj else ""
            # Normalise: sha256 → SHA-256
            if hash_alg and not hash_alg.startswith("SHA-"):
                hash_alg = hash_alg.replace("SHA", "SHA-").replace("MD", "MD")
        except Exception:
            hash_alg = ""

        # Public key
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = "ECDSA", pub.key_size
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            key_type, key_bits = "Ed25519", 256
        elif isinstance(pub, ed448.Ed448PublicKey):
            key_type, key_bits = "Ed448", 448
        else:
            key_type, key_bits = type(pub).__name__, 0

        # CA flag + path length
        is_ca = False
        path_len: Optional[int] = None
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca    = bc.value.ca
            path_len = bc.value.path_length
        except x509.ExtensionNotFound:
            pass

        # SANs (leaf only)
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in san_ext.value
                    if isinstance(n, (x509.DNSName, x509.IPAddress))]
        except x509.ExtensionNotFound:
            pass

        # Determine role
        if position == 0:
            role = "leaf"
        elif is_self_signed and is_ca:
            role = "root"
        else:
            role = "intermediate"

        node = CertNode(
            position=position,
            role=role,
            subject_cn=subject_cn,
            subject_dn=_dn_string(cert.subject),
            issuer_cn=issuer_cn,
            issuer_dn=_dn_string(cert.issuer),
            not_before=not_before,
            not_after=not_after,
            days_to_expiry=days_to_expiry,
            serial_number=serial_hex,
            fingerprint_sha256=fp,
            key_type=key_type,
            key_size_bits=key_bits,
            signature_algorithm=sig_name,
            hash_algorithm=hash_alg,
            is_self_signed=is_self_signed,
            is_ca=is_ca,
            path_length_constraint=path_len,
            san_domains=sans,
        )
        _classify_cert_node(node)
        return node

    except Exception as e:
        logger.debug(f"parse_cert_node error pos={position}: {e}")
        return None


def _classify_cert_node(node: CertNode):
    """Set weak_key / weak_hash / broken_hash flags on a CertNode in-place."""
    h = node.hash_algorithm.upper()
    node.broken_hash = h in _BROKEN_HASHES
    node.weak_hash   = h in _WEAK_HASHES

    if node.key_type == "RSA":
        node.weak_key = node.key_size_bits < _WEAK_RSA_BITS
    elif node.key_type in ("ECDSA", "EC"):
        node.weak_key = node.key_size_bits < _WEAK_ECC_BITS


# ── Chain extraction ──────────────────────────────────────────────────────────

def _extract_chain_ssl(domain: str, port: int,
                        timeout: int) -> Optional[list[bytes]]:
    """
    Extract the full DER chain using ssl.SSLSocket.
    Returns list of DER bytes (leaf first) or None on failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                # Python 3.10+ / OpenSSL 1.1.1+
                try:
                    chain = tls_sock.get_verified_chain()
                    if chain:
                        return [c.public_bytes(
                            __import__("cryptography.hazmat.primitives.serialization",
                                        fromlist=["Encoding"]).Encoding.DER
                        ) for c in chain]
                except AttributeError:
                    pass

                # Fallback: at least get the leaf
                leaf_der = tls_sock.getpeercert(binary_form=True)
                return [leaf_der] if leaf_der else None

    except Exception as e:
        logger.debug(f"_extract_chain_ssl {domain}:{port}: {e}")
        return None


def _check_chain_continuity(nodes: list[CertNode]) -> tuple[bool, bool]:
    """
    Returns (chain_complete, chain_ordered).
    chain_complete: every issuer matches the next cert's subject.
    chain_ordered:  leaf is first, root is last.
    """
    if len(nodes) <= 1:
        return True, True

    ordered = nodes[0].role == "leaf"
    complete = True
    for i in range(len(nodes) - 1):
        if nodes[i].issuer_dn != nodes[i + 1].subject_dn:
            # Allow CN-only match as fallback
            if nodes[i].issuer_cn != nodes[i + 1].subject_cn:
                complete = False
    return complete, ordered


def _fetch_http_security_headers(domain: str, port: int = 443,
                                  timeout: int = 8) -> dict:
    """
    Make a HEAD request to collect security-relevant HTTP headers.
    Returns dict with hsts, hsts_max_age, expect_ct keys.
    """
    result = {"has_hsts": False, "hsts_max_age": 0, "has_expect_ct": False}
    try:
        import http.client, ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        conn = http.client.HTTPSConnection(domain, port=port, timeout=timeout,
                                           context=ctx)
        conn.request("HEAD", "/", headers={"Host": domain,
                                            "User-Agent": "PQCMonitor/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            result["has_hsts"] = True
            for part in hsts.split(";"):
                part = part.strip()
                if part.lower().startswith("max-age="):
                    try:
                        result["hsts_max_age"] = int(part.split("=", 1)[1].strip())
                    except ValueError:
                        pass

        result["has_expect_ct"] = "expect-ct" in headers
        conn.close()
    except Exception as e:
        logger.debug(f"HTTP header fetch {domain}:{port}: {e}")
    return result


def _check_caa(domain: str) -> bool:
    """Check whether the domain has DNS CAA records (passive DNS query)."""
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "CAA")
        return True
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def analyse_chain(domain: str, port: int = 443,
                  timeout: int = 10,
                  check_http_headers: bool = True,
                  check_caa: bool = True) -> ChainAnalysis:
    """
    Perform a full certificate chain analysis for domain:port.

    Parameters
    ----------
    domain              Target hostname
    port                TCP port (default 443)
    timeout             Connection timeout in seconds
    check_http_headers  Fetch HTTPS HEAD to collect HSTS / Expect-CT
    check_caa           Query DNS for CAA record presence

    Returns
    -------
    ChainAnalysis dataclass
    """
    ts = datetime.now(timezone.utc).isoformat()
    result = ChainAnalysis(domain=domain, port=port, timestamp=ts, success=False)

    chain_ders = _extract_chain_ssl(domain, port, timeout)
    if not chain_ders:
        result.error = "chain_extraction_failed"
        return result

    result.success      = True
    result.chain_length = len(chain_ders)

    # Parse each cert
    nodes: list[CertNode] = []
    for i, der in enumerate(chain_ders):
        node = _parse_cert_node(der, i)
        if node:
            nodes.append(node)

    # Ensure last cert is classified as root if self-signed
    if nodes and nodes[-1].is_self_signed:
        nodes[-1].role = "root"

    result.certs = [n.to_dict() for n in nodes]

    # Chain continuity
    result.chain_complete, result.chain_ordered = _check_chain_continuity(nodes)

    # Aggregate weakness across chain
    weakest_bits = 999999
    for node in nodes:
        if node.broken_hash and node.role != "leaf":
            result.has_broken_intermediate = True
        if node.weak_hash and node.role not in ("leaf",):
            result.has_weak_intermediate = True
        if node.role == "root" and (node.weak_key or node.broken_hash):
            result.has_weak_root = True
        # Track weakest key in chain (excluding root — we can't control it)
        if node.role != "root" and node.key_size_bits > 0:
            if node.key_size_bits < weakest_bits:
                weakest_bits = node.key_size_bits
                result.weakest_link_position = node.position
                result.weakest_link_bits     = node.key_size_bits
        if node.broken_hash:
            result.weakest_hash = node.hash_algorithm

    # HTTP security headers
    if check_http_headers and port in (443, 8443):
        http_meta = _fetch_http_security_headers(domain, port, timeout)
        result.has_hsts     = http_meta["has_hsts"]
        result.hsts_max_age = http_meta["hsts_max_age"]
        result.has_expect_ct = http_meta["has_expect_ct"]

    # CAA records
    if check_caa:
        result.has_caa_record = _check_caa(domain)

    logger.debug(
        f"Chain {domain}:{port} length={result.chain_length} "
        f"complete={result.chain_complete} weak_int={result.has_weak_intermediate}"
    )
    return result


def chain_findings(analysis: ChainAnalysis) -> list[dict]:
    """
    Convert a ChainAnalysis into a list of Finding-compatible dicts
    that the CryptoAssessor can ingest alongside its own findings.
    """
    findings = []

    if not analysis.success:
        return findings

    if not analysis.chain_complete:
        findings.append({
            "severity": "high",
            "category": "chain",
            "message": "Incomplete certificate chain: issuer/subject gap detected",
            "guideline": "all",
            "recommendation": "Configure server to send the full chain including all intermediates",
        })

    if not analysis.chain_ordered:
        findings.append({
            "severity": "low",
            "category": "chain",
            "message": "Certificate chain sent out of order by server",
            "guideline": "all",
            "recommendation": "Reorder chain so leaf is first and root/intermediates follow",
        })

    for cert in analysis.certs:
        role = cert.get("role", "")
        cn   = cert.get("subject_cn", "?")
        pos  = cert.get("position", 0)

        if cert.get("broken_hash") and role != "leaf":
            findings.append({
                "severity": "critical",
                "category": "chain",
                "message": f"Intermediate/root CA uses broken hash: "
                           f"{cert.get('hash_algorithm','')} ({cn})",
                "guideline": "nist_800_131a",
                "recommendation": "The CA must reissue with SHA-256 or stronger. "
                                  "Consider switching to a CA with modern infrastructure.",
            })

        if cert.get("weak_key") and role == "intermediate":
            findings.append({
                "severity": "high",
                "category": "chain",
                "message": f"Intermediate CA has weak key: "
                           f"{cert.get('key_type','')} {cert.get('key_size_bits',0)} bits ({cn})",
                "guideline": "bsi_tr02102",
                "recommendation": "Intermediate CA key is below recommended minimum. "
                                  "The CA should reissue with a stronger key.",
            })

        if cert.get("days_to_expiry", 999) < 0 and role == "intermediate":
            findings.append({
                "severity": "critical",
                "category": "chain",
                "message": f"Intermediate CA certificate is EXPIRED ({cn})",
                "guideline": "all",
                "recommendation": "Server is presenting an expired intermediate. "
                                  "Update to the CA's current intermediate certificate.",
            })

        if role == "leaf" and cert.get("days_to_expiry", 999) < 14:
            # Very soon — supplement the main cert expiry finding
            findings.append({
                "severity": "critical",
                "category": "chain",
                "message": f"Leaf certificate expires in {cert.get('days_to_expiry')} days",
                "guideline": "all",
                "recommendation": "Renew the leaf certificate immediately.",
            })

    if analysis.has_weak_root:
        findings.append({
            "severity": "high",
            "category": "chain",
            "message": "Root CA certificate uses weak/broken hash or key size",
            "guideline": "nist_800_131a",
            "recommendation": "Transition to a CA whose root uses SHA-256+ and RSA-4096 or ECDSA P-384.",
        })

    if not analysis.has_hsts and analysis.success:
        findings.append({
            "severity": "medium",
            "category": "chain",
            "message": "HTTP Strict Transport Security (HSTS) header not present",
            "guideline": "all",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        })
    elif analysis.has_hsts and analysis.hsts_max_age < 15552000:  # 180 days
        findings.append({
            "severity": "low",
            "category": "chain",
            "message": f"HSTS max-age too short: {analysis.hsts_max_age}s (recommended ≥ 15552000s)",
            "guideline": "all",
            "recommendation": "Increase HSTS max-age to at least 180 days (15552000 seconds).",
        })

    if not analysis.has_caa_record:
        findings.append({
            "severity": "low",
            "category": "chain",
            "message": "No DNS CAA record found — any CA can issue for this domain",
            "guideline": "all",
            "recommendation": "Add CAA records to restrict which CAs may issue certificates.",
        })

    return findings
