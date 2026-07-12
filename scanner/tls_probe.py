#!/usr/bin/env python3
"""
PQC-Monitor: TLS Probe Module
Performs non-intrusive TLS handshake and certificate extraction.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import ssl
import socket
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, ed25519, ed448
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int = 0
    key_type: str = ""
    key_size_bits: int = 0
    signature_algorithm: str = ""
    hash_algorithm: str = ""
    san_domains: list = None
    is_ev: bool = False
    is_self_signed: bool = False
    serial_number: str = ""
    fingerprint_sha256: str = ""

    def __post_init__(self):
        if self.san_domains is None:
            self.san_domains = []


@dataclass
class TLSProbeResult:
    domain: str
    port: int
    timestamp: str
    success: bool
    error: Optional[str] = None

    # TLS session info
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""
    key_group: str = ""          # negotiated TLS key-exchange group (e.g. X25519MLKEM768)

    # Certificate chain
    certificate: Optional[CertificateInfo] = None
    chain_length: int = 0

    # PQC indicators
    has_pqc_kem: bool = False
    has_pqc_sig: bool = False
    pqc_algorithms: list = None

    # Raw scan data for re-assessment
    raw_cipher_list: list = None

    def __post_init__(self):
        if self.pqc_algorithms is None:
            self.pqc_algorithms = []
        if self.raw_cipher_list is None:
            self.raw_cipher_list = []

    def to_dict(self):
        d = asdict(self)
        if self.certificate:
            d['certificate'] = asdict(self.certificate)
        return d


# Known PQC algorithm indicators in cipher suite names / extensions
PQC_KEM_INDICATORS = [
    "kyber", "mlkem", "ml-kem", "ntru", "saber", "frodo", "mceliece",
    "x25519kyber768", "x25519mlkem768", "p256kyber768"
]
PQC_SIG_INDICATORS = [
    "dilithium", "mldsa", "ml-dsa", "falcon", "sphincs", "slhdsa", "slh-dsa",
    "xmss", "lms"
]


def _detect_pqc(cipher_name: str, tls_version: str,
                key_group: str = "") -> tuple[bool, bool, list]:
    """Detect PQC references in the cipher suite, TLS version, or negotiated
    key-exchange group. In TLS 1.3 the cipher suite does NOT encode the KEX
    group, so ML-KEM is only visible via the negotiated group (key_group)."""
    hay = " ".join(s.lower() for s in (cipher_name, tls_version, key_group) if s)
    pqc_algos = []
    has_kem = any(ind in hay for ind in PQC_KEM_INDICATORS)
    has_sig = any(ind in hay for ind in PQC_SIG_INDICATORS)
    if has_kem:
        where = key_group or cipher_name
        pqc_algos.append(f"PQC-KEM detected in: {where}")
    if has_sig:
        pqc_algos.append(f"PQC-Sig detected in: {cipher_name}")
    return has_kem, has_sig, pqc_algos


def _parse_certificate(cert_der: bytes) -> Optional[CertificateInfo]:
    """Parse a DER-encoded X.509 certificate into CertificateInfo."""
    if not HAS_CRYPTOGRAPHY or not cert_der:
        return None
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        info = CertificateInfo()

        # Subject
        try:
            info.subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            info.subject_cn = ""

        # Issuer
        try:
            info.issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            info.issuer_cn = ""

        # Validity
        try:
            info.not_before = cert.not_valid_before_utc.isoformat()
            info.not_after = cert.not_valid_after_utc.isoformat()
            now = datetime.now(timezone.utc)
            delta = cert.not_valid_after_utc - now
            info.days_to_expiry = delta.days
        except Exception:
            pass

        # Public key
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            info.key_type = "RSA"
            info.key_size_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            info.key_type = "ECDSA"
            info.key_size_bits = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            info.key_type = "Ed25519"
            info.key_size_bits = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            info.key_type = "Ed448"
            info.key_size_bits = 448
        else:
            info.key_type = str(type(pub_key).__name__)

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid
        sig_hash = cert.signature_hash_algorithm
        info.signature_algorithm = cert.signature_algorithm_oid.dotted_string
        try:
            # Map OID to human-readable
            sig_name_map = {
                "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
                "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
                "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
                "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
                "1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
                "1.2.840.10045.4.3.3":   "ecdsa-with-SHA384",
                "1.2.840.10045.4.3.4":   "ecdsa-with-SHA512",
                "1.3.101.112":           "Ed25519",
                "1.3.101.113":           "Ed448",
            }
            info.signature_algorithm = sig_name_map.get(
                sig_algo.dotted_string, sig_algo.dotted_string
            )
        except Exception:
            pass

        if sig_hash:
            info.hash_algorithm = sig_hash.name.upper()

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.san_domains = [
                n.value for n in san_ext.value
                if isinstance(n, (x509.DNSName, x509.IPAddress))
            ]
        except x509.ExtensionNotFound:
            pass

        # Self-signed
        info.is_self_signed = (cert.subject == cert.issuer)

        # Serial
        info.serial_number = hex(cert.serial_number)

        # SHA-256 fingerprint
        import hashlib
        info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

        return info

    except Exception as e:
        logger.debug(f"Certificate parse error: {e}")
        return None


def probe_tls(domain: str, port: int = 443, timeout: int = 10) -> TLSProbeResult:
    """
    Perform a non-intrusive TLS handshake against domain:port.
    Returns TLSProbeResult with all extracted cryptographic metadata.
    """
    ts = datetime.now(timezone.utc).isoformat()
    result = TLSProbeResult(domain=domain, port=port, timestamp=ts, success=False)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            # For SMTP/STARTTLS on port 465 we still wrap directly
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                result.success = True
                result.tls_version = tls_sock.version() or ""
                cipher = tls_sock.cipher()
                if cipher:
                    result.cipher_suite = cipher[0]
                    result.cipher_bits = cipher[2] or 0
                    result.key_exchange = _infer_key_exchange(cipher[0])

                # Negotiated key-exchange group (Python >=3.13 + OpenSSL >=3.2).
                # This is where ML-KEM lives — the TLS 1.3 cipher suite does NOT
                # encode the KEX group, so PQC is invisible without reading it.
                try:
                    result.key_group = tls_sock.group() or "" if hasattr(tls_sock, "group") else ""
                except (OSError, ssl.SSLError):
                    result.key_group = ""

                # PQC detection (cipher suite + TLS version + negotiated group)
                kem, sig, algos = _detect_pqc(
                    result.cipher_suite, result.tls_version, result.key_group)
                result.has_pqc_kem = kem
                result.has_pqc_sig = sig
                result.pqc_algorithms = algos

                # Certificate
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert_der:
                    result.certificate = _parse_certificate(cert_der)

                # Try to get full chain length
                try:
                    chain = tls_sock.get_verified_chain()
                    result.chain_length = len(chain) if chain else 1
                except AttributeError:
                    result.chain_length = 1

    except socket.timeout:
        result.error = "timeout"
    except ConnectionRefusedError:
        result.error = "connection_refused"
    except ssl.SSLError as e:
        result.error = f"ssl_error:{e.reason}"
    except OSError as e:
        result.error = f"os_error:{e}"
    except Exception as e:
        result.error = f"error:{e}"

    return result


def _infer_key_exchange(cipher_name: str) -> str:
    """Infer the key exchange mechanism from the cipher suite name."""
    upper = cipher_name.upper()
    if "ECDHE" in upper:
        return "ECDHE"
    if "DHE" in upper or "EDH" in upper:
        return "DHE"
    if "ECDH" in upper:
        return "ECDH"
    if "DH" in upper:
        return "DH"
    if "RSA" in upper:
        return "RSA"
    if "PSK" in upper:
        return "PSK"
    # TLS 1.3 suites don't encode key exchange in the name
    return "TLS1.3"


def probe_domain_all_ports(domain: str, ports: list, timeout: int = 10) -> list:
    """Probe multiple ports for a given domain."""
    results = []
    for port in ports:
        r = probe_tls(domain, port, timeout)
        if r.success or r.error not in ("connection_refused", "timeout"):
            results.append(r.to_dict())
    return results
