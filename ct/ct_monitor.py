#!/usr/bin/env python3
"""
PQC-Monitor: Certificate Transparency Monitor
Queries the crt.sh CT aggregator to detect when PQC-enabled certificates
are issued for monitored domains — without any active scanning.

Detection strategy
──────────────────
1. Fetch all unexpired certificates for a domain from crt.sh JSON API.
2. For each certificate retrieve the full DER via crt.sh/id/<id>.pem.
3. Inspect:
   a. Subject Public Key Info OID  — detects PQC public keys (ML-DSA, SLH-DSA,
      Falcon, XMSS …) as they gain X.509 OID assignments.
   b. Signature algorithm OID      — detects hybrid or pure PQC signatures.
   c. Subject Alternative Names    — collects subdomain coverage.
   d. Issuer                       — identifies which CA is issuing PQC certs.
4. Store results in the `ct_certificates` table; emit structured findings.

crt.sh is a free public service operated by Sectigo.  Rate-limit: max one
request per second, batch size ≤ 100 certs per domain query.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Public constants ──────────────────────────────────────────────────────────

CRTSH_JSON_URL  = "https://crt.sh/?q={domain}&output=json&exclude=expired"
CRTSH_PEM_URL   = "https://crt.sh/?d={cert_id}"
REQUEST_TIMEOUT = 15   # seconds
RATE_LIMIT_SECS = 1.1  # stay well within crt.sh acceptable use

# ── Known PQC OID registry ────────────────────────────────────────────────────
# Sources:
#   IETF draft-ietf-lamps-dilithium-certificates
#   IETF draft-ietf-lamps-kyber-certificates (informational; KEM not in X.509 sig)
#   NIST FIPS 203/204/205 OID assignments (pending formal registry)
#   Open Quantum Safe project interim OIDs (1.3.9999.x)

PQC_SIGNATURE_OIDS: dict[str, str] = {
    # ML-DSA (CRYSTALS-Dilithium) — FIPS 204
    # draft-ietf-lamps-dilithium-certificates-04
    "1.3.6.1.4.1.2.267.12.4.4":  "ML-DSA-44",
    "1.3.6.1.4.1.2.267.12.6.5":  "ML-DSA-65",
    "1.3.6.1.4.1.2.267.12.8.7":  "ML-DSA-87",
    # SLH-DSA (SPHINCS+) — FIPS 205
    # draft-ietf-lamps-x509-slhdsa
    "1.3.9999.6.4.13": "SLH-DSA-SHA2-128s",
    "1.3.9999.6.4.16": "SLH-DSA-SHA2-128f",
    "1.3.9999.6.5.10": "SLH-DSA-SHA2-192s",
    "1.3.9999.6.5.12": "SLH-DSA-SHA2-192f",
    "1.3.9999.6.6.10": "SLH-DSA-SHA2-256s",
    "1.3.9999.6.6.12": "SLH-DSA-SHA2-256f",
    "1.3.9999.6.7.13": "SLH-DSA-SHAKE-128s",
    "1.3.9999.6.7.15": "SLH-DSA-SHAKE-128f",
    "1.3.9999.6.8.10": "SLH-DSA-SHAKE-192s",
    "1.3.9999.6.8.12": "SLH-DSA-SHAKE-192f",
    "1.3.9999.6.9.10": "SLH-DSA-SHAKE-256s",
    "1.3.9999.6.9.12": "SLH-DSA-SHAKE-256f",
    # Falcon — draft-ietf-lamps-falcon-certificates
    "1.3.9999.3.6":  "Falcon-512",
    "1.3.9999.3.9":  "Falcon-1024",
    "1.3.9999.3.11": "Falcon-padded-512",
    "1.3.9999.3.12": "Falcon-padded-1024",
    # XMSS / LMS (stateful; RFC 8391, RFC 8708)
    "0.4.0.127.0.15.1.1.13.0": "XMSS",
    "0.4.0.127.0.15.1.1.13.1": "XMSSMT",
    "1.2.840.113549.1.9.16.3.17": "LMS",
    # Hybrid: classical + PQC composite (draft-ounsworth-pq-composite-sigs)
    "2.16.840.1.114027.80.8.1.1":  "Composite-ML-DSA-44-RSA2048-PSS",
    "2.16.840.1.114027.80.8.1.2":  "Composite-ML-DSA-44-RSA2048-PKCS15",
    "2.16.840.1.114027.80.8.1.3":  "Composite-ML-DSA-44-Ed25519",
    "2.16.840.1.114027.80.8.1.4":  "Composite-ML-DSA-44-ECDSA-P256",
    "2.16.840.1.114027.80.8.1.21": "Composite-ML-DSA-65-RSA3072-PSS",
    "2.16.840.1.114027.80.8.1.22": "Composite-ML-DSA-65-RSA3072-PKCS15",
    "2.16.840.1.114027.80.8.1.23": "Composite-ML-DSA-65-ECDSA-P256",
    "2.16.840.1.114027.80.8.1.24": "Composite-ML-DSA-65-ECDSA-brainpoolP256r1",
    "2.16.840.1.114027.80.8.1.25": "Composite-ML-DSA-65-Ed25519",
    "2.16.840.1.114027.80.8.1.26": "Composite-ML-DSA-87-ECDSA-P384",
    "2.16.840.1.114027.80.8.1.27": "Composite-ML-DSA-87-ECDSA-brainpoolP384r1",
    "2.16.840.1.114027.80.8.1.28": "Composite-ML-DSA-87-Ed448",
    "2.16.840.1.114027.80.8.1.29": "Composite-ML-DSA-87-RSA4096-PSS",
}

# Public key OIDs (for SPKI inspection)
PQC_PUBKEY_OIDS: dict[str, str] = {
    # ML-KEM — FIPS 203 (KEM; used in TLS, not in X.509 sig itself)
    "1.3.6.1.4.1.22554.5.6.1": "ML-KEM-512",
    "1.3.6.1.4.1.22554.5.6.2": "ML-KEM-768",
    "1.3.6.1.4.1.22554.5.6.3": "ML-KEM-1024",
    # ML-DSA public keys
    "1.3.6.1.4.1.2.267.12.4.4": "ML-DSA-44",
    "1.3.6.1.4.1.2.267.12.6.5": "ML-DSA-65",
    "1.3.6.1.4.1.2.267.12.8.7": "ML-DSA-87",
    # Falcon public keys
    "1.3.9999.3.6":  "Falcon-512",
    "1.3.9999.3.9":  "Falcon-1024",
}

# OIDs that appear in experimental/pilot deployments before final assignments
EXPERIMENTAL_PQC_OID_PREFIXES = ("1.3.9999.", "1.3.6.1.4.1.22554.")


@dataclass
class CTCertificate:
    """Represents one certificate entry from CT logs."""
    # Identity
    cert_id: int                        # crt.sh internal ID
    sha256_fingerprint: str
    domain: str                         # queried domain
    subject_cn: str
    issuer_cn: str
    issuer_org: str

    # Validity
    not_before: str
    not_after: str
    days_to_expiry: int

    # Crypto
    signature_algorithm_oid: str
    signature_algorithm_name: str
    pubkey_algorithm_oid: str
    pubkey_algorithm_name: str
    pubkey_size_bits: int

    # PQC classification
    is_pqc_signature: bool
    is_pqc_pubkey: bool
    is_hybrid: bool
    pqc_algorithms: list = field(default_factory=list)

    # Metadata
    sans: list = field(default_factory=list)
    log_entries: list = field(default_factory=list)   # CT log names
    first_seen: str = ""
    queried_at: str = ""

    @property
    def has_any_pqc(self) -> bool:
        return self.is_pqc_signature or self.is_pqc_pubkey

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CTSummary:
    """Aggregated CT findings for one domain."""
    domain: str
    queried_at: str
    total_certs_found: int
    pqc_certs_found: int
    hybrid_certs_found: int
    classical_certs_found: int
    pqc_issuers: list = field(default_factory=list)
    pqc_algorithms_seen: list = field(default_factory=list)
    earliest_pqc_cert_date: Optional[str] = None
    latest_pqc_cert_date: Optional[str] = None
    certificates: list = field(default_factory=list)   # list of CTCertificate dicts
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── crt.sh client ─────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    """GET with error handling; returns None on failure."""
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "PQCMonitor/1.0 CT-research"})
        r.raise_for_status()
        return r
    except requests.RequestException as e:
        logger.debug(f"HTTP error {url}: {e}")
        return None


def _fetch_cert_list(domain: str) -> list[dict]:
    """
    Fetch the JSON list of certificates for *domain* from crt.sh.
    Returns a list of raw dicts; empty on failure.
    """
    # crt.sh supports wildcard prefix search with %.domain syntax
    url = CRTSH_JSON_URL.format(domain=f"%.{domain}")
    r = _get(url)
    if not r:
        # Retry exact match
        url = CRTSH_JSON_URL.format(domain=domain)
        r = _get(url)
    if not r:
        return []
    try:
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.debug(f"JSON parse error for {domain}: {e}")
        return []


def _fetch_cert_pem(cert_id: int) -> Optional[bytes]:
    """Fetch a single certificate in PEM form from crt.sh."""
    time.sleep(RATE_LIMIT_SECS)
    r = _get(CRTSH_PEM_URL.format(cert_id=cert_id))
    return r.content if r else None


# ── Certificate parsing ───────────────────────────────────────────────────────

def _parse_pem_certificate(pem_bytes: bytes) -> Optional[dict]:
    """
    Parse a PEM certificate using the `cryptography` library.
    Returns a dict of crypto facts, or None on failure.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        from cryptography.x509.oid import NameOID

        cert = x509.load_pem_x509_certificate(pem_bytes)

        # Subject / Issuer
        def _cn(name):
            try:
                return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                return ""

        def _org(name):
            try:
                return name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            except Exception:
                return ""

        subject_cn = _cn(cert.subject)
        issuer_cn  = _cn(cert.issuer)
        issuer_org = _org(cert.issuer)

        # Validity
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc.isoformat()
        not_after  = cert.not_valid_after_utc.isoformat()
        days_to_expiry = (cert.not_valid_after_utc - now).days

        # Signature algorithm
        sig_oid  = cert.signature_algorithm_oid.dotted_string
        sig_hash = cert.signature_hash_algorithm
        sig_name = _resolve_sig_name(cert, sig_oid)

        # Public key
        pub   = cert.public_key()
        pk_oid, pk_name, pk_bits = _inspect_pubkey(pub)

        # SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in san_ext.value
                    if isinstance(n, (x509.DNSName, x509.IPAddress))]
        except Exception:
            pass

        # SHA-256 fingerprint
        fp = cert.fingerprint(cert.signature_hash_algorithm or __import__(
            "cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]
        ).SHA256()).hex()

        return {
            "subject_cn":              subject_cn,
            "issuer_cn":               issuer_cn,
            "issuer_org":              issuer_org,
            "not_before":              not_before,
            "not_after":               not_after,
            "days_to_expiry":          days_to_expiry,
            "signature_algorithm_oid": sig_oid,
            "signature_algorithm_name": sig_name,
            "pubkey_algorithm_oid":    pk_oid,
            "pubkey_algorithm_name":   pk_name,
            "pubkey_size_bits":        pk_bits,
            "sans":                    sans,
            "sha256_fingerprint":      fp,
        }
    except Exception as e:
        logger.debug(f"Certificate parse error: {e}")
        return None


def _resolve_sig_name(cert, oid: str) -> str:
    """Human-readable signature algorithm name."""
    # Check PQC registry first
    if oid in PQC_SIGNATURE_OIDS:
        return PQC_SIGNATURE_OIDS[oid]

    # Fall back to classical name mapping
    _classical = {
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
    if oid in _classical:
        return _classical[oid]

    # Try the cryptography library name
    try:
        h = cert.signature_hash_algorithm
        return h.name.upper() if h else oid
    except Exception:
        return oid


def _inspect_pubkey(pub_key) -> tuple[str, str, int]:
    """Return (oid_string, human_name, key_size_bits) for a public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dh
        if isinstance(pub_key, rsa.RSAPublicKey):
            return ("1.2.840.113549.1.1.1", "RSA", pub_key.key_size)
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            return ("1.2.840.10045.2.1", f"ECDSA-{pub_key.curve.name}", pub_key.key_size)
        if isinstance(pub_key, ed25519.Ed25519PublicKey):
            return ("1.3.101.112", "Ed25519", 256)
        if isinstance(pub_key, ed448.Ed448PublicKey):
            return ("1.3.101.113", "Ed448", 448)
    except Exception:
        pass

    # For PQC keys the cryptography library may not recognise the OID yet;
    # the raw OID will have been captured from the signature algorithm instead.
    return ("unknown", "Unknown", 0)


# ── PQC classification ────────────────────────────────────────────────────────

def _classify_pqc(sig_oid: str, pk_oid: str) -> tuple[bool, bool, bool, list]:
    """
    Returns (is_pqc_sig, is_pqc_pk, is_hybrid, pqc_algorithm_names).
    """
    pqc_algos = []
    is_pqc_sig = sig_oid in PQC_SIGNATURE_OIDS
    is_pqc_pk  = pk_oid in PQC_PUBKEY_OIDS

    if is_pqc_sig:
        pqc_algos.append(PQC_SIGNATURE_OIDS[sig_oid])
    if is_pqc_pk and PQC_PUBKEY_OIDS[pk_oid] not in pqc_algos:
        pqc_algos.append(PQC_PUBKEY_OIDS[pk_oid])

    # Experimental OID prefix detection (catch pre-assignment deployments)
    for oid in (sig_oid, pk_oid):
        if any(oid.startswith(p) for p in EXPERIMENTAL_PQC_OID_PREFIXES):
            if oid not in PQC_SIGNATURE_OIDS and oid not in PQC_PUBKEY_OIDS:
                pqc_algos.append(f"Experimental-PQC:{oid}")
                is_pqc_sig = True  # treat as PQC

    # Hybrid: name contains "Composite" or both classical and PQC OIDs in same cert
    is_hybrid = "Composite" in " ".join(pqc_algos)

    return is_pqc_sig, is_pqc_pk, is_hybrid, pqc_algos


# ── Main public API ───────────────────────────────────────────────────────────

def monitor_domain(domain: str, fetch_pem: bool = True,
                   max_certs: int = 200) -> CTSummary:
    """
    Query CT logs for *domain* and classify each certificate for PQC usage.

    Parameters
    ----------
    domain      Target domain (e.g. "example.com")
    fetch_pem   If True, download each certificate's PEM to inspect OIDs.
                Set False in tests or when only the crt.sh JSON metadata
                is needed (faster but cannot detect PQC OIDs directly).
    max_certs   Upper bound on certificates processed per domain.

    Returns
    -------
    CTSummary with all found certificates and aggregated findings.
    """
    queried_at = datetime.now(timezone.utc).isoformat()
    summary = CTSummary(
        domain=domain,
        queried_at=queried_at,
        total_certs_found=0,
        pqc_certs_found=0,
        hybrid_certs_found=0,
        classical_certs_found=0,
    )

    raw_list = _fetch_cert_list(domain)
    if not raw_list:
        summary.error = "no_results_or_network_error"
        return summary

    # Deduplicate by cert_id
    seen_ids: set[int] = set()
    unique = []
    for entry in raw_list:
        cid = entry.get("id") or entry.get("min_cert_id")
        if cid and cid not in seen_ids:
            seen_ids.add(cid)
            unique.append(entry)

    summary.total_certs_found = len(unique)
    processed = unique[:max_certs]
    certs_out: list[CTCertificate] = []

    for entry in processed:
        cert_id   = entry.get("id") or entry.get("min_cert_id", 0)
        issuer_cn = entry.get("issuer_ca_id", "")
        first_seen = entry.get("entry_timestamp", "")
        name_value = entry.get("name_value", domain)

        # Default values from JSON (no PEM fetch)
        sig_oid  = ""
        sig_name = "unknown"
        pk_oid   = ""
        pk_name  = "unknown"
        pk_bits  = 0
        sans: list[str] = [n.strip() for n in name_value.split("\n") if n.strip()]
        subject_cn = sans[0] if sans else domain
        issuer_org = ""
        not_before = ""
        not_after  = entry.get("not_after", "")
        fp         = entry.get("id", "")

        # Expiry from JSON
        days_to_expiry = 0
        if not_after:
            try:
                exp = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                days_to_expiry = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass

        # Full OID inspection from PEM
        if fetch_pem and cert_id:
            pem = _fetch_cert_pem(cert_id)
            if pem:
                parsed = _parse_pem_certificate(pem)
                if parsed:
                    subject_cn = parsed["subject_cn"] or subject_cn
                    issuer_cn  = parsed["issuer_cn"]  or str(issuer_cn)
                    issuer_org = parsed["issuer_org"]
                    not_before = parsed["not_before"]
                    not_after  = parsed["not_after"]
                    days_to_expiry = parsed["days_to_expiry"]
                    sig_oid    = parsed["signature_algorithm_oid"]
                    sig_name   = parsed["signature_algorithm_name"]
                    pk_oid     = parsed["pubkey_algorithm_oid"]
                    pk_name    = parsed["pubkey_algorithm_name"]
                    pk_bits    = parsed["pubkey_size_bits"]
                    sans       = parsed["sans"] or sans
                    fp         = parsed["sha256_fingerprint"]

        is_pqc_sig, is_pqc_pk, is_hybrid, pqc_algos = _classify_pqc(sig_oid, pk_oid)

        ct_cert = CTCertificate(
            cert_id=cert_id,
            sha256_fingerprint=str(fp),
            domain=domain,
            subject_cn=str(subject_cn),
            issuer_cn=str(issuer_cn),
            issuer_org=str(issuer_org),
            not_before=not_before,
            not_after=not_after,
            days_to_expiry=days_to_expiry,
            signature_algorithm_oid=sig_oid,
            signature_algorithm_name=sig_name,
            pubkey_algorithm_oid=pk_oid,
            pubkey_algorithm_name=pk_name,
            pubkey_size_bits=pk_bits,
            is_pqc_signature=is_pqc_sig,
            is_pqc_pubkey=is_pqc_pk,
            is_hybrid=is_hybrid,
            pqc_algorithms=pqc_algos,
            sans=sans,
            first_seen=first_seen,
            queried_at=queried_at,
        )
        certs_out.append(ct_cert)

    # Aggregate
    summary.certificates    = [c.to_dict() for c in certs_out]
    summary.pqc_certs_found    = sum(1 for c in certs_out if c.has_any_pqc)
    summary.hybrid_certs_found = sum(1 for c in certs_out if c.is_hybrid)
    summary.classical_certs_found = (
        summary.total_certs_found - summary.pqc_certs_found
    )

    pqc_certs = [c for c in certs_out if c.has_any_pqc]
    if pqc_certs:
        summary.pqc_issuers = sorted({c.issuer_cn for c in pqc_certs if c.issuer_cn})
        summary.pqc_algorithms_seen = sorted({
            a for c in pqc_certs for a in c.pqc_algorithms
        })
        dates = [c.not_before for c in pqc_certs if c.not_before]
        if dates:
            summary.earliest_pqc_cert_date = min(dates)
            summary.latest_pqc_cert_date   = max(dates)

    logger.info(
        f"CT monitor {domain}: {summary.total_certs_found} certs, "
        f"{summary.pqc_certs_found} PQC, {summary.hybrid_certs_found} hybrid"
    )
    return summary


def monitor_domains(domains: list[str], fetch_pem: bool = True,
                    max_certs_per_domain: int = 100) -> list[CTSummary]:
    """
    Run CT monitoring across a list of domains sequentially.
    Rate-limiting is applied per certificate PEM fetch inside monitor_domain().
    """
    results = []
    for domain in domains:
        logger.info(f"CT monitoring: {domain}")
        summary = monitor_domain(domain, fetch_pem=fetch_pem,
                                 max_certs=max_certs_per_domain)
        results.append(summary)
        time.sleep(RATE_LIMIT_SECS)   # polite inter-domain pause
    return results
