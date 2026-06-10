#!/usr/bin/env python3
"""
PQC-Monitor: Crypto Extractor
Parses raw TLS probe and Shodan scan dicts into a normalised
CryptoFacts structure that the assessor and report generator consume.

This module decouples data extraction from scoring, allowing the same
raw JSON to be re-parsed after guideline updates without re-scanning.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ── Security-strength lookup tables ──────────────────────────────────────────
# Approximate classical security bits for common primitives
# Sources: NIST SP 800-57 Part 1, BSI TR-02102-1

RSA_STRENGTH = {
    512: 56, 768: 64, 1024: 80, 1536: 96, 2048: 112,
    3072: 128, 4096: 140, 7680: 192, 15360: 256,
}

ECC_STRENGTH = {
    192: 96, 224: 112, 256: 128, 384: 192, 521: 260,
}

HASH_STRENGTH = {
    "MD5": 18, "SHA-1": 69, "SHA-224": 112, "SHA-256": 128,
    "SHA-384": 192, "SHA-512": 256,
    "SHA3-256": 128, "SHA3-384": 192, "SHA3-512": 256,
    "RIPEMD-160": 80,
}

TLS_VERSION_STRENGTH = {
    "SSLv2": 0, "SSLv3": 20, "TLSv1.0": 50,
    "TLSv1.1": 60, "TLSv1.2": 112, "TLSv1.3": 128,
}

# Known PQC algorithm indicators
PQC_KEM_PATTERNS = re.compile(
    r"(kyber|mlkem|ml.?kem|ntru|saber|frodo|mceliece|x25519kyber|x25519mlkem|p256kyber)",
    re.IGNORECASE,
)
PQC_SIG_PATTERNS = re.compile(
    r"(dilithium|mldsa|ml.?dsa|falcon|sphincs|slhdsa|slh.?dsa|xmss|lms)",
    re.IGNORECASE,
)

# Forward-secrecy key-exchange mechanisms
FORWARD_SECRET_KEX = {"ECDHE", "DHE", "EDH", "TLS1.3"}


@dataclass
class CryptoFacts:
    """
    Normalised, source-independent summary of the cryptographic
    configuration of a single TLS service endpoint.
    """
    domain: str
    port: int
    source: str                        # "direct" | "shodan"
    scan_timestamp: str

    # TLS session
    tls_version: str = ""
    tls_version_strength: int = 0      # classical security bits
    cipher_suite: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""
    has_forward_secrecy: bool = False

    # Certificate public key
    key_type: str = ""                 # RSA | ECDSA | Ed25519 | Ed448 | …
    key_size_bits: int = 0
    key_strength_bits: int = 0         # estimated security strength
    recommended_key_size: int = 0      # guideline-recommended minimum

    # Certificate signature
    signature_algorithm: str = ""
    hash_algorithm: str = ""
    hash_strength_bits: int = 0

    # Certificate validity
    cert_subject_cn: str = ""
    cert_issuer_cn: str = ""
    cert_days_to_expiry: Optional[int] = None
    cert_is_self_signed: bool = False
    cert_fingerprint_sha256: str = ""

    # PQC indicators
    has_pqc_kem: bool = False
    has_pqc_sig: bool = False
    pqc_algorithms_detected: list = field(default_factory=list)

    # DANE / DNSSEC (populated by service_discovery)
    has_dane: bool = False
    has_dnssec: bool = False

    # Derived weakness flags (set by classify())
    has_broken_cipher: bool = False    # RC4, NULL, EXPORT, DES
    has_weak_key: bool = False         # RSA<2048, ECDSA<224
    has_deprecated_hash: bool = False  # SHA-1, MD5
    has_old_tls: bool = False          # TLS<1.2
    is_pqc_ready: bool = False         # has PQC or extremely strong classical

    def classify(self) -> "CryptoFacts":
        """Populate derived weakness flags from the raw field values."""
        cipher_up = self.cipher_suite.upper()
        self.has_broken_cipher = any(
            w in cipher_up for w in ("RC4", "NULL", "EXPORT", "ANON", "_DES_")
        ) or (
            "3DES" in cipher_up or "DES_EDE" in cipher_up
        )
        self.has_weak_key = (
            (self.key_type == "RSA" and 0 < self.key_size_bits < 2048) or
            (self.key_type == "ECDSA" and 0 < self.key_size_bits < 224)
        )
        h = self.hash_algorithm.upper()
        self.has_deprecated_hash = h in ("MD5", "MD4", "SHA1", "SHA-1")
        self.has_old_tls = self.tls_version in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
        self.is_pqc_ready = self.has_pqc_kem or self.has_pqc_sig
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def overall_strength_bits(self) -> int:
        """
        Conservative estimate of the minimum security strength across all
        primitives in use — the weakest link determines the chain strength.
        """
        strengths = [s for s in [
            self.tls_version_strength,
            self.key_strength_bits,
            self.hash_strength_bits,
        ] if s > 0]
        return min(strengths) if strengths else 0


def _nearest_rsa_strength(bits: int) -> int:
    """Interpolate RSA security strength for non-standard key sizes."""
    if bits <= 0:
        return 0
    sizes = sorted(RSA_STRENGTH)
    for i, s in enumerate(sizes):
        if bits <= s:
            if i == 0:
                return RSA_STRENGTH[s]
            prev = sizes[i - 1]
            # linear interpolation
            frac = (bits - prev) / (s - prev)
            return int(RSA_STRENGTH[prev] + frac * (RSA_STRENGTH[s] - RSA_STRENGTH[prev]))
    return RSA_STRENGTH[sizes[-1]]


def _nearest_ecc_strength(bits: int) -> int:
    if bits <= 0:
        return 0
    sizes = sorted(ECC_STRENGTH)
    for s in sizes:
        if bits <= s:
            return ECC_STRENGTH[s]
    return ECC_STRENGTH[sizes[-1]]


def extract(scan_result: dict) -> Optional[CryptoFacts]:
    """
    Convert a raw TLSProbeResult or Shodan service dict into a CryptoFacts
    object.  Returns None if the scan failed or has no useful data.
    """
    if not scan_result:
        return None

    success = scan_result.get("success", False)
    source = scan_result.get("source", "direct")
    # Shodan results are always "successful" (they come pre-collected)
    if not success and source != "shodan":
        return None

    cert = scan_result.get("certificate") or {}
    tls_ver = scan_result.get("tls_version", "")
    cipher = scan_result.get("cipher_suite", "")

    # ── TLS version strength ──────────────────────────────────────
    tls_strength = TLS_VERSION_STRENGTH.get(tls_ver, 0)

    # ── Key exchange / forward secrecy ────────────────────────────
    kex = scan_result.get("key_exchange", "")
    if not kex:
        kex = _infer_kex(cipher, tls_ver)
    # TLS 1.3 always provides forward secrecy (mandated by spec)
    if tls_ver == "TLSv1.3":
        has_fs = True
    else:
        has_fs = kex in FORWARD_SECRET_KEX

    # ── Key strength ──────────────────────────────────────────────
    key_type = (cert.get("key_type") or "").upper()
    key_size = cert.get("key_size_bits") or 0
    if key_type == "RSA":
        key_strength = _nearest_rsa_strength(key_size)
        rec_size = 3072
    elif key_type in ("ECDSA", "EC"):
        key_strength = _nearest_ecc_strength(key_size)
        rec_size = 256
    elif key_type in ("ED25519",):
        key_strength = 128
        rec_size = 256
    elif key_type in ("ED448",):
        key_strength = 224
        rec_size = 448
    else:
        key_strength = 0
        rec_size = 0

    # ── Hash strength ─────────────────────────────────────────────
    hash_alg = (cert.get("hash_algorithm") or "").upper().replace("SHA", "SHA-")
    # normalise: SHA256 → SHA-256
    hash_alg = re.sub(r"SHA-(\d)", r"SHA-\1", hash_alg)
    hash_alg = re.sub(r"SHA(\d)", r"SHA-\1", hash_alg)
    hash_strength = HASH_STRENGTH.get(hash_alg, 0)
    if not hash_strength:
        # try without hyphen variants
        for k, v in HASH_STRENGTH.items():
            if k.replace("-", "") == hash_alg.replace("-", ""):
                hash_strength = v
                hash_alg = k
                break

    # ── PQC detection ─────────────────────────────────────────────
    pqc_algos = []
    has_kem = bool(PQC_KEM_PATTERNS.search(cipher))
    has_sig = bool(PQC_SIG_PATTERNS.search(cipher))
    # Also check explicit flags from probe
    has_kem = has_kem or bool(scan_result.get("has_pqc_kem"))
    has_sig = has_sig or bool(scan_result.get("has_pqc_sig"))
    if has_kem:
        m = PQC_KEM_PATTERNS.search(cipher)
        pqc_algos.append(f"PQC-KEM:{m.group(0) if m else 'detected'}")
    if has_sig:
        m = PQC_SIG_PATTERNS.search(cipher)
        pqc_algos.append(f"PQC-Sig:{m.group(0) if m else 'detected'}")
    pqc_algos.extend(scan_result.get("pqc_algorithms") or [])

    facts = CryptoFacts(
        domain=scan_result.get("domain", ""),
        port=scan_result.get("port", 0),
        source=source,
        scan_timestamp=scan_result.get("timestamp", ""),

        tls_version=tls_ver,
        tls_version_strength=tls_strength,
        cipher_suite=cipher,
        cipher_bits=scan_result.get("cipher_bits") or 0,
        key_exchange=kex,
        has_forward_secrecy=has_fs,

        key_type=key_type,
        key_size_bits=key_size,
        key_strength_bits=key_strength,
        recommended_key_size=rec_size,

        signature_algorithm=cert.get("signature_algorithm") or "",
        hash_algorithm=hash_alg,
        hash_strength_bits=hash_strength,

        cert_subject_cn=cert.get("subject_cn") or "",
        cert_issuer_cn=cert.get("issuer_cn") or "",
        cert_days_to_expiry=cert.get("days_to_expiry"),
        cert_is_self_signed=bool(cert.get("is_self_signed")),
        cert_fingerprint_sha256=cert.get("fingerprint_sha256") or "",

        has_pqc_kem=has_kem,
        has_pqc_sig=has_sig,
        pqc_algorithms_detected=pqc_algos,

        has_dane=bool(scan_result.get("has_dane")),
        has_dnssec=bool(scan_result.get("has_dnssec")),
    )
    return facts.classify()


def extract_all(scan_results: list) -> list[CryptoFacts]:
    """Extract CryptoFacts from a list of raw scan dicts, skipping failures."""
    out = []
    for r in scan_results:
        f = extract(r)
        if f is not None:
            out.append(f)
    return out


def _infer_kex(cipher: str, tls_ver: str) -> str:
    """Infer key-exchange mechanism from cipher name and TLS version."""
    u = cipher.upper()
    if "ECDHE" in u:
        return "ECDHE"
    if "DHE" in u or "EDH" in u:
        return "DHE"
    if "ECDH" in u:
        return "ECDH"
    if "DH" in u:
        return "DH"
    if tls_ver == "TLSv1.3":
        return "TLS1.3"   # TLS 1.3 mandates (EC)DHE; cipher name omits it
    if "RSA" in u:
        return "RSA"
    return "UNKNOWN"


def summarise_domain(domain: str, facts_list: list[CryptoFacts]) -> dict:
    """
    Aggregate multiple per-port CryptoFacts for a domain into a single
    summary dict suitable for reporting.
    """
    if not facts_list:
        return {"domain": domain, "services": 0}

    tls_versions = sorted({f.tls_version for f in facts_list if f.tls_version})
    ciphers = sorted({f.cipher_suite for f in facts_list if f.cipher_suite})
    key_types = sorted({f.key_type for f in facts_list if f.key_type})
    min_strength = min(
        (f.overall_strength_bits for f in facts_list if f.overall_strength_bits > 0),
        default=0
    )
    has_pqc = any(f.has_pqc_kem or f.has_pqc_sig for f in facts_list)
    has_fs = any(f.has_forward_secrecy for f in facts_list)
    has_broken = any(f.has_broken_cipher for f in facts_list)
    has_weak_key = any(f.has_weak_key for f in facts_list)
    has_dep_hash = any(f.has_deprecated_hash for f in facts_list)
    has_old_tls = any(f.has_old_tls for f in facts_list)
    expiry_days = [f.cert_days_to_expiry for f in facts_list
                   if f.cert_days_to_expiry is not None]

    return {
        "domain": domain,
        "services_found": len(facts_list),
        "tls_versions": tls_versions,
        "cipher_suites": ciphers,
        "key_types": key_types,
        "min_security_strength_bits": min_strength,
        "has_forward_secrecy": has_fs,
        "has_pqc": has_pqc,
        "has_broken_cipher": has_broken,
        "has_weak_key": has_weak_key,
        "has_deprecated_hash": has_dep_hash,
        "has_old_tls": has_old_tls,
        "min_cert_expiry_days": min(expiry_days) if expiry_days else None,
        "pqc_algorithms": list({a for f in facts_list
                                 for a in f.pqc_algorithms_detected}),
    }
