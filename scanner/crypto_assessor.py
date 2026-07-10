#!/usr/bin/env python3
"""
PQC-Monitor: Crypto Assessment Engine
Evaluates TLS probe results against versioned guidelines and produces
a PQC readiness score with detailed findings.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
from typing import Optional
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)

try:
    from scanner.cipher_enum import _OPENSSL_TO_IANA
except ImportError:  # stand-alone / relative execution
    try:
        from cipher_enum import _OPENSSL_TO_IANA
    except ImportError:
        _OPENSSL_TO_IANA = {}

GUIDELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "guidelines")

# PQC readiness levels
LEVEL_CRITICAL = "critical"   # 0-25
LEVEL_WEAK     = "weak"       # 26-50
LEVEL_MODERATE = "moderate"   # 51-75
LEVEL_READY    = "ready"      # 76-100
LEVEL_NA       = "na"         # no TLS service — not applicable


def score_to_level(score: int) -> str:
    if score <= 25:   return LEVEL_CRITICAL
    if score <= 50:   return LEVEL_WEAK
    if score <= 75:   return LEVEL_MODERATE
    return LEVEL_READY


@dataclass
class Finding:
    severity: str        # critical / high / medium / low / info
    category: str        # tls_version / cipher / key_size / hash / certificate / pqc
    message: str
    guideline: str       # which guideline triggered this
    recommendation: str = ""
    ciphers: list = field(default_factory=list)  # named suites (cipher_enum findings)


@dataclass
class DomainAssessment:
    domain: str
    scan_timestamp: str
    assessment_timestamp: str
    guidelines_used: list = field(default_factory=list)
    score: int = 0
    level: str = ""
    findings: list = field(default_factory=list)
    services_assessed: int = 0
    tls_versions_found: list = field(default_factory=list)
    cipher_suites_found: list = field(default_factory=list)
    key_types_found: list = field(default_factory=list)
    has_pqc: bool = False
    certificate_expiry_days: Optional[int] = None
    errors: list = field(default_factory=list)
    # CDN context
    cdn_name: str = ""
    cdn_slug: str = ""
    cdn_pqc_support: str = ""
    # Service type tag (T2-1)
    service_type: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d['findings'] = [asdict(f) if isinstance(f, Finding) else f for f in self.findings]
        return d


class CryptoAssessor:
    """
    Loads guideline JSON files and assesses scan results against them.
    Designed for re-assessment: pass new scan data OR existing scan data
    with updated guidelines.
    """

    def __init__(self, guideline_ids: list = None, guidelines_dir: str = None):
        self.guidelines_dir = guidelines_dir or GUIDELINES_DIR
        self.guidelines = {}
        active = guideline_ids or ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"]
        for gid in active:
            self._load_guideline(gid)

    def _load_guideline(self, gid: str):
        path = os.path.join(self.guidelines_dir, f"{gid}.json")
        try:
            with open(path) as f:
                self.guidelines[gid] = json.load(f)
            logger.debug(f"Loaded guideline: {gid} v{self.guidelines[gid].get('version','?')}")
        except FileNotFoundError:
            logger.warning(f"Guideline file not found: {path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {path}: {e}")

    def assess_domain(self, domain: str, scan_results: list,
                      assessment_ts: str = None,
                      chain_analysis: dict = None,
                      cipher_enum: dict = None,
                      cdn_result: dict = None,
                      extra_findings: list = None,
                      service_type: str = None) -> DomainAssessment:
        """
        Assess a domain given per-port scan results plus optional enrichment data.

        scan_results    : list of dicts from TLSProbeResult.to_dict()
        chain_analysis  : ChainAnalysis.to_dict() from chain_validator
        cipher_enum     : CipherEnumResult.to_dict() from cipher_enum
        cdn_result      : CDNDetectionResult.to_dict() from cdn_detector
        extra_findings  : pre-computed Finding dicts to merge in
        """
        from datetime import datetime, timezone
        if not assessment_ts:
            assessment_ts = datetime.now(timezone.utc).isoformat()

        scan_ts = scan_results[0].get("timestamp", "") if scan_results else ""
        assessment = DomainAssessment(
            domain=domain,
            scan_timestamp=scan_ts,
            assessment_timestamp=assessment_ts,
            guidelines_used=list(self.guidelines.keys()),
            service_type=service_type,
        )

        if not scan_results:
            assessment.errors.append("No scan data available")
            assessment.score = 0
            assessment.level = LEVEL_NA
            return assessment

        findings = []
        scores = []

        for svc in scan_results:
            if not svc.get("success") and svc.get("source") != "shodan":
                if svc.get("error"):
                    assessment.errors.append(
                        f"Port {svc.get('port','?')}: {svc['error']}"
                    )
                continue

            assessment.services_assessed += 1

            tls_ver = svc.get("tls_version", "")
            if tls_ver and tls_ver not in assessment.tls_versions_found:
                assessment.tls_versions_found.append(tls_ver)
            tls_score, tls_findings = self._assess_tls_version(tls_ver)
            scores.append(tls_score)
            findings.extend(tls_findings)

            cipher = svc.get("cipher_suite", "")
            cipher = _OPENSSL_TO_IANA.get(cipher, cipher)  # normalise to IANA
            if cipher and cipher not in assessment.cipher_suites_found:
                assessment.cipher_suites_found.append(cipher)
            cipher_score, cipher_findings = self._assess_cipher(cipher)
            scores.append(cipher_score)
            findings.extend(cipher_findings)

            cert = svc.get("certificate") or {}
            if cert:
                key_type = cert.get("key_type", "")
                if key_type and key_type not in assessment.key_types_found:
                    assessment.key_types_found.append(key_type)
                cert_score, cert_findings = self._assess_certificate(cert)
                scores.append(cert_score)
                findings.extend(cert_findings)
                if cert.get("days_to_expiry") is not None:
                    assessment.certificate_expiry_days = cert["days_to_expiry"]

            if svc.get("has_pqc_kem") or svc.get("has_pqc_sig") or svc.get("has_pqc"):
                assessment.has_pqc = True

        # ── Chain analysis score adjustment ───────────────────────
        if chain_analysis:
            chain_score, chain_penalty_findings = self._assess_chain(chain_analysis)
            scores.append(chain_score)
            findings.extend(chain_penalty_findings)

        # ── Cipher enumeration score adjustment ───────────────────
        if cipher_enum:
            enum_score, enum_penalty_findings = self._assess_cipher_enum(cipher_enum)
            scores.append(enum_score)
            findings.extend(enum_penalty_findings)

            # Merge the FULL enumerated cipher set (IANA names) so the
            # assessment record reflects everything the server accepts,
            # not just the single passively-negotiated suite per service.
            for c in cipher_enum.get("supported_ciphers", []) or []:
                if not isinstance(c, dict):
                    continue
                name = c.get("iana_name") or c.get("openssl_name")
                if name and name not in assessment.cipher_suites_found:
                    assessment.cipher_suites_found.append(name)
                ver = c.get("tls_version")
                if ver and ver not in assessment.tls_versions_found:
                    assessment.tls_versions_found.append(ver)

        # ── CDN context ───────────────────────────────────────────
        if cdn_result and cdn_result.get("detected"):
            assessment.cdn_name     = cdn_result.get("cdn_name", "")
            assessment.cdn_slug     = cdn_result.get("cdn_slug", "")
            assessment.cdn_pqc_support = cdn_result.get("pqc_support", "unknown")

        # ── Inject pre-computed extra findings ────────────────────
        if extra_findings:
            for f in extra_findings:
                if isinstance(f, dict):
                    findings.append(Finding(
                        severity=f.get("severity", "info"),
                        category=f.get("category", ""),
                        message=f.get("message", ""),
                        guideline=f.get("guideline", "all"),
                        recommendation=f.get("recommendation", ""),
                        ciphers=f.get("ciphers", []) or [],
                    ))

        # PQC bonus / penalty
        if assessment.has_pqc:
            scores.append(95)
            findings.append(Finding(
                severity="info", category="pqc",
                message="PQC algorithm detected in TLS negotiation",
                guideline="all",
                recommendation="Verify PQC implementation follows NIST FIPS 203/204/205"
            ))
        else:
            scores.append(30)
            findings.append(Finding(
                severity="medium", category="pqc",
                message="No Post-Quantum Cryptography algorithms detected",
                guideline="all",
                recommendation="Plan migration to ML-KEM (FIPS 203) for key exchange "
                               "and ML-DSA (FIPS 204) for signatures"
            ))

        # Certificate expiry warning
        if assessment.certificate_expiry_days is not None:
            if assessment.certificate_expiry_days < 0:
                findings.append(Finding(
                    severity="critical", category="certificate",
                    message=f"Certificate EXPIRED {abs(assessment.certificate_expiry_days)} days ago",
                    guideline="all", recommendation="Renew certificate immediately"
                ))
                scores.append(0)
            elif assessment.certificate_expiry_days < 30:
                findings.append(Finding(
                    severity="high", category="certificate",
                    message=f"Certificate expires in {assessment.certificate_expiry_days} days",
                    guideline="all", recommendation="Renew certificate urgently"
                ))

        # Deduplicate
        seen: set[str] = set()
        deduped = []
        for f in findings:
            key = (f.message if isinstance(f, Finding) else f.get("message", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        assessment.findings = deduped
        assessment.score = int(sum(scores) / len(scores)) if scores else 0
        assessment.score = max(0, min(100, assessment.score))
        assessment.level = score_to_level(assessment.score)

        return assessment

    def _assess_tls_version(self, tls_version: str) -> tuple[int, list]:
        findings = []
        scores = []

        for gid, guideline in self.guidelines.items():
            tls_rules = guideline.get("tls_versions", {})
            rule = tls_rules.get(tls_version)
            if not rule:
                # Unknown / not listed → treat as acceptable
                scores.append(60)
                continue

            status = rule.get("status", "")
            score = rule.get("score", 50)
            scores.append(score)

            if status == "disallowed":
                findings.append(Finding(
                    severity="critical",
                    category="tls_version",
                    message=f"Disallowed TLS version in use: {tls_version}",
                    guideline=gid,
                    recommendation="Disable TLS 1.0/1.1 and SSLv2/SSLv3 immediately. "
                                   "Enable TLS 1.3 only."
                ))
            elif status == "deprecated":
                findings.append(Finding(
                    severity="high",
                    category="tls_version",
                    message=f"Deprecated TLS version: {tls_version}",
                    guideline=gid,
                    recommendation="Migrate to TLS 1.3. Disable TLS 1.1."
                ))

        return (int(sum(scores)/len(scores)) if scores else 50), findings

    def _assess_cipher(self, cipher: str) -> tuple[int, list]:
        if not cipher:
            return 50, []

        findings = []
        scores = []
        cipher_upper = cipher.upper()

        for gid, guideline in self.guidelines.items():
            cipher_rules = guideline.get("cipher_suites", {})

            if any(c.upper() == cipher_upper for c in cipher_rules.get("recommended", [])):
                scores.append(90)
            elif any(c.upper() == cipher_upper for c in cipher_rules.get("acceptable", [])):
                scores.append(65)
            elif any(c.upper() == cipher_upper for c in cipher_rules.get("deprecated", [])):
                scores.append(35)
                findings.append(Finding(
                    severity="medium",
                    category="cipher",
                    message=f"Deprecated cipher suite: {cipher}",
                    guideline=gid,
                    recommendation="Upgrade to AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)"
                ))
            elif any(c.upper() == cipher_upper for c in cipher_rules.get("disallowed", [])):
                scores.append(0)
                findings.append(Finding(
                    severity="critical",
                    category="cipher",
                    message=f"Disallowed cipher suite: {cipher}",
                    guideline=gid,
                    recommendation="Disable RC4, DES, 3DES, NULL ciphers immediately"
                ))
            else:
                # Check for known-weak patterns
                if any(w in cipher_upper for w in ["RC4","DES","NULL","EXPORT","ANON","MD5"]):
                    scores.append(0)
                    findings.append(Finding(
                        severity="critical",
                        category="cipher",
                        message=f"Cipher suite contains weak element: {cipher}",
                        guideline=gid,
                        recommendation="Remove all export-grade, null, anonymous, and RC4 ciphers"
                    ))
                else:
                    scores.append(60)

        return (int(sum(scores)/len(scores)) if scores else 50), findings

    def _assess_certificate(self, cert: dict) -> tuple[int, list]:
        findings = []
        scores = []

        key_type = cert.get("key_type", "").upper()
        key_size = cert.get("key_size_bits", 0)
        hash_alg = (cert.get("hash_algorithm", "") or "").upper()
        sig_alg = cert.get("signature_algorithm", "")

        for gid, guideline in self.guidelines.items():
            key_rules = guideline.get("key_sizes", {})
            hash_rules = guideline.get("hash_functions", {})

            # RSA key size check
            if key_type == "RSA" and key_size and "RSA" in key_rules:
                rsa_rule = key_rules["RSA"]
                min_ok = rsa_rule.get("minimum_acceptable", 2048)
                recommended = rsa_rule.get("recommended", 3072)
                disallowed_below = rsa_rule.get("disallowed_below", 1024)

                if key_size <= disallowed_below:
                    scores.append(0)
                    findings.append(Finding(
                        severity="critical", category="key_size",
                        message=f"RSA key too small: {key_size} bits (minimum {disallowed_below})",
                        guideline=gid,
                        recommendation=f"Replace with RSA {recommended}+ or ECDSA P-256/P-384"
                    ))
                elif key_size < min_ok:
                    scores.append(20)
                    findings.append(Finding(
                        severity="high", category="key_size",
                        message=f"RSA key below minimum: {key_size} bits",
                        guideline=gid,
                        recommendation=f"Use at minimum RSA-{min_ok}"
                    ))
                elif key_size < recommended:
                    scores.append(60)
                    findings.append(Finding(
                        severity="medium", category="key_size",
                        message=f"RSA key size {key_size} bits is below recommended {recommended}",
                        guideline=gid,
                        recommendation=f"Use RSA-{recommended} or transition to ECDSA/PQC"
                    ))
                else:
                    scores.append(80)

            # ECDSA key size check
            elif key_type == "ECDSA" and key_size and "ECDSA" in key_rules:
                ecdsa_rule = key_rules["ECDSA"]
                min_bits = ecdsa_rule.get("minimum_bits", 224)
                if key_size < min_bits:
                    scores.append(10)
                    findings.append(Finding(
                        severity="high", category="key_size",
                        message=f"ECDSA key too small: {key_size} bits",
                        guideline=gid,
                        recommendation="Use P-256 (256-bit) or larger ECDSA curves"
                    ))
                else:
                    scores.append(85)

            # Hash algorithm check
            if hash_alg:
                hash_rule = hash_rules.get(hash_alg) or hash_rules.get(
                    hash_alg.replace("-","").replace("SHA","SHA-"), {}
                )
                if hash_rule:
                    h_status = hash_rule.get("status", "")
                    h_score = hash_rule.get("score", 50)
                    scores.append(h_score)
                    if h_status == "disallowed":
                        findings.append(Finding(
                            severity="critical", category="hash",
                            message=f"Disallowed hash algorithm in certificate: {hash_alg}",
                            guideline=gid,
                            recommendation="Replace certificate signed with MD5/SHA-1 immediately"
                        ))
                    elif "deprecated" in h_status:
                        findings.append(Finding(
                            severity="high", category="hash",
                            message=f"Deprecated hash algorithm: {hash_alg}",
                            guideline=gid,
                            recommendation="Reissue certificate with SHA-256 or SHA-384 signature"
                        ))

            # SHA-1 in signature algorithm string
            if sig_alg and "sha1" in sig_alg.lower():
                scores.append(10)
                findings.append(Finding(
                    severity="critical", category="hash",
                    message=f"Certificate uses SHA-1 signature: {sig_alg}",
                    guideline=gid,
                    recommendation="Reissue certificate with SHA-256/SHA-384 signature algorithm"
                ))

        return (int(sum(scores)/len(scores)) if scores else 60), findings

    # ── Chain analysis scoring ─────────────────────────────────────

    def _assess_chain(self, chain: dict) -> tuple[int, list]:
        """
        Derive a score contribution from ChainAnalysis data.
        Penalises incomplete chains, weak intermediates, missing HSTS/CAA.
        """
        findings = []
        score = 80   # start optimistic — chain issues are incremental penalties

        if not chain.get("chain_complete"):
            score -= 20

        if chain.get("has_broken_intermediate"):
            score -= 30
            findings.append(Finding(
                severity="critical", category="chain",
                message="Intermediate CA in chain uses broken hash algorithm",
                guideline="nist_800_131a",
                recommendation="Switch to a CA whose intermediate uses SHA-256 or stronger."
            ))

        if chain.get("has_weak_intermediate"):
            score -= 15

        if chain.get("has_weak_root"):
            score -= 10

        weakest = chain.get("weakest_link_bits", 0)
        if 0 < weakest < 2048:
            score -= 20
        elif 0 < weakest < 3072:
            score -= 5

        if not chain.get("has_hsts"):
            score -= 5

        if not chain.get("has_caa_record"):
            score -= 3

        return max(0, score), findings

    # ── Cipher enumeration scoring ─────────────────────────────────

    def _assess_cipher_enum(self, enum: dict) -> tuple[int, list]:
        """
        Score based on the full set of accepted cipher suites.
        A server that accepts broken ciphers scores much lower than
        the passive-handshake result alone would show.
        """
        findings = []
        score = 80

        if enum.get("has_null_cipher"):
            score -= 50
        if enum.get("has_export_cipher"):
            score -= 40
        if enum.get("has_anon_cipher"):
            score -= 40
        if enum.get("has_rc4"):
            score -= 35
        if enum.get("has_3des"):
            score -= 20
        if enum.get("has_no_forward_secrecy") and not enum.get("tls13_supported"):
            score -= 15

        disallowed = enum.get("disallowed_count", 0)
        deprecated = enum.get("deprecated_count", 0)
        score -= min(disallowed * 8, 30)
        score -= min(deprecated * 3, 15)

        if not enum.get("tls13_supported"):
            score -= 10

        return max(0, score), findings
