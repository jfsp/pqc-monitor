#!/usr/bin/env python3
"""
PQC-Monitor: PQC Migration Roadmap Generator
Produces a prioritised, phased migration plan from assessment data.

Given a set of domain assessments this module:
  1. Classifies each finding into one of three migration phases anchored
     to real regulatory deadlines.
  2. Estimates implementation effort for each remediation action.
  3. Assigns a dependency ordering (you cannot deploy PQC key exchange
     before you have TLS 1.3, for example).
  4. Aggregates into a sector-level roadmap with a completion estimate.
  5. Emits structured RoadmapItem and DomainRoadmap dataclasses that the
     dashboard, CLI, and report generator consume.

Phase anchors
─────────────
Phase 1 – Immediate / Emergency   (now → 6 months)
  Fix anything that is already non-compliant with current standards:
  SSLv3/TLS 1.0/1.1, RC4, DES/3DES, NULL ciphers, MD5/SHA-1 certs,
  RSA < 2048, expired certificates.

Phase 2 – Classical Hardening     (6 → 18 months)
  Reach best-practice classical crypto posture required before PQC
  migration makes sense: TLS 1.3 only, ECDHE/AEAD-only ciphers,
  RSA ≥ 3072 or ECDSA P-256+, SHA-256+ hashes, HSTS, CAA.
  Deadline: BSI TR-02102-1 mandates RSA/DH ≥ 3000 bits for new
  deployments from 2026.

Phase 3 – PQC Transition           (18 → 48 months)
  Deploy hybrid or pure PQC key exchange and signatures.
  Deadline: NIST SP 800-131Ar3 anticipates full PQC transition
  to be required by 2030.

Effort scale
────────────
  LOW    1–5 person-days:  config change only (cipher list, TLS version)
  MEDIUM 5–20 person-days: certificate reissuance, library upgrade
  HIGH   20–60 person-days: application code changes, library replacement
  CRITICAL: also includes operational urgency (downtime risk, compliance)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── Phase definitions ─────────────────────────────────────────────────────────

PHASE_1 = "phase1_immediate"
PHASE_2 = "phase2_classical_hardening"
PHASE_3 = "phase3_pqc_transition"

PHASE_LABELS = {
    PHASE_1: "Phase 1 — Immediate Remediation",
    PHASE_2: "Phase 2 — Classical Hardening",
    PHASE_3: "Phase 3 — PQC Transition",
}

PHASE_DESCRIPTIONS = {
    PHASE_1: (
        "Fix current non-compliance. Anything here is already below the minimum "
        "acceptable bar of NIST SP 800-131Ar3, BSI TR-02102-1, and CCN-STIC-221. "
        "These items carry regulatory and operational risk today."
    ),
    PHASE_2: (
        "Reach best-practice classical posture. Required foundation before PQC "
        "migration can proceed. BSI TR-02102-1 mandates RSA/DH ≥ 3000 bits for "
        "new deployments from 2026."
    ),
    PHASE_3: (
        "Deploy post-quantum cryptography. NIST FIPS 203 (ML-KEM), FIPS 204 "
        "(ML-DSA), and FIPS 205 (SLH-DSA) are the target algorithms. "
        "Full transition expected to be required by 2030."
    ),
}

# Regulatory deadline anchors (used for date estimation)
_NOW = datetime.now(timezone.utc).date()
PHASE_1_DEADLINE = _NOW + timedelta(days=180)         # 6 months
PHASE_2_DEADLINE = date(2026, 12, 31)                  # BSI 2026 mandate
PHASE_3_DEADLINE = date(2030, 1, 1)                    # NIST 2030 horizon


# ── Effort constants ──────────────────────────────────────────────────────────

EFFORT_LOW      = "low"       # config-only, 1–5 days
EFFORT_MEDIUM   = "medium"    # cert/library, 5–20 days
EFFORT_HIGH     = "high"      # code + testing, 20–60 days

EFFORT_DAYS = {
    EFFORT_LOW:    (1, 5),
    EFFORT_MEDIUM: (5, 20),
    EFFORT_HIGH:   (20, 60),
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class RoadmapItem:
    """One discrete migration action for a single domain."""
    domain: str
    phase: str                   # PHASE_1 / PHASE_2 / PHASE_3
    phase_label: str
    category: str                # tls_version / cipher / key_size / hash / pqc / chain / infrastructure
    action: str                  # Short imperative description
    detail: str                  # Longer technical explanation
    effort: str                  # low / medium / high
    effort_days_min: int
    effort_days_max: int
    priority: int                # 1 (highest) – 10 (lowest)
    depends_on: list             # action categories that must complete first
    target_date: str             # ISO date string (estimated)
    guideline_refs: list         # e.g. ["NIST SP 800-131Ar3", "BSI TR-02102-1"]
    current_state: str           # what was found
    target_state: str            # what it should be after

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DomainRoadmap:
    """Complete migration roadmap for one domain."""
    domain: str
    current_score: int
    current_level: str
    generated_at: str
    items: list = field(default_factory=list)       # list of RoadmapItem dicts
    phase1_items: int = 0
    phase2_items: int = 0
    phase3_items: int = 0
    total_effort_days_min: int = 0
    total_effort_days_max: int = 0
    estimated_completion: str = ""
    has_pqc: bool = False
    cdn_note: str = ""
    score_after_phase1: int = 0
    score_after_phase2: int = 0
    score_after_phase3: int = 100

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SectorRoadmap:
    """Aggregated roadmap across all domains in a sector."""
    generated_at: str
    sector: str
    region: str
    domain_count: int
    avg_current_score: float
    domains: list = field(default_factory=list)     # list of DomainRoadmap dicts (summary)
    phase1_domain_count: int = 0
    phase2_domain_count: int = 0
    phase3_domain_count: int = 0
    total_effort_days_min: int = 0
    total_effort_days_max: int = 0
    critical_domains: list = field(default_factory=list)
    pqc_ready_domains: list = field(default_factory=list)
    estimated_sector_completion: str = ""
    action_summary: dict = field(default_factory=dict)  # action → count

    def to_dict(self) -> dict:
        return asdict(self)


# ── Roadmap item factories ────────────────────────────────────────────────────

def _item(domain, phase, category, action, detail, effort,
          priority, depends_on, target_date, guideline_refs,
          current_state, target_state) -> RoadmapItem:
    emin, emax = EFFORT_DAYS[effort]
    return RoadmapItem(
        domain=domain,
        phase=phase,
        phase_label=PHASE_LABELS[phase],
        category=category,
        action=action,
        detail=detail,
        effort=effort,
        effort_days_min=emin,
        effort_days_max=emax,
        priority=priority,
        depends_on=depends_on,
        target_date=str(target_date),
        guideline_refs=guideline_refs,
        current_state=current_state,
        target_state=target_state,
    )


# ── Finding → RoadmapItem mapping ────────────────────────────────────────────

def _findings_to_items(domain: str, findings: list,
                        assessment: dict) -> list[RoadmapItem]:
    """
    Convert a list of assessment findings into ordered RoadmapItems.
    Each finding category maps to a concrete action with phase, effort,
    dependency chain, and date estimate.
    """
    items: list[RoadmapItem] = []
    seen_actions: set[str] = set()

    def _add(item: RoadmapItem):
        key = (item.domain, item.action)
        if key not in seen_actions:
            seen_actions.add(key)
            items.append(item)

    tls_versions   = assessment.get("tls_versions") or []
    cipher_suites  = assessment.get("cipher_suites") or []
    key_types      = assessment.get("key_types") or []
    score          = assessment.get("score", 50)
    has_pqc        = bool(assessment.get("has_pqc"))
    cdn_name       = assessment.get("cdn_name", "")

    if isinstance(tls_versions, str):
        try: tls_versions = json.loads(tls_versions)
        except Exception: tls_versions = []
    if isinstance(cipher_suites, str):
        try: cipher_suites = json.loads(cipher_suites)
        except Exception: cipher_suites = []

    # Build index of finding categories for efficient lookup
    finding_cats: dict[str, list[dict]] = {}
    finding_sevs: dict[str, str] = {}  # category → worst severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = f.get("category", "")
        sev = f.get("severity", "info")
        finding_cats.setdefault(cat, []).append(f)
        if cat not in finding_sevs or sev_order.get(sev, 4) < sev_order.get(finding_sevs[cat], 4):
            finding_sevs[cat] = sev

    # ── Phase 1: Immediate ──────────────────────────────────────────

    # Disallowed TLS versions
    disallowed_tls = [v for v in tls_versions
                      if v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]
    if disallowed_tls or finding_sevs.get("tls_version") == "critical":
        _add(_item(
            domain, PHASE_1, "tls_version",
            action="Disable deprecated TLS protocols",
            detail=(
                f"Remove support for {', '.join(disallowed_tls) or 'TLS 1.0/1.1/SSLv3'} "
                "from all TLS listeners. Configure minimum protocol version to TLS 1.2, "
                "ideally TLS 1.3 only. This is a server configuration change in your "
                "web server, load balancer, or application server."
            ),
            effort=EFFORT_LOW,
            priority=1,
            depends_on=[],
            target_date=_NOW + timedelta(days=30),
            guideline_refs=["NIST SP 800-131Ar3", "BSI TR-02102-1", "CCN-STIC-221"],
            current_state=f"Protocols in use: {', '.join(disallowed_tls) or 'deprecated versions'}",
            target_state="TLS 1.3 (primary) + TLS 1.2 (transitional)",
        ))

    # Disallowed ciphers
    broken_ciphers = [c for c in cipher_suites
                      if any(w in c.upper() for w in
                             ("RC4", "NULL", "EXPORT", "ANON", "DES_CBC", "3DES"))]
    if broken_ciphers or finding_sevs.get("cipher") == "critical" \
            or finding_sevs.get("cipher_enum") == "critical":
        _add(_item(
            domain, PHASE_1, "cipher",
            action="Remove broken cipher suites",
            detail=(
                f"Disable: {', '.join(broken_ciphers[:4]) or 'RC4, NULL, EXPORT, 3DES ciphers'}. "
                "These are cryptographically broken and expose sessions to passive decryption "
                "or active attack. Configure server to offer only AEAD suites "
                "(AES-GCM, ChaCha20-Poly1305)."
            ),
            effort=EFFORT_LOW,
            priority=1,
            depends_on=[],
            target_date=_NOW + timedelta(days=14),
            guideline_refs=["NIST SP 800-131Ar3", "BSI TR-02102-1"],
            current_state=f"Broken ciphers accepted: {', '.join(broken_ciphers[:3]) or 'present'}",
            target_state="AEAD-only cipher suites (AES-256-GCM, ChaCha20-Poly1305)",
        ))

    # SHA-1 / MD5 signed certificate
    if finding_sevs.get("hash") == "critical":
        _add(_item(
            domain, PHASE_1, "certificate",
            action="Replace SHA-1 or MD5 signed certificate",
            detail=(
                "The current certificate uses a broken hash algorithm in its signature. "
                "Request a new certificate from your CA with SHA-256 (minimum) or "
                "SHA-384 signature algorithm. Most CAs no longer issue SHA-1 certs; "
                "if yours does, change CA."
            ),
            effort=EFFORT_LOW,
            priority=2,
            depends_on=[],
            target_date=_NOW + timedelta(days=7),
            guideline_refs=["NIST SP 800-131Ar3", "BSI TR-02102-1", "CCN-STIC-221"],
            current_state="Certificate signed with SHA-1 or MD5",
            target_state="Certificate signed with SHA-256 or SHA-384",
        ))

    # Expired certificate
    expiry = assessment.get("cert_expiry_days") or assessment.get("certificate_expiry_days")
    if expiry is not None and expiry < 0:
        _add(_item(
            domain, PHASE_1, "certificate",
            action="Renew expired certificate immediately",
            detail=(
                f"Certificate expired {abs(expiry)} days ago. "
                "Browsers reject expired certificates, causing complete service outage. "
                "Renew immediately. Consider automating renewal with ACME/Let's Encrypt."
            ),
            effort=EFFORT_LOW,
            priority=1,
            depends_on=[],
            target_date=_NOW,
            guideline_refs=["all"],
            current_state=f"Certificate expired {abs(expiry)} days ago",
            target_state="Valid certificate with ≥ 30 days to expiry",
        ))

    # Small RSA key (< 2048)
    if finding_sevs.get("key_size") == "critical":
        _add(_item(
            domain, PHASE_1, "key_size",
            action="Replace under-strength RSA key (< 2048 bits)",
            detail=(
                "Key size below the absolute minimum. Generate a new 3072-bit RSA key "
                "(or better: ECDSA P-256) and reissue the certificate. RSA < 2048 is "
                "disallowed by NIST and BSI. Requires coordination with your CA."
            ),
            effort=EFFORT_LOW,
            priority=2,
            depends_on=[],
            target_date=_NOW + timedelta(days=14),
            guideline_refs=["NIST SP 800-131Ar3", "BSI TR-02102-1"],
            current_state="RSA key < 2048 bits",
            target_state="RSA ≥ 3072 bits or ECDSA P-256/P-384",
        ))

    # Broken intermediate CA in chain
    if finding_sevs.get("chain") == "critical":
        _add(_item(
            domain, PHASE_1, "chain",
            action="Fix certificate chain (broken intermediate)",
            detail=(
                "An intermediate or root CA in the served chain uses a broken hash "
                "or has expired. Update the intermediate certificate bundle on the "
                "server to the CA's current chain. Check CA's website for updated "
                "intermediate certificate."
            ),
            effort=EFFORT_LOW,
            priority=2,
            depends_on=["certificate"],
            target_date=_NOW + timedelta(days=14),
            guideline_refs=["NIST SP 800-131Ar3"],
            current_state="Broken or expired intermediate CA in chain",
            target_state="Complete chain with SHA-256+ intermediates",
        ))

    # ── Phase 2: Classical Hardening ───────────────────────────────

    # Upgrade to TLS 1.3
    if "TLSv1.3" not in tls_versions:
        _add(_item(
            domain, PHASE_2, "tls_version",
            action="Enable TLS 1.3",
            detail=(
                "TLS 1.3 provides mandatory forward secrecy, AEAD-only ciphers, "
                "and reduced handshake latency. Required before PQC hybrid key "
                "exchange can be deployed (X25519MLKEM768 is TLS 1.3 only). "
                "Enable in web server/load balancer configuration. "
                "OpenSSL 1.1.1+ and all major TLS libraries support TLS 1.3."
            ),
            effort=EFFORT_LOW,
            priority=3,
            depends_on=["cipher"],
            target_date=PHASE_2_DEADLINE - timedelta(days=180),
            guideline_refs=["NIST SP 800-131Ar3", "BSI TR-02102-1"],
            current_state="TLS 1.3 not enabled",
            target_state="TLS 1.3 as primary protocol",
        ))

    # Remove static RSA key exchange (non-PFS ciphers)
    non_pfs = [c for c in cipher_suites
               if c.startswith("TLS_RSA_") or c.startswith("RSA_")]
    if non_pfs or finding_sevs.get("cipher_enum") in ("high", "medium"):
        _add(_item(
            domain, PHASE_2, "cipher",
            action="Restrict cipher suites to ECDHE/DHE-only (enforce forward secrecy)",
            detail=(
                "Remove all static RSA key-exchange cipher suites. Configure server to "
                "require ephemeral key exchange (ECDHE preferred, DHE acceptable). "
                "Recommended TLS 1.2 cipher list: ECDHE-ECDSA-AES256-GCM-SHA384, "
                "ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305. "
                "This ensures all sessions have forward secrecy."
            ),
            effort=EFFORT_LOW,
            priority=4,
            depends_on=["tls_version"],
            target_date=PHASE_2_DEADLINE - timedelta(days=150),
            guideline_refs=["BSI TR-02102-1", "NIST SP 800-131Ar3"],
            current_state="Static RSA key exchange accepted",
            target_state="ECDHE-only ephemeral key exchange",
        ))

    # Upgrade RSA key to 3072+
    if finding_sevs.get("key_size") in ("high", "medium") and \
            "critical" not in finding_sevs.get("key_size", ""):
        _add(_item(
            domain, PHASE_2, "key_size",
            action="Upgrade RSA certificate key to ≥ 3072 bits",
            detail=(
                "RSA-2048 provides only 112-bit security strength. BSI TR-02102-1 "
                "mandates RSA ≥ 3000 bits for new deployments from 2026. "
                "Consider migrating to ECDSA P-256 (128-bit security, smaller cert, "
                "faster handshake) as an alternative. Requires certificate reissuance."
            ),
            effort=EFFORT_LOW,
            priority=5,
            depends_on=[],
            target_date=PHASE_2_DEADLINE - timedelta(days=120),
            guideline_refs=["BSI TR-02102-1", "NIST SP 800-131Ar3"],
            current_state="RSA-2048 (112-bit security)",
            target_state="RSA-3072 or ECDSA P-256/P-384",
        ))

    # Add HSTS
    chain_findings_raw = finding_cats.get("chain", [])
    hsts_missing = any("HSTS" in f.get("message", "") for f in chain_findings_raw)
    if hsts_missing:
        _add(_item(
            domain, PHASE_2, "infrastructure",
            action="Deploy HTTP Strict Transport Security (HSTS)",
            detail=(
                "Add Strict-Transport-Security header with max-age ≥ 15552000 "
                "(180 days), includeSubDomains, and preload. This prevents "
                "protocol downgrade attacks and ensures clients always use HTTPS. "
                "Server configuration change only — no certificate or code changes."
            ),
            effort=EFFORT_LOW,
            priority=5,
            depends_on=["tls_version"],
            target_date=PHASE_2_DEADLINE - timedelta(days=90),
            guideline_refs=["all"],
            current_state="HSTS header absent or insufficient",
            target_state="HSTS max-age=31536000; includeSubDomains; preload",
        ))

    # Add CAA records
    caa_missing = any("CAA" in f.get("message", "") for f in chain_findings_raw)
    if caa_missing:
        _add(_item(
            domain, PHASE_2, "infrastructure",
            action="Add DNS CAA records",
            detail=(
                "Add Certification Authority Authorization (CAA) DNS records to "
                "restrict which CAs may issue certificates for this domain. "
                "Example: '0 issue \"letsencrypt.org\"'. "
                "Reduces certificate mis-issuance risk. DNS change only."
            ),
            effort=EFFORT_LOW,
            priority=6,
            depends_on=[],
            target_date=PHASE_2_DEADLINE - timedelta(days=60),
            guideline_refs=["all"],
            current_state="No CAA DNS record",
            target_state="CAA record restricting issuance to approved CAs",
        ))

    # Incomplete chain fix
    incomplete_chain = any("Incomplete" in f.get("message", "")
                           for f in chain_findings_raw)
    if incomplete_chain:
        _add(_item(
            domain, PHASE_2, "chain",
            action="Configure complete certificate chain on server",
            detail=(
                "Server is not sending the full intermediate chain. Clients that "
                "do not have the intermediate cached will fail to validate. "
                "Download the intermediate certificate(s) from your CA and "
                "configure the server to send the full chain (leaf + intermediates, "
                "excluding the root which is in browser trust stores)."
            ),
            effort=EFFORT_LOW,
            priority=4,
            depends_on=["certificate"],
            target_date=PHASE_2_DEADLINE - timedelta(days=120),
            guideline_refs=["all"],
            current_state="Incomplete chain (intermediate missing)",
            target_state="Full leaf + intermediate chain served",
        ))

    # ── Phase 3: PQC Transition ─────────────────────────────────────

    # Upgrade TLS library for PQC
    _add(_item(
        domain, PHASE_3, "pqc",
        action="Upgrade TLS library / server software to PQC-capable version",
        detail=(
            "PQC hybrid key exchange (X25519MLKEM768, per IETF draft-kwiatkowski-"
            "tls-ecdhe-mlkem) requires OpenSSL 3.5+ (announced for 2025), "
            "BoringSSL (already supports), or liboqs integration. "
            "Audit the TLS library version used by your web server, load balancer, "
            "and application runtimes. Plan upgrade schedule."
        ),
        effort=EFFORT_MEDIUM,
        priority=7,
        depends_on=["tls_version", "cipher"],
        target_date=date(2027, 6, 30),
        guideline_refs=["NIST SP 800-131Ar3", "NIST FIPS 203"],
        current_state="TLS library without PQC support",
        target_state="OpenSSL 3.5+ or BoringSSL with ML-KEM support",
    ))

    # Enable hybrid PQC key exchange
    if not has_pqc:
        _add(_item(
            domain, PHASE_3, "pqc",
            action="Enable hybrid PQC key exchange (X25519MLKEM768)",
            detail=(
                "Configure TLS 1.3 to offer X25519MLKEM768 hybrid key exchange "
                "(classical X25519 + ML-KEM-768). This provides quantum resistance "
                "for key agreement without breaking classical clients. "
                "Browser support: Chromium since M124, Firefox in progress. "
                "Server: nginx 1.27+/OpenSSL 3.5, or Apache with mod_ssl + OpenSSL 3.5. "
                "CDN support: Cloudflare already enables this automatically."
            ),
            effort=EFFORT_MEDIUM,
            priority=8,
            depends_on=["tls_version", "cipher", "infrastructure"],
            target_date=date(2028, 6, 30),
            guideline_refs=["NIST FIPS 203 (ML-KEM)", "NIST SP 800-131Ar3"],
            current_state="Classical X25519 key exchange only",
            target_state="X25519MLKEM768 hybrid key exchange enabled",
        ))

    # Migrate to ML-DSA certificate (when CA support is available)
    _add(_item(
        domain, PHASE_3, "pqc",
        action="Plan migration to PQC certificate (ML-DSA signature)",
        detail=(
            "When CAs begin issuing ML-DSA (FIPS 204 / CRYSTALS-Dilithium) "
            "certificates — expected from major CAs 2027–2028 — migrate the leaf "
            "certificate. Hybrid certificates (classical + PQC signatures) will "
            "likely be available first. Track CA roadmaps for Let's Encrypt, "
            "DigiCert, Sectigo, and FNMT-RCM (for Spanish public administration). "
            "This requires code changes if the application pins certificate algorithms."
        ),
        effort=EFFORT_HIGH,
        priority=9,
        depends_on=["pqc"],
        target_date=date(2029, 1, 1),
        guideline_refs=["NIST FIPS 204 (ML-DSA)", "NIST SP 800-131Ar3"],
        current_state="Classical RSA/ECDSA certificate",
        target_state="ML-DSA or hybrid (classical + ML-DSA) certificate",
    ))

    # Application-level crypto audit
    _add(_item(
        domain, PHASE_3, "pqc",
        action="Audit application-level cryptography for PQC impact",
        detail=(
            "TLS migration handles transport security. Applications that also "
            "perform cryptographic operations (JWT signing, file encryption, "
            "database encryption, API signature verification, code signing, "
            "document signing) need separate PQC migration plans. "
            "Inventory all cryptographic operations, identify those with "
            "long-lived secrets or data, and prioritise 'harvest now, decrypt later' "
            "attack surfaces."
        ),
        effort=EFFORT_HIGH,
        priority=10,
        depends_on=["pqc"],
        target_date=date(2028, 12, 31),
        guideline_refs=["NIST SP 800-131Ar3", "NIST SP 800-232 (ipd)"],
        current_state="Application crypto not assessed",
        target_state="All application crypto inventoried and PQC migration planned",
    ))

    # CDN-specific note
    if cdn_name:
        _add(_item(
            domain, PHASE_3, "pqc",
            action=f"Coordinate PQC rollout with CDN provider ({cdn_name})",
            detail=(
                f"TLS is terminated at the {cdn_name} edge, not the origin server. "
                "PQC migration at the CDN layer is controlled by the CDN provider's "
                "roadmap and your CDN configuration. Separately assess the origin "
                "server TLS configuration (accessible only from CDN egress IPs). "
                "Ensure CDN-to-origin ('backend') TLS also uses strong crypto."
            ),
            effort=EFFORT_MEDIUM,
            priority=8,
            depends_on=[],
            target_date=date(2028, 6, 30),
            guideline_refs=["NIST SP 800-131Ar3"],
            current_state=f"TLS terminated by {cdn_name}; origin crypto opaque",
            target_state=f"{cdn_name} PQC enabled + origin TLS independently hardened",
        ))

    return items


# ── Score projections ─────────────────────────────────────────────────────────

def _project_scores(current_score: int, items: list[RoadmapItem]) -> tuple[int, int, int]:
    """
    Estimate score improvement after each phase.
    Heuristic: each resolved phase-1 critical finding is worth ~15 pts,
    phase-2 ~10 pts, phase-3 ~20 pts (PQC bonus).
    Capped at 100.
    """
    p1 = sum(1 for i in items if i.phase == PHASE_1)
    p2 = sum(1 for i in items if i.phase == PHASE_2)
    p3 = sum(1 for i in items if i.phase == PHASE_3)

    after_p1 = min(100, current_score + p1 * 14)
    after_p2 = min(100, after_p1 + p2 * 8)
    after_p3 = min(100, after_p2 + p3 * 10)
    return after_p1, after_p2, after_p3


# ── Public API ────────────────────────────────────────────────────────────────

def generate_domain_roadmap(assessment: dict) -> DomainRoadmap:
    """
    Generate a complete migration roadmap for one domain from its assessment dict.

    Parameters
    ----------
    assessment  : dict from Database.get_latest_assessments() or similar.
                  Must contain at minimum: domain, score, level, findings_json.

    Returns
    -------
    DomainRoadmap dataclass.
    """
    domain  = assessment.get("domain", "unknown")
    score   = assessment.get("score", 0)
    level   = assessment.get("level", "")
    has_pqc = bool(assessment.get("has_pqc"))
    cdn_name = assessment.get("cdn_name", "")

    # Domains with no TLS service have nothing to remediate — skip them.
    if level == "na":
        logger.debug(f"Skipping roadmap for {domain}: no TLS service (level=na)")
        return DomainRoadmap(
            domain=domain,
            current_score=0,
            current_level="na",
            generated_at=datetime.now(timezone.utc).isoformat(),
            items=[],
            phase1_items=0, phase2_items=0, phase3_items=0,
            total_effort_days_min=0, total_effort_days_max=0,
            estimated_completion="",
            has_pqc=False,
            score_after_phase1=0, score_after_phase2=0, score_after_phase3=0,
        )

    findings = assessment.get("findings_json") or assessment.get("findings") or []
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    items = _findings_to_items(domain, findings, assessment)
    items.sort(key=lambda i: (
        {PHASE_1: 0, PHASE_2: 1, PHASE_3: 2}.get(i.phase, 3),
        i.priority
    ))

    p1_count = sum(1 for i in items if i.phase == PHASE_1)
    p2_count = sum(1 for i in items if i.phase == PHASE_2)
    p3_count = sum(1 for i in items if i.phase == PHASE_3)

    total_min = sum(i.effort_days_min for i in items)
    total_max = sum(i.effort_days_max for i in items)

    # Estimated completion: latest target_date across all items
    dates = [i.target_date for i in items if i.target_date]
    estimated_completion = max(dates) if dates else str(PHASE_3_DEADLINE)

    s1, s2, s3 = _project_scores(score, items)

    cdn_note = ""
    if cdn_name:
        cdn_note = (
            f"⚠ TLS is terminated by {cdn_name}. "
            "Scan reflects CDN edge configuration, not origin server. "
            "Coordinate all TLS/PQC changes with CDN configuration."
        )

    roadmap = DomainRoadmap(
        domain=domain,
        current_score=score,
        current_level=level,
        generated_at=datetime.now(timezone.utc).isoformat(),
        items=[i.to_dict() for i in items],
        phase1_items=p1_count,
        phase2_items=p2_count,
        phase3_items=p3_count,
        total_effort_days_min=total_min,
        total_effort_days_max=total_max,
        estimated_completion=estimated_completion,
        has_pqc=has_pqc,
        cdn_note=cdn_note,
        score_after_phase1=s1,
        score_after_phase2=s2,
        score_after_phase3=s3,
    )
    logger.info(
        f"Roadmap for {domain}: {len(items)} items | "
        f"P1={p1_count} P2={p2_count} P3={p3_count} | "
        f"effort {total_min}–{total_max}d | "
        f"score {score}→{s1}→{s2}→{s3}"
    )
    return roadmap


def generate_sector_roadmap(assessments: list, sector: str = "",
                             region: str = "") -> SectorRoadmap:
    """
    Generate an aggregated migration roadmap for all domains in a sector.

    Parameters
    ----------
    assessments : list of assessment dicts
    sector      : sector label (e.g. "finance")
    region      : region label (e.g. "Spain")

    Returns
    -------
    SectorRoadmap dataclass.
    """
    if not assessments:
        return SectorRoadmap(
            generated_at=datetime.now(timezone.utc).isoformat(),
            sector=sector, region=region, domain_count=0,
            avg_current_score=0.0,
        )

    # Exclude no-TLS domains — they have nothing to remediate.
    scored = [a for a in assessments if a.get("level") != "na"]
    na_count = len(assessments) - len(scored)
    if na_count:
        logger.debug(f"Sector roadmap: skipping {na_count} domain(s) with no TLS service")
    if not scored:
        return SectorRoadmap(
            generated_at=datetime.now(timezone.utc).isoformat(),
            sector=sector, region=region, domain_count=0,
            avg_current_score=0.0,
        )

    domain_roadmaps = [generate_domain_roadmap(a) for a in scored]
    scores = [r.current_score for r in domain_roadmaps]

    # Aggregate counts and effort
    p1_domains = sum(1 for r in domain_roadmaps if r.phase1_items > 0)
    p2_domains = sum(1 for r in domain_roadmaps if r.phase2_items > 0)
    p3_domains = sum(1 for r in domain_roadmaps if r.phase3_items > 0)
    total_min  = sum(r.total_effort_days_min for r in domain_roadmaps)
    total_max  = sum(r.total_effort_days_max for r in domain_roadmaps)

    # Action frequency count
    action_counts: dict[str, int] = {}
    for r in domain_roadmaps:
        for item in r.items:
            act = item.get("action", "") if isinstance(item, dict) else item.action
            action_counts[act] = action_counts.get(act, 0) + 1

    critical_domains = [
        r.domain for r in domain_roadmaps if r.current_level == "critical"
    ]
    pqc_ready = [r.domain for r in domain_roadmaps if r.has_pqc]

    # Sector estimated completion = latest across all domains
    all_dates = [r.estimated_completion for r in domain_roadmaps if r.estimated_completion]
    sector_completion = max(all_dates) if all_dates else str(PHASE_3_DEADLINE)

    # Build domain summaries (subset of fields to keep response lean)
    domain_summaries = [{
        "domain":              r.domain,
        "current_score":       r.current_score,
        "current_level":       r.current_level,
        "phase1_items":        r.phase1_items,
        "phase2_items":        r.phase2_items,
        "phase3_items":        r.phase3_items,
        "effort_days_min":     r.total_effort_days_min,
        "effort_days_max":     r.total_effort_days_max,
        "estimated_completion": r.estimated_completion,
        "score_after_phase1":  r.score_after_phase1,
        "score_after_phase2":  r.score_after_phase2,
        "score_after_phase3":  r.score_after_phase3,
        "has_pqc":             r.has_pqc,
        "cdn_note":            r.cdn_note,
    } for r in domain_roadmaps]

    sector_roadmap = SectorRoadmap(
        generated_at=datetime.now(timezone.utc).isoformat(),
        sector=sector,
        region=region,
        domain_count=len(scored),
        avg_current_score=round(sum(scores) / len(scores), 1),
        domains=domain_summaries,
        phase1_domain_count=p1_domains,
        phase2_domain_count=p2_domains,
        phase3_domain_count=p3_domains,
        total_effort_days_min=total_min,
        total_effort_days_max=total_max,
        critical_domains=critical_domains,
        pqc_ready_domains=pqc_ready,
        estimated_sector_completion=sector_completion,
        action_summary=dict(sorted(action_counts.items(),
                                    key=lambda x: -x[1])),
    )

    logger.info(
        f"Sector roadmap: {len(scored)} domains ({na_count} skipped, no TLS) | "
        f"avg_score={sector_roadmap.avg_current_score} | "
        f"effort {total_min}–{total_max}d"
    )
    return sector_roadmap


# ── Text rendering ────────────────────────────────────────────────────────────

def render_roadmap_text(roadmap: DomainRoadmap) -> str:
    """Render a DomainRoadmap as a plain-text report section."""
    lines = []
    sep = "─" * 72

    lines += [
        sep,
        f"  MIGRATION ROADMAP: {roadmap.domain}",
        sep,
        f"  Current PQC Score : {roadmap.current_score}/100 ({roadmap.current_level.upper()})",
        f"  Projected Scores  : Phase 1 → {roadmap.score_after_phase1}  "
        f"Phase 2 → {roadmap.score_after_phase2}  "
        f"Phase 3 → {roadmap.score_after_phase3}",
        f"  Total Effort      : {roadmap.total_effort_days_min}–{roadmap.total_effort_days_max} person-days",
        f"  Est. Completion   : {roadmap.estimated_completion}",
    ]

    if roadmap.cdn_note:
        lines.append(f"  {roadmap.cdn_note}")

    lines.append("")

    current_phase = None
    for item in roadmap.items:
        if isinstance(item, dict):
            phase     = item.get("phase", "")
            phase_lbl = item.get("phase_label", phase)
            action    = item.get("action", "")
            detail    = item.get("detail", "")
            effort    = item.get("effort", "")
            emin      = item.get("effort_days_min", 0)
            emax      = item.get("effort_days_max", 0)
            target    = item.get("target_date", "")
            current   = item.get("current_state", "")
            target_s  = item.get("target_state", "")
            refs      = item.get("guideline_refs", [])
        else:
            phase, phase_lbl = item.phase, item.phase_label
            action, detail   = item.action, item.detail
            effort, emin, emax = item.effort, item.effort_days_min, item.effort_days_max
            target, current  = item.target_date, item.current_state
            target_s, refs   = item.target_state, item.guideline_refs

        if phase != current_phase:
            current_phase = phase
            phase_desc = PHASE_DESCRIPTIONS.get(phase, "")
            lines += [
                "",
                f"  {'─'*68}",
                f"  {phase_lbl.upper()}",
                f"  {phase_desc}",
                f"  {'─'*68}",
                "",
            ]

        lines += [
            f"  ▶  {action}",
            f"     Target: {target}  |  Effort: {effort.upper()} ({emin}–{emax} days)  |  Refs: {', '.join(refs)}",
            f"     Now:    {current}",
            f"     After:  {target_s}",
            "",
        ]
        if detail:
            # Wrap detail at 68 chars
            words = detail.split()
            line_buf = "     "
            for word in words:
                if len(line_buf) + len(word) + 1 > 72:
                    lines.append(line_buf)
                    line_buf = "     " + word
                else:
                    line_buf += (" " if line_buf != "     " else "") + word
            if line_buf.strip():
                lines.append(line_buf)
            lines.append("")

    lines.append(sep)
    return "\n".join(lines) + "\n"


def render_sector_roadmap_text(roadmap: SectorRoadmap) -> str:
    """Render a SectorRoadmap as a plain-text executive summary."""
    lines = []
    sep = "═" * 72

    lines += [
        sep,
        "  PQC MIGRATION ROADMAP — SECTOR SUMMARY",
        sep,
        f"  Sector    : {roadmap.sector or 'N/A'}",
        f"  Region    : {roadmap.region or 'N/A'}",
        f"  Generated : {roadmap.generated_at[:19]}",
        "",
        f"  Domains Assessed         : {roadmap.domain_count}",
        f"  Average PQC Score        : {roadmap.avg_current_score:.1f}/100",
        f"  Domains Needing Phase 1  : {roadmap.phase1_domain_count} (immediate action required)",
        f"  Domains Needing Phase 2  : {roadmap.phase2_domain_count} (classical hardening)",
        f"  Domains Needing Phase 3  : {roadmap.phase3_domain_count} (PQC transition)",
        f"  Total Sector Effort      : {roadmap.total_effort_days_min}–{roadmap.total_effort_days_max} person-days",
        f"  Estimated Completion     : {roadmap.estimated_sector_completion}",
        "",
    ]

    if roadmap.critical_domains:
        lines += [
            "  ⚠  CRITICAL DOMAINS (immediate action required):",
        ]
        for d in roadmap.critical_domains:
            lines.append(f"     • {d}")
        lines.append("")

    if roadmap.pqc_ready_domains:
        lines += ["  ✓  PQC-Ready domains:"]
        for d in roadmap.pqc_ready_domains:
            lines.append(f"     • {d}")
        lines.append("")

    lines += [
        "  TOP ACTIONS ACROSS SECTOR:",
    ]
    for action, count in list(roadmap.action_summary.items())[:8]:
        lines.append(f"     {count:>3}x  {action}")

    lines += [
        "",
        "  DOMAIN MIGRATION SNAPSHOT:",
        f"  {'Domain':<42} {'Score':>5}  {'P1':>3} {'P2':>3} {'P3':>3}  {'Effort':>12}",
        "  " + "─" * 70,
    ]
    for d in sorted(roadmap.domains, key=lambda x: x.get("current_score", 0)):
        dom   = d.get("domain", "")[:40]
        sc    = d.get("current_score", 0)
        p1    = d.get("phase1_items", 0)
        p2    = d.get("phase2_items", 0)
        p3    = d.get("phase3_items", 0)
        emin  = d.get("effort_days_min", 0)
        emax  = d.get("effort_days_max", 0)
        lines.append(f"  {dom:<42} {sc:>5}  {p1:>3} {p2:>3} {p3:>3}  {emin:>5}–{emax:<5}d")

    lines.append(sep)
    return "\n".join(lines) + "\n"
