#!/usr/bin/env python3
"""
PQC-Monitor: CDN Detector
Detects whether a domain is served through a CDN/TLS-terminating proxy,
which means the TLS scan reveals the CDN's crypto config rather than the
origin server's.  This is critical context for PQC readiness assessment.

Detection methods (all passive/non-intrusive):
  1. CNAME chain walking       — resolves CNAMEs to find CDN-owned hostnames
  2. HTTP response headers     — Server, Via, X-Cache, X-Served-By, CF-Ray …
  3. IP range / ASN lookup     — compares resolved IP against known CDN CIDR blocks
  4. TLS certificate SANs      — wildcard CDN certs (*.cloudflare.com etc.)
  5. Reverse DNS (PTR)         — e.g. *.cloudfront.net, *.fastly.net

Known CDN fingerprints are maintained as a structured registry so new
providers can be added without code changes.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ── CDN fingerprint registry ──────────────────────────────────────────────────

@dataclass
class CDNProfile:
    name: str                           # Display name
    slug: str                           # machine-readable key
    pqc_support: str                    # "yes" | "no" | "partial" | "unknown"
    pqc_note: str                       # human-readable PQC status note
    cname_patterns: list[str]           # regex patterns on CNAME targets
    header_patterns: dict[str, str]     # {header_name: regex_value}
    ptr_patterns: list[str]             # regex patterns on reverse-DNS PTR
    cert_san_patterns: list[str]        # regex patterns on leaf cert SANs
    asns: list[int]                     # known ASNs
    # CIDR blocks stored as strings; parsed on first use
    cidr_blocks: list[str] = field(default_factory=list)


# ── Known CDN/proxy registry ──────────────────────────────────────────────────

CDN_REGISTRY: list[CDNProfile] = [
    CDNProfile(
        name="Cloudflare",
        slug="cloudflare",
        pqc_support="yes",
        pqc_note="Cloudflare supports X25519Kyber768 (ML-KEM hybrid) on TLS 1.3 "
                 "since 2023. PQC is applied at the CDN edge; origin may differ.",
        cname_patterns=[r"\.cloudflare\.com$", r"\.cloudflare\.net$"],
        header_patterns={
            "cf-ray":    r".+",
            "server":    r"(?i)cloudflare",
        },
        ptr_patterns=[r"\.cloudflare\.net$", r"\.cloudflare\.com$"],
        cert_san_patterns=[r"\*\.cloudflare\.com$", r"cloudflare\.com$"],
        asns=[13335, 209242],
        cidr_blocks=[
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        ],
    ),
    CDNProfile(
        name="Fastly",
        slug="fastly",
        pqc_support="partial",
        pqc_note="Fastly has announced PQC roadmap but deployment is experimental. "
                 "Check Fastly TLS configuration documentation for current status.",
        cname_patterns=[r"\.fastly\.net$", r"\.fastlylb\.net$",
                         r"\.fastly\.com$", r"\.fastly\.org$"],
        header_patterns={
            "x-served-by": r"(?i)fastly",
            "x-cache":     r"(?i)fastly",
            "via":         r"(?i)fastly",
        },
        ptr_patterns=[r"\.fastly\.net$"],
        cert_san_patterns=[r"\*\.fastly\.net$", r"fastly\.net$"],
        asns=[54113, 394536],
        cidr_blocks=[
            "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
            "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
            "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18",
            "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20",
            "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22",
            "199.27.72.0/21", "199.232.0.0/16",
        ],
    ),
    CDNProfile(
        name="Amazon CloudFront",
        slug="cloudfront",
        pqc_support="partial",
        pqc_note="AWS CloudFront supports TLS_AES_128_GCM_SHA256 and "
                 "TLS_AES_256_GCM_SHA384 (TLS 1.3). PQC hybrid KEM not yet generally available.",
        cname_patterns=[r"\.cloudfront\.net$"],
        header_patterns={
            "x-amz-cf-id":  r".+",
            "x-amz-cf-pop": r".+",
            "via":          r"(?i)cloudfront",
        },
        ptr_patterns=[r"\.cloudfront\.net$"],
        cert_san_patterns=[r"\*\.cloudfront\.net$"],
        asns=[16509, 14618],
        cidr_blocks=[],  # AWS ranges are large and frequently updated
    ),
    CDNProfile(
        name="Akamai",
        slug="akamai",
        pqc_support="partial",
        pqc_note="Akamai has published PQC roadmap material. TLS 1.3 supported. "
                 "PQC hybrid deployment status varies by customer configuration.",
        cname_patterns=[r"\.akamai\.net$", r"\.akamaized\.net$",
                         r"\.akamaiedge\.net$", r"\.edgesuite\.net$",
                         r"\.edgekey\.net$", r"\.akamaihd\.net$"],
        header_patterns={
            "x-check-cacheable": r".+",
            "x-akamai-transformed": r".+",
            "server": r"(?i)akamai",
        },
        ptr_patterns=[r"\.akamai\.net$", r"\.akamaiedge\.net$"],
        cert_san_patterns=[r"\.akamai\.net$", r"\.akamaized\.net$"],
        asns=[16625, 20940, 12222, 17334],
        cidr_blocks=[],
    ),
    CDNProfile(
        name="AWS Elastic Load Balancer",
        slug="aws-elb",
        pqc_support="no",
        pqc_note="AWS ALB/NLB does not yet support PQC cipher suites in production. "
                 "TLS configuration is set per-listener; origin server crypto is not visible.",
        cname_patterns=[
            r"\.elb\.amazonaws\.com$",
            r"\.elb\.[a-z0-9-]+\.amazonaws\.com$",
            r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$",
        ],
        header_patterns={},
        ptr_patterns=[r"\.compute\.amazonaws\.com$", r"\.compute-1\.amazonaws\.com$"],
        cert_san_patterns=[r"\.elb\.amazonaws\.com$"],
        asns=[16509, 14618],
        cidr_blocks=[],
    ),
    CDNProfile(
        name="Azure Front Door / CDN",
        slug="azure-fd",
        pqc_support="no",
        pqc_note="Azure Front Door supports TLS 1.3. PQC hybrid cipher suites "
                 "are on the Azure roadmap but not yet deployed in production.",
        cname_patterns=[
            r"\.azurefd\.net$", r"\.azureedge\.net$",
            r"\.trafficmanager\.net$", r"\.cloudapp\.net$",
        ],
        header_patterns={
            "x-ms-request-id": r".+",
            "x-cache":         r"(?i)tcp|miss",
            "x-azure-ref":     r".+",
        },
        ptr_patterns=[r"\.cloudapp\.net$", r"\.azure\.com$"],
        cert_san_patterns=[r"\.azurefd\.net$", r"\.azureedge\.net$"],
        asns=[8075, 8068, 8069],
        cidr_blocks=[],
    ),
    CDNProfile(
        name="Google Cloud CDN / Load Balancer",
        slug="google-cloud-lb",
        pqc_support="partial",
        pqc_note="Google has deployed X25519Kyber768 hybrid TLS in Chrome and "
                 "some Google services since 2023. GCP Cloud CDN PQC status depends "
                 "on configuration.",
        cname_patterns=[
            r"\.googlehosted\.com$",
            r"\.googleapis\.com$",
            r"\.ghs\.google\.com$",
            r"\.ghs\.googlehosted\.com$",
        ],
        header_patterns={
            "via":    r"(?i)google",
            "server": r"(?i)gws|google-frontend|scaffolding",
        },
        ptr_patterns=[r"\.1e100\.net$", r"\.googlebot\.com$"],
        cert_san_patterns=[r"\.googlehosted\.com$", r"\.google\.com$"],
        asns=[15169, 396982, 139070],
        cidr_blocks=[],
    ),
    CDNProfile(
        name="Imperva / Incapsula",
        slug="imperva",
        pqc_support="unknown",
        pqc_note="Imperva Incapsula WAF/CDN TLS configuration is customer-dependent. "
                 "PQC support not yet publicly documented.",
        cname_patterns=[r"\.incapdns\.net$", r"\.imperva\.com$"],
        header_patterns={
            "x-iinfo": r".+",
            "x-cdn":   r"(?i)imperva|incapsula",
        },
        ptr_patterns=[r"\.incapsula\.com$"],
        cert_san_patterns=[r"\.incapdns\.net$"],
        asns=[19551],
        cidr_blocks=[],
    ),
    CDNProfile(
        name="Sucuri",
        slug="sucuri",
        pqc_support="unknown",
        pqc_note="Sucuri WAF/CDN PQC support not yet documented.",
        cname_patterns=[r"\.sucuri\.net$"],
        header_patterns={"x-sucuri-id": r".+"},
        ptr_patterns=[r"\.sucuri\.net$"],
        cert_san_patterns=[r"\.sucuri\.net$"],
        asns=[30148],
        cidr_blocks=[],
    ),
]

# Build a fast name→profile index
_CDN_BY_SLUG: dict[str, CDNProfile] = {c.slug: c for c in CDN_REGISTRY}


# ── Detection helpers ─────────────────────────────────────────────────────────

def _walk_cnames(domain: str, max_depth: int = 8) -> list[str]:
    """
    Follow the CNAME chain from *domain* and return all names encountered
    (including the input domain and the final A/AAAA target).
    """
    chain = [domain]
    current = domain
    for _ in range(max_depth):
        try:
            if HAS_DNSPYTHON:
                answers = dns.resolver.resolve(current, "CNAME")
                target = str(answers[0].target).rstrip(".")
            else:
                # Basic fallback via getaddrinfo (won't expose CNAMEs directly)
                break
            chain.append(target)
            current = target
        except Exception:
            break
    return chain


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _ptr_lookup(ip: str) -> Optional[str]:
    if HAS_DNSPYTHON:
        try:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            pass
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _fetch_http_headers(domain: str, port: int = 443,
                         timeout: int = 8) -> dict[str, str]:
    """HEAD request to collect HTTP response headers (lowercase keys)."""
    import http.client, ssl as _ssl
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        conn = http.client.HTTPSConnection(domain, port=port,
                                            timeout=timeout, context=ctx)
        conn.request("HEAD", "/", headers={
            "Host": domain,
            "User-Agent": "PQCMonitor/1.0 (non-intrusive security research)"
        })
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return headers
    except Exception as e:
        logger.debug(f"_fetch_http_headers {domain}:{port}: {e}")
        return {}


def _ip_in_cdn_cidr(ip: str, profile: CDNProfile) -> bool:
    """Return True if *ip* falls within any of the profile's CIDR blocks."""
    if not profile.cidr_blocks or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in profile.cidr_blocks:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


def _match_patterns(value: str, patterns: list[str]) -> bool:
    if not value:
        return False
    for pat in patterns:
        try:
            if re.search(pat, value, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False


# ── Detection core ─────────────────────────────────────────────────────────────

@dataclass
class CDNDetectionResult:
    domain: str
    resolved_ip: Optional[str]
    ptr_record: Optional[str]
    cname_chain: list[str]

    detected: bool
    cdn_name: Optional[str]
    cdn_slug: Optional[str]
    pqc_support: str          # yes / no / partial / unknown / n/a
    pqc_note: str

    confidence: str           # high / medium / low
    evidence: list[str]       # human-readable list of matched signals
    origin_hidden: bool       # True when CDN masks origin TLS config
    http_headers: dict        # relevant headers found

    def to_dict(self) -> dict:
        return asdict(self)


def detect_cdn(domain: str, port: int = 443,
               cert_sans: list[str] = None,
               timeout: int = 8) -> CDNDetectionResult:
    """
    Detect whether *domain* is served through a CDN or TLS-terminating proxy.

    Parameters
    ----------
    domain      Target hostname
    port        HTTPS port (default 443)
    cert_sans   SANs from the leaf certificate (from tls_probe), if available
    timeout     Per-request timeout in seconds

    Returns
    -------
    CDNDetectionResult with detection verdict and PQC context.
    """
    cert_sans = cert_sans or []
    evidence: list[str] = []

    # Gather signals
    resolved_ip  = _resolve_ip(domain)
    cname_chain  = _walk_cnames(domain)
    ptr_record   = _ptr_lookup(resolved_ip) if resolved_ip else None
    http_headers = _fetch_http_headers(domain, port, timeout)

    # Keep only security-relevant headers
    relevant_header_keys = {
        "server", "via", "x-cache", "x-served-by", "cf-ray",
        "x-amz-cf-id", "x-amz-cf-pop", "x-azure-ref", "x-iinfo",
        "x-sucuri-id", "x-check-cacheable", "x-akamai-transformed",
        "x-ms-request-id",
    }
    relevant_headers = {k: v for k, v in http_headers.items()
                        if k in relevant_header_keys}

    # Score each CDN profile
    best_profile: Optional[CDNProfile] = None
    best_score  = 0
    best_evidence: list[str] = []

    for profile in CDN_REGISTRY:
        score = 0
        ev: list[str] = []

        # CNAME match
        for cname in cname_chain[1:]:   # skip the queried domain itself
            if _match_patterns(cname, profile.cname_patterns):
                score += 40
                ev.append(f"CNAME → {cname} matches {profile.name}")
                break

        # HTTP headers
        for header, pattern in profile.header_patterns.items():
            val = http_headers.get(header, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                score += 30
                ev.append(f"Header {header}: {val[:60]}")
                break   # one header match per profile is enough

        # IP range
        if resolved_ip and _ip_in_cdn_cidr(resolved_ip, profile):
            score += 35
            ev.append(f"IP {resolved_ip} in {profile.name} CIDR block")

        # PTR record
        if ptr_record and _match_patterns(ptr_record, profile.ptr_patterns):
            score += 30
            ev.append(f"PTR {ptr_record} matches {profile.name}")

        # Certificate SANs
        for san in cert_sans:
            if _match_patterns(san, profile.cert_san_patterns):
                score += 25
                ev.append(f"Cert SAN {san} matches {profile.name}")
                break

        if score > best_score:
            best_score   = score
            best_profile = profile
            best_evidence = ev

    # Decision threshold
    detected = best_score >= 25
    if not detected:
        best_profile = None

    confidence = "high" if best_score >= 60 else "medium" if best_score >= 30 else "low"

    return CDNDetectionResult(
        domain=domain,
        resolved_ip=resolved_ip,
        ptr_record=ptr_record,
        cname_chain=cname_chain,
        detected=detected,
        cdn_name=best_profile.name if best_profile else None,
        cdn_slug=best_profile.slug if best_profile else None,
        pqc_support=best_profile.pqc_support if best_profile else "n/a",
        pqc_note=best_profile.pqc_note if best_profile else "",
        confidence=confidence if detected else "n/a",
        evidence=best_evidence,
        origin_hidden=detected,   # CDN always masks origin TLS
        http_headers=relevant_headers,
    )


def cdn_findings(result: CDNDetectionResult) -> list[dict]:
    """Convert CDNDetectionResult into Finding-compatible dicts."""
    findings = []
    if not result.detected:
        return findings

    findings.append({
        "severity": "info",
        "category": "cdn",
        "message": (
            f"CDN detected: {result.cdn_name} (confidence: {result.confidence}). "
            f"TLS scan reflects CDN edge crypto, not the origin server."
        ),
        "guideline": "all",
        "recommendation": (
            f"PQC support at edge: {result.pqc_support.upper()}. "
            f"{result.pqc_note} "
            "Separately assess the origin server's TLS configuration."
        ),
    })

    if result.pqc_support == "no":
        findings.append({
            "severity": "medium",
            "category": "cdn",
            "message": f"{result.cdn_name} CDN edge does not support PQC cipher suites",
            "guideline": "nist_800_131a",
            "recommendation": "Request PQC-capable TLS configuration from CDN provider, "
                               "or consider a CDN that supports ML-KEM hybrid key exchange.",
        })

    return findings
