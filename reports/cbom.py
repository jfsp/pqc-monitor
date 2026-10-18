#!/usr/bin/env python3
"""
PQC-Monitor: CBOM export (CycloneDX Cryptography Bill of Materials).

Builds a CycloneDX BOM with the cryptographic assets PQC-Monitor has observed on
ONE organisation's internet-facing services, so the organisation can load its
cryptographic inventory into its own tooling (CBOMkit, Dependency-Track,
cyclonedx-cli, CMDBs, ...). Follows the CBOM model that IBM/CBOM upstreamed into
CycloneDX 1.6 and the OWASP "Authoritative Guide to CBOM" (2nd ed., CycloneDX 1.7).

Spec versions: "1.6" (default — widest tool support) or "1.7" (adds certificate
serial number, fingerprint, lifecycle state and extensions; algorithm families
and elliptic curves from the CycloneDX cryptography registry).

Model
─────
metadata.component   platform "<org> — internet-facing services" (org/<id>);
                     supplier = the organisation; lifecycle phase "discovery"
services[]           one per domain; endpoints = URIs of ports that completed a
                     TLS handshake; PQC-Monitor score/level/... as pqc-monitor:*
                     properties. No-TLS and not-yet-assessed domains are listed
                     without endpoints (include_no_tls).
components[] (type cryptographic-asset)
  protocol           one per endpoint and TLS version: cipher suites (algorithm
                     refs + IANA code points) and offered key-exchange groups
  certificate        leaf certificate per endpoint, CA chain certificates when
                     the chain was analysed, valid CT-log certificates (include_ct)
  related-crypto-material   the public key of each certificate
  algorithm          deduplicated: suite primitives, TLS groups (ML-KEM hybrids
                     depend on their parts), signature, key and hash algorithms
evidence.occurrences every endpoint (or crt.sh entry) where an asset was seen
dependencies         org → services → protocols / leaf certificates →
                     algorithms, keys, issuing CA; hybrid group → parts
annotations          one per PQC-Monitor finding, attached to the domain's
                     service (include_findings)
compositions         aggregate "incomplete": only externally observable crypto

Data source: the newest assessment per domain, the raw probe results of the
newest run that actually probed the domain, and the newest enrichment blob per
type (chain / cipher_enum / group_enum / cdn / ssllabs / dns_status).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional

SPEC_VERSIONS = ("1.6", "1.7")
DEFAULT_SPEC = "1.6"
MEDIA_TYPE = "application/vnd.cyclonedx+json"
PROP = "pqc-monitor"
TOOL_NAME = "PQC-Monitor"
TOOL_URL = "https://github.com/jfsp/pqc-monitor"

EXTRA_TYPES = ("chain", "cipher_enum", "group_enum", "cdn", "ssllabs")
CT_CERTS_PER_DOMAIN = 20     # newest valid CT certificates per domain
MAX_SANS = 50                # SAN values copied into a certificate
MAX_CONTEXT = 6              # labels joined into one occurrence context


# ══════════════════════════════════════════════════════════════════════════════
# Small helpers
# ══════════════════════════════════════════════════════════════════════════════

def _dt(ts) -> Optional[datetime]:
    """Parse the timestamp formats found in the DB (isoformat with or without
    offset, 'Z', space separator, date only). Naive values are UTC."""
    if not ts:
        return None
    if isinstance(ts, datetime):
        dt = ts
    else:
        s = str(ts).strip().replace(" ", "T", 1)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(ts) -> Optional[str]:
    """RFC 3339 UTC timestamp (JSON-schema 'date-time'), or None."""
    dt = _dt(ts)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _slug(value: str) -> str:
    s = re.sub(r"[^a-z0-9.+_-]+", "-", str(value).lower()).strip("-")
    return s or "x"


def _hex(value) -> str:
    """Hex digits only, lower case ('0x3A:4F' → '3a4f')."""
    return re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()


def _serial(value) -> str:
    """Certificate serial as upper-case hex without 0x / separators."""
    s = str(value or "").strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return _hex(s).upper()


def _prop(name: str, value) -> Optional[dict]:
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (list, tuple, set)):
        value = ", ".join(str(v) for v in value)
    return {"name": f"{PROP}:{name}", "value": str(value)}


def _props(*pairs) -> list:
    out = []
    for name, value in pairs:
        p = _prop(name, value)
        if p:
            out.append(p)
    return out


def _norm_hash(h: str) -> str:
    """'SHA256' / 'sha-256' / 'SHA_256' → 'SHA-256'; MD5 stays MD5."""
    u = (h or "").upper().replace("_", "-").strip()
    m = re.fullmatch(r"SHA-?(1|224|256|384|512)", u)
    if m:
        return f"SHA-{m.group(1)}"
    m = re.fullmatch(r"SHA3-?(224|256|384|512)", u)
    if m:
        return f"SHA3-{m.group(1)}"
    if u in ("MD5", "MD-5"):
        return "MD5"
    return u


_DN_SHORT = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
    "2.5.4.97": "organizationIdentifier", "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
    "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}


def _readable_dn(dn: str) -> str:
    """chain_validator stores 'OID=value,OID=value' (unescaped). Rewrite to
    'C=US, O=Example, CN=host' with short names and RFC 4514 comma escaping."""
    if not dn:
        return ""
    parts = re.split(r",(?=\s*\d+(?:\.\d+)+=)", dn)
    out = []
    for part in parts:
        if "=" not in part:
            continue
        oid, value = part.split("=", 1)
        oid = oid.strip()
        value = value.replace("\\", "\\\\").replace(",", "\\,")
        out.append(f"{_DN_SHORT.get(oid, oid)}={value}")
    return ", ".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# Cryptographic registry (names follow the CycloneDX cryptography-defs patterns)
# ══════════════════════════════════════════════════════════════════════════════

# key → (1.6 'curve' text, 1.7 ellipticCurve enum, curve OID, classical bits)
_CURVES = {
    "P-224":      ("secp224r1", "nist/P-224", "1.3.132.0.33", 112),
    "P-256":      ("secp256r1", "nist/P-256", "1.2.840.10045.3.1.7", 128),
    "P-384":      ("secp384r1", "nist/P-384", "1.3.132.0.34", 192),
    "P-521":      ("secp521r1", "nist/P-521", "1.3.132.0.35", 256),
    "Curve25519": ("Curve25519", "other/Curve25519", "1.3.101.110", 128),
    "Curve448":   ("Curve448", "other/Curve448", "1.3.101.111", 224),
}
_EC_BITS_TO_CURVE = {224: "P-224", 256: "P-256", 384: "P-384", 521: "P-521"}
_SECG_TO_CURVE = {"secp224r1": "P-224", "secp256r1": "P-256", "prime256v1": "P-256",
                  "secp384r1": "P-384", "secp521r1": "P-521", "p-224": "P-224",
                  "p-256": "P-256", "p-384": "P-384", "p-521": "P-521"}

# Families valid in CycloneDX 1.7 cryptography-defs (only those we emit).
_FAMILIES_17 = {
    "3DES", "AES", "ARIA", "CAMELLIA", "ChaCha20", "DES", "DSA", "ECDH", "ECDSA",
    "EdDSA", "FFDH", "HKDF", "HMAC", "IDEA", "MD5", "ML-DSA", "ML-KEM", "RC4",
    "RSAES-PKCS1", "RSASSA-PKCS1", "RSASSA-PSS", "SEED", "SHA-1", "SHA-2",
    "SHA-3", "SLH-DSA",
}

_HASHES = {   # name → (family, digest bits, oid, classical collision bits, NIST cat)
    "MD5":      ("MD5",   "128", "1.2.840.113549.2.5",     18,  0),
    "SHA-1":    ("SHA-1", "160", "1.3.14.3.2.26",          63,  0),
    "SHA-224":  ("SHA-2", "224", "2.16.840.1.101.3.4.2.4", 112, 0),
    "SHA-256":  ("SHA-2", "256", "2.16.840.1.101.3.4.2.1", 128, 2),
    "SHA-384":  ("SHA-2", "384", "2.16.840.1.101.3.4.2.2", 192, 4),
    "SHA-512":  ("SHA-2", "512", "2.16.840.1.101.3.4.2.3", 256, 5),
    "SHA3-256": ("SHA-3", "256", "2.16.840.1.101.3.4.2.8", 128, 2),
    "SHA3-384": ("SHA-3", "384", "2.16.840.1.101.3.4.2.9", 192, 4),
    "SHA3-512": ("SHA-3", "512", "2.16.840.1.101.3.4.2.10", 256, 5),
}
_HMAC_OID = {"MD5": "1.3.6.1.5.5.8.1.1", "SHA-1": "1.2.840.113549.2.7",
             "SHA-224": "1.2.840.113549.2.8", "SHA-256": "1.2.840.113549.2.9",
             "SHA-384": "1.2.840.113549.2.10", "SHA-512": "1.2.840.113549.2.11"}
_HKDF_OID = {"SHA-256": "1.2.840.113549.1.9.16.3.29",
             "SHA-384": "1.2.840.113549.1.9.16.3.30",
             "SHA-512": "1.2.840.113549.1.9.16.3.31"}

_SYM_OID = {
    ("AES", 128, "gcm"): "2.16.840.1.101.3.4.1.6",
    ("AES", 192, "gcm"): "2.16.840.1.101.3.4.1.26",
    ("AES", 256, "gcm"): "2.16.840.1.101.3.4.1.46",
    ("AES", 128, "cbc"): "2.16.840.1.101.3.4.1.2",
    ("AES", 192, "cbc"): "2.16.840.1.101.3.4.1.22",
    ("AES", 256, "cbc"): "2.16.840.1.101.3.4.1.42",
    ("AES", 128, "ccm"): "2.16.840.1.101.3.4.1.7",
    ("AES", 192, "ccm"): "2.16.840.1.101.3.4.1.27",
    ("AES", 256, "ccm"): "2.16.840.1.101.3.4.1.47",
    ("CAMELLIA", 128, "cbc"): "1.2.392.200011.61.1.1.1.2",
    ("CAMELLIA", 192, "cbc"): "1.2.392.200011.61.1.1.1.3",
    ("CAMELLIA", 256, "cbc"): "1.2.392.200011.61.1.1.1.4",
    ("SEED", 128, "cbc"): "1.2.410.200004.1.4",
}

_NISTQ_BY_KEY = {128: 1, 192: 3, 256: 5}

# IANA TLS cipher-suite code points (cross-checked against OpenSSL and
# tlslite-ng; RFC 8446 for the TLS 1.3 CCM suites, RFC 4162 for SEED).
_SUITE_IDS = {
    "TLS_RSA_WITH_NULL_MD5": 0x0001, "TLS_RSA_WITH_NULL_SHA": 0x0002,
    "TLS_RSA_WITH_RC4_128_MD5": 0x0004, "TLS_RSA_WITH_RC4_128_SHA": 0x0005,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": 0x0016,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": 0x0032,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": 0x0033,
    "TLS_DH_ANON_WITH_AES_128_CBC_SHA": 0x0034,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": 0x0038,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": 0x0039,
    "TLS_DH_ANON_WITH_AES_256_CBC_SHA": 0x003A,
    "TLS_RSA_WITH_NULL_SHA256": 0x003B,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
    "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": 0x0040,
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA": 0x0041,
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA": 0x0044,
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA": 0x0045,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 0x0067,
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": 0x006A,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B,
    "TLS_DH_ANON_WITH_AES_128_CBC_SHA256": 0x006C,
    "TLS_DH_ANON_WITH_AES_256_CBC_SHA256": 0x006D,
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA": 0x0084,
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA": 0x0087,
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA": 0x0088,
    "TLS_RSA_WITH_SEED_CBC_SHA": 0x0096,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 0x009E,
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 0x009F,
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": 0x00A2,
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": 0x00A3,
    "TLS_DH_ANON_WITH_AES_128_GCM_SHA256": 0x00A6,
    "TLS_DH_ANON_WITH_AES_256_GCM_SHA384": 0x00A7,
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256": 0x00BA,
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256": 0x00BE,
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256": 0x00C0,
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256": 0x00C4,
    "TLS_AES_128_GCM_SHA256": 0x1301, "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303, "TLS_AES_128_CCM_SHA256": 0x1304,
    "TLS_AES_128_CCM_8_SHA256": 0x1305,
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA": 0xC006,
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": 0xC007,
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": 0xC008,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_RSA_WITH_NULL_SHA": 0xC010,
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA": 0xC011,
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": 0xC012,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA": 0xC018,
    "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA": 0xC019,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xC027,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xC028,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": 0xC072,
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": 0xC073,
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256": 0xC076,
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384": 0xC077,
    "TLS_RSA_WITH_AES_128_CCM": 0xC09C, "TLS_RSA_WITH_AES_256_CCM": 0xC09D,
    "TLS_DHE_RSA_WITH_AES_128_CCM": 0xC09E, "TLS_DHE_RSA_WITH_AES_256_CCM": 0xC09F,
    "TLS_RSA_WITH_AES_128_CCM_8": 0xC0A0, "TLS_RSA_WITH_AES_256_CCM_8": 0xC0A1,
    "TLS_DHE_RSA_WITH_AES_128_CCM_8": 0xC0A2, "TLS_DHE_RSA_WITH_AES_256_CCM_8": 0xC0A3,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": 0xC0AC,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": 0xC0AD,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8": 0xC0AE,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8": 0xC0AF,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA8,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA9,
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCAA,
}

# OpenSSL suite names (as negotiated by the ssl module) → IANA names, for the
# suites not covered by scanner.cipher_enum._OPENSSL_TO_IANA.
_OPENSSL_TO_IANA = {
    "NULL-MD5": "TLS_RSA_WITH_NULL_MD5", "NULL-SHA": "TLS_RSA_WITH_NULL_SHA",
    "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5", "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "DHE-DSS-AES128-SHA": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "DHE-RSA-AES128-SHA": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "DHE-DSS-AES256-SHA": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES256-SHA": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "NULL-SHA256": "TLS_RSA_WITH_NULL_SHA256",
    "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "DHE-DSS-AES128-SHA256": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "CAMELLIA128-SHA": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "DHE-RSA-CAMELLIA128-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "DHE-RSA-AES128-SHA256": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "DHE-DSS-AES256-SHA256": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "DHE-RSA-AES256-SHA256": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "CAMELLIA256-SHA": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "DHE-RSA-CAMELLIA256-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "SEED-SHA": "TLS_RSA_WITH_SEED_CBC_SHA",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-DSS-AES128-GCM-SHA256": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    "DHE-DSS-AES256-GCM-SHA384": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-ECDSA-AES256-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CAMELLIA128-SHA256": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-ECDSA-CAMELLIA256-SHA384": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-RSA-CAMELLIA128-SHA256": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-RSA-CAMELLIA256-SHA384": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-ECDSA-AES128-CCM": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "ECDHE-ECDSA-AES256-CCM": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "ECDHE-ECDSA-AES128-CCM8": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "ECDHE-ECDSA-AES256-CCM8": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

# TLS supported groups: name → (code point, kind, data)
_TLS_GROUPS = {
    "secp256r1": (0x0017, "ecdh", "P-256"),
    "secp384r1": (0x0018, "ecdh", "P-384"),
    "secp521r1": (0x0019, "ecdh", "P-521"),
    "x25519":    (0x001D, "x", "Curve25519"),
    "x448":      (0x001E, "x", "Curve448"),
    "ffdhe2048": (0x0100, "ffdhe", 2048),
    "ffdhe3072": (0x0101, "ffdhe", 3072),
    "ffdhe4096": (0x0102, "ffdhe", 4096),
    "ffdhe6144": (0x0103, "ffdhe", 6144),
    "ffdhe8192": (0x0104, "ffdhe", 8192),
    "MLKEM512":  (0x0200, "mlkem", 512),
    "MLKEM768":  (0x0201, "mlkem", 768),
    "MLKEM1024": (0x0202, "mlkem", 1024),
    "SecP256r1MLKEM768":  (0x11EB, "hybrid", ("ML-KEM-768", "secp256r1", 128, 3)),
    "X25519MLKEM768":     (0x11EC, "hybrid", ("ML-KEM-768", "x25519", 128, 3)),
    "SecP384r1MLKEM1024": (0x11ED, "hybrid", ("ML-KEM-1024", "secp384r1", 192, 5)),
    "X25519Kyber768Draft00": (0x6399, "draft", ("Kyber-768", "x25519", 128, 3)),
    "P256Kyber768Draft00":   (0x639A, "draft", ("Kyber-768", "secp256r1", 128, 3)),
}
_TLS_GROUPS_LC = {k.lower(): k for k in _TLS_GROUPS}

# Certificate signature algorithms: OID → (name stem, kind, hash)
_SIG_OIDS = {
    "1.2.840.113549.1.1.4":  ("RSA-PKCS1-1.5", "rsa", "MD5"),
    "1.2.840.113549.1.1.5":  ("RSA-PKCS1-1.5", "rsa", "SHA-1"),
    "1.2.840.113549.1.1.14": ("RSA-PKCS1-1.5", "rsa", "SHA-224"),
    "1.2.840.113549.1.1.11": ("RSA-PKCS1-1.5", "rsa", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA-PKCS1-1.5", "rsa", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA-PKCS1-1.5", "rsa", "SHA-512"),
    "1.2.840.113549.1.1.10": ("RSA-PSS", "pss", ""),
    "1.2.840.10045.4.1":     ("ECDSA", "ecdsa", "SHA-1"),
    "1.2.840.10045.4.3.1":   ("ECDSA", "ecdsa", "SHA-224"),
    "1.2.840.10045.4.3.2":   ("ECDSA", "ecdsa", "SHA-256"),
    "1.2.840.10045.4.3.3":   ("ECDSA", "ecdsa", "SHA-384"),
    "1.2.840.10045.4.3.4":   ("ECDSA", "ecdsa", "SHA-512"),
    "1.2.840.10040.4.3":     ("DSA", "dsa", "SHA-1"),
    "2.16.840.1.101.3.4.3.2": ("DSA", "dsa", "SHA-256"),
    "1.3.101.112":           ("Ed25519", "eddsa", ""),
    "1.3.101.113":           ("Ed448", "eddsa", ""),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "mldsa", ""),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "mldsa", ""),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "mldsa", ""),
}
for _i, _p in enumerate(("SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f",
                         "SHA2-256s", "SHA2-256f", "SHAKE-128s", "SHAKE-128f",
                         "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f")):
    _SIG_OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = (f"SLH-DSA-{_p}", "slhdsa", "")

_SIG_NAMES = {   # names written by tls_probe / chain_validator / ct_monitor
    "md5withrsaencryption": "1.2.840.113549.1.1.4",
    "sha1withrsaencryption": "1.2.840.113549.1.1.5",
    "sha224withrsaencryption": "1.2.840.113549.1.1.14",
    "sha256withrsaencryption": "1.2.840.113549.1.1.11",
    "sha384withrsaencryption": "1.2.840.113549.1.1.12",
    "sha512withrsaencryption": "1.2.840.113549.1.1.13",
    "rsassa-pss": "1.2.840.113549.1.1.10", "rsassapss": "1.2.840.113549.1.1.10",
    "ecdsa-with-sha1": "1.2.840.10045.4.1",
    "ecdsa-with-sha224": "1.2.840.10045.4.3.1",
    "ecdsa-with-sha256": "1.2.840.10045.4.3.2",
    "ecdsa-with-sha384": "1.2.840.10045.4.3.3",
    "ecdsa-with-sha512": "1.2.840.10045.4.3.4",
    "ed25519": "1.3.101.112", "ed448": "1.3.101.113",
    "ml-dsa-44": "2.16.840.1.101.3.4.3.17", "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
    "ml-dsa-87": "2.16.840.1.101.3.4.3.19",
}

_ML_LEVELS = {512: (128, 1), 768: (192, 3), 1024: (256, 5)}
_MLDSA_LEVELS = {"44": (128, 2), "65": (192, 3), "87": (256, 5)}


def _spec(name, primitive, *, family=None, mode=None, padding=None, param=None,
          curve=None, functions=None, classical=None, nistq=None, oid=None,
          deps=(), props=()) -> dict:
    """Algorithm specification (rendered into a component by _Builder)."""
    return {"name": name, "primitive": primitive, "family": family, "mode": mode,
            "padding": padding, "param": param, "curve": curve,
            "functions": list(functions or []), "classical": classical,
            "nistq": nistq, "oid": oid, "deps": list(deps), "props": list(props)}


def _rsa_strength(bits: int) -> int:
    """NIST SP 800-57 Pt 1 r5 Table 2 (floor) for RSA / finite-field DH."""
    if bits >= 15360:
        return 256
    if bits >= 7680:
        return 192
    if bits >= 3072:
        return 128
    if bits >= 2048:
        return 112
    if bits >= 1024:
        return 80
    return 0


def hash_spec(h: str) -> Optional[dict]:
    h = _norm_hash(h)
    if h not in _HASHES:
        return None
    fam, bits, oid, classical, nistq = _HASHES[h]
    return _spec(h, "hash", family=fam, param=bits, functions=["digest"],
                 classical=classical, nistq=nistq, oid=oid)


def hmac_spec(h: str) -> Optional[dict]:
    h = _norm_hash(h)
    hs = hash_spec(h)
    if not hs:
        return None
    strength = {"SHA-1": (128, 1), "SHA-224": (192, 3), "SHA-256": (256, 5),
                "SHA-384": (256, 5), "SHA-512": (256, 5)}.get(h, (None, None))
    return _spec(f"HMAC-{h}", "mac", family="HMAC", param=hs["param"],
                 functions=["tag", "keyderive"], classical=strength[0],
                 nistq=strength[1], oid=_HMAC_OID.get(h), deps=[hs])


def hkdf_spec(h: str) -> Optional[dict]:
    h = _norm_hash(h)
    hs = hash_spec(h)
    if not hs:
        return None
    return _spec(f"HKDF-{h}", "kdf", family="HKDF", param=hs["param"],
                 functions=["keyderive"], classical=256, nistq=5,
                 oid=_HKDF_OID.get(h), deps=[hs])


def cipher_spec(token: str) -> Optional[dict]:
    """Bulk cipher of a TLS suite name fragment ('AES_128_GCM', 'CHACHA20_POLY1305',
    '3DES_EDE_CBC', 'RC4_128', 'SEED_CBC', 'AES_128_CCM_8', ...). None for NULL."""
    t = (token or "").upper()
    if not t or t == "NULL":
        return None
    if t == "CHACHA20_POLY1305":
        return _spec("ChaCha20-Poly1305", "ae", family="ChaCha20", param="256",
                     functions=["encrypt", "decrypt", "tag"], classical=256,
                     nistq=5, oid="1.2.840.113549.1.9.16.3.18")
    m = re.fullmatch(r"(AES|CAMELLIA|ARIA)_(128|192|256)_(GCM|CBC|CCM)(_8)?", t)
    if m:
        fam, bits, mode = m.group(1), int(m.group(2)), m.group(3).lower()
        fam_name = {"AES": "AES", "CAMELLIA": "CAMELLIA", "ARIA": "ARIA"}[fam]
        name = f"{fam_name}-{bits}-{mode.upper()}"
        if m.group(4):
            name += "-64"            # CCM_8: 64-bit tag
        aead = mode in ("gcm", "ccm")
        return _spec(name, "ae" if aead else "block-cipher", family=fam_name,
                     mode=mode, param=str(bits),
                     functions=["encrypt", "decrypt", "tag"] if aead
                     else ["encrypt", "decrypt"],
                     classical=bits, nistq=_NISTQ_BY_KEY.get(bits),
                     oid=_SYM_OID.get((fam_name, bits, mode)))
    if t in ("3DES_EDE_CBC", "DES_EDE3_CBC"):
        return _spec("3DES-168-CBC", "block-cipher", family="3DES", mode="cbc",
                     param="168", functions=["encrypt", "decrypt"],
                     classical=112, nistq=0, oid="1.2.840.113549.3.7")
    m = re.fullmatch(r"DES(40)?_CBC(?:_40)?", t)
    if m:
        bits = 40 if (m.group(1) or t.endswith("_40")) else 56
        return _spec(f"DES-{bits}-CBC", "block-cipher", family="DES", mode="cbc",
                     param=str(bits), functions=["encrypt", "decrypt"],
                     classical=bits, nistq=0, oid="1.3.14.3.2.7")
    m = re.fullmatch(r"RC4_(40|56|128)", t)
    if m:
        return _spec(f"RC4-{m.group(1)}", "stream-cipher", family="RC4",
                     param=m.group(1), functions=["encrypt", "decrypt"],
                     classical=0, nistq=0, oid="1.2.840.113549.3.4")
    if t == "SEED_CBC":
        return _spec("SEED-128-CBC", "block-cipher", family="SEED", mode="cbc",
                     param="128", functions=["encrypt", "decrypt"], classical=128,
                     nistq=1, oid="1.2.410.200004.1.4")
    if t == "IDEA_CBC":
        return _spec("IDEA-128-CBC", "block-cipher", family="IDEA", mode="cbc",
                     param="128", functions=["encrypt", "decrypt"], classical=128,
                     nistq=1)
    return _spec(t.replace("_", "-"), "unknown")


def kx_spec(token: str) -> Optional[dict]:
    """Key exchange of a TLS 1.2 suite (ECDHE / DHE / RSA / ECDH / DH)."""
    t = (token or "").upper()
    if t == "ECDHE":
        return _spec("ECDHE", "key-agree", family="ECDH",
                     functions=["keygen", "keyderive"], nistq=0)
    if t in ("DHE", "EDH"):
        return _spec("FFDHE", "key-agree", family="FFDH",
                     functions=["keygen", "keyderive"], nistq=0)
    if t == "ECDH":
        return _spec("ECDH", "key-agree", family="ECDH",
                     functions=["keyderive"], nistq=0)
    if t == "DH":
        return _spec("FFDH", "key-agree", family="FFDH",
                     functions=["keyderive"], nistq=0)
    if t == "RSA":
        return _spec("RSA-PKCS1-1.5", "pke", family="RSAES-PKCS1",
                     padding="pkcs1v15", functions=["encrypt", "decrypt"],
                     nistq=0, oid="1.2.840.113549.1.1.1")
    return None


def auth_spec(token: str) -> Optional[dict]:
    """Server authentication of a TLS 1.2 suite (RSA / ECDSA / DSS)."""
    t = (token or "").upper()
    if t == "RSA":
        return _spec("RSA", "signature", functions=["sign", "verify"], nistq=0,
                     oid="1.2.840.113549.1.1.1")
    if t == "ECDSA":
        return _spec("ECDSA", "signature", family="ECDSA",
                     functions=["sign", "verify"], nistq=0,
                     oid="1.2.840.10045.2.1")
    if t in ("DSS", "DSA"):
        return _spec("DSA", "signature", family="DSA",
                     functions=["sign", "verify"], nistq=0,
                     oid="1.2.840.10040.4.1")
    return None


def _ec_group_spec(curve_key: str) -> dict:
    text, _enum, oid, bits = _CURVES[curve_key]
    if curve_key in ("Curve25519", "Curve448"):
        name = "x25519" if curve_key == "Curve25519" else "x448"
    else:
        name = f"ECDH-{curve_key}"
    return _spec(name, "key-agree", family="ECDH", curve=curve_key,
                 functions=["keygen", "keyderive"], classical=bits, nistq=0,
                 oid=oid)


def mlkem_spec(bits: int) -> dict:
    classical, cat = _ML_LEVELS[bits]
    return _spec(f"ML-KEM-{bits}", "kem", family="ML-KEM", param=str(bits),
                 functions=["keygen", "encapsulate", "decapsulate"],
                 classical=classical, nistq=cat,
                 oid=f"2.16.840.1.101.3.4.4.{ {512: 1, 768: 2, 1024: 3}[bits] }")


def group_spec(group: str) -> Optional[dict]:
    """Algorithm component for a TLS supported group (as offered/negotiated)."""
    name = _TLS_GROUPS_LC.get((group or "").lower())
    if not name:
        return None
    code, kind, data = _TLS_GROUPS[name]
    gprops = [("tls-group", name), ("tls-group-id", f"0x{code:04X}")]
    if kind in ("ecdh", "x"):
        s = _ec_group_spec(data)
    elif kind == "ffdhe":
        s = _spec(f"FFDHE-{name}", "key-agree", family="FFDH", param=str(data),
                  functions=["keygen", "keyderive"],
                  classical=_rsa_strength(data), nistq=0)
    elif kind == "mlkem":
        s = mlkem_spec(data)
    else:
        pqc_name, classical_group, classical, cat = data
        if pqc_name == "Kyber-768":
            pq = _spec("Kyber-768", "kem", param="768",
                       functions=["keygen", "encapsulate", "decapsulate"],
                       classical=192, nistq=3,
                       props=[("pre-standard", "CRYSTALS-Kyber round 3 draft; "
                               "superseded by ML-KEM (FIPS 203)")])
        else:
            pq = mlkem_spec(int(pqc_name.rsplit("-", 1)[1]))
        cl = group_spec(classical_group)
        extra = [("hybrid", "true")]
        if kind == "draft":
            extra.append(("pre-standard", "draft code point; replaced by "
                          "X25519MLKEM768 / SecP256r1MLKEM768"))
        s = _spec(name, "kem", functions=["keygen", "encapsulate", "decapsulate"],
                  classical=classical, nistq=cat, deps=[pq, cl], props=extra)
    s["props"] = gprops + list(s["props"])
    return s


def signature_spec(sig: str, hash_alg: str = "", sig_oid: str = "") -> Optional[dict]:
    """Certificate signature algorithm from a name or dotted OID (+ hash)."""
    raw = (sig or "").strip()
    oid = (sig_oid or "").strip()
    if not oid:
        if re.fullmatch(r"\d+(\.\d+)+", raw):
            oid = raw
        else:
            oid = _SIG_NAMES.get(raw.lower().replace(" ", ""), "")
    entry = _SIG_OIDS.get(oid)
    if not entry:
        if not raw and not oid:
            return None
        return _spec(raw or oid, "signature", functions=["sign", "verify"],
                     oid=oid or None)
    stem, kind, h = entry
    h = _norm_hash(h or hash_alg)
    hs = hash_spec(h)
    deps = [hs] if hs else []
    if kind == "rsa":
        return _spec(f"{stem}-{h}", "signature", family="RSASSA-PKCS1",
                     padding="pkcs1v15", functions=["sign", "verify"], nistq=0,
                     oid=oid, deps=deps)
    if kind == "pss":
        name = f"RSA-PSS-{h}" if hs else "RSA-PSS"
        return _spec(name, "signature", family="RSASSA-PSS", padding="other",
                     functions=["sign", "verify"], nistq=0, oid=oid, deps=deps)
    if kind == "ecdsa":
        return _spec(f"ECDSA-{h}", "signature", family="ECDSA",
                     functions=["sign", "verify"], nistq=0, oid=oid, deps=deps)
    if kind == "dsa":
        return _spec(f"DSA-{h}", "signature", family="DSA",
                     functions=["sign", "verify"], nistq=0, oid=oid, deps=deps)
    if kind == "eddsa":
        bits = 128 if stem == "Ed25519" else 224
        return _spec(stem, "signature", family="EdDSA",
                     curve="Curve25519" if stem == "Ed25519" else "Curve448",
                     functions=["sign", "verify"], classical=bits, nistq=0, oid=oid)
    if kind == "mldsa":
        classical, cat = _MLDSA_LEVELS[stem.rsplit("-", 1)[1]]
        return _spec(stem, "signature", family="ML-DSA", param=stem.rsplit("-", 1)[1],
                     functions=["keygen", "sign", "verify"], classical=classical,
                     nistq=cat, oid=oid)
    if kind == "slhdsa":
        size = int(re.search(r"(128|192|256)", stem).group(1))
        return _spec(stem, "signature", family="SLH-DSA",
                     functions=["keygen", "sign", "verify"], classical=size,
                     nistq=_NISTQ_BY_KEY[size], oid=oid)
    return None


def key_algorithm_spec(key_type: str, bits: int, curve: str = "") -> Optional[dict]:
    """Algorithm of a certificate public key ('RSA' 2048 → RSA-2048, ...)."""
    kt = (key_type or "").strip()
    ku = kt.upper().replace("-", "").replace("_", "")
    bits = int(bits or 0)
    if ku in ("RSA", "RSAENCRYPTION", "RSAPUBLICKEY"):
        if not bits:
            return _spec("RSA", "signature", functions=["sign", "verify"], nistq=0,
                         oid="1.2.840.113549.1.1.1")
        return _spec(f"RSA-{bits}", "signature", param=str(bits),
                     functions=["sign", "verify"], classical=_rsa_strength(bits),
                     nistq=0, oid="1.2.840.113549.1.1.1")
    if ku in ("ECDSA", "EC", "IDECPUBLICKEY", "ELLIPTICCURVEPUBLICKEY"):
        curve = _SECG_TO_CURVE.get((curve or "").lower(), curve or "")
        if curve and curve not in _CURVES:          # e.g. brainpoolP256r1
            return _spec(f"ECDSA-{curve}", "signature", family="ECDSA",
                         param=str(bits) if bits else None,
                         functions=["sign", "verify"], nistq=0,
                         oid="1.2.840.10045.2.1",
                         props=[("curve", curve)])
        ckey = curve if curve in _CURVES else _EC_BITS_TO_CURVE.get(bits)
        if not ckey:
            return _spec("ECDSA", "signature", family="ECDSA",
                         functions=["sign", "verify"], nistq=0,
                         oid="1.2.840.10045.2.1")
        _t, _e, coid, cbits = _CURVES[ckey]
        props = [] if curve else [("curve-inferred-from-key-size", "true")]
        return _spec(f"ECDSA-{ckey}", "signature", family="ECDSA", curve=ckey,
                     functions=["sign", "verify"], classical=cbits, nistq=0,
                     oid=coid, props=props)
    if ku in ("ED25519", "ED448"):
        return signature_spec("Ed25519" if ku == "ED25519" else "Ed448")
    m = re.search(r"ML-?DSA-?(44|65|87)", kt, re.I)
    if m:
        return signature_spec(f"ML-DSA-{m.group(1)}")
    if not kt:
        return None
    return _spec(kt, "unknown", param=str(bits) if bits else None)


def parse_suite(name: str) -> Optional[dict]:
    """
    Split a TLS cipher-suite name into its primitives.
    Returns {"name", "tls13", "kx", "auth", "cipher", "mac"} or None.
    Accepts IANA names and OpenSSL names (mapped through _OPENSSL_TO_IANA and
    scanner.cipher_enum's table).
    """
    n = canonical_suite(name)
    if not n:
        return None
    u = n.upper()
    if not u.startswith("TLS_"):
        return None
    if "_WITH_" not in u:                      # TLS 1.3: TLS_<AEAD>_<HASH>
        body, _, h = u[4:].rpartition("_")
        if not re.fullmatch(r"AES_(128|256)_(GCM|CCM(_8)?)|CHACHA20_POLY1305", body) \
                or h not in ("SHA256", "SHA384"):
            # Signalling values (…_SCSV) or unknown names: keep the name only.
            return {"name": n, "tls13": True, "kx": None, "auth": None,
                    "cipher": None, "mac": None}
        return {"name": n, "tls13": True, "kx": None, "auth": None,
                "cipher": body, "mac": h}
    left, right = u[4:].split("_WITH_", 1)
    parts = left.split("_")
    kx = parts[0]
    auth = parts[1] if len(parts) > 1 else ("RSA" if kx == "RSA" else None)
    if auth in ("ANON", "EXPORT", "EXPORT1024"):
        auth = None
    tokens = right.split("_")
    if tokens[-1] in ("SHA", "SHA256", "SHA384", "MD5"):
        mac, cipher = tokens[-1], "_".join(tokens[:-1])
    else:
        mac, cipher = "SHA256", right            # CCM suites: PRF SHA-256
    if mac == "SHA":
        mac = "SHA1"
    return {"name": n, "tls13": False, "kx": kx, "auth": auth,
            "cipher": cipher, "mac": mac}


_SCANNER_OPENSSL_MAP: Optional[dict] = None


def canonical_suite(name: str) -> str:
    """IANA name for an IANA or OpenSSL suite name ('' when empty)."""
    global _SCANNER_OPENSSL_MAP
    n = (name or "").strip()
    if not n:
        return ""
    if n.upper().startswith("TLS_") or n.upper().startswith("SSL_"):
        return n
    if _SCANNER_OPENSSL_MAP is None:
        try:
            from scanner.cipher_enum import _OPENSSL_TO_IANA as _m
            _SCANNER_OPENSSL_MAP = dict(_m)
        except Exception:
            _SCANNER_OPENSSL_MAP = {}
    return _OPENSSL_TO_IANA.get(n) or _SCANNER_OPENSSL_MAP.get(n) or n


def suite_identifiers(name: str) -> list:
    """IANA code point as the two bytes, e.g. ['0xC0', '0x2F'] (schema example form)."""
    code = _SUITE_IDS.get((name or "").upper())
    if code is None:
        return []
    return [f"0x{code >> 8:02X}", f"0x{code & 0xFF:02X}"]


def suite_algorithm_specs(parsed: dict) -> list:
    """Algorithm specs referenced by one cipher suite."""
    if not parsed:
        return []
    specs = []
    if parsed["tls13"]:
        c = cipher_spec(parsed["cipher"])
        k = hkdf_spec(parsed["mac"])
        specs = [c, k]
    else:
        specs.append(kx_spec(parsed["kx"]))
        if parsed["kx"] != "RSA":          # RSA key transport authenticates itself
            specs.append(auth_spec(parsed["auth"]))
        specs.append(cipher_spec(parsed["cipher"]))
        specs.append(hmac_spec(parsed["mac"]))
    return [s for s in specs if s]


# ══════════════════════════════════════════════════════════════════════════════
# Data collection (DB access) and endpoint assembly
# ══════════════════════════════════════════════════════════════════════════════

_PORT_SCHEME = {
    443: "https", 8443: "https", 465: "smtps", 993: "imaps", 995: "pop3s",
    636: "ldaps", 5061: "sips", 25: "smtp", 587: "smtp", 2525: "smtp",
    143: "imap", 110: "pop3", 389: "ldap",
}
_STARTTLS_PORTS = {25, 587, 2525, 143, 110, 389}


def endpoint_uri(host: str, port: int) -> str:
    return f"{_PORT_SCHEME.get(int(port), 'tls')}://{host}:{int(port)}"


def collect_org_data(db, org: dict, domains: Iterable[str], *,
                     include_ct: bool = True, scope_note: str = "") -> dict:
    """
    Read everything the CBOM needs for `domains` (the org's domains the
    requester may see). Index-friendly bulk reads only; see data/database.py.
    """
    requested = sorted({d.strip() for d in (domains or []) if d and d.strip()},
                       key=str.lower)
    assessed_raw = db.latest_assessments_for(requested)
    # One row per host, case-insensitively: keep the newest.
    assessed: dict = {}
    for name, row in assessed_raw.items():
        key = name.lower()
        cur = assessed.get(key)
        if cur is None or (_dt(row.get("assessed_at")) or datetime.min.replace(tzinfo=timezone.utc)) > \
                (_dt(cur[1].get("assessed_at")) or datetime.min.replace(tzinfo=timezone.utc)):
            assessed[key] = (name, row)
    assessments = {name: row for name, row in assessed.values()}
    unassessed = [d for d in requested if d.lower() not in assessed]

    tls_hosts = [n for n, a in assessments.items() if a.get("level") != "na"]
    na_hosts = [n for n, a in assessments.items() if a.get("level") == "na"]
    scans = db.latest_network_scans_for(tls_hosts)
    extra = db.latest_extra_for(tls_hosts, EXTRA_TYPES)
    for d, blobs in db.latest_extra_for(na_hosts, ["dns_status"]).items():
        extra.setdefault(d, {}).update(blobs)
    ct = {}
    if include_ct:
        ct_names = list(dict.fromkeys(list(assessments) + requested))
        ct = db.ct_certificates_for(ct_names)
    return {"org": dict(org or {}), "requested": requested,
            "assessments": assessments, "unassessed": unassessed,
            "scans": scans, "extra": extra, "ct": ct, "scope_note": scope_note}


def _endpoints(host: str, scan_info: Optional[dict], extra: dict) -> list:
    """
    Per-port TLS endpoints for one host:
    [{"port", "uri", "starttls", "versions": {"1.3": {"suites": [...],
      "source": "enumerated"|"negotiated"}}, "negotiated": {...},
      "leaf": cert dict|None, "groups": [...]|None, "chain": [...]|None}]
    """
    scans = (scan_info or {}).get("scans") or []
    by_port: dict = {}
    for s in scans:
        if not isinstance(s, dict):
            continue
        if not s.get("success") and s.get("source") != "shodan":
            continue
        try:
            port = int(s.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not port:
            continue
        cur = by_port.get(port)
        if cur is None or (not cur.get("tls_version") and s.get("tls_version")):
            by_port[port] = s
    enum = extra.get("cipher_enum") or {}
    genum = extra.get("group_enum") or {}
    chain = extra.get("chain") or {}

    def _port_of(blob):
        try:
            return int(blob.get("port") or 443)
        except (TypeError, ValueError):
            return 443

    out = []
    for port in sorted(by_port):
        s = by_port[port]
        ver = _tls_version(s.get("tls_version"))
        neg_suite = canonical_suite(s.get("cipher_suite", ""))
        versions: dict = {}
        if enum.get("success") and _port_of(enum) == port:
            for c in enum.get("supported_ciphers") or []:
                if not isinstance(c, dict):
                    continue
                v = _tls_version(c.get("tls_version"))
                nm = canonical_suite(c.get("iana_name") or c.get("openssl_name") or "")
                if v and nm:
                    entry = versions.setdefault(v, {"suites": [], "source": "enumerated"})
                    if nm not in entry["suites"]:
                        entry["suites"].append(nm)
        if ver and ver not in versions:
            versions[ver] = {"suites": [neg_suite] if neg_suite else [],
                             "source": "negotiated"}
        elif ver and neg_suite and neg_suite not in versions[ver]["suites"]:
            versions[ver]["suites"].append(neg_suite)
        # cipher_enum cannot restrict TLS 1.3 suites through the ssl module and
        # records only the suite the server prefers; say so instead of
        # implying a full enumeration.
        v13 = versions.get("1.3")
        if v13 and v13["source"] == "enumerated" and len(v13["suites"]) <= 1:
            v13["source"] = "server-preferred"
        groups = None
        if genum.get("success") and _port_of(genum) == port:
            groups = list(genum.get("offered_groups") or [])
            if genum.get("tls13_supported") and "1.3" not in versions:
                versions["1.3"] = {"suites": [], "source": "enumerated"}
        chain_certs = None
        if chain.get("success") and _port_of(chain) == port:
            chain_certs = [c for c in (chain.get("certs") or []) if isinstance(c, dict)]
        cert = s.get("certificate") if isinstance(s.get("certificate"), dict) else None
        out.append({
            "port": port,
            "uri": endpoint_uri(host, port),
            "starttls": s.get("source") == "starttls" or port in _STARTTLS_PORTS,
            "source": s.get("source") or "probe",
            "versions": versions,
            "negotiated": {"version": ver, "suite": neg_suite,
                           "group": s.get("key_group") or ""},
            "leaf": cert if cert else None,
            "groups": groups,
            "chain": chain_certs,
            "has_dane": s.get("has_dane"),
            "has_dnssec": s.get("has_dnssec"),
        })
    return out


def _tls_version(v) -> str:
    """'TLSv1.3' → '1.3', 'TLSv1' → '1.0', 'SSLv3' → 'SSL3.0'."""
    s = str(v or "").strip()
    if not s:
        return ""
    m = re.fullmatch(r"(?i)TLS\s*v?\s*(1(?:\.[0-3])?)", s)
    if m:
        ver = m.group(1)
        return "1.0" if ver == "1" else ver
    m = re.fullmatch(r"(?i)SSL\s*v?\s*([23](?:\.0)?)", s)
    if m:
        return f"SSL{m.group(1)[0]}.0"
    return s


# ══════════════════════════════════════════════════════════════════════════════
# BOM builder
# ══════════════════════════════════════════════════════════════════════════════

class _Builder:
    def __init__(self, spec: str, now: datetime, tool_version: str):
        self.spec = spec
        self.v17 = spec == "1.7"
        self.now = now
        self.tool_version = tool_version
        self.components: dict = {}
        self.services: dict = {}
        self.deps: dict = {}
        self.occ: dict = {}           # ref → {location: [labels]}
        self.cert_data: dict = {}     # cert ref → merged data
        self.annotations: list = []

    # ── generic ─────────────────────────────────────────────────────────────
    def dep(self, ref: str, *targets):
        s = self.deps.setdefault(ref, set())
        for t in targets:
            if t and t != ref:
                s.add(t)

    def occur(self, ref: str, location: str, label: str = ""):
        if not ref or not location:
            return
        labels = self.occ.setdefault(ref, {}).setdefault(location, [])
        if label and label not in labels:
            labels.append(label)

    # ── algorithms ──────────────────────────────────────────────────────────
    def algorithm(self, spec: Optional[dict], location: str = "",
                  label: str = "") -> Optional[str]:
        if not spec:
            return None
        ref = f"crypto/algorithm/{_slug(spec['name'])}"
        if ref not in self.components:
            ap = {"primitive": spec["primitive"]}
            fam = spec.get("family")
            if self.v17 and fam in _FAMILIES_17:
                ap["algorithmFamily"] = fam
            if spec.get("param"):
                ap["parameterSetIdentifier"] = str(spec["param"])
            ck = spec.get("curve")
            if ck in _CURVES:
                if self.v17:
                    ap["ellipticCurve"] = _CURVES[ck][1]
                else:
                    ap["curve"] = _CURVES[ck][0]
            if spec.get("mode"):
                ap["mode"] = spec["mode"]
            if spec.get("padding"):
                ap["padding"] = spec["padding"]
            if spec.get("functions"):
                ap["cryptoFunctions"] = list(spec["functions"])
            if spec.get("classical") is not None:
                ap["classicalSecurityLevel"] = int(spec["classical"])
            if spec.get("nistq") is not None:
                ap["nistQuantumSecurityLevel"] = int(spec["nistq"])
            cp = {"assetType": "algorithm", "algorithmProperties": ap}
            if spec.get("oid"):
                cp["oid"] = spec["oid"]
            comp = {"type": "cryptographic-asset", "bom-ref": ref,
                    "name": spec["name"], "cryptoProperties": cp}
            props = _props(*spec.get("props", []))
            if props:
                comp["properties"] = props
            self.components[ref] = comp
            self.dep(ref)
            for d in spec.get("deps") or []:
                dref = self.algorithm(d)
                self.dep(ref, dref)
        if location:
            self.occur(ref, location, label)
            for d in spec.get("deps") or []:
                self.occur(f"crypto/algorithm/{_slug(d['name'])}", location,
                           f"part of {spec['name']}")
        return ref

    # ── certificates ────────────────────────────────────────────────────────
    def certificate(self, c: dict, *, location: str = "", label: str = "",
                    role: str = "leaf", source: str = "observed") -> Optional[str]:
        """Add/merge a certificate (normalised dict, see _norm_* helpers)."""
        fp = c.get("fp") or ""
        if fp:
            ref = f"crypto/certificate/sha256:{fp}"
        else:
            ident = c.get("serial") or c.get("subject_cn") or ""
            if not ident:
                return None
            ref = f"crypto/certificate/{_slug(c.get('subject_cn') or 'cert')}-{_slug(ident)}"
        cur = self.cert_data.get(ref)
        if cur is None:
            cur = dict(c)
            cur["roles"] = set()
            cur["sources"] = set()
            cur["ct_domains"] = set()
            self.cert_data[ref] = cur
        else:
            for k, v in c.items():
                if v not in (None, "", [], 0) and cur.get(k) in (None, "", [], 0):
                    cur[k] = v
        cur["roles"].add(role)
        cur["sources"].add(source)
        if c.get("ct_domain"):
            cur["ct_domains"].add(c["ct_domain"])
        if location:
            self.occur(ref, location, label)
        return ref

    def _render_certificates(self):
        for ref, c in self.cert_data.items():
            sig = signature_spec(c.get("sig") or "", c.get("hash") or "",
                                 c.get("sig_oid") or "")
            sig_ref = self.algorithm(sig)
            key_alg = key_algorithm_spec(c.get("key_type") or "", c.get("key_bits") or 0,
                                         c.get("key_curve") or "")
            key_alg_ref = self.algorithm(key_alg)
            key_ref = None
            if key_alg_ref:
                key_ref = f"crypto/key/{ref.split('/', 2)[2]}"
                self._public_key(key_ref, key_alg, key_alg_ref, c)
            self.dep(ref, sig_ref, key_ref)
            if c.get("issuer_ref") and c["issuer_ref"] in self.cert_data:
                self.dep(ref, c["issuer_ref"])
            # Where the certificate was seen is where its key and algorithms are used.
            for loc in list(self.occ.get(ref, {})):
                self.occur(key_ref, loc, "certificate public key")
                self.occur(key_alg_ref, loc, "certificate key algorithm")
                self.occur(sig_ref, loc, "certificate signature")

            nb, na = _dt(c.get("not_before")), _dt(c.get("not_after"))
            subject = c.get("subject_dn") or (f"CN={c['subject_cn']}" if c.get("subject_cn") else "")
            issuer = c.get("issuer_dn") or (f"CN={c['issuer_cn']}" if c.get("issuer_cn") else "")
            cp = {}
            if self.v17 and c.get("serial"):
                cp["serialNumber"] = c["serial"]
            if subject:
                cp["subjectName"] = subject
            if issuer:
                cp["issuerName"] = issuer
            if nb:
                cp["notValidBefore"] = _iso(nb)
            if na:
                cp["notValidAfter"] = _iso(na)
            if not self.v17:
                if sig_ref:
                    cp["signatureAlgorithmRef"] = sig_ref
                if key_ref:
                    cp["subjectPublicKeyRef"] = key_ref
            cp["certificateFormat"] = "X.509"
            state, reason = self._cert_state(nb, na)
            if self.v17:
                if c.get("fp") and len(c["fp"]) == 64:
                    cp["fingerprint"] = {"alg": "SHA-256", "content": c["fp"]}
                if state:
                    st = {"state": state}
                    if reason:
                        st["reason"] = reason
                    cp["certificateState"] = [st]
                if nb:
                    cp["activationDate"] = _iso(nb)
                exts = []
                sans = list(c.get("sans") or [])
                if sans:
                    exts.append({"commonExtensionName": "subjectAlternativeName",
                                 "commonExtensionValue": _san_value(sans)})
                if c.get("is_ca"):
                    bc = "CA:TRUE"
                    if c.get("path_len") is not None:
                        bc += f", pathlen:{c['path_len']}"
                    exts.append({"commonExtensionName": "basicConstraints",
                                 "commonExtensionValue": bc})
                if exts:
                    cp["certificateExtensions"] = exts
                rel = []
                if sig_ref:
                    rel.append({"type": "signatureAlgorithm", "ref": sig_ref})
                if key_ref:
                    rel.append({"type": "publicKey", "ref": key_ref})
                if c.get("issuer_ref") and c["issuer_ref"] in self.cert_data:
                    rel.append({"type": "issuerCertificate", "ref": c["issuer_ref"]})
                if rel:
                    cp["relatedCryptographicAssets"] = rel
            name = c.get("subject_cn") or (c.get("sans") or [""])[0] \
                or (f"certificate {c['fp'][:16]}" if c.get("fp") else "certificate")
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                    "cryptoProperties": {"assetType": "certificate",
                                         "certificateProperties": cp}}
            roles = sorted(c["roles"])
            props = _props(
                ("certificate:role", roles),
                ("certificate:source", sorted(c["sources"])),
                ("certificate:state", None if self.v17 else state),
                ("certificate:serial", None if self.v17 else c.get("serial")),
                ("certificate:sha256", None if self.v17 else c.get("fp")),
                ("certificate:sans", None if self.v17 else _san_value(c.get("sans") or [])),
                ("certificate:san-count", len(c.get("sans_all") or c.get("sans") or []) or None),
                ("certificate:self-signed", True if c.get("self_signed") else None),
                ("certificate:pqc", True if c.get("pqc") else None),
                ("certificate:hybrid", True if c.get("hybrid") else None),
                ("ct:domain", sorted(c["ct_domains"]) or None),
                ("ct:crtsh-id", c.get("ct_id")),
            )
            if props:
                comp["properties"] = props
            self.components[ref] = comp

    def _cert_state(self, nb, na):
        if na and na < self.now:
            return "deactivated", f"certificate expired {_iso(na)}"
        if nb and nb > self.now:
            return "pre-activation", f"certificate not valid before {_iso(nb)}"
        if nb or na:
            return "active", None
        return None, None

    def _public_key(self, key_ref, key_alg, key_alg_ref, c):
        rp = {"type": "public-key"}
        nb, na = _dt(c.get("not_before")), _dt(c.get("not_after"))
        state, _ = self._cert_state(nb, na)
        if state == "active":
            rp["state"] = "active"
        elif state == "deactivated":
            rp["state"] = "deactivated"
        if not self.v17:
            rp["algorithmRef"] = key_alg_ref
        if c.get("key_bits"):
            rp["size"] = int(c["key_bits"])
        if self.v17:
            rp["relatedCryptographicAssets"] = [{"type": "algorithm", "ref": key_alg_ref}]
        cp = {"assetType": "related-crypto-material",
              "relatedCryptoMaterialProperties": rp}
        if key_alg.get("oid"):
            cp["oid"] = "1.2.840.10045.2.1" if key_alg.get("family") == "ECDSA" \
                else key_alg["oid"]
        self.components[key_ref] = {
            "type": "cryptographic-asset", "bom-ref": key_ref,
            "name": key_alg["name"], "cryptoProperties": cp,
            "properties": _props(("key:certificate", c.get("subject_cn") or c.get("fp"))),
        }
        self.dep(key_ref, key_alg_ref)

    # ── protocol ────────────────────────────────────────────────────────────
    def protocol(self, host: str, ep: dict, ver: str, info: dict,
                 cert_refs: list) -> str:
        ref = f"crypto/protocol/tls{ver}@{host}:{ep['port']}"
        loc = ep["uri"]
        suites = []
        alg_refs = []
        group_refs = []
        if ver == "1.3" and ep.get("groups"):
            for g in ep["groups"]:
                gref = self.algorithm(group_spec(g), loc,
                                      "offered TLS 1.3 key-exchange group")
                if gref:
                    group_refs.append(gref)
        for name in info.get("suites") or []:
            parsed = parse_suite(name)
            refs = []
            for spec in suite_algorithm_specs(parsed):
                r = self.algorithm(spec, loc, f"TLS {ver} cipher suites")
                if r and r not in refs:
                    refs.append(r)
            suite = {"name": parsed["name"] if parsed else name}
            if refs:
                suite["algorithms"] = refs
            ids = suite_identifiers(suite["name"])
            if ids:
                suite["identifiers"] = ids
            if self.v17 and ver == "1.3" and ep.get("groups"):
                suite["tlsGroups"] = [(_TLS_GROUPS_LC.get(g.lower()) or g)
                                      for g in ep["groups"]]
            suites.append(suite)
            alg_refs.extend(r for r in refs if r not in alg_refs)
        pp = {"type": "tls" if not ver.startswith("SSL") else "other",
              "version": ver.replace("SSL", "") if ver.startswith("SSL") else ver}
        if suites:
            pp["cipherSuites"] = suites
        related = group_refs + [r for r in cert_refs if r]
        if related:
            if self.v17:
                pp["relatedCryptographicAssets"] = (
                    [{"type": "algorithm", "ref": r} for r in group_refs]
                    + [{"type": "certificate", "ref": r} for r in cert_refs if r])
            else:
                pp["cryptoRefArray"] = related
        pqc_groups = [g for g in (ep.get("groups") or [])
                      if _TLS_GROUPS.get(_TLS_GROUPS_LC.get(g.lower(), ""), (0, ""))[1]
                      in ("mlkem", "hybrid", "draft")]
        pqc = None
        if ver == "1.3":
            pqc = ("offered" if pqc_groups else "not offered") \
                if ep.get("groups") is not None else "unknown"
        neg = ep.get("negotiated") or {}
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f"TLS {ver}" if not ver.startswith("SSL") else ver.replace("SSL", "SSL "),
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
            "properties": _props(
                ("endpoint", loc),
                ("cipher-suites-source", info.get("source")),
                ("negotiated-cipher-suite",
                 neg.get("suite") if neg.get("version") == ver else None),
                ("negotiated-group",
                 neg.get("group") if neg.get("version") == ver else None),
                ("pqc-key-exchange", pqc),
                ("pqc-groups-offered", pqc_groups or None),
                ("starttls", True if ep.get("starttls") else None),
            ),
        }
        if not comp["properties"]:
            del comp["properties"]
        self.components[ref] = comp
        self.occur(ref, loc, f"TLS {ver}")
        self.dep(ref, *alg_refs, *group_refs, *cert_refs)
        return ref

    # ── service ─────────────────────────────────────────────────────────────
    def service(self, host: str, org_name: str, endpoints: list, props: list,
                dep_refs: list) -> str:
        ref = f"service/{host}"
        svc = {"bom-ref": ref, "name": host}
        if org_name:
            svc["provider"] = {"name": org_name}
        if endpoints:
            svc["endpoints"] = endpoints
            svc["x-trust-boundary"] = True
        if props:
            svc["properties"] = props
        self.services[ref] = svc
        self.dep(ref, *dep_refs)
        return ref

    # ── finalise ────────────────────────────────────────────────────────────
    def finish_occurrences(self):
        for ref, locs in self.occ.items():
            comp = self.components.get(ref)
            if not comp:
                continue
            occs = []
            for loc in sorted(locs):
                o = {"location": loc}
                labels = locs[loc][:MAX_CONTEXT]
                if labels:
                    o["additionalContext"] = "; ".join(labels)
                occs.append(o)
            if occs:
                comp["evidence"] = {"occurrences": occs}


def _san_value(sans: list) -> str:
    vals = []
    for s in sans[:MAX_SANS]:
        s = str(s)
        vals.append(("IP:" if re.fullmatch(r"[0-9.:a-fA-F]+", s) and
                     (":" in s or s.count(".") == 3) else "DNS:") + s)
    if len(sans) > MAX_SANS:
        vals.append(f"(+{len(sans) - MAX_SANS} more)")
    return ", ".join(vals)


def _norm_probe_cert(cert: dict) -> dict:
    """tls_probe.CertificateInfo dict → normalised certificate."""
    sans = [str(s) for s in (cert.get("san_domains") or [])]
    return {
        "fp": _hex(cert.get("fingerprint_sha256")),
        "serial": _serial(cert.get("serial_number")),
        "subject_cn": cert.get("subject_cn") or "",
        "issuer_cn": cert.get("issuer_cn") or "",
        "not_before": cert.get("not_before") or "",
        "not_after": cert.get("not_after") or "",
        "key_type": cert.get("key_type") or "",
        "key_bits": cert.get("key_size_bits") or 0,
        "key_curve": cert.get("key_curve") or "",
        "sig": cert.get("signature_algorithm") or "",
        "hash": cert.get("hash_algorithm") or "",
        "sans": sans[:MAX_SANS], "sans_all": sans,
        "self_signed": bool(cert.get("is_self_signed")),
    }


def _norm_chain_cert(node: dict) -> dict:
    """chain_validator.CertNode dict → normalised certificate."""
    sans = [str(s) for s in (node.get("san_domains") or [])]
    return {
        "fp": _hex(node.get("fingerprint_sha256")),
        "serial": _serial(node.get("serial_number")),
        "subject_cn": node.get("subject_cn") or "",
        "subject_dn": _readable_dn(node.get("subject_dn") or ""),
        "issuer_cn": node.get("issuer_cn") or "",
        "issuer_dn": _readable_dn(node.get("issuer_dn") or ""),
        "not_before": node.get("not_before") or "",
        "not_after": node.get("not_after") or "",
        "key_type": node.get("key_type") or "",
        "key_bits": node.get("key_size_bits") or 0,
        "key_curve": node.get("key_curve") or "",
        "sig": node.get("signature_algorithm") or "",
        "hash": node.get("hash_algorithm") or "",
        "sans": sans[:MAX_SANS], "sans_all": sans,
        "self_signed": bool(node.get("is_self_signed")),
        "is_ca": bool(node.get("is_ca")),
        "path_len": node.get("path_length_constraint"),
    }


def _norm_ct_cert(row: dict, domain: str) -> dict:
    """ct_certificates row → normalised certificate."""
    sans = [str(s) for s in (row.get("sans") or [])]
    pk = row.get("pubkey_algorithm_name") or ""
    curve = ""
    m = re.fullmatch(r"(?i)ECDSA-(.+)", pk)      # ct_monitor: "ECDSA-<curve name>"
    if m:
        pk, curve = "ECDSA", _SECG_TO_CURVE.get(m.group(1).lower(), m.group(1))
    key_type = {"rsaencryption": "RSA", "id-ecpublickey": "ECDSA",
                "ecpublickey": "ECDSA", "ed25519": "Ed25519",
                "ed448": "Ed448", "unknown": ""}.get(pk.lower(), pk)
    return {
        "fp": _hex(row.get("sha256_fingerprint")),
        "subject_cn": row.get("subject_cn") or "",
        "issuer_cn": row.get("issuer_cn") or "",
        "issuer_dn": ", ".join(p for p in (
            f"O={row['issuer_org']}" if row.get("issuer_org") else "",
            f"CN={row['issuer_cn']}" if row.get("issuer_cn") else "") if p),
        "not_before": row.get("not_before") or "",
        "not_after": row.get("not_after") or "",
        "key_type": key_type,
        "key_bits": row.get("pubkey_size_bits") or 0,
        "key_curve": curve,
        "sig": row.get("signature_algorithm_name") or "",
        "sig_oid": row.get("signature_algorithm_oid") or "",
        "sans": sans[:MAX_SANS], "sans_all": sans,
        "pqc": bool(row.get("is_pqc_signature") or row.get("is_pqc_pubkey")),
        "hybrid": bool(row.get("is_hybrid")),
        "ct_id": row.get("cert_id"),
        "ct_domain": domain,
    }


def _finding_text(f: dict) -> str:
    sev = str(f.get("severity") or "info").upper()
    cat = f.get("category") or "general"
    gl = f.get("guideline") or ""
    msg = f.get("message") or ""
    head = f"[{sev}] {cat}" + (f" ({gl})" if gl and gl != "all" else "") + f": {msg}"
    rec = f.get("recommendation") or ""
    return head + (f"\nRecommendation: {rec}" if rec else "")


def build_cbom(data: dict, *, spec: str = DEFAULT_SPEC, include_findings: bool = True,
               include_ct: bool = True, include_no_tls: bool = True,
               tool_version: Optional[str] = None, now: Optional[datetime] = None,
               serial: Optional[str] = None) -> dict:
    """Build the CycloneDX document from collect_org_data() output (no DB access)."""
    if spec not in SPEC_VERSIONS:
        raise ValueError(f"unsupported CycloneDX spec version {spec!r}; "
                         f"use one of {', '.join(SPEC_VERSIONS)}")
    if tool_version is None:
        try:
            from version import VERSION as tool_version
        except Exception:
            tool_version = "unknown"
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    b = _Builder(spec, now, tool_version)
    org = data.get("org") or {}
    org_name = org.get("name") or "Organisation"
    org_ref = f"org/{org.get('id', 'x')}"
    tool_component = {"type": "application", "name": TOOL_NAME,
                      "version": tool_version,
                      "externalReferences": [{"type": "vcs", "url": TOOL_URL}]}
    annotator = {"type": "application", "name": TOOL_NAME, "version": tool_version}

    assessments = data.get("assessments") or {}
    scans = data.get("scans") or {}
    extra_all = data.get("extra") or {}
    service_refs = []
    counts = {"tls": 0, "na": 0, "unassessed": len(data.get("unassessed") or [])}

    for host in sorted(assessments, key=str.lower):
        a = assessments[host]
        extra = extra_all.get(host) or {}
        level = a.get("level") or ""
        if level == "na":
            counts["na"] += 1
            if not include_no_tls:
                continue
            dns = extra.get("dns_status") or {}
            svc_props = _props(
                ("assessed-at", _iso(a.get("assessed_at"))),
                ("level", "na"), ("tls", "no TLS service found"),
                ("dns-status", dns.get("status")),
                ("dns-status-since", dns.get("since")),
            )
            service_refs.append(b.service(host, org_name, [], svc_props, []))
            continue
        counts["tls"] += 1
        eps = _endpoints(host, scans.get(host), extra)
        dep_refs = []
        for ep in eps:
            leaf_ref = None
            if ep.get("leaf"):
                leaf_ref = b.certificate(_norm_probe_cert(ep["leaf"]),
                                         location=ep["uri"],
                                         label="server certificate")
            if ep.get("chain"):
                prev = None
                for node in sorted(ep["chain"], key=lambda n: n.get("position", 0)
                                   if (n.get("position", 0) or 0) >= 0 else 99):
                    role = node.get("role") or ("leaf" if node.get("position") == 0
                                                else "intermediate")
                    cref = b.certificate(_norm_chain_cert(node), location=ep["uri"],
                                         label=f"certificate chain ({role})",
                                         role=role)
                    if role == "leaf" and leaf_ref is None:
                        leaf_ref = cref
                    if prev and cref and prev != cref:
                        p = b.cert_data[prev]
                        cur = b.cert_data[cref]
                        dn_match = bool(p.get("issuer_dn")) and \
                            p.get("issuer_dn") == cur.get("subject_dn")
                        cn_match = bool(p.get("issuer_cn")) and \
                            p.get("issuer_cn") == cur.get("subject_cn")
                        if dn_match or cn_match:
                            p.setdefault("issuer_ref", cref)
                    prev = cref
            cert_refs = [leaf_ref] if leaf_ref else []
            proto_refs = [b.protocol(host, ep, ver, info, cert_refs)
                          for ver, info in sorted(ep["versions"].items())]
            dep_refs.extend(proto_refs)
            dep_refs.extend(cert_refs)
        findings = a.get("findings_json") if isinstance(a.get("findings_json"), list) else []
        sev_counts: dict = {}
        for f in findings:
            if isinstance(f, dict):
                s = str(f.get("severity") or "info").lower()
                sev_counts[s] = sev_counts.get(s, 0) + 1
        cdn = extra.get("cdn") or {}
        ssl = extra.get("ssllabs") or {}
        genum = extra.get("group_enum") or {}
        chain = extra.get("chain") or {}
        tls_versions = a.get("tls_versions") if isinstance(a.get("tls_versions"), list) else []
        guidelines = a.get("guidelines_used") if isinstance(a.get("guidelines_used"), list) else []
        svc_props = _props(
            ("assessed-at", _iso(a.get("assessed_at"))),
            ("run-id", a.get("run_id")),
            ("score", a.get("score")),
            ("level", level),
            ("has-pqc", bool(a.get("has_pqc"))),
            ("pqc-grading-basis",
             "offered" if genum.get("success") else "negotiated"),
            ("pqc-groups-offered", genum.get("pqc_groups") if genum.get("success") else None),
            ("pqc-hybrid-only", bool(genum.get("hybrid_only")) if genum.get("pqc_groups") else None),
            ("offered-groups", genum.get("offered_groups") if genum.get("success") else None),
            ("tls-versions", tls_versions or None),
            ("service-type", a.get("service_type")),
            ("certificate-expiry-days", a.get("cert_expiry_days")),
            ("guidelines", guidelines or None),
            ("findings", len(findings) if include_findings else None),
            *[(f"findings:{k}", v) for k, v in sorted(sev_counts.items())
              if include_findings],
            ("cdn", cdn.get("cdn_name") if cdn.get("detected") else None),
            ("ssllabs-grade", ssl.get("grade") if ssl.get("status") == "READY" else None),
            ("ssllabs-tested", _iso(ssl.get("test_time")) if ssl.get("status") == "READY" else None),
            ("hsts", bool(chain.get("has_hsts")) if chain.get("success") else None),
            ("dane", True if any(e.get("has_dane") for e in eps) else None),
            ("dnssec", True if any(e.get("has_dnssec") for e in eps) else None),
            ("network-scan-at", _iso((scans.get(host) or {}).get("scanned_at"))),
        )
        sref = b.service(host, org_name, [e["uri"] for e in eps], svc_props,
                         list(dict.fromkeys(dep_refs)))
        service_refs.append(sref)
        if include_findings:
            ts = _iso(a.get("assessed_at")) or _iso(now)
            for i, f in enumerate(x for x in findings if isinstance(x, dict)):
                b.annotations.append({
                    "bom-ref": f"annotation/{host}/{i + 1}",
                    "subjects": [sref],
                    "annotator": {"component": annotator},
                    "timestamp": ts,
                    "text": _finding_text(f),
                })

    # Domains with no assessment yet.
    if include_no_tls:
        for host in data.get("unassessed") or []:
            service_refs.append(b.service(
                host, org_name, [],
                _props(("level", "not assessed"),
                       ("tls", "domain has not been scanned yet")), []))

    # CT-log certificates (valid now), newest first, capped per domain.
    ct_count = 0
    if include_ct:
        seen_ct = set()
        for domain in sorted(data.get("ct") or {}, key=str.lower):
            kept = 0
            for row in data["ct"][domain]:
                if kept >= CT_CERTS_PER_DOMAIN:
                    break
                na = _dt(row.get("not_after"))
                if na is None or na < now:
                    continue
                c = _norm_ct_cert(row, domain)
                key = c.get("fp") or (c.get("ct_id"), domain)
                loc = f"https://crt.sh/?id={c['ct_id']}" if c.get("ct_id") else ""
                ref = b.certificate(c, location=loc, label="CT log entry",
                                    role="ct-logged", source="ct-log")
                if ref and key not in seen_ct:
                    seen_ct.add(key)
                    kept += 1
                    ct_count += 1

    b._render_certificates()
    b.finish_occurrences()

    # Root of the dependency graph: the organisation's service estate.
    b.dep(org_ref, *service_refs)

    org_props = _props(
        ("org-id", org.get("id")),
        ("sector", org.get("sector")),
        ("country-code", org.get("country_code")),
        ("country", org.get("country")),
        ("region", org.get("region")),
        ("domains-in-scope", len(data.get("requested") or [])),
        ("domains-with-tls", counts["tls"]),
        ("domains-without-tls", counts["na"]),
        ("domains-not-assessed", counts["unassessed"]),
        ("ct-certificates", ct_count if include_ct else None),
        ("scope", data.get("scope_note") or "organisation"),
        ("content", ", ".join(x for x, on in (("findings", include_findings),
                                               ("ct-log certificates", include_ct),
                                               ("services without TLS", include_no_tls))
                              if on) or "crypto assets only"),
    )
    metadata = {
        "timestamp": _iso(now),
        "lifecycles": [{"phase": "discovery"}],
        "tools": {"components": [tool_component]},
        "component": {
            "type": "platform", "bom-ref": org_ref,
            "name": f"{org_name} — internet-facing services",
            "description": (f"Cryptographic assets that {TOOL_NAME} observed on the "
                            f"internet-facing TLS services of the organisation "
                            f"'{org_name}' (externally observable cryptography only)"),
            "supplier": {"name": org_name},
        },
        "supplier": {"name": org_name},
    }
    if org_props:
        metadata["properties"] = org_props

    rank = {"protocol": 0, "certificate": 1, "related-crypto-material": 2,
            "algorithm": 3}

    def _ckey(c):
        at = c.get("cryptoProperties", {}).get("assetType", "")
        return (rank.get(at, 9), c["bom-ref"])

    components = sorted(b.components.values(), key=_ckey)
    known = set(b.components) | set(b.services) | {org_ref}
    dependencies = []
    for ref in sorted(b.deps):
        if ref not in known:
            continue
        d = {"ref": ref}
        targets = sorted(t for t in b.deps[ref] if t in known)
        if targets:
            d["dependsOn"] = targets
        dependencies.append(d)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "services": sorted(b.services.values(), key=lambda s: s["bom-ref"].lower()),
        "dependencies": dependencies,
        "compositions": [{"aggregate": "incomplete", "assemblies": [org_ref]}],
    }
    if b.annotations:
        bom["annotations"] = b.annotations
    if not bom["services"]:
        del bom["services"]
    return bom


def generate_org_cbom(db, org: dict, domains: Iterable[str], *,
                      spec: str = DEFAULT_SPEC, include_findings: bool = True,
                      include_ct: bool = True, include_no_tls: bool = True,
                      scope_note: str = "", now: Optional[datetime] = None) -> dict:
    """collect_org_data() + build_cbom()."""
    if spec not in SPEC_VERSIONS:
        raise ValueError(f"unsupported CycloneDX spec version {spec!r}")
    data = collect_org_data(db, org, domains, include_ct=include_ct,
                            scope_note=scope_note)
    return build_cbom(data, spec=spec, include_findings=include_findings,
                      include_ct=include_ct, include_no_tls=include_no_tls, now=now)


def dumps(bom: dict, pretty: bool = True) -> str:
    return json.dumps(bom, indent=2 if pretty else None, ensure_ascii=False) + "\n"


def media_type(spec: str = DEFAULT_SPEC) -> str:
    return f"{MEDIA_TYPE}; version={spec}"


def cbom_filename(org: dict, now: Optional[datetime] = None) -> str:
    """cbom-<org-slug>-<YYYYMMDD>.cdx.json (ASCII only, safe for headers)."""
    now = now or datetime.now(timezone.utc)
    name = (org or {}).get("name") or f"org-{(org or {}).get('id', '')}"
    ascii_name = name.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:60] \
        or f"org-{(org or {}).get('id', 'x')}"
    return f"cbom-{slug}-{now.strftime('%Y%m%d')}.cdx.json"
