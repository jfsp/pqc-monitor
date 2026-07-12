"""
PQC-Monitor: TLS 1.3 supported-group enumeration (OFFERED groups).

Determines which key-exchange groups a server *offers*, as opposed to the one
it happens to *negotiate* with a particular client. Negotiation depends on the
client's own group list and preference order — two browsers hitting the same
server can land on different groups — so "offered" is the only stable measure
of server-side PQC readiness.

Why not use the ssl module?
──────────────────────────
There is no way to control the offered group list from Python's ssl module on
Python <= 3.13:
  * SSLSocket.group()          → Python 3.13+, but reports only the NEGOTIATED group.
  * SSLContext.set_ecdh_curve()→ accepts a colon-separated group list (via
                                 SSL_CTX_set1_groups_list) only from Python 3.14.
  * SSLContext.set_groups()    → still an unmerged CPython proposal (gh-136306).
So we speak TLS 1.3 directly.

How it works (RFC 8446 §4.1.4)
──────────────────────────────
For each candidate group G we send a ClientHello advertising:
    supported_groups = [G]        (only G)
    key_share        = []         (EMPTY — we send no key material)
A server that supports G cannot complete the handshake without a key share, so
it replies with a HelloRetryRequest whose key_share extension names G as the
selected group. A server that does NOT support G has no common group and sends
a fatal alert (handshake_failure / insufficient_security).

    HelloRetryRequest naming G   → G is OFFERED
    fatal alert                  → G is NOT offered

Because we never complete the handshake, no local ML-KEM implementation is
required. This works on any Python/OpenSSL, including stacks that cannot
themselves perform a hybrid key exchange.

Cost: one TCP connection + one flight per group (~10 groups → ~10 probes).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""
from __future__ import annotations

import logging
import os
import socket
import struct
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── IANA TLS supported-group registry (subset we probe) ───────────────────────
# https://www.iana.org/assignments/tls-parameters/
GROUPS: dict[str, int] = {
    # Classical ECC
    "secp256r1":              0x0017,
    "secp384r1":              0x0018,
    "secp521r1":              0x0019,
    "x25519":                 0x001D,
    "x448":                   0x001E,
    # Finite-field DH
    "ffdhe2048":              0x0100,
    "ffdhe3072":              0x0101,
    # PQC hybrids (RFC 9370 / draft-kwiatkowski-tls-ecdhe-mlkem)
    "X25519MLKEM768":         0x11EC,
    "SecP256r1MLKEM768":      0x11EB,
    "SecP384r1MLKEM1024":     0x11ED,
    # Pure ML-KEM (draft-connolly-tls-mlkem-key-agreement)
    "MLKEM512":               0x0200,
    "MLKEM768":               0x0201,
    "MLKEM1024":              0x0202,
    # Legacy draft hybrids (still seen in the wild)
    "X25519Kyber768Draft00":  0x6399,
    "P256Kyber768Draft00":    0x639A,
}

# Groups that constitute post-quantum key exchange.
PQC_GROUPS: frozenset[str] = frozenset({
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519Kyber768Draft00", "P256Kyber768Draft00",
})

# Hybrid = classical + PQC combined (defence in depth; NIST-recommended posture).
HYBRID_GROUPS: frozenset[str] = frozenset({
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "X25519Kyber768Draft00", "P256Kyber768Draft00",
})

# RFC 8701 GREASE values reserved for supported_groups. A server MUST NOT
# negotiate these. Used as a host-independent negative control: if a probe
# reports one as "offered", the probe logic is producing false positives.
GREASE_GROUPS: dict[str, int] = {
    "GREASE_0x0A0A": 0x0A0A,
    "GREASE_0xDADA": 0xDADA,
}

_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

_GROUP_BY_ID = {v: k for k, v in GROUPS.items()}


@dataclass
class GroupEnumResult:
    """Offered key-exchange groups for one endpoint."""
    domain: str
    port: int
    timestamp: str
    success: bool
    error: Optional[str] = None

    offered_groups: list = field(default_factory=list)   # names, in probe order
    unsupported_groups: list = field(default_factory=list)
    inconclusive_groups: list = field(default_factory=list)  # timeouts/resets

    # PQC posture, derived from OFFERED groups
    has_pqc_kem: bool = False
    pqc_groups: list = field(default_factory=list)
    hybrid_only: bool = False        # PQC offered, all of it hybrid (good)
    tls13_supported: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ── ClientHello construction ─────────────────────────────────────────────────

def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _build_client_hello(host: str, group_id: int) -> bytes:
    """TLS 1.3 ClientHello offering exactly one group and an EMPTY key_share."""
    # Extension: server_name (SNI) — omit for IP literals.
    exts = b""
    try:
        socket.inet_aton(host)
        is_ip = True
    except OSError:
        is_ip = False
    if not is_ip:
        hb = host.encode("idna")
        sni = struct.pack("!BH", 0, len(hb)) + hb          # name_type=host_name
        exts += _ext(0x0000, struct.pack("!H", len(sni)) + sni)

    # supported_versions: TLS 1.3 only
    exts += _ext(0x002B, bytes([2]) + struct.pack("!H", 0x0304))

    # supported_groups: ONLY the group under test
    exts += _ext(0x000A, struct.pack("!HH", 2, group_id))

    # key_share: EMPTY client_shares → forces HelloRetryRequest if group is supported
    exts += _ext(0x0033, struct.pack("!H", 0))

    # signature_algorithms (required by RFC 8446 for certificate auth)
    sigalgs = [0x0403, 0x0503, 0x0603,          # ECDSA P-256/384/521 + SHA2
               0x0804, 0x0805, 0x0806,          # RSA-PSS
               0x0401, 0x0501, 0x0601]          # RSA PKCS#1
    sa = b"".join(struct.pack("!H", s) for s in sigalgs)
    exts += _ext(0x000D, struct.pack("!H", len(sa)) + sa)

    # psk_key_exchange_modes — harmless, improves interop with strict stacks
    exts += _ext(0x002D, bytes([1, 1]))

    body = (
        struct.pack("!H", 0x0303)               # legacy_version = TLS 1.2
        + os.urandom(32)                        # random
        + bytes([32]) + os.urandom(32)          # legacy_session_id (compat mode)
        + struct.pack("!H", 2) + struct.pack("!H", 0x1301)  # TLS_AES_128_GCM_SHA256
        + bytes([1, 0])                         # compression: null
        + struct.pack("!H", len(exts)) + exts
    )
    hs = bytes([1]) + struct.pack("!I", len(body))[1:] + body   # Handshake: ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs    # TLS record


# ── Response parsing ─────────────────────────────────────────────────────────

def _recv_record(sock: socket.socket) -> tuple[int, bytes]:
    """Read one TLS record. Returns (content_type, payload). Raises on EOF."""
    hdr = _recv_exact(sock, 5)
    ctype, _ver, length = hdr[0], hdr[1:3], struct.unpack("!H", hdr[3:5])[0]
    if length > 65535:
        raise ValueError("oversized TLS record")
    return ctype, _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf


def _selected_group_from_server_hello(payload: bytes) -> Optional[int]:
    """Given a Handshake payload, if it is a (Hello)ServerHello, return the
    group id named in its key_share extension (HRR: selected_group)."""
    if len(payload) < 4 or payload[0] != 2:        # 2 = ServerHello
        return None
    body = payload[4:]
    if len(body) < 35:
        return None
    random = body[2:34]
    is_hrr = random == _HRR_RANDOM
    p = 34
    sid_len = body[p]; p += 1 + sid_len            # legacy_session_id_echo
    p += 2 + 1                                    # cipher_suite + compression
    if p + 2 > len(body):
        return None
    ext_len = struct.unpack("!H", body[p:p + 2])[0]; p += 2
    end = min(p + ext_len, len(body))
    while p + 4 <= end:
        etype, elen = struct.unpack("!HH", body[p:p + 4]); p += 4
        edata = body[p:p + elen]; p += elen
        if etype == 0x0033:                       # key_share
            if is_hrr and len(edata) >= 2:
                # HelloRetryRequest.key_share = selected_group (2 bytes)
                return struct.unpack("!H", edata[:2])[0]
            if len(edata) >= 2:
                # Real ServerHello: KeyShareEntry.group
                return struct.unpack("!H", edata[:2])[0]
    return None


# ── Single-group probe ───────────────────────────────────────────────────────

def _probe_group(host: str, port: int, name: str, gid: int,
                 timeout: float) -> str:
    """Return 'offered' | 'unsupported' | 'inconclusive'."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_client_hello(host, gid))
            ctype, payload = _recv_record(s)

            if ctype == 0x15:                     # Alert
                # handshake_failure(40) / insufficient_security(71) → no common group
                return "unsupported"
            if ctype == 0x16:                     # Handshake
                sel = _selected_group_from_server_hello(payload)
                if sel is None:
                    return "inconclusive"
                if sel == gid:
                    return "offered"
                # Server named a different group than the only one we offered:
                # non-conformant; treat as not offered.
                logger.debug("%s:%d group %s → server selected 0x%04x",
                             host, port, name, sel)
                return "unsupported"
            return "inconclusive"
    except (socket.timeout, ConnectionError, OSError, ValueError) as e:
        logger.debug("group probe %s:%d %s: %s", host, port, name, e)
        return "inconclusive"


# ── Public API ───────────────────────────────────────────────────────────────

def enumerate_groups(domain: str, port: int = 443, timeout: float = 6.0,
                     groups: Optional[dict[str, int]] = None) -> GroupEnumResult:
    """
    Enumerate the key-exchange groups *offered* by domain:port.

    One TLS 1.3 ClientHello per candidate group; never completes a handshake,
    so it needs no local PQC crypto support.
    """
    groups = groups or GROUPS
    result = GroupEnumResult(
        domain=domain, port=port,
        timestamp=datetime.now(timezone.utc).isoformat(),
        success=False,
    )

    for name, gid in groups.items():
        verdict = _probe_group(domain, port, name, gid, timeout)
        if verdict == "offered":
            result.offered_groups.append(name)
        elif verdict == "unsupported":
            result.unsupported_groups.append(name)
        else:
            result.inconclusive_groups.append(name)

    # If every probe was inconclusive, the endpoint is unreachable / not TLS 1.3.
    if not result.offered_groups and not result.unsupported_groups:
        result.error = "no TLS 1.3 response to any group probe"
        return result

    result.success = True
    result.tls13_supported = bool(result.offered_groups)
    result.pqc_groups = [g for g in result.offered_groups if g in PQC_GROUPS]
    result.has_pqc_kem = bool(result.pqc_groups)
    result.hybrid_only = (
        result.has_pqc_kem
        and all(g in HYBRID_GROUPS for g in result.pqc_groups)
    )

    logger.info(
        "Group enum %s:%d: %d offered (%s) — PQC: %s",
        domain, port, len(result.offered_groups),
        ", ".join(result.offered_groups) or "none",
        ", ".join(result.pqc_groups) or "no",
    )
    return result


def group_enum_findings(res: GroupEnumResult) -> list[dict]:
    """Findings derived from OFFERED groups (client-independent)."""
    findings: list[dict] = []
    if not res.success:
        return findings

    if res.has_pqc_kem:
        findings.append({
            "severity": "info", "category": "pqc",
            "message": "Server offers post-quantum key exchange: "
                       + ", ".join(res.pqc_groups),
            "guideline": "all",
            "recommendation": "Verify the implementation follows NIST FIPS 203 (ML-KEM).",
        })
        if not res.hybrid_only:
            findings.append({
                "severity": "low", "category": "pqc",
                "message": "Server offers pure (non-hybrid) ML-KEM key exchange.",
                "guideline": "all",
                "recommendation": "Prefer hybrid groups (e.g. X25519MLKEM768) so the "
                                  "exchange stays secure if either primitive fails.",
            })
    else:
        findings.append({
            "severity": "medium", "category": "pqc",
            "message": "Server offers no post-quantum key-exchange group "
                       "(harvest-now-decrypt-later exposure).",
            "guideline": "all",
            "recommendation": "Enable a hybrid group such as X25519MLKEM768 "
                              "(NIST FIPS 203 / ML-KEM).",
        })
    return findings


def probe_negative_control(domain: str, port: int = 443,
                           timeout: float = 6.0) -> dict:
    """Host-independent soundness check for the enumerator.

    Probes RFC 8701 GREASE codepoints, which no conformant server may ever
    select. Any "offered" verdict here means the probe reports false positives
    and every result from it is suspect.

    Returns {"sound": bool, "false_positives": [...], "verdicts": {...}}.
    """
    verdicts = {
        name: _probe_group(domain, port, name, gid, timeout)
        for name, gid in GREASE_GROUPS.items()
    }
    fps = [n for n, v in verdicts.items() if v == "offered"]
    return {"sound": not fps, "false_positives": fps, "verdicts": verdicts}
