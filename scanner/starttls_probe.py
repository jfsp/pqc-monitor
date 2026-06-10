#!/usr/bin/env python3
"""
PQC-Monitor: STARTTLS Probe
Performs non-intrusive STARTTLS upgrades for SMTP (25/587), IMAP (143),
POP3 (110) and LDAP (389), then hands off to the same TLS extraction
pipeline used by tls_probe.py.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Optional

from scanner.tls_probe import _parse_certificate, _detect_pqc, _infer_key_exchange

logger = logging.getLogger(__name__)

# STARTTLS protocol upgrade bytes
_STARTTLS_COMMANDS = {
    25:  (b"EHLO pqcmonitor\r\n", b"STARTTLS\r\n"),
    587: (b"EHLO pqcmonitor\r\n", b"STARTTLS\r\n"),
    143: (b". CAPABILITY\r\n",    b". STARTTLS\r\n"),
    110: (b"CAPA\r\n",            None),   # POP3 STLS
    389: None,                             # LDAP StartTLS (binary – skip)
}
_POP3_STARTTLS = b"STLS\r\n"


def _recv_line(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read until CRLF with a simple byte-at-a-time loop (small banners)."""
    buf = b""
    sock.settimeout(timeout)
    while not buf.endswith(b"\n"):
        try:
            c = sock.recv(1)
            if not c:
                break
            buf += c
        except socket.timeout:
            break
    return buf


def _recv_multiline(sock: socket.socket, timeout: float = 3.0) -> bytes:
    """Read a multi-line SMTP/IMAP greeting (stop when we see a non-dash 3-digit code)."""
    buf = b""
    sock.settimeout(timeout)
    while True:
        line = _recv_line(sock, timeout)
        buf += line
        if not line:
            break
        # SMTP continuation: "250-…"; final line: "250 …"
        if len(line) >= 4 and line[3:4] == b" ":
            break
        # IMAP tagged response ends with "OK" or "NO"
        if line.strip().endswith(b"OK") or line.strip().endswith(b"NO"):
            break
    return buf


def probe_starttls(domain: str, port: int, timeout: int = 10) -> dict:
    """
    Attempt a STARTTLS upgrade on the given port, then extract the TLS
    session and certificate metadata.

    Returns a dict compatible with TLSProbeResult.to_dict(), with
    source="starttls" added.
    """
    ts = datetime.now(timezone.utc).isoformat()
    base = {
        "domain": domain, "port": port, "timestamp": ts,
        "success": False, "source": "starttls",
        "tls_version": "", "cipher_suite": "", "cipher_bits": 0,
        "key_exchange": "", "has_pqc_kem": False, "has_pqc_sig": False,
        "pqc_algorithms": [], "certificate": None, "chain_length": 0,
        "raw_cipher_list": [], "error": None,
    }

    if port == 389:
        base["error"] = "ldap_starttls_not_supported"
        return base

    try:
        sock = socket.create_connection((domain, port), timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        base["error"] = f"connect:{e}"
        return base

    try:
        sock.settimeout(timeout)

        # ── Receive server greeting ───────────────────────────────
        greeting = _recv_multiline(sock, timeout)
        logger.debug(f"{domain}:{port} greeting: {greeting[:80]!r}")

        if port in (25, 587):
            # SMTP EHLO
            sock.sendall(b"EHLO pqcmonitor.local\r\n")
            _recv_multiline(sock, timeout)
            sock.sendall(b"STARTTLS\r\n")
            resp = _recv_line(sock, timeout)
            if not resp.startswith(b"220"):
                base["error"] = f"smtp_starttls_rejected:{resp[:40]!r}"
                sock.close()
                return base

        elif port == 143:
            # IMAP STARTTLS
            sock.sendall(b"a001 STARTTLS\r\n")
            resp = _recv_line(sock, timeout)
            if b"OK" not in resp.upper():
                base["error"] = f"imap_starttls_rejected:{resp[:40]!r}"
                sock.close()
                return base

        elif port == 110:
            # POP3 STLS
            sock.sendall(b"CAPA\r\n")
            _recv_multiline(sock, timeout)
            sock.sendall(_POP3_STARTTLS)
            resp = _recv_line(sock, timeout)
            if not resp.startswith(b"+OK"):
                base["error"] = f"pop3_stls_rejected:{resp[:40]!r}"
                sock.close()
                return base

        # ── TLS upgrade ───────────────────────────────────────────
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        tls_sock = ctx.wrap_socket(sock, server_hostname=domain)

        base["success"] = True
        base["tls_version"] = tls_sock.version() or ""
        cipher = tls_sock.cipher()
        if cipher:
            base["cipher_suite"] = cipher[0]
            base["cipher_bits"] = cipher[2] or 0
            base["key_exchange"] = _infer_key_exchange(cipher[0])

        kem, sig, algos = _detect_pqc(base["cipher_suite"], base["tls_version"])
        base["has_pqc_kem"] = kem
        base["has_pqc_sig"] = sig
        base["pqc_algorithms"] = algos

        cert_der = tls_sock.getpeercert(binary_form=True)
        if cert_der:
            cert_info = _parse_certificate(cert_der)
            base["certificate"] = cert_info.__dict__ if cert_info else None

        try:
            chain = tls_sock.get_verified_chain()
            base["chain_length"] = len(chain) if chain else 1
        except AttributeError:
            base["chain_length"] = 1

        tls_sock.close()

    except ssl.SSLError as e:
        base["error"] = f"ssl:{e.reason}"
        sock.close()
    except socket.timeout:
        base["error"] = "timeout"
        sock.close()
    except Exception as e:
        base["error"] = f"error:{e}"
        try:
            sock.close()
        except Exception:
            pass

    return base
