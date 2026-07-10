#!/usr/bin/env python3
"""
PQC-Monitor: Service Discovery
Non-intrusive detection of TLS-enabled services on a domain.
Uses TCP connect probes and DNS SRV/TLSA records — no port knocking
or exploit-style techniques.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import socket
import logging
import concurrent.futures
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# Well-known TLS-bearing ports with service labels
TLS_PORTS = {
    443:  "https",
    8443: "https-alt",
    4443: "https-alt2",
    465:  "smtps",
    993:  "imaps",
    995:  "pop3s",
    636:  "ldaps",
    5061: "sips",
    8883: "mqtt-tls",
    2096: "cpanel-ssl",
    2087: "whm-ssl",
    10000:"webmin",
}

# STARTTLS ports (require protocol-level upgrade before TLS)
# NOTE: implicit-TLS variants (465 SMTPS, 993 IMAPS, 995 POP3S) live in
# TLS_PORTS above — they are wrapped directly. The ports here speak plaintext
# first and must be upgraded via EHLO/STARTTLS (SMTP), STARTTLS (IMAP),
# STLS (POP3). 2525 is a widely-used alternative SMTP submission port.
STARTTLS_PORTS = {
    25:   "smtp",
    587:  "submission",
    2525: "submission-alt",
    143:  "imap",
    110:  "pop3",
    389:  "ldap",
}

# Protocol family per STARTTLS port — drives the upgrade handshake so it is
# selected by PROTOCOL, not by a hardcoded port number.
STARTTLS_PROTOCOL = {
    25:   "smtp",
    587:  "smtp",
    2525: "smtp",
    143:  "imap",
    110:  "pop3",
    389:  "ldap",
}


@dataclass
class ServiceInfo:
    domain: str
    ip: str
    port: int
    service: str
    is_open: bool
    tls_direct: bool      # True = direct TLS; False = STARTTLS
    banner: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _tcp_connect(host: str, port: int, timeout: float = 5.0) -> tuple[bool, Optional[str]]:
    """Attempt a TCP connection. Returns (open, error_string)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None
    except ConnectionRefusedError:
        return False, "refused"
    except socket.timeout:
        return False, "timeout"
    except OSError as e:
        return False, str(e)


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def discover_tls_services(
    domain: str,
    ports: list = None,
    timeout: float = 5.0,
    max_workers: int = 10,
    include_starttls: bool = False
) -> list[ServiceInfo]:
    """
    Discover which TLS services are reachable on a domain.

    Performs plain TCP connect checks to identify open ports.
    Does NOT initiate TLS handshakes here — that is handled by tls_probe.py.
    Returns a list of ServiceInfo objects for open ports only.
    """
    probe_ports = ports if ports is not None else list(TLS_PORTS.keys())
    if include_starttls:
        probe_ports += list(STARTTLS_PORTS.keys())
    # Dedupe while preserving order (callers may already include STARTTLS ports)
    probe_ports = list(dict.fromkeys(probe_ports))

    ip = _resolve_ip(domain)
    if not ip:
        logger.debug(f"Cannot resolve {domain}")
        return []

    results = []

    def probe(port):
        is_tls_direct = port in TLS_PORTS
        service_name = TLS_PORTS.get(port) or STARTTLS_PORTS.get(port, f"port-{port}")
        open_, err = _tcp_connect(domain, port, timeout)
        if open_:
            return ServiceInfo(
                domain=domain,
                ip=ip,
                port=port,
                service=service_name,
                is_open=True,
                tls_direct=is_tls_direct,
                error=None
            )
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, p): p for p in probe_ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda s: s.port)
    logger.debug(f"{domain}: {len(results)} open TLS port(s): "
                 f"{[s.port for s in results]}")
    return results


def get_tlsa_records(domain: str, port: int = 443) -> list[dict]:
    """
    Fetch DANE TLSA records for a domain:port (passive DNS query).
    TLSA presence indicates DNSSEC + certificate pinning awareness.
    Returns list of TLSA record dicts (empty if none or DNS unavailable).
    """
    try:
        import dns.resolver
        import dns.rdatatype
        qname = f"_{port}._tcp.{domain}"
        answers = dns.resolver.resolve(qname, "TLSA")
        records = []
        for rdata in answers:
            records.append({
                "usage":     rdata.usage,
                "selector":  rdata.selector,
                "mtype":     rdata.mtype,
                "cert_data": rdata.cert.hex() if rdata.cert else ""
            })
        return records
    except Exception:
        return []


def check_dnssec(domain: str) -> bool:
    """
    Check whether a domain has DNSSEC enabled (passive DNS check).
    Returns True if DNSKEY records are found.
    """
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False


def full_service_profile(domain: str, ports: list = None,
                         timeout: float = 5.0) -> dict:
    """
    Build a complete service profile for a domain:
      - Open TLS ports
      - TLSA / DANE records on port 443
      - DNSSEC status
    """
    services = discover_tls_services(domain, ports, timeout)
    tlsa = get_tlsa_records(domain, 443)
    dnssec = check_dnssec(domain)

    return {
        "domain": domain,
        "services": [s.to_dict() for s in services],
        "tlsa_records": tlsa,
        "has_dane": len(tlsa) > 0,
        "has_dnssec": dnssec,
        "open_ports": [s.port for s in services],
    }
