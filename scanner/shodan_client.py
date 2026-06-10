#!/usr/bin/env python3
"""
PQC-Monitor: Shodan Client
Uses Shodan API for passive service and crypto data retrieval.
Falls back gracefully if no API key is configured.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import shodan as shodan_lib
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False


class ShodanClient:
    """
    Wrapper around the Shodan API for passive reconnaissance.
    Extracts TLS/crypto metadata from Shodan banners without
    active scanning.
    """

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.api = None
        self.available = False

        if not HAS_SHODAN:
            logger.warning("shodan library not installed. pip install shodan")
            return
        if not api_key:
            logger.info("No Shodan API key configured. Falling back to direct scanning.")
            return

        try:
            self.api = shodan_lib.Shodan(api_key)
            info = self.api.info()
            self.available = True
            logger.info(f"Shodan API ready. Plan: {info.get('plan','unknown')}, "
                        f"Credits: {info.get('query_credits','?')}")
        except Exception as e:
            logger.warning(f"Shodan API init failed: {e}")

    def get_host_crypto(self, domain: str) -> list:
        """
        Look up a domain/IP in Shodan and extract TLS/crypto metadata.
        Returns a list of service dicts (one per port with TLS data found).
        """
        if not self.available:
            return []

        results = []
        try:
            # Resolve hostname to IP for Shodan lookup
            import socket
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                logger.debug(f"Cannot resolve {domain}")
                return []

            host = self.api.host(ip)
            ts = datetime.now(timezone.utc).isoformat()

            for service in host.get("data", []):
                port = service.get("port", 0)
                transport = service.get("transport", "tcp")
                if transport != "tcp":
                    continue

                ssl_data = service.get("ssl", {})
                if not ssl_data:
                    continue

                svc = {
                    "domain": domain,
                    "ip": ip,
                    "port": port,
                    "timestamp": ts,
                    "source": "shodan",
                    "tls_version": "",
                    "cipher_suite": "",
                    "certificate": {},
                    "raw_ssl": ssl_data
                }

                # Extract TLS version
                versions = ssl_data.get("versions", [])
                if versions:
                    # Use the highest acceptable version
                    version_priority = {
                        "TLSv1.3": 5, "TLSv1.2": 4, "TLSv1.1": 3,
                        "TLSv1.0": 2, "SSLv3": 1, "SSLv2": 0
                    }
                    best = max(
                        (v for v in versions if not v.startswith("-")),
                        key=lambda v: version_priority.get(v, 0),
                        default=""
                    )
                    svc["tls_version"] = best

                # Extract cipher
                cipher = ssl_data.get("cipher", {})
                svc["cipher_suite"] = cipher.get("name", "")
                svc["cipher_bits"] = cipher.get("bits", 0)

                # Extract certificate info
                cert = ssl_data.get("cert", {})
                if cert:
                    subject = cert.get("subject", {})
                    issuer = cert.get("issuer", {})
                    pubkey = cert.get("pubkey", {})
                    svc["certificate"] = {
                        "subject_cn": subject.get("CN", ""),
                        "issuer_cn": issuer.get("CN", ""),
                        "not_after": cert.get("expires", ""),
                        "not_before": cert.get("issued", ""),
                        "key_type": pubkey.get("type", "").upper(),
                        "key_size_bits": pubkey.get("bits", 0),
                        "signature_algorithm": cert.get("sig_alg", ""),
                        "fingerprint_sha256": cert.get("fingerprint", {}).get("sha256", "")
                    }

                # PQC indicators
                cipher_name_lower = svc["cipher_suite"].lower()
                pqc_indicators = [
                    "kyber", "mlkem", "ml-kem", "dilithium", "mldsa", "ml-dsa",
                    "falcon", "sphincs", "slhdsa", "frodo", "ntru"
                ]
                svc["has_pqc"] = any(ind in cipher_name_lower for ind in pqc_indicators)

                results.append(svc)

        except shodan_lib.APIError as e:
            logger.debug(f"Shodan API error for {domain}: {e}")
        except Exception as e:
            logger.debug(f"Shodan lookup error for {domain}: {e}")

        return results

    def search_sector(self, query: str, max_results: int = 100) -> list:
        """
        Use Shodan search to find hosts matching a sector query.
        E.g.: 'ssl.cert.subject.cn:*.bankofspain.es country:ES'
        Returns list of {ip, port, domain, ssl_data}.
        """
        if not self.available:
            return []
        results = []
        try:
            search_results = self.api.search(query, limit=max_results)
            for match in search_results.get("matches", []):
                ssl_data = match.get("ssl", {})
                hostnames = match.get("hostnames", [])
                domain = hostnames[0] if hostnames else match.get("ip_str", "")
                results.append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 443),
                    "domain": domain,
                    "ssl_data": ssl_data,
                    "org": match.get("org", ""),
                    "country": match.get("location", {}).get("country_name", "")
                })
        except Exception as e:
            logger.warning(f"Shodan search error: {e}")
        return results
