#!/usr/bin/env python3
"""
PQC-Monitor: Scan Orchestrator
Coordinates multi-domain scanning, Shodan fallback, and assessment storage.

Scan order per domain:
  1. Shodan API (if key configured and --shodan flag set)
  2. Service discovery (TCP connect to identify open TLS ports)
  3. Direct TLS probe on discovered ports + STARTTLS
  4. Certificate chain analysis (full chain + HSTS + CAA)
  5. Active cipher suite enumeration (multiple ClientHellos)
  6. CDN detection (CNAME / headers / IP / PTR)
  7. Crypto extraction + assessment against guidelines

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import os
import sys
import concurrent.futures

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.tls_probe import probe_tls
from scanner.group_enum import enumerate_groups
from scanner.starttls_probe import probe_starttls
from scanner.service_discovery import (
    discover_tls_services, get_tlsa_records, check_dnssec, STARTTLS_PORTS
)
from scanner.shodan_client import ShodanClient
from scanner.crypto_assessor import CryptoAssessor
from scanner.chain_validator import analyse_chain, chain_findings
from scanner.cipher_enum import enumerate_ciphers, cipher_enum_findings
from scanner.ssllabs_client import SSLLabsClient
from scanner.cdn_detector import detect_cdn, cdn_findings
from data.database import Database

logger = logging.getLogger(__name__)

DEFAULT_PORTS     = [443, 8443, 465, 993, 995, 636]
STARTTLS_PORT_SET = set(STARTTLS_PORTS.keys())

# T2-1: canonical service_type label per port number
SERVICE_TYPE_MAP: dict[int, str] = {
    443:   "web_primary",
    8443:  "web_secondary",
    4443:  "web_secondary",
    465:   "smtp",
    587:   "smtp",
    25:    "smtp",
    993:   "imap",
    143:   "imap",
    995:   "pop3",
    110:   "pop3",
    636:   "ldap",
    389:   "ldap",
    2096:  "web_secondary",
    2087:  "web_secondary",
    10000: "web_secondary",
    5061:  "sip",
    8883:  "mqtt",
}


def _port_to_service_type(port: int) -> str:
    """Return a service_type label for a port, falling back to 'other'."""
    return SERVICE_TYPE_MAP.get(port, "other")


class ScanOrchestrator:
    """Runs scans across a list of domains, stores results, and triggers assessment."""

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.ports        = cfg.get("ports", DEFAULT_PORTS)
        self.timeout      = cfg.get("timeout", 10)
        self.max_workers  = cfg.get("max_workers", 20)
        self.use_starttls = cfg.get("use_starttls", True)
        self.do_chain     = cfg.get("chain_analysis", True)
        self.do_cipher_enum = cfg.get("cipher_enum", True)
        self.do_cdn       = cfg.get("cdn_detection", True)

        self.db = Database(cfg.get("db_path", "data/pqc_monitor.db"))
        self.shodan = ShodanClient(cfg.get("shodan_api_key", ""))
        self.ssllabs_enabled = cfg.get("ssllabs_enabled", True)
        self.ssllabs = SSLLabsClient(cfg.get("ssllabs_email", ""))

        guideline_ids  = cfg.get("guidelines",
                                  ["nist_800_131a", "bsi_tr02102", "ccn_stic_221"])
        guidelines_dir = cfg.get("guidelines_dir",
                                  os.path.join(os.path.dirname(__file__), "..", "guidelines"))
        self.assessor = CryptoAssessor(guideline_ids, guidelines_dir)

    def scan_domains(self, domains: list, sector: str = "", region: str = "",
                     country_code: str = "", country: str = "",
                     use_shodan: bool = False, progress_callback=None) -> str:
        """Scan a list of domains. Returns run_id."""
        logger.info(
            f"Starting scan: {len(domains)} domains | "
            f"Shodan={'yes' if use_shodan and self.shodan.available else 'no'} | "
            f"chain={self.do_chain} | cipher_enum={self.do_cipher_enum} | "
            f"cdn={self.do_cdn}"
        )
        run_id = self.db.create_run(domains, sector=sector, region=region,
                                    country_code=country_code, country=country)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(self._scan_domain, domain, run_id, use_shodan): domain
                    for domain in domains
                }
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    domain = futures[future]
                    completed += 1
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Scan failed for {domain}: {e}")
                    if progress_callback:
                        progress_callback(completed, len(domains), domain)
            self.db.finish_run(run_id, "completed")
            logger.info(f"Scan complete. run_id={run_id}")
        except Exception as e:
            self.db.finish_run(run_id, "failed")
            logger.error(f"Scan run {run_id} failed: {e}")
            raise
        return run_id

    def reassess_run(self, run_id: str, guideline_ids: list = None) -> str:
        """Re-assess a previous run against (updated) guidelines. No network traffic."""
        logger.info(f"Re-assessing run {run_id} with guidelines: {guideline_ids}")
        runs     = self.db.list_runs(200)
        original = next((r for r in runs if r["run_id"] == run_id), None)
        if not original:
            raise ValueError(f"Run {run_id} not found")

        domains      = json.loads(original.get("domain_list", "[]"))
        new_assessor = CryptoAssessor(
            guideline_ids or list(self.assessor.guidelines.keys()),
            os.path.join(os.path.dirname(__file__), "..", "guidelines")
        )
        new_run_id = self.db.create_run(
            domains,
            sector=original.get("sector", ""),
            region=original.get("region", ""),
            country_code=original.get("country_code", ""),
            country=original.get("country", ""),
            notes=f"Re-assessment of run {run_id}"
        )
        for domain in domains:
            raw_scans  = self.db.get_domain_scans(domain, run_id)
            # Re-assessment reuses stored scan data; no new network calls
            extra = self.db.get_domain_extra(domain, run_id)
            assessment = new_assessor.assess_domain(
                domain, raw_scans,
                chain_analysis=extra.get("chain"),
                cipher_enum=extra.get("cipher_enum"),
                cdn_result=extra.get("cdn"),
            )
            self.db.save_assessment(new_run_id, assessment.to_dict())
        self.db.finish_run(new_run_id, "completed")
        logger.info(f"Re-assessment complete. new_run_id={new_run_id}")
        return new_run_id

    def _scan_domain(self, domain: str, run_id: str, use_shodan: bool):
        """Full scan pipeline for one domain."""
        results = []
        primary_port = 443

        # ── 1. Shodan ─────────────────────────────────────────────
        if use_shodan and self.shodan.available:
            shodan_results = self.shodan.get_host_crypto(domain)
            if shodan_results:
                for r in shodan_results:
                    self.db.save_scan_result(run_id, r)
                results = shodan_results
                logger.debug(f"{domain}: {len(results)} services via Shodan")

        # ── 2. Direct probing ─────────────────────────────────────
        if not results:
            all_probe_ports = list(self.ports)
            if self.use_starttls:
                all_probe_ports += [p for p in STARTTLS_PORT_SET if p not in all_probe_ports]

            open_services = discover_tls_services(
                domain, ports=all_probe_ports,
                timeout=min(self.timeout, 5),
                include_starttls=self.use_starttls
            )

            tlsa       = get_tlsa_records(domain, 443)
            has_dnssec = check_dnssec(domain)

            probed_any = False
            for svc in open_services:
                probed_any = True
                if svc.port == 443:
                    primary_port = 443
                r_dict = (
                    probe_tls(domain, svc.port, self.timeout).to_dict()
                    if svc.tls_direct
                    else probe_starttls(domain, svc.port, self.timeout)
                )
                r_dict["has_dane"]   = len(tlsa) > 0
                r_dict["has_dnssec"] = has_dnssec
                self.db.save_scan_result(run_id, r_dict)
                if r_dict.get("success"):
                    results.append(r_dict)

            if not probed_any:
                r_dict = probe_tls(domain, 443, self.timeout).to_dict()
                self.db.save_scan_result(run_id, r_dict)
                if r_dict.get("success"):
                    results.append(r_dict)

        # Extract leaf cert SANs for CDN detection
        cert_sans: list[str] = []
        for r in results:
            cert = r.get("certificate") or {}
            if isinstance(cert, dict):
                cert_sans = cert.get("san_domains") or []
                if cert_sans:
                    break

        # ── 3. Certificate chain analysis ─────────────────────────
        chain_result = None
        chain_extra_findings: list[dict] = []
        if self.do_chain and results:
            try:
                chain_result = analyse_chain(
                    domain, port=primary_port, timeout=self.timeout
                )
                chain_extra_findings = chain_findings(chain_result)
                self.db.save_domain_extra(run_id, domain, "chain",
                                           chain_result.to_dict())
                logger.debug(
                    f"{domain} chain: len={chain_result.chain_length} "
                    f"complete={chain_result.chain_complete}"
                )
            except Exception as e:
                logger.debug(f"Chain analysis failed for {domain}: {e}")

        # ── 4. Active cipher enumeration ──────────────────────────
        enum_result = None
        enum_extra_findings: list[dict] = []
        if self.do_cipher_enum and results:
            try:
                enum_result = enumerate_ciphers(
                    domain, port=primary_port,
                    timeout=min(self.timeout, 6),
                    max_workers=8
                )
                enum_extra_findings = cipher_enum_findings(enum_result)
                self.db.save_domain_extra(run_id, domain, "cipher_enum",
                                           enum_result.to_dict())
                logger.debug(
                    f"{domain} cipher_enum: {len(enum_result.supported_ciphers)} ciphers "
                    f"dis={enum_result.disallowed_count}"
                )
            except Exception as e:
                logger.debug(f"Cipher enum failed for {domain}: {e}")

        # ── 4c. Offered key-exchange groups (authoritative for PQC) ─
        # Grades on what the server OFFERS, not what our client negotiates:
        # negotiation varies by client, offered support does not.
        group_result = None
        if results:
            try:
                group_result = enumerate_groups(
                    domain, port=primary_port,
                    timeout=min(self.timeout, 6),
                )
                # NOTE: PQC findings are emitted by the assessor (which knows the
                # grading basis) — not merged here, to avoid duplicate findings.
                self.db.save_domain_extra(run_id, domain, "group_enum",
                                           group_result.to_dict())
                logger.debug(
                    f"{domain} group_enum: offered={group_result.offered_groups} "
                    f"pqc={group_result.pqc_groups}"
                )
            except Exception as e:
                logger.debug(f"Group enumeration failed for {domain}: {e}")

        # ── 4b. SSL Labs cached report (display only — no scoring) ─
        # Cache-only lookup (fromCache=on): never triggers a new SSL Labs
        # assessment during a scan run. Fresh assessments are on-demand
        # from the domain detail view.
        if self.ssllabs_enabled and self.ssllabs.available and results:
            try:
                ssllabs_summary = self.ssllabs.get_cached(domain)
                if ssllabs_summary:
                    self.db.save_domain_extra(run_id, domain, "ssllabs",
                                               ssllabs_summary)
                    logger.debug(
                        f"{domain} ssllabs: grade={ssllabs_summary.get('grade')} "
                        f"(cached {ssllabs_summary.get('test_time')})"
                    )
            except Exception as e:
                logger.debug(f"SSL Labs lookup failed for {domain}: {e}")

        # ── 5. CDN detection ──────────────────────────────────────
        cdn_result = None
        cdn_extra_findings: list[dict] = []
        if self.do_cdn:
            try:
                cdn_result = detect_cdn(
                    domain, port=primary_port,
                    cert_sans=cert_sans, timeout=self.timeout
                )
                cdn_extra_findings = cdn_findings(cdn_result)
                self.db.save_domain_extra(run_id, domain, "cdn",
                                           cdn_result.to_dict())
                if cdn_result.detected:
                    logger.debug(
                        f"{domain} CDN: {cdn_result.cdn_name} "
                        f"({cdn_result.confidence}) PQC={cdn_result.pqc_support}"
                    )
            except Exception as e:
                logger.debug(f"CDN detection failed for {domain}: {e}")

        # ── 6. Assess ─────────────────────────────────────────────
        assessment = self.assessor.assess_domain(
            domain, results,
            chain_analysis=chain_result.to_dict() if chain_result else None,
            cipher_enum=enum_result.to_dict() if enum_result else None,
            cdn_result=cdn_result.to_dict() if cdn_result else None,
            group_enum=group_result.to_dict() if group_result else None,
            extra_findings=(
                chain_extra_findings + enum_extra_findings + cdn_extra_findings
            ),
            service_type=_port_to_service_type(primary_port),
        )
        self.db.save_assessment(run_id, assessment.to_dict())
