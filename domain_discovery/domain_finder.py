#!/usr/bin/env python3
"""
PQC-Monitor: Domain Discovery
Natural language → domain list using AI-assisted OSINT.
E.g.: "financial institutions in Spain" → [banco.es, bbva.com, ...]

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import logging
import re
import os
import socket
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


DOMAIN_DISCOVERY_SYSTEM = """You are a cybersecurity researcher assistant helping to build a
list of internet domains for a specific sector and geographic region for the purpose of
non-intrusive cryptographic posture assessment.

When given a sector/region query, respond ONLY with a JSON object in the following format:
{
  "query_interpreted": "brief description of what was understood",
  "sector": "sector name",
  "region": "region/country name",
  "domains": ["domain1.tld", "domain2.tld", ...],
  "notes": "any caveats or notes"
}

Rules:
- Include only REAL, publicly known domains of organisations in the specified sector/region
- Focus on the primary public-facing domain (e.g., www.bbva.com not intranet.bbva.com)
- Include regulators, central institutions, and major private players in the sector
- Do NOT invent domains - only include ones you are confident exist
- Aim for 20-50 domains for broad sectors, fewer for narrow ones
- The domains will be used for passive TLS/certificate scanning only
- Include both national institutions and major international ones with presence in the region
"""


class DomainDiscovery:
    """
    Translates natural language sector/region descriptions into domain lists.
    Uses Anthropic API if available; falls back to curated offline lists.
    """

    def __init__(self, anthropic_api_key: str = "", model: str = "claude-sonnet-4-20250514"):
        self.api_key = anthropic_api_key
        self.model = model
        self.client = None

        if HAS_ANTHROPIC and anthropic_api_key:
            self.client = anthropic.Anthropic(api_key=anthropic_api_key)
            logger.info("Domain discovery: Anthropic API ready")
        else:
            logger.info("Domain discovery: running in offline mode (curated lists only)")

    def discover(self, query: str, max_domains: int = 50,
                 validate: bool = True) -> dict:
        """
        Main entry point. Takes a natural language query and returns
        a dict with domain list and metadata.
        """
        logger.info(f"Domain discovery query: '{query}'")

        result = {
            "query": query,
            "domains": [],
            "source": "unknown",
            "notes": ""
        }

        if self.client:
            result = self._discover_via_ai(query, max_domains)
        else:
            result = self._discover_offline(query, max_domains)

        # Validate domains (DNS resolution check)
        if validate and result.get("domains"):
            logger.info(f"Validating {len(result['domains'])} domains...")
            result["domains"] = self._validate_domains(result["domains"])
            result["validated"] = True

        logger.info(f"Discovered {len(result.get('domains',[]))} domains for: {query}")
        return result

    def _discover_via_ai(self, query: str, max_domains: int) -> dict:
        """Use Anthropic API to generate domain list."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=DOMAIN_DISCOVERY_SYSTEM,
                messages=[{
                    "role": "user",
                    "content": f"Generate a domain list for: {query}\n"
                               f"Limit to {max_domains} most important domains."
                }]
            )
            text = message.content[0].text
            # Strip any markdown
            text = re.sub(r"```json\s*|\s*```", "", text).strip()
            data = json.loads(text)
            data["source"] = "anthropic_ai"
            return data
        except json.JSONDecodeError as e:
            logger.error(f"AI response parse error: {e}")
            return self._discover_offline(query, max_domains)
        except Exception as e:
            logger.error(f"AI domain discovery error: {e}")
            return self._discover_offline(query, max_domains)

    def _discover_offline(self, query: str, max_domains: int) -> dict:
        """
        Fallback: match query against curated sector/region domain lists.
        """
        query_lower = query.lower()

        # Determine sector
        sector = "generic"
        for s in OFFLINE_DOMAINS:
            if any(kw in query_lower for kw in SECTOR_KEYWORDS.get(s, [])):
                sector = s
                break

        # Determine region
        region = "global"
        for r in REGION_KEYWORDS:
            if any(kw in query_lower for kw in REGION_KEYWORDS[r]):
                region = r
                break

        domains = []
        # Try sector+region specific
        key = f"{sector}_{region}"
        domains.extend(OFFLINE_DOMAINS.get(key, []))
        # Fall back to sector global
        domains.extend(OFFLINE_DOMAINS.get(sector, []))
        # Deduplicate
        seen = set()
        unique = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique.append(d)

        return {
            "query": query,
            "query_interpreted": f"Offline lookup: {sector} in {region}",
            "sector": sector,
            "region": region,
            "domains": unique[:max_domains],
            "source": "offline_curated",
            "notes": "Offline mode - set ANTHROPIC_API_KEY for AI-powered discovery"
        }

    def _validate_domains(self, domains: list) -> list:
        """Filter domains to those that resolve via DNS."""
        valid = []
        for domain in domains:
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(domain)
                valid.append(domain)
            except (socket.gaierror, socket.timeout):
                logger.debug(f"Domain does not resolve: {domain}")
        return valid

    def save_domain_list(self, domains: list, filename: str):
        """Save domain list to file, one domain per line."""
        with open(filename, "w") as f:
            f.write("\n".join(domains) + "\n")
        logger.info(f"Saved {len(domains)} domains to {filename}")

    def load_domain_list(self, filename: str) -> list:
        """Load domain list from file."""
        domains = []
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
        return domains


# ──────────────────────────────────────────────────────────────
# Sector keyword matching
# ──────────────────────────────────────────────────────────────

SECTOR_KEYWORDS = {
    "finance": ["financial", "finance", "bank", "banking", "insurance", "fintech",
                "stock", "exchange", "payment", "credit", "invest"],
    "healthcare": ["health", "hospital", "medical", "pharmaceutical", "pharma",
                   "clinical", "nhs", "sanidad"],
    "energy": ["energy", "power", "electricity", "utility", "grid", "nuclear",
               "oil", "gas", "renewables"],
    "government": ["government", "public", "ministry", "ministry", "administr",
                   "gov", "federal", "national", "state"],
    "telecom": ["telecom", "telecommunications", "isp", "internet", "mobile",
                "operator", "network"],
    "transport": ["transport", "logistics", "airline", "airport", "railway",
                  "port", "shipping"],
}

REGION_KEYWORDS = {
    "spain": ["spain", "spanish", "españa", "iberian"],
    "germany": ["germany", "german", "deutschland"],
    "france": ["france", "french", "français"],
    "europe": ["europe", "european", "eu", "emea"],
    "uk": ["uk", "britain", "british", "england"],
    "usa": ["usa", "united states", "american", "us "],
    "global": ["global", "worldwide", "international"],
}

# ──────────────────────────────────────────────────────────────
# Curated offline domain lists
# ──────────────────────────────────────────────────────────────

OFFLINE_DOMAINS = {
    "finance_spain": [
        "bancosantander.es", "bbva.es", "caixabank.es", "bankia.es",
        "sabadell.com", "bankinter.com", "unicaja.es", "ibercaja.es",
        "bde.es", "cnmv.es", "dgsfp.mineco.gob.es", "mapfre.com",
        "axa.es", "allianz.es", "mutua-madrilena.es"
    ],
    "finance_europe": [
        "ecb.europa.eu", "eba.europa.eu", "esma.europa.eu", "eiopa.europa.eu",
        "bnpparibas.com", "deutschebank.com", "ing.com", "unicredit.com",
        "santander.com", "bbva.com", "hsbc.com", "barclays.com",
        "credit-suisse.com", "ubs.com", "rabobank.com"
    ],
    "finance_germany": [
        "bundesbank.de", "bafin.de", "deutschebank.de", "commerzbank.de",
        "hypovereinsbank.de", "sparkasse.de", "volksbanken-raiffeisenbanken.de",
        "dzbank.de", "kfw.de", "aareal-bank.com"
    ],
    "finance": [
        "swift.com", "bis.org", "imf.org", "worldbank.org",
        "visa.com", "mastercard.com", "paypal.com", "stripe.com"
    ],
    "healthcare_europe": [
        "who.int", "ecdc.europa.eu", "ema.europa.eu",
        "nhs.uk", "inrs.fr", "rki.de", "isciii.es"
    ],
    "government_spain": [
        "administracion.gob.es", "seap.minhac.gob.es", "minhap.gob.es",
        "boe.es", "ccn-cert.cni.es", "incibe.es", "cnpic.es",
        "agpd.es", "aeat.es", "seg-social.es"
    ],
    "government_europe": [
        "europa.eu", "ec.europa.eu", "europarl.europa.eu",
        "enisa.europa.eu", "cert.europa.eu", "eeas.europa.eu"
    ],
    "telecom_spain": [
        "telefonica.com", "movistar.es", "orange.es", "vodafone.es",
        "masmovil.es", "yoigo.com"
    ],
    "energy_europe": [
        "entsoe.eu", "iea.org", "edf.fr", "rwe.com", "e-on.com",
        "engie.com", "iberdrola.com", "endesa.com", "repsol.com"
    ],
    "generic": [
        "example.com", "cloudflare.com", "google.com",
        "amazon.com", "microsoft.com"
    ]
}
