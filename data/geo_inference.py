#!/usr/bin/env python3
"""
PQC-Monitor: Geographic inference from domain TLDs.

Reads data/tld_geo.csv (user-editable) to map ccTLDs to country_code,
country display name, and region.

Inference rules:
  - Generic TLDs (.com, .net, .org, .io, .gov, .edu, .mil, .int, .co)
    carry no geographic signal and are ignored.
  - If the domain list contains exactly one distinct ccTLD → infer.
  - If the domain list contains multiple distinct ccTLDs → no inference.
  - If the domain list contains only generic TLDs → no inference.

Returns a GeoInferenceResult with the inferred values and a human-readable
message suitable for CLI output.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# TLDs that carry no geographic signal — always excluded from inference
GENERIC_TLDS = frozenset({
    "com", "net", "org", "io", "gov", "edu", "mil", "int",
    "co", "info", "biz", "name", "pro", "aero", "coop", "museum",
    "app", "dev", "cloud", "online", "site", "web", "store",
    "tech", "digital", "global", "world",
})

_DEFAULT_CSV = os.path.join(os.path.dirname(__file__), "tld_geo.csv")


def _load_table(csv_path: str = _DEFAULT_CSV) -> dict[str, dict]:
    """
    Load tld_geo.csv into a dict keyed by lowercase TLD.
    Returns {} and logs a warning if the file is missing.
    """
    table: dict[str, dict] = {}
    if not os.path.exists(csv_path):
        logger.warning(f"tld_geo.csv not found at {csv_path} — geo inference disabled")
        return table
    try:
        with open(csv_path, encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 3)
                if len(parts) != 4:
                    logger.debug(f"tld_geo.csv line {lineno}: expected 4 fields, got {len(parts)} — skipped")
                    continue
                tld, cc, country, region = (p.strip() for p in parts)
                if tld:
                    table[tld.lower()] = {
                        "country_code": cc.upper(),
                        "country":      country,
                        "region":       region,
                    }
    except Exception as exc:
        logger.error(f"Failed to load tld_geo.csv: {exc}")
    return table


def _extract_tld(domain: str) -> str:
    """Return the rightmost label of a domain, lowercased."""
    return domain.strip().rstrip(".").rsplit(".", 1)[-1].lower()


@dataclass
class GeoInferenceResult:
    """Result of a geo inference attempt."""
    country_code: str = ""
    country:      str = ""
    region:       str = ""
    inferred:     bool = False   # True when values were auto-derived from TLDs
    message:      str = ""       # CLI-ready feedback line


def infer_from_domains(
    domains: list[str],
    csv_path: str = _DEFAULT_CSV,
) -> GeoInferenceResult:
    """
    Infer country_code, country, and region from a list of domain names.

    Returns a GeoInferenceResult. If inference is not possible the
    country/region fields are empty strings and inferred=False.
    The .message field is always set for CLI display.
    """
    table = _load_table(csv_path)

    if not table:
        return GeoInferenceResult(
            message="→ Country inference skipped: tld_geo.csv not available"
        )

    # Extract ccTLDs only (skip generic TLDs and anything not in the table)
    cc_tlds: list[str] = []
    for d in domains:
        tld = _extract_tld(d)
        if tld in GENERIC_TLDS:
            continue
        if tld in table:
            cc_tlds.append(tld)
        # unknown TLD (e.g. new gTLD not in table) → silently ignored

    if not cc_tlds:
        return GeoInferenceResult(
            message="→ Country inference skipped: no ccTLDs found in domain list"
        )

    distinct = set(cc_tlds)

    if len(distinct) > 1:
        sorted_tlds = ", ".join(f".{t}" for t in sorted(distinct))
        return GeoInferenceResult(
            message=f"→ Country inference skipped: multiple ccTLDs found ({sorted_tlds})"
        )

    # Single ccTLD — infer
    tld = next(iter(distinct))
    entry = table[tld]
    msg = (
        f"→ Inferred from .{tld}: "
        f"{entry['country_code']} – {entry['country']} / {entry['region']}"
    )
    return GeoInferenceResult(
        country_code=entry["country_code"],
        country=entry["country"],
        region=entry["region"],
        inferred=True,
        message=msg,
    )


def infer_and_fill(
    domains: list[str],
    country_code: str = "",
    country:      str = "",
    region:       str = "",
    csv_path: str = _DEFAULT_CSV,
) -> GeoInferenceResult:
    """
    Convenience wrapper used by CLI commands.

    If country_code is already provided by the operator, skip inference
    and return a result reflecting the explicit values.  Otherwise run
    inference and fill any empty fields from the result.

    region is filled independently: if not provided and inference
    succeeds, the inferred region is used.
    """
    if country_code:
        # Operator supplied explicit country — honour it, no inference
        return GeoInferenceResult(
            country_code=country_code,
            country=country,
            region=region,
            inferred=False,
            message=f"→ Country: {country_code}{' – ' + country if country else ''}"
                    + (f" / {region}" if region else ""),
        )

    result = infer_from_domains(domains, csv_path=csv_path)

    # Fill region independently if not supplied
    if not region and result.inferred:
        region = result.region
    elif region:
        # Operator gave a region explicitly — keep it even if inference ran
        result.region = region

    result.country_code = result.country_code or ""
    result.country      = result.country      or ""
    result.region       = region              or result.region

    return result
