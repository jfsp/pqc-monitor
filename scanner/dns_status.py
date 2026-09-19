#!/usr/bin/env python3
"""
PQC-Monitor: DNS presence check for no-TLS domains

Splits level="na" (no reachable TLS service) domains into:

  resolvable   — has an A or AAAA address. Something may come online on it,
                 so it stays in the monthly no-TLS rescan.
  nxdomain     — the name no longer exists in DNS.            ┐ "unresolvable":
  no_address   — the name exists but has no A/AAAA record     ┘ not scannable,
                 (e.g. only TXT/MX, DMARC/DKIM-only names).     left out of scans
  dns_error    — timeout / SERVFAIL. Unknown; not scanned this cycle and
                 NOT marked unresolvable. Re-checked next cycle.

Results are stored in domain_extra (data_type='dns_status') under the
domain's latest run — no schema change. Each record carries `since`, the
first time the current status was observed, so "disappeared on <date>" is
preserved across monthly re-checks. Unresolvable domains are re-checked
(cheaply, DNS only) every cycle and rejoin the rescan if they resolve again.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

logger = logging.getLogger(__name__)

try:
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False

DATA_TYPE = "dns_status"
RESOLVABLE = "resolvable"
NXDOMAIN = "nxdomain"
NO_ADDRESS = "no_address"
DNS_ERROR = "dns_error"
UNRESOLVABLE = frozenset({NXDOMAIN, NO_ADDRESS})

STATUS_LABELS = {
    RESOLVABLE: "Resolves",
    NXDOMAIN:   "Not in DNS (NXDOMAIN)",
    NO_ADDRESS: "No A/AAAA record",
    DNS_ERROR:  "DNS lookup failed",
}


def _query(resolver, name: str, rtype: str):
    """(status, [addresses]) for one record type."""
    try:
        ans = resolver.resolve(name, rtype)
        return RESOLVABLE, [str(r) for r in ans]
    except dns.resolver.NXDOMAIN:
        return NXDOMAIN, []
    except dns.resolver.NoAnswer:
        return NO_ADDRESS, []
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return DNS_ERROR, []   # LifetimeTimeout subclasses Timeout
    except dns.exception.DNSException:
        return DNS_ERROR, []


def classify(domain: str, timeout: float = 5.0,
             resolver_factory: Optional[Callable] = None) -> tuple:
    """Return (status, addresses) for *domain*. Retries once on DNS errors."""
    if not HAS_DNSPYTHON and resolver_factory is None:
        return DNS_ERROR, []
    make = resolver_factory or (lambda: dns.resolver.Resolver())
    for attempt in (1, 2):
        resolver = make()
        try:
            resolver.lifetime = timeout
        except Exception:
            pass
        st_a, addrs = _query(resolver, domain, "A")
        if st_a == RESOLVABLE:
            return RESOLVABLE, addrs
        if st_a == NXDOMAIN:
            return NXDOMAIN, []
        st_aaaa, addrs6 = _query(resolver, domain, "AAAA")
        if st_aaaa == RESOLVABLE:
            return RESOLVABLE, addrs6
        if st_aaaa == NXDOMAIN:
            return NXDOMAIN, []
        if st_a == NO_ADDRESS and st_aaaa == NO_ADDRESS:
            return NO_ADDRESS, []
        # at least one lookup errored — retry once before reporting
    return DNS_ERROR, []


def refresh_dns_status(db, domains: Iterable[str], workers: int = 32,
                       timeout: float = 5.0,
                       classify_fn: Callable = classify) -> dict:
    """
    Classify *domains* and persist the result. Returns
    {"by_status": {status: count}, "status": {domain: status}}.
    """
    domains = sorted(set(domains))
    if not domains:
        return {"by_status": {}, "status": {}}
    run_ids = db.latest_run_ids_bulk()
    previous = db.latest_extra_bulk(DATA_TYPE)
    now = datetime.now(timezone.utc).isoformat()

    def _one(d):
        try:
            return d, classify_fn(d, timeout=timeout)
        except Exception as e:  # classification must never abort the batch
            logger.debug("dns_status %s: %s", d, e)
            return d, (DNS_ERROR, [])

    results = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for d, (status, addrs) in ex.map(_one, domains):
            results[d] = (status, addrs)

    counts: dict = {}
    status_map = {}
    for d, (status, addrs) in results.items():
        counts[status] = counts.get(status, 0) + 1
        status_map[d] = status
        prev = previous.get(d) if isinstance(previous.get(d), dict) else {}
        since = prev.get("since") if prev.get("status") == status else now
        blob = {
            "status": status,
            "label": STATUS_LABELS.get(status, status),
            "addresses": addrs[:4],
            "checked_at": now,
            "since": since or now,
            "previous_status": prev.get("status") if prev.get("status") != status else prev.get("previous_status"),
        }
        run_id = run_ids.get(d)
        if run_id:
            db.save_domain_extra(run_id, d, DATA_TYPE, blob)
    logger.info("DNS status for %d no-TLS domain(s): %s", len(domains),
                ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return {"by_status": counts, "status": status_map}


def unresolvable_domains(db) -> dict:
    """{domain: blob} for domains whose latest dns_status is unresolvable.
    Callers must intersect with the CURRENT no-TLS set: a domain that has
    since come back (and been scanned) keeps its old dns_status record."""
    return {d: b for d, b in db.latest_extra_bulk(DATA_TYPE).items()
            if isinstance(b, dict) and b.get("status") in UNRESOLVABLE}
