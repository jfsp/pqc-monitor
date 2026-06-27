#!/usr/bin/env python3
"""
PQC-Monitor: DNS Deep-Dive Enumerator (T3-1)
Enumerates all sub-services of a domain via DNS record walking,
CT log SAN harvesting, a built-in subdomain wordlist, and optional
DNSDumpster scraping.  Results feed the scan pipeline with a
candidate list of {host, port, service_type} tuples.

Sources (in order of reliability):
  1. Direct DNS queries  — A/AAAA, MX, NS, CNAME, TXT, SRV
  2. CT SAN harvest      — unique FQDNs from crt.sh certificate SANs
  3. Wordlist brute-force — ~120 common prefixes resolved concurrently
  4. DNSDumpster API     — official REST API (requires api key)
  5. Passive DNS fallback — SRV probing + zone transfer attempt when
                            DNSDumpster quota is exceeded or unavailable

Results are deduplicated and stored in domain_extra as type 'dns_enum'.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import concurrent.futures
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    import dns.zone
    import dns.query
    import dns.xfr
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not installed — DNS enumeration will be limited")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Session-level DNSDumpster quota flag ──────────────────────────────────────
# Set to True the first time a quota-exceeded response is detected.
# All subsequent calls skip the API for the rest of the process lifetime.
_DNSDUMPSTER_QUOTA_EXHAUSTED: bool = False


class DnsDumpsterQuotaError(Exception):
    """Raised when the DNSDumpster daily quota is exhausted."""


# ── Port→service_type mapping (mirrors orchestrator.SERVICE_TYPE_MAP) ─────────

_PORT_SERVICE: dict[int, str] = {
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
}

# Ports we'll suggest scanning on discovered hosts
_DEFAULT_PROBE_PORTS = [443, 25, 587, 993, 636]

# ── Subdomain wordlist ─────────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST: list[str] = [
    # Web / application
    "www", "web", "app", "portal", "secure", "login", "auth", "sso",
    "api", "api2", "rest", "graphql", "gateway", "proxy",
    # Mail
    "mail", "smtp", "imap", "pop", "mx", "mx1", "mx2", "email",
    "webmail", "outlook", "exchange", "autodiscover",
    # Infrastructure
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "vpn", "remote", "gateway", "firewall", "fw", "ras",
    "cdn", "static", "assets", "media", "img", "images",
    # Admin / management
    "admin", "manage", "mgmt", "panel", "dashboard", "monitor",
    "syslog", "log", "logs", "metrics",
    # Dev / staging
    "dev", "staging", "stage", "test", "qa", "uat", "sandbox",
    "preview", "beta", "demo",
    # LDAP / directory
    "ldap", "ldaps", "dc", "dc1", "dc2", "ad", "dir",
    # Misc services
    "ftp", "sftp", "ssh", "rdp", "citrix",
    "intranet", "internal", "extranet",
    "shop", "store", "pay", "payment", "billing",
    "support", "helpdesk", "servicedesk",
    "wiki", "docs", "confluence", "jira",
    "git", "gitlab", "github", "svn", "ci", "jenkins",
    "cloud", "aws", "azure",
    # Common numbered hosts
    "host1", "host2", "server", "server1", "server2",
    # Geographic/regional
    "eu", "us", "uk", "de", "fr", "es",
]

# ── SRV service prefixes to probe in passive fallback ─────────────────────────
# Format: (service, proto) → port hint
_SRV_SERVICES: list[tuple[str, str]] = [
    ("_https",        "_tcp"),
    ("_http",         "_tcp"),
    ("_smtp",         "_tcp"),
    ("_submission",   "_tcp"),
    ("_smtps",        "_tcp"),
    ("_imap",         "_tcp"),
    ("_imaps",        "_tcp"),
    ("_pop3",         "_tcp"),
    ("_pop3s",        "_tcp"),
    ("_ldap",         "_tcp"),
    ("_ldaps",        "_tcp"),
    ("_sip",          "_tcp"),
    ("_sip",          "_udp"),
    ("_xmpp-client",  "_tcp"),
    ("_xmpp-server",  "_tcp"),
    ("_autodiscover", "_tcp"),
    ("_dav",          "_tcp"),
    ("_davs",         "_tcp"),
    ("_ftp",          "_tcp"),
    ("_sftp",         "_tcp"),
    ("_ssh",          "_tcp"),
]

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class TlsCandidate:
    """A {host, port, service_type} tuple recommended for TLS scanning."""
    host: str
    port: int
    service_type: str
    source: str  # dns_record | ct_san | wordlist | dnsdumpster | passive_dns

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DnsEnumerationResult:
    domain: str
    a_records: list[str]       = field(default_factory=list)
    aaaa_records: list[str]    = field(default_factory=list)
    mx_hosts: list[str]        = field(default_factory=list)
    ns_hosts: list[str]        = field(default_factory=list)
    cname_chain: list[str]     = field(default_factory=list)
    spf_record: Optional[str]  = None
    dmarc_record: Optional[str] = None
    subdomains: list[str]      = field(default_factory=list)   # all discovered FQDNs
    tls_candidates: list[dict] = field(default_factory=list)   # TlsCandidate dicts
    errors: list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _resolve(domain: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """
    Query *domain* for records of *rtype*.  Returns a list of string values.
    Empty list on NXDOMAIN / timeout / not-installed.
    """
    if not HAS_DNSPYTHON:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []
    except Exception as exc:
        logger.debug(f"DNS {rtype} query for {domain} failed: {exc}")
        return []


def _cname_chain(domain: str, max_depth: int = 8) -> list[str]:
    """Follow CNAME chain up to max_depth hops; returns list of targets."""
    chain: list[str] = []
    current = domain
    for _ in range(max_depth):
        targets = _resolve(current, "CNAME")
        if not targets:
            break
        target = targets[0].rstrip(".")
        chain.append(target)
        current = target
    return chain


def _txt_records(domain: str) -> tuple[Optional[str], Optional[str]]:
    """Return (spf_record, dmarc_record) from TXT queries."""
    spf = None
    dmarc = None
    for txt in _resolve(domain, "TXT"):
        clean = txt.strip('"')
        if clean.startswith("v=spf1") and spf is None:
            spf = clean
    for txt in _resolve(f"_dmarc.{domain}", "TXT"):
        clean = txt.strip('"')
        if clean.startswith("v=DMARC1") and dmarc is None:
            dmarc = clean
    return spf, dmarc


def _resolves(fqdn: str, timeout: float = 3.0) -> bool:
    """Quick check: does the FQDN have at least one A or AAAA record?"""
    if HAS_DNSPYTHON:
        return bool(_resolve(fqdn, "A", timeout) or _resolve(fqdn, "AAAA", timeout))
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(fqdn)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def _wordlist_subdomains(
    domain: str,
    wordlist: list[str],
    max_workers: int = 30,
    timeout: float = 3.0,
) -> list[str]:
    """Resolve wordlist prefixes against domain concurrently; return resolving FQDNs."""
    candidates = [f"{w}.{domain}" for w in wordlist]
    found: list[str] = []

    def check(fqdn: str) -> Optional[str]:
        return fqdn if _resolves(fqdn, timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for result in ex.map(check, candidates):
            if result:
                found.append(result)
    return found


def _ct_sans(domain: str) -> list[str]:
    """
    Harvest unique FQDNs from crt.sh certificate SANs for *domain*.
    Uses the same JSON endpoint as ct/ct_monitor.py.
    Returns a de-duplicated, lowercase list of FQDNs that are children
    of *domain* (wildcards stripped).
    """
    if not HAS_REQUESTS:
        return []
    url = f"https://crt.sh/?q=%.{domain}&output=json&exclude=expired"
    try:
        resp = requests.get(url, timeout=15, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.debug(f"CT SAN harvest failed for {domain}: {exc}")
        return []

    fqdns: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(f".{domain}") or name == domain:
                fqdns.add(name)
    return sorted(fqdns)


def _passive_dns_enum(domain: str, ns_hosts: list[str],
                      timeout: float = 5.0) -> list[str]:
    """
    Passive DNS fallback enumeration using only standard DNS queries.
    No external APIs — relies purely on dnspython.

    Techniques (all non-intrusive):
      • SRV record probing for well-known service prefixes
      • Zone transfer attempt (AXFR) against each authoritative NS
        — harmless: most servers refuse with REFUSED or NOTAUTH
      • TLD / ccTLD variants of the apex domain
      • Reverse-lookup PTR probing of the apex A records

    Returns a deduplicated, sorted list of FQDNs that are children of *domain*.
    """
    if not HAS_DNSPYTHON:
        return []

    fqdns: set[str] = set()

    # ── SRV records ───────────────────────────────────────────────
    for svc, proto in _SRV_SERVICES:
        qname = f"{svc}.{proto}.{domain}"
        for rec in _resolve(qname, "SRV", timeout):
            # SRV record: "priority weight port target"
            parts = rec.split()
            if len(parts) >= 4:
                target = parts[3].rstrip(".")
                if target and target != "." and (
                    target == domain or target.endswith(f".{domain}")
                ):
                    fqdns.add(target.lower())
            logger.debug(f"SRV {qname} → {rec}")

    # ── Zone transfer (AXFR) ──────────────────────────────────────
    # Attempt against each NS; virtually all public resolvers refuse this,
    # but internal / misconfigured NS sometimes allow it.
    for ns in ns_hosts:
        ns_clean = ns.rstrip(".")
        try:
            # Resolve NS to IP first (needed for dns.query.xfr)
            ns_ips = _resolve(ns_clean, "A", timeout)
            if not ns_ips:
                ns_ips = _resolve(ns_clean, "AAAA", timeout)
            if not ns_ips:
                continue
            ns_ip = ns_ips[0]
            logger.debug(f"Attempting AXFR for {domain} from {ns_clean} ({ns_ip})")
            xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout * 2)
            z = dns.zone.from_xfr(xfr)
            for name in z.nodes:
                fqdn = str(name)
                if fqdn == "@":
                    continue
                full = f"{fqdn}.{domain}".lower()
                fqdns.add(full)
                logger.info(f"AXFR {domain} via {ns_clean}: found {full}")
        except (dns.exception.FormError, dns.exception.Timeout,
                dns.xfr.TransferError, EOFError, OSError,
                PermissionError, ConnectionRefusedError) as exc:
            logger.debug(f"AXFR refused/failed for {domain} from {ns_clean}: {exc}")
        except Exception as exc:
            logger.debug(f"AXFR error for {domain} from {ns_clean}: {exc}")

    # ── TLD variants ──────────────────────────────────────────────
    # Try common ccTLD / gTLD siblings if the apex has a known extension.
    # e.g. example.es → try example.com, example.eu, example.org
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        apex, tld = parts
        alt_tlds = ["com", "net", "org", "eu", "int", "gov"]
        for alt in alt_tlds:
            if alt == tld:
                continue
            candidate = f"{apex}.{alt}"
            if _resolves(candidate, timeout):
                # It's a sibling domain, not a subdomain — add as a note
                # but don't include in the fqdns set (it's a different apex)
                logger.debug(f"TLD variant resolves: {candidate}")

    # ── PTR / reverse lookup of apex A records ────────────────────
    apex_a = _resolve(domain, "A", timeout)
    for ip in apex_a[:4]:   # limit to first 4 IPs
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
            if hostname != domain and hostname.endswith(f".{domain}"):
                fqdns.add(hostname)
                logger.debug(f"PTR {ip} → {hostname}")
        except (socket.herror, socket.gaierror):
            pass

    return sorted(fqdns)


def _dnsdumpster_subdomains(
    domain: str,
    api_key: str = "",
    timeout: int = 15,
) -> list[str]:
    """
    Query DNSDumpster for additional subdomains.

    If *api_key* is provided, uses the official REST API:
        GET https://api.dnsdumpster.com/domain/{domain}
        X-API-Key: <api_key>
    Rate limit: 1 request per 2 seconds (respected internally).
    Free plan: up to 50 records. Plus plan: up to 200/page with pagination.

    Without an API key, falls back to a best-effort HTML scrape of
    dnsdumpster.com (unofficial, CSRF-token based, may break without warning).
    The scrape path is kept for development/testing only — the API path is
    strongly preferred for production use.

    Returns a sorted, deduplicated list of FQDNs that are children of *domain*.
    Empty list on any failure.

    Raises DnsDumpsterQuotaError when the daily quota is exhausted so the
    caller can activate the passive DNS fallback.
    """
    if not HAS_REQUESTS:
        return []

    global _DNSDUMPSTER_QUOTA_EXHAUSTED
    if _DNSDUMPSTER_QUOTA_EXHAUSTED:
        raise DnsDumpsterQuotaError("Daily quota already exhausted this session")

    if api_key:
        return _dnsdumpster_api(domain, api_key, timeout)
    return _dnsdumpster_scrape(domain, timeout)


def _dnsdumpster_api(
    domain: str,
    api_key: str,
    timeout: int,
    paginate: bool = True,
) -> list[str]:
    """
    Query the DNSDumpster REST API.

    Authentication : X-API-Key header
    Endpoint       : GET https://api.dnsdumpster.com/domain/{domain}
    Rate limit     : 1 request per 2 seconds (enforced here with a sleep)
    Pagination     : ?page=N  (Plus plan; free plan max 50 records)

    Response structure (from https://dnsdumpster.com/developer/):
      {
        "a":     [ {"host": "...", "ips": [{...}]}, ... ],
        "cname": [ ... ],
        "mx":    [ ... ],
        "ns":    [ ... ],
        "txt":   [ "v=spf1 ...", ... ],
        "total_a_recs": N
      }

    We harvest unique FQDNs that are children of *domain* from all record
    sections.  TXT records are strings (no host field) so they are skipped
    for FQDN extraction but logged for SPF/DMARC awareness.

    Raises DnsDumpsterQuotaError on {"error": "Daily quota exceeded"}.
    """
    import time

    global _DNSDUMPSTER_QUOTA_EXHAUSTED

    base_url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers  = {
        "X-API-Key":    api_key,
        "Accept":       "application/json",
        "User-Agent":   "PQC-Monitor/1.3 (security research)",
    }
    fqdns: set[str] = set()
    page = 1

    while True:
        url = base_url if page == 1 else f"{base_url}?page={page}"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except Exception as exc:
            logger.warning(f"DNSDumpster request failed for {domain} (page {page}): {exc}")
            break

        # ── Quota detection: check raw text before JSON parsing ───────────────
        # DNSDumpster delivers {"error":"Daily quota exceeded"} as the body of
        # a 429.  Check the raw text first so we catch it regardless of whether
        # the body is valid JSON or whether resp.json() raises.
        raw_text = resp.text or ""
        if "quota" in raw_text.lower() or "daily" in raw_text.lower():
            _DNSDUMPSTER_QUOTA_EXHAUSTED = True
            logger.warning(
                f"DNSDumpster daily quota exceeded (HTTP {resp.status_code}) — "
                "disabling for this session, activating passive DNS fallback"
            )
            raise DnsDumpsterQuotaError(raw_text[:200])

        # ── Parse JSON body for structured error messages ──────────────────────
        try:
            data = resp.json()
        except Exception:
            data = {}

        if isinstance(data, dict) and data.get("error"):
            logger.warning(f"DNSDumpster API error for {domain}: {data['error']}")
            break

        if resp.status_code == 429:
            # Genuine per-request rate limit (no quota language in body)
            logger.warning(
                f"DNSDumpster rate limit hit for {domain} — "
                "respecting 2-second limit between requests"
            )
            time.sleep(2)
            continue

        if resp.status_code == 401:
            logger.warning("DNSDumpster API key rejected (401) — check X-API-Key value")
            break

        if resp.status_code == 403:
            logger.warning("DNSDumpster 403 — plan restriction for this endpoint")
            break

        if not resp.ok:
            logger.warning(
                f"DNSDumpster API error for {domain} (page {page}): "
                f"HTTP {resp.status_code}"
            )
            break

        # Harvest FQDNs from all record sections that carry a 'host' field
        # Actual keys: a, cname, mx, ns  (aaaa not documented but harmless to try)
        found_this_page = 0
        for section in ("a", "aaaa", "cname", "mx", "ns"):
            for record in data.get(section, []):
                host = record.get("host", "").lower().strip().rstrip(".")
                if host and (host == domain or host.endswith(f".{domain}")):
                    if host not in fqdns:
                        fqdns.add(host)
                        found_this_page += 1

        # TXT records are plain strings — log SPF/DMARC but no FQDNs to harvest
        for txt in data.get("txt", []):
            if txt.startswith("v=spf1") or txt.startswith("v=DMARC1"):
                logger.debug(f"DNSDumpster TXT for {domain}: {txt[:80]}")

        total = data.get("total_a_recs", 0)
        logger.debug(
            f"DNSDumpster page {page} for {domain}: "
            f"{found_this_page} new FQDNs (total_a_recs={total})"
        )

        # Paginate only if Plus plan has more records and pagination is enabled
        # Free plan: 50 records; Plus plan: 200/page.  Stop when page returns nothing new.
        if not paginate or found_this_page == 0:
            break

        # Respect the 2-second rate limit between paginated requests
        time.sleep(2)
        page += 1

        # Safety cap: never fetch more than 10 pages (2000 records)
        if page > 10:
            logger.debug(f"DNSDumpster: reached page cap for {domain}")
            break

    logger.info(
        f"DNSDumpster API: {len(fqdns)} unique FQDNs for {domain} "
        f"({page} page(s) fetched)"
    )
    return sorted(fqdns)


def _dnsdumpster_scrape(domain: str, timeout: int) -> list[str]:
    """
    Fallback HTML scrape of dnsdumpster.com (unofficial, best-effort).
    Uses CSRF-token extraction then a POST to the free search form.
    May break at any time if DNSDumpster changes their front-end.
    """
    session = requests.Session()
    base = "https://dnsdumpster.com"
    try:
        r = session.get(base, timeout=timeout,
                        headers={"User-Agent": "PQC-Monitor/1.2 (DNS research)"})
        r.raise_for_status()

        csrf = None
        for line in r.text.splitlines():
            if "csrfmiddlewaretoken" in line and "value=" in line:
                start = line.find('value="') + 7
                end   = line.find('"', start)
                csrf  = line[start:end]
                break
        if not csrf:
            logger.debug("DNSDumpster scrape: could not extract CSRF token")
            return []

        post = session.post(
            base,
            data={"csrfmiddlewaretoken": csrf, "targetip": domain, "user": "free"},
            headers={"Referer": base, "User-Agent": "PQC-Monitor/1.2 (DNS research)"},
            timeout=timeout,
        )
        post.raise_for_status()
        html = post.text
    except Exception as exc:
        logger.debug(f"DNSDumpster scrape failed for {domain}: {exc}")
        return []

    import re
    fqdns: set[str] = set()
    for match in re.finditer(
        r'<td[^>]*>\s*([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')\s*</td>',
        html
    ):
        fqdn = match.group(1).lower().strip()
        if fqdn.endswith(f".{domain}"):
            fqdns.add(fqdn)

    logger.debug(f"DNSDumpster scrape returned {len(fqdns)} hosts for {domain}")
    return sorted(fqdns)


def _build_candidates(
    domain: str,
    all_subdomains: list[str],
    mx_hosts: list[str],
    ns_hosts: list[str],
) -> list[TlsCandidate]:
    """
    Build TLS scan candidate list from all discovered hosts.
    Each host gets a candidate per default probe port.
    MX hosts → smtp candidates; NS hosts → no TLS probes by default.
    """
    candidates: list[TlsCandidate] = []
    seen: set[tuple[str, int]] = set()

    def add(host: str, port: int, source: str):
        host = host.rstrip(".").lower()
        key = (host, port)
        if key in seen:
            return
        seen.add(key)
        candidates.append(TlsCandidate(
            host=host,
            port=port,
            service_type=_PORT_SERVICE.get(port, "other"),
            source=source,
        ))

    # Primary domain itself
    for port in _DEFAULT_PROBE_PORTS:
        add(domain, port, "dns_record")

    # Subdomains → web + mail ports
    for sub in all_subdomains:
        for port in _DEFAULT_PROBE_PORTS:
            add(sub, port, "subdomain")

    # MX hosts → SMTP-specific ports only
    for mx in mx_hosts:
        for port in [25, 587, 465]:
            add(mx, port, "mx_record")

    return candidates


# ── Public API ────────────────────────────────────────────────────────────────

def is_dnsdumpster_quota_exhausted() -> bool:
    """Return True if DNSDumpster daily quota was hit this session."""
    return _DNSDUMPSTER_QUOTA_EXHAUSTED


def enumerate_domain(
    domain: str,
    use_wordlist: bool = True,
    use_ct: bool = True,
    use_dnsdumpster: bool = False,
    dnsdumpster_api_key: str = "",
    wordlist: list[str] = None,
    max_workers: int = 30,
    timeout: float = 5.0,
) -> DnsEnumerationResult:
    """
    Full DNS deep-dive for *domain*.

    Parameters
    ----------
    domain              Root domain to enumerate (e.g. "example.com")
    use_wordlist        Brute-force with built-in wordlist (default True)
    use_ct              Harvest SANs from crt.sh CT logs (default True)
    use_dnsdumpster     Query DNSDumpster (default False — requires explicit opt-in).
                        If *dnsdumpster_api_key* is set, uses the official API;
                        otherwise falls back to a fragile HTML scrape.
                        When the daily quota is exhausted, automatically falls
                        back to passive DNS enumeration for this and all
                        subsequent domains in the session.
    dnsdumpster_api_key Optional API key for api.dnsdumpster.com.
                        Configure via dns_enumeration.dnsdumpster_api_key in
                        config.yaml or the PQC_DNSDUMPSTER_KEY env variable.
    wordlist            Override built-in wordlist
    max_workers         Concurrency for wordlist resolution
    timeout             Per-query DNS timeout in seconds

    Returns
    -------
    DnsEnumerationResult with all discovered data and TLS candidates.
    """
    result = DnsEnumerationResult(domain=domain)
    wl = wordlist if wordlist is not None else SUBDOMAIN_WORDLIST
    all_subs: set[str] = set()

    # ── A / AAAA ──────────────────────────────────────────────────
    result.a_records    = _resolve(domain, "A",    timeout)
    result.aaaa_records = _resolve(domain, "AAAA", timeout)
    if not result.a_records and not result.aaaa_records:
        result.errors.append(f"Domain {domain} does not resolve")

    # ── CNAME chain ───────────────────────────────────────────────
    result.cname_chain = _cname_chain(domain)

    # ── MX ────────────────────────────────────────────────────────
    mx_raw = _resolve(domain, "MX", timeout)
    # MX records look like "10 mail.example.com." — extract host
    for rec in mx_raw:
        parts = rec.split()
        host = (parts[-1] if parts else rec).rstrip(".")
        if host and host not in result.mx_hosts:
            result.mx_hosts.append(host)
            all_subs.add(host)

    # ── NS ────────────────────────────────────────────────────────
    ns_raw = _resolve(domain, "NS", timeout)
    result.ns_hosts = [r.rstrip(".") for r in ns_raw]

    # ── TXT (SPF / DMARC) ─────────────────────────────────────────
    result.spf_record, result.dmarc_record = _txt_records(domain)

    # ── CT SAN harvest ────────────────────────────────────────────
    if use_ct:
        try:
            ct_subs = _ct_sans(domain)
            logger.debug(f"{domain}: CT SANs found {len(ct_subs)} subdomains")
            all_subs.update(ct_subs)
        except Exception as exc:
            result.errors.append(f"CT harvest error: {exc}")
            logger.warning(f"CT harvest failed for {domain}: {exc}")

    # ── Wordlist brute-force ──────────────────────────────────────
    if use_wordlist:
        try:
            wl_subs = _wordlist_subdomains(domain, wl, max_workers, timeout)
            logger.debug(f"{domain}: wordlist found {len(wl_subs)} subdomains")
            all_subs.update(wl_subs)
        except Exception as exc:
            result.errors.append(f"Wordlist error: {exc}")
            logger.warning(f"Wordlist enumeration failed for {domain}: {exc}")

    # ── DNSDumpster (with quota detection + passive fallback) ─────
    if use_dnsdumpster:
        try:
            dd_subs = _dnsdumpster_subdomains(domain, api_key=dnsdumpster_api_key)
            logger.debug(f"{domain}: DNSDumpster found {len(dd_subs)} subdomains")
            all_subs.update(dd_subs)
        except DnsDumpsterQuotaError:
            # Quota hit — fall through to passive DNS below
            logger.info(
                f"{domain}: DNSDumpster quota exhausted — "
                "running passive DNS fallback (SRV + AXFR attempt)"
            )
            use_passive = True
        except Exception as exc:
            result.errors.append(f"DNSDumpster error: {exc}")
            logger.debug(f"DNSDumpster failed for {domain}: {exc}")
            use_passive = False
        else:
            use_passive = False
    else:
        # When DNSDumpster is not enabled, still run passive DNS to get
        # SRV records and opportunistic AXFR — these are always safe.
        use_passive = True

    # ── Passive DNS fallback / supplement ────────────────────────
    if use_passive:
        try:
            passive_subs = _passive_dns_enum(domain, result.ns_hosts, timeout)
            if passive_subs:
                logger.info(
                    f"{domain}: passive DNS found {len(passive_subs)} additional hosts"
                )
            all_subs.update(passive_subs)
        except Exception as exc:
            result.errors.append(f"Passive DNS error: {exc}")
            logger.warning(f"Passive DNS failed for {domain}: {exc}")

    # Filter to confirmed children of root domain, deduplicate
    result.subdomains = sorted(
        s for s in all_subs
        if s != domain and (s.endswith(f".{domain}") or "." in s)
    )

    # ── Build TLS candidates ──────────────────────────────────────
    candidates = _build_candidates(
        domain,
        result.subdomains,
        result.mx_hosts,
        result.ns_hosts,
    )
    result.tls_candidates = [c.to_dict() for c in candidates]

    logger.info(
        f"DNS enumeration {domain}: "
        f"{len(result.a_records)} A, "
        f"{len(result.mx_hosts)} MX, "
        f"{len(result.subdomains)} subdomains, "
        f"{len(result.tls_candidates)} TLS candidates"
    )
    return result


import logging
import concurrent.futures
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not installed — DNS enumeration will be limited")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Port→service_type mapping (mirrors orchestrator.SERVICE_TYPE_MAP) ─────────

_PORT_SERVICE: dict[int, str] = {
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
}

# Ports we'll suggest scanning on discovered hosts
_DEFAULT_PROBE_PORTS = [443, 25, 587, 993, 636]

# ── Subdomain wordlist ─────────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST: list[str] = [
    # Web / application
    "www", "web", "app", "portal", "secure", "login", "auth", "sso",
    "api", "api2", "rest", "graphql", "gateway", "proxy",
    # Mail
    "mail", "smtp", "imap", "pop", "mx", "mx1", "mx2", "email",
    "webmail", "outlook", "exchange", "autodiscover",
    # Infrastructure
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "vpn", "remote", "gateway", "firewall", "fw", "ras",
    "cdn", "static", "assets", "media", "img", "images",
    # Admin / management
    "admin", "manage", "mgmt", "panel", "dashboard", "monitor",
    "syslog", "log", "logs", "metrics",
    # Dev / staging
    "dev", "staging", "stage", "test", "qa", "uat", "sandbox",
    "preview", "beta", "demo",
    # LDAP / directory
    "ldap", "ldaps", "dc", "dc1", "dc2", "ad", "dir",
    # Misc services
    "ftp", "sftp", "ssh", "rdp", "citrix",
    "intranet", "internal", "extranet",
    "shop", "store", "pay", "payment", "billing",
    "support", "helpdesk", "servicedesk",
    "wiki", "docs", "confluence", "jira",
    "git", "gitlab", "github", "svn", "ci", "jenkins",
    "cloud", "aws", "azure",
    # Common numbered hosts
    "host1", "host2", "server", "server1", "server2",
    # Geographic/regional
    "eu", "us", "uk", "de", "fr", "es",
]

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class TlsCandidate:
    """A {host, port, service_type} tuple recommended for TLS scanning."""
    host: str
    port: int
    service_type: str
    source: str  # dns_record | ct_san | wordlist | dnsdumpster

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DnsEnumerationResult:
    domain: str
    a_records: list[str]       = field(default_factory=list)
    aaaa_records: list[str]    = field(default_factory=list)
    mx_hosts: list[str]        = field(default_factory=list)
    ns_hosts: list[str]        = field(default_factory=list)
    cname_chain: list[str]     = field(default_factory=list)
    spf_record: Optional[str]  = None
    dmarc_record: Optional[str] = None
    subdomains: list[str]      = field(default_factory=list)   # all discovered FQDNs
    tls_candidates: list[dict] = field(default_factory=list)   # TlsCandidate dicts
    errors: list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _resolve(domain: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """
    Query *domain* for records of *rtype*.  Returns a list of string values.
    Empty list on NXDOMAIN / timeout / not-installed.
    """
    if not HAS_DNSPYTHON:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []
    except Exception as exc:
        logger.debug(f"DNS {rtype} query for {domain} failed: {exc}")
        return []


def _cname_chain(domain: str, max_depth: int = 8) -> list[str]:
    """Follow CNAME chain up to max_depth hops; returns list of targets."""
    chain: list[str] = []
    current = domain
    for _ in range(max_depth):
        targets = _resolve(current, "CNAME")
        if not targets:
            break
        target = targets[0].rstrip(".")
        chain.append(target)
        current = target
    return chain


def _txt_records(domain: str) -> tuple[Optional[str], Optional[str]]:
    """Return (spf_record, dmarc_record) from TXT queries."""
    spf = None
    dmarc = None
    for txt in _resolve(domain, "TXT"):
        clean = txt.strip('"')
        if clean.startswith("v=spf1") and spf is None:
            spf = clean
    for txt in _resolve(f"_dmarc.{domain}", "TXT"):
        clean = txt.strip('"')
        if clean.startswith("v=DMARC1") and dmarc is None:
            dmarc = clean
    return spf, dmarc


def _resolves(fqdn: str, timeout: float = 3.0) -> bool:
    """Quick check: does the FQDN have at least one A or AAAA record?"""
    if HAS_DNSPYTHON:
        return bool(_resolve(fqdn, "A", timeout) or _resolve(fqdn, "AAAA", timeout))
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(fqdn)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def _wordlist_subdomains(
    domain: str,
    wordlist: list[str],
    max_workers: int = 30,
    timeout: float = 3.0,
) -> list[str]:
    """Resolve wordlist prefixes against domain concurrently; return resolving FQDNs."""
    candidates = [f"{w}.{domain}" for w in wordlist]
    found: list[str] = []

    def check(fqdn: str) -> Optional[str]:
        return fqdn if _resolves(fqdn, timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for result in ex.map(check, candidates):
            if result:
                found.append(result)
    return found


def _ct_sans(domain: str) -> list[str]:
    """
    Harvest unique FQDNs from crt.sh certificate SANs for *domain*.
    Uses the same JSON endpoint as ct/ct_monitor.py.
    Returns a de-duplicated, lowercase list of FQDNs that are children
    of *domain* (wildcards stripped).
    """
    if not HAS_REQUESTS:
        return []
    url = f"https://crt.sh/?q=%.{domain}&output=json&exclude=expired"
    try:
        resp = requests.get(url, timeout=15, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.debug(f"CT SAN harvest failed for {domain}: {exc}")
        return []

    fqdns: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(f".{domain}") or name == domain:
                fqdns.add(name)
    return sorted(fqdns)


def _dnsdumpster_subdomains(
    domain: str,
    api_key: str = "",
    timeout: int = 15,
) -> list[str]:
    """
    Query DNSDumpster for additional subdomains.

    If *api_key* is provided, uses the official REST API:
        GET https://api.dnsdumpster.com/domain/{domain}
        X-API-Key: <api_key>
    Rate limit: 1 request per 2 seconds (respected internally).
    Free plan: up to 50 records. Plus plan: up to 200/page with pagination.

    Without an API key, falls back to a best-effort HTML scrape of
    dnsdumpster.com (unofficial, CSRF-token based, may break without warning).
    The scrape path is kept for development/testing only — the API path is
    strongly preferred for production use.

    Returns a sorted, deduplicated list of FQDNs that are children of *domain*.
    Empty list on any failure.
    """
    if not HAS_REQUESTS:
        return []

    if api_key:
        return _dnsdumpster_api(domain, api_key, timeout)
    return _dnsdumpster_scrape(domain, timeout)


def _dnsdumpster_api(
    domain: str,
    api_key: str,
    timeout: int,
    paginate: bool = True,
) -> list[str]:
    """
    Query the DNSDumpster REST API.

    Authentication : X-API-Key header
    Endpoint       : GET https://api.dnsdumpster.com/domain/{domain}
    Rate limit     : 1 request per 2 seconds (enforced here with a sleep)
    Pagination     : ?page=N  (Plus plan; free plan max 50 records)

    Response structure (from https://dnsdumpster.com/developer/):
      {
        "a":     [ {"host": "...", "ips": [{...}]}, ... ],
        "cname": [ ... ],
        "mx":    [ ... ],
        "ns":    [ ... ],
        "txt":   [ "v=spf1 ...", ... ],
        "total_a_recs": N
      }

    We harvest unique FQDNs that are children of *domain* from all record
    sections.  TXT records are strings (no host field) so they are skipped
    for FQDN extraction but logged for SPF/DMARC awareness.
    """
    import time

    base_url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers  = {
        "X-API-Key":    api_key,
        "Accept":       "application/json",
        "User-Agent":   "PQC-Monitor/1.3 (security research)",
    }
    fqdns: set[str] = set()
    page = 1

    while True:
        url = base_url if page == 1 else f"{base_url}?page={page}"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except Exception as exc:
            logger.warning(f"DNSDumpster request failed for {domain} (page {page}): {exc}")
            break

        if resp.status_code == 429:
            logger.warning(
                f"DNSDumpster rate limit hit for {domain} — "
                "respecting 2-second limit between requests"
            )
            time.sleep(2)
            continue  # retry same page

        if resp.status_code == 401:
            logger.warning("DNSDumpster API key rejected (401) — check X-API-Key value")
            break

        if resp.status_code == 403:
            logger.warning("DNSDumpster 403 — plan restriction for this endpoint")
            break

        if not resp.ok:
            logger.warning(
                f"DNSDumpster API error for {domain} (page {page}): "
                f"HTTP {resp.status_code}"
            )
            break

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"DNSDumpster returned non-JSON for {domain}: {exc}")
            break

        # Harvest FQDNs from all record sections that carry a 'host' field
        # Actual keys: a, cname, mx, ns  (aaaa not documented but harmless to try)
        found_this_page = 0
        for section in ("a", "aaaa", "cname", "mx", "ns"):
            for record in data.get(section, []):
                host = record.get("host", "").lower().strip().rstrip(".")
                if host and (host == domain or host.endswith(f".{domain}")):
                    if host not in fqdns:
                        fqdns.add(host)
                        found_this_page += 1

        # TXT records are plain strings — log SPF/DMARC but no FQDNs to harvest
        for txt in data.get("txt", []):
            if txt.startswith("v=spf1") or txt.startswith("v=DMARC1"):
                logger.debug(f"DNSDumpster TXT for {domain}: {txt[:80]}")

        total = data.get("total_a_recs", 0)
        logger.debug(
            f"DNSDumpster page {page} for {domain}: "
            f"{found_this_page} new FQDNs (total_a_recs={total})"
        )

        # Paginate only if Plus plan has more records and pagination is enabled
        # Free plan: 50 records; Plus plan: 200/page.  Stop when page returns nothing new.
        if not paginate or found_this_page == 0:
            break

        # Respect the 2-second rate limit between paginated requests
        time.sleep(2)
        page += 1

        # Safety cap: never fetch more than 10 pages (2000 records)
        if page > 10:
            logger.debug(f"DNSDumpster: reached page cap for {domain}")
            break

    logger.info(
        f"DNSDumpster API: {len(fqdns)} unique FQDNs for {domain} "
        f"({page} page(s) fetched)"
    )
    return sorted(fqdns)


def _dnsdumpster_scrape(domain: str, timeout: int) -> list[str]:
    """
    Fallback HTML scrape of dnsdumpster.com (unofficial, best-effort).
    Uses CSRF-token extraction then a POST to the free search form.
    May break at any time if DNSDumpster changes their front-end.
    """
    session = requests.Session()
    base = "https://dnsdumpster.com"
    try:
        r = session.get(base, timeout=timeout,
                        headers={"User-Agent": "PQC-Monitor/1.2 (DNS research)"})
        r.raise_for_status()

        csrf = None
        for line in r.text.splitlines():
            if "csrfmiddlewaretoken" in line and "value=" in line:
                start = line.find('value="') + 7
                end   = line.find('"', start)
                csrf  = line[start:end]
                break
        if not csrf:
            logger.debug("DNSDumpster scrape: could not extract CSRF token")
            return []

        post = session.post(
            base,
            data={"csrfmiddlewaretoken": csrf, "targetip": domain, "user": "free"},
            headers={"Referer": base, "User-Agent": "PQC-Monitor/1.2 (DNS research)"},
            timeout=timeout,
        )
        post.raise_for_status()
        html = post.text
    except Exception as exc:
        logger.debug(f"DNSDumpster scrape failed for {domain}: {exc}")
        return []

    import re
    fqdns: set[str] = set()
    for match in re.finditer(
        r'<td[^>]*>\s*([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')\s*</td>',
        html
    ):
        fqdn = match.group(1).lower().strip()
        if fqdn.endswith(f".{domain}"):
            fqdns.add(fqdn)

    logger.debug(f"DNSDumpster scrape returned {len(fqdns)} hosts for {domain}")
    return sorted(fqdns)


def _build_candidates(
    domain: str,
    all_subdomains: list[str],
    mx_hosts: list[str],
    ns_hosts: list[str],
) -> list[TlsCandidate]:
    """
    Build TLS scan candidate list from all discovered hosts.
    Each host gets a candidate per default probe port.
    MX hosts → smtp candidates; NS hosts → no TLS probes by default.
    """
    candidates: list[TlsCandidate] = []
    seen: set[tuple[str, int]] = set()

    def add(host: str, port: int, source: str):
        host = host.rstrip(".").lower()
        key = (host, port)
        if key in seen:
            return
        seen.add(key)
        candidates.append(TlsCandidate(
            host=host,
            port=port,
            service_type=_PORT_SERVICE.get(port, "other"),
            source=source,
        ))

    # Primary domain itself
    for port in _DEFAULT_PROBE_PORTS:
        add(domain, port, "dns_record")

    # Subdomains → web + mail ports
    for sub in all_subdomains:
        for port in _DEFAULT_PROBE_PORTS:
            add(sub, port, "subdomain")

    # MX hosts → SMTP-specific ports only
    for mx in mx_hosts:
        for port in [25, 587, 465]:
            add(mx, port, "mx_record")

    return candidates


# ── Public API ────────────────────────────────────────────────────────────────

def enumerate_domain(
    domain: str,
    use_wordlist: bool = True,
    use_ct: bool = True,
    use_dnsdumpster: bool = False,
    dnsdumpster_api_key: str = "",
    wordlist: list[str] = None,
    max_workers: int = 30,
    timeout: float = 5.0,
) -> DnsEnumerationResult:
    """
    Full DNS deep-dive for *domain*.

    Parameters
    ----------
    domain              Root domain to enumerate (e.g. "example.com")
    use_wordlist        Brute-force with built-in wordlist (default True)
    use_ct              Harvest SANs from crt.sh CT logs (default True)
    use_dnsdumpster     Query DNSDumpster (default False — requires explicit opt-in).
                        If *dnsdumpster_api_key* is set, uses the official API;
                        otherwise falls back to a fragile HTML scrape.
    dnsdumpster_api_key Optional API key for api.dnsdumpster.com.
                        Configure via dns_enumeration.dnsdumpster_api_key in
                        config.yaml or the PQC_DNSDUMPSTER_KEY env variable.
    wordlist            Override built-in wordlist
    max_workers         Concurrency for wordlist resolution
    timeout             Per-query DNS timeout in seconds

    Returns
    -------
    DnsEnumerationResult with all discovered data and TLS candidates.
    """
    result = DnsEnumerationResult(domain=domain)
    wl = wordlist if wordlist is not None else SUBDOMAIN_WORDLIST
    all_subs: set[str] = set()

    # ── A / AAAA ──────────────────────────────────────────────────
    result.a_records    = _resolve(domain, "A",    timeout)
    result.aaaa_records = _resolve(domain, "AAAA", timeout)
    if not result.a_records and not result.aaaa_records:
        result.errors.append(f"Domain {domain} does not resolve")

    # ── CNAME chain ───────────────────────────────────────────────
    result.cname_chain = _cname_chain(domain)

    # ── MX ────────────────────────────────────────────────────────
    mx_raw = _resolve(domain, "MX", timeout)
    # MX records look like "10 mail.example.com." — extract host
    for rec in mx_raw:
        parts = rec.split()
        host = (parts[-1] if parts else rec).rstrip(".")
        if host and host not in result.mx_hosts:
            result.mx_hosts.append(host)
            all_subs.add(host)

    # ── NS ────────────────────────────────────────────────────────
    ns_raw = _resolve(domain, "NS", timeout)
    result.ns_hosts = [r.rstrip(".") for r in ns_raw]

    # ── TXT (SPF / DMARC) ─────────────────────────────────────────
    result.spf_record, result.dmarc_record = _txt_records(domain)

    # ── CT SAN harvest ────────────────────────────────────────────
    if use_ct:
        try:
            ct_subs = _ct_sans(domain)
            logger.debug(f"{domain}: CT SANs found {len(ct_subs)} subdomains")
            all_subs.update(ct_subs)
        except Exception as exc:
            result.errors.append(f"CT harvest error: {exc}")
            logger.warning(f"CT harvest failed for {domain}: {exc}")

    # ── Wordlist brute-force ──────────────────────────────────────
    if use_wordlist:
        try:
            wl_subs = _wordlist_subdomains(domain, wl, max_workers, timeout)
            logger.debug(f"{domain}: wordlist found {len(wl_subs)} subdomains")
            all_subs.update(wl_subs)
        except Exception as exc:
            result.errors.append(f"Wordlist error: {exc}")
            logger.warning(f"Wordlist enumeration failed for {domain}: {exc}")

    # ── DNSDumpster ───────────────────────────────────────────────
    if use_dnsdumpster:
        try:
            dd_subs = _dnsdumpster_subdomains(domain, api_key=dnsdumpster_api_key)
            logger.debug(f"{domain}: DNSDumpster found {len(dd_subs)} subdomains")
            all_subs.update(dd_subs)
        except Exception as exc:
            result.errors.append(f"DNSDumpster error: {exc}")
            logger.debug(f"DNSDumpster failed for {domain}: {exc}")

    # Filter to confirmed children of root domain, deduplicate
    result.subdomains = sorted(
        s for s in all_subs
        if s != domain and (s.endswith(f".{domain}") or "." in s)
    )

    # ── Build TLS candidates ──────────────────────────────────────
    candidates = _build_candidates(
        domain,
        result.subdomains,
        result.mx_hosts,
        result.ns_hosts,
    )
    result.tls_candidates = [c.to_dict() for c in candidates]

    logger.info(
        f"DNS enumeration {domain}: "
        f"{len(result.a_records)} A, "
        f"{len(result.mx_hosts)} MX, "
        f"{len(result.subdomains)} subdomains, "
        f"{len(result.tls_candidates)} TLS candidates"
    )
    return result
