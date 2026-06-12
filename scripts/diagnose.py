#!/usr/bin/env python3
"""
PQC-Monitor: Shodan + DNS Enumerator Diagnostic Script
Run this on the production server to diagnose what's actually happening.

Usage:
  python3 diagnose.py --config /opt/pqc-monitor/config/config.yaml --domain example.com

SPDX-License-Identifier: GPL-3.0-or-later
"""

import sys
import os
import json
import argparse
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s"
)
logger = logging.getLogger("diagnose")

# ── Arg parsing ───────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="PQC-Monitor diagnostics")
parser.add_argument("--config", default="config/config.yaml",
                    help="Path to config.yaml")
parser.add_argument("--domain", default="example.com",
                    help="Domain to test against")
args = parser.parse_args()

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


# ── Load config ───────────────────────────────────────────────────────────────

def sep(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


sep("1. Config loading")
try:
    from pqc_monitor import load_config
    cfg = load_config(args.config)
    print(f"  Config file      : {args.config}")
    print(f"  shodan_api_key   : {'SET (' + cfg['shodan_api_key'][:6] + '...)' if cfg.get('shodan_api_key') else 'NOT SET'}")
    print(f"  dnsdumpster_key  : {'SET (' + cfg['dnsdumpster_api_key'][:6] + '...)' if cfg.get('dnsdumpster_api_key') else 'NOT SET'}")
    print(f"  dns_use_wordlist : {cfg.get('dns_use_wordlist')}")
    print(f"  dns_use_ct       : {cfg.get('dns_use_ct')}")
except Exception as e:
    print(f"  ERROR loading config: {e}")
    sys.exit(1)


# ── Shodan ────────────────────────────────────────────────────────────────────

sep("2. Shodan API")
try:
    import shodan as shodan_lib
    print("  shodan library   : INSTALLED")
except ImportError:
    print("  shodan library   : NOT INSTALLED — run: pip install shodan")
    shodan_lib = None

if shodan_lib and cfg.get("shodan_api_key"):
    api = shodan_lib.Shodan(cfg["shodan_api_key"])
    try:
        info = api.info()
        print(f"  api.info() OK")
        print(f"  plan             : {info.get('plan')}")
        print(f"  query_credits    : {info.get('query_credits')}")
        print(f"  scan_credits     : {info.get('scan_credits')}")
        print(f"  unlocked         : {info.get('unlocked')}")
        print(f"  Raw info dict    : {json.dumps(info, indent=4)}")

        credits = info.get("query_credits", 0)
        if credits == 0:
            print("\n  ⚠️  DIAGNOSIS: query_credits = 0")
            print("     api.host() will raise a Shodan APIError for every lookup.")
            print("     The scanner will silently fall back to direct probing.")
            print("     Credits reset on the 1st of each month.")
        else:
            print(f"\n  Testing api.host() for {args.domain}...")
            import socket
            try:
                ip = socket.gethostbyname(args.domain)
                print(f"  Resolved {args.domain} → {ip}")
                try:
                    host = api.host(ip)
                    services = host.get("data", [])
                    ssl_services = [s for s in services if s.get("ssl")]
                    print(f"  api.host() OK — {len(services)} services, "
                          f"{len(ssl_services)} with SSL data")
                    for s in ssl_services[:3]:
                        print(f"    port {s['port']}: "
                              f"TLS={s.get('ssl',{}).get('versions',[])} "
                              f"cipher={s.get('ssl',{}).get('cipher',{}).get('name','?')}")
                except shodan_lib.APIError as e:
                    print(f"  ❌ api.host() APIError: {e}")
                    print("     This is the most common cause of Shodan producing no data.")
            except socket.gaierror as e:
                print(f"  ❌ DNS resolution failed for {args.domain}: {e}")
    except shodan_lib.APIError as e:
        print(f"  ❌ api.info() failed: {e}")
    except Exception as e:
        print(f"  ❌ Shodan error: {e}")
elif not cfg.get("shodan_api_key"):
    print("  ⚠️  No API key in config — Shodan disabled")


# ── CLI scan --shodan flag ────────────────────────────────────────────────────

sep("3. CLI scan --shodan flag behaviour")
print("  The scan command requires the --shodan flag to be passed explicitly:")
print("    pqc_monitor.py scan --domain example.com --shodan")
print()
print("  Without --shodan:")
print("    use_shodan=False is passed to orchestrator.scan_domains()")
print("    Shodan is NEVER called regardless of API key or credits")
print()
print("  Dashboard: the 'Use Shodan API' checkbox must be ticked before scanning.")
print("  It is UNCHECKED by default.")


# ── DNS Enumerator ────────────────────────────────────────────────────────────

sep("4. DNS Enumerator")

dd_key = cfg.get("dnsdumpster_api_key", "")
use_wl = cfg.get("dns_use_wordlist", True)
use_ct = cfg.get("dns_use_ct", True)

print(f"  dnsdumpster_api_key : {'SET' if dd_key else 'NOT SET'}")
print(f"  use_wordlist        : {use_wl}")
print(f"  use_ct              : {use_ct}")
print(f"  use_dnsdumpster     : {'True (key present)' if dd_key else 'False (no key)'}")
print()
print("  NOTE: DNS enumeration is NOT part of the regular scan pipeline.")
print("  It only runs when explicitly triggered via:")
print("    CLI:  pqc_monitor.py scan --domain example.com --dns-enumerate")
print("          (flag does not exist yet — see diagnosis below)")
print("    API:  POST /app/api/dns-enumerate")
print("    API:  POST /app/api/save-domains  with dns_enumerate=true")

# Check if --dns-enumerate flag exists on CLI
sep("5. CLI --dns-enumerate flag check")
try:
    import click
    from pqc_monitor import scan as scan_cmd
    params = {p.name: p for p in scan_cmd.params}
    if "dns_enumerate" in params or "dns-enumerate" in params:
        print("  ✅ --dns-enumerate flag EXISTS on scan command")
    else:
        print("  ❌ --dns-enumerate flag is MISSING from scan command")
        print("     Current scan flags:", list(params.keys()))
        print()
        print("  DIAGNOSIS: There is no CLI flag to trigger DNS enumeration")
        print("  during a scan. It must be added to pqc_monitor.py.")
except Exception as e:
    print(f"  Error checking: {e}")


# ── DNSDumpster API connectivity ──────────────────────────────────────────────

if dd_key:
    sep(f"6. DNSDumpster API test for {args.domain}")
    try:
        import requests
        url = f"https://api.dnsdumpster.com/domain/{args.domain}"
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {dd_key}", "Accept": "application/json"},
            timeout=15
        )
        print(f"  HTTP status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            hosts = data.get("host_records", [])
            print(f"  ✅ API call OK — {len(hosts)} host records returned")
            for h in hosts[:5]:
                print(f"    {h.get('host')} → {h.get('ips', [])}")
        elif r.status_code == 401:
            print("  ❌ 401 Unauthorized — API key is invalid or not accepted")
        elif r.status_code == 403:
            print("  ❌ 403 Forbidden — key may be valid but plan doesn't include this endpoint")
        else:
            print(f"  ❌ Unexpected status: {r.text[:200]}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
else:
    sep("6. DNSDumpster API test")
    print("  Skipped — no API key configured")


# ── Summary ───────────────────────────────────────────────────────────────────

sep("SUMMARY")
issues = []

if not cfg.get("shodan_api_key"):
    issues.append("Shodan API key not in config")
elif shodan_lib:
    try:
        info2 = shodan_lib.Shodan(cfg["shodan_api_key"]).info()
        if info2.get("query_credits", 0) == 0:
            issues.append("Shodan query_credits = 0 (resets monthly)")
    except Exception:
        issues.append("Shodan API key present but api.info() failed")

# Check for missing --dns-enumerate CLI flag
try:
    from pqc_monitor import scan as scan_cmd2
    params2 = {p.name: p for p in scan_cmd2.params}
    if "dns_enumerate" not in params2:
        issues.append("--dns-enumerate flag missing from CLI scan command")
except Exception:
    pass

if not dd_key:
    issues.append("DNSDumpster API key not in config (enumeration disabled)")

if issues:
    print("  Issues found:")
    for i in issues:
        print(f"    ❌ {i}")
else:
    print("  ✅ No issues found")

print()
