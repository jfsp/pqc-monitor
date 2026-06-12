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

parser = argparse.ArgumentParser(description="PQC-Monitor diagnostics")
parser.add_argument("--config", default="config/config.yaml",
                    help="Path to config.yaml")
parser.add_argument("--domain", default="example.com",
                    help="Domain to test against")
args = parser.parse_args()

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def sep(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


# ── Config ────────────────────────────────────────────────────────────────────

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
shodan_lib = None
try:
    import shodan as shodan_lib
    print("  shodan library   : INSTALLED")
except ImportError:
    print("  shodan library   : NOT INSTALLED — run: pip install shodan")

if shodan_lib and cfg.get("shodan_api_key"):
    api = shodan_lib.Shodan(cfg["shodan_api_key"])
    try:
        info = api.info()
        plan    = info.get("plan", "unknown")
        credits = info.get("query_credits", 0)
        print(f"  api.info() OK")
        print(f"  plan             : {plan}")
        print(f"  query_credits    : {credits}")
        print(f"  Raw info dict    : {json.dumps(info, indent=4)}")

        if plan == "oss":
            print()
            print("  ℹ️  Plan 'oss' (free tier): query_credits=0 is NORMAL.")
            print("     The free plan uses rate limits, not a credit bucket.")
            print("     api.host() should work — testing now...")
        elif credits == 0:
            print()
            print("  ⚠️  Paid plan with 0 credits — host lookups may fail.")

        import socket
        try:
            ip = socket.gethostbyname(args.domain)
            print(f"\n  Resolved {args.domain} → {ip}")
            try:
                host = api.host(ip)
                services = host.get("data", [])
                ssl_services = [s for s in services if s.get("ssl")]
                print(f"  ✅ api.host() OK — {len(services)} services, "
                      f"{len(ssl_services)} with SSL/TLS data")
                for s in ssl_services[:3]:
                    tls = s.get("ssl", {}).get("versions", [])
                    cipher = s.get("ssl", {}).get("cipher", {}).get("name", "?")
                    print(f"    port {s['port']}: TLS={tls}  cipher={cipher}")
                if not ssl_services:
                    print(f"    (No SSL/TLS data for this IP in Shodan's index)")
            except shodan_lib.APIError as e:
                print(f"  ❌ api.host() APIError: {e}")
                if "No information available" in str(e):
                    print("     This IP is not in Shodan's index — try a different domain.")
                elif "query credits" in str(e).lower():
                    print("     Credit quota actually exhausted (unusual for oss plan).")
        except socket.gaierror as e:
            print(f"  ❌ DNS resolution failed for {args.domain}: {e}")
    except shodan_lib.APIError as e:
        print(f"  ❌ api.info() failed: {e}")
    except Exception as e:
        print(f"  ❌ Shodan error: {e}")
elif not cfg.get("shodan_api_key"):
    print("  ⚠️  No API key in config — Shodan disabled")


# ── CLI flags ─────────────────────────────────────────────────────────────────

sep("3. CLI scan flag check")
try:
    from pqc_monitor import scan as scan_cmd
    params = {p.name: p for p in scan_cmd.params}
    print(f"  Current scan flags: {list(params.keys())}")
    print()

    shodan_ok = "shodan" in params
    dns_ok    = "dns_enumerate" in params

    print(f"  --shodan flag        : {'✅ present' if shodan_ok else '❌ MISSING'}")
    print(f"  --dns-enumerate flag : {'✅ present' if dns_ok else '❌ MISSING'}")

    if not shodan_ok or not dns_ok:
        print()
        print("  Deploy v1.3.4+ to get both flags.")
    else:
        print()
        print("  Usage:")
        print("    pqc_monitor.py scan --domain example.com --shodan")
        print("    pqc_monitor.py scan --domain example.com --dns-enumerate")
        print("    pqc_monitor.py scan --domain example.com --shodan --dns-enumerate")
        print()
        print("  Dashboard: tick 'Use Shodan API' checkbox before scanning.")
        print("  It is unchecked by default.")
except Exception as e:
    print(f"  Error checking: {e}")


# ── DNSDumpster ───────────────────────────────────────────────────────────────

dd_key = cfg.get("dnsdumpster_api_key", "")

if dd_key:
    sep(f"4. DNSDumpster API test for {args.domain}")
    try:
        import requests
        url = f"https://api.dnsdumpster.com/domain/{args.domain}"
        # Correct header is X-API-Key (not Authorization: Bearer)
        r = requests.get(
            url,
            headers={
                "X-API-Key": dd_key,
                "Accept": "application/json",
            },
            timeout=15,
        )
        print(f"  HTTP status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            # Response has host_records list
            hosts = data.get("host_records", [])
            print(f"  ✅ API call OK — {len(hosts)} host records")
            for h in hosts[:5]:
                ips = [i.get("ip") for i in h.get("ips", [])]
                print(f"    {h.get('host')} → {ips}")
            print(f"  Top-level keys: {list(data.keys())[:10]}")
        elif r.status_code == 401:
            print("  ❌ 401 Unauthorized — check your API key value")
        elif r.status_code == 403:
            print("  ❌ 403 Forbidden — key valid but plan restriction")
        else:
            print(f"  ❌ HTTP {r.status_code}: {r.text[:300]}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
else:
    sep("4. DNSDumpster API")
    print("  Skipped — no API key in config")


# ── Summary ───────────────────────────────────────────────────────────────────

sep("SUMMARY")
issues = []

try:
    from pqc_monitor import scan as scan_cmd2
    params2 = {p.name: p for p in scan_cmd2.params}
    if "dns_enumerate" not in params2:
        issues.append("--dns-enumerate flag missing (deploy v1.3.4+)")
    if "shodan" not in params2:
        issues.append("--shodan flag missing (deploy v1.3.4+)")
except Exception:
    pass

if not dd_key:
    issues.append("DNSDumpster API key not in config")

if not cfg.get("shodan_api_key"):
    issues.append("Shodan API key not in config")

if issues:
    print("  Issues found:")
    for i in issues:
        print(f"    ❌ {i}")
else:
    print("  ✅ No issues found")
print()
