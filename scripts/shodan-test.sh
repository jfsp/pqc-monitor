#!/usr/bin/env bash
# shodan-test.sh — verify the Shodan API key configured in PQC-Monitor
#
# Usage:
#   bash scripts/shodan-test.sh [ip|domain]
#
# The target is optional; defaults to 8.8.8.8 (Google DNS) which is
# freely accessible on the oss plan.  Passing a domain resolves it to
# an IP first, but note that CDN/anycast IPs (e.g. google.com) may
# return 403 on the oss plan even with a valid key — use a stable,
# well-known IP for a reliable connectivity test.
#
# The script reads the API key from the same sources pqc_monitor.py uses:
#   1. SHODAN_API_KEY environment variable
#   2. shodan.api_key in /etc/pqc-monitor/config.yaml
#   3. shodan.api_key in config/config.yaml (dev fallback)
#
# Exit codes:
#   0 — key is valid and the host lookup succeeded
#   1 — key is missing, invalid, quota/plan error, or lookup failed
#   2 — shodan Python library not installed
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

TARGET="${1:-8.8.8.8}"
CONFIG_PROD="/etc/pqc-monitor/config.yaml"
CONFIG_DEV="$(dirname "$0")/../config/config.yaml"

# ── Locate API key ────────────────────────────────────────────────────────────

API_KEY="${SHODAN_API_KEY:-}"

if [[ -z "$API_KEY" ]]; then
    for cfg in "$CONFIG_PROD" "$CONFIG_DEV"; do
        if [[ -f "$cfg" ]]; then
            API_KEY=$(python3 -c "
import yaml, sys
with open('$cfg') as f:
    d = yaml.safe_load(f)
print(d.get('shodan', {}).get('api_key', '') or '')
" 2>/dev/null || true)
            [[ -n "$API_KEY" ]] && break
        fi
    done
fi

if [[ -z "$API_KEY" ]]; then
    echo '{"error":"No Shodan API key found. Set SHODAN_API_KEY or configure shodan.api_key in config.yaml"}'
    exit 1
fi

# ── Run the test via inline Python ────────────────────────────────────────────

python3 - "$API_KEY" "$TARGET" <<'PYEOF'
import sys
import json
import socket

api_key = sys.argv[1]
target  = sys.argv[2]

try:
    import shodan as shodan_lib
except ImportError:
    print(json.dumps({"error": "shodan library not installed — run: pip install shodan"}))
    sys.exit(2)

api = shodan_lib.Shodan(api_key)

# ── 1. Account info ───────────────────────────────────────────────────────────
try:
    info = api.info()
except shodan_lib.APIError as e:
    print(json.dumps({"error": f"API key rejected: {e}"}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Connection failed: {e}"}))
    sys.exit(1)

plan    = info.get("plan", "unknown")
credits = info.get("query_credits", 0)
scan_cr = info.get("scan_credits", 0)

# ── 2. Resolve target to IP if a hostname was given ───────────────────────────
# The oss plan only allows lookups against IPs in Shodan's shared dataset.
# CDN/anycast IPs from gethostbyname() (e.g. google.com → 173.x.x.x) are
# often outside that set and return 403.  Use a stable IP like 8.8.8.8 to
# confirm the key and plan are working correctly.
ip = target
if not target[0].isdigit():
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(json.dumps({
            "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
            "error": f"Could not resolve {target}: {e}"
        }))
        sys.exit(1)

# ── 3. Host lookup ────────────────────────────────────────────────────────────
try:
    host = api.host(ip)
except shodan_lib.APIError as e:
    err = str(e)
    no_data = "no information available" in err.lower()
    plan_restricted = "403" in err or "access denied" in err.lower()
    print(json.dumps({
        "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
        "host_lookup": {
            "target": target,
            "ip": ip,
            "status": "no_data" if no_data else "plan_restricted" if plan_restricted else "error",
            "detail": err,
            "hint": (
                "oss plan cannot query this IP — try bash scripts/shodan-test.sh 8.8.8.8"
                if plan_restricted else None
            ),
        }
    }, indent=2))
    sys.exit(0 if no_data else 1)
except Exception as e:
    print(json.dumps({
        "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
        "error": f"Host lookup failed: {e}"
    }))
    sys.exit(1)

# ── 4. Extract TLS services ───────────────────────────────────────────────────
tls_services = []
for svc in host.get("data", []):
    ssl = svc.get("ssl", {})
    if not ssl:
        continue
    port   = svc.get("port", 0)
    cert   = ssl.get("cert", {})
    pubkey = cert.get("pubkey", {})
    tls_services.append({
        "port":     port,
        "tls":      [v for v in ssl.get("versions", []) if not v.startswith("-")],
        "cipher":   ssl.get("cipher", {}).get("name", ""),
        "key_type": pubkey.get("type", "").upper(),
        "key_bits": pubkey.get("bits", 0),
        "subject":  cert.get("subject", {}).get("CN", ""),
        "issuer":   cert.get("issuer", {}).get("CN", ""),
        "expires":  cert.get("expires", ""),
        "sig_alg":  cert.get("sig_alg", ""),
    })

# ── 5. Output ─────────────────────────────────────────────────────────────────
result = {
    "account": {
        "plan": plan,
        "query_credits": credits,
        "scan_credits": scan_cr,
        "note": (
            "oss plan uses rate limits, not a credit bucket — credits=0 is normal"
            if plan == "oss" else
            ("WARNING: query credits low or exhausted" if credits < 10 else "ok")
        ),
    },
    "host_lookup": {
        "target":      target,
        "ip":          ip,
        "org":         host.get("org", ""),
        "country":     host.get("country_name", ""),
        "asn":         host.get("data", [{}])[0].get("asn", "") if host.get("data") else "",
        "total_ports": len(host.get("data", [])),
        "ports":       host.get("ports", []),
        "tls_ports":   len(tls_services),
        "tls_services": tls_services,
    }
}
print(json.dumps(result, indent=2))
PYEOF
