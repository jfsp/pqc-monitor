#!/usr/bin/env bash
# shodan-test.sh — verify the Shodan API key configured in PQC-Monitor
#
# Usage:
#   bash scripts/shodan-test.sh [domain]
#
# The domain is optional; defaults to bundesbank.de.
# The script reads the API key from the same sources pqc_monitor.py uses:
#   1. SHODAN_API_KEY environment variable
#   2. shodan.api_key in /etc/pqc-monitor/config.yaml
#   3. shodan.api_key in config/config.yaml (dev fallback)
#
# Exit codes:
#   0 — key is valid and a host lookup succeeded
#   1 — key is missing, invalid, or the lookup returned no data
#   2 — shodan Python library not installed
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

DOMAIN="${1:-bundesbank.de}"
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

python3 - "$API_KEY" "$DOMAIN" <<'PYEOF'
import sys
import json
import socket

api_key = sys.argv[1]
domain  = sys.argv[2]

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

# ── 2. Host lookup ────────────────────────────────────────────────────────────
try:
    ip = socket.gethostbyname(domain)
except socket.gaierror as e:
    print(json.dumps({
        "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
        "error": f"Could not resolve {domain}: {e}"
    }))
    sys.exit(1)

try:
    host = api.host(ip)
except shodan_lib.APIError as e:
    err = str(e)
    no_data = "no information available" in err.lower()
    print(json.dumps({
        "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
        "host_lookup": {
            "domain": domain,
            "ip": ip,
            "status": "no_data" if no_data else "error",
            "detail": err,
        }
    }, indent=2))
    sys.exit(0 if no_data else 1)
except Exception as e:
    print(json.dumps({
        "account": {"plan": plan, "query_credits": credits, "scan_credits": scan_cr},
        "error": f"Host lookup failed: {e}"
    }))
    sys.exit(1)

# ── 3. Extract TLS services ───────────────────────────────────────────────────
tls_services = []
for svc in host.get("data", []):
    ssl = svc.get("ssl", {})
    if not ssl:
        continue
    port = svc.get("port", 0)
    versions  = [v for v in ssl.get("versions", []) if not v.startswith("-")]
    cipher    = ssl.get("cipher", {})
    cert      = ssl.get("cert", {})
    subject   = cert.get("subject", {})
    issuer    = cert.get("issuer", {})
    pubkey    = cert.get("pubkey", {})
    tls_services.append({
        "port":     port,
        "tls":      versions,
        "cipher":   cipher.get("name", ""),
        "key_type": pubkey.get("type", "").upper(),
        "key_bits": pubkey.get("bits", 0),
        "subject":  subject.get("CN", ""),
        "issuer":   issuer.get("CN", ""),
        "expires":  cert.get("expires", ""),
        "sig_alg":  cert.get("sig_alg", ""),
    })

# ── 4. Output ─────────────────────────────────────────────────────────────────
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
        "domain": domain,
        "ip":     ip,
        "org":    host.get("org", ""),
        "country": host.get("country_name", ""),
        "total_ports": len(host.get("data", [])),
        "tls_ports": len(tls_services),
        "tls_services": tls_services,
    }
}
print(json.dumps(result, indent=2))
PYEOF
