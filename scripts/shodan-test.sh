#!/usr/bin/env bash
# shodan-test.sh — verify the Shodan API key configured in PQC-Monitor
#
# Runs two host lookups to confirm both key validity and plan capability:
#   1. 8.8.8.8      — in Shodan's free shared dataset; succeeds on any plan
#   2. google.com   — resolves to a CDN IP outside the free dataset;
#                     succeeds only on paid plans with full index access
#
# Usage:
#   bash scripts/shodan-test.sh
#
# The script reads the API key from the same sources pqc_monitor.py uses:
#   1. SHODAN_API_KEY environment variable
#   2. shodan.api_key in /etc/pqc-monitor/config.yaml
#   3. shodan.api_key in config/config.yaml (dev fallback)
#
# Exit codes:
#   0 — key is valid (free-tier test passed; paid-tier result informational)
#   1 — key is missing, invalid, or the free-tier test itself failed
#   2 — shodan Python library not installed
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

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

python3 - "$API_KEY" <<'PYEOF'
import sys
import json
import socket

api_key = sys.argv[1]

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

# ── 2. Helper: single host lookup ─────────────────────────────────────────────
def lookup(target: str) -> dict:
    """
    Resolve *target* to an IP if needed, then call api.host().
    Returns a result dict — never raises.
    """
    ip = target
    if not target[0].isdigit():
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return {"target": target, "ip": None, "status": "dns_error", "detail": str(e)}

    try:
        host = api.host(ip)
    except shodan_lib.APIError as e:
        err = str(e)
        if "403" in err or "access denied" in err.lower():
            return {"target": target, "ip": ip, "status": "plan_restricted",
                    "detail": err}
        if "no information available" in err.lower():
            return {"target": target, "ip": ip, "status": "no_data",
                    "detail": err}
        return {"target": target, "ip": ip, "status": "error", "detail": err}
    except Exception as e:
        return {"target": target, "ip": ip, "status": "error", "detail": str(e)}

    tls_services = []
    for svc in host.get("data", []):
        ssl = svc.get("ssl", {})
        if not ssl:
            continue
        cert   = ssl.get("cert", {})
        pubkey = cert.get("pubkey", {})
        tls_services.append({
            "port":     svc.get("port", 0),
            "tls":      [v for v in ssl.get("versions", []) if not v.startswith("-")],
            "cipher":   ssl.get("cipher", {}).get("name", ""),
            "key_type": pubkey.get("type", "").upper(),
            "key_bits": pubkey.get("bits", 0),
            "subject":  cert.get("subject", {}).get("CN", ""),
            "issuer":   cert.get("issuer", {}).get("CN", ""),
            "expires":  cert.get("expires", ""),
            "sig_alg":  cert.get("sig_alg", ""),
        })

    return {
        "target":       target,
        "ip":           ip,
        "status":       "ok",
        "org":          host.get("org", ""),
        "country":      host.get("country_name", ""),
        "asn":          host.get("data", [{}])[0].get("asn", "") if host.get("data") else "",
        "ports":        host.get("ports", []),
        "tls_ports":    len(tls_services),
        "tls_services": tls_services,
    }

# ── 3. Test 1 — free-tier IP (8.8.8.8) ───────────────────────────────────────
# Should succeed on any valid key regardless of plan.
# Failure here means the key is broken or the account is suspended.
free_result = lookup("8.8.8.8")

# ── 4. Test 2 — restricted IP (google.com CDN) ────────────────────────────────
# Resolves to a CDN/anycast IP outside the oss shared dataset.
# Success → paid plan with full index access.
# 403    → oss / restricted plan (key is valid but dataset is limited).
paid_result = lookup("google.com")

if paid_result["status"] == "plan_restricted":
    paid_result["note"] = (
        "Expected on oss/free plan — key is valid but full index requires a paid plan"
    )
elif paid_result["status"] == "ok":
    paid_result["note"] = "Full index access confirmed — paid plan"

# ── 5. Derive overall plan capability ─────────────────────────────────────────
if free_result["status"] == "ok" and paid_result["status"] == "ok":
    capability = "full"
elif free_result["status"] == "ok":
    capability = "restricted (oss/free — shared dataset only)"
else:
    capability = "unknown — free-tier test failed"

# ── 6. Output ─────────────────────────────────────────────────────────────────
result = {
    "account": {
        "plan":          plan,
        "query_credits": credits,
        "scan_credits":  scan_cr,
        "capability":    capability,
        "note": (
            "oss plan uses rate limits, not a credit bucket — credits=0 is normal"
            if plan == "oss" else
            ("WARNING: query credits low or exhausted" if credits < 10 else "ok")
        ),
    },
    "test_free_tier":  free_result,
    "test_paid_tier":  paid_result,
}
print(json.dumps(result, indent=2))

# Exit 1 only if the free-tier test (key validity check) failed
if free_result["status"] not in ("ok", "no_data"):
    sys.exit(1)
PYEOF
