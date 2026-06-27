#!/usr/bin/env bash
# dnsdumpster-test.sh — verify the DNSDumpster API key configured in PQC-Monitor
#
# Usage:
#   bash scripts/dnsdumpster-test.sh [domain]
#
# The domain is optional; defaults to bundesbank.de.
# The script reads the API key from the same sources pqc_monitor.py uses:
#   1. PQC_DNSDUMPSTER_KEY environment variable
#   2. dns_enumeration.dnsdumpster_api_key in /etc/pqc-monitor/config.yaml
#   3. dns_enumeration.dnsdumpster_api_key in config/config.yaml (dev fallback)
#
# Exit codes:
#   0 — key is valid and the API returned results (or no data for this domain)
#   1 — key is missing, rejected, or quota exceeded
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

DOMAIN="${1:-bundesbank.de}"
CONFIG_PROD="/etc/pqc-monitor/config.yaml"
CONFIG_DEV="$(dirname "$0")/../config/config.yaml"

# ── Locate API key ────────────────────────────────────────────────────────────

API_KEY="${PQC_DNSDUMPSTER_KEY:-}"

if [[ -z "$API_KEY" ]]; then
    for cfg in "$CONFIG_PROD" "$CONFIG_DEV"; do
        if [[ -f "$cfg" ]]; then
            API_KEY=$(python3 -c "
import yaml, sys
with open('$cfg') as f:
    d = yaml.safe_load(f)
print(d.get('dns_enumeration', {}).get('dnsdumpster_api_key', '') or '')
" 2>/dev/null || true)
            [[ -n "$API_KEY" ]] && break
        fi
    done
fi

if [[ -z "$API_KEY" ]]; then
    echo '{"error":"No DNSDumpster API key found. Set PQC_DNSDUMPSTER_KEY or configure dns_enumeration.dnsdumpster_api_key in config.yaml"}'
    exit 1
fi

# ── Call the API ──────────────────────────────────────────────────────────────

RESPONSE=$(curl -sf \
    -H "X-API-Key: $API_KEY" \
    -H "Accept: application/json" \
    "https://api.dnsdumpster.com/domain/${DOMAIN}" 2>&1) || {
    echo '{"error":"curl request failed — check network connectivity"}'
    exit 1
}

# ── Interpret the response ────────────────────────────────────────────────────

python3 - "$DOMAIN" <<PYEOF
import json, sys

domain   = sys.argv[1]
raw      = '''$RESPONSE'''

try:
    data = json.loads(raw)
except Exception:
    print(json.dumps({"error": "Non-JSON response", "raw": raw[:200]}))
    sys.exit(1)

# Error responses
if isinstance(data, dict) and data.get("error"):
    err = data["error"]
    print(json.dumps({"error": err}))
    code = 1 if any(w in err.lower() for w in ("quota", "daily", "invalid", "unauthorized", "key")) else 0
    sys.exit(code)

# Count discovered hosts per record type
counts = {
    section: len(data.get(section, []))
    for section in ("a", "aaaa", "cname", "mx", "ns", "txt")
}
total_hosts = sum(counts[s] for s in ("a", "aaaa", "cname", "mx", "ns"))

# Collect sample hostnames (up to 5)
samples = []
for section in ("a", "cname", "mx", "ns"):
    for rec in data.get(section, []):
        host = rec.get("host", "").strip()
        if host and host not in samples:
            samples.append(host)
        if len(samples) >= 5:
            break
    if len(samples) >= 5:
        break

result = {
    "status": "ok",
    "domain": domain,
    "record_counts": counts,
    "total_hosts": total_hosts,
    "total_a_recs": data.get("total_a_recs", counts["a"]),
    "sample_hosts": samples,
}
print(json.dumps(result, indent=2))
PYEOF
