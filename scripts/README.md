# PQC-Monitor — Operational Scripts

All scripts are run from the **project root** (not from inside `scripts/`):

```bash
cd /opt/pqc-monitor
python3 scripts/<script>.py [options]
```

They load `config/config.yaml` automatically. Override with `--config`.

---

## reassess_all.py

Reassess **every domain already in the database** so existing rows pick up
the v1.9.0 fixes (full enumerated cipher set merged into `cipher_suites`;
findings that name the specific offending suites).

Two modes, very different resource profiles:

| Mode | Network | CPU | When |
|------|---------|-----|------|
| **score-only** (default) | none | light | Fixes both v1.9.0 bugs on existing data — the `cipher_enum` blobs are already on disk. **Start here.** |
| `--rescan` | dozens of TCP conns/domain | heavy (~5–15 s/domain) | Only for domains whose `cipher_enum` blob is genuinely missing. |

It writes one new `scan_run` tagged `reassess-all (<mode>)`; old rows are
kept (history preserved), the dashboard shows the newest per domain.

### Options

| Flag | Description |
|------|-------------|
| `--config PATH` | config.yaml (db path, guidelines, SSL Labs email) |
| `--db PATH` | override the database path directly |
| `--rescan` | full network rescan (heavy); default is score-only |
| `--only-missing` | only domains lacking a `cipher_enum` blob |
| `--workers N` | parallelism (default 2; capped at 4 with `--rescan`) |
| `--sleep S` | delay between domains (default 0 score-only, 2.0 rescan) |
| `--limit N` | process at most N domains (staged rollout / smoke test) |
| `--dry-run` | report only; write nothing |

### Recommended sequence

```bash
cd /opt/pqc-monitor
# 1. Preview
python3 scripts/reassess_all.py --dry-run
# 2. Fix existing data — no traffic, no API calls:
python3 scripts/reassess_all.py
# 3. (Optional) fill genuinely-missing cipher data, gently:
python3 scripts/reassess_all.py --rescan --only-missing --workers 2 --sleep 3
```

On the production Google Cloud VM, prefer the defaults (2 workers,
score-only). For a large `--rescan`, stage with `--limit 20` first and keep
`--sleep` ≥ 2 to spread outbound connections. SSL Labs is **not** triggered
by this script even in `--rescan` mode (it only reads SSL Labs cache, same
as a normal scan) — fresh SSL Labs assessments remain on-demand from the UI.

---

## bulk_org_assign.py

Bulk-assign domains to an organisation by TLD pattern.

Given an organisation name and one or more TLD patterns, the script scans
every domain in the database (from `assessments` and `domain_lists`) and
assigns any that match to the named organisation, creating it if it does
not already exist.

**Matching rule:** domain `D` matches TLD `T` when `D == T` (exact) or
`D` ends with `.<T>` (any subdomain at any depth).

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `--tld TLD` | Yes (repeatable) | Apex domain to match (e.g. `bde.es`) |
| `--org NAME` | Yes | Organisation name — created if absent |
| `--sector TEXT` | — | Sector label (e.g. `Financial Services`) |
| `--region TEXT` | — | Region label (e.g. `EU/Spain`) |
| `--description TEXT` | — | Free-text notes |
| `--no-update` | — | Do not update sector/region if org already exists |
| `--dry-run` / `-n` | — | Show changes without writing to the DB |
| `--verbose` / `-v` | — | Print every matched domain |
| `--config PATH` | — | Path to config.yaml |
| `--db PATH` | — | Direct path to SQLite file (overrides config) |

### Examples

```bash
# Preview — no changes written
python3 scripts/bulk_org_assign.py \
    --tld bde.es \
    --org "Banco de España" \
    --sector "Financial Services" \
    --region "EU/Spain" \
    --dry-run

# Live assign
python3 scripts/bulk_org_assign.py \
    --tld bde.es \
    --org "Banco de España" \
    --sector "Financial Services" \
    --region "EU/Spain"

# Multiple TLDs for the same org
python3 scripts/bulk_org_assign.py \
    --tld bde.es --tld bancodeespana.es \
    --org "Banco de España" \
    --sector "Financial Services" \
    --region "EU/Spain"

# Verbose — prints every matched domain
python3 scripts/bulk_org_assign.py \
    --tld example.com --org "Example Corp" --dry-run --verbose
```

### Notes

- Assignments are **additive** — existing org domains are never removed.
- The org's sector and region are updated if they differ (unless `--no-update`).
- Domains must already exist in the database (scanned or in a domain list).
  Run a scan first if the database is empty.

---

## diagnose.py

Checks Shodan and DNSDumpster integration against a live domain.

```bash
python3 scripts/diagnose.py \
    --config config/config.yaml \
    --domain bde.es
```

Reports:
1. Config loading — confirms API keys are read correctly
2. Shodan API — calls `api.info()` and `api.host()`, shows SSL services
3. CLI flags — verifies `--shodan` and `--dns-enumerate` exist on `scan`
4. DNSDumpster API — live test with correct `X-API-Key` header, shows response structure

### Notes on Shodan free plan (`oss`)

`query_credits: 0` is **normal** on the free plan — it uses rate limiting,
not a credit bucket. `api.host()` still works. The diagnostic will tell
you if it actually fails.

### Notes on DNSDumpster

The API uses `X-API-Key` header (not `Authorization: Bearer`).
Rate limit: 1 request per 2 seconds. Free plan: 50 records.
Plus plan: 200 records/page with `?page=N` pagination.
