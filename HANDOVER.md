# PQC-Monitor — Developer Handover Document

**Version:** 1.9.1
**Date:** 2026-07-09
**Status:** Active development — full cipher detail + SSL Labs integration; MX + SMTP/STARTTLS fixes
**Purpose:** Context transfer for continuing development in a new session
**Repository:** https://github.com/jfsp/pqc-monitor

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Version History](#2-version-history)
3. [Repository Layout](#3-repository-layout)
4. [Architecture](#4-architecture)
5. [Database Schema](#5-database-schema)
6. [API Reference](#6-api-reference)
7. [Authentication & RBAC](#7-authentication--rbac)
8. [Known Issues & Technical Debt](#8-known-issues--technical-debt)
9. [Critical Implementation Notes](#9-critical-implementation-notes)
10. [Planned Features — Prioritised Backlog](#10-planned-features--prioritised-backlog)

---

## 1. Project Overview

PQC-Monitor is an open-source platform for assessing the Post-Quantum Cryptography (PQC) readiness of internet-facing services within a sector or region. It performs passive TLS/certificate reconnaissance, scores each domain against regulatory guidelines (NIST SP 800-131Ar3, BSI TR-02102-1, CCN-STIC-221), tracks migration progress over time, and generates actionable migration roadmaps.

**Technology stack:**
Python 3.10+ · Flask 3.x · SQLite (WAL mode) · Gunicorn (production) · Werkzeug password hashing · APScheduler · Chart.js (dashboard) · Jinja2 templates

**Deployment model:**
Two systemd services — `pqc-monitor-web` (Gunicorn) and `pqc-monitor-scheduler` (APScheduler daemon) — managed by `pqc-monitor.target`. Nginx reverse proxy for TLS termination. Runs as the `pqcmonitor` system user. Runtime data under `/var/lib/pqc-monitor/`, code under `/opt/pqc-monitor/`.

**License:** GPL-3.0-or-later
**AI-assisted:** Substantial portions generated with Claude (Anthropic). All code reviewed by developer.

### Git Workflow for AI-Assisted Development

When continuing work with Claude, the expected workflow is:

1. Share the updated zip **or** paste individual files that need changing
2. Claude delivers modified files **plus** ready-to-apply git commits
   (one logical commit per concern, conventional commit format: `type(scope): message`)
3. Stage and commit each change:
   ```bash
   git add <changed-files>
   git commit -m "feat(scope): description"
   git push origin main
   ```

**Commit format:**
```
type(scope): short description (≤72 chars)

- bullet explaining what changed and why

files/changed.py
```
Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

### Deployment Workflow

```bash
scripts/deploy.sh --dry-run      # preview
sudo scripts/deploy.sh           # deploy last commit
sudo scripts/deploy.sh --from abc1234
```

---

## 2. Version History

| Version | Key additions |
|---------|--------------|
| 1.0.0 | Core scan engine, TLS probe, assessor, guidelines, dashboard SPA, CLI, scheduler |
| 1.1.0 | RBAC (admin/analyst roles), systemd units, VERSION file |
| 1.1.1–1.1.3 | Login loop fix, tab visibility fixes, sortable columns |
| 1.2.0 | T2-1 service_type; T3-1 dns_enumerator (CT SANs + wordlist + DNSDumpster) |
| 1.3.0 | DNSDumpster API key; Organisation grouping (v14); analyst org scoping |
| 1.3.1 | 10 production deployment fixes (systemd, gunicorn, nginx, DB path, sessions) |
| 1.4.0 | level=na for no-TLS; analyst tab scoping; deploy.sh; fix_notls_level.py |
| 1.5.0 | Country on organisations (v15); country filter in dashboard |
| 1.5.1 | Country + region on scan runs (v16); TLD-based geo-inference |
| 1.5.2 | Fix: country edits not persisting; fix: silent migration failures |
| 1.6.0 | Community concept; ROLE_COMMUNITY_MANAGER; Group Report tab; schema v17 |
| 1.6.1 | Fix: deploy.sh had data/ in PROTECTED list |
| 1.6.2 | Fix: DATABASE→PQC_DB key error in community/region endpoints |
| 1.6.3 | Fix: deploy.sh restart guard broke on non-root systemctl is-active |
| 1.7.0 | Group Report: By Country; SVG charts; sortable table; bulk_assign.py |
| 1.8.0 | Fix: community report scoping; DNS enum quota detection + passive fallback; --skip-scanned; test scripts |
| 1.9.0 | Full cipher detail in UI (drill-down view); findings name specific ciphers; CAMELLIA/SEED probes; SSL Labs API v4 integration (T3-3, display-only) |
| 1.9.1 | Fix: MX priority/non-FQDN normalisation (+ DB repair script); SMTP/STARTTLS reported no-TLS on 465/587/2525 (protocol-based dispatch, added 2525) |

### 2.8 — v1.8.0 detail

**Bug fixes: community report scoping, DNS enumeration, scan deduplication + test scripts**

#### Fix 1 — Community manager group reports showed all orgs (not just community's)

`api_region_report`, `api_country_report` and their CSV/PDF variants called
`db.get_region_aggregate()` / `db.get_country_aggregate()` with no user context,
returning every org in the region/country regardless of the user's community.

**Fix:**
- `data/database.py`: added `allowed_org_ids` optional parameter to
  `get_region_aggregate()` and `get_country_aggregate()`; filters the org list
  post-query when provided.
- `app_routes.py`: added `_allowed_org_ids(user, db)` helper — returns `None`
  for admins (no filter), or a `set` of org IDs for community managers
  (direct `user.org_ids` ∪ orgs from all `user.community_ids`). Applied to
  all 6 report endpoints. `api_regions()` and `api_countries()` refactored to
  reuse the same helper.

#### Fix 2 — DNSDumpster quota detection did not work

DNSDumpster returns `{"error":"Daily quota exceeded"}` as the **body of a HTTP
429**. The previous code branched on `resp.status_code == 429` *before* reading
the body, entering an infinite sleep-and-retry loop.

**Fix (`scanner/dns_enumerator.py`):**
- Read `resp.text` immediately after every request, *before* any status-code
  branching. If the text contains "quota" or "daily", set
  `_DNSDUMPSTER_QUOTA_EXHAUSTED = True` and raise `DnsDumpsterQuotaError`.
- Genuine per-request 429s (no quota language in body) still sleep and retry.
- `_DNSDUMPSTER_QUOTA_EXHAUSTED` is a module-level session flag; once set,
  `_dnsdumpster_subdomains()` raises immediately without making any HTTP request.
- `is_dnsdumpster_quota_exhausted()` public accessor for the CLI to surface a
  one-time warning to stderr.

**Also fixed:** the file had been doubled (two complete copies of every function)
by a prior bad `str_replace`; Python silently used the second (old) definition
of every function. Rebuilt from backup with surgical patches. Always run
`grep -c "def _dnsdumpster_api" scanner/dns_enumerator.py` after edits to this
file — the answer must be `1`.

#### Added — Passive DNS fallback

`_passive_dns_enum(domain, ns_hosts, timeout)` activates automatically when:
- DNSDumpster quota is hit, **or**
- DNSDumpster is not configured

Techniques (all passive, dnspython only, no external APIs):
- **SRV records**: probes 20 well-known service prefixes (`_https._tcp`,
  `_smtp._tcp`, `_imaps._tcp`, `_ldap._tcp`, etc.)
- **AXFR (zone transfer)**: attempts against each authoritative NS; refused by
  virtually all public servers, but catches misconfigured ones silently
- **PTR reverse lookup**: resolves apex A records back to hostnames

#### Added — `--skip-scanned` / `--force` CLI flags

`pqc_monitor.py scan` now accepts:
- `--skip-scanned`: queries `db.get_assessed_domains(domain_list)` before
  starting; prints the skipped list; exits cleanly if nothing remains
- `--force`: overrides `--skip-scanned`, scans everything regardless

`data/database.py`: `get_assessed_domains(domains)` — single IN-clause query,
returns `set` of domains with at least one existing assessment.

#### Added — Test scripts

Two new scripts in `scripts/`:

**`scripts/shodan-test.sh`**: verifies Shodan API key from config. Runs two
lookups:
1. `8.8.8.8` — always accessible on oss plan; confirms key validity
2. `google.com` — CDN IP outside free dataset; 403 = oss plan, success = paid

Reports `"capability": "full"` or `"restricted (oss/free)"`. Exit 0 if key
valid; exit 1 on key error; exit 2 if shodan library not installed.

**`scripts/dnsdumpster-test.sh`**: verifies DNSDumpster API key from config.
Calls `GET https://api.dnsdumpster.com/domain/<domain>` with `X-API-Key`
header. Reports record counts per type (a, aaaa, cname, mx, ns, txt) and
sample hostnames. Detects quota exhaustion. Exit 0 on success; exit 1 on
key/quota error.

**Shodan plan note (important for operations):**
The `oss` (free) plan gives access to a shared dataset of well-known IPs only.
CDN/anycast IPs resolved from `gethostbyname("google.com")` return 403 even
with a valid key — this is a plan restriction, not an authentication error.
`8.8.8.8` and `1.1.1.1` are reliable test targets on any plan. The scan
orchestrator's `shodan_client.py` already handles 403 gracefully; no change
needed there.

**Files changed:** `app_routes.py`, `data/database.py`,
`scanner/dns_enumerator.py`, `pqc_monitor.py`, `scripts/shodan-test.sh` (new),
`scripts/dnsdumpster-test.sh` (new).

---

### 2.9 — v1.9.0 detail

**Full TLS cipher detail + SSL Labs integration (T3-3)**

#### Fix 1 — Domain detail did not show the full accepted cipher set

Root cause: the full enumeration lived in `domain_extra['cipher_enum']` but
`assessments.cipher_suites` only stored the single passively-negotiated suite
per service, `/api/domain/<domain>` never returned `domain_extra`, and the
modal truncated to 2 ciphers which meant it never reached the dashboard.

- `scanner/crypto_assessor.py`: merges all enumerated suites (IANA) into
  `cipher_suites_found` / `tls_versions_found`; passive cipher names are
  normalised OpenSSL→IANA before `_assess_cipher()` (this also fixed a latent
  bug: guideline cipher lists are IANA, so passive names never matched and
  always fell through to the generic 60 score).
- `data/database.py`: `get_latest_domain_extra(domain, data_types)` (latest
  blob per type across runs, `_recorded_at`/`_run_id` provenance) and
  `get_latest_run_id_for_domain(domain)`.
- `app_routes.py` + legacy `dashboard/app.py` endpoint: domain detail now
  returns `"extra": {cipher_enum, chain, cdn, ssllabs}`.
- `dashboard/app.py` UI: modal shows cipher counts by security level, an
  SSL Labs grade badge with link, and a **Full TLS Details →** button opening
  the new `view-domain-full` drill-down (sibling view in `.main`, depth
  verified with the §9.2 checker; no nav tab — reached from the modal only).
  The full view renders every accepted suite (IANA name, protocol, bits,
  category, colour-coded assessment), chain summary, and the SSL Labs panel.

  Now: the assessor merges the full enumerated suite set (IANA names) into `assessments.cipher_suites`; `/api/domain/<domain>` returns the latest `cipher_enum`/`chain`/`cdn`/ `ssllabs` blobs; the modal shows a per-security-level summary with a **Full TLS Details** drill-down view (`view-domain-full`) listing every accepted suite (protocol, bits, category, colour-coded assessment).

- **CAMELLIA / SEED probes** added to `cipher_enum.py` (coverage gap vs SSL
  Labs on European servers).
- **SSL Labs API v4 integration** (`scanner/ssllabs_client.py`): cache-only
  during scan runs (`fromCache=on`, never triggers external assessments
  inline); on-demand fresh assessment from the detail view (`startNew=on`,
  `publish=off`, `scan.run` permission), polled by the UI. Grade + report
  link shown in the modal/detail. **Display only — does not affect the PQC
  score** (explicit decision). Requires one-time `register_email()` with an
  organisational email; config `ssllabs.email` or `PQC_SSLLABS_EMAIL`.
- **`scripts/reassess_all.py`**: reassess every existing domain. Score-only
  by default (no traffic/CPU-light, reuses stored blobs, regenerates named
  findings); `--rescan` for a resource-guarded network rescan
  (`--workers`/`--sleep`/`--limit`/`--only-missing`/`--dry-run`).

#### Fix 2 — CIPHER_ENUM findings now name the ciphers to remove

`cipher_enum_findings()` appends the sorted IANA names to every finding
message (truncated at 20 with "+N more") and adds a `ciphers` list field.
Note: `extra_findings` are computed at scan time and persisted in
`findings_json` — existing assessments keep their old messages until the
domain is re-scanned (`reassess` reuses stored extras but findings are
regenerated from the stored `cipher_enum` blob, so a reassess run also
picks up the named lists).

#### Added — CAMELLIA/SEED probes

7 new entries in `TLS12_CIPHER_GROUPS` + `_OPENSSL_TO_IANA`, all
`deprecated` (non-NIST-approved): ECDHE/DHE/RSA CAMELLIA CBC variants and
SEED-SHA. Closes the visible gap vs SSL Labs on European servers.

#### Added — SSL Labs API v4 (`scanner/ssllabs_client.py`)

- **Design**: cache-only during scan runs (`fromCache=on`, maxAge 168h) —
  fresh SSL Labs assessments take 60+ s and are concurrency-limited, so they
  are only triggered on demand from the detail view (`startNew=on`,
  `publish=off`) and polled by the UI (5 s → 10 s backoff, 40 attempts).
- **Grade is display-only** — it does NOT feed the PQC score (decided
  2026-07-09).
- **Registration**: v4 requires a one-time registration with an
  organisational email (free-mail providers rejected). Helper:
  `python3 -c "from scanner.ssllabs_client import register_email; print(register_email('First','Last','Org','you@org.example'))"`.
  Config `ssllabs.email` (or env `PQC_SSLLABS_EMAIL`); empty = disabled.
  `app_factory.py` exposes it as `app.config["SSLLABS_EMAIL"]`.
- **Endpoints** (`app_routes.py`): `GET /api/ssllabs/<domain>` (auth +
  domain-scoping; persists summary to `domain_extra` when READY) and
  `POST /api/ssllabs/<domain>/refresh` (requires `scan.run` — it causes
  external scanning by Qualys against the target; audited as
  `ssllabs.refresh`).
- **Storage**: `domain_extra['ssllabs']` = {host, status, grade (worst
  across endpoints), grades, endpoints[], engine_version, criteria_version,
  test_time, retrieved_at, report_url}.
- **Rate limits**: 429 (client cool-off) and 529 (service overload) are
  surfaced as `rate_limited`; scan-time lookups fail soft.

**Files changed:** `scanner/cipher_enum.py`, `scanner/crypto_assessor.py`,
`scanner/orchestrator.py`, `scanner/ssllabs_client.py` (new),
`data/database.py`, `app_routes.py`, `app_factory.py`, `dashboard/app.py`,
`pqc_monitor.py`, `config/config.yaml.example`,
`tests/test_ssllabs_and_cipher_detail.py` (new), `tests/test_assessor.py`, `scripts/reassess_all.py` (new).

---

### 2.10 — v1.9.1 detail

**Bug fix 1 — MX records stored as "5 SMTP.domain.com"**

MX rdata is `<priority> <exchange>`. The direct-DNS MX path
(`_resolve(domain,"MX")` → `parts[-1]`) split it, but the DNSDumpster
harvest (`record.get("host")`) and passive-DNS paths let the raw
priority-prefixed string through into `mx_hosts`, `subdomains` and
`tls_candidates[].host`.

- `scanner/dns_enumerator.py`: new `_normalise_mx_host(value)` — strips a
  leading numeric priority, lower-cases, removes the trailing dot, and
  rejects anything that is not a hostname (a lone `5`; the `.` from a
  null-MX `0 .`; hosts without a dot). Applied in the direct MX loop, the
  DNSDumpster `mx` section, and as a final guard in `_build_candidates()`
  (which also skips any candidate whose host still isn't a usable FQDN).
- `scripts/fix_mx_entries.py` (new): repairs existing `dns_enum` blobs
  in `domain_extra` in place. Cleans `mx_hosts`, `subdomains` and
  `tls_candidates[].host`, dedupes, drops unusable entries, and only
  rewrites a blob when something changed. No network, idempotent,
  `--dry-run`/`--config`/`--db`. Self-contained normaliser (no dnspython
  import) with a test asserting it agrees with the scanner's.

  UPDATE (post-1.9.1): on the production DB the malformed values were NOT in
  `dns_enum` blobs (that DB had 0 such blobs) but in the `domain`
  PRIMARY-KEY column of real rows — `5 smtp.domain.org`,
  `20 mail01.otherdomain.org`, even `primary DNS domain`. The script now
  ALSO repairs the `domain` column across all 7 domain-keyed tables
  (raw_scans, assessments, ct_queries, ct_certificates, domain_extra,
  roadmaps, domain_organisations): RENAME → normalised FQDN; MERGE (drop the
  duplicate) when a correct row already exists; DROP rows with no
  recoverable hostname. Idempotent. Run `--dry-run` first — it prints every
  rename/merge/drop before you commit.

**Bug fix 2 — SMTP with TLS reported as "no TLS"; 465/587/2525 not scanned**

Root cause: `probe_starttls()` selected the EHLO/STARTTLS upgrade with a
hardcoded `if port in (25, 587)`. Any other SMTP port fell through the
`if/elif` chain and attempted a *direct* `ctx.wrap_socket()` on a still-
plaintext socket → handshake failure → recorded as no TLS. Port 2525 was
in neither `TLS_PORTS` nor `STARTTLS_PORTS`, so it was never even probed.

- `scanner/starttls_probe.py`: dispatch by **protocol family**
  (`_PORT_PROTOCOL[port]` → smtp/imap/pop3/ldap), not port number, so
  25/587/2525 all take the SMTP path. Unknown ports now return an explicit
  `starttls_protocol_unknown_for_port:<n>` error instead of wrapping a
  plaintext socket. Greeting/EHLO parser hardened: dropped the IMAP
  `endswith("OK")` heuristic (misfired on SMTP banners), added an
  `if b"STARTTLS" not in ehlo` guard, and IMAP now reads a tagged
  multiline response.
- `scanner/service_discovery.py`: added 2525 (`submission-alt`) to
  `STARTTLS_PORTS` + new `STARTTLS_PROTOCOL` map; deduped probe ports so
  callers that already include STARTTLS ports don't double-probe. Implicit-
  TLS ports (465/993/995) stay in `TLS_PORTS` and are wrapped directly.
- `scanner/orchestrator.py`: `DEFAULT_PORTS` now includes 995;
  `_build_candidates()` MX ports are 25/587/465/2525.
- `pqc_monitor.py` + `config/config.yaml.example`: `scanning.use_starttls`
  is now actually read (was always the hardcoded default `True`); mail
  ports documented.

Verified with a mock STARTTLS server: 2525 and 587 both complete the
upgrade and report TLS 1.3.

**Files changed:** `scanner/dns_enumerator.py`, `scanner/starttls_probe.py`,
`scanner/service_discovery.py`, `scanner/orchestrator.py`, `pqc_monitor.py`,
`config/config.yaml.example`, `scripts/fix_mx_entries.py` (new),
`tests/test_mx_and_smtp.py` (new).


### 2. Production actions taken this session (on the live DB)

1. Ran `fix_mx_entries.py` — repaired malformed `domain` keys
   (`5 smtp.bde.es` → `smtp.bde.es`, `20 mail01.bancaditalia.it` → …,
   `primary DNS domain` deleted).
2. Discovered a batch of no-TLS hosts (`a-bancox2.bde.es`, `x-www.bde.es`,
   several `escb.eu`) showing **"30 weak"**. Root cause: a reassess run
   (`06b6e9c1`, 2026-07-10 08:53) executed with the **pre-fix assessor**.
   Confirmed via `services_assessed=0` on those rows.
3. Deleted the erroneous rows manually:
   `DELETE FROM assessments WHERE services_assessed=0 AND level!='na';`
   After the delete, the hosts correctly show **No TLS** again (the older
   `na` row became the newest).

The fixed assessor + reassess prevent recurrence: a re-run now writes a
correct `na` that becomes the newest row.

---

### 3. Deployment checklist (next session / when applying)

- Deliver as a zip (per workflow — never server-side patch scripts).
- After deploy, confirm the assessor fix is actually present:
  `grep -n "No reachable TLS service" /opt/pqc-monitor/scanner/crypto_assessor.py`
  (the deployed copy has diverged from the repo before — always verify).
- SSL Labs: one-time `register_email()`, then set `ssllabs.email` in
  `/etc/…/config.yaml` (empty = disabled; everything else still works).
- MX repair: `python3 scripts/fix_mx_entries.py --dry-run` against
  `/var/lib/pqc-monitor/pqc_monitor.db`, review, then apply. One-time.
- Reassess to propagate fixes to what's displayed (dashboard shows
  newest-per-domain): `python3 scripts/reassess_all.py` (score-only, no
  traffic). Use `--rescan --only-missing` only if `domain_extra` shows
  domains genuinely lacking cipher data. Mind the e2-micro: keep workers
  low (default 2), score-only unless a rescan is required.

### 5. Open threads / suggestions (not done)

- **Repo→/opt sync script** (requested earlier, separate from this session):
  full-tree sync excluding `.git`, overwrite mode (only new/changed files)
  + audit mode, never overwrite local `/opt` config unless `--force`.
- **`--service smtp` filter** for a targeted rescan (re-probe only
  mail-bearing hosts to pick up the STARTTLS fix without a full rescan).
- **Group-report view** (`view-group-report`) is referenced but absent from
  the rendered shell — pre-existing, not caused by this session's changes.
- General reminder: the dashboard shows **newest-per-domain**, so any
  assessor change only reaches the display after a reassess. A wrong newest
  row (from buggy logic) persists until overwritten or deleted.

---

## 3. Repository Layout

```
pqc-monitor/
├── app_factory.py          # Production Flask app factory (Gunicorn entry point)
├── app_routes.py           # Auth-protected /app/* blueprint (analyst + admin API)
├── pqc_monitor.py          # CLI entry point (scan, dashboard, schedule, reassess)
├── version.py              # VERSION file reader
├── admin/
│   └── routes.py           # Admin-only /admin/* blueprint
├── auth/
│   ├── auth_routes.py      # Login/logout/change-password routes
│   ├── middleware.py       # require_auth, current_user, filter_assessments
│   ├── models.py           # User, AuditEvent dataclasses; PERMISSIONS dict
│   └── store.py            # AuthStore: user/session/domain-list CRUD (SQLite)
├── ct/
│   └── ct_monitor.py       # Certificate Transparency log monitor (crt.sh)
├── dashboard/
│   └── app.py              # DASHBOARD_HTML SPA + legacy create_app() (dev only)
├── data/
│   ├── database.py         # Database class: all SQLite queries
│   ├── migrations.py       # Schema migration runner (current: v17)
│   ├── geo_inference.py    # TLD-based country/region inference
│   └── tld_geo.csv         # ccTLD → country_code/country/region mapping
├── domain_discovery/
│   └── domain_finder.py    # AI-powered domain discovery (Claude API)
├── guidelines/             # JSON rule files (nist_800_131a, bsi_tr02102, ccn_stic_221)
├── roadmap/
│   └── generator.py        # PQC migration roadmap generator
├── reports/
│   ├── report_generator.py # CSV/JSON/text export
│   └── community_report.py # Group Report: build_report(), export_csv(), export_pdf()
├── scanner/
│   ├── orchestrator.py     # Scan coordinator
│   ├── tls_probe.py        # TLS handshake prober
│   ├── crypto_assessor.py  # Scoring engine (guidelines → findings → score/level)
│   ├── crypto_extractor.py # Certificate field parser
│   ├── cipher_enum.py      # Cipher suite enumerator
│   ├── chain_validator.py  # Certificate chain analyser
│   ├── cdn_detector.py     # CDN fingerprinter
│   ├── dns_enumerator.py   # DNS deep-dive (CT SANs + wordlist + DNSDumpster + passive)
│   ├── service_discovery.py# Port scanner
│   ├── shodan_client.py    # Shodan integration
│   └── starttls_probe.py   # STARTTLS prober (SMTP/IMAP/LDAP)
├── scheduler/
│   └── scan_scheduler.py   # APScheduler wrapper
├── scripts/
│   ├── deploy.sh           # Incremental git→deployment sync
│   ├── fix_notls_level.py  # One-time DB fix: critical→na for no-TLS rows
│   ├── bulk_assign.py      # Bulk region/community assignment from org name list
│   ├── bulk_org_assign.py  # Bulk domain→org assignment by TLD
│   ├── diagnose.py         # API connectivity diagnostic
│   ├── shodan-test.sh      # Shodan API key + plan capability test (NEW v1.8.0)
│   ├── dnsdumpster-test.sh # DNSDumpster API key test (NEW v1.8.0)
│   └── wait-for-db.sh      # DB readiness poll for systemd ExecStartPre
├── systemd/
│   ├── pqc-monitor-web.service
│   ├── pqc-monitor-scheduler.service
│   ├── pqc-monitor.target
│   └── pqc-monitor.env     # Secrets template
├── tests/
└── config/
    └── config.yaml.example
```

---

## 4. Architecture

### Request flow (production)

```
Browser → nginx (TLS) → Gunicorn → Flask
                                    ├── /login, /logout       auth/auth_routes.py
                                    ├── /app/*                app_routes.py  (RBAC)
                                    │    ├── /api/summary
                                    │    ├── /api/assessments
                                    │    ├── /api/communities
                                    │    ├── /api/regions
                                    │    ├── /api/countries
                                    │    ├── /api/roadmap
                                    │    ├── /api/scan  (admin)
                                    │    └── /api/ct    (admin)
                                    └── /admin/*              admin/routes.py (admin)
```

### Assessment pipeline

```
orchestrator.scan_domain(domain)
  └── service_discovery  → open ports
  └── tls_probe          → TLS handshake per port
  └── crypto_extractor   → parse certificate fields
  └── chain_validator    → verify chain
  └── cipher_enum        → enumerate cipher suites
  └── cdn_detector       → CDN fingerprint
  └── shodan_client      → Shodan enrichment (optional, oss plan: shared dataset only)
  └── crypto_assessor    → score + findings → DomainAssessment
       └── level = "na"  if no TLS service found (score=0, no findings)
  └── database.save_assessment()
```

### DNS enumeration pipeline

```
enumerate_domain(domain)
  └── Direct DNS         → A, AAAA, MX, NS, CNAME, TXT (SPF/DMARC)
  └── CT SANs            → crt.sh JSON API (use_ct=True)
  └── Wordlist brute     → ~120 prefixes resolved concurrently (use_wordlist=True)
  └── DNSDumpster API    → official REST API with X-API-Key header
       └── On quota hit  → DnsDumpsterQuotaError → _DNSDUMPSTER_QUOTA_EXHAUSTED=True
  └── Passive DNS        → always runs when DD quota hit OR DD not configured
       ├── SRV records   → 20 well-known service prefixes
       ├── AXFR attempt  → per NS host (silently refused by most; catches misconfigs)
       └── PTR lookup    → reverse-resolve apex A records
```

### Score levels

| Level | Score | Meaning |
|-------|-------|---------|
| `critical` | 0–25 | Broken/deprecated algorithms in active use |
| `weak` | 26–50 | Acceptable today but not PQC-ready |
| `moderate` | 51–75 | Good classical crypto, no PQC yet |
| `ready` | 76–100 | PQC algorithms present or fully prepared |
| `na` | — | No TLS service found — not applicable |

`na` domains are excluded from all score averages, level counts, and roadmap generation.

---

## 5. Database Schema

**Current schema version:** 17 (managed by `data/migrations.py`)

### Key tables

**`scan_runs`** — one row per scan job
```sql
run_id TEXT PK, started_at TEXT, completed_at TEXT,
status TEXT, domain_count INTEGER, sector TEXT, region TEXT,
country_code TEXT, country TEXT
```

**`assessments`** — one row per domain per scan run
```sql
id INTEGER PK, run_id TEXT FK, domain TEXT, assessed_at TEXT,
guidelines_used TEXT (JSON), score INTEGER, level TEXT,
findings_json TEXT (JSON), tls_versions TEXT (JSON),
cipher_suites TEXT (JSON), has_pqc INTEGER, cert_expiry_days INTEGER,
errors_json TEXT (JSON), service_type TEXT
```
`level` values: `critical` | `weak` | `moderate` | `ready` | `na`

**`organisations`** — org groupings
```sql
id INTEGER PK, name TEXT, sector TEXT, region TEXT, description TEXT,
country_code TEXT, country TEXT
```

**`communities`** (v17)
```sql
id INTEGER PK, name TEXT, description TEXT, created_at TEXT, created_by TEXT
```

**`community_organisations`** (v17)
```sql
community_id INTEGER FK, org_id INTEGER FK  -- PK: both cols
```

**`user_communities`** (v17)
```sql
user_id TEXT, community_id INTEGER FK  -- PK: both cols
```

**`domain_organisations`** — domain ↔ org membership
**`domain_lists`** — saved domain lists with JSON domain array
**`domain_extra`** — keyed blob store (CDN, DNS, Shodan enrichment)
**`tls_results`** — raw probe results per port per domain per run
**`users`**, **`user_domain_lists`**, **`user_organisations`** — RBAC tables
**`roadmaps`** — saved roadmap results
**`ct_summaries`**, **`ct_certificates`** — CT monitor results
**`audit_log`** — all auth and data-access events

---

## 6. API Reference

All endpoints under `/app/api/` require authentication. Admin-only endpoints
additionally check `require_admin` or `user.can("permission")`.

### Summary & assessments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/summary` | user | Dashboard stats (excludes `na`) |
| GET | `/api/assessments` | user | Latest assessments (domain-scoped for analysts) |
| GET | `/api/assessments?run_id=X` | user | Assessments for a specific run |
| GET | `/api/assessments?service_type=X` | user | Filter by service type |
| GET | `/api/assessments?org_id=X` | user | Filter by organisation |
| GET | `/api/assessments?region=X` | user | Filter by region |
| GET | `/api/assessments?country_code=X` | user | Filter by country |
| GET | `/api/domain/<domain>` | user | Domain detail + history |

### Group Report (community_manager or admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/communities` | List communities visible to user |
| GET | `/api/communities/<id>/report` | JSON aggregate report |
| GET | `/api/communities/<id>/report.csv` | CSV download |
| GET | `/api/communities/<id>/report.pdf` | PDF download (requires weasyprint) |
| GET | `/api/regions` | Distinct regions visible to user |
| GET | `/api/regions/<name>/report` | JSON aggregate by region |
| GET | `/api/regions/<name>/report.csv` | CSV download |
| GET | `/api/regions/<name>/report.pdf` | PDF download |
| GET | `/api/countries` | Distinct countries visible to user |
| GET | `/api/countries/<cc>/report` | JSON aggregate by country |
| GET | `/api/countries/<cc>/report.csv` | CSV download |
| GET | `/api/countries/<cc>/report.pdf` | PDF download |

**Community scoping:** all 12 group report endpoints call `_allowed_org_ids(user, db)`
which returns `None` for admins (no filter) or a `set` of org IDs for community
managers. The DB aggregate functions filter to that set when provided.

### Scanning (admin only)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Trigger a scan |
| POST | `/api/reassess` | Re-score existing scan data |
| POST | `/api/discover` | AI-powered domain discovery |
| POST | `/api/dns-enumerate` | DNS deep-dive enumeration |
| GET | `/api/runs` | List scan runs |

### Organisations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/organisations` | user | Orgs visible to current user |
| POST | `/api/organisations` | admin | Create org |
| PUT | `/api/organisations/<id>` | admin | Update org |
| DELETE | `/api/organisations/<id>` | admin | Delete org |

---

## 7. Authentication & RBAC

### Roles

| Role | Key permissions |
|------|----------------|
| `admin` | Everything: scan, discover, manage users/lists/orgs/communities, CT, roadmap |
| `community_manager` | View Group Report for assigned communities only; cannot scan or manage |
| `analyst` | View assessments/roadmaps/CT for assigned domains only |

### Community manager scoping

Access = union of:
1. Direct `user.org_ids`
2. All orgs in `user.community_ids` (via `db.get_community_orgs(cid)`)

Computed by `_allowed_org_ids(user, db)` in `app_routes.py`. Returns `None` for
admins. Applied to all group report endpoints.

### Dashboard tab visibility

| Tab | Admin | Community Manager | Analyst |
|-----|-------|------------------|---------|
| Dashboard | ✓ | ✓ | ✓ |
| Group Report | ✓ | ✓ | hidden |
| Domain Discovery | ✓ | hidden | hidden |
| Scan | ✓ | hidden | hidden |
| Trends | ✓ | ✓ | ✓ |
| CT Monitor | ✓ | ✓ (view only) | ✓ (view only) |
| Roadmap | ✓ | ✓ (view only) | ✓ (view only) |
| Settings | ✓ | ✓ | ✓ |

---

## 8. Known Issues & Technical Debt

### 8.1 Antivirus false positives

`scanner/cipher_enum.py` triggers AV heuristics (SSL stripping tool signatures).
Fix: move cipher strings to a JSON data file. See §10 T1-1.

### 8.2 `dashboard/app.py` is a monolith

~2300-line file with HTML+CSS+JS as a Python string. New views should use
`static/` + Jinja2 templates.

### 8.3 Cipher enumeration is slow

One TCP connection per cipher group; 3–4 minutes per domain at full enumeration.
Consider caching results in `domain_extra`.

### 8.4 No rate limiting on scan endpoints

Only `/login` has rate limiting.

### 8.5 Shodan oss plan restriction

The `oss` (free) plan covers a shared dataset of well-known IPs only. CDN/anycast
IPs (e.g. resolved from `google.com`) return 403 even with a valid key. This is
expected and handled gracefully in `shodan_client.py`. Use `8.8.8.8` or `1.1.1.1`
to test connectivity. See `scripts/shodan-test.sh` for a two-tier test.

### 8.6 dns_enumerator.py is sensitive to str_replace

This file has been accidentally doubled twice during edits. After every change,
verify: `grep -c "def _dnsdumpster_api" scanner/dns_enumerator.py` must return `1`.
Also run `python3 -m py_compile scanner/dns_enumerator.py` before deploying.

---

## 9. Critical Implementation Notes

### 9.1 The two Flask apps in dashboard/app.py

`dashboard/app.py` contains **two** `create_app()` implementations:
- Legacy one (used by `pqc_monitor.py dashboard` for dev)
- `app_factory.create_app()` is the production entry point

**Always work in `app_factory.py` + `app_routes.py` + `admin/routes.py`.**

### 9.2 HTML structure of dashboard views

All views are siblings inside `<div class="main">`. A missing `</div>` causes
all subsequent views to inherit `display:none`. Verify after edits:

```python
python3 -c "
from app_factory import create_app
app = create_app({'db_path':'/tmp/check.db','https_enabled':False})
c = app.test_client()
c.post('/login', data={'username':'admin','password':'changeme123'}, follow_redirects=True)
body = c.get('/app/').data.decode()
main_open = body.find('<div class=\"main\">')
depth = 0; view_depths = {}; i = main_open
while i < len(body):
    if body[i:i+4] == '<div': depth += 1
    elif body[i:i+6] == '</div>': depth -= 1
    chunk = body[i:i+60]
    for v in ['view-dashboard','view-domains','view-scan','view-trends',
              'view-ct','view-roadmap','view-settings','view-group-report']:
        if 'id=\"'+v+'\"' in chunk: view_depths[v] = depth
    i += 1
for v,d in view_depths.items(): print(f'  {\"OK\" if d==2 else \"WRONG depth=\"+str(d)}  {v}')
"
```

### 9.3 fetch() path rewrite

Dashboard JS uses `/api/...` paths. Under `/app/` the auth shell rewrites these
to `/app/api/...`. All new JS fetch calls must use `/api/...` paths.

### 9.4 Config: https_enabled and ProxyFix

```yaml
dashboard:
  https_enabled: true   # set true when behind nginx with TLS
```

nginx must pass: `proxy_set_header X-Forwarded-Proto $scheme;`

### 9.5 Domain-list scoping in new endpoints

Every endpoint returning domain data **must** call `filter_assessments(data, user)`.

### 9.6 Community scoping in group report endpoints

Every group report endpoint must call `_allowed_org_ids(user, db)` and pass the
result to the relevant DB function. Pattern:

```python
@app_bp.route("/api/regions/<path:region>/report")
@require_community_manager
def api_region_report(region):
    db   = _db()
    user = current_user()
    from reports.community_report import build_report
    rows   = db.get_region_aggregate(region, allowed_org_ids=_allowed_org_ids(user, db))
    report = build_report(region, "Region", rows)
    return jsonify(report)
```

### 9.7 DNSDumpster API key configuration

```yaml
dns_enumeration:
  dnsdumpster_api_key: "your-key"
```
Or export `PQC_DNSDUMPSTER_KEY`. Without a key, falls back to HTML scraping
(fragile, dev-only). Test with `scripts/dnsdumpster-test.sh`.

The API returns quota errors as `{"error":"Daily quota exceeded"}` in the body
of a HTTP 429. The enumerator detects this by inspecting `resp.text` before any
status-code branching. Once detected, `_DNSDUMPSTER_QUOTA_EXHAUSTED = True`
prevents all further API calls for the session; passive DNS fallback activates.

### 9.8 Database key in Flask config

The database instance is registered as `current_app.config["PQC_DB"]`, accessed
via `_db()` in `app_routes.py`. **Never use `config["DATABASE"]`** — that key
does not exist and will raise a KeyError.

### 9.9 systemd unit constraints

- No `${VAR:-default}` in `ExecStart` — declare defaults as `Environment=` lines
- `StartLimitIntervalSec`/`StartLimitBurst` belong in `[Unit]`, not `[Service]`
- No inline bash with shell variables in `ExecStartPre` — use a separate script
- `Type=simple` is correct for gunicorn

### 9.10 level="na" — no-TLS domains

Must be excluded from: score averages, level counts, roadmap generation,
distribution charts. Present in the "No TLS" stat card on the dashboard.

### 9.11 deploy.sh trigger sets

`scripts/deploy.sh` restarts services only when files in their trigger sets are
synced. New Python modules must be added to `WEB_TRIGGERS` or `SCHEDULER_TRIGGERS`.

---

## 10. Planned Features — Prioritised Backlog

### Tier 1 — Config / data changes only

- **[T1-1]** Fix AV false positives — move cipher strings to JSON, replace dynamic imports
- **[T1-2]** Geography / region on domain lists — schema v18
- **[T1-3]** Expiry warnings in dashboard — `cert_expiry_days` already stored
- **[T1-4]** Export roadmap as PDF/DOCX
- **[T1-5]** Asset criticality weighting

### Tier 2 — New columns + existing module extension

- **[T2-1]** Service type UI filtering (schema delivered v1.2.0; UI work remains)
- **[T2-2]** Per-domain resource aggregation view
- **[T2-3]** Geographic coordinates on assessments
- **[T2-4]** Executive PDF reporting
- **[T2-5]** Budget and resource estimation in roadmap

### Tier 3 — New modules, moderate complexity

- **[T3-2]** Geographic map view (choropleth + dot; requires T2-3; Leaflet.js)
- ~~**[T3-3]** SSL Labs integration~~ — **delivered in v1.9.0** (cache-only during scans + on-demand fresh; results in domain_extra; display-only grade)
- **[T3-4]** Sector benchmarking (AVG score by sector+region across all runs)

### Tier 4 — Significant architectural changes

- **[T4-1]** Multi-resource domain model
- **[T4-2]** Trend alerting and notifications (email/webhook)
- **[T4-3]** SAML / OIDC authentication
- **[T4-4]** Dashboard frontend separation (static/ + Jinja2 templates)

---

## Appendix A — Running the Test Suite

```bash
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest tests.test_auth -v   # specific module
python3 tests/seed_demo_data.py --runs 3  # seed demo data
python3 pqc_monitor.py dashboard          # → http://localhost:5000  admin/changeme123
```

---

## Appendix B — Deployment Quick Reference

```bash
# Service management
sudo systemctl enable --now pqc-monitor.target
sudo systemctl status pqc-monitor-web
journalctl -u pqc-monitor-web -f
journalctl -u pqc-monitor-scheduler -f

# Config files
/etc/pqc-monitor/config.yaml       # perms: 640 root:pqcmonitor
/etc/pqc-monitor/pqc-monitor.env   # perms: 640 root:pqcmonitor

# Runtime data
/var/lib/pqc-monitor/pqc_monitor.db

# Deploy
sudo scripts/deploy.sh --dry-run
sudo scripts/deploy.sh

# Connectivity tests
bash scripts/shodan-test.sh         # tests 8.8.8.8 (free) + google.com (paid)
bash scripts/dnsdumpster-test.sh    # tests API key + quota status

# DNS enumeration
./pqc_monitor.py scan --domains list.txt --dns-enumerate
./pqc_monitor.py scan --domains list.txt --dns-enumerate --skip-scanned
./pqc_monitor.py scan --domains list.txt --dns-enumerate --skip-scanned --force

# One-time DB fix for existing installs (no-TLS → na)
python3 scripts/fix_notls_level.py --dry-run
python3 scripts/fix_notls_level.py
```

---

## Appendix C — Adding a New Feature: Checklist

1. **New DB columns** → add migration to `data/migrations.py`, bump version
2. **New DB methods** → add to `data/database.py` `Database` class
3. **New scan step** → add module in `scanner/`, wire into `orchestrator._scan_domain`
4. **New API endpoint** → `app_routes.py` (analyst/community_manager) or `admin/routes.py` (admin)
   - Always add `@require_auth` (or `@require_admin` / `@require_community_manager`)
   - Always call `filter_assessments()` for domain data
   - Always call `_allowed_org_ids()` for community-scoped group data
5. **New dashboard view** → add HTML view div inside `<div class="main">` in `dashboard/app.py`
   - Verify all view divs at depth=2 using script in §9.2
6. **New tests** → add to appropriate `tests/test_*.py`
7. **Version bump** → edit `VERSION` file, add row to §2 table, add §2.x detail section
8. **CHANGELOG** → add entry under new version heading
9. **RBAC** → add permission strings to `PERMISSIONS` in `auth/models.py` if needed
10. **Deploy script** → add new Python module to `WEB_TRIGGERS` / `SCHEDULER_TRIGGERS`
11. **Lint check** → `python3 -m py_compile <file>` before delivering any Python file

---

## Appendix D — Operational Scripts

| Script | Purpose |
|--------|---------|
| `scripts/deploy.sh` | Incremental git→/opt/pqc-monitor sync; restarts only affected services |
| `scripts/shodan-test.sh` | Two-tier Shodan key + plan test (8.8.8.8 free; google.com paid) |
| `scripts/dnsdumpster-test.sh` | DNSDumpster API key test; reports record counts per type |
| `scripts/fix_notls_level.py` | One-time retroactive fix for critical→na no-TLS rows |
| `scripts/bulk_assign.py` | Bulk region/community assignment from org name list |
| `scripts/bulk_org_assign.py` | Bulk domain→org assignment by TLD |
| `scripts/diagnose.py` | Shodan/DNSDumpster connectivity diagnostic |
| `scripts/wait-for-db.sh` | DB readiness poll (systemd ExecStartPre for scheduler) |
