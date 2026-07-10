# Changelog

All notable changes to PQC-Monitor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [1.9.0] — 2026-07-09

### Fixed
- **Domain detail showed only the passively-negotiated cipher suite**: the
  full active cipher enumeration (stored in `domain_extra['cipher_enum']`)
  never reached the UI, and the modal truncated `cipher_suites` to 2 entries.
  The assessor now merges the complete enumerated suite set (IANA names) into
  `assessments.cipher_suites`, `/api/domain/<domain>` returns the latest
  enrichment blobs (`cipher_enum`, `chain`, `cdn`, `ssllabs`), and the modal
  shows a per-security-level summary with a **Full TLS Details** drill-down
  view listing every accepted suite (protocol, bits, category, assessment).
- **CIPHER_ENUM findings did not name the offending suites**: every
  cipher-enumeration finding (NULL/EXPORT/ANON/RC4/3DES/no-FS/deprecated) now
  lists the specific IANA cipher suite names to remove, both in the message
  and in a machine-readable `ciphers` field.
- **Passive cipher names never matched guideline rules**: the passively
  negotiated cipher (OpenSSL notation, e.g. `ECDHE-RSA-AES128-GCM-SHA256`)
  is now normalised to IANA notation before `_assess_cipher()`, so guideline
  `recommended`/`deprecated` lists (which use IANA names) match correctly.
- **`tests/test_assessor.py`**: `test_empty_scan_list` still expected
  `level="critical"` for a no-TLS domain — stale since the v1.4.0 `na` change.

### Added
- **CAMELLIA and SEED cipher probes** (`scanner/cipher_enum.py`): 7 new
  probe entries + IANA mappings, closing the coverage gap vs SSL Labs on
  European servers (e.g. `TLS_RSA_WITH_CAMELLIA_128_CBC_SHA`).
- **SSL Labs integration (T3-3)** — `scanner/ssllabs_client.py`:
  - Qualys SSL Labs **API v4** client (one-time registration required;
    registered organisational email sent as auth header; helper
    `register_email()` included). v3 was deprecated 2023-12-31.
  - **Cache-only during scan runs** (`fromCache=on`, never triggers external
    assessments inline); summary stored in `domain_extra['ssllabs']`.
  - **On-demand fresh assessment** from the Full TLS Details view
    (`startNew=on`, `publish=off`), polled by the UI; restricted to users
    with `scan.run` permission. New endpoints:
    `GET /app/api/ssllabs/<domain>` (poll + persist when READY),
    `POST /app/api/ssllabs/<domain>/refresh`.
  - Grade + link to the public ssllabs.com report shown in the domain modal
    and detail view. **Display only — the grade does not affect the PQC
    score** (by design decision).
  - Config: `ssllabs.enabled` / `ssllabs.email` (or `PQC_SSLLABS_EMAIL`).
- **`data/database.py`**: `get_latest_domain_extra(domain, data_types)` —
  most recent enrichment blob per type across all runs (with `_recorded_at` /
  `_run_id` provenance); `get_latest_run_id_for_domain(domain)`.
- **Tests**: `tests/test_ssllabs_and_cipher_detail.py` (7 tests).
- **`scripts/reassess_all.py`**: reassess every existing domain to backfill
  the two fixes above. Score-only by default (no traffic/CPU-light —
  reuses stored `cipher_enum`/chain/CDN blobs and regenerates the named
  findings); `--rescan` for a resource-guarded network rescan
  (`--workers`/`--sleep`/`--limit`/`--only-missing`/`--dry-run`).
- **`scanner/crypto_assessor.py`**: `Finding` gains an optional machine-
  readable `ciphers` list, carried through from cipher-enum findings.

---

## [1.8.0] — 2026-06-27

### Fixed
- **`app_routes.py`**: community manager region/country Group Reports returned
  all organisations in the region/country instead of only those belonging to
  the user's assigned communities. Added `_allowed_org_ids(user, db)` helper
  that returns `None` for admins (no restriction) or a `set` of org IDs for
  community managers (direct `user.org_ids` + all orgs from their communities).
  Applied to all 6 region/country report endpoints (JSON, CSV, PDF variants).
  Refactored `api_regions()` and `api_countries()` list endpoints to reuse the
  same helper. Admins are unaffected.
- **`data/database.py`**: added `get_assessed_domains(domains)` — returns the
  subset of a domain list that already has at least one assessment record;
  used by `--skip-scanned` in the CLI.
- **`scanner/dns_enumerator.py`**: DNSDumpster quota exhaustion was not
  detected. The API returns `{"error":"Daily quota exceeded"}` as the body of
  a HTTP 429 response; the old code branched on status code before reading the
  body, entering an infinite 2-second retry loop. Fixed by inspecting
  `resp.text` for the word "quota" or "daily" before any status-code branching.
  Added `DnsDumpsterQuotaError` exception, session-level `_DNSDUMPSTER_QUOTA_EXHAUSTED`
  flag, and `is_dnsdumpster_quota_exhausted()` public accessor. Subsequent
  domains in the same scan session skip the API entirely once quota is hit.
  Also fixed: the file had been inadvertently doubled (two full copies of every
  function) by a prior edit; rebuilt cleanly from backup with surgical patches.

### Added
- **`scanner/dns_enumerator.py`**: passive DNS fallback (`_passive_dns_enum`)
  — activates automatically when DNSDumpster quota is exhausted or when
  DNSDumpster is not configured. Uses dnspython only, no external APIs.
  Techniques: SRV record probing (20 well-known service prefixes), zone
  transfer attempt (AXFR) against each authoritative NS (silently refused by
  virtually all public servers, catches misconfigured ones), PTR reverse lookup
  of apex A records.
- **`pqc_monitor.py`**: `scan` command gains `--skip-scanned` and `--force`
  flags. `--skip-scanned` queries `get_assessed_domains()` before starting,
  prints the skipped domain list, and exits cleanly if nothing remains.
  `--force` overrides `--skip-scanned` and scans all domains regardless.
- **`scripts/shodan-test.sh`**: new test script to verify the Shodan API key
  from config. Runs two lookups — `8.8.8.8` (in the oss free shared dataset,
  confirms key validity) and `google.com` (CDN IP, outside free dataset,
  confirms paid plan capability). Reports `"capability"` field: `"full"` or
  `"restricted (oss/free — shared dataset only)"`. Exit 0 if key is valid;
  exit 1 if key is broken/missing; exit 2 if shodan library not installed.
- **`scripts/dnsdumpster-test.sh`**: new test script to verify the DNSDumpster
  API key from config. Calls the API for a target domain, reports record counts
  per type and a sample of discovered hostnames. Detects quota exhaustion and
  key errors. Exit 0 on success or no-data; exit 1 on key/quota error.

### Changed
- **`scanner/dns_enumerator.py`**: passive DNS fallback now also runs when
  DNSDumpster is not configured (not just on quota exhaustion), ensuring
  SRV/AXFR/PTR probing always supplements CT and wordlist results.

---

## [1.7.0] — 2026-06-27

### Added
- **Group Report: By Country view** — new "By Country" option in the view
  selector; `/app/api/countries` lists distinct countries from visible orgs;
  `/app/api/countries/<cc>/report[.csv/.pdf]` return aggregate reports;
  `get_country_aggregate()` and `get_countries()` added to `data/database.py`
- **Group Report: Charts** — two inline SVG charts rendered above the table
  on report load: donut chart (org count by readiness level with legend) and
  horizontal bar chart (score per organisation, colour-coded by level, sorted
  by descending score)
- **Group Report: Sortable table** — clicking any column header sorts
  ascending/descending with ▲/▼ indicator; level column sorts by severity
  order (Critical → Weak → Moderate → Ready → N/A); text columns default to
  ascending, numeric columns default to descending on first click
- **`scripts/bulk_assign.py`** — standalone bulk-assignment tool:
  given a list of org names (file or stdin), sets a region and/or creates
  (if absent) and populates a community; supports `--dry-run`; case-insensitive
  org name matching; unmatched names reported as warnings; skips already-assigned

### Changed
- Group Report view: `grClearTable()` also hides the chart area on reset;
  country filter is still shown only when group spans >1 country

---

## [1.6.3] — 2026-06-27

### Fixed
- **`scripts/deploy.sh`**: `restart_service()` called `systemctl is-active --quiet`
  as a pre-flight guard before `systemctl restart`. On this server, running as a
  non-root user, `is-active --quiet` returns non-zero for active system services
  despite the service genuinely running — causing the deploy script to print
  "not running — skipping restart" and silently skip the restart.
  Fixed by removing the guard entirely: `systemctl restart` is idempotent and
  works on running, stopped, or failed units. If the unit doesn't exist it fails
  with a clear error message.

---

## [1.6.2] — 2026-06-27

### Fixed
- **`app_routes.py`**: all 8 community/region API endpoints used
  `current_app.config["DATABASE"]` which does not exist — the correct
  key registered by `app_factory.py` is `"PQC_DB"`, accessible via the
  existing `_db()` helper. This caused 500 errors on every call to
  `/app/api/communities`, `/app/api/regions`, and all report endpoints.
  Replaced all 8 occurrences with `_db()`.
- **`admin/routes.py`**: communities view div was injected outside
  `</div><!--/main-->`, making it invisible when selected. Moved inside
  the main content area. Table class `data-table` corrected to `tbl`
  (the only table class defined in the admin stylesheet). Added
  `loadCommunities()` call to `showView()` dispatch so the table
  populates on nav click.

---

## [1.6.1] — 2026-06-27

### Fixed
- **`scripts/deploy.sh`**: `data/` was listed in `PROTECTED` paths, causing
  `data/database.py`, `data/migrations.py`, `data/geo_inference.py`, and
  `data/tld_geo.csv` to be silently skipped on every deployment. The live
  database (`pqc_monitor.db`) and scan artefacts live in `/var/lib/pqc-monitor/`
  — a completely separate path that is never tracked by git — so they were
  never at risk of being overwritten. Removed `data/` from `PROTECTED`; added
  explanatory comment. `data/` remains in `WEB_TRIGGERS` and
  `SCHEDULER_TRIGGERS` so service restarts still fire correctly when DB or
  migration code changes.

---

## [1.6.0] — 2026-06-27

### Added
- Community concept: group organisations for scoped access and reporting
- `ROLE_COMMUNITY_MANAGER`: new role between analyst and admin; auto-promoted
  from analyst on first community assignment
- Group Report tab: By Community + By Region views, country filter, PDF/CSV
  export, executive summary paragraph
- `reports/community_report.py`: weasyprint PDF generation (A4 landscape)
- 8 new API endpoints under `/app/api/communities` and `/app/api/regions`
- `community` CLI group with 7 subcommands (create, list, add-org, remove-org,
  assign-user, revoke-user, report, region-report)
- Admin UI: Communities section with create/edit/delete and org assignment
- Schema v17: `communities`, `community_organisations`, `user_communities`
- 31 new tests

---

## [1.5.2] — 2026-06-27

### Fixed
- `data/database.py`: `update_organisation()` whitelist missing `country_code`
  and `country` — fields were silently dropped on every PATCH
- `admin/routes.py`: `syncCountryName()` referenced but never implemented —
  ReferenceError in browser prevented country value from being submitted
- `data/database.py`: migration failures logged at DEBUG and swallowed; now
  logged at ERROR and re-raised, causing hard startup failure with clear message

---

## [1.5.1] — 2026-06-27

### Added
- Country and region on scan runs (schema v16)
- TLD-based auto-inference via `data/tld_geo.csv` and `data/geo_inference.py`
- `--country-code` / `--country` on `scan` and `schedule` CLI commands
- `list-runs` output gains Country and Region columns
- 12 new tests in `TestGeoInference`

---

## [1.5.0] — 2026-06-27

### Added
- Country on organisations: `country_code` (ISO 3166-1 alpha-2) + `country`
  (display name); schema v15
- Country dropdown filter in dashboard Domain Assessments view
- `?country_code=` filter on `GET /api/assessments`
- 7 new tests

---

## [1.4.0] — 2026-06-27

### Fixed
- No-TLS domains shown as Critical → now level `na` (N/A)
- Analyst users could see tabs with forbidden actions
- Roadmap included entries for no-TLS (na) domains
- Scheduler service not starting due to DB path mismatch in systemd unit

### Added
- `scripts/deploy.sh`: incremental git→deployment sync
- `scripts/fix_notls_level.py`: one-time retroactive fix for existing na rows

---

## [1.3.1] — 2026-06-25

### Fixed
- 10 production deployment issues (systemd, gunicorn, nginx, DB path, sessions)

---

## [1.3.0] — 2026-06-12

### Added
- DNSDumpster official REST API key support
- Organisation grouping (schema v14): full org CRUD API + admin panel tab
- `?org_id=` and `?region=` filters on assessments
- Analyst org scoping in RBAC

---

## [1.2.0] — 2026-06-12

### Added
- T2-1: `service_type` column on assessments (schema v13)
- T3-1: `scanner/dns_enumerator.py` — CT SANs + wordlist + DNSDumpster
- `POST /api/dns-enumerate` endpoint
- `dns_enumerate` flag on `POST /api/save-domains`

---

## [Unreleased]

---

## [1.1.3] — earlier

### Fixed
- CT/Roadmap/Settings tabs empty — missing `</div>` in `view-trends`

---

## [1.1.2] — earlier

### Fixed
- CT/Roadmap/Settings tabs empty (stray `return app`)
- `showView` used implicit `event.target`

### Added
- Dashboard card filtering and sortable columns

---

## [1.1.1] — earlier

### Fixed
- Login loop on plain HTTP (`SESSION_COOKIE_SECURE` defaulted True)
- Absolute `?next=` URL redirect

---

## [1.1.0] — earlier

### Added
- RBAC (admin/analyst roles), systemd units, `VERSION` file

---

## [1.0.0] — earlier

Initial release: core scan engine, TLS probe, assessor, guidelines, dashboard
SPA, CLI, scheduler.
