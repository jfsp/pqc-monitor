# PQC-Monitor — Developer Handover Document

**Version:** 1.4.0
**Date:** 2026-06-27
**Status:** 452/452 tests passing (no new tests this session — bug fixes only)
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

### Source Repository

**GitHub:** https://github.com/jfsp/pqc-monitor

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

**Commit format used in this project:**
```
type(scope): short description (≤72 chars)

- bullet explaining what changed and why
- backlog reference if applicable (e.g. T2-1, T3-1)

files/changed.py
```
Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

### Deployment Workflow (incremental)

The server runs from `/opt/pqc-monitor`. Git checkout is in a separate user's home directory. Use `scripts/deploy.sh` to sync changed files:

```bash
# Preview what would be deployed (last commit)
scripts/deploy.sh --dry-run

# Deploy last commit (restarts services only if Python code changed)
sudo scripts/deploy.sh

# Deploy from a specific commit
sudo scripts/deploy.sh --from abc1234
```

The script uses `git diff --diff-filter=AMRC` to identify changed files, skips protected paths (`config/config.yaml`, `data/`, `.venv/`), syncs with `rsync --checksum`, and restarts services only when files in their trigger sets change (see §9.9).

---

## 2. Version History

| Version | Key additions |
|---------|--------------|
| 1.0.0 | Core scan engine, TLS probe, assessor, guidelines, dashboard SPA, CLI, scheduler |
| 1.1.0 | RBAC (admin/analyst roles), systemd units, `VERSION` file, `https_enabled` config, domain list CRUD |
| 1.1.1 | Fix: login loop on plain HTTP (`SESSION_COOKIE_SECURE` defaulted True); fix: absolute `?next=` URL redirect |
| 1.1.2 | Fix: CT/Roadmap/Settings tabs empty (stray `return app` before blueprint registration); fix: `showView` used implicit `event.target`; added dashboard card filtering and sortable columns |
| 1.1.3 | Fix: CT/Roadmap/Settings still empty — `</div>` missing from `view-trends`, making CT/Roadmap/Settings children of trends in DOM |
| 1.2.0 | T2-1: `service_type` column on assessments (migration v13), port→service_type map, `?service_type=` filter on `GET /api/assessments`; T3-1: `scanner/dns_enumerator.py` (CT SANs + wordlist + DNSDumpster), `POST /api/dns-enumerate`, `dns_enumerate` flag on `POST /api/save-domains` |
| 1.3.0 | DNSDumpster official API key support; Organisation grouping (migration v14); full org CRUD API; admin panel tab; `?org_id=` and `?region=` filters; analyst org scoping in RBAC |
| 1.3.1 | Fix: production deployment — systemd unit errors, database path, session persistence, reverse proxy headers. See §2.1 for full details. |
| 1.4.0 | Fix: no-TLS domains shown as Critical → now N/A; fix: analyst sees forbidden tabs; fix: roadmap includes N/A domains; fix: scheduler service not starting (DB path mismatch); new: incremental deploy script. See §2.2 for full details. |
| 1.5.0 | Feature: Country on organisations — `country_code` (ISO 3166-1 alpha-2) + `country` (display name) on every org; schema v15; country dropdown filter in dashboard; `?country_code=` on `/api/assessments`. See §2.3 for full details. |
| 1.5.1 | Feature: Country + region on scan runs — TLD-based auto-inference via `data/tld_geo.csv`; schema v16; `--country-code`/`--country` on `scan` and `schedule` CLI commands; `list-runs` shows country column. See §2.4 for full details. |
| 1.5.2 | Fix: country edits not persisting — `update_organisation()` whitelist missing `country_code`/`country`; `syncCountryName()` undefined in admin UI; migration failures silently swallowed (now ERROR + re-raise). See §2.5 for full details. |
| 1.6.0 | Feature: Community concept — group organisations for scoped access and reporting; `ROLE_COMMUNITY_MANAGER`; Group Report tab (community + region views, PDF/CSV export, country filter); 8 new API endpoints; `community` CLI group (7 subcommands); weasyprint PDF; 31 new tests; schema v17. See §2.6 for full details. |
| 1.6.1 | Fix: `scripts/deploy.sh` — `data/` was in PROTECTED list, blocking `data/database.py`, `data/migrations.py`, `data/geo_inference.py`, `data/tld_geo.csv` from being deployed. Live DB lives in `/var/lib/` and is never in git. Removed `data/` from PROTECTED; added explanatory comment. |
| 1.7.0 | Feature: Group Report enhancements — By Country view (DB + 4 API endpoints); inline SVG charts (donut + bar); sortable table headers; `scripts/bulk_assign.py` for bulk region/community assignment. See §2.7 for full details. |

### 2.1 v1.3.1 — Deployment fixes (2026-06-25)

This release contains no functional changes. All changes fix production deployment issues discovered on first deployment to a Ubuntu server behind nginx.

**Files changed:** `systemd/pqc-monitor-web.service`, `systemd/pqc-monitor-scheduler.service`, `scripts/wait-for-db.sh` (new), `data/database.py`, `app_factory.py`, `pqc_monitor.py`, `install.sh`, `config/config.yaml.example`

#### Fix 1 — systemd `${VAR:-default}` syntax not supported

`ExecStart` arguments go directly to `execve()` — no shell involved. The bash `${VAR:-default}` fallback syntax is not understood by systemd's own `${}` expansion. **Fix:** Declare defaults as `Environment=` lines before `EnvironmentFile=`.

#### Fix 2 — `StartLimitIntervalSec`/`StartLimitBurst` in wrong section

These keys belong in `[Unit]`, not `[Service]`. Moved to `[Unit]` in both service files.

#### Fix 3 — Scheduler fails if web service has not yet created the database

New script `scripts/wait-for-db.sh` invoked as `ExecStartPre`. Added `Requires=pqc-monitor-web.service`.

#### Fix 4 — Database path resolution is CWD-dependent

`Database.__init__` now resolves to absolute path at construction time via `os.path.abspath(db_path)`.

#### Fix 5 — `app_factory.create_app()` ignores `config.yaml` when called by gunicorn

`create_app()` now calls `load_config()` when invoked with no arguments.

#### Fix 6 — Relative `db_path` in `load_config()` is CWD-dependent

Resolved against `ROOT` (the app directory) at config load time.

#### Fix 7 — Database stored alongside code in `/opt/pqc-monitor/data/`

Runtime data moved to `/var/lib/pqc-monitor/`. `ReadWritePaths` updated in both service units.

#### Fix 8 — Gunicorn control socket tries to write to `/home/pqcmonitor`

`--worker-tmp-dir /tmp` added to the gunicorn `ExecStart` invocation.

#### Fix 9 — `Type=notify` with plain gunicorn causes systemd timeout

Changed to `Type=simple`.

#### Fix 10 — Login loop: session cookie not persisting after successful auth

Added `ProxyFix` middleware. `proxy_set_header X-Forwarded-Proto $scheme;` required in nginx.

---

### 2.2 v1.4.0 — Bug fixes and deploy tooling (2026-06-27)

**Files changed:** `scanner/crypto_assessor.py`, `data/database.py`, `app_routes.py`, `dashboard/app.py`, `roadmap/generator.py`, `systemd/pqc-monitor-scheduler.service`, `scripts/deploy.sh` (new), `scripts/fix_notls_level.py` (new)

#### Fix 1 — No-TLS domains shown as Critical

**Root cause:** `crypto_assessor.assess_domain()` returned `score=0, level="critical"` when `scan_results` was empty (domain has no TLS service). These domains appeared in the Critical count in the dashboard and showed a red Critical badge in the domain table.

**Fix:** Added `LEVEL_NA = "na"` constant. Empty scan results now produce `level="na"`. Changes propagated throughout the stack:

- `scanner/crypto_assessor.py` — `LEVEL_NA` constant; `not scan_results` branch uses it
- `data/database.py` — `get_summary_stats()` excludes `level="na"` rows from score averaging and level counts; adds `na_count` field
- `app_routes.py` — analyst-scoped summary stats block applies same exclusion
- `dashboard/app.py`:
  - CSS: `.val-na`, `.score-na`, `.dot-na` (muted grey)
  - Stats grid: new "No TLS" card (`stat-na`, `filter-card-na`) — clickable filter
  - `loadSummary()` populates `stat-na` from `s.na_count`
  - `renderAssessments()` shows "N/A" score badge and "No TLS" level for na rows; findings column shows "—"
  - `applyFilterAndSort()` — `LEVEL_ORDER` gets `na: 4`; score sort pushes na rows to the end
  - `showDomainDetail()` — score shows "N/A", level shows "No TLS Service"
  - `levelColor()` returns `var(--muted)` for `"na"`

**One-time DB migration:** Run `scripts/fix_notls_level.py` to retroactively fix existing rows. The script identifies no-TLS rows by requiring all five conditions: `level="critical"`, `score=0`, `tls_versions=[]`, `cipher_suites=[]`, `errors_json` contains `"No scan data available"`. Supports `--dry-run`.

```bash
python3 scripts/fix_notls_level.py --dry-run   # preview
python3 scripts/fix_notls_level.py              # apply
```

#### Fix 2 — Analyst user sees tabs with forbidden actions

**Root cause:** Nav buttons for Domain Discovery, Scan, CT Monitor, and Settings were rendered unconditionally regardless of role. Analysts lack `scan.run`, `domain_list.manage`, and `ct.run` — clicking those tabs produced 403 errors.

**Fix:** Jinja2 `{% if user.is_admin %}` conditionals in `dashboard/app.py`:
- **Domain Discovery** tab: hidden for analysts (Discover and Save List both require `scan.run`/`domain_list.manage`)
- **Scan** tab: hidden for analysts (Start Scan and Re-Assess both require `scan.run`)
- **CT Monitor** tab: remains visible (analysts have `ct.view_own`; stats/data load fine); only the "Run CT Monitor" action panel is hidden
- **Generate Roadmap** panel: hidden for analysts (requires `roadmap.generate`)
- **Settings** tab: visible to all (static reference info, no API calls)

#### Fix 3 — Roadmap shows entries for no-TLS domains

**Root cause:** `generate_sector_roadmap()` passed all assessments including `level="na"` ones to `generate_domain_roadmap()`, producing empty zero-score roadmap entries that inflated P1 counts and distorted effort estimates.

**Fix:** `roadmap/generator.py`:
- `generate_domain_roadmap()` — returns early with a zero-effort empty `DomainRoadmap` when `level="na"`
- `generate_sector_roadmap()` — filters out `level="na"` assessments before processing; `domain_count` and `avg_current_score` reflect only scored domains; logs skipped count at DEBUG

#### Fix 4 — Scheduler service not starting (DB path mismatch)

**Root cause:** The deployed service file set `Environment=PQC_DB_PATH=data/pqc_monitor.db` (relative) and then constructed `/opt/pqc-monitor/${PQC_DB_PATH}` in an inline bash `ExecStartPre`, resolving to `/opt/pqc-monitor/data/pqc_monitor.db`. The actual database (per `config.yaml`) is at `/var/lib/pqc-monitor/pqc_monitor.db`. The inline bash also used shell variables `$waited` and `$limit` in the unit directive, which systemd tried to expand as environment variables, causing the "Referenced but unset environment variable" warnings and blank `(s elapsed)` in the logs.

**Fix:** `systemd/pqc-monitor-scheduler.service`:
- `PQC_DB_PATH` set to the correct absolute path `/var/lib/pqc-monitor/pqc_monitor.db`
- Inline bash replaced with the clean `ExecStartPre=/opt/pqc-monitor/scripts/wait-for-db.sh $PQC_DB_PATH 60` form (systemd expands `$PQC_DB_PATH` from the `Environment=` block; the script's own local variables never appear in the unit directive)

**To deploy on server:**
```bash
sudo cp systemd/pqc-monitor-scheduler.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart pqc-monitor-scheduler
```

#### New: Incremental deployment script (`scripts/deploy.sh`)

Syncs only the files changed in the last git commit (or a specified base commit) from the git checkout to `/opt/pqc-monitor`, then restarts only the services whose Python code was touched.

```bash
scripts/deploy.sh --dry-run          # preview
sudo scripts/deploy.sh               # deploy last commit
sudo scripts/deploy.sh --from abc123 # deploy from specific commit
sudo scripts/deploy.sh --no-restart  # sync without restarting services
```

Service restart trigger sets (restart only when these paths change):
- `pqc-monitor-web`: `app_factory.py`, `app_routes.py`, `version.py`, `requirements.txt`, `admin/`, `auth/`, `ct/`, `dashboard/`, `data/`, `domain_discovery/`, `reports/`, `roadmap/`, `scanner/`
- `pqc-monitor-scheduler`: `pqc_monitor.py`, `version.py`, `requirements.txt`, `ct/`, `data/`, `scanner/`, `scheduler/`

Files outside both sets (`scripts/`, `tests/`, `systemd/`, `guidelines/`, docs) never trigger a restart.

---

## 2.7 — v1.7.0 detail

**Group Report enhancements + bulk assignment tool**

### By Country view

New "By Country" option in the Group Report view-by selector. Fetches `/app/api/countries` which returns distinct `country_code`/`country` pairs from orgs visible to the current user. Selecting a country loads the aggregate report via `/app/api/countries/<cc>/report` (same structure as community/region). CSV and PDF export work identically. DB layer: `get_country_aggregate(cc)` filters `organisations` by `UPPER(country_code) = UPPER(?)` and feeds `_build_group_aggregate()`. `get_countries()` returns distinct pairs ordered by `country_code`.

### Inline charts

Two SVG charts rendered above the table when a report is loaded:

- **Donut chart** (`#gr-donut`): org count by readiness level (Critical/Weak/Moderate/Ready/N/A) with legend. Pure inline SVG, no external library.
- **Bar chart** (`#gr-bars`): one horizontal bar per org, sorted descending by score, colour-coded by level. Bar width proportional to score (0–100). Clears when no report is loaded.

Both charts respond to the country filter dropdown.

### Sortable table

Every column header in the Group Report table is clickable. `grSort(col)` sorts `_grFiltered` in place and re-renders. Sort state tracked via `_grSortCol` + `_grSortAsc`. Visual indicator (▲/▼) shown on the active column via `.gr-sort-ind` spans. Level column maps to severity order for sorting. Text columns (name, CC) default to ascending on first click; numeric columns default to descending.

### `scripts/bulk_assign.py`

Standalone script (no Flask context required). Usage:

```bash
# Set region on orgs from file:
python3 scripts/bulk_assign.py --region Europe --file orgs.txt

# Create/add to community:
python3 scripts/bulk_assign.py --community "Spanish Banking" --file orgs.txt

# Both at once, dry-run:
python3 scripts/bulk_assign.py --region Europe --community "EU Finance" --file orgs.txt --dry-run

# From stdin:
echo -e "Banco Santander\nBBVA" | python3 scripts/bulk_assign.py --region Europe
```

Input: one org name per line, `#` comments, blank lines ignored. Matching is case-insensitive exact (no partial match). Unmatched names printed as warnings. Already-assigned orgs skipped. Community created if it doesn't exist. DB path auto-detected from `config.yaml` or defaults to `/var/lib/pqc-monitor/pqc_monitor.db`.

**Files changed**: `data/database.py`, `app_routes.py`, `dashboard/app.py`, `scripts/bulk_assign.py` (new).

---

## 2.6 — v1.6.0 detail

**Community — group organisations for scoped access and reporting**

### Data model

```
communities               (id, name, description, created_at, created_by)
community_organisations   (community_id, org_id, added_at, added_by)  PK both cols
user_communities          (user_id, community_id, granted_at, granted_by)  PK both cols
```

Schema v17 adds all three tables with cascade deletes and indexes. Domain resolution for non-admin users now has three additive paths: direct domain lists → direct org assignments → community org assignments.

### Role: `community_manager`

New role between `analyst` and `admin`. Auto-promoted from `analyst` when first community is assigned via admin UI or CLI (`set_user_communities`). Admins are never affected. Has `group_report.view` permission (same as admin). Cannot access admin panel, run scans, or manage users.

### Group Report tab

Replaces the previous concept of separate community/region dashboards with a single tab. Positioned after Dashboard, before Domain Discovery. Tab is hidden from analysts. Features:

- Top selector: **By Community** or **By Region** (switches the group dropdown)
- Country filter: only shown when the selected group spans >1 distinct country
- Aggregate table: one row per org — CC, Sector, Domains, Score, Level badge, Critical/Weak/Moderate/Ready/No TLS/PQC counts; Totals row at bottom
- Executive summary panel: auto-generated paragraph (org count, avg score, PQC detection status)
- CSV and PDF export buttons (disabled until a group is selected)

### PDF report (`reports/community_report.py`)

Generated server-side via weasyprint. A4 landscape. Contains: PQC-Monitor branding header, group name + generation timestamp, executive summary paragraph, colour-coded aggregate table, footer. Requires weasyprint system deps (Pango, Cairo) — install with `apt install python3-weasyprint` or `pip install weasyprint` after system deps. PDF endpoint returns 503 JSON if weasyprint is not installed, so the rest of the app is not affected.

### API endpoints

All under `/app/api/` (auth-gated, require `community_manager` or `admin`):

| Endpoint | Description |
|---|---|
| `GET /api/communities` | List communities (scoped to user's assignments for non-admin) |
| `GET /api/communities/<id>/report` | JSON aggregate report |
| `GET /api/communities/<id>/report.csv` | CSV download |
| `GET /api/communities/<id>/report.pdf` | PDF download |
| `GET /api/regions` | Distinct region values visible to user |
| `GET /api/regions/<name>/report` | JSON aggregate by region |
| `GET /api/regions/<name>/report.csv` | CSV download |
| `GET /api/regions/<name>/report.pdf` | PDF download |

### CLI

```bash
# Create a community
pqc_monitor.py community create "Spanish Banking Sector" -d "Major Spanish banks"

# Add orgs
pqc_monitor.py community add-org 1 3   # community 1, org 3

# Assign user (auto-promotes analyst → community_manager)
pqc_monitor.py community assign-user 1 javier

# Generate reports
pqc_monitor.py community report 1 --format text
pqc_monitor.py community report 1 --format csv -o report.csv
pqc_monitor.py community region-report Europe --format json
```

### Admin UI

New **Communities** section in the left nav (between Organisations and Monitoring). Create/edit/delete communities, assign orgs via checkbox list. User modal updated: `community_manager` role option; community assignment section visible when role is `community_manager`; note explains auto-promote behaviour.

### Deploy notes

Run `deploy.sh` — both web and scheduler restart (both touch `data/`). Migration v17 runs automatically on startup. Install weasyprint system deps before deploying if PDF export is required:

```bash
sudo apt install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
pip install weasyprint>=62.0 --break-system-packages
```

PDF export gracefully degrades (503 JSON) if weasyprint is absent.

---

## 2.5 — v1.5.2 detail

**Bug fixes: country edits not persisting + silent migration failures**

Three bugs prevented country from being saved after the v1.5.0/v1.5.1 deploy:

1. **`data/database.py` — `update_organisation()` whitelist** (root cause of data loss):
   The `allowed` set was `{"name", "sector", "region", "description"}` — `country_code`
   and `country` were not included. Every PATCH received both fields from the route,
   but `update_organisation()` silently filtered them out before building the SQL UPDATE.
   Fixed: `allowed = {"name", "sector", "region", "description", "country_code", "country"}`.

2. **`admin/routes.py` — `syncCountryName()` undefined** (prevented value from being set):
   The country-code `<select>` had `onchange="syncCountryName()"` but the function was
   never implemented. Selecting a country threw `ReferenceError: syncCountryName is not
   defined` in the browser console, which in some browsers resets the select value before
   `submitOrgModal()` reads it. Fixed: added `syncCountryName()` implementation that
   extracts the display name from the selected option text and writes it to `f-org-country`.

3. **`data/database.py` — silent migration failure** (masked the schema lag):
   `Database.__init__` caught all migration exceptions and logged them at `DEBUG` level
   with the message `"Migrations skipped"`, then continued normally. Schema v15 almost
   certainly failed on startup (import path issue under gunicorn) and was swallowed,
   leaving the DB at v14 with no visible error. Fixed: now logs at `ERROR` and re-raises,
   causing a hard startup failure with a clear message instead of silent data loss.

**Deploy notes**: apply the three patches to the live server manually (as done during
diagnosis) then `sudo systemctl restart pqc-monitor-web`. No DB migration needed — v15
and v16 were applied manually during diagnosis.

---

## 2.4 — v1.5.1 detail

**Country and Region on Scan Runs + TLD-based Auto-Inference**

Every scan run now stores `country_code` and `country` alongside the existing `sector` and `region` fields. When not explicitly provided, both are auto-inferred from the ccTLDs in the domain list.

Inference rules (implemented in `data/geo_inference.py`):
- If the domain list yields exactly **one distinct ccTLD** → infer country and region from `data/tld_geo.csv`.
- If the domain list yields **multiple distinct ccTLDs** → no inference; CLI echoes which ccTLDs were found.
- If the domain list contains **only generic TLDs** (`.com`, `.net`, `.org`, etc.) → no inference.
- If `--country-code` is supplied explicitly → inference is skipped; the explicit value is used.
- Region is also auto-filled when omitted and inference succeeds.
- The CLI always echoes the inference outcome (inferred, skipped, or reason for skip).

`data/tld_geo.csv` — user-editable CSV shipped with the project. Format: `tld,country_code,country,region`. Comments (`#`) and blank lines are ignored. Admins may add, remove, or correct entries without touching code. Changes take effect on the next scan.

Changes by file:

- `data/tld_geo.csv` — new file; 200+ ccTLD entries covering Europe, America, Asia, Middle East, Africa, Oceania.
- `data/geo_inference.py` — new module; `infer_from_domains()`, `infer_and_fill()`, `_load_table()`. Pure stdlib, no network.
- `data/migrations.py` — migration **v16**: `ALTER TABLE scan_runs ADD COLUMN country_code TEXT DEFAULT ''` + `country TEXT DEFAULT ''`.
- `data/database.py` — `create_run()` accepts `country_code` and `country`; INSERT updated.
- `scanner/orchestrator.py` — `scan_domains()` and `reassess_run()` accept and propagate `country_code`/`country`.
- `scheduler/scan_scheduler.py` — `add_schedule()` stores `country_code`/`country` in `config_json`; `_run_scheduled_scan()` passes them to `scan_domains()`.
- `pqc_monitor.py` — `scan` command gains `--country-code`/`--country` options and calls `infer_and_fill()`; `schedule` command same; `list-runs` output gains Country and Region columns.
- `tests/test_orgs_and_dns.py` — `TestGeoInference` class with 12 tests (single ccTLD, mixed, generic, infer_and_fill, edge cases, CSV spot-checks, DB integration).

**Schema**: v16. Deploy path: `deploy.sh` (web + scheduler restart; both touch `data/`).

---

## 2.3 — v1.5.0 detail

**Country on Organisations**

Every organisation now carries `country_code` (ISO 3166-1 alpha-2, e.g. `ES`) and `country` (display name, e.g. `Spain`). Both fields default to empty string so existing data is unaffected.

Changes by file:

- `data/migrations.py` — migration **v15**: two `ALTER TABLE` statements add `country_code TEXT DEFAULT ''` and `country TEXT DEFAULT ''` to `organisations`.
- `data/database.py` — `create_organisation()` and `update_organisation()` accept both new fields; `update_organisation` whitelist updated.
- `admin/routes.py` — POST `/admin/api/organisations` and PATCH `/admin/api/organisations/<id>` pass/return both fields; org table gains a Country column; edit modal has a full ISO 3166-1 alpha-2 `<select>` with `syncCountryName()` auto-fill for the display name.
- `app_routes.py` — `GET /api/assessments` accepts `?country_code=XX` (case-insensitive); filters in-memory via `get_domain_org()`, same pattern as `?region=`.
- `dashboard/app.py` — new `<select id="filter-country">` in Domain Assessments toolbar (right of Region); `_activeCountry` state; `populateCountryDropdown()` builds options dynamically from `_orgsCache` (only countries with at least one org); country filter block in `applyFilterAndSort()`.
- `tests/test_orgs_and_dns.py` — 7 new tests covering DB-layer create/update/default and API-layer create/update/list.

**Schema**: v15. No breaking changes. Deploy path: run `deploy.sh` (web service restart only; scheduler not affected).

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
│   └── migrations.py       # Schema migration runner (current: v14)
├── domain_discovery/
│   └── domain_finder.py    # AI-powered domain discovery (Claude API)
├── guidelines/             # JSON rule files (nist_800_131a, bsi_tr02102, ccn_stic_221)
├── roadmap/
│   └── generator.py        # PQC migration roadmap generator
├── reports/
│   └── report_generator.py # CSV/JSON/text export
├── scanner/
│   ├── orchestrator.py     # Scan coordinator
│   ├── tls_probe.py        # TLS handshake prober
│   ├── crypto_assessor.py  # Scoring engine (guidelines → findings → score/level)
│   ├── crypto_extractor.py # Certificate field parser
│   ├── cipher_enum.py      # Cipher suite enumerator
│   ├── chain_validator.py  # Certificate chain analyser
│   ├── cdn_detector.py     # CDN fingerprinter
│   ├── dns_enumerator.py   # DNS deep-dive (CT SANs + wordlist + DNSDumpster)
│   ├── service_discovery.py# Port scanner
│   ├── shodan_client.py    # Shodan integration
│   └── starttls_probe.py   # STARTTLS prober (SMTP/IMAP/LDAP)
├── scheduler/
│   └── scan_scheduler.py   # APScheduler wrapper
├── scripts/
│   ├── deploy.sh           # Incremental git→deployment sync (NEW v1.4.0)
│   ├── fix_notls_level.py  # One-time DB fix: critical→na for no-TLS rows (NEW v1.4.0)
│   ├── bulk_org_assign.py  # Bulk domain→org assignment by TLD
│   ├── diagnose.py         # Shodan/DNSDumpster connectivity diagnostic
│   └── wait-for-db.sh      # DB readiness poll for systemd ExecStartPre
├── systemd/
│   ├── pqc-monitor-web.service
│   ├── pqc-monitor-scheduler.service
│   ├── pqc-monitor.target
│   └── pqc-monitor.env     # Secrets template (copy to /etc/pqc-monitor/)
├── tests/                  # 452 tests
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
  └── shodan_client      → Shodan enrichment (optional)
  └── crypto_assessor    → score + findings → DomainAssessment
       └── level = "na"  if no TLS service found (score=0, no findings)
  └── database.save_assessment()
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

**Current schema version:** 14 (managed by `data/migrations.py`)

### Key tables

**`scan_runs`** — one row per scan job
```sql
run_id TEXT PK, started_at TEXT, completed_at TEXT,
status TEXT, domain_count INTEGER, sector TEXT, region TEXT
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

**`tls_results`** — raw probe results (one row per port per domain per run)

**`domain_lists`** — saved domain lists with JSON domain array

**`domain_extra`** — keyed blob store for enrichment data (CDN, DNS, Shodan)

**`organisations`** — org groupings (name, sector, region)

**`domain_organisations`** — domain ↔ org membership

**`users`**, **`user_domain_lists`**, **`user_organisations`** — RBAC tables

**`roadmaps`** — saved roadmap results

**`ct_summaries`**, **`ct_certificates`** — CT monitor results

**`audit_log`** — all auth and data-access events

---

## 6. API Reference

All endpoints under `/app/api/` require authentication (`require_auth`). Admin-only endpoints additionally check `require_admin` or `user.can("permission")`.

### Summary & assessments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/summary` | user | Dashboard stats (excludes `na` domains from counts) |
| GET | `/api/assessments` | user | All latest assessments (domain-scoped for analysts) |
| GET | `/api/assessments?run_id=X` | user | Assessments for a specific run |
| GET | `/api/assessments?service_type=X` | user | Filter by service type |
| GET | `/api/assessments?org_id=X` | user | Filter by organisation |
| GET | `/api/assessments?region=X` | user | Filter by region |
| GET | `/api/domain/<domain>` | user | Domain detail + history |

### Scanning (admin only)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Trigger a scan |
| POST | `/api/reassess` | Re-score existing scan data against updated guidelines |
| POST | `/api/discover` | AI-powered domain discovery |
| POST | `/api/dns-enumerate` | DNS deep-dive enumeration |
| GET | `/api/runs` | List scan runs |

### Domain lists

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/domain-lists` | user | Lists visible to current user |
| POST | `/api/domain-lists` | admin | Create list |
| PUT | `/api/domain-lists/<id>` | admin | Update list |
| DELETE | `/api/domain-lists/<id>` | admin | Delete list |
| POST | `/api/save-domains` | admin | Save discovered domains to list |

### Roadmap

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/roadmap` | user | Domain roadmaps (na domains excluded) |
| GET | `/api/roadmap/domain/<d>` | user | Single domain roadmap |
| POST | `/api/roadmap/generate` | admin | Generate + optionally save roadmaps |
| GET | `/api/roadmap/stats` | user | Roadmap summary statistics |

### CT Monitor

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/ct/stats` | user | CT summary statistics |
| GET | `/api/ct/summaries` | user | Per-domain CT summaries |
| GET | `/api/ct/certificates` | user | PQC certificates detected |
| GET | `/api/ct/timeline` | user | Certificate timeline data |
| POST | `/api/ct/monitor` | admin | Trigger CT scan |

### Organisations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/organisations` | user | Orgs visible to current user |
| POST | `/api/organisations` | admin | Create org |
| PUT | `/api/organisations/<id>` | admin | Update org |
| DELETE | `/api/organisations/<id>` | admin | Delete org |

### Export

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/export?format=csv\|json\|text` | user | Export assessments |

---

## 7. Authentication & RBAC

### Roles

| Role | Key permissions |
|------|----------------|
| `admin` | Everything: scan, discover, manage users/lists/orgs, CT, roadmap generation, settings |
| `analyst` | View assessments/roadmaps/CT data for assigned domains only. Cannot scan, discover, or manage anything. |

### Analyst domain scoping

Analyst access is the **union** of:
1. Domain lists explicitly assigned to the user (`user_domain_lists`)
2. Domains in organisations the user is assigned to (`user_organisations` → `domain_organisations`)

Deduplication happens in `AuthStore.get_user_domains()`.

### Dashboard tab visibility by role

| Tab | Admin | Analyst |
|-----|-------|---------|
| Dashboard | ✓ | ✓ |
| Domain Discovery | ✓ | hidden |
| Scan | ✓ | hidden |
| Trends | ✓ | ✓ |
| CT Monitor | ✓ | ✓ (view only; Run button hidden) |
| Roadmap | ✓ | ✓ (view only; Generate button hidden) |
| Settings | ✓ | ✓ (read-only reference info) |

### Adding a new API endpoint

Always use this pattern:
```python
from auth.middleware import require_auth, current_user, filter_assessments

@app_bp.route("/api/new-endpoint")
@require_auth
def api_new_endpoint():
    user = current_user()
    data = db.get_something()
    return jsonify(filter_assessments(data, user))
```

For single-domain endpoints:
```python
if not user.is_admin:
    allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
    if domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
```

---

## 8. Known Issues & Technical Debt

### 8.1 Antivirus false positives (not yet fixed)

The ZIP distribution is flagged by some AV engines. Root causes in priority order:

1. **`scanner/cipher_enum.py`** — Contains `ssl.CERT_NONE` + `check_hostname = False` + explicit cipher strings (`RC4-SHA`, `NULL-SHA`, `EXP-RC4-MD5`, etc.) matching SSL stripping / MITM tool signatures. *Fix: move cipher strings to a JSON data file; rename `_probe_cipher`.*

2. **`app_factory.py`** — `importlib.reload()` is a known malware evasion technique. *Fix: `make_blueprint()` factory functions.*

3. **`install.sh`** — `useradd`, `chown -R`, writes to `/etc/systemd/` matches dropper heuristics. *Fix: limited options; could split archive.*

4. **`ct/ct_monitor.py` and `scanner/chain_validator.py`** — `__import__()` dynamic imports. *Fix: top-level try/except imports.*

### 8.2 `dashboard/app.py` is a ~2300-line monolith

The entire SPA (HTML + CSS + JS) lives as a Python string in one file. IDE support is poor for the embedded JS/CSS. Future new views should consider splitting into `static/` + Jinja2 templates.

### 8.3 Cipher enumeration is slow

`cipher_enum.py` opens one TCP connection per cipher group. Full enumeration can take 3–4 minutes per domain. Consider caching results in `domain_extra`.

### 8.4 No rate limiting on scan endpoints

Only `/login` has rate limiting. Add per-user scan concurrency limit for internet-facing deployments.

### 8.5 `domain_lists.domains_json` not indexed

Domain membership lookup iterates all lists. Fine for <1000 domains; will slow at scale. Consider a `domain_list_members` join table.

---

## 9. Critical Implementation Notes

### 9.1 The two Flask apps in dashboard/app.py

`dashboard/app.py` contains **two** `create_app()` implementations:
- The legacy one (used by `pqc_monitor.py dashboard` command for dev)
- `app_factory.create_app()` is the production entry point

**Always work in `app_factory.py` + `app_routes.py` + `admin/routes.py`.** Do not add routes to the legacy `create_app()` — those routes are not RBAC-protected.

### 9.2 HTML structure of dashboard views

All seven views are siblings inside `<div class="main">` in `DASHBOARD_HTML`. They are all present in the DOM; visibility is toggled via the `.active` CSS class.

**Critical:** A missing `</div>` closing tag causes all subsequent views to inherit the unclosed view's `display:none` state. Always verify with the depth-checking script after HTML edits:

```python
python3 -c "
from app_factory import create_app
import auth.auth_routes as _ar; _ar._login_attempts.clear()
app = create_app({'db_path':'/tmp/check.db','https_enabled':False})
c = app.test_client()
c.post('/login', data={'username':'admin','password':'changeme123'}, follow_redirects=True)
body = c.get('/app/').data.decode()
main_open = body.find('<div class=\"main\">')
depth = 0
view_depths = {}
i = main_open
while i < len(body):
    if body[i:i+4] == '<div': depth += 1
    elif body[i:i+6] == '</div>': depth -= 1
    chunk = body[i:i+60]
    for v in ['view-dashboard','view-domains','view-scan','view-trends',
              'view-ct','view-roadmap','view-settings']:
        if 'id=\"'+v+'\"' in chunk: view_depths[v] = depth
    i += 1
for v,d in view_depths.items(): print(f'  {\"OK\" if d==2 else \"WRONG depth=\"+str(d)}  {v}')
"
```

### 9.3 fetch() rewrite

The dashboard JS uses `/api/...` paths. Under the auth shell at `/app/`, these are rewritten to `/app/api/...` by an IIFE injected in `dashboard_home()` in `app_routes.py`. Any new JS fetch calls must use `/api/...` paths.

### 9.4 Config: https_enabled and ProxyFix

```yaml
dashboard:
  https_enabled: true   # set true when behind nginx with TLS
```

`ProxyFix` middleware (v1.3.1) makes Flask trust `X-Forwarded-Proto: https` from nginx. **nginx must pass:** `proxy_set_header X-Forwarded-Proto $scheme;`

### 9.5 Domain-list scoping in new endpoints

Every new endpoint returning domain data **must** call `filter_assessments(data, user)`. See §7 for the pattern.

### 9.6 DNSDumpster integration

Set `dns_enumeration.dnsdumpster_api_key` in `config.yaml` or export `PQC_DNSDUMPSTER_KEY`. Without a key, falls back to HTML scraping (fragile, dev only).

### 9.7 Organisation scoping interaction with domain lists

Analyst access = union of domain-list assignments + org-derived domains. Deduplicated in `AuthStore.get_user_domains()`. The `?org_id=` filter is an additional filter on top of RBAC — analysts cannot use it to see domains outside their allowed set.

### 9.8 systemd unit constraints

- **Do not use `${VAR:-default}` in `ExecStart`/`ExecStartPre`** — bash fallback syntax is not supported. Declare defaults as `Environment=` lines before `EnvironmentFile=`.
- **Do not put `StartLimitIntervalSec`/`StartLimitBurst` in `[Service]`** — they belong in `[Unit]`.
- **Do not use inline bash with shell variables in `ExecStartPre`** — systemd expands `${}` before bash gets it. Put non-trivial shell logic in a separate script.
- **`Type=simple` is correct for gunicorn** — `Type=notify` requires gunicorn to emit `sd_notify(READY=1)`.
- **When adding `Environment=` lines with absolute paths, verify they match `config.yaml`** — the scheduler service bug (v1.4.0) was caused by `PQC_DB_PATH` pointing to the wrong location.

### 9.9 Deploy script service trigger sets

`scripts/deploy.sh` restarts services only when files in their trigger sets are synced. If adding a new Python module, ensure it is listed in the appropriate trigger set in the `WEB_TRIGGERS` or `SCHEDULER_TRIGGERS` arrays in `scripts/deploy.sh`.

### 9.10 `level="na"` — no-TLS domains

Domains where no TLS service is found are stored with `level="na"`, `score=0`. They must be excluded from:
- Score averages and level counts in `get_summary_stats()` and the analyst summary block in `api_summary()`
- Roadmap generation (`generate_sector_roadmap()` filters them; `generate_domain_roadmap()` returns early)
- Distribution chart (already excluded since `na` is not in the four level buckets)

The "No TLS" stat card on the dashboard is clickable and filters the domain table to show only na-level domains.

---

## 10. Planned Features — Prioritised Backlog

Features ordered from smallest to largest change surface.

---

### Tier 1 — Config / data changes only (no new modules)

**[T1-1] Fix AV false positives**
Move cipher name strings in `cipher_enum.py` to a JSON data file. Replace `__import__()` calls. Replace `importlib.reload()` with `make_blueprint()` factories. *Low risk, self-contained.*

**[T1-2] Geography / region on domain lists**
Add `region` and `country_code` columns to `domain_lists` (migration v15). Surface in domain list editor modal.

**[T1-3] Expiry and certificate age warnings in dashboard**
`cert_expiry_days` already stored in assessments. Add a JS filter for "expiring within 30/60/90 days" — zero new backend code.

**[T1-4] Export roadmap as PDF/DOCX**
`roadmap/generator.py` already has `render_roadmap_text()`. Add `render_roadmap_docx()`. Expose via `GET /api/roadmap/export?format=docx`.

**[T1-5] Asset Criticality Weighting**
Add `criticality TEXT DEFAULT 'normal'` to assessments. Admin UI dropdown. Roadmap phase assignment weighted by criticality.

---

### Tier 2 — New columns + existing module extension

**[T2-1] Resource type tagging** *(schema delivered in v1.2.0)*
`service_type` column exists. Dashboard filtering by service type is the remaining UI work.

**[T2-2] Per-domain resource aggregation view**
`GET /api/domain/<domain>/resources` → assessments grouped by `service_type`. Requires T2-1 complete.

**[T2-3] Geographic coordinates on assessments**
Add `country_code`, `latitude`, `longitude` to assessments. Populate from ip-api.com. Prerequisite for T3-2.

**[T2-4] Executive PDF Reporting**
New `reports/pdf_report.py` using `weasyprint`. `GET /api/export?format=pdf`.

**[T2-5] Budget and Resource Estimation**
Extend roadmap with `cost_min_eur`, `cost_max_eur`, `fte_months`. New `roadmap/budget_estimator.py`.

---

### Tier 3 — New modules, moderate complexity

**[T3-1] DNS deep-dive on domain add** *(delivered in v1.2.0)*
Integration with domain-add flow is remaining work.

**[T3-2] Geographic map view**
Choropleth + dot map. Requires T2-3. Leaflet.js (CDN).

**[T3-3] SSL Labs integration**
Optional enrichment via Qualys SSL Labs API v4. Results in `domain_extra`. Async polling required.

**[T3-4] Sector Benchmarking**
`AVG(score)` by `(sector, region)` across all runs. `GET /api/benchmarks`. New `view-benchmarks` dashboard view.

---

### Tier 4 — Significant architectural changes

**[T4-1] Multi-resource domain model**
Domain as container of resources with per-resource scores and weighted aggregate. Requires T2-1 + T3-1.

**[T4-2] Trend alerting and notifications**
Email/webhook on score drop or new critical finding. New `alerting/` module.

**[T4-3] SAML / OIDC authentication**
`AuthProvider` interface designed for this. Implement `SAMLAuthProvider` or `OIDCProvider`.

**[T4-4] Dashboard frontend separation**
Extract `DASHBOARD_HTML` from `dashboard/app.py` into `static/` files.

---

## Appendix A — Running the Test Suite

```bash
# Development
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_*.py'

# Specific module
python3 -m unittest tests.test_auth -v

# Seed demo data for manual testing
python3 tests/seed_demo_data.py --runs 3
python3 pqc_monitor.py dashboard  # → http://localhost:5000  admin/changeme123
```

**Test count:** 452 (as of v1.3.0; v1.4.0 adds no new tests — bug fixes only)

| File | Coverage |
|------|---------|
| `test_assessor.py` | Scoring engine, guideline loading, finding generation |
| `test_auth.py` | Full RBAC: permissions, AuthStore CRUD, authentication, endpoint protection, domain list CRUD |
| `test_ct.py` | CT monitor: OID registry, certificate parsing, DB storage, Flask API endpoints |
| `test_roadmap.py` | Phase assignment, effort calculation, score projection, text rendering, DB storage, API endpoints |
| `test_scan_quality.py` | Chain validator, cipher enum, CDN detector, domain_extra DB |
| `test_scanner.py` | TLS probe, crypto extractor, STARTTLS probe |
| `test_t2_t3_features.py` | T2-1 service_type tagging + T3-1 DNS enumerator (42 tests) |
| `test_orgs_and_dns.py` | Organisation CRUD, user↔org RBAC, admin API, assessment filters, DNSDumpster API key (44 tests) |

---

## Appendix B — Deployment Quick Reference

```bash
# Fresh production install
sudo ./install.sh --production

# Service management
sudo systemctl enable --now pqc-monitor.target
sudo systemctl status pqc-monitor-web
journalctl -u pqc-monitor-web -f
journalctl -u pqc-monitor-scheduler -f

# Config files (do not edit install directory directly)
/etc/pqc-monitor/config.yaml       # app config (perms: 640 root:pqcmonitor)
/etc/pqc-monitor/pqc-monitor.env   # secrets (perms: 640 root:pqcmonitor)

# Runtime data
/var/lib/pqc-monitor/pqc_monitor.db   # SQLite database

# Incremental deploy (from git checkout)
chmod +x scripts/deploy.sh
scripts/deploy.sh --dry-run       # preview
sudo scripts/deploy.sh            # apply

# nginx
sudo cp /opt/pqc-monitor/systemd/nginx-pqc-monitor.conf \
        /etc/nginx/sites-available/pqc-monitor
# Ensure nginx config includes:
#   proxy_set_header X-Forwarded-Proto $scheme;
#   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
sudo certbot --nginx -d your.domain.example
sudo systemctl reload nginx

# One-time DB fix for existing installs (no-TLS → na)
python3 scripts/fix_notls_level.py --dry-run
python3 scripts/fix_notls_level.py
```

---

## Appendix C — Adding a New Feature: Checklist

1. **New DB columns** → add migration to `data/migrations.py`, bump version number
2. **New DB methods** → add to `data/database.py` `Database` class
3. **New scan step** → add module in `scanner/`, wire into `orchestrator._scan_domain`
4. **New API endpoint** → add to `app_routes.py` (analyst) or `admin/routes.py` (admin)
   - Always add `@require_auth` (or `@require_admin`)
   - Always call `filter_assessments()` for domain data
5. **New dashboard view** → add HTML view div inside `<div class="main">` in `dashboard/app.py`
   - Add nav button with `onclick="showView('newview',this)"`; wrap in `{% if user.is_admin %}` if admin-only
   - Add data-loading call in `showView()` function
   - Verify all view divs are at depth=2 using the verification script in §9.2
6. **New tests** → add to appropriate `tests/test_*.py`
7. **Version bump** → edit `VERSION` file, add row to §2 version table, add §2.x detail section
8. **RBAC** → add new permission strings to `PERMISSIONS` dict in `auth/models.py` if needed
9. **Deploy script** → if new Python module, add its path to `WEB_TRIGGERS` / `SCHEDULER_TRIGGERS` in `scripts/deploy.sh`

---

## Appendix D — Operational Scripts

Scripts live in `scripts/` and are run from the project root:

```bash
cd /opt/pqc-monitor
python3 scripts/<script>.py --help
```

### deploy.sh — Incremental deployment (NEW v1.4.0)

Syncs files changed in last git commit to `/opt/pqc-monitor`. Restarts only affected services.

```bash
scripts/deploy.sh --dry-run
sudo scripts/deploy.sh
sudo scripts/deploy.sh --from abc1234
sudo scripts/deploy.sh --no-restart
```

### fix_notls_level.py — One-time DB migration (NEW v1.4.0)

Fixes assessments stored as `level="critical"` that should be `level="na"` (no TLS service). Safe to run multiple times. Supports `--dry-run`.

```bash
python3 scripts/fix_notls_level.py --dry-run
python3 scripts/fix_notls_level.py
```

### wait-for-db.sh — Database readiness check (NEW v1.3.1)

Invoked by `pqc-monitor-scheduler.service` as `ExecStartPre`. Polls for DB file every 2 seconds, logs progress every 10 seconds, exits 1 after timeout.

```bash
scripts/wait-for-db.sh [db_path] [timeout_seconds]
```

### bulk_org_assign.py — Bulk domain → organisation assignment

Assigns domains matching a TLD pattern to a named organisation. Additive — never removes existing assignments.

```bash
python3 scripts/bulk_org_assign.py \
    --tld bde.es \
    --org "Banco de España" \
    --sector "Financial Services" \
    --region "EU/Spain" \
    --dry-run
```

### diagnose.py — API integration diagnostic

Tests Shodan and DNSDumpster connectivity from the production environment.

```bash
python3 scripts/diagnose.py --config config/config.yaml --domain bde.es
```
