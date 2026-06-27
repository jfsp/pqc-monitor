# Changelog

All notable changes to PQC-Monitor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

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
- **Community concept** — group organisations into named communities for
  scoped reporting and user access control
  - Schema migration v17: `communities`, `community_organisations`,
    `user_communities` tables with cascade deletes and indexes
  - Full CRUD in DB layer (`create_community`, `update_community`,
    `delete_community`, `set_community_orgs`, `get_community_orgs`,
    `get_community_domains`, `set_user_communities`, `get_user_communities`)
  - Aggregate report engine: `get_community_aggregate()`,
    `get_region_aggregate()`, `_build_group_aggregate()` — per-org score,
    level counts, PQC count from latest assessments
- **`ROLE_COMMUNITY_MANAGER`** — new role between analyst and admin
  - Auto-promoted from analyst when first community is assigned
  - Permissions: view own communities, generate group reports, export
  - Admins are never demoted by community assignment
- **Group Report tab** in dashboard (admin + community_manager only)
  - Positioned after Dashboard, before Domain Discovery
  - Toggle between Community view and Region view via top selector
  - Country filter dropdown (shown only when group spans >1 country)
  - Live aggregate table: org, CC, sector, domains, score, level, critical/
    weak/moderate/ready/no-TLS/PQC columns with totals row
  - Executive summary panel (auto-generated from aggregate stats)
  - CSV export and PDF export buttons
- **`reports/community_report.py`** — new module
  - `build_report()`: structured dict with summary, totals, per-org rows
  - `export_csv()`, `export_text()`: tabular output
  - `export_pdf()`: weasyprint A4 landscape PDF with branding header,
    executive summary, colour-coded level badges, totals row, footer
- **Admin UI — Communities section**
  - New nav item and view: create/edit/delete communities, assign orgs
  - User modal: community_manager role option; community checkbox group
    (shown for community_manager role); auto-promote note
- **API endpoints** (8 new routes under `/app/api/`)
  - `GET /api/communities` — list visible communities (scoped for non-admin)
  - `GET /api/communities/<id>/report` — JSON aggregate report
  - `GET /api/communities/<id>/report.csv` — CSV download
  - `GET /api/communities/<id>/report.pdf` — PDF download
  - `GET /api/regions` — list distinct regions visible to user
  - `GET /api/regions/<name>/report` — JSON aggregate by region
  - `GET /api/regions/<name>/report.csv` — CSV download
  - `GET /api/regions/<name>/report.pdf` — PDF download
- **CLI command group** `community`
  - `create <name>` — create a community
  - `list` — list all communities with org count
  - `add-org <community_id> <org_id>` — add org to community
  - `remove-org <community_id> <org_id>` — remove org from community
  - `assign-user <community_id> <username>` — assign user (auto-promotes)
  - `report <community_id> [--format text|json|csv] [-o file]`
  - `region-report <region> [--format text|json|csv] [-o file]`
- **`requirements.txt`**: added `weasyprint>=62.0` for PDF generation
- **`tests/test_communities.py`**: 31 new tests across 4 classes
  (DB CRUD, auth store + auto-promote, report generation, aggregates)

---
## [1.5.2] — 2026-06-27

### Fixed
- **`data/database.py`**: `update_organisation()` `allowed` whitelist was missing
  `country_code` and `country` — both fields were silently dropped on every PATCH,
  so country edits never persisted to the DB
- **`admin/routes.py`**: `syncCountryName()` was referenced in `onchange` on the
  country-code `<select>` but never defined — selecting a country threw a
  `ReferenceError` in the browser, preventing the value from being committed before
  `submitOrgModal()` read it
- **`data/database.py`**: migration failures were caught and logged at `DEBUG` level
  (`"Migrations skipped"`) then silently swallowed — schema upgrades could fail
  invisibly in production; now logged at `ERROR` and re-raised so startup fails
  loudly with a clear message

---
## [1.5.1] — 2026-06-27

### Added
- **TLD-based geo inference** (`data/geo_inference.py` + `data/tld_geo.csv`)
  - Reads user-editable CSV (200+ ccTLD entries); no network calls; pure stdlib
  - Single ccTLD list → infers country_code, country, region automatically
  - Multiple ccTLDs → no inference; CLI echoes which TLDs were found
  - All generic TLDs (.com/.net/.org/…) → no inference
  - Explicit `--country-code` always overrides inference
- **Country + region on scan runs** — schema migration v16
  - `data/database.py`: `create_run()` stores `country_code` + `country`
  - `scanner/orchestrator.py`: `scan_domains()` and `reassess_run()` propagate both fields
  - `scheduler/scan_scheduler.py`: `add_schedule()` stores in `config_json`, passes on run
- **CLI**: `scan` and `schedule` commands gain `--country-code` and `--country` options
- **CLI**: `list-runs` output now shows Country and Region columns
- **Tests**: `TestGeoInference` class — 12 tests in `test_orgs_and_dns.py`

---
## [1.5.0] — 2026-06-27

### Added
- **Country on organisations** (`country_code` ISO 3166-1 alpha-2 + `country` display name)
  - Schema migration v15: two new columns on `organisations`, default empty string
  - Admin UI: ISO country dropdown with auto-fill in create/edit org modal; Country column in org table
  - Dashboard: Country filter dropdown (alongside existing Org and Region filters), client-side via `_orgsCache`
  - API: `GET /api/assessments?country_code=XX` server-side filter (mirrors `?region=`)
  - 7 new tests in `test_orgs_and_dns.py` (DB layer + admin API)

---
## [Unreleased]

*Add entries here as work progresses on the next release.*

---

## [1.3.0] — 2026-06-12

### Added

**DNSDumpster API key support**

- `scanner/dns_enumerator.py`: split `_dnsdumpster_subdomains()` into two paths:
  `_dnsdumpster_api()` (official REST endpoint, requires paid key) and
  `_dnsdumpster_scrape()` (unofficial CSRF/HTML fallback, development only).
  The top-level wrapper routes based on whether a key is present.
- `use_dnsdumpster` now defaults to `False` in `enumerate_domain()`. It is
  automatically enabled when `dnsdumpster_api_key` is configured; otherwise
  callers must opt in explicitly.
- `config/config.yaml.example`: new `dns_enumeration` block with
  `dnsdumpster_api_key`, `use_wordlist`, `use_ct` keys.
- `pqc_monitor.py` `load_config()`: reads `dns_enumeration.*` keys;
  `PQC_DNSDUMPSTER_KEY` environment variable overrides config file.
- `app_factory.py`: populates `DNS_ENUM_CONFIG` dict in `app.config`.
- `app_routes.py` `POST /api/dns-enumerate`: reads server config defaults;
  `use_dnsdumpster` is derived from key presence rather than defaulting True.

**Organisation grouping (T-ORG)**

- Migration v14: three new tables — `organisations` (name, sector, region,
  description), `domain_organisations` (domain↔org many-to-one), and
  `user_organisations` (user↔org many-to-many). Cascading deletes on all FK
  relationships.
- `data/database.py`: full organisation CRUD (`create_organisation`,
  `get_organisations`, `get_organisation`, `update_organisation`,
  `delete_organisation`); domain assignment (`set_org_domains`,
  `get_org_domains`, `get_domain_org`, `get_assessments_by_org`);
  user assignment helpers (`set_user_orgs`, `get_user_org_ids`,
  `get_org_domains_for_user`).
  `get_latest_assessments()` now includes `org_id`, `org_name`, `org_region`
  columns via LEFT JOIN; `get_organisations()` includes the `domains` list.
- `auth/models.py`: `org.manage` and `org.view_all` added to admin permissions;
  `org.view_own` added to analyst permissions. `User` dataclass gains
  `org_ids: list` field; `to_dict()` includes `org_ids`.
- `auth/store.py`: `_row_to_user()` loads `org_ids`; `set_user_orgs()` method
  for atomic org assignment; `get_user_domains()` now unions domain-list access
  and org-derived access, deduplicating results.
- `admin/routes.py`: 7 new admin API endpoints (`GET/POST /api/organisations`,
  `GET/PATCH/DELETE /api/organisations/<id>`,
  `PUT /api/organisations/<id>/domains`,
  `GET/PUT /api/users/<uid>/orgs`).
  Admin panel: new "🏢 Organisations" sidebar tab with create/edit/delete/domain-
  assignment modals; user edit modal gains an Organisations checkbox group.
- `app_routes.py`: `GET /api/assessments` gains `?org_id=` and `?region=`
  query filters; new `GET /api/organisations` endpoint (admin sees all, analysts
  see only their assigned orgs).
- `dashboard/app.py`: Org and Region `<select>` dropdowns added to the Domain
  Assessments toolbar; `loadAssessments()` fetches `/api/organisations` in
  parallel and populates both dropdowns; `applyDropdownFilters()` and
  `populateOrgDropdown()` / `populateRegionDropdown()` wired up; `esc()`
  helper added.

### Migration notes

Schema now at v14. Existing databases auto-upgrade on first connection.
All new tables are nullable/optional — no existing data is affected.
Analyst access model: users inherit domain visibility from *both* their
domain list assignments (existing) and their org assignments (new). The
union is deduplicated.

---

## [1.2.0] — 2026-06-11

### Added

**T2-1 — Resource type tagging on assessments**

- `service_type` column on `assessments` table (migration v13). Values:
  `web_primary`, `web_secondary`, `smtp`, `imap`, `pop3`, `ldap`, `sip`, `mqtt`, `other`.
- `orchestrator.py`: `SERVICE_TYPE_MAP` and `_port_to_service_type(port)` derive
  a label from the primary port; passed into `assess_domain()` and stored per row.
- `crypto_assessor.py`: `DomainAssessment` gains `service_type: Optional[str]`;
  `assess_domain()` accepts the keyword argument.
- `database.py`: `save_assessment()` persists `service_type`; new
  `get_assessments_by_service_type(run_id, service_type)` for filtered queries.
- `GET /api/assessments`: accepts optional `?service_type=` query parameter.
- Migration v12 reserved as placeholder for T1-2; migration v13 is the real ALTER TABLE.

**T3-1 — DNS deep-dive on domain add**

- New `scanner/dns_enumerator.py` with `enumerate_domain()` entry point.
  Four enumeration passes: (1) direct DNS (A/AAAA/MX/NS/CNAME/TXT),
  (2) CT SAN harvest via crt.sh, (3) wordlist brute-force (120 built-in prefixes,
  concurrent resolution), (4) DNSDumpster CSRF scrape. Each source is
  independently guarded; errors collected non-fatally.
  Returns `DnsEnumerationResult` with `tls_candidates` list ready for the scan pipeline.
- `POST /api/dns-enumerate`: on-demand endpoint. Accepts `use_wordlist`,
  `use_ct`, `use_dnsdumpster` flags. Stores in `domain_extra` (type `dns_enum`)
  when `run_id` given. Requires `scan.run` permission.
- `POST /api/save-domains`: gains optional `dns_enumerate: true` + `run_id`;
  runs enumeration on save and returns per-domain summary.

### Migration notes

Schema now at v13. Existing databases auto-upgrade on first connection.
`service_type` is nullable — all pre-existing rows are unaffected.

---

## [1.1.3] — 2026-06-11

### Fixed

**CT Monitor, Roadmap, and Settings views still empty after v1.1.2**

The `view-trends` `<div>` was never closed in `dashboard/app.py`. The CT Monitor,
Roadmap, and Settings view `<div>` elements were therefore children of `view-trends`
in the DOM, not siblings. When `view-trends` was deactivated (`.view` CSS sets
`display:none`) all three hidden views became invisible along with it, regardless
of whether they had the `.active` class applied.

Fix: added the missing `</div>  <!-- /view-trends -->` at line 827, restoring all
seven views to the correct sibling relationship within `<div class="main">`. All
views are now at DOM depth 2 (main=1, view=1) as intended.

This was a pre-existing HTML structure bug introduced when the CT Monitor and
Roadmap views were added in earlier sessions. The v1.1.2 JavaScript fixes
(`showView`, Chart.js guards, `renderSettingsVersion`) were correct but could not
overcome the CSS hiding caused by the nesting bug.

## [1.1.2] — 2026-06-11

### Fixed

**CT Monitor, Roadmap, and Settings tabs showed empty content**

Root cause: `showView(name)` used the implicit global `event.target` to highlight
the active nav button. When `event.target` was not the nav button (or when `showView`
was called programmatically via `showView2`), the function threw a silent TypeError
that aborted execution before Chart.js render calls in CT and Roadmap could run.
Settings appeared empty because it received no data calls — but the TypeError on
`event.target` still caused execution to abort in some browser contexts.

Fixes applied:
- `showView(name, btn)` — accepts an explicit `btn` parameter (the clicked element,
  passed as `this` from each nav button's `onclick`). Falls back to `event.target`
  only if available.
- All nav buttons updated: `onclick="showView('ct',this)"` etc.
- `showView2` (used by scan-run "View" buttons) now delegates to `showView` with
  the matching nav button found by name, ensuring data-loading functions always run.
- `if (name === 'settings') { renderSettingsVersion(); }` added to `showView` so
  the Settings tab is explicitly activated.
- All Chart.js instantiations guarded with `typeof Chart === 'undefined'` checks to
  prevent crashes when Chart.js CDN load is slow.

### Added

**Dashboard — filter by stat card**
- Clicking a stat card (Critical, Weak, Moderate, PQC-Ready, PQC Detected) filters
  the Domain Assessments table to show only matching domains.
- Active filter shown as an accent badge next to the panel title.
- "✕ Clear filter" button appears when a filter is active.
- Clicking the same card again toggles the filter off.
- Cards gain a hover lift effect and an active outline when selected.

**Dashboard — sortable columns**
- All Domain Assessment table columns are now clickable sort headers: Domain,
  Score, Level, Key, PQC, Findings.
- First click sorts ascending; second click reverses to descending.
- Active sort column and direction shown with ▲/▼ indicators in the header.
- Sort is applied after filtering, so both work together.
- Findings column sorts by critical-severity count (×100) + high-severity count,
  putting the most urgent domains first.

**Implementation detail**
- `_allAssessments` module-level variable stores the full unfiltered dataset so
  filter/sort operations are purely client-side with no additional API calls.
- `setFilter(level)` and `sortBy(col)` functions call `applyFilterAndSort()` which
  filters first, then sorts, then calls `renderAssessments()`.



### Fixed

**Login loop on plain-HTTP deployments** (`auth/auth_routes.py`, `app_factory.py`, `pqc_monitor.py`)
- `SESSION_COOKIE_SECURE` defaulted to `True`, causing browsers to silently discard
  session cookies over plain HTTP. Login succeeded server-side but every subsequent
  request appeared unauthenticated, creating an infinite `/login` redirect loop.
- Fix: `https_enabled` now defaults to `False`. Set `https_enabled: true` in
  `config.yaml` only when a TLS-terminating reverse proxy (nginx/Caddy) is in front.
- Added `https_enabled` key to `config/config.yaml.example` with clear instructions.
- Added `https_enabled` to `load_config()` in `pqc_monitor.py`.

**Absolute `?next=` URL rejected after login** (`auth/auth_routes.py`)
- Flask middleware builds `?next=http://host/app/` (absolute URL) when redirecting
  unauthenticated requests. The open-redirect safety check blocked absolute URLs and
  fell back incorrectly, worsening the login loop.
- Fix: parse absolute `?next=` values, strip scheme+host, use path component only.
  Open-redirect protection is preserved.

**Dashboard rendered unstyled with literal `v{{ version }}`** (`app_factory.py`, `app_routes.py`, `dashboard/app.py`)
- A stray `return app` on line 112 of `app_factory.py` placed all blueprint
  registration code after an unreachable return. The app started with only 2 routes
  (`/api/version` and `/static/...`); every other URL fell through to error pages.
- The `_APP_SHELL` + `_extract_body()` approach stripped the `<head>` block
  (containing all CSS) and never ran `DASHBOARD_HTML` through Jinja2's template
  engine, leaving `{{ version }}` as a literal string.
- Fix: removed the stray `return`; corrected blueprint registration order.
  `dashboard_home` now renders `DASHBOARD_HTML` directly as a Jinja2 template
  (passing `version`, `user`, `is_admin`). Auth user bar integrated into the
  dashboard's existing `<header>` element. `_APP_SHELL` and `_extract_body`
  removed entirely.

**Blueprint re-registration across test instances** (`app_factory.py`)
- Module-level blueprint imports caused `AssertionError` on the second `create_app()`
  call in tests (Flask refuses to register a blueprint on a second app).
- Fix: blueprint modules are reloaded inside `create_app()` so each test gets
  fresh blueprint instances.

### Added

**Domain List CRUD** (`admin/routes.py`, `data/database.py`, `data/migrations.py`)
- Full create / edit / delete capability for domain lists in the Admin panel.
- **New admin API routes:**
  - `GET  /admin/api/domain-lists` — index with `domain_count`, `user_count`, `updated_at`
  - `GET  /admin/api/domain-lists/<id>` — full record including `domains` array
  - `POST /admin/api/domain-lists` — create with name, query, domains
  - `PATCH /admin/api/domain-lists/<id>` — update name / query / domains independently
  - `DELETE /admin/api/domain-lists/<id>` — delete list and cascade user assignments
  - `GET  /admin/api/domains/known` — all distinct domains with assessment data,
    sorted alphabetically; used to populate the domain picker
- **Domain List Editor modal** — two-pane interface:
  - *Left pane*: filterable checklist of all domains that have ever been scanned.
    Checking/unchecking immediately updates the right pane. "Select all visible"
    and "Clear" buttons for bulk operations.
  - *Right pane*: current list members with per-item remove buttons, free-text
    entry (comma/newline-separated bulk paste supported, strips blanks), A→Z sort,
    and Clear all.
  - Changes are not saved until the user clicks "Create List" / "Save Changes".
- **New DB methods:** `get_domain_list_full()`, `update_domain_list()`,
  `delete_domain_list()`, `get_all_known_domains()`.
- **Migration v11:** adds `updated_at` column to `domain_lists`.

**Tests** — 24 new tests in `TestDomainListCRUD`:
  index (empty, domain count, user count), create (success, missing name, empty
  domains, strip blanks), get single (full, 404), update (name, domains replace,
  query only, sets `updated_at`, 404), delete (success, cascades assignments, 404),
  known domains (empty, from assessments, no duplicates, sorted), direct DB method
  coverage.

### Regression tests added
- `test_absolute_next_url_is_stripped_to_path` — login with absolute `?next=` must
  redirect to the path, not loop back to `/login`
- `test_session_survives_after_login_on_http` — session cookie readable over HTTP



### Added

**Versioning**
- `VERSION` file at project root — single source of truth for the version string.
  All UI components, the CLI, and the `/api/version` endpoint read from this file.
  Releasing a new version requires editing only `VERSION` and adding a CHANGELOG entry.
- `version.py` — Python module that reads `VERSION` at import time and exports
  `VERSION` and `__version__` constants.
- `GET /api/version` endpoint returns `{"version": "…", "name": "PQC-Monitor"}`.
- Version string displayed in: browser header bar, footer, login page footer,
  admin panel header, Settings → About panel, and `pqc_monitor.py --version`.

**Role-Based Access Control (RBAC)**
- `auth/models.py` — `User`, `AuditEvent` dataclasses; `ROLE_ADMIN`/`ROLE_ANALYST`
  constants; `PERMISSIONS` dict; `has_permission()` helper.
- `auth/store.py` — SQLite-backed `AuthStore`: user CRUD, Werkzeug PBKDF2/scrypt
  password hashing, authentication with configurable account lockout (10 failures →
  15-minute block), domain-list assignment via `user_domain_lists` join table,
  `get_user_domains()` for scope resolution, and audit log writer.
- `auth/middleware.py` — `AuthProvider` interface (swap `LocalAuthProvider` for SAML/OIDC
  without touching route code); `login_user`/`logout_user`/`current_user` session helpers;
  `require_auth`, `require_role`, `require_admin` decorators; `filter_assessments()` and
  `scope_domains()` for per-analyst domain scoping.
- `auth/auth_routes.py` — `/login`, `/logout`, `/change-password` blueprint with
  in-memory per-IP rate limiting (10 attempts/minute).
- `admin/routes.py` — Full admin SPA at `/admin/*`: user management table,
  create/edit/delete/password-reset modals, domain-list assignment checkboxes,
  audit log table. Access restricted to `ROLE_ADMIN`.
- `app_routes.py` — Analyst app blueprint at `/app/*`. All existing API endpoints
  re-exposed with `@require_auth` + domain-scoping. Admins see all; analysts see
  only their assigned lists.
- `app_factory.py` — New Flask application factory replacing `dashboard/app.py`'s
  `create_app()`. Registers auth, admin, and app blueprints; configures secure session
  cookies (HttpOnly, SameSite=Lax, Secure=True); adds HSTS, CSP, X-Frame-Options:DENY,
  X-Content-Type-Options:nosniff on every response.
- Database migration v10: `users`, `user_domain_lists`, `audit_log` tables.

**Systemd deployment**
- `systemd/pqc-monitor.target` — service group target; `systemctl start pqc-monitor.target`
  starts both services together.
- `systemd/pqc-monitor-web.service` — Gunicorn WSGI service. Hardened with
  `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, `CapabilityBoundingSet=`.
  `Type=notify` for clean readiness signalling. Restart-on-failure with 5-attempt limit.
- `systemd/pqc-monitor-scheduler.service` — APScheduler daemon service. Separate process
  from web so long-running scans never delay HTTP responses. Restart-on-failure.
- `systemd/pqc-monitor.env` — Environment file template with `PQC_SECRET_KEY`,
  `PQC_BIND`, `PQC_WEB_WORKERS`, `SHODAN_API_KEY`, `ANTHROPIC_API_KEY`.
- `systemd/nginx-pqc-monitor.conf` — Sample nginx reverse proxy: TLS 1.2/1.3,
  modern cipher suites, HSTS, security headers, upstream proxy to Gunicorn.
- `scheduler-daemon` CLI command — blocking process entry point for the systemd
  service unit. Loads saved schedules, runs APScheduler, handles SIGTERM gracefully.
- `gunicorn>=22.0.0` added to `requirements.txt`.

**Install script** (`install.sh`)
- `--production` flag: creates `pqcmonitor` system user, installs to `/opt/pqc-monitor`,
  creates `/etc/pqc-monitor/{config.yaml,pqc-monitor.env}` with correct permissions,
  installs systemd units, auto-generates `PQC_SECRET_KEY`.
- `--demo` flag retained for seeding demo data.
- Development mode (no flags) unchanged: local `.venv` install.

**Tests** (`tests/test_auth.py`) — 69 tests
- Permission model: admin/analyst capabilities, `User.can()`, `is_admin` property.
- AuthStore: user CRUD, password hashing, duplicate rejection, lockout logic,
  last-login tracking, failed-login counter reset.
- Authentication: correct/wrong credentials, inactive users, lockout after 10 failures.
- Domain-list assignment: assign, revoke, atomic replace, `get_user_domains()`,
  deduplication, idempotent double-assign.
- Audit log: event storage, field population, anonymous events, user-id filter, limit.
- Flask endpoint protection: 401 for unauthenticated API calls, 403 for role violations,
  login/logout cycle, security headers on every response.
- Admin API: list/create/update/delete users, duplicate detection, self-delete prevention,
  password reset, domain-list assignment, domain-scoping verification.

### Changed

- `pqc_monitor.py` — `dashboard` command now uses `app_factory.create_app()` instead
  of `dashboard.app.create_app()`. Added `--version` option.
- `dashboard/app.py` — Version string in logo and footer changed from hardcoded
  `v1.0` to `{{ version }}` Jinja2 template variable.
- `config/config.yaml.example` — unchanged; production config lives at
  `/etc/pqc-monitor/config.yaml`.

### Security

- All session cookies set HttpOnly, SameSite=Lax; Secure=True in production.
- Content-Security-Policy header on every response.
- HSTS header on every HTTPS response (configurable).
- Account lockout and per-IP rate limiting on `/login`.
- Passwords hashed with Werkzeug PBKDF2/scrypt; never logged or serialised in API responses.
- `pqcmonitor` system user has no login shell, no home directory.
- Systemd units use `ProtectSystem=full`, `PrivateTmp`, `NoNewPrivileges`,
  `CapabilityBoundingSet=` for defence-in-depth.

- Passive CT log querying via crt.sh JSON API — no active scanning
- PQC OID classification registry covering ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
  Falcon, XMSS/LMS, ML-KEM (SPKI), and composite/hybrid signature schemes
- Full X.509 PEM inspection mode (`--fetch-pem`) for direct OID extraction from
  certificate DER structure when crt.sh metadata is insufficient
- Experimental OID prefix detection (1.3.9999.\*, 1.3.6.1.4.1.22554.\*) to catch
  pre-standard deployments before final OID assignments are published
- Domain deduplication by crt.sh cert_id; configurable max-certs-per-domain limit
- `CTCertificate` and `CTSummary` dataclasses with `to_dict()` for DB persistence

**Database** (`data/database.py`, `data/migrations.py`)
- `ct_queries` table: per-domain CT query results with PQC/hybrid counts and issuers
- `ct_certificates` table: individual certificate records with OID fields and PQC flags
- Migration v7: CT tables added to existing databases without data loss
- `save_ct_summary()`, `get_ct_summaries()`, `get_ct_pqc_certificates()`,
  `get_ct_timeline()`, `get_ct_stats()` methods

**Dashboard** (`dashboard/app.py`)
- New **CT Monitor** navigation tab
- Summary cards: domains monitored, total certs, PQC certs, hybrid certs, domains with PQC
- Run CT monitor panel with domain input and PEM-fetch toggle
- PQC certificate timeline chart (stacked bar: pure PQC vs hybrid, by month)
- PQC algorithm distribution doughnut chart
- Domain CT summary table with per-domain PQC/hybrid counts and issuer names
- PQC & hybrid certificates detail table with OID names, type badges, expiry
- OID reference table covering all monitored PQC algorithm assignments
- REST endpoints: `GET /api/ct/stats`, `GET /api/ct/summaries`,
  `GET /api/ct/certificates`, `GET /api/ct/timeline`, `POST /api/ct/monitor`

**CLI** (`pqc_monitor.py`)
- `ct-monitor` command: queries CT logs, persists results, prints summary table
- `--fetch-pem` flag for full OID inspection
- `--output` for JSON export of CT results

**Tests** (`tests/test_ct.py`) — 42 tests
- OID registry completeness and correctness
- `_classify_pqc()` for all algorithm families including composites and experimentals
- `CTCertificate` dataclass behaviour
- `monitor_domain()` with full HTTP mocking (no network required)
- Database CT storage, deduplication, filtering, stats, timeline
- All 5 Flask CT API endpoints

---

## [1.0.0] — 2026-04-17

### Added

**Core scanning engine**
- `scanner/tls_probe.py` — Non-intrusive TLS handshake and X.509 certificate
  extraction via Python `ssl` + `cryptography` library. Extracts TLS version,
  cipher suite, key type/size, signature algorithm, hash algorithm, SANs, and
  certificate expiry.
- `scanner/starttls_probe.py` — STARTTLS upgrade support for SMTP (25/587),
  IMAP (143), and POP3 (110) before handing off to the same TLS extraction
  pipeline.
- `scanner/service_discovery.py` — Non-intrusive TCP-connect port discovery
  with DANE/TLSA record lookup and DNSSEC check via `dnspython`.
- `scanner/shodan_client.py` — Optional Shodan API integration for passive
  reconnaissance. Automatic fallback to direct probing when no key is
  configured.
- `scanner/crypto_extractor.py` — Source-independent normalisation of raw
  probe data into `CryptoFacts` objects with security-strength estimates
  (RSA/ECC/hash), forward-secrecy detection, and broken-primitive flags.
- `scanner/crypto_assessor.py` — Multi-guideline scoring engine producing
  0–100 PQC readiness scores with structured findings (severity, category,
  recommendation, guideline attribution).
- `scanner/orchestrator.py` — Parallel scan coordinator: service discovery →
  TLS/STARTTLS probing → Shodan fallback → assessment → SQLite storage.

**Guidelines (versioned JSON)**
- `guidelines/nist_800_131a.json` — NIST SP 800-131Ar3 (October 2024 IPD):
  TLS versions, cipher suites, RSA/ECDSA/DH key sizes, hash functions, PQC
  algorithms (ML-KEM/FIPS 203, ML-DSA/FIPS 204, SLH-DSA/FIPS 205).
- `guidelines/bsi_tr02102.json` — BSI TR-02102-1 version 2026-01:
  RSA/DH minimum 3000 bits from 2026; brainpool curve preferences; FrodoKEM
  conservative PQC option.
- `guidelines/ccn_stic_221.json` — CCN-STIC-221 (2023): Spanish CCN
  authorised mechanisms aligned with ENISA and EU eIDAS.

**Domain discovery**
- `domain_discovery/domain_finder.py` — Natural language → domain list
  using Anthropic API (AI mode) with curated offline fallback covering
  finance, healthcare, government, energy, and telecom sectors across
  Spain, Germany, France, EU, UK, USA.

**Dashboard**
- `dashboard/app.py` — Flask REST API + single-file embedded HTML/JS dashboard.
  Views: Dashboard, Domain Discovery, Scan, Trends, Settings.
  Charts: readiness distribution (doughnut), TLS version coverage (bar),
  sector trend over time (line), readiness level changes (stacked bar),
  PQC adoption rate (line), per-domain score history (line).
  Export: CSV, JSON, plain-text report via `/api/export`.
  Schedule management UI in Trends view.

**Database**
- `data/database.py` — SQLite storage for raw scans, assessments, domain lists,
  scan runs, and periodic schedules. Longitudinal queries for trend charts.
- `data/migrations.py` — Incremental schema versioning; idempotent migration
  runner with duplicate-column error tolerance.

**Scheduler**
- `scheduler/scan_scheduler.py` — APScheduler-based periodic scan management.
  Schedules persisted in SQLite; re-registered on restart.

**Reports**
- `reports/report_generator.py` — CSV, JSON envelope, and plain-text report
  generation. JSON includes export metadata, summary statistics, and full
  assessment records for traceability.

**CLI** (`pqc_monitor.py`)
- `discover` — Natural language domain discovery with optional DNS validation
  and file output.
- `scan` — Multi-domain parallel scan with Shodan toggle, sector/region
  tagging, and per-domain progress output.
- `dashboard` — Launch web dashboard (configurable host/port).
- `schedule` — Add periodic scan schedule (default 90-day interval).
- `reassess` — Re-score historical raw scan data against updated guidelines
  without re-scanning.
- `export` — CSV / JSON / text export to stdout or file.
- `report` — Full text readiness report with trend section.
- `list-runs` — Tabular scan run history.
- `list-schedules` — Configured periodic schedule summary.

**Tests**
- `tests/test_assessor.py` — 33 tests: scoring engine, database layer,
  guideline JSON validation, score-level boundaries.
- `tests/test_scanner.py` — 60 tests: key exchange inference, PQC detection,
  RSA/ECC strength calculation, crypto extraction, weakness flags, forward
  secrecy, service discovery (mocked), migrations, report generation.
- `tests/seed_demo_data.py` — Realistic synthetic data seeder with 15 domain
  profiles across finance, government, healthcare, energy, and telecom sectors
  in Spain and Europe. Supports multiple historical runs for trend testing.

**Infrastructure**
- `install.sh` — Bash install script with `--venv` and `--demo` options.
- `Dockerfile` + `docker-compose.yml` — Container deployment.
- `config/config.yaml.example` — Annotated configuration template.
- `.gitignore` — Excludes databases, API keys, and virtual environments.
- `README.md` — Full documentation including architecture, usage, and scoring
  guide.
- `CONTRIBUTING.md` — Development setup, branching model, PR checklist,
  guideline update procedure, code of conduct.

### Security

- All scanning is non-intrusive: TCP-connect only for service discovery,
  standard TLS handshake for crypto extraction, no exploit payloads.
- API keys never committed; config excluded from version control.
- SPDX licence headers on all source files.
- AI-assistance disclosure in all generated source files and README.

### Guidelines applied

| ID | Name | Version | Published |
|----|------|---------|-----------|
| `nist_800_131a` | NIST SP 800-131Ar3 | r3-ipd | October 2024 |
| `bsi_tr02102` | BSI TR-02102-1 | 2026-01 | January 2026 |
| `ccn_stic_221` | CCN-STIC-221 | 2023 | 2023 |

---

[Unreleased]: https://github.com/your-org/pqc-monitor/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/your-org/pqc-monitor/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/your-org/pqc-monitor/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/your-org/pqc-monitor/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/your-org/pqc-monitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/your-org/pqc-monitor/releases/tag/v1.0.0
