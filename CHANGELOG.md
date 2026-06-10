# Changelog

All notable changes to PQC-Monitor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

*Add entries here as work progresses on the next release.*

---

## [1.1.0] — 2026-06-10

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

[Unreleased]: https://github.com/your-org/pqc-monitor/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/your-org/pqc-monitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/your-org/pqc-monitor/releases/tag/v1.0.0
