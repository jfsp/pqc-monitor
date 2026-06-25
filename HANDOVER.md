# PQC-Monitor — Developer Handover Document

**Version:** 1.3.1
**Date:** 2026-06-25
**Status:** 452/452 tests passing
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
Two systemd services — `pqc-monitor-web` (Gunicorn) and `pqc-monitor-scheduler` (APScheduler daemon) — managed by `pqc-monitor.target`. Nginx reverse proxy for TLS termination. Runs as the `pqcmonitor` system user under `/opt/pqc-monitor`. Runtime data stored under `/var/lib/pqc-monitor/`.

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

Files changed:
  path/to/file.py
```
Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

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

### 2.1 v1.3.1 — Deployment fixes (2026-06-25)

This release contains no functional changes. All changes fix production deployment issues discovered on first deployment to a Ubuntu server behind nginx.

**Files changed:** `systemd/pqc-monitor-web.service`, `systemd/pqc-monitor-scheduler.service`, `scripts/wait-for-db.sh` (new), `data/database.py`, `app_factory.py`, `pqc_monitor.py`, `install.sh`, `config/config.yaml.example`

#### Fix 1 — systemd `${VAR:-default}` syntax not supported (`pqc-monitor-web.service`)

`ExecStart` arguments go directly to `execve()` — no shell involved. The bash `${VAR:-default}` fallback syntax is not understood by systemd's own `${}` expansion. Gunicorn received the literal string `${PQC_WEB_WORKERS:-2}` as the worker count, and `${PQC_BIND:-127.0.0.1:5000}` was mangled to `-127.0.0.1:5000`.

**Fix:** Declare defaults as `Environment=` lines before `EnvironmentFile=`. systemd processes them in order, so the `.env` file overrides the built-in defaults when the variable is set there — same semantic, correct syntax.

```ini
Environment=PQC_BIND=127.0.0.1:5000
Environment=PQC_WEB_WORKERS=2
EnvironmentFile=/etc/pqc-monitor/pqc-monitor.env
```

#### Fix 2 — `StartLimitIntervalSec`/`StartLimitBurst` in wrong section (both service files)

These keys belong in `[Unit]`, not `[Service]`. They were moved from `[Service]` in systemd v230. Modern systemd ignores them in `[Service]` with a warning. Moved to `[Unit]` in both service files.

#### Fix 3 — Scheduler fails if web service has not yet created the database

The scheduler called `Database(db_path)` at startup, which calls `sqlite3.connect()`. If the web service had not yet run to create the DB, this failed with `OperationalError: unable to open database file`.

**Fix:** New script `scripts/wait-for-db.sh` is invoked as `ExecStartPre` in the scheduler unit. It polls for the DB file every 2 seconds (up to 60 seconds) before `ExecStart` runs. The script is a separate file rather than an inline shell command because systemd expands `${...}` in `ExecStartPre` directives before passing to bash, destroying bash variables like `$waited` and arithmetic like `$((waited % 10))`.

Additionally added `Requires=pqc-monitor-web.service` so systemd does not attempt to start the scheduler if the web service is not running.

#### Fix 4 — Database path resolution is CWD-dependent (`data/database.py`)

`Database.__init__` stored the raw `db_path` string in `self.db_path`, then called `sqlite3.connect(self.db_path)` on every `_connect()`. The `os.makedirs()` call used `os.path.abspath()` (resolving against the master process CWD) but that resolved path was discarded. When gunicorn forked workers their CWD differed, so `sqlite3.connect("data/pqc_monitor.db")` resolved to a different path.

**Fix:** Resolve to absolute path once at construction time:
```python
def __init__(self, db_path: str = DEFAULT_DB_PATH):
    self.db_path = os.path.abspath(db_path)
    os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
```

#### Fix 5 — `app_factory.create_app()` ignores `config.yaml` when called by gunicorn (`app_factory.py`)

Gunicorn calls `create_app()` with no arguments (`cfg = {}`), so `db_path` fell back to the hardcoded string `"data/pqc_monitor.db"`, ignoring `/etc/pqc-monitor/config.yaml` entirely.

**Fix:** Load config when no dict is passed:
```python
def create_app(config: dict = None) -> Flask:
    if config is None:
        try:
            from pqc_monitor import load_config
            cfg = load_config()
        except Exception:
            cfg = {}
    else:
        cfg = config
```

#### Fix 6 — Relative `db_path` in `load_config()` is CWD-dependent (`pqc_monitor.py`)

CLI commands using a relative `db_path` from config resolved it against the process CWD at each `Database()` call. Now resolved against `ROOT` (the app directory) at config load time:

```python
raw_db_path = raw.get("database", {}).get("path", "data/pqc_monitor.db")
db_path = raw_db_path if os.path.isabs(raw_db_path) \
          else os.path.join(ROOT, raw_db_path)
```

#### Fix 7 — Database stored alongside code in `/opt/pqc-monitor/data/` (`install.sh`)

Runtime-writable data should not live inside the code directory. `ProtectSystem=full` makes the app directory read-only at runtime, then `ReadWritePaths=/opt/pqc-monitor/data` punched a writable hole back in.

**Fix:** Runtime data moved to `/var/lib/pqc-monitor/`:
- `install.sh` creates `/var/lib/pqc-monitor/` (owned `pqcmonitor:pqcmonitor 750`)
- `install.sh` no longer creates `$INSTALL_DIR/data/` subdirectories
- `install.sh` patches `config.yaml` database path to `/var/lib/pqc-monitor/pqc_monitor.db`
- `install.sh` patches `config.yaml` log path to `/var/log/pqc-monitor/pqc_monitor.log`
- `install.sh` initialises the database as `pqcmonitor` before starting services
- Both service units: `ReadWritePaths=/var/lib/pqc-monitor /var/log/pqc-monitor`

#### Fix 8 — Gunicorn control socket tries to write to `/home/pqcmonitor` (`pqc-monitor-web.service`)

The `pqcmonitor` service user is created with `--no-create-home`. Gunicorn's worker heartbeat mechanism creates a temporary socket file in the process home directory as a fallback. `PrivateTmp=true` already provides a private `/tmp`.

**Fix:** `--worker-tmp-dir /tmp` added to the gunicorn `ExecStart` invocation.

#### Fix 9 — `Type=notify` with plain gunicorn causes systemd timeout (`pqc-monitor-web.service`)

`Type=notify` tells systemd to wait for an `sd_notify(READY=1)` signal before marking the service started. Standard gunicorn does not send this signal. The service started correctly but systemd would eventually time out waiting.

**Fix:** Changed to `Type=simple`. Gunicorn is a long-running foreground process — `simple` is the correct type.

#### Fix 10 — Login loop: session cookie not persisting after successful auth (`app_factory.py`)

Symptom: POST /login returns 302, GET /app/ immediately redirects back to /login. Login succeeds but the browser drops the session cookie on the redirect.

Root cause: Flask sits behind nginx (TLS termination). Without `ProxyFix`, Flask sees all traffic as plain HTTP from the loopback, so `request.url` in `require_auth` generates `http://pqc-monitor.ddns.net/app/` as the `next=` parameter. After login, `auth_routes.py` correctly strips this to the path `/app/` and redirects. The browser follows, `require_auth` fires again, generates another `http://` next URL — infinite loop. Separately, if `https_enabled: true` is set, the `Secure` cookie flag means the browser will not send the cookie on what it considers a plain-HTTP redirect target.

**Fix:** Added `ProxyFix` middleware so Flask correctly reads `X-Forwarded-Proto` from nginx:
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
```

`ProxyFix` is part of Werkzeug (already a Flask dependency — no new package required). Nginx must pass `proxy_set_header X-Forwarded-Proto $scheme;` (standard in most configs).

After applying this fix, set `https_enabled: true` in `/etc/pqc-monitor/config.yaml` to enable `Secure` cookies and HSTS headers.

---

## 3. Repository Layout

```
pqc-monitor/
├── VERSION                     # "1.3.1" — ONLY file to edit when releasing
├── version.py                  # reads VERSION, exports VERSION/__version__
├── pqc_monitor.py              # CLI entry point (12 commands)
├── scripts/
│   ├── README.md               # Script usage reference
│   ├── wait-for-db.sh          # NEW: polls for DB file existence (used by scheduler unit ExecStartPre)
│   ├── bulk_org_assign.py      # Bulk-assign domains to an org by TLD pattern
│   └── diagnose.py             # Shodan + DNSDumpster integration diagnostic
├── app_factory.py              # Flask app factory — the production entry point
├── app_routes.py               # Analyst /app/* Blueprint (24 routes)
│
├── auth/
│   ├── models.py               # User, AuditEvent dataclasses; PERMISSIONS dict
│   ├── store.py                # AuthStore: SQLite user CRUD, password hashing, audit
│   ├── middleware.py           # Decorators: require_auth, require_role, require_admin
│   │                           # AuthProvider interface (swap for SAML later)
│   └── auth_routes.py          # /login  /logout  /change-password
│
├── admin/
│   └── routes.py               # /admin/* Blueprint — User mgmt + Domain List CRUD SPA
│
├── scanner/
│   ├── orchestrator.py         # Parallel scan coordinator (steps 1-6 per domain)
│   ├── service_discovery.py    # TCP port discovery + DANE/DNSSEC
│   ├── tls_probe.py            # TLS handshake + leaf certificate extraction
│   ├── starttls_probe.py       # SMTP/IMAP/LDAP STARTTLS probes
│   ├── chain_validator.py      # Full chain analysis: per-cert scoring, HSTS, CAA
│   ├── cipher_enum.py          # Active cipher suite enumeration (multiple ClientHellos)
│   ├── cdn_detector.py         # CDN detection: CNAME, headers, IP ranges, PTR
│   ├── crypto_assessor.py      # Scoring engine → DomainAssessment dataclass
│   ├── crypto_extractor.py     # Raw scan dict → normalised CryptoFacts
│   └── shodan_client.py        # Optional Shodan API wrapper
│
├── ct/
│   └── ct_monitor.py           # crt.sh CT log queries + PQC OID classification
│
├── roadmap/
│   └── generator.py            # 3-phase PQC migration roadmap generator
│
├── domain_discovery/
│   └── domain_finder.py        # NL → domain list via Anthropic API (offline fallback)
│
├── dashboard/
│   └── app.py                  # 2180-line Python file containing:
│                               #   - Flask create_app() (legacy, used for dev only)
│                               #   - DASHBOARD_HTML: full SPA as a Jinja2 template string
│                               # WARNING: see Critical Implementation Notes §9.1
│
├── data/
│   ├── database.py             # Database class: 27 public methods, SQLite WAL
│   └── migrations.py           # 14 incremental schema migrations (v1-v14)
│
├── scheduler/
│   └── scan_scheduler.py       # APScheduler wrapper; persists schedules in DB
│
├── reports/
│   └── report_generator.py     # CSV / JSON / plain-text export
│
├── guidelines/                 # Versioned policy rule JSON files
│   ├── nist_800_131a.json      # NIST SP 800-131Ar3 (Oct 2024 IPD)
│   ├── bsi_tr02102.json        # BSI TR-02102-1 (2026-01)
│   └── ccn_stic_221.json       # CCN-STIC-221 (2023)
│
├── systemd/                    # Production deployment
│   ├── pqc-monitor.target      # Groups both services
│   ├── pqc-monitor-web.service # Gunicorn; Type=simple; --worker-tmp-dir /tmp
│   ├── pqc-monitor-scheduler.service  # Requires web service; ExecStartPre wait-for-db.sh
│   ├── pqc-monitor.env         # Environment template → /etc/pqc-monitor/
│   └── nginx-pqc-monitor.conf  # Sample nginx reverse proxy
│
├── tests/
│   ├── test_assessor.py        # Scoring engine + guideline tests
│   ├── test_auth.py            # Full RBAC + domain list CRUD (366 tests total)
│   ├── test_ct.py              # CT monitor tests
│   ├── test_roadmap.py         # Roadmap generator tests
│   ├── test_scan_quality.py    # Chain validator, cipher enum, CDN detector
│   ├── test_scanner.py         # TLS probe + extractor tests
│   └── seed_demo_data.py       # Generates realistic synthetic scan data
│
├── config/
│   └── config.yaml.example     # Annotated configuration template
│
├── install.sh                  # Dev (--demo) and production (--production) installer
├── requirements.txt            # All Python dependencies
├── README.md                   # Full deployment and usage documentation
├── CHANGELOG.md                # Per-version change log
└── CONTRIBUTING.md             # Release procedure + contribution guide
```

---

## 4. Architecture

### 4.1 Request flow (authenticated)

```
Browser
  └─ HTTPS → nginx (X-Forwarded-Proto: https) → Gunicorn
       └─ ProxyFix (werkzeug) — rewrites request.url to https://
            └─ Flask app_factory.create_app()
                 ├─ auth_bp   (/login, /logout, /change-password)
                 ├─ admin_bp  (/admin/*, /admin/api/*)
                 └─ app_bp    (/app/, /app/api/*)
                       └─ require_auth decorator
                            └─ filter_assessments(data, user)  ← domain scoping
```

### 4.2 Scan pipeline (per domain, in `orchestrator._scan_domain`)

```
1. Shodan API (optional, if key configured)
2. service_discovery  → open TLS ports + STARTTLS ports
3. tls_probe          → leaf cert + TLS version + cipher suite
   starttls_probe     → SMTP/IMAP/LDAP STARTTLS
4. chain_validator    → full chain, HSTS, CAA
5. cipher_enum        → active cipher suite enumeration
6. cdn_detector       → CDN identification + PQC support note
7. crypto_assessor    → DomainAssessment (score 0-100, level, findings)
```

### 4.3 Dashboard rendering

`app_routes.dashboard_home()` renders `DASHBOARD_HTML` from `dashboard/app.py`
directly as a Jinja2 template, injecting `version`, `user`, `is_admin`.

A fetch-rewrite IIFE (injected before the first `<script src=` tag) rewrites
all `fetch('/api/...')` calls to `fetch('/app/api/...')` so the existing
dashboard JavaScript works under the `/app/` prefix without modification.

**Important:** The DASHBOARD_HTML string contains `{{ version }}`, `{{ user.username }}`,
and related Jinja2 expressions — these are rendered server-side at request time,
not client-side.

### 4.4 Blueprint test isolation

`app_factory.create_app()` calls `importlib.reload()` on the three blueprint
modules before registering them. This is intentional — Flask raises
`AssertionError` if the same Blueprint object is registered on two different
Flask app instances (which happens in tests). Do not remove this pattern without
replacing it with `make_blueprint()` factory functions in each module.

### 4.5 Version management

Edit only `VERSION`. The string is read by:
- `version.py` → `VERSION` constant imported everywhere
- `pqc_monitor.py --version` (via `click.version_option`)
- `GET /api/version` endpoint
- All Jinja2 templates via the `version` context variable

### 4.6 Production filesystem layout

```
/opt/pqc-monitor/        root:pqcmonitor  755  — application code (read-only at runtime)
/etc/pqc-monitor/        root:pqcmonitor  750  — configuration
  config.yaml                                    — app config (640 root:pqcmonitor)
  pqc-monitor.env                                — secrets/env (640 root:pqcmonitor)
/var/lib/pqc-monitor/    pqcmonitor       750  — runtime data (writable)
  pqc_monitor.db                                 — SQLite database
/var/log/pqc-monitor/    pqcmonitor       750  — logs (writable)
```

The code directory is intentionally read-only at runtime. `ProtectSystem=full` in
the service units enforces this. `ReadWritePaths` grants write access only to
`/var/lib/pqc-monitor` and `/var/log/pqc-monitor` — not to the app tree.

---

## 5. Database Schema

**SQLite file:** `/var/lib/pqc-monitor/pqc_monitor.db`
**Development:** `data/pqc_monitor.db` (relative to project root)
**Current migration:** v14
**Connection mode:** WAL (Write-Ahead Logging) for concurrent reads

### Tables

| Table | Purpose |
|-------|---------|
| `scan_runs` | One row per scan batch: run_id (UUID8), domain_list JSON, sector, region, status |
| `raw_scans` | One row per domain×port×protocol: raw TLS probe result JSON |
| `assessments` | One row per domain per run: score, level, findings_json, tls_versions, has_pqc |
| `domain_lists` | Named lists of domains: id, name, query, domains_json, created_at, updated_at |
| `scheduled_scans` | APScheduler-managed periodic scan configs |
| `domain_extra` | Enrichment data per domain per run: chain/cipher_enum/cdn JSON blobs |
| `ct_queries` | CT log query results per domain |
| `ct_certificates` | Individual certificate records from CT logs |
| `roadmaps` | Persisted roadmap items per domain per run |
| `users` | RBAC users: username, email, password_hash, role, is_active, lockout state |
| `user_domain_lists` | Many-to-many: which users can see which domain lists |
| `audit_log` | Login/logout/action events with IP and user-agent |
| `organisations` | Named organisations grouping domains |
| `domain_organisations` | Many-to-many: domain → org assignments |
| `user_organisations` | Many-to-many: user → org assignments |

### Migration history

```
v1   Initial schema (scan_runs, raw_scans, assessments, domain_lists, scheduled_scans)
v2   Add notes to scan_runs
v3   Add has_dane, has_dnssec to raw_scans
v4   Add services_assessed to assessments
v5   Add key_types to assessments
v6   Add sector, region to scheduled_scans
v7   Add ct_queries, ct_certificates (Certificate Transparency)
v8   Add domain_extra (chain analysis, cipher enum, CDN enrichment)
v9   Add roadmaps table
v10  Add users, user_domain_lists, audit_log (RBAC)
v11  Add updated_at to domain_lists
v12  Add service_type to assessments
v13  Add dns_enumerator results to domain_extra
v14  Add organisations, domain_organisations, user_organisations
```

New migrations are appended to `data/migrations.py` MIGRATIONS list.
Migrations run automatically on first DB connection via `apply_migrations()`.

### Key Database class methods

```python
# Scan lifecycle
db.create_run(domains, sector, region) → run_id
db.save_scan_result(run_id, result_dict)
db.save_assessment(run_id, assessment_dict)
db.finish_run(run_id, status)

# Retrieval
db.get_latest_assessments(run_id=None) → list  # scoped by run or latest per domain
db.get_domain_history(domain) → list            # all assessments for one domain
db.get_summary_stats() → dict                   # counts by level for dashboard cards
db.get_sector_trends() → list                   # score over time

# Domain lists
db.save_domain_list(name, domains, query) → id
db.get_domain_list_full(id) → dict              # includes domains array
db.update_domain_list(id, name, domains, query)
db.delete_domain_list(id)                       # cascades user_domain_lists
db.get_all_known_domains() → list               # distinct domains from assessments

# Enrichment
db.save_domain_extra(run_id, domain, data_type, data)  # type: chain|cipher_enum|cdn
db.get_domain_extra(domain, run_id) → dict

# CT
db.save_ct_summary(summary_dict)
db.get_ct_pqc_certificates(domain=None) → list

# Roadmap
db.save_roadmap(run_id, roadmap_dict)
db.get_roadmaps(run_id=None, domain=None) → list
```

---

## 6. API Reference

All routes under `/app/api/*` require authentication (`require_auth`).
All routes under `/admin/api/*` require admin role (`require_admin`).
Domain-scoped routes filter results via `filter_assessments(data, user)`.

### Analyst API (`/app/api/`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | Dashboard stat cards + recent runs |
| GET | `/api/assessments?run_id=` | Domain assessment list (domain-scoped) |
| GET | `/api/domain/<domain>` | Single domain detail + history |
| GET | `/api/trends` | Score trends over time |
| GET | `/api/runs` | Scan run history |
| GET | `/api/domain-lists` | Lists visible to current user |
| POST | `/api/discover` | NL domain discovery (admin only) |
| POST | `/api/scan` | Trigger scan (admin only) |
| POST | `/api/reassess` | Re-score existing run (admin only) |
| POST | `/api/save-domains` | Save discovered domains as list (admin only) |
| GET | `/api/ct/stats` | CT aggregate stats |
| GET | `/api/ct/summaries?domain=` | CT query summaries |
| GET | `/api/ct/certificates?domain=` | PQC certificates found |
| GET | `/api/ct/timeline` | CT findings by month |
| POST | `/api/ct/monitor` | Run CT log query (admin only) |
| GET | `/api/roadmap/stats` | Roadmap summary stats |
| GET | `/api/roadmap?run_id=&domain=` | Roadmap items |
| GET | `/api/roadmap/domain/<domain>` | Single domain roadmap |
| POST | `/api/roadmap/generate` | Generate roadmaps (admin only) |
| GET | `/api/export?format=csv\|json\|text` | Export results |
| GET | `/api/schedules` | Periodic scan schedules |
| POST | `/api/schedules` | Add schedule (admin only) |
| GET | `/api/me` | Current user info |
| GET | `/api/version` | `{"version":"1.3.1","name":"PQC-Monitor"}` |

### Admin API (`/admin/api/`)

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/users` | List all / create user |
| GET/PATCH/DELETE | `/api/users/<uid>` | Get / update / delete user |
| POST | `/api/users/<uid>/password` | Reset password |
| GET/PUT | `/api/users/<uid>/domain-lists` | Get/set domain list assignments |
| GET | `/api/domain-lists` | All lists with domain_count, user_count |
| GET | `/api/domain-lists/<id>` | Full list including domains array |
| POST | `/api/domain-lists` | Create list |
| PATCH | `/api/domain-lists/<id>` | Update name/query/domains |
| DELETE | `/api/domain-lists/<id>` | Delete + cascade assignments |
| GET | `/api/domains/known` | All assessed domains (for picker) |
| GET | `/api/audit-log?limit=&user_id=` | Audit events |

---

## 7. Authentication & RBAC

### Roles and permissions

```python
ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"

PERMISSIONS = {
    ROLE_ADMIN:   {"user.manage", "domain_list.manage", "scan.run",
                   "schedule.manage", "ct.run", "roadmap.generate",
                   "report.export", "admin.panel", "audit.view", ...},
    ROLE_ANALYST: {"domain_list.view_own", "scan.view_own",
                   "ct.view_own", "roadmap.view_own", "report.export"},
}
```

### Domain scoping

Analysts are assigned domain lists by admins. The `AuthStore.get_user_domains(user_id)`
method resolves all domain strings from assigned lists. Every API endpoint that
returns domain data calls `filter_assessments(data, user)` which:
- Returns all data unchanged for admins
- Returns only rows where `row["domain"] in allowed_domains` for analysts

Analyst access is the **union** of two sources:
1. Domain lists explicitly assigned to the user (`user_domain_lists` table)
2. Domains belonging to organisations the user is assigned to (`user_organisations` → `domain_organisations`)

The union is deduplicated in `AuthStore.get_user_domains()`.

### Session model

- Flask signed cookies (`itsdangerous` HMAC), 8-hour lifetime
- `SESSION_COOKIE_SECURE = False` by default; set `https_enabled: true` in config when nginx+TLS is in front
- `ProxyFix` middleware reads `X-Forwarded-Proto` from nginx — nginx must pass `proxy_set_header X-Forwarded-Proto $scheme;`
- 10 failed logins → 15-minute account lockout
- 10 login attempts/IP/minute rate limiting
- Default credentials: `admin` / `changeme123` — **change immediately after first login**

### AuthProvider interface

```python
class AuthProvider:
    def authenticate(self, username, password) -> Optional[User]: ...
    def get_user(self, user_id) -> Optional[User]: ...
```

`LocalAuthProvider` (currently active) uses `AuthStore`.
To add SAML/OIDC: implement `SAMLAuthProvider`, swap in `app_factory.py`.

### Decorators

```python
@require_auth          # any authenticated user; 401 JSON for /api/ paths
@require_role("admin") # specific role; 403 for /api/ paths
@require_admin         # shorthand for @require_role("admin")
```

---

## 8. Known Issues & Technical Debt

### 8.1 Antivirus false positives (not yet fixed)

The ZIP distribution is flagged by some AV engines. Root causes in priority order:

1. **`scanner/cipher_enum.py`** — Primary trigger. Contains `ssl.CERT_NONE` +
   `check_hostname = False` + `ctx.set_ciphers()` in a loop with explicit strings
   `RC4-SHA`, `NULL-SHA`, `EXP-RC4-MD5`, `ADH-`, `AECDH-` etc. This pattern
   matches SSL stripping / MITM tool signatures exactly.
   *Fix: move cipher name strings to a JSON file; rename `_probe_cipher` to
   something less suggestive; add a prominent comment block explaining purpose.*

2. **`app_factory.py`** — `importlib.reload()` is a known malware evasion technique.
   *Fix: implement `make_blueprint()` factory functions in each blueprint module
   and call those instead. Each call returns a fresh Blueprint with all routes
   registered.*

3. **`install.sh`** — `useradd`, `chown -R`, writes to `/etc/systemd/` in sequence
   matches dropper/persistence heuristics.
   *Fix: not much can be done; could split into separate archive.*

4. **`ct/ct_monitor.py` and `scanner/chain_validator.py`** — `__import__()` dynamic
   imports flagged as obfuscation.
   *Fix: replace with standard top-level imports with try/except ImportError.*

### 8.2 `dashboard/app.py` is a 2180-line monolith

The entire SPA (HTML, CSS, JS) lives as a Python string in one file. This makes
git diffs hard to read and IDE support poor for the JS/CSS. Future new views
should consider splitting into a `static/` directory or a proper Jinja2
templates folder, with JS loaded from separate files.

### 8.3 Cipher enumeration is slow

`cipher_enum.py` opens one TCP connection per cipher group (30+ groups for TLS 1.2).
At 6-second timeout each, a full enumeration can take 3-4 minutes per domain
even with 8 parallel workers. Consider caching results in `domain_extra` and
skipping re-enumeration on re-assessment.

### 8.4 No rate limiting on scan endpoints

The `/api/scan` endpoint can trigger expensive outbound network activity. Only
`/login` has rate limiting. Add `require_auth` + a per-user scan concurrency
limit for internet-facing deployments.

### 8.5 `domain_lists.domains_json` not indexed

Domain membership lookup iterates all lists. Fine for <1000 domains. Will slow
down at larger scale. Consider a `domain_list_members` join table.

---

## 9. Critical Implementation Notes

### 9.1 The two Flask apps in dashboard/app.py

`dashboard/app.py` contains **two** `create_app()` implementations:
- The legacy one (used in standalone `pqc_monitor.py dashboard` command for dev)
- `app_factory.create_app()` is the production entry point

When adding features to the web UI, **always** work in `app_factory.py` +
`app_routes.py` + `admin/routes.py`. Do not add routes to `dashboard/app.py`'s
legacy `create_app()` — those routes are not protected by RBAC.

### 9.2 HTML structure of dashboard views

All seven views (`view-dashboard`, `view-domains`, `view-scan`, `view-trends`,
`view-ct`, `view-roadmap`, `view-settings`) are siblings inside
`<div class="main">` in `DASHBOARD_HTML`. They are all always present in the DOM
with `display:none` and the active one gets `display:block` via `.active` CSS class.

**Critical:** The `</div>` that closes each view must be present. A missing
closing div causes all subsequent views to become children of the unclosed one,
inheriting its `display:none` state. Always verify with a depth-counting script
after editing view HTML. This was the root cause of the v1.1.2 and v1.1.3 bugs.

```python
# Verification script — run after any HTML edits to dashboard/app.py
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

The dashboard JS was written to call `/api/...` directly. Under the auth shell it
runs at `/app/` and must call `/app/api/...`. This is handled by a fetch-rewrite
IIFE injected by `dashboard_home()` in `app_routes.py`:

```python
fetch_rewrite = """<script>
(function(){
  const _orig = window.fetch;
  window.fetch = function(url, opts) {
    if (typeof url === 'string' && url.startsWith('/api/')) {
      url = '/app' + url;
    }
    return _orig.call(this, url, opts);
  };
})();
</script>"""
```

Any new JS fetch calls in the dashboard must use `/api/...` paths (not `/app/api/...`)
so they work both in the standalone dev server and under the auth shell.

### 9.4 Config: https_enabled and ProxyFix

```yaml
# config.yaml — set this after nginx+TLS is confirmed working
dashboard:
  https_enabled: true   # set true when behind nginx with TLS
```

When `https_enabled: true`, `SESSION_COOKIE_SECURE = True` and HSTS headers are sent.
`ProxyFix` middleware (added in v1.3.1) makes Flask trust `X-Forwarded-Proto: https`
from nginx, so `request.url` reflects `https://` and the `Secure` cookie flag is
consistent with what the browser sees.

**nginx must pass:** `proxy_set_header X-Forwarded-Proto $scheme;`

Without `ProxyFix`: Flask generates `http://` next-param URLs after login → infinite
redirect loop. This was the primary deployment failure in v1.3.0 → v1.3.1.

### 9.5 Domain-list scoping in new endpoints

Every new API endpoint that returns domain-related data **must** call
`filter_assessments(data, user)` from `auth/middleware.py`. Failing to do so
leaks cross-tenant data to analysts. The pattern:

```python
from auth.middleware import require_auth, current_user, filter_assessments

@app_bp.route("/api/new-endpoint")
@require_auth
def api_new_endpoint():
    user = current_user()
    data = db.get_something()
    return jsonify(filter_assessments(data, user))
```

For endpoints with a single domain parameter:
```python
if not user.is_admin:
    allowed = set(current_app.config["AUTH_STORE"].get_user_domains(user.id))
    if domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
```

### 9.6 DNSDumpster integration

The DNS enumerator (`scanner/dns_enumerator.py`) supports two paths:

**Official API (recommended for production):**
Set `dns_enumeration.dnsdumpster_api_key` in `config.yaml` or export
`PQC_DNSDUMPSTER_KEY`. The module calls `https://api.dnsdumpster.com/domain/{domain}`
with `Authorization: Bearer <key>`. Obtain a key at https://dnsdumpster.com/api/

**HTML scrape (fallback, development only):**
When no key is configured, the module falls back to a CSRF-token extraction
and HTML POST to `dnsdumpster.com`. This is fragile, unofficial, and may break
without notice. It is disabled by default (`use_dnsdumpster=False` unless a key
is present or the caller explicitly passes `use_dnsdumpster=True`).

### 9.7 Organisation scoping interaction with domain lists

Analyst access is the **union** of two sources:
1. Domain lists explicitly assigned to the user (`user_domain_lists` table)
2. Domains belonging to organisations the user is assigned to (`user_organisations` →
   `domain_organisations`)

The union is deduplicated in `AuthStore.get_user_domains()`. This means an admin
can assign access via either mechanism without conflict. If a domain is in both
sources it appears only once.

The `?org_id=` filter on `GET /api/assessments` is an **additional** filter
on top of RBAC scoping — a user cannot use it to see domains outside their
allowed set.

### 9.8 systemd unit constraints

**Do not use `${VAR:-default}` in `ExecStart` or `ExecStartPre`.**
systemd expands `${}` before passing arguments to the process — bash fallback
syntax is not supported. Declare defaults as `Environment=` lines before the
`EnvironmentFile=` directive; the env file overrides them when the variable is set.

**Do not put `StartLimitIntervalSec`/`StartLimitBurst` in `[Service]`.**
These keys belong in `[Unit]` since systemd v230.

**Do not use inline shell commands with bash variables in `ExecStartPre`.**
Systemd expands `${}` in the directive before bash gets it, destroying variables
like `$waited` and arithmetic like `$((waited % 10))`. Put any non-trivial shell
logic in a separate script and call that script from `ExecStartPre`.

**`Type=simple` is correct for gunicorn.** `Type=notify` requires gunicorn to
emit `sd_notify(READY=1)`, which standard gunicorn does not do.

---

## 10. Planned Features — Prioritised Backlog

Features are ordered from smallest to largest change surface. Items marked
**(discussed)** were mentioned in the development session; others are editorial
recommendations.

---

### Tier 1 — Config / data changes only (no new modules)

**[T1-1] Fix AV false positives**
Move cipher name strings in `cipher_enum.py` to a JSON data file. Replace
`__import__()` calls in `ct/ct_monitor.py` and `scanner/chain_validator.py` with
top-level try/except imports. Replace `importlib.reload()` in `app_factory.py`
with `make_blueprint()` factory functions. *Low risk, self-contained.*

**[T1-2] Geography / region on domain lists** *(requested)*
Add `region` and `country_code` columns to `domain_lists` (migration v15).
Surface region in the domain list editor modal. The RBAC scoping model already
supports domain-list-scoped access — adding region to lists means analysts can
be assigned a regional list (e.g. "EU Finance") and automatically see only
relevant geography.

**[T1-3] Expiry and certificate age warnings in dashboard**
The assessments table already stores `cert_expiry_days`. Add a dashboard filter
for "expiring within 30/60/90 days" using the existing card-filter mechanism.
Zero new backend code needed — purely a JS/HTML addition to the dashboard.

**[T1-4] Export roadmap as PDF/DOCX** *(discussed in development session)*
The `roadmap/generator.py` already has `render_roadmap_text()` and
`render_sector_roadmap_text()`. Add `render_roadmap_docx()` using the existing
`docx` skill. Expose via `GET /api/roadmap/export?format=docx`.

**[T1-5] Asset Criticality Weighting** *(High Value / Low-Medium Complexity)*
Migration: add `criticality TEXT DEFAULT 'normal'` to `assessments`.
Admin UI: criticality dropdown on domain detail panel.
`roadmap/generator.py`: phase assignment weighted by criticality.
Dashboard: criticality colour column; filter pill.

---

### Tier 2 — New columns + existing module extension

**[T2-1] Resource type tagging on assessments** *(requested — schema delivered in v1.2.0)*
`service_type` column exists. Dashboard filtering by service type is the remaining UI work.

**[T2-2] Per-domain resource aggregation view** *(requested)*
Domain detail panel grouping all resources (web, SMTP, IMAP, LDAP) with per-service
score rows. Requires T2-1 complete.
- `GET /api/domain/<domain>/resources` → assessments grouped by service_type
- Dashboard: extend `showDomainDetail()` to show resource table

**[T2-3] Geographic coordinates on domain assessments**
Add `country_code`, `latitude`, `longitude` to `assessments`. Populate from
ip-api.com (free, no key) during scan. Prerequisite for the map view (T3-2).

**[T2-4] Executive PDF Reporting** *(High Value / Medium Complexity)*
New module: `reports/pdf_report.py` using `weasyprint` (HTML→PDF).
Cover page, traffic-light table, phase summary, regulatory deadline countdown.
`GET /api/export?format=pdf`. Admin "Export PDF" button.

**[T2-5] Budget and Resource Estimation** *(High Value / High Complexity)*
Extend roadmap with cost estimates: `cost_min_eur`, `cost_max_eur`, `fte_months`.
New `roadmap/budget_estimator.py` mapping task types to effort multipliers.
`GET /api/roadmap/export?format=budget_csv`.

---

### Tier 3 — New modules, moderate complexity

**[T3-1] DNS deep-dive on domain add** *(requested — delivered in v1.2.0)*
`scanner/dns_enumerator.py` exists. Integration with domain add flow is the remaining work.

**[T3-2] Geographic map view** *(requested)*
Choropleth + dot map showing PQC readiness by country. Requires T2-3.
Leaflet.js (CDN, no API key). New `view-map` dashboard view.

**[T3-3] SSL Labs integration** *(discussed)*
Optional enrichment via Qualys SSL Labs API v4. Default OFF. Results in `domain_extra`
as type `ssl_labs`. Async polling required (assessments take 60-120s).
New module: `scanner/ssl_labs_client.py`.

**[T3-4] Sector Benchmarking** *(Medium Value / Low-Medium Complexity)*
Aggregate `AVG(score)` by `(sector, region)` across all scan runs.
`GET /api/benchmarks`. New `view-benchmarks` dashboard view.
Only meaningful in multi-organisation deployments.

---

### Tier 4 — Significant architectural changes

**[T4-1] Multi-resource domain model** *(requested)*
Domain as container of resources (web, SMTP, IMAP, LDAP) with per-resource scores
and a weighted aggregate. Requires T2-1 + T3-1. Full dashboard refactor.

**[T4-2] Trend alerting and notifications**
Email/webhook when score drops below threshold or new critical finding appears.
New `alerting/` module, `alerts` table, APScheduler job, Settings panel.

**[T4-3] SAML / OIDC authentication**
`AuthProvider` interface already designed for this. Implement `SAMLAuthProvider`
using `python3-saml` or `OIDCProvider` using `authlib`. Swap in `app_factory.py`.

**[T4-4] Dashboard frontend separation**
Extract `DASHBOARD_HTML` from `dashboard/app.py` into `static/` files.
Quality-of-life for development; no functional change.

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

**Test count:** 452 (as of v1.3.0; v1.3.1 adds no new tests — deployment fixes only)

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

# nginx
sudo cp /opt/pqc-monitor/systemd/nginx-pqc-monitor.conf \
        /etc/nginx/sites-available/pqc-monitor
# Ensure nginx config includes:
#   proxy_set_header X-Forwarded-Proto $scheme;
#   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
sudo certbot --nginx -d your.domain.example
sudo systemctl reload nginx

# After update
sudo systemctl stop pqc-monitor.target
sudo ./install.sh --production
sudo systemctl start pqc-monitor.target

# Manual DB migration (existing installs upgrading from data/ to /var/lib/)
sudo mkdir -p /var/lib/pqc-monitor
sudo chown pqcmonitor:pqcmonitor /var/lib/pqc-monitor
sudo chmod 750 /var/lib/pqc-monitor
sudo mv /opt/pqc-monitor/data/pqc_monitor.db /var/lib/pqc-monitor/
sudo chown pqcmonitor:pqcmonitor /var/lib/pqc-monitor/pqc_monitor.db
sudo sed -i 's|data/pqc_monitor.db|/var/lib/pqc-monitor/pqc_monitor.db|' \
    /etc/pqc-monitor/config.yaml
sudo systemctl daemon-reload && sudo systemctl restart pqc-monitor.target
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
   - Add nav button with `onclick="showView('newview',this)"`
   - Add data-loading call in `showView()` function
   - Verify all view divs are at depth=2 using the verification script in §9.2
6. **New tests** → add to appropriate `tests/test_*.py`
7. **Version bump** → edit `VERSION` file, add CHANGELOG entry
8. **RBAC** → add new permission strings to `PERMISSIONS` dict in `auth/models.py` if needed

---

## Appendix D — Operational Scripts

Scripts live in `scripts/` and are run from the project root:

```bash
cd /opt/pqc-monitor
python3 scripts/<script>.py --help
```

All scripts load `config/config.yaml` automatically; override with `--config`.
See `scripts/README.md` for full usage.

### wait-for-db.sh — Database readiness check (NEW in v1.3.1)

Invoked by `pqc-monitor-scheduler.service` as `ExecStartPre`. Polls for the
SQLite database file every 2 seconds, logging progress every 10 seconds. Exits 1
after 60 seconds if the file has not appeared.

```bash
# Usage (args are positional, both optional)
scripts/wait-for-db.sh [db_path] [timeout_seconds]
# Default: /var/lib/pqc-monitor/pqc_monitor.db  60
```

### bulk_org_assign.py — Bulk domain → organisation assignment

Assigns every domain matching a TLD pattern to a named organisation. Assignments
are additive — existing org domains are never removed.

```bash
python3 scripts/bulk_org_assign.py \
    --tld bde.es \
    --org "Banco de España" \
    --sector "Financial Services" \
    --region "EU/Spain" \
    --dry-run   # preview without writing
```

### diagnose.py — API integration diagnostic

Tests Shodan and DNSDumpster connectivity from the production environment.

```bash
python3 scripts/diagnose.py --config config/config.yaml --domain bde.es
```
