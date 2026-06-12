# PQC-Monitor — Developer Handover Document

**Version:** 1.3.0  
**Date:** 2026-06-11  
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
Two systemd services — `pqc-monitor-web` (Gunicorn) and `pqc-monitor-scheduler` (APScheduler daemon) — managed by `pqc-monitor.target`. Nginx reverse proxy for TLS termination. Runs as the `pqcmonitor` system user under `/opt/pqc-monitor`.

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
| 1.3.0 | DNSDumpster official API key support (`dns_enumeration.dnsdumpster_api_key` in config, `PQC_DNSDUMPSTER_KEY` env var; `use_dnsdumpster` now defaults to `False`); Organisation grouping (migration v14: `organisations`, `domain_organisations`, `user_organisations` tables; full CRUD API; admin "🏢 Organisations" panel tab; `?org_id=` and `?region=` filters on assessments; org/region dropdowns in dashboard; analyst org scoping in RBAC) |

---

## 3. Repository Layout

```
pqc-monitor/
├── VERSION                     # "1.3.0" — ONLY file to edit when releasing
├── version.py                  # reads VERSION, exports VERSION/__version__
├── pqc_monitor.py              # CLI entry point (12 commands)
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
│   └── migrations.py           # 11 incremental schema migrations (v1-v11)
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
│   ├── pqc-monitor-web.service # Gunicorn; hardened with NoNewPrivileges etc.
│   ├── pqc-monitor-scheduler.service
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
  └─ HTTPS → nginx → Gunicorn
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

---

## 5. Database Schema

**SQLite file:** `data/pqc_monitor.db` (production: `/opt/pqc-monitor/data/pqc_monitor.db`)  
**Current migration:** v11  
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
| GET | `/api/version` | `{"version":"1.1.3","name":"PQC-Monitor"}` |

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

### Session model

- Flask signed cookies (`itsdangerous` HMAC), 8-hour lifetime
- `SESSION_COOKIE_SECURE = False` by default (plain HTTP safe)
- Set `https_enabled: true` in config.yaml **only** after nginx TLS is working
- 10 failed logins → 15-minute account lockout
- 10 login attempts/IP/minute rate limiting
- Default credentials: `admin` / `changeme123`

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

### 8.6 assessments table has no `service_type` column

Currently a domain maps to one aggregated assessment. The planned multi-resource
model (web, SMTP, etc.) requires the assessments table to carry a `service_type`
or `resource_type` column and the dashboard to aggregate across resources per domain.

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

### 9.4 Config: https_enabled vs cookie_secure

```yaml
# config.yaml — set this ONLY after nginx+TLS is confirmed working
dashboard:
  https_enabled: false   # default; safe for plain HTTP
```

When `https_enabled: true`, `SESSION_COOKIE_SECURE = True` and HSTS headers are sent.
Setting this while serving over plain HTTP causes a login loop (the browser
silently discards Secure cookies over HTTP).

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

---

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

In the UI, DNSDumpster is used via:
- `POST /app/api/dns-enumerate` — the server reads the key from `DNS_ENUM_CONFIG`;
  `use_dnsdumpster` is True only when a key is configured.
- `POST /app/api/save-domains` with `dns_enumerate: true` — same logic.

There is no UI field for the API key; it is a server-side configuration only.
Exposing API keys in the browser would allow any logged-in user to enumerate
arbitrary domains against the operator's paid quota.

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
Add `region` and `country_code` columns to `domain_lists` (migration v12).
Surface region in the domain list editor modal. The RBAC scoping model already
supports domain-list-scoped access — adding region to lists means analysts can
be assigned a regional list (e.g. "EU Finance") and automatically see only
relevant geography. This is the smallest change that enables regional filtering.

**[T1-3] Expiry and certificate age warnings in dashboard**  
The assessments table already stores `cert_expiry_days`. Add a dashboard filter
for "expiring within 30/60/90 days" using the existing card-filter mechanism.
Zero new backend code needed — purely a JS/HTML addition to the dashboard.

**[T1-4] Export roadmap as PDF/DOCX** *(discussed in development session)*  
The `roadmap/generator.py` already has `render_roadmap_text()` and
`render_sector_roadmap_text()`. Add `render_roadmap_docx()` using the existing
`docx` skill. Expose via `GET /api/roadmap/export?format=docx`.

---

### Tier 2 — New columns + existing module extension

**[T2-1] Resource type tagging on assessments** *(requested)*  
Add `service_type` column to `assessments` (migration v12 or v13):
`web_primary`, `web_secondary`, `smtp`, `imap`, `pop3`, `ldap`, `api`, `other`.

This is the prerequisite for the multi-resource domain view and all resource-type
filtering. The orchestrator already probes SMTP/IMAP/LDAP via STARTTLS — the
scan result just needs to carry a `service_type` label. The assessor stores it.

Changes needed:
- Migration: `ALTER TABLE assessments ADD COLUMN service_type TEXT`
- `orchestrator._scan_domain`: derive `service_type` from port number
  (`443→web_primary`, `25/587→smtp`, `993→imap`, etc.)
- `crypto_assessor.assess_domain`: accept and store `service_type`
- `app_routes.api_assessments`: add `?service_type=` filter parameter
- Dashboard: add service-type filter pills above domain table

**[T2-2] Per-domain resource aggregation view** *(requested)*  
Once `service_type` exists, add a domain detail panel that groups all resources
for a domain (web, SMTP, IMAP, LDAP) with a row per service showing its
individual score, TLS version, and findings. Clicking a row drills into the
existing `showDomainDetail()` but scoped to that resource.

Changes needed (backend minimal, mostly dashboard JS):
- `GET /api/domain/<domain>/resources` → list of assessments grouped by service_type
- Dashboard: extend `showDomainDetail()` to show a resource table before the
  findings list

**[T2-3] Geographic coordinates on domain assessments**  
Add `country_code`, `latitude`, `longitude` columns to `assessments`.
Populate from IP geolocation during scan (MaxMind GeoLite2-free, or
ip-api.com — free, no API key required for non-commercial use).

Prerequisite for the map view. The `cdn_detector.py` already resolves IPs —
geolocation is a small addition to the CDN detection step.

Changes needed:
- `requirements.txt`: add `geoip2` or use `requests` to call ip-api.com
- Migration: add three columns to `assessments`
- `scanner/cdn_detector.py` or new `scanner/geo_resolver.py`
- `scanner/orchestrator.py`: call geo resolver after CDN detection

---

### Tier 3 — New modules, moderate complexity

**[T3-1] DNS deep-dive on domain add** *(requested)*  
When a domain is added to a list (or discovered), enumerate all sub-services:
query A/AAAA, MX, NS, CNAME chains, TXT (SPF, DMARC), SRV records. This
produces a list of candidate hosts to probe for TLS. The existing
`service_discovery.py` probes ports but doesn't walk DNS — this adds the DNS
enumeration layer.

New module: `scanner/dns_enumerator.py`

```python
@dataclass
class DnsEnumerationResult:
    domain: str
    a_records: list[str]          # IPv4 addresses
    aaaa_records: list[str]       # IPv6 addresses  
    mx_hosts: list[str]           # mail servers
    ns_hosts: list[str]           # nameservers
    cname_chain: list[str]        # CNAME targets
    spf_record: Optional[str]
    dmarc_record: Optional[str]
    subdomains: list[str]         # from certificate SANs + brute-force wordlist
    tls_candidates: list[dict]    # {host, port, service_type} for scanning
```

Integration points:
- `domain_discovery/domain_finder.py`: call DNS enumeration after NL discovery
- `scanner/orchestrator.py`: call DNS enumeration before port scanning to expand
  the scan target list
- New `domain_extra` data type `dns_enum` to store results
- Admin domain-list editor: show DNS-discovered hosts alongside manually added domains

External tool option: DNSDumpster has an informal API (scraping-based, no key).
More reliable: use `dnspython` (already in requirements) directly. For
subdomain discovery, CT log SANs via crt.sh (already in `ct/ct_monitor.py`)
are a good passive source.

**[T3-2] Geographic map view** *(requested)*  
A choropleth or dot map showing PQC readiness by country. Requires T2-3
(coordinates on assessments) and T1-2 (regions on domain lists).

Recommended approach: Leaflet.js (free, no API key) with GeoJSON country
boundaries. The dashboard already loads Chart.js from CDN — add Leaflet similarly.

New dashboard view `view-map`:
- Choropleth layer: countries coloured by average PQC score (green/yellow/orange/red)
- Dot layer: individual domain markers, click to open domain detail
- Filter panel: by region, service type, readiness level

**[T3-3] SSL Labs integration (discussed in session)**  
Optional enrichment layer: after a primary scan, query the Qualys SSL Labs API
v4 (requires registered email in HTTP header) for the standard A-F grade and
vulnerability flags (ROBOT, POODLE, Heartbleed etc.). SSL Labs does not assess
PQC readiness so this supplements rather than replaces existing scanning.

Key design constraints established in the discussion:
- Must default to OFF (`ssl_labs_api_email:` absent in config)
- Must use `publish=off` parameter
- Results stored in `domain_extra` table (already exists) as type `ssl_labs`
- Async polling (assessments take 60-120s) — store `pending` state, poll later
- Rate-limit compliance: honour `X-Max-Assessments` and `X-Current-Assessments` headers
- Terms of service: only scan domains the operator controls or is authorised to assess

New module: `scanner/ssl_labs_client.py`

---

### Tier 4 — Significant architectural changes

**[T4-1] Multi-resource domain model** *(requested)*  
The full realisation of the "domain as a container of resources" concept.
Currently each domain has one aggregated assessment. The target model:

```
Domain: bancosantander.es
  ├── www.bancosantander.es:443   (web_primary)    score=82  TLSv1.3
  ├── mail.bancosantander.es:25   (smtp)           score=61  TLSv1.2
  ├── owa.bancosantander.es:443   (web_secondary)  score=74  TLSv1.2
  └── ldap.bancosantander.es:636  (ldap)           score=55  TLSv1.2
  Aggregate score: 68 (weighted by service criticality)
```

This requires:
1. T2-1 (service_type column) as prerequisite
2. T3-1 (DNS enumeration) to discover all resources
3. `crypto_assessor.py` aggregate scoring across resources
4. Dashboard domain table: show aggregate score with expand/collapse per resource
5. RBAC: filter by domain still works (all resources for a domain are visible or hidden together)

**[T4-2] Trend alerting and notifications**  
Send email/webhook when a domain's score drops below a threshold or a new
critical finding appears. Requires:
- `alerting/` module: threshold config + email/webhook dispatch
- New `alerts` table in DB
- APScheduler job to check for new findings after each scan
- UI panel in Settings to configure thresholds and notification targets

**[T4-3] SAML / OIDC authentication**  
The `AuthProvider` interface (`auth/middleware.py`) is already designed for this.
Implement `SAMLAuthProvider(AuthProvider)` using `python3-saml` or
`pysaml2`, or `OIDCProvider` using `authlib`. Swap in `app_factory.py`.
The admin user management UI would need to handle externally-authenticated users
(no local password, cannot reset via admin panel).

**[T4-4] Dashboard frontend separation**  
Extract `DASHBOARD_HTML` from `dashboard/app.py` into proper files:
- `static/dashboard.html` (or Jinja2 template in `templates/`)
- `static/dashboard.js`
- `static/dashboard.css`

This is a quality-of-life change for development — no functional difference —
but it makes the JS editable with IDE support, sourcemaps, and proper diffs.
Requires updating `app_routes.dashboard_home()` to use `render_template()`
instead of `render_template_string()`.

---

### Tier 1 additions — Config / data changes only

**[T1-5] Asset Criticality Weighting** *(Tier 1 — High Value / Low-Medium Complexity)*

**Business value:** Currently `assessments` treats `www.bank.es:443` and `intranet-wiki.bank.es:80` identically. CISOs need the roadmap to reflect real business risk. A domain tagged "Critical Payment Gateway" should surface at the top of Phase 1 regardless of its raw score.

**Implementation:**
- Migration: `ALTER TABLE assessments ADD COLUMN criticality TEXT DEFAULT 'normal'` — values: `critical | high | normal | low`.
- Admin UI: add criticality dropdown to the domain detail panel (or a bulk-edit modal).
- `roadmap/generator.py`: multiply phase assignment score threshold by criticality factor (e.g. critical assets enter Phase 1 at a higher score threshold, forcing earlier action).
- Dashboard: add criticality colour indicator column to the domain table; filter pill.
- `GET /api/assessments`: add `?criticality=` filter.

**Code surface:** 3-4 files, ~150 lines, 1 migration. No new modules. Directly unlocks more useful roadmap output.

---

### Tier 2 additions — New modules, high value

**[T2-4] Executive PDF Reporting** *(Tier 2 — High Value / Medium Complexity)*

**Business value:** CISOs present to boards. The current exports (CSV, JSON) are engineer-facing. A one-page PDF that says "42% of critical services are not PQC-ready, deadline BSI 2026" with a traffic-light table eliminates manual PowerPoint work.

**Implementation:**
- New module: `reports/pdf_report.py` using `reportlab` (already commonly available) or `weasyprint` (HTML→PDF, easier to style).
- Template: cover page (org name, date, score summary), executive traffic-light table (domain | criticality | level | expiry), phase summary card, regulatory deadline countdown (BSI 2026, NIST 2030).
- `GET /api/export?format=pdf` route in `app_routes.py`.
- Admin: "Export PDF" button in dashboard toolbar.
- Optional: per-org PDF (filter by org before rendering).

**Dependencies:** `reportlab` or `weasyprint` + `Pillow`. Requires `pdf` skill.

**Code surface:** 1 new module (~250 lines), 1 route addition, dashboard button. No schema change. Medium effort due to layout work; low risk.

**[T2-5] Budget and Resource Estimation Integration** *(Tier 2 — High Value / High Complexity)*

**Business value:** The roadmap already outputs phases and effort-day estimates. The missing step for a CISO is translating "Phase 1: 45-90 days effort" into "€180,000-360,000 at blended day rate" and "3 FTE for 6 months". This makes PQC migration a line item in the budget cycle rather than an abstract security recommendation.

**Implementation:**
- New config block: `budget.day_rate_eur`, `budget.currency`, `budget.fte_days_per_year`.
- `roadmap/generator.py`: add `cost_min_eur`, `cost_max_eur`, `fte_months` to `RoadmapItem` and `DomainRoadmap` dataclasses.
- New `roadmap/budget_estimator.py`: maps task type (cert replacement, TLS config, library upgrade, HSM procurement) to effort multipliers and procurement cost bands.
- `GET /api/roadmap/export?format=budget_csv` — one row per phase, columns: phase, task_type, effort_days, cost_eur_min, cost_eur_max, fte_months, regulatory_deadline.
- Dashboard: add cost column to roadmap table (hidden by default, shown when budget config is set).

**Code surface:** 1 new module (~200 lines), extend `generator.py` (~100 lines), 1 config block, 1 export route, optional dashboard column. Schema: add 3 columns to `roadmaps` table. High complexity in the cost modelling logic; the rest is straightforward.

---

### Tier 3 additions — Medium value

**[T3-4] Sector Benchmarking** *(Tier 3 — Medium Value / Low-Medium Complexity)*

**Business value:** The `scan_runs` table already stores `sector` and `region`. An aggregated benchmarking view lets a CISO say "our average PQC score is 61, the Financial Services EU average is 48 — we are ahead of our peers". This is a powerful justification tool for security investment.

**Implementation:**
- `data/database.py`: new `get_sector_benchmarks()` method — aggregate `AVG(score)`, `SUM(has_pqc)`, level distribution by `(sector, region)` across all scan runs.
- `GET /api/benchmarks` endpoint returning sector aggregates.
- New dashboard view `view-benchmarks`: bar chart (Chart.js, already loaded) of sector averages; highlight the current organisation's position.
- Optional: anonymisation guard — only show benchmark if ≥3 distinct organisations contribute (avoids de-anonymisation in small sectors).

**Note:** Benchmarking is only meaningful when multiple organisations are scanned from the same instance (enterprise/sector-wide deployment). For single-org deployments, this view would be empty or trivial. The feature is most valuable in a managed-service or sector-regulator deployment model.

**Code surface:** 1 new DB method, 1 new route, 1 new dashboard view (~150 lines JS/HTML). No schema change. Low implementation risk; medium strategic value depending on deployment model.

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

**Test count:** 452 (as of v1.3.0)  
**Test files and what they cover:**

| File | Coverage |
|------|---------|
| `test_assessor.py` | Scoring engine, guideline loading, finding generation |
| `test_auth.py` | Full RBAC: permissions, AuthStore CRUD, authentication, endpoint protection, domain list CRUD (69 + 24 tests) |
| `test_ct.py` | CT monitor: OID registry, certificate parsing, DB storage, Flask API endpoints |
| `test_roadmap.py` | Phase assignment, effort calculation, score projection, text rendering, DB storage, API endpoints |
| `test_scan_quality.py` | Chain validator, cipher enum, CDN detector, domain_extra DB |
| `test_scanner.py` | TLS probe, crypto extractor, STARTTLS probe |
| `test_t2_t3_features.py` | T2-1 service_type tagging + T3-1 DNS enumerator (42 tests) |
| `test_orgs_and_dns.py` | Organisation CRUD, user↔org RBAC, admin API, assessment filters, DNSDumpster API key (44 tests) |

---

## Appendix B — Deployment Quick Reference

```bash
# Production install
sudo ./install.sh --production

# Service management
sudo systemctl enable --now pqc-monitor.target
sudo systemctl status pqc-monitor-web
journalctl -u pqc-monitor-web -f
journalctl -u pqc-monitor-scheduler -f

# Config files (do not edit install directory directly)
/etc/pqc-monitor/config.yaml       # app config (perms: 640 root:pqcmonitor)
/etc/pqc-monitor/pqc-monitor.env   # secrets (perms: 640 root:pqcmonitor)

# nginx
sudo cp /opt/pqc-monitor/systemd/nginx-pqc-monitor.conf \
        /etc/nginx/sites-available/pqc-monitor
sudo certbot --nginx -d your.domain.example
sudo systemctl reload nginx

# After update
sudo systemctl stop pqc-monitor.target
sudo ./install.sh --production
sudo systemctl start pqc-monitor.target
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

