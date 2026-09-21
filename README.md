# PQC-Monitor v1.12.0

**Post-Quantum Cryptography Readiness Monitor**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![AI-assisted](https://img.shields.io/badge/AI--assisted-Claude%2FAnthropic-purple)](https://anthropic.com)

---

## ⚠️ Disclaimer

> **This software was created with the assistance of Artificial Intelligence (Claude by Anthropic).**
> For informational and research purposes only. No warranties of any kind.
>
> **NON-INTRUSIVE passive reconnaissance only.** No exploit payloads, no malicious content,
> no denial-of-service. Users must have proper authorisation before scanning any systems.
>
> Automated assessments must be reviewed by qualified security professionals before making
> compliance or migration decisions.

---

## Overview

PQC-Monitor assesses the cryptographic posture of web services within a sector and region,
tracking readiness for Post-Quantum Cryptography (PQC) migration. It provides:

- TLS/certificate discovery and analysis across a list of domains
- Scoring against NIST SP 800-131Ar3, BSI TR-02102-1, and CCN-STIC-221
- Certificate Transparency log monitoring for PQC certificate deployments
- PQC migration roadmap generation with phased action plans
- Role-based web interface: **Admin**, **Community Manager** and **Analyst** roles,
  with domain-list and community scoping
- Periodic scan scheduling with time-based trend tracking: a monthly scan of
  all TLS-serving domains, a monthly rescan of no-TLS domains that still
  resolve in DNS (names that no longer resolve are recorded and skipped), and
  a weekly throttled Qualys SSL Labs sweep
- Per-domain detail screen with findings, recommendations, full TLS details and
  the migration action plan, linkable as `#domain/<name>`

---

## Contents

- [Architecture](#architecture)
- [Version](#version)
- [Quick Start — Development](#quick-start--development)
- [Production Deployment](#production-deployment)
  - [System Requirements](#system-requirements)
  - [Installation](#installation)
  - [Systemd Services](#systemd-services)
  - [Reverse Proxy (nginx)](#reverse-proxy-nginx)
  - [First Login](#first-login)
- [Configuration](#configuration)
- [Web Interface](#web-interface)
- [Scheduled Jobs](#scheduled-jobs)
- [CLI Reference](#cli-reference)
- [Role-Based Access Control](#role-based-access-control)
- [Updating](#updating)
- [Running Tests](#running-tests)
- [Guidelines](#guidelines)
- [License](#license)

---

## Architecture

```
pqc-monitor/
├── VERSION                     # Single source of truth for version string
├── version.py                  # Python version module (reads VERSION)
├── pqc_monitor.py              # CLI entry point (13 commands + `community` group)
├── app_factory.py              # Flask application factory (RBAC, CSRF, mailer wiring)
├── app_routes.py               # Analyst / community-manager /app/* blueprint
├── install.sh                  # Installer: --demo (dev) / --production
├── Dockerfile                  # Container image (development convenience)
├── docker-compose.yml          # Compose stack for local runs
│
├── auth/                       # Authentication & authorisation
│   ├── models.py               # User, AuditEvent dataclasses; role/permission constants
│   ├── store.py                # SQLite user store, password hashing, reset tokens, audit log
│   ├── middleware.py           # Flask decorators, session helpers, AuthProvider
│   ├── auth_routes.py          # /login, /logout, /change-password, /forgot, /reset/<token>
│   ├── mailer.py               # Optional SMTP mailer (local MTA or authenticated relay)
│   └── csrf.py                 # Synchroniser token + same-origin guard for the JSON API
│
├── admin/
│   └── routes.py               # /admin/* — users, domain lists, orgs, communities, audit
│
├── scanner/                    # Scanning engine
│   ├── orchestrator.py         # Parallel scan coordinator
│   ├── service_discovery.py    # TCP-connect port discovery + DANE/DNSSEC
│   ├── tls_probe.py            # TLS handshake & certificate extraction
│   ├── starttls_probe.py       # SMTP/IMAP/POP3 STARTTLS upgrade (protocol-based dispatch)
│   ├── chain_validator.py      # Full certificate chain analysis
│   ├── cipher_enum.py          # Active cipher suite enumeration
│   ├── group_enum.py           # Offered key-exchange group enumeration (authoritative for PQC)
│   ├── dns_enumerator.py       # CT SANs + wordlist + DNSDumpster + passive DNS fallback
│   ├── cdn_detector.py         # CDN detection (Cloudflare, Fastly, Akamai …)
│   ├── crypto_assessor.py      # Multi-guideline scoring engine
│   ├── crypto_extractor.py     # Raw scan → normalised CryptoFacts
│   ├── ssllabs_client.py       # Qualys SSL Labs API v4 client (display-only grade)
│   ├── ssllabs_sweep.py        # Throttled SSL Labs collection job (weekly schedule)
│   ├── dns_status.py           # DNS presence check for no-TLS domains
│   └── shodan_client.py        # Optional Shodan API wrapper
│
├── ct/
│   └── ct_monitor.py           # Certificate Transparency log monitor
│
├── roadmap/
│   └── generator.py            # PQC migration roadmap generator
│
├── domain_discovery/
│   └── domain_finder.py        # NL → domain list (AI + offline)
│
├── dashboard/
│   └── app.py                  # Embedded dashboard HTML/JS (version-templated)
│
├── data/
│   ├── database.py             # SQLite storage layer
│   ├── migrations.py           # Incremental schema versioning (current: v18)
│   ├── trends.py               # Time-bucketed trend aggregation (Trends tab)
│   ├── geo_inference.py        # TLD-based country/region inference
│   └── tld_geo.csv             # ccTLD → country_code/country/region mapping
│
├── scheduler/
│   ├── scan_scheduler.py       # DB-driven scheduler (scheduled_scans.next_run, 60 s tick)
│   └── schedule_audit.py       # Coverage audit + auto schedules (scan, no-TLS rescan, SSL Labs)
│
├── reports/
│   ├── report_generator.py     # CSV / JSON / plain-text export
│   └── community_report.py     # Group Report build / CSV / PDF (weasyprint)
│
├── scripts/                    # Operational scripts — see scripts/README.md
│
├── guidelines/                 # Versioned cryptographic policy rules (JSON)
│   ├── nist_800_131a.json      # NIST SP 800-131Ar3 (Oct 2024)
│   ├── bsi_tr02102.json        # BSI TR-02102-1 (2026-01)
│   └── ccn_stic_221.json       # CCN-STIC-221 (2023)
│
├── systemd/                    # Systemd deployment files
│   ├── pqc-monitor.target      # Service group target
│   ├── pqc-monitor-web.service # Gunicorn web service
│   ├── pqc-monitor-scheduler.service  # Scheduler daemon (Wants= the web service)
│   ├── pqc-monitor.env         # Environment file template
│   └── nginx-pqc-monitor.conf  # Sample nginx reverse proxy config
│
├── docs/                       # DATABASE.md, historical handovers, presentation
├── tests/                      # 597 unit tests
└── config/
    └── config.yaml.example     # Annotated configuration template
```

---

## Version

The version is stored in the `VERSION` file at the project root. It is the
single source of truth — all other components read from it:

```
cat VERSION         # 1.12.0
```

```python
from version import VERSION   # "1.12.0"
```

The version appears in:
- The browser UI (header bar, footer, Settings → About)
- The login page footer
- The admin panel header
- `pqc_monitor.py --version`
- `GET /api/version` → `{"version": "1.12.0", "name": "PQC-Monitor"}`

To release a new version, update `VERSION` and add a CHANGELOG entry.
No other source files need editing.

---

## Quick Start — Development

```bash
git clone https://github.com/your-org/pqc-monitor.git
cd pqc-monitor
./install.sh --demo          # creates .venv, installs deps, seeds demo data

source .venv/bin/activate
python3 pqc_monitor.py dashboard
# Open http://localhost:5000
# Login: admin / changeme123
```

---

## Production Deployment

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 13 (trixie) or Ubuntu 22.04 LTS | Debian 13 (trixie) or Ubuntu 24.04 LTS |
| Python | 3.10 | 3.12 |
| RAM | 512 MB | 2 GB |
| Disk | 1 GB | 10 GB (for scan data over large periods of time) |
| CPU | 1 core | 2–4 cores |
| Network | Outbound TCP 443/80 | Outbound unrestricted |

The web service and scheduler run as a dedicated non-privileged system user
(`pqcmonitor`). A reverse proxy (nginx or Caddy) handles TLS termination.

### Installation

```bash
# 1. Clone or copy the project to the server
git clone https://github.com/your-org/pqc-monitor.git
cd pqc-monitor

# 2. Run the production installer (requires root)
sudo ./install.sh --production

# This will:
#   - Create the pqcmonitor system user
#   - Install files to /opt/pqc-monitor
#   - Create a Python venv at /opt/pqc-monitor/.venv
#   - Install systemd units
#   - Generate a random PQC_SECRET_KEY
#   - Create /etc/pqc-monitor/config.yaml and pqc-monitor.env
```

### Systemd Services

Three units are installed:

| Unit | Purpose |
|------|---------|
| `pqc-monitor.target` | Service group — manages both services together |
| `pqc-monitor-web.service` | Gunicorn WSGI server (Flask app) |
| `pqc-monitor-scheduler.service` | Scheduler daemon: runs the jobs in `scheduled_scans` (scans, SSL Labs sweep) |

```bash
# Start everything
sudo systemctl enable --now pqc-monitor.target

# Check status
sudo systemctl status pqc-monitor-web
sudo systemctl status pqc-monitor-scheduler

# Follow logs
journalctl -u pqc-monitor-web -f
journalctl -u pqc-monitor-scheduler -f

# Restart after a config change
sudo systemctl restart pqc-monitor-web

# Stop everything
sudo systemctl stop pqc-monitor.target
```

The web service and scheduler are independent. A scan initiated by the
scheduler will never block a user's web request — they run in separate processes.
The scheduler unit only `Wants=` the web unit, so restarting the web service
does not restart the scheduler or interrupt a running scheduled scan.

After the first start, create the automatic schedules once:

```bash
sudo -u pqcmonitor /opt/pqc-monitor/.venv/bin/python3 \
    /opt/pqc-monitor/scripts/schedule_audit.py --create-monthly --refresh-dns
```

See [Scheduled Jobs](#scheduled-jobs).

### Reverse Proxy (nginx)

The web service binds to `127.0.0.1:5000` by default. Put nginx (or Caddy) in
front for TLS termination:

```bash
sudo cp /opt/pqc-monitor/systemd/nginx-pqc-monitor.conf \
        /etc/nginx/sites-available/pqc-monitor
sudo ln -s /etc/nginx/sites-available/pqc-monitor \
           /etc/nginx/sites-enabled/pqc-monitor

# Edit the config to set your domain and certificate paths
sudo nano /etc/nginx/sites-available/pqc-monitor

# Get a free TLS certificate
sudo certbot --nginx -d your.domain.example

sudo nginx -t && sudo systemctl reload nginx
```

The sample config at `systemd/nginx-pqc-monitor.conf` configures:
- HTTP → HTTPS redirect
- TLS 1.2/1.3 with modern cipher suites
- HSTS with 2-year max-age
- Security headers
- Upstream proxy to Gunicorn with 120-second timeout for scan API calls

### Environment Configuration

Edit `/etc/pqc-monitor/pqc-monitor.env` (permissions: `640`, owner `root:pqcmonitor`):

```bash
# Secret key for session signing (auto-generated during install)
PQC_SECRET_KEY=<64-char hex string — change if compromised>

# Gunicorn bind address
PQC_BIND=127.0.0.1:5000

# Worker count: (2 × CPU cores) + 1
PQC_WEB_WORKERS=3

# Optional: Shodan API key for passive scanning
SHODAN_API_KEY=

# Optional: Anthropic API key for AI domain discovery
ANTHROPIC_API_KEY=
```

### Application Configuration

Edit `/etc/pqc-monitor/config.yaml`:

```yaml
database:
  path: "/var/lib/pqc-monitor/pqc_monitor.db"

scanning:
  timeout: 10
  max_workers: 20

dashboard:
  host: "127.0.0.1"
  port: 5000

logging:
  level: INFO
  file: "/var/log/pqc-monitor/pqc-monitor.log"
```

### First Login

After starting the services, navigate to `https://your.domain.example`.

**Default credentials:** `admin` / `changeme123`

> ⚠️ **Change this immediately.** Click your username → *Password* or use
> the admin panel → Edit user → Reset password (optionally forcing a change at
> next login). If the optional mailer is configured, users can also reset their
> own password from the **Forgot password?** link on the login page.

---

## Configuration

Full annotated example at `config/config.yaml.example`.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `database.path` | `data/pqc_monitor.db` | SQLite database path |
| `scanning.timeout` | `10` | Seconds per connection attempt |
| `scanning.max_workers` | `20` | Parallel scan threads |
| `scanning.ports` | `[443,8443,465,993,995,636,5061]` | Direct-TLS ports to probe |
| `scanning.use_starttls` | `true` | Also probe STARTTLS ports (25/587/2525/143/110) |
| `scheduler.default_interval_days` | `90` | Present in the example config but not currently read; the auto schedules default to 30 days (`schedule_audit.py --interval-days`) and `schedule --interval` sets its own |
| `guidelines.active` | all three | Which guideline files to apply |
| `mail.enabled` | `false` | Optional SMTP mailer (password-reset emails) |
| `mail.mode` | `local` | `local` (local MTA) or `relay` (authenticated submission) |
| `reset.token_ttl_minutes` | `45` | Password-reset token lifetime |
| `reset.base_url` | — | Absolute base URL used to build reset links |
| `ssllabs.enabled` / `ssllabs.email` | — | Qualys SSL Labs API v4 (registered email) |
| `ssllabs.sweep_concurrency` | `6` | Max parallel SSL Labs assessments in the sweep (also capped by the account limit SSL Labs reports) |
| `ssllabs.sweep_max_age_days` | `6` | Hosts with an SSL Labs result newer than this are skipped |

Environment variables override config file values:

| Variable | Config equivalent |
|----------|------------------|
| `PQC_SECRET_KEY` | `dashboard.secret_key` |
| `SHODAN_API_KEY` | `shodan.api_key` |
| `ANTHROPIC_API_KEY` | `ai.anthropic_api_key` |
| `PQC_MAIL_PASSWORD` | `mail.relay_password` (preferred; never commit to yaml) |
| `PQC_SSLLABS_EMAIL` | `ssllabs.email` |

---

## Web Interface

The web interface is served at the root URL. After login, two areas are accessible
depending on role:

### `/app` — Main Dashboard (all authenticated users)

| Tab | Description |
|-----|-------------|
| Dashboard | Summary cards, distribution chart, TLS coverage, domain table. No-TLS domains that no longer resolve in DNS are labelled "No DNS". Clicking a domain opens its detail screen |
| Group Report | By Community / Region / Country aggregates, charts, CSV+PDF export (admin + community manager) |
| Domain Discovery | Natural-language domain list generation |
| Scan | Manual scan, re-assessment, scan history (with source — scheduled / manual — and domain count) |
| Trends | Time-based trends (day/week/month/quarter, auto from schedule cadence): average score + domains monitored, readiness level share, PQC adoption; snapshot or scan-activity view; scope by organisation/community; per-domain history |
| CT Monitor | Certificate Transparency log monitoring |
| Roadmap | PQC migration plan generator |
| Settings | Guidelines, scoring guide, version information |

Analysts see only domains from their assigned domain lists. Admins see all domains.

**Domain detail screen.** Clicking a domain on the Dashboard or Roadmap tab
opens a full page with the score summary, all findings with their
recommendations, the full TLS details (protocols, ports, offered key-exchange
groups, accepted cipher suites, certificate chain, SSL Labs grade) and the
migration action plan. It has its own URL (`/app/#domain/example.com`, which
can be bookmarked and survives the login redirect), a searchable box to switch
to another domain, and a Back button that returns to the previous tab with its
filters and scroll position.

### `/admin` — Administration (Admin role only)

| Section | Description |
|---------|-------------|
| Users | Create, edit, disable, delete users; reset passwords (optionally forcing a change at next login) |
| Domain Lists | View all lists; see which users are assigned |
| Organisations | Create, edit, delete organisations; sector/region/country metadata |
| Communities | Create, edit, delete communities; assign organisations and community managers |
| Audit Log | Login/logout events, data access, scan initiations |

---

## Scheduled Jobs

The scheduler daemon reads the `scheduled_scans` table every minute and starts
any enabled job whose `next_run` has passed. `next_run` is the source of
truth: restarts do not reset the cadence, jobs that fell due while the daemon
was down run when it starts, and schedule changes take effect without a
restart. After each run `next_run` is set to the run's start time plus the
interval.

`scripts/schedule_audit.py --create-monthly` creates and maintains three
automatic schedules:

| Schedule | Interval | What it does |
|----------|----------|--------------|
| All Domains — monthly (auto) | 30 days | Scans every domain whose latest assessment found a TLS service |
| No-TLS Domains — monthly rescan (auto) | 30 days | Checks every no-TLS domain in DNS; rescans those that still resolve, so services that come online are detected. Names with no DNS entry or no A/AAAA record are recorded ("No DNS") with the date first seen and are not scanned; they are re-checked each month |
| SSL Labs sweep — weekly (auto) | 7 days | Collects Qualys SSL Labs results for TLS-serving HTTPS domains without a recent result, staying within the limits SSL Labs sets for your account and backing off when rate-limited |

Both domain lists are rebuilt right before each run, so newly added domains
are always included. Scheduled runs are marked `Scheduled #<id>` in Scan
History. SSL Labs is not contacted during scans; the grade is display-only and
does not affect the PQC score.

```bash
python3 pqc_monitor.py list-schedules                        # kind, next and last run
python3 scripts/schedule_audit.py                            # read-only coverage audit
python3 scripts/schedule_audit.py --create-monthly --dry-run
python3 scripts/schedule_audit.py --create-monthly --refresh-dns
python3 pqc_monitor.py ssllabs-sweep --dry-run               # pending hosts + account limits
```

---

## CLI Reference

```
python3 pqc_monitor.py --version
python3 pqc_monitor.py --help
```

| Command | Description |
|---------|-------------|
| `discover` | Generate domain list from natural-language query |
| `scan` | Scan domains for cryptographic posture |
| `dashboard` | Launch the web dashboard |
| `scheduler-daemon` | Run the periodic scan daemon (used by systemd) |
| `schedule` | Add a periodic scan schedule |
| `reassess` | Re-score existing scan data against updated guidelines |
| `ct-monitor` | Query CT logs for PQC certificate deployments |
| `roadmap` | Generate PQC migration roadmap |
| `export` | Export results to CSV, JSON, or text |
| `report` | Generate a full text readiness report |
| `list-runs` | List recent scan runs |
| `list-schedules` | List configured schedules (kind, next and last run) |
| `ssllabs-sweep` | Run the throttled SSL Labs sweep now (normally weekly via the scheduler) |
| `community` | Command group: `create`, `list`, `add-org`, `remove-org`, `assign-user`, `report`, `region-report` |

```bash
# Examples
python3 pqc_monitor.py discover "financial institutions in Spain" -o domains.txt
python3 pqc_monitor.py scan --domains domains.txt --sector finance --region Spain
python3 pqc_monitor.py roadmap --format text
python3 pqc_monitor.py export --format csv -o results.csv
python3 pqc_monitor.py ct-monitor --domain example.com --fetch-pem
```

---

## Role-Based Access Control

### Roles

| Role | Capabilities |
|------|-------------|
| **Admin** | Full access: manage users, view all domains, run scans, access admin panel, view audit log |
| **Community Manager** | Group Report for assigned communities and organisations only; cannot scan or manage users |
| **Analyst** | Read-only access to assigned domain lists only |

### Domain-list scoping

Analysts are assigned one or more **domain lists** by an admin. They can only see
assessment data, CT results, roadmaps, and reports for domains in those lists.

Assignment workflow:
1. Admin creates domain lists (via Scanner → Scan → Save List, or CLI `discover`)
2. Admin navigates to `/admin` → Users → Edit → Assigned Domain Lists
3. Analyst logs in and sees only their scoped data

### Session security

- Sessions are signed cookies (HMAC-SHA256 via Flask/itsdangerous)
- 8-hour session lifetime; HttpOnly + SameSite=Lax flags
- Secure flag enabled in production (requires HTTPS)
- 10 failed login attempts → 15-minute account lockout
- 10 login attempts per IP per minute rate limit
- `dashboard.secret_key` hard-fails at startup in production instead of falling
  back to a per-process random value (which breaks multi-worker Gunicorn)
- CSRF protection app-wide: synchroniser token on the server-rendered auth
  forms plus a strict same-origin check on the JSON API
- Changing or resetting a password bumps `users.session_epoch`, which signs out
  every other session immediately

### Password reset and forced change

- **Self-service:** `/forgot` → emailed link → `/reset/<token>`. Tokens are
  single-use, SHA-256-hashed at rest and expire (default 45 minutes); creating a
  new one invalidates outstanding tokens. Responses are identical whether or not
  the account exists; per-IP rate limited; every event audited; reset never
  auto-logs-in. Requires the optional mailer (`mail.enabled`) — without it,
  admin-mediated reset still works.
- **Forced change:** an admin reset may set `must_change_password`, pinning the
  user to `/change-password` until a new password is set.

### SAML / External IdP (future)

The auth layer uses an `AuthProvider` interface. To add SAML or OIDC:

1. Implement `class SAMLAuthProvider(AuthProvider)` in `auth/middleware.py`
2. In `app_factory.py`, replace `LocalAuthProvider(store)` with your provider
3. No route code needs to change

---

## Updating

```bash
# 1. Stop services
sudo systemctl stop pqc-monitor.target

# 2. Update code
cd /path/to/pqc-monitor-source
git pull

# 3. Re-run production installer (preserves config and database)
sudo ./install.sh --production

# 4. Restart services
sudo systemctl start pqc-monitor.target

# 4a. When upgrading to 1.12.0: create the new automatic schedules once
sudo -u pqcmonitor /opt/pqc-monitor/.venv/bin/python3 \
    /opt/pqc-monitor/scripts/schedule_audit.py --create-monthly --refresh-dns

# 5. Verify
sudo systemctl status pqc-monitor-web
journalctl -u pqc-monitor-web -n 20
```

The installer preserves `/etc/pqc-monitor/config.yaml` and
`/etc/pqc-monitor/pqc-monitor.env`. Database migrations run automatically
on first startup after an update. If you deploy with `scripts/deploy.sh`
instead of the installer, copy changed files from `systemd/` to
`/etc/systemd/system/` and run `systemctl daemon-reload` yourself — the deploy
script does not install unit files.

---

## Running Tests

```bash
# Development
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_*.py' -v

# Production
sudo -u pqcmonitor /opt/pqc-monitor/.venv/bin/python3 \
    -m unittest discover -s /opt/pqc-monitor/tests -p 'test_*.py'
```

597 tests covering: scoring engine, database layer, guidelines JSON, scanner
modules, CDN detection, certificate chain validation, cipher enumeration,
STARTTLS/MX handling, SSL Labs client and sweep, scheduler, DNS status of
no-TLS domains, trends, CT monitor, roadmap generator,
communities/organisations, and the RBAC auth layer.

---

## Guidelines

| ID | Name | Version | Source |
|----|------|---------|--------|
| `nist_800_131a` | NIST SP 800-131Ar3 | Oct 2024 IPD | [doi.org/10.6028/NIST.SP.800-131Ar3.ipd](https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd) |
| `bsi_tr02102` | BSI TR-02102-1 | 2026-01 | [bsi.bund.de/TG02102](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf) |
| `ccn_stic_221` | CCN-STIC-221 | 2023 | [ccn-cert.cni.es](https://www.ccn-cert.cni.es) |

When a guideline is updated: edit the JSON file, then re-assess existing scans
without rescanning:

```bash
python3 pqc_monitor.py reassess <run_id>
# or: Dashboard → Scan tab → Re-Assessment panel
```

---

## PQC Readiness Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🔴 Critical | 0–25 | Broken/deprecated: RC4, DES, MD5, RSA-1024, SHA-1 certs |
| 🟠 Weak | 26–50 | Below recommended minimums; no PQC |
| 🟡 Moderate | 51–75 | Good classical crypto (TLS 1.3, ECDHE, SHA-256); no PQC yet |
| 🟢 Ready | 76–100 | PQC detected (ML-KEM, ML-DSA) or transition complete |
| ⚪ N/A (`na`) | — | No reachable TLS service; excluded from averages, level counts, roadmaps and the main monthly scan. Rescanned monthly if the name still resolves; shown as "No DNS" and not scanned if it does not |

---

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). See [CHANGELOG.md](CHANGELOG.md) for version history.

---

*AI-assisted development notice: substantial portions of this codebase were generated with
the assistance of Claude (Anthropic). All code reviewed and provided under GPL-3.0-or-later.*
