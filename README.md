# PQC-Monitor v1.1.0

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
- Role-based web interface: **Admin** and **Analyst** roles with domain-list scoping
- Periodic scan scheduling with trend tracking

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
├── pqc_monitor.py              # CLI entry point (10 commands)
├── app_factory.py              # Flask application factory (RBAC-enabled)
├── app_routes.py               # Analyst /app/* blueprint
│
├── auth/                       # Authentication & authorisation
│   ├── models.py               # User, AuditEvent dataclasses; role constants
│   ├── store.py                # SQLite user store, password hashing, audit log
│   ├── middleware.py           # Flask decorators, session helpers, AuthProvider
│   └── auth_routes.py          # /login, /logout, /change-password
│
├── admin/
│   └── routes.py               # /admin/* — user/domain-list management SPA
│
├── scanner/                    # Scanning engine
│   ├── orchestrator.py         # Parallel scan coordinator
│   ├── service_discovery.py    # TCP-connect port discovery + DANE/DNSSEC
│   ├── tls_probe.py            # TLS handshake & certificate extraction
│   ├── starttls_probe.py       # SMTP/IMAP/POP3 STARTTLS upgrade
│   ├── chain_validator.py      # Full certificate chain analysis
│   ├── cipher_enum.py          # Active cipher suite enumeration
│   ├── cdn_detector.py         # CDN detection (Cloudflare, Fastly, Akamai …)
│   ├── crypto_assessor.py      # Multi-guideline scoring engine
│   ├── crypto_extractor.py     # Raw scan → normalised CryptoFacts
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
│   └── migrations.py           # Incremental schema versioning
│
├── scheduler/
│   └── scan_scheduler.py       # APScheduler periodic scan management
│
├── reports/
│   └── report_generator.py     # CSV / JSON / plain-text export
│
├── guidelines/                 # Versioned cryptographic policy rules (JSON)
│   ├── nist_800_131a.json      # NIST SP 800-131Ar3 (Oct 2024)
│   ├── bsi_tr02102.json        # BSI TR-02102-1 (2026-01)
│   └── ccn_stic_221.json       # CCN-STIC-221 (2023)
│
├── systemd/                    # Systemd deployment files
│   ├── pqc-monitor.target      # Service group target
│   ├── pqc-monitor-web.service # Gunicorn web service
│   ├── pqc-monitor-scheduler.service  # APScheduler daemon
│   ├── pqc-monitor.env         # Environment file template
│   └── nginx-pqc-monitor.conf  # Sample nginx reverse proxy config
│
├── tests/                      # 340 unit tests
└── config/
    └── config.yaml.example     # Annotated configuration template
```

---

## Version

The version is stored in the `VERSION` file at the project root. It is the
single source of truth — all other components read from it:

```
cat VERSION         # 1.1.0
```

```python
from version import VERSION   # "1.1.0"
```

The version appears in:
- The browser UI (header bar, footer, Settings → About)
- The login page footer
- The admin panel header
- `pqc_monitor.py --version`
- `GET /api/version` → `{"version": "1.1.0", "name": "PQC-Monitor"}`

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
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Python | 3.10 | 3.12 |
| RAM | 512 MB | 2 GB |
| Disk | 1 GB | 10 GB (for scan data) |
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
| `pqc-monitor-scheduler.service` | APScheduler periodic scan daemon |

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
  path: "/opt/pqc-monitor/data/pqc_monitor.db"

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
> the admin panel → Edit user → Reset password.

---

## Configuration

Full annotated example at `config/config.yaml.example`.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `database.path` | `data/pqc_monitor.db` | SQLite database path |
| `scanning.timeout` | `10` | Seconds per connection attempt |
| `scanning.max_workers` | `20` | Parallel scan threads |
| `scanning.ports` | `[443,8443,465,993,636]` | TLS ports to probe |
| `scheduler.default_interval_days` | `90` | Default scan interval |
| `guidelines.active` | all three | Which guideline files to apply |

Environment variables override config file values:

| Variable | Config equivalent |
|----------|------------------|
| `PQC_SECRET_KEY` | `dashboard.secret_key` |
| `SHODAN_API_KEY` | `shodan.api_key` |
| `ANTHROPIC_API_KEY` | `ai.anthropic_api_key` |

---

## Web Interface

The web interface is served at the root URL. After login, two areas are accessible
depending on role:

### `/app` — Main Dashboard (all authenticated users)

| Tab | Description |
|-----|-------------|
| Dashboard | Summary cards, distribution chart, TLS coverage, domain table |
| Domain Discovery | Natural-language domain list generation |
| Scan | Manual scan, re-assessment, scan history |
| Trends | Score over time, level changes, PQC adoption, per-domain history |
| CT Monitor | Certificate Transparency log monitoring |
| Roadmap | PQC migration plan generator |
| Settings | Guidelines, scoring guide, version information |

Analysts see only domains from their assigned domain lists. Admins see all domains.

### `/admin` — Administration (Admin role only)

| Section | Description |
|---------|-------------|
| Users | Create, edit, disable, delete users; reset passwords |
| Domain Lists | View all lists; see which users are assigned |
| Audit Log | Login/logout events, data access, scan initiations |

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
| `list-schedules` | List configured periodic schedules |

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

# 5. Verify
sudo systemctl status pqc-monitor-web
journalctl -u pqc-monitor-web -n 20
```

The installer preserves `/etc/pqc-monitor/config.yaml` and
`/etc/pqc-monitor/pqc-monitor.env`. Database migrations run automatically
on first startup after an update.

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

340 tests covering: scoring engine, database layer, guidelines JSON, scanner
modules, CDN detection, certificate chain validation, cipher enumeration,
CT monitor, roadmap generator, and the full RBAC auth layer.

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

---

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). See [CHANGELOG.md](CHANGELOG.md) for version history.

---

*AI-assisted development notice: substantial portions of this codebase were generated with
the assistance of Claude (Anthropic). All code reviewed and provided under GPL-3.0-or-later.*
