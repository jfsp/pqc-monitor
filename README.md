# PQC-Monitor: Post-Quantum Cryptography Readiness Monitor

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![AI-assisted](https://img.shields.io/badge/AI--assisted-Claude%2FAnthropic-purple)](https://anthropic.com)

---

## ⚠️ DISCLAIMER

> **This software was created with the assistance of Artificial Intelligence (Claude by Anthropic).**
> It is provided for informational and research purposes only. No warranties of any kind are made
> regarding accuracy, completeness, or fitness for any purpose.
>
> **NON-INTRUSIVE passive reconnaissance only.** No exploit payloads, no malicious content,
> no denial-of-service. Users must have proper authorisation before scanning any systems.
>
> Automated cryptographic assessments must be reviewed by qualified security professionals
> before making compliance or migration decisions.

---

## Overview

**PQC-Monitor** assesses the cryptographic posture of web services within a sector/region
and tracks readiness for Post-Quantum Cryptography (PQC) migration.

It discovers TLS-enabled services, extracts cryptographic metadata, scores against three
authoritative guidelines, and presents results in an interactive web dashboard with
periodic trend tracking.

---

## Features

| Feature | Details |
|---------|---------|
| Domain Discovery | Natural language → domain list via Anthropic AI or curated offline lists |
| Service Discovery | Non-intrusive TCP-connect; TLS direct + STARTTLS ports |
| TLS Probing | Handshake + X.509 extraction (port 443, 8443, 636 …) |
| STARTTLS | SMTP (25/587), IMAP (143), POP3 (110) upgrade probing |
| Shodan Integration | Passive lookup; auto-fallback to direct scanning |
| Crypto Assessment | 0–100 score against NIST SP 800-131Ar3, BSI TR-02102-1, CCN-STIC-221 |
| PQC Detection | Detects ML-KEM, ML-DSA, Kyber, Dilithium in TLS negotiation |
| DANE / DNSSEC | Records TLSA and DNSKEY presence |
| Dashboard | Flask web UI — distribution, TLS coverage, domain table, trends |
| Trend Tracking | SQLite-backed; per-domain history charts |
| Export | CSV, JSON envelope, plain-text report |
| Guideline Versioning | JSON rule files; re-assess old scans when rules change |
| Scheduling | APScheduler periodic scans (default 90-day interval) |

---

## Architecture

```
pqc-monitor/
├── pqc_monitor.py              # CLI (click) — 9 commands
├── scanner/
│   ├── service_discovery.py    # TCP-connect + DANE/DNSSEC
│   ├── tls_probe.py            # TLS handshake & certificate extraction
│   ├── starttls_probe.py       # SMTP/IMAP/POP3 STARTTLS upgrade
│   ├── shodan_client.py        # Shodan API wrapper (optional)
│   ├── crypto_extractor.py     # Raw scans → normalised CryptoFacts
│   ├── crypto_assessor.py      # Multi-guideline scoring engine
│   └── orchestrator.py         # Parallel scan coordinator
├── domain_discovery/
│   └── domain_finder.py        # NL → domain list (AI + offline fallback)
├── guidelines/                 # Versioned JSON policy rules
│   ├── nist_800_131a.json      # NIST SP 800-131Ar3 (Oct 2024)
│   ├── bsi_tr02102.json        # BSI TR-02102-1 (2026-01)
│   └── ccn_stic_221.json       # CCN-STIC-221 (2023)
├── dashboard/
│   └── app.py                  # Flask REST API + embedded dashboard UI
├── reports/
│   └── report_generator.py     # CSV / JSON / plain-text export
├── data/
│   ├── database.py             # SQLite storage layer
│   ├── migrations.py           # Incremental schema versioning
│   ├── scans/                  # Optional raw scan JSON output
│   └── trends/                 # Optional trend exports
├── scheduler/
│   └── scan_scheduler.py       # APScheduler periodic scans
├── tests/
│   ├── test_assessor.py        # 33 tests — scoring, DB, guidelines
│   ├── test_scanner.py         # 60 tests — extraction, probes, reports
│   └── seed_demo_data.py       # Synthetic data seeder
├── config/config.yaml.example
├── install.sh
├── Dockerfile + docker-compose.yml
├── CONTRIBUTING.md
└── CHANGELOG.md
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

## Guidelines

| ID | Name | Version | Source |
|----|------|---------|--------|
| `nist_800_131a` | NIST SP 800-131Ar3 | Oct 2024 IPD | [doi.org/10.6028/NIST.SP.800-131Ar3.ipd](https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd) |
| `bsi_tr02102` | BSI TR-02102-1 | 2026-01 | [bsi.bund.de/TG02102](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf) |
| `ccn_stic_221` | CCN-STIC-221 | 2023 | [ccn-cert.cni.es](https://www.ccn-cert.cni.es) |

---

## Installation

**Requirements:** Python 3.10+, Linux (Ubuntu 22.04+ recommended)

```bash
git clone https://github.com/your-org/pqc-monitor.git
cd pqc-monitor
chmod +x install.sh && ./install.sh          # basic install
./install.sh --venv --demo                   # virtualenv + seed demo data
```

**Docker:**
```bash
docker-compose up -d     # dashboard at http://localhost:5000
```

---

## Quick Start

```bash
# 1. Discover domains
python3 pqc_monitor.py discover "financial institutions in Spain" -o domains.txt

# 2. Scan
python3 pqc_monitor.py scan --domains domains.txt --sector finance --region Spain

# 3. Dashboard
python3 pqc_monitor.py dashboard          # open http://localhost:5000

# 4. Export / report
python3 pqc_monitor.py export --format csv -o results.csv
python3 pqc_monitor.py report -o report-Q1.txt

# 5. Schedule quarterly scans
python3 pqc_monitor.py schedule --domains domains.txt --interval 90d --name "Spain Finance"

# 6. Re-assess after guideline update (no re-scanning)
python3 pqc_monitor.py list-runs
python3 pqc_monitor.py reassess <run_id>
```

---

## Configuration (`config/config.yaml`)

```yaml
shodan:
  api_key: ""           # or set SHODAN_API_KEY env var

scanning:
  timeout: 10
  max_workers: 20
  ports: [443, 8443, 465, 993, 636]
  use_starttls: true

dashboard:
  host: "127.0.0.1"
  port: 5000

scheduler:
  default_interval_days: 90

ai:
  anthropic_api_key: "" # or set ANTHROPIC_API_KEY env var
  model: "claude-sonnet-4-20250514"

guidelines:
  active: [nist_800_131a, bsi_tr02102, ccn_stic_221]
```

---

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
# 93 tests in ~2 seconds
```

---

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). See [CHANGELOG.md](CHANGELOG.md) for history.

---

*AI-assisted development notice: substantial portions generated with Claude (Anthropic).
All code reviewed and provided under GPL-3.0-or-later.*
