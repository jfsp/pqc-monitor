# Changelog

All notable changes to PQC-Monitor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**Certificate Transparency Monitor** (`ct/ct_monitor.py`)
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

[Unreleased]: https://github.com/your-org/pqc-monitor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/pqc-monitor/releases/tag/v1.0.0
