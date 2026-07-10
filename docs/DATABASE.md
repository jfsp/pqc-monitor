# PQC-Monitor — Database Reference & Operational Guide

SQLite database. On production it lives at
`/var/lib/pqc-monitor/pqc_monitor.db` (never in git). The path is resolved
from `db_path` in `config/config.yaml`; the loader default is
`data/pqc_monitor.db` for local runs.

All timestamps are ISO-8601 UTC strings (e.g. `2026-07-10T08:53:54.927558+00:00`),
**not** SQLite datetimes — compare them lexicographically or with
`substr(...)`, not with `date()`/`julianday()` unless you slice to a valid
prefix first. Booleans are stored as INTEGER `0`/`1`. Several columns hold
JSON as TEXT (suffix `_json`, plus `raw_json`, `domains_json`, `items_json`,
`config_json`, `guidelines_used`, `tls_versions`, `cipher_suites`,
`key_types`).

> Reading the DB directly is safe. **Before any manual `UPDATE`/`DELETE`,
> back it up:** `cp /var/lib/pqc-monitor/pqc_monitor.db{,.bak}`. The app
> keeps the DB open; ad-hoc writes while it runs are fine for SQLite WAL but
> a backup is cheap insurance.

---

## 1. Mental model

A **scan run** (`scan_runs`) is one execution over a set of domains. Each run
produces, per domain:

- one or more **raw scans** (`raw_scans`) — one row per `(domain, port)`
  probed, whether or not TLS succeeded;
- one **assessment** (`assessments`) — the scored result, referencing the
  guidelines;
- optional **enrichment blobs** (`domain_extra`) — cipher enumeration, chain
  analysis, CDN detection, SSL Labs, DNS enumeration — keyed by `data_type`.

The dashboard shows the **newest assessment per domain** (max `assessed_at`).
That single fact explains most "why is the dashboard showing X" questions:
a stale or wrong newest row wins until a newer correct one is written.

Domains are grouped for reporting via `organisations` (+ country tags),
`communities`, and `domain_lists`. Access control is `users` + the
`user_*` / `*_organisations` mapping tables. `audit_log` records actions.

`schema_version` tracks migrations applied by `data/database.py` at startup.

---

## 2. Core tables

### scan_runs
One row per run. `run_id` is an 8-char hex string (the app's key; the
INTEGER `id` is unused by joins). `status` is `running` → `completed` /
`partial` / `failed`. `domain_list` is a JSON array of the domains targeted.
Reassessment runs carry a `notes` like `reassess-all (score-only)`.

### raw_scans
One row per `(domain, port)` probe. `success` = 1 only when a TLS handshake
completed. `raw_json` is the full `TLSProbeResult` / STARTTLS dict — the
authoritative record; the flat columns are denormalised for querying.
`error` holds `connection_refused` / `timeout` / `ssl_error:*` etc. for
failed probes. `has_dane` / `has_dnssec` are per-scan DNS security flags.

Key point: a host with **no reachable TLS** still gets `raw_scans` rows —
all with `success=0`. It is the *assessment* that must render this as `na`.

### assessments
The scored result. `run_id` + `domain` + `assessed_at`. `score` 0–100,
`level` ∈ {`na`, `critical`, `weak`, `moderate`, `good`, `excellent`}.
`services_assessed` is how many `raw_scans` succeeded for this assessment —
**`services_assessed=0` means no TLS handshake succeeded**, so the only
valid `level` for such a row is `na`. `findings_json` is a JSON array of
finding dicts (`severity`, `category`, `message`, `guideline`,
`recommendation`, and — since 1.9.0 — `ciphers` for cipher-enum findings).
`tls_versions` / `cipher_suites` / `key_types` are JSON arrays.

> **Invariant worth checking:** `services_assessed = 0 AND level != 'na'` is
> impossible for a correct row. It was the signature of the 1.9.1 scoring
> bug (a no-TLS host scored "30 weak" purely on the PQC penalty). See §5.

### domain_extra
Enrichment, one row per `(run_id, domain, data_type)`. `data_type` is one
of: `cipher_enum`, `chain`, `cdn`, `ssllabs`, `dns_enum`. `json_data` is the
blob. Read the latest per type across runs with
`Database.get_latest_domain_extra(domain, data_types=[...])`.

Notable blob shapes:
- `cipher_enum`: `supported_ciphers[]` (each: `openssl_name`, `iana_name`,
  `tls_version`, `bits`, `category`, `security_level`), plus
  `recommended_count` / `acceptable_count` / `deprecated_count` /
  `disallowed_count` and `tls13_supported` / `tls12_supported`.
- `ssllabs`: `grade` (worst across endpoints), `grades[]`, `endpoints[]`,
  `test_time`, `report_url`. Display-only — never feeds the score.
- `dns_enum`: `mx_hosts[]`, `subdomains[]`, `tls_candidates[]`
  (`host`/`port`/`service_type`/`source`). MX hosts must be bare FQDNs —
  see §5 for the "priority prefix" bug.

### ct_queries / ct_certificates
Certificate Transparency monitoring. `ct_queries` is one summary row per
domain query; `ct_certificates` holds individual certs with PQC/hybrid
flags (`is_pqc_signature`, `is_pqc_pubkey`, `is_hybrid`).

### roadmaps
Generated PQC migration roadmaps per domain (phase item counts, effort
range, projected scores, `items_json` for the detail).

---

## 3. Grouping & access-control tables

- **organisations** — `name`, `sector`, `region`, `country_code` (ISO
  3166-1 alpha-2), `country`. Domains map via **domain_organisations**
  (`domain` + `org_id`, composite PK).
- **communities** — named groups of organisations, mapped via
  **community_organisations**.
- **domain_lists** — saved domain sets (`domains_json`); schedules reference
  them.
- **users** — `role` ∈ {`admin`, `analyst`, `community_manager`};
  `password_hash`, `failed_logins`, `locked_until` for auth/lockout.
- **user_organisations / user_communities / user_domain_lists** — grant
  tables (composite PKs) that scope what a non-admin user can see.
- **audit_log** — `username`, `action`, `resource`, `timestamp`, `detail`.
- **scheduled_scans** — recurring runs (`interval_days`, `next_run`,
  `enabled`, `config_json`).

---

## 4. Handy queries

Run read-only queries with:
```bash
sqlite3 -header -column /var/lib/pqc-monitor/pqc_monitor.db "SELECT ..."
```

**Latest assessment per domain (what the dashboard shows):**
```sql
SELECT a.domain, a.score, a.level, a.services_assessed, a.assessed_at
FROM assessments a
JOIN (SELECT domain, MAX(assessed_at) AS ts FROM assessments GROUP BY domain) m
  ON a.domain = m.domain AND a.assessed_at = m.ts
ORDER BY a.score;
```

**All assessment history for one domain (diagnosing "why this score"):**
```sql
SELECT run_id, assessed_at, score, level, services_assessed
FROM assessments WHERE domain = 'a-bancox2.bde.es' ORDER BY assessed_at;
```

**Raw probe detail for a domain (did any port actually do TLS?):**
```sql
SELECT domain, port, success, error, tls_version, cipher_suite
FROM raw_scans WHERE domain = 'a-bancox2.bde.es' ORDER BY scanned_at DESC;
```

**Level distribution across the latest-per-domain set:**
```sql
SELECT level, COUNT(*) FROM (
  SELECT a.domain, a.level FROM assessments a
  JOIN (SELECT domain, MAX(assessed_at) ts FROM assessments GROUP BY domain) m
    ON a.domain=m.domain AND a.assessed_at=m.ts
) GROUP BY level ORDER BY COUNT(*) DESC;
```

**What enrichment exists, by type:**
```sql
SELECT data_type, COUNT(*) FROM domain_extra GROUP BY data_type;
```

**Runs, newest first:**
```sql
SELECT run_id, started_at, finished_at, status, notes FROM scan_runs
ORDER BY started_at DESC LIMIT 20;
```

**Domains with a stored cipher enumeration (drives the full-detail view):**
```sql
SELECT DISTINCT domain FROM domain_extra WHERE data_type='cipher_enum';
```

**Org / country breakdown of latest scores:**
```sql
SELECT o.country, COUNT(*) , ROUND(AVG(a.score),1) AS avg_score
FROM assessments a
JOIN (SELECT domain, MAX(assessed_at) ts FROM assessments GROUP BY domain) m
  ON a.domain=m.domain AND a.assessed_at=m.ts
JOIN domain_organisations d ON d.domain = a.domain
JOIN organisations o ON o.id = d.org_id
GROUP BY o.country ORDER BY avg_score;
```

---

## 5. Integrity checks & known failure modes

These `SELECT`s find inconsistencies. **Back up before any fix.**

**(a) Impossible "scored but no service" rows** — the 1.9.1 scoring-bug
signature (no-TLS host scored non-`na`). Should return 0 rows on a healthy
DB:
```sql
SELECT domain, run_id, score, level, assessed_at
FROM assessments WHERE services_assessed = 0 AND level != 'na';
```
If any appear, they were written by a pre-1.9.1 assessor. Either re-run
`scripts/reassess_all.py` (now writes a correct `na` that becomes the
newest row) or delete them:
```sql
-- preview, then delete
DELETE FROM assessments WHERE services_assessed = 0 AND level != 'na';
```

**(b) Malformed MX / domain keys** — priority-prefixed or non-FQDN values
that leaked in as a `domain`. Should be 0 rows:
```sql
SELECT DISTINCT domain FROM raw_scans
WHERE domain GLOB '[0-9]* *' OR domain NOT LIKE '%.%';
SELECT DISTINCT domain FROM assessments
WHERE domain GLOB '[0-9]* *' OR domain NOT LIKE '%.%';
```
Fix with `scripts/fix_mx_entries.py` (repairs the `domain` column across all
seven domain-keyed tables — rename / merge-on-collision / drop — plus
`dns_enum` blobs). Run `--dry-run` first.

**(c) Assessments referencing a missing run:**
```sql
SELECT COUNT(*) FROM assessments a
LEFT JOIN scan_runs r ON r.run_id = a.run_id WHERE r.run_id IS NULL;
```

**(d) Runs left "running" (crashed / interrupted):**
```sql
SELECT run_id, started_at, notes FROM scan_runs WHERE status = 'running';
```

**(e) Domains assigned to an organisation that no longer exists:**
```sql
SELECT d.domain, d.org_id FROM domain_organisations d
LEFT JOIN organisations o ON o.id = d.org_id WHERE o.id IS NULL;
```

**(f) SQLite's own structural check:**
```bash
sqlite3 /var/lib/pqc-monitor/pqc_monitor.db "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

---

## 6. Maintenance

- **Backup:** `cp /var/lib/pqc-monitor/pqc_monitor.db{,.bak}` (stop is not
  required for a copy, but do it during a quiet moment).
- **Reclaim space after large deletes:** `VACUUM;` (needs free disk ≈ DB
  size; the prod VM is a 1 GB e2-micro with no swap — check `df -h` first).
- **Schema version:** `SELECT * FROM schema_version ORDER BY version;`
- **Never** hand-edit `password_hash` or the `user_*` grant tables to change
  access — use the app's RBAC so audit and lockout stay consistent.

---

*Schema generated from `data/database.py` as of v1.9.1 (2026-07-10). If the
schema changes, regenerate this table list rather than editing by hand.*
