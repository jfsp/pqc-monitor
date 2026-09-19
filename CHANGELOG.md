# Changelog

All notable changes to PQC-Monitor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Changed
- **Trends tab plots time, not scan runs.** The x axis is now proportional to
  time and data is grouped into day / week / month / quarter periods
  (`data/trends.py`). Granularity is picked automatically from the fastest
  enabled scan schedule and the length of the range (8–90 points), and can be
  set manually; range presets 3M / 6M / 1Y / 2Y / All.
- Two views. **Snapshot** (default): each point is the portfolio at the end of
  the period, using every domain's latest assessment up to then. Domains not
  rescanned within 3× the longest schedule interval (90 d for monthly) drop
  out. **Scan activity**: only assessments made in the period, shown as bars.
- The score chart has a second y-axis: domains monitored (snapshot) or
  assessed (activity). Readiness levels are a stacked area chart that shows
  % share by default (toggle to counts) and include No-TLS. PQC adoption shows
  % of TLS-serving domains plus the absolute count on a second axis.
- Scope selector on the Trends tab: all visible domains, a community, or an
  organisation (limited to what the user may see).
- Per-domain score history uses the same time axis.
- **Trends load faster and show progress.** Results are cached per process
  (5 min TTL, keyed on the assessments data version, the scope's domain set
  and every parameter, so new scans invalidate it). The browser also keeps
  each result for 2 minutes, so switching back to a view is instant. Scopes
  of up to 900 domains are filtered in SQL. While loading, the caption shows
  "Loading…" and the charts dim; failures (HTTP error, non-JSON response,
  network error) are shown in the caption instead of leaving stale charts.
- The per-domain history picker loads from the new scoped
  `/api/trends/domains` and follows the selected scope. It no longer fetches
  the full `/api/assessments` payload, which queued trend requests behind it
  on the two sync Gunicorn workers (4–5 s in production).
- **Domain detail is now its own screen.** Clicking a domain on the Dashboard
  or Roadmap tab opens one page with the summary, all findings and their
  recommendations, the full TLS details and the migration action plan. It
  replaces the panel that opened at the bottom of the dashboard, the separate
  "Full TLS Details" view and the Roadmap drawer.
- The domain screen has its own URL (`#domain/<name>`). Browser Back/Forward
  work, and returning keeps the dashboard's filters, sort order and scroll
  position.
- A searchable box on the domain screen switches to any other monitored domain.
- **Scheduler rewritten around the database.** `next_run` in `scheduled_scans`
  is now the source of truth. A 60 s tick starts due jobs, jobs that fell due
  while the daemon was down run on start, and schedule changes apply without a
  restart. After each run `last_run` is set and
  `next_run = run start + interval`. Scheduled runs are marked
  `notes=scheduled:#<id> <name>`; runs left `running` by a killed daemon are
  marked `interrupted`. A stale `next_run` left by the old scheduler is
  repaired to `last_run + interval`.
- The auto domain lists are rebuilt right before each scheduled run, so
  domains added since the last run are included.
- **No-TLS monthly rescan.** A new auto schedule rescans `level=na` domains
  that still resolve (A/AAAA), so services that come online are detected.
  Names with no DNS entry (`nxdomain`) or no address (`no_address`) are
  recorded as `dns_status` in `domain_extra` with the date first seen, are not
  scanned, and are re-checked in DNS every cycle. The dashboard shows them as
  "No DNS" and counts them on the No TLS card. No schema change.
- **SSL Labs moved out of the scan.** A new throttled sweep
  (`scanner/ssllabs_sweep.py`, weekly auto schedule, manual
  `pqc_monitor.py ssllabs-sweep`) collects reports for serviceable HTTPS
  domains. It follows the `/info` limits and newAssessmentCoolOff, backs off
  on 429/529/503, stops on credential errors, skips fresh records (so an
  interrupted sweep resumes) and stores error results too.
- `scripts/schedule_audit.py --create-monthly` now creates or refreshes all
  three auto schedules (`--no-ssllabs`, `--sweep-interval-days`,
  `--refresh-dns`). Scan History shows a Source and a Domains column.
- systemd: the scheduler now `Wants=` instead of `Requires=` the web service,
  so web restarts no longer restart it.

### Fixed
- **Trends returned HTTP 504 after the caching change.** The cache-validity
  check used `MAX(assessed_at)`, which has no index, so every request (cache
  hits included) scanned the whole assessments table including
  `findings_json`. On the 1 GB production VM that was disk-bound and exceeded
  nginx's 120 s timeout. The check is now `COUNT(*), MAX(id)` (index-only).
  New optional covering index `idx_assessments_trend`
  (`scripts/add_trend_index.py`) lets trend reads skip the table entirely.
  The domain picker request now waits for the trends response instead of
  running in parallel on the second Gunicorn worker.
- **Trend charts were averaging partial runs.** `get_sector_trends()` grouped
  by scan run, so one-domain rescans and ad-hoc batches were plotted as
  portfolio averages (swings between 0 and 78) and PQC adoption fell to 0
  between monthly sweeps.
- **`/app/api/trends` was not RBAC-scoped.** Analysts saw the global
  aggregate. It is now limited to the user's visible domains; `org:` /
  `community:` scopes are checked against the user's assignments (403
  otherwise).
- The per-domain history selector added duplicate entries every time the
  Trends tab was opened.
- **The monthly schedule depended on how long the scheduler had been up.**
  APScheduler's `IntervalTrigger` counted 30 days from process start and
  ignored `next_run`, and every web restart restarted the scheduler through
  `Requires=`. The 2026-09-04 run fired 30 days after a restart, a week after
  its `next_run`.
- **Scans set off SSL Labs rate limits.** `analyze?fromCache=on` starts a
  new assessment on a cache miss, so the scan asked for one per domain: HTTP
  429 for 2,915 of 3,168 domains on 2026-09-04.
- **Certificates with IP-address SANs dropped the whole domain's result**
  ("Object of type IPv4Address is not JSON serializable"). SAN values are now
  stored as strings, and `raw_json` is written with `default=str`.
- Production `/api/domain` did not return `group_enum`, so the TLS details
  view never showed the key-exchange groups offered by the server.
- A bookmarked `#…` deep link now survives the login redirect.
- Findings and action-plan text in the domain view are HTML-escaped.
- The dashboard table said "No scan data yet. Run a scan first." while it was
  still loading, because that message was the table's initial HTML. It now shows
  a loading row, and an error row with a Retry link if the request fails. If
  two loads overlap, a slower older response can no longer overwrite a newer one.
- The domain box on the domain screen now lists only domains with a TLS
  service; no-TLS (`level=na`) domains are excluded.

---

## [1.11.0] — 2026-07-31

Released as tag `v1.11.0`. Three independently-deployable changes plus a
follow-up, delivered in the 2026-07-29/31 sessions and verified on the live
server.

### Added
- **User management Phase 1 — self-service password reset + auth hardening**
  (spec: `HANDOVER_user_mgmt.md`):
  - `auth/mailer.py` — optional SMTP mailer, `mode: local` (local MTA) or
    `relay` (STARTTLS/SSL: Gmail app-password, Proton Bridge). Pure stdlib
    `smtplib`; `send()` never raises into the request path.
  - Public `/forgot` and `/reset/<token>`: single-use SHA-256-hashed tokens,
    default 45-minute TTL, newest-token-wins, generic responses regardless of
    account existence, per-IP rate limit, fully audited, no auto-login.
  - **Session invalidation on password change** — `users.session_epoch` is
    bumped by `set_password`, written into the session at login and checked in
    `current_user()`. Reset and admin-reset sign out ALL sessions; a
    self-service change re-issues the current device so only OTHER sessions
    drop.
  - **Forced password change** — `users.must_change_password`; admin reset
    accepts `{"must_change": true}`; flagged users are pinned to
    `/change-password` (API returns 403) until they set a new password.
  - **App-wide CSRF** (`auth/csrf.py`) — form synchroniser token plus a strict
    same-origin (Origin/Referer) guard for the JSON API, enforced via
    `before_request`, skipped under `TESTING`.
  - Hardening: email-format validation in `create_user`/`update_user`;
    constant-time dummy hash in `authenticate()` for unknown users;
    `secret_key` hard-fails at startup in production instead of falling back to
    a silent per-process random value.
  - `scripts/mail_selftest.py` — verify relay credentials from the shell.
    `relay_password` is config-or-env (`PQC_MAIL_PASSWORD` overrides
    `mail.relay_password`).
  - **Schema v18**: `password_reset_tokens`, `users.must_change_password`,
    `users.session_epoch`.
- **Schedule coverage audit + monthly auto-schedule** —
  `scheduler/schedule_audit.py` (logic) + `scripts/schedule_audit.py` (CLI).
  Reports which assessed domains are in no enabled schedule and can
  create/refresh ONE auto-managed monthly schedule (`--create-monthly`, default
  30 days, `--interval-days` overrides). Idempotent and cron-safe; writes the
  schedule tables directly rather than going through APScheduler, so the
  scheduler service must be restarted after a write. `level=na` domains are
  **excluded by default** (`--include-na` opts them back in) — they are the
  worst-case unit of work (~13 timeout-bound connects). Selection is by the
  *current* latest level, so domains reconcile in and out automatically.
- **Dashboard shows TLS-serving ports** — `api_domain_detail` returns
  `tls_ports` derived from the latest run's successful probes (not the
  truncated `scans[:5]`); `dashboard/app.py` renders "TLS ports" in the summary
  box and "TLS-serving ports" in the drill-down. `_PORT_SERVICE` labels
  direct-TLS and STARTTLS ports; unknown ports render as "port N".

### Notes
- Migration numbering: v18 was consumed by the auth reset feature. The §10
  backlog previously earmarked v18 for T1-2 (geography on domain lists); that
  and any other pending schema change must take the next free version.
  Phase 2 (TOTP 2FA) is reserved for **v19**; the next schema feature after
  that is v20+.
- 95/95 existing auth tests pass. Automated coverage for the Phase 1 paths
  (token lifecycle, mailer transports, CSRF block/allow, session-kill,
  must_change) is **not yet in `tests/`** — see HANDOVER_user_mgmt.md.

---

## [1.10.0] — 2026-07-12

### Fixed
- **PQC detection was wrong for every domain ever scanned**: `has_pqc` was
  decided by regex-matching PQC indicators (`mlkem`, `kyber`, …) against the
  **cipher suite name**. In TLS 1.3 the suite encodes only AEAD + hash
  (`TLS_AES_256_GCM_SHA384`); the key-exchange group — where ML-KEM lives — is
  carried in the `supported_groups`/`key_share` extensions and never appears in
  the suite name, so the regex could not fire for any real server. `has_pqc`
  was therefore `False` for every row in the database. Detection now enumerates
  the key-exchange groups the server **offers**.
- **`get_latest_domain_extra()` full-table-scanned `domain_extra`**: the only
  index led with `run_id` while the query filters on `domain`. New index
  `idx_domain_extra_domain(domain, data_type, recorded_at)`, created via
  `CREATE INDEX IF NOT EXISTS` at DB init (no migration step). Also affected the
  score-only reassess path and the dashboard domain-detail view.

### Added
- **`scanner/group_enum.py`** — offered key-exchange group enumerator. Speaks
  TLS 1.3 directly (RFC 8446 §4.1.4): for each candidate group it sends a
  ClientHello with `supported_groups=[G]` and an **empty `key_share`**; a
  HelloRetryRequest naming G means G is offered, a fatal alert means it is not.
  The handshake is never completed, so no local ML-KEM implementation is
  required. Grading is on *offered*, not *negotiated*, groups — the negotiated
  group is a property of the client/server pair. `pqc_grading_basis` records
  which basis was used (`offered` = authoritative, `negotiated` = fallback).
  Cost: ~15 TCP connections per domain.
- **GREASE soundness control** — `probe_negative_control()` probes RFC 8701
  GREASE codepoints, which no conformant server may select. If one is reported
  as offered, the enumerator is producing false positives and every result is
  suspect.
- **`scripts/pqc_selftest.py`** — standalone self-test (not wired into
  startup): runs the GREASE gate first, then exercises the real scanner path
  against reference hosts and cross-checks against **testssl.sh** (which
  reports *offered* KEMs; sslscan reports only the negotiated group and cannot
  corroborate). Requires a full testssl checkout at `/opt/testssl/`; honours
  `$PQC_TESTSSL`.
- **`data/database.py`**: `domains_with_successful_extra()` and
  `latest_extra_bulk()` — bulk helpers replacing one query per domain.
- **`scripts/reassess_all.py`**: `--only-missing-groups` for the group-enum
  backfill; a failed `group_enum` blob counts as missing so errored domains are
  retried. A full network rescan is required to fix historical `has_pqc` —
  score-only reassess cannot, since no historical row has a `group_enum` blob.

---

## [1.9.1] — 2026-07-09

### Fixed
- **No-TLS domains scored "30 / weak" after re-assessment instead of "na"**:
  `assess_domain()` only returned the `na` level when `scan_results` was
  *empty*. A domain whose every stored scan *failed* (connection refused /
  timeout on all ports — a host with no reachable TLS) skipped that guard,
  fell through the per-service loop with zero services assessed, and was then
  scored purely on the unconditional PQC penalty (`+30`, "No PQC detected"),
  yielding score 30 / weak with a single PQC finding. Now, if no service
  completes a TLS handshake, the domain is `na` (score 0, no findings) — the
  same as having no scan data. This surfaced when re-assessing hosts that
  were previously (correctly) "No TLS": `scripts/reassess_all.py` replayed
  their stored failed scans through the assessor. The script now writes a
  fresh `na` assessment for such domains (so the newest row is always
  correct, rather than leaving a stale row as the latest).
- **MX records stored with priority prefix / non-FQDN** (e.g.
  `"5 SMTP.domain.com"`): MX rdata is `<priority> <exchange>`; the priority
  is a mail-routing preference, irrelevant as a scan target. The direct-DNS
  path already split it, but the DNSDumpster and passive-DNS paths let the
  raw string through into `mx_hosts`, `subdomains`, and
  `tls_candidates[].host`. Added `_normalise_mx_host()` (strips priority,
  lower-cases, removes trailing dot, rejects non-hostnames such as a lone
  `5` or the `.` from a null-MX `0 .`) and applied it at every MX ingestion
  point plus a final safety net in `_build_candidates()`.
- **SMTP/STARTTLS servers reported as "no TLS"; 465/587/2525 not scanned**:
  `probe_starttls()` hardcoded `if port in (25, 587)` for the EHLO/STARTTLS
  upgrade, so any other SMTP port fell through and attempted a *direct* TLS
  wrap on a plaintext socket — the handshake failed and the service was
  recorded as having no TLS. Port **2525** was in no port map at all.
  - STARTTLS handshake now dispatches by **protocol family** (smtp/imap/pop3),
    not port number, so alternative ports work identically.
  - Added **2525** to `STARTTLS_PORTS`/`STARTTLS_PROTOCOL`; MX scan candidates
    now include 25/587/465/2525; added 995 (POP3S) to the default probe set.
  - Unknown STARTTLS ports now fail with an explicit
    `starttls_protocol_unknown_for_port:<n>` error instead of silently
    wrapping a plaintext socket (which looked like "no TLS").
  - Hardened the SMTP greeting/EHLO parser: removed the IMAP
    `endswith("OK")` heuristic that could prematurely terminate an SMTP
    banner, and added an explicit check that the server advertises STARTTLS
    before issuing it.
  - `scanning.use_starttls` is now actually read from config (was always
    defaulting to the hardcoded `True`).

### Added
- **`scripts/fix_mx_entries.py`**: repairs malformed MX host entries in the
  database. Repairs BOTH (a) the `domain` primary-key column across every
  domain-keyed table — raw_scans, assessments, ct_queries, ct_certificates,
  domain_extra, roadmaps, domain_organisations — where a bad MX host was fed
  in as a scan target (e.g. `5 smtp.bde.es`, `20 mail01.x.it`,
  `primary DNS domain`), and (b) the `dns_enum` enrichment blobs
  (`mx_hosts`, `subdomains`, `tls_candidates[].host`). Per malformed domain
  key it renames to the normalised FQDN, or — on collision with an existing
  correct row — drops the duplicate, or deletes rows whose value has no
  recoverable hostname. No network; idempotent; `--dry-run` / `--config`
  / `--db`.
- **Tests**: `tests/test_mx_and_smtp.py` (13 tests) — MX normalisation,
  candidate building, STARTTLS port coverage, protocol dispatch, and the
  repair-script cleaning logic.

---

## [1.9.0] — 2026-07-09

### Fixed
- **Domain detail showed only the passively-negotiated cipher suite**: the
  full active cipher enumeration (stored in `domain_extra['cipher_enum']`)
  never reached the UI, and the modal truncated `cipher_suites` to 2 entries.
  The assessor now merges the complete enumerated suite set (IANA names) into
  `assessments.cipher_suites`, `/api/domain/<domain>` returns the latest
  enrichment blobs (`cipher_enum`, `chain`, `cdn`, `ssllabs`), and the modal
  shows a per-security-level summary with a **Full TLS Details** drill-down
  view listing every accepted suite (protocol, bits, category, assessment).
- **CIPHER_ENUM findings did not name the offending suites**: every
  cipher-enumeration finding (NULL/EXPORT/ANON/RC4/3DES/no-FS/deprecated) now
  lists the specific IANA cipher suite names to remove, both in the message
  and in a machine-readable `ciphers` field.
- **Passive cipher names never matched guideline rules**: the passively
  negotiated cipher (OpenSSL notation, e.g. `ECDHE-RSA-AES128-GCM-SHA256`)
  is now normalised to IANA notation before `_assess_cipher()`, so guideline
  `recommended`/`deprecated` lists (which use IANA names) match correctly.
- **`tests/test_assessor.py`**: `test_empty_scan_list` still expected
  `level="critical"` for a no-TLS domain — stale since the v1.4.0 `na` change.

### Added
- **CAMELLIA and SEED cipher probes** (`scanner/cipher_enum.py`): 7 new
  probe entries + IANA mappings, closing the coverage gap vs SSL Labs on
  European servers (e.g. `TLS_RSA_WITH_CAMELLIA_128_CBC_SHA`).
- **SSL Labs integration (T3-3)** — `scanner/ssllabs_client.py`:
  - Qualys SSL Labs **API v4** client (one-time registration required;
    registered organisational email sent as auth header; helper
    `register_email()` included). v3 was deprecated 2023-12-31.
  - **Cache-only during scan runs** (`fromCache=on`, never triggers external
    assessments inline); summary stored in `domain_extra['ssllabs']`.
  - **On-demand fresh assessment** from the Full TLS Details view
    (`startNew=on`, `publish=off`), polled by the UI; restricted to users
    with `scan.run` permission. New endpoints:
    `GET /app/api/ssllabs/<domain>` (poll + persist when READY),
    `POST /app/api/ssllabs/<domain>/refresh`.
  - Grade + link to the public ssllabs.com report shown in the domain modal
    and detail view. **Display only — the grade does not affect the PQC
    score** (by design decision).
  - Config: `ssllabs.enabled` / `ssllabs.email` (or `PQC_SSLLABS_EMAIL`).
- **`data/database.py`**: `get_latest_domain_extra(domain, data_types)` —
  most recent enrichment blob per type across all runs (with `_recorded_at` /
  `_run_id` provenance); `get_latest_run_id_for_domain(domain)`.
- **Tests**: `tests/test_ssllabs_and_cipher_detail.py` (7 tests).
- **`scripts/reassess_all.py`**: reassess every existing domain to backfill
  the two fixes above. Score-only by default (no traffic/CPU-light —
  reuses stored `cipher_enum`/chain/CDN blobs and regenerates the named
  findings); `--rescan` for a resource-guarded network rescan
  (`--workers`/`--sleep`/`--limit`/`--only-missing`/`--dry-run`).
- **`scanner/crypto_assessor.py`**: `Finding` gains an optional machine-
  readable `ciphers` list, carried through from cipher-enum findings.

---

## [1.8.0] — 2026-06-27

### Fixed
- **`app_routes.py`**: community manager region/country Group Reports returned
  all organisations in the region/country instead of only those belonging to
  the user's assigned communities. Added `_allowed_org_ids(user, db)` helper
  that returns `None` for admins (no restriction) or a `set` of org IDs for
  community managers (direct `user.org_ids` + all orgs from their communities).
  Applied to all 6 region/country report endpoints (JSON, CSV, PDF variants).
  Refactored `api_regions()` and `api_countries()` list endpoints to reuse the
  same helper. Admins are unaffected.
- **`data/database.py`**: added `get_assessed_domains(domains)` — returns the
  subset of a domain list that already has at least one assessment record;
  used by `--skip-scanned` in the CLI.
- **`scanner/dns_enumerator.py`**: DNSDumpster quota exhaustion was not
  detected. The API returns `{"error":"Daily quota exceeded"}` as the body of
  a HTTP 429 response; the old code branched on status code before reading the
  body, entering an infinite 2-second retry loop. Fixed by inspecting
  `resp.text` for the word "quota" or "daily" before any status-code branching.
  Added `DnsDumpsterQuotaError` exception, session-level `_DNSDUMPSTER_QUOTA_EXHAUSTED`
  flag, and `is_dnsdumpster_quota_exhausted()` public accessor. Subsequent
  domains in the same scan session skip the API entirely once quota is hit.
  Also fixed: the file had been inadvertently doubled (two full copies of every
  function) by a prior edit; rebuilt cleanly from backup with surgical patches.

### Added
- **`scanner/dns_enumerator.py`**: passive DNS fallback (`_passive_dns_enum`)
  — activates automatically when DNSDumpster quota is exhausted or when
  DNSDumpster is not configured. Uses dnspython only, no external APIs.
  Techniques: SRV record probing (20 well-known service prefixes), zone
  transfer attempt (AXFR) against each authoritative NS (silently refused by
  virtually all public servers, catches misconfigured ones), PTR reverse lookup
  of apex A records.
- **`pqc_monitor.py`**: `scan` command gains `--skip-scanned` and `--force`
  flags. `--skip-scanned` queries `get_assessed_domains()` before starting,
  prints the skipped domain list, and exits cleanly if nothing remains.
  `--force` overrides `--skip-scanned` and scans all domains regardless.
- **`scripts/shodan-test.sh`**: new test script to verify the Shodan API key
  from config. Runs two lookups — `8.8.8.8` (in the oss free shared dataset,
  confirms key validity) and `google.com` (CDN IP, outside free dataset,
  confirms paid plan capability). Reports `"capability"` field: `"full"` or
  `"restricted (oss/free — shared dataset only)"`. Exit 0 if key is valid;
  exit 1 if key is broken/missing; exit 2 if shodan library not installed.
- **`scripts/dnsdumpster-test.sh`**: new test script to verify the DNSDumpster
  API key from config. Calls the API for a target domain, reports record counts
  per type and a sample of discovered hostnames. Detects quota exhaustion and
  key errors. Exit 0 on success or no-data; exit 1 on key/quota error.

### Changed
- **`scanner/dns_enumerator.py`**: passive DNS fallback now also runs when
  DNSDumpster is not configured (not just on quota exhaustion), ensuring
  SRV/AXFR/PTR probing always supplements CT and wordlist results.

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
- Community concept: group organisations for scoped access and reporting
- `ROLE_COMMUNITY_MANAGER`: new role between analyst and admin; auto-promoted
  from analyst on first community assignment
- Group Report tab: By Community + By Region views, country filter, PDF/CSV
  export, executive summary paragraph
- `reports/community_report.py`: weasyprint PDF generation (A4 landscape)
- 8 new API endpoints under `/app/api/communities` and `/app/api/regions`
- `community` CLI group with 7 subcommands (create, list, add-org, remove-org,
  assign-user, report, region-report)
- Admin UI: Communities section with create/edit/delete and org assignment
- Schema v17: `communities`, `community_organisations`, `user_communities`
- 31 new tests

---

## [1.5.2] — 2026-06-27

### Fixed
- `data/database.py`: `update_organisation()` whitelist missing `country_code`
  and `country` — fields were silently dropped on every PATCH
- `admin/routes.py`: `syncCountryName()` referenced but never implemented —
  ReferenceError in browser prevented country value from being submitted
- `data/database.py`: migration failures logged at DEBUG and swallowed; now
  logged at ERROR and re-raised, causing hard startup failure with clear message

---

## [1.5.1] — 2026-06-27

### Added
- Country and region on scan runs (schema v16)
- TLD-based auto-inference via `data/tld_geo.csv` and `data/geo_inference.py`
- `--country-code` / `--country` on `scan` and `schedule` CLI commands
- `list-runs` output gains Country and Region columns
- 12 new tests in `TestGeoInference`

---

## [1.5.0] — 2026-06-27

### Added
- Country on organisations: `country_code` (ISO 3166-1 alpha-2) + `country`
  (display name); schema v15
- Country dropdown filter in dashboard Domain Assessments view
- `?country_code=` filter on `GET /api/assessments`
- 7 new tests

---

## [1.4.0] — 2026-06-27

### Fixed
- No-TLS domains shown as Critical → now level `na` (N/A)
- Analyst users could see tabs with forbidden actions
- Roadmap included entries for no-TLS (na) domains
- Scheduler service not starting due to DB path mismatch in systemd unit

### Added
- `scripts/deploy.sh`: incremental git→deployment sync
- `scripts/fix_notls_level.py`: one-time retroactive fix for existing na rows

---

## [1.3.1] — 2026-06-25

### Fixed
- 10 production deployment issues (systemd, gunicorn, nginx, DB path, sessions)

---

## [1.3.0] — 2026-06-12

### Added
- DNSDumpster official REST API key support
- Organisation grouping (schema v14): full org CRUD API + admin panel tab
- `?org_id=` and `?region=` filters on assessments
- Analyst org scoping in RBAC

---

## [1.2.0] — 2026-06-12

### Added
- T2-1: `service_type` column on assessments (schema v13)
- T3-1: `scanner/dns_enumerator.py` — CT SANs + wordlist + DNSDumpster
- `POST /api/dns-enumerate` endpoint
- `dns_enumerate` flag on `POST /api/save-domains`

---

## [1.1.3] — earlier

### Fixed
- CT/Roadmap/Settings tabs empty — missing `</div>` in `view-trends`

---

## [1.1.2] — earlier

### Fixed
- CT/Roadmap/Settings tabs empty (stray `return app`)
- `showView` used implicit `event.target`

### Added
- Dashboard card filtering and sortable columns

---

## [1.1.1] — earlier

### Fixed
- Login loop on plain HTTP (`SESSION_COOKIE_SECURE` defaulted True)
- Absolute `?next=` URL redirect

---

## [1.1.0] — earlier

### Added
- RBAC (admin/analyst roles), systemd units, `VERSION` file

---

## [1.0.0] — earlier

Initial release: core scan engine, TLS probe, assessor, guidelines, dashboard
SPA, CLI, scheduler.
