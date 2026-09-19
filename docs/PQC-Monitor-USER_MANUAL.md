# PQC-Monitor — User Manual

**Version:** applies to PQC-Monitor v1.11.0
**Audience:** Analysts and Community Managers
**Licence:** GPL-3.0 · https://github.com/jfsp/pqc-monitor

---

## 1. Scope of this manual

This manual documents the PQC-Monitor web interface from the point of view of a user with the
`analyst` or `community_manager` role. Administrative functions (user management, organisations,
domain lists, audit log, scan triggering, domain discovery, roadmap generation, CT monitor runs)
are **not** covered here — they belong to the `admin` role and are documented separately.

If a screen or button described here is missing from your session, it is almost always a role
scoping difference. See §3.3.

> **SCREENSHOT PLACEHOLDER — `01-landing-dashboard.png`**
> Full dashboard immediately after login: header, navigation bar, KPI cards, both charts and the
> top of the Domain Assessments table.

---

## 2. Concepts you need before using the tool

### 2.1 What PQC-Monitor measures

PQC-Monitor performs **non-intrusive, passive assessment** of the TLS posture of internet-facing
services and grades how prepared each service is for the post-quantum transition. It does not
exploit, brute-force or stress anything; it negotiates TLS, enumerates offered cipher suites and
key-exchange groups, inspects certificates and chains, and queries public sources (Certificate
Transparency logs, Qualys SSL Labs cache).

Assessment rules come from three published guideline sets, shipped as JSON and versioned with the
tool:

| Guideline ID | Standard | Version in tool |
|---|---|---|
| `nist_800_131a` | NIST SP 800-131A Rev. 3 | r3-ipd-2024 |
| `bsi_tr02102` | BSI TR-02102-1 | 2026-01 |
| `ccn_stic_221` | CCN-STIC-221 | 2023 |

### 2.2 The PQC readiness score

Each assessment produces an integer score 0–100 and a level. The score is the mean of the
individual sub-scores produced by TLS version analysis, cipher analysis, certificate analysis,
chain analysis, cipher-enumeration analysis and the PQC key-exchange check, clamped to 0–100.

| Score | Level | Meaning |
|---|---|---|
| 0–25 | **Critical** | Broken or deprecated algorithms in use (MD5, RC4, DES, RSA-1024, SHA-1 signing) |
| 26–50 | **Weak** | Acceptable today but not PQC-ready (RSA-2048, TLS 1.2 only, no forward secrecy) |
| 51–75 | **Moderate** | Good classical crypto with TLS 1.3 and ECDHE, but no PQC elements |
| 76–100 | **Ready** | PQC algorithms present (ML-KEM, ML-DSA) or fully prepared for transition |
| — | **N/A** | No reachable TLS service on the host. Excluded from average-score maths. |

Two things worth internalising as an analyst:

- **PQC presence is worth a lot.** A domain offering a post-quantum group contributes a 95
  sub-score; a domain offering none contributes 30. A "Moderate" domain with excellent classical
  hygiene is usually only one configuration change away from "Ready".
- **An expired certificate contributes a 0 sub-score** and a `critical` finding, which will drag
  an otherwise healthy domain down hard.

### 2.3 Offered vs negotiated PQC — the grading basis

PQC grading is based on the key-exchange groups the **server offers**, not on what a particular
client happens to negotiate. Negotiation depends on the client's own group list, so a
negotiated-only check systematically under-reports. The Full TLS Details view labels this
explicitly ("offered by server — client-independent").

Where a record predates the group-enumeration feature, the detail view shows the older
negotiated-only wording ("server may still offer PQC"). Treat those as lower-confidence and worth
a re-scan request.

Hybrid groups (e.g. `X25519MLKEM768`) are the preferred deployment. A server offering a **pure,
non-hybrid ML-KEM** group generates a `low` finding recommending hybrid, because hybrid stays
secure if either primitive is broken.

### 2.4 Findings

Every assessment carries a list of findings. Each has:

- **Severity:** `critical`, `high`, `medium`, `low`, `info`
- **Category:** `tls_version`, `cipher`, `key_size`, `hash`, `certificate`, `chain`, `pqc`
- **Message**, **recommendation**, and the **guideline** that produced it

The Domain Assessments table summarises only the `critical` and `high` counts per row; open the
domain detail to see the full list.

### 2.5 Scoping

Analysts and community managers see **only the domains in the domain lists assigned to them** by
an administrator. A banner under the header states this. All KPI cards, charts and tables — and
the average score — are recomputed over your visible subset, so your figures will legitimately
differ from another user's.

---

## 3. Getting started

### 3.1 Signing in

Open the tool URL and sign in with your username and password.

- After **10 consecutive failed attempts** the account is locked for **15 minutes**.
- Browser sessions last **8 hours**.
- If an administrator issued you a temporary password, you are redirected to a forced
  password-change screen and cannot use the tool until you set a new one.
- Passwords must be **at least 10 characters**.

> **SCREENSHOT PLACEHOLDER — `02-login.png`**
> Login form, including the "Forgot password" link.

### 3.2 Forgotten password

Use the **Forgot password** link. A single-use, time-limited reset link is emailed to the address
on your account. Opening it takes you to a reset form. For privacy, the response is identical
whether or not the address is registered.

Changing your password **invalidates all your other active sessions**, on every device.

> **SCREENSHOT PLACEHOLDER — `03-password-reset.png`**
> The reset form reached from the emailed link.

### 3.3 What your role gives you

| Capability | Analyst | Community Manager |
|---|---|---|
| Dashboard, domain detail, Full TLS Details | ✅ | ✅ |
| Trends, schedules (read-only) | ✅ | ✅ |
| CT Monitor (view stored results) | ✅ | ✅ |
| Roadmap (view generated plans) | ✅ | ✅ |
| Settings (reference) | ✅ | ✅ |
| **Group Report** tab | ❌ | ✅ |
| Report export | via API (§10) | Group Report CSV/PDF + API |
| Scan, Domain Discovery, roadmap generation, CT runs, admin panel | ❌ | ❌ |

If you need a domain scanned, a roadmap regenerated or a CT query executed, ask an administrator.

### 3.4 Header and navigation

The header shows the product version, your username, a role badge, a **Password** link (change
your own password) and **Sign out**. The navigation bar below it switches between views without
reloading the page.

> **SCREENSHOT PLACEHOLDER — `04-header-nav.png`**
> Close-up of the header: version, username, role badge, Password / Sign out links, and the
> navigation buttons as seen by an analyst (no Scan / Domain Discovery buttons).

---

## 4. Dashboard

The default view and your main working surface.

### 4.1 KPI cards

| Card | Content | Clickable filter |
|---|---|---|
| Domains Monitored | Count of domains visible to you | — |
| Avg PQC Score | Mean score, excluding N/A domains | — |
| Critical | Domains scoring 0–25 | ✅ |
| Weak | Domains scoring 26–50 | ✅ |
| Moderate | Domains scoring 51–75 | ✅ |
| PQC-Ready | Domains scoring 76–100 | ✅ |
| No TLS | Domains with no reachable TLS service | ✅ |
| PQC Detected | Domains offering a post-quantum group | ✅ |
| PQC Certs (CT) | PQC certificates seen in CT logs | — |
| Urgent Actions | Count of Phase 1 roadmap actions | — |

Clicking a filter card restricts the assessments table to that population and shows a filter badge
next to the table title. **✕ Clear filter** removes it.

> **SCREENSHOT PLACEHOLDER — `05-kpi-cards.png`**
> The KPI row with one filter card active (e.g. Critical) and the filter badge visible on the
> table header.

### 4.2 Charts

- **Readiness Distribution** — doughnut of Critical / Weak / Moderate / Ready / No TLS.
- **TLS Version Coverage** — how many of your domains serve each TLS version.

### 4.3 Domain Assessments table

Columns: **Domain · Score · Level · TLS · Key · PQC · Findings**.

- **Domain** is a link that opens the detail panel.
- **Key** is the certificate key type (e.g. `RSA-2048`, `EC-P256`).
- **PQC** shows a `✓ PQC` pill when a post-quantum group is offered.
- **Findings** shows counts of `critical` and `high` findings, or a green tick when there are none.
- Sort by clicking **Domain, Score, Level, Key, PQC** or **Findings**. Default sort is Score
  ascending, i.e. worst first.
- Three dropdown filters stack with the card filters: **All Organisations**, **All Regions**,
  **All Countries**.
- **↻ Refresh** re-fetches the latest assessment per domain.

> **SCREENSHOT PLACEHOLDER — `06-assessments-table.png`**
> The table with the organisation/region/country dropdowns visible and a mix of levels in the rows.

### 4.4 Domain detail panel

Clicking a domain opens a panel below the table.

Left side: the score in large type, coloured by level, with the level name (or "No TLS Service").

Right side:
- **TLS** — protocol versions found
- **TLS ports** — each TCP port serving TLS, with the detected service and version
- **Ciphers accepted** — total count, broken down into recommended / acceptable / deprecated /
  disallowed. If cipher enumeration data is absent, the first few negotiated suites are shown
  instead
- **PQC** — Detected / Not detected
- **Cert expires** — days remaining, red under 30 days
- **SSL Labs** — cached Qualys grade with a link to the full report on ssllabs.com
- **Full TLS Details →** button

Below: the complete findings list, each with severity, category, message, recommendation and
originating guideline.

> **SCREENSHOT PLACEHOLDER — `07-domain-detail.png`**
> Detail panel for a domain with several findings of mixed severity.

### 4.5 Full TLS Details (drill-down)

Reached from the detail panel. **← Back** returns to the dashboard.

Contents:

1. **TLS protocols** and **TLS-serving ports**.
2. **Key-exchange groups** offered by the server, in server order. Post-quantum groups are
   highlighted in violet and bordered. A line below states whether PQC key exchange is offered and
   whether it is hybrid.
3. **Accepted cipher suites** — a table of IANA name, protocol, bits, category and assessment
   (RECOMMENDED / ACCEPTABLE / DEPRECATED / DISALLOWED), sorted worst-assessment-last. A footnote
   gives the enumeration timestamp, TLS 1.3/1.2 support, and warns that enumeration probes a
   curated suite list — very rare suites may not be covered.
4. **Certificate chain** — chain length, completeness, root CA.
5. **Qualys SSL Labs** — grade, per-endpoint IP grades and warning flags, assessment time, engine
   and criteria versions. The grade is **informational only and does not affect the PQC score**.
   The "Request fresh SSL Labs assessment" button is admin-only; as an analyst you see the cached
   result and the link to ssllabs.com.

> **SCREENSHOT PLACEHOLDER — `08-full-tls-details.png`**
> Full TLS Details for a domain that offers a hybrid PQC group, with the cipher table and SSL Labs
> panel visible.

---

## 5. Group Report (Community Managers)

Aggregate readiness across a set of organisations. Visible only to `community_manager` and `admin`.

**Controls (top row):**

- **View by** — Community, Region or Country
- **Group selector** — the specific community / region / country
- **Country filter** — appears only when the loaded group spans more than one country
- **⬇ CSV** and **⬇ PDF** — enabled once a report is loaded

**Executive summary** — a short generated paragraph above the charts.

**Charts** — a readiness-distribution donut and a score-by-organisation bar chart.

**Table** — one row per organisation: Organisation, CC (country code), Sector, Domains, Score,
Level, and counts for Crit / Weak / Mod / Ready / NTLS / PQC. Every column except Sector is
sortable; click again to reverse.

> **SCREENSHOT PLACEHOLDER — `09-group-report.png`**
> Group Report loaded for a community: summary paragraph, donut, bar chart and table.

> **SCREENSHOT PLACEHOLDER — `10-group-report-pdf.png`**
> First page of the exported PDF.

---

## 6. Trends

Longitudinal view. Requires at least two scan runs; with fewer, the charts show a prompt instead.

- **Score Trend Over Time** — average score per scan run.
- **Readiness Level Changes** — stacked bars showing how the level population moved between runs.
- **PQC Adoption Rate** — percentage of domains offering PQC over time.
- **Per-Domain Score History** — pick any visible domain from the dropdown for its own score
  timeline. Useful for evidencing that a remediation actually landed.
- **Periodic Scan Schedules** — read-only list of configured recurring scans and their intervals.
  Schedules are created by administrators from the CLI. Domains with level `na` are deliberately
  excluded from auto-scheduling.

> **SCREENSHOT PLACEHOLDER — `11-trends.png`**
> Trends view with the score trend line and both secondary charts populated.

> **SCREENSHOT PLACEHOLDER — `12-domain-history.png`**
> Per-Domain Score History for a domain that improved across runs.

---

## 7. CT Monitor

Passive analysis of Certificate Transparency logs (source: crt.sh) for monitored domains. No active
scanning is involved. PQC and hybrid certificates are identified by OID classification.

**KPI cards:** Domains Monitored · Total Certs · PQC Certs Found · Hybrid Certs · Domains with PQC.

**Charts:** PQC Certificate Timeline and PQC Algorithm Distribution.

**Domain CT Summary table:** Domain, Queried (last query time), Total Certs, PQC Certs, Hybrid,
Algorithms, Issuers.

**PQC & Hybrid Certificates Detected:** Domain, Subject CN, Issuer, Signature Algorithm, PQC
Algorithms, Type, Not Before, Expiry.

**PQC OID Registry:** the OIDs the tool watches, with algorithm, type and standard — ML-DSA-44/65/87
(FIPS 204), ML-KEM-768 (FIPS 203), Falcon-512/1024 (NIST Round 3), SLH-DSA-SHA2-128s (FIPS 205),
and Composite-ML-DSA (draft-ounsworth). The `1.3.9999.*` prefix is experimental and used in
pre-standard deployments, so hits there indicate a test or pilot certificate rather than a
production PQC rollout.

The **Run CT Monitor** panel is admin-only; analysts see stored results and can refresh the tables.

> **SCREENSHOT PLACEHOLDER — `13-ct-monitor.png`**
> CT Monitor view: KPI cards, timeline chart and Domain CT Summary table.

> **SCREENSHOT PLACEHOLDER — `14-ct-pqc-certs.png`**
> The PQC & Hybrid Certificates Detected table with at least one row.

---

## 8. Roadmap

A phased migration plan derived from existing scan data — no additional scanning. Generation is
admin-triggered; analysts consume the generated plans.

**KPI cards:** Domains with Roadmap · Phase 1 Actions · Phase 2 Actions · Phase 3 (PQC) Actions ·
Est. Effort Range.

**Charts:** Score Projection by Phase, and Effort Distribution in person-days.

**Domain Migration Plans table:** Domain, Score Now, → Phase 1, → Phase 2, → Phase 3, action counts
per phase, Effort, Est. Completion. The arrow columns are the projected score after each phase —
the practical argument for prioritisation. Click a row to open the action plan.

**Action Plan drawer:** three phase summary boxes (action count and person-day range), an optional
CDN note, then each action with:

- the action title and an effort badge (LOW/MEDIUM/HIGH plus a min–max day range)
- target date and guideline references
- **Now:** current state → **→** target state
- a detail paragraph

> A CDN note means the domain sits behind a CDN. The observed TLS posture is the CDN's, not the
> origin's; remediation may be a provider setting rather than a server change, and the origin
> should be assessed separately.

**Phase reference:**

| Phase | Horizon | Focus | Regulatory anchor |
|---|---|---|---|
| P1 | Now → 6 months | Disable broken crypto: TLS ≤1.1, RC4, DES, NULL, SHA-1 certs, RSA<2048 | Already non-compliant with NIST/BSI/CCN today |
| P2 | 6 → 18 months | Enable TLS 1.3, ECDHE-only, RSA ≥ 3072, HSTS, CAA records | BSI TR-02102-1: RSA ≥ 3000 bits from 2026 |
| P3 | 18 → 48 months | Deploy ML-KEM hybrid key exchange, plan ML-DSA cert migration, audit app-level crypto | NIST SP 800-131Ar3: PQC transition required by 2030 |

> **SCREENSHOT PLACEHOLDER — `15-roadmap-overview.png`**
> Roadmap view: KPI cards, both charts and the Domain Migration Plans table.

> **SCREENSHOT PLACEHOLDER — `16-roadmap-action-plan.png`**
> Action Plan drawer for one domain, showing Phase 1 and Phase 2 items.

---

## 9. Settings

Reference information only — nothing here is editable by an analyst.

- **Guidelines in Use** — the three guideline sets, their versions, publication dates and source
  links. Check this before quoting a finding in a report, so you cite the version actually applied.
- **PQC Readiness Score Guide** — the score/level table reproduced in §2.2.
- **About PQC-Monitor** — version, GPL-3.0 licence, AI-assisted development notice, and the
  disclaimer that the tool is for research and informational purposes and that users are
  responsible for having authorisation to scan target systems.

> **SCREENSHOT PLACEHOLDER — `17-settings.png`**
> Settings view with all three panels.

---

## 10. Exporting data

**Group Report (Community Managers):** the ⬇ CSV and ⬇ PDF buttons on the Group Report toolbar
export the currently loaded and filtered group.

**Full assessment export (all roles with export permission):** the export panel lives in the
admin-only Scan view, but the endpoint itself is available to analysts. Request it directly from
the browser while signed in:

```
/app/api/export?format=csv     # CSV — spreadsheet analysis
/app/api/export?format=json    # JSON — pipelines and further processing
/app/api/export?format=text    # Plain-text report — pasteable summary
```

Add `&run_id=<id>` to export a specific scan run; without it you get the latest assessment per
domain. Exports are scoped to your visible domains and are recorded in the audit log.

---

## 11. Analyst workflows

### 11.1 Weekly posture triage

1. Dashboard → click the **Critical** card.
2. Sort by **Score** ascending, work top-down.
3. Open each domain, read the findings, note anything with `critical` severity in the
   `certificate` category — expired or near-expiry certificates are the fastest wins.
4. Cross-check the Roadmap tab for the same domains: Phase 1 actions are already non-compliant
   with current guidance and carry the strongest remediation argument.

### 11.2 Answering "are we exposed to harvest-now-decrypt-later?"

1. Dashboard → **PQC Detected** card to see the population that already offers PQC.
2. Invert it mentally: everything else is exposed for the lifetime of the data in transit.
3. For any individual domain, open **Full TLS Details** and read the offered key-exchange groups —
   that is the authoritative evidence, not the negotiated result.
4. Use CT Monitor to check whether PQC or hybrid certificates exist for the same domains.

### 11.3 Building a remediation case for a business owner

1. Roadmap → open the domain's Action Plan.
2. Take the Phase 1/2/3 effort ranges and the projected score after each phase.
3. Pull the guideline references from the individual actions — they map directly to NIST/BSI/CCN
   requirements.
4. Add the Trends per-domain history as before/after evidence once work completes.

### 11.4 Reporting on a community or region

1. Group Report → View by Community/Region/Country → select the group.
2. Apply the country filter if the group spans several.
3. Sort by Score ascending to lead with the weakest organisations, or by Crit to lead with the
   most acute.
4. Export PDF for distribution, CSV for your own analysis.

---

## 12. Troubleshooting

| Symptom | Explanation / action |
|---|---|
| Fewer domains than a colleague sees | Domain-list scoping. Your KPIs are computed over your assigned lists only. Ask an admin to widen your assignment. |
| No **Scan** or **Domain Discovery** tab | Admin-only. Request scans through an administrator. |
| No **Group Report** tab | Requires `community_manager` or `admin`. |
| "No scan data yet. Run a scan first." | No assessments exist for your visible domains yet. |
| Trends charts empty or showing a prompt | Fewer than two scan runs exist. |
| Domain shows N/A / No TLS | No reachable TLS service. These are excluded from the average score and from auto-scheduling. |
| Cipher table missing, "re-scan with cipher_enum enabled" | The stored record predates cipher enumeration. Request a re-scan. |
| PQC line reads "negotiated-only check" | Older record graded before server-group enumeration existed. Lower confidence — request a re-scan. |
| SSL Labs shows "no report" | Nothing cached for that domain. Follow the ssllabs.com link, or ask an admin to request a fresh assessment. |
| Signed out unexpectedly | Either the 8-hour session expired, or a password change invalidated all your sessions. |
| Account locked | 10 failed logins triggers a 15-minute lockout. Wait it out or use password reset. |

---

## 13. Screenshot index

| File | Section | Content |
|---|---|---|
| `01-landing-dashboard.png` | §1 | Dashboard immediately after login |
| `02-login.png` | §3.1 | Login form |
| `03-password-reset.png` | §3.2 | Password reset form |
| `04-header-nav.png` | §3.4 | Header and analyst navigation bar |
| `05-kpi-cards.png` | §4.1 | KPI row with an active filter |
| `06-assessments-table.png` | §4.3 | Domain Assessments table and filters |
| `07-domain-detail.png` | §4.4 | Domain detail panel with findings |
| `08-full-tls-details.png` | §4.5 | Full TLS Details drill-down |
| `09-group-report.png` | §5 | Group Report loaded |
| `10-group-report-pdf.png` | §5 | Exported PDF, first page |
| `11-trends.png` | §6 | Trends view |
| `12-domain-history.png` | §6 | Per-domain score history |
| `13-ct-monitor.png` | §7 | CT Monitor overview |
| `14-ct-pqc-certs.png` | §7 | PQC/hybrid certificates table |
| `15-roadmap-overview.png` | §8 | Roadmap overview |
| `16-roadmap-action-plan.png` | §8 | Action Plan drawer |
| `17-settings.png` | §9 | Settings view |

Suggested location in the repository: `docs/images/`, referenced from `docs/USER_MANUAL.md`.
