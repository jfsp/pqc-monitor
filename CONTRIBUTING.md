# Contributing to PQC-Monitor

Thank you for considering a contribution to PQC-Monitor.
This document covers how to report issues, propose changes, and submit code.

---

## ⚠️ Legal notice

By submitting a contribution you agree that:

1. Your contribution is your own original work.
2. You license it under the **GNU General Public License v3.0 or later**
   (the same licence as this project).
3. You have read and agree to our [Code of Conduct](#code-of-conduct).

---

## Ways to contribute

| Type | How |
|------|-----|
| Bug report | Open a GitHub Issue with the **bug** label |
| Security issue | E-mail the maintainers — do **not** open a public issue |
| Feature request | Open a GitHub Issue with the **enhancement** label |
| Code / fix | Fork → branch → PR (see below) |
| Guideline update | Edit `guidelines/*.json` and open a PR with justification |
| Documentation | PRs to `README.md`, `CONTRIBUTING.md`, or inline docstrings |

---

## Development setup

```bash
git clone https://github.com/your-org/pqc-monitor.git
cd pqc-monitor

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install -r requirements.txt

# Seed demo data so the dashboard has content
python3 tests/seed_demo_data.py --runs 3

# Run the test suite — must pass before any PR
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

---

## Branching model

| Branch | Purpose |
|--------|---------|
| `main` | Stable, always deployable |
| `develop` | Integration branch for new features |
| `feature/<name>` | Individual feature work |
| `fix/<name>` | Bug fixes |
| `guideline/<name>` | Guideline JSON updates |

PRs should target **`develop`** unless they are critical hotfixes.

---

## Commit message convention

```
<type>(<scope>): <short summary>

<optional body — wrap at 72 chars>

<optional footer: Closes #NNN / Breaking-Change: ...>
```

Types: `feat` `fix` `docs` `test` `refactor` `guideline` `chore`

Examples:
```
feat(scanner): add STARTTLS support for POP3 port 110
fix(assessor): correct RSA-1024 boundary check (was < not <=)
guideline(bsi): update TR-02102-1 to 2026-01 key-size requirements
docs(readme): add Docker quickstart
```

---

## Pull request checklist

Before opening a PR, verify all of the following:

- [ ] `python3 -m unittest discover -s tests -p 'test_*.py'` passes with **0 failures**
- [ ] New code has corresponding unit tests
- [ ] All Python files pass `python3 -c "import ast; ast.parse(open('FILE').read())"`
- [ ] SPDX licence header present in every new `.py` file:
      `# SPDX-License-Identifier: GPL-3.0-or-later`
- [ ] AI-assistance disclosure if applicable:
      `# AI-assisted development: portions generated with Claude (Anthropic)`
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] If this is a release PR: `VERSION` file updated to the new semver string

---

## Releasing a new version

1. Update `VERSION`:
   ```bash
   echo "1.2.0" > VERSION
   ```

2. Move `[Unreleased]` entries in `CHANGELOG.md` to a new `## [1.2.0] — YYYY-MM-DD` section.

3. Update the comparison links at the bottom of `CHANGELOG.md`.

4. Commit: `git commit -am "release: v1.2.0"`

5. Tag: `git tag -a v1.2.0 -m "v1.2.0"`

No other source files need editing — all UI and CLI components read the version
string from the `VERSION` file automatically via `version.py`.


- [ ] No API keys, passwords, or scan databases committed
  (check `.gitignore` includes `config/config.yaml` and `data/*.db`)
- [ ] Non-intrusive scanning principle preserved — no exploit payloads,
  no DoS-capable request rates, no credential stuffing

---

## Updating guidelines

The `guidelines/` directory contains versioned JSON files that define
cryptographic weakness rules.  When a new version of NIST SP 800-131A,
BSI TR-02102-1, or CCN-STIC-221 is published:

1. **Do not edit the existing JSON file in place.** Copy it:
   ```bash
   cp guidelines/nist_800_131a.json guidelines/nist_800_131a_r3_2024.json
   ```
2. Update `version` and `published` fields in the new file.
3. Apply rule changes (see schema in existing files).
4. Add a `CHANGELOG.md` entry citing the official source URL.
5. Open a PR with the label **guideline**.

Existing scan data can then be re-assessed against the new rules using:
```bash
python3 pqc_monitor.py reassess <run_id>
```
or via the dashboard **Re-Assessment** panel.

---

## Code style

- Python 3.10+ type hints where practical
- `dataclass` preferred over plain `dict` for structured data
- No external formatting tools required, but PEP 8 compliance expected
- Line length ≤ 100 characters
- Docstrings on all public classes and functions

---

## Code of conduct

Be respectful and constructive.  Harassment, discrimination, or
deliberate obfuscation of security research will result in removal.
We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

*PQC-Monitor is licensed under GPL-3.0-or-later.
AI-assisted development notice: portions of this project were generated
with the assistance of Claude (Anthropic).*
