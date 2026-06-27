#!/usr/bin/env bash
# PQC-Monitor: Incremental deployment from git working tree
# ==========================================================
# Syncs only the files changed in the last git commit (or a specific
# commit given with --from) from the git checkout to the deployment dir,
# then restarts only the services whose Python code was touched.
#
# Usage:
#   scripts/deploy.sh [OPTIONS]
#
# Options:
#   -s, --source DIR     Git checkout root  (default: parent of this script)
#   -d, --dest   DIR     Deployment target  (default: /opt/pqc-monitor)
#   -f, --from   HASH    Diff from this commit instead of HEAD~1
#   -n, --dry-run        Print what would be synced without doing it
#   -r, --no-restart     Skip service restart after sync
#   -h, --help           Show this help
#
# Examples:
#   scripts/deploy.sh
#   scripts/deploy.sh --from abc1234
#   scripts/deploy.sh --dest /srv/pqc-monitor --dry-run
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2024 PQC-Monitor Contributors
# AI-assisted development: portions generated with Claude (Anthropic)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST_DIR="/opt/pqc-monitor"
FROM_COMMIT=""
DRY_RUN=false
RESTART=true

# Files/dirs that must never be overwritten in production.
#
# NOTE: data/database.py, data/migrations.py, data/geo_inference.py,
# data/tld_geo.csv etc. are Python/config SOURCE files that live in
# /opt/pqc-monitor/data/ and MUST be deployed.
#
# The live SQLite database (pqc_monitor.db) and runtime scan artefacts
# live in /var/lib/pqc-monitor/ — a completely separate path that is
# never part of the git repo, so they cannot appear in `git diff` and
# need no protection here.
#
# Only protect files that (a) exist in the repo AND (b) contain
# instance-specific secrets or local overrides.
PROTECTED=(
    "config/config.yaml"
    ".env"
    ".venv/"
)

# Per-service restart triggers.
# A service is restarted only when at least one synced file matches its
# prefix list. Non-Python assets (docs, scripts/, systemd/, guidelines/,
# tests/) are intentionally absent from both lists.
#
# pqc-monitor-web      — Flask/Gunicorn app and everything it imports
# pqc-monitor-scheduler — scheduler daemon and everything it calls at runtime

WEB_TRIGGERS=(
    "app_factory.py"
    "app_routes.py"
    "version.py"
    "requirements.txt"
    "admin/"
    "auth/"
    "ct/"
    "dashboard/"
    "data/"
    "domain_discovery/"
    "reports/"
    "roadmap/"
    "scanner/"
)

SCHEDULER_TRIGGERS=(
    "pqc_monitor.py"
    "version.py"
    "requirements.txt"
    "ct/"
    "data/"
    "scanner/"
    "scheduler/"
)

# ── Colours ───────────────────────────────────────────────────────────────────

RED="\033[0;31m"; YELLOW="\033[0;33m"; GREEN="\033[0;32m"
CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

info()    { echo -e "${CYAN}▸${RESET} $*"; }
ok()      { echo -e "${GREEN}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET} $*"; }
err()     { echo -e "${RED}✗${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────

usage() {
    sed -n '/^# Usage/,/^[^#]/{ /^#/{ s/^# \{0,2\}//; p } }' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--source)     SOURCE_DIR="$2"; shift 2 ;;
        -d|--dest)       DEST_DIR="$2";   shift 2 ;;
        -f|--from)       FROM_COMMIT="$2"; shift 2 ;;
        -n|--dry-run)    DRY_RUN=true;    shift ;;
        -r|--no-restart) RESTART=false;   shift ;;
        -h|--help)       usage ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Sanity checks ─────────────────────────────────────────────────────────────

section "Pre-flight"

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
    err "Not a git repository: ${SOURCE_DIR}"
    exit 1
fi
ok "Source git repo: ${SOURCE_DIR}"

if [[ ! -d "${DEST_DIR}" ]]; then
    err "Deployment directory does not exist: ${DEST_DIR}"
    exit 1
fi
ok "Deployment target: ${DEST_DIR}"

# ── Resolve the commit range ──────────────────────────────────────────────────

section "Commit range"

cd "${SOURCE_DIR}"

HEAD_HASH=$(git rev-parse HEAD)
HEAD_MSG=$(git log -1 --pretty=format:"%h %s")

if [[ -n "${FROM_COMMIT}" ]]; then
    if ! git cat-file -t "${FROM_COMMIT}" &>/dev/null; then
        err "Unknown commit: ${FROM_COMMIT}"
        exit 1
    fi
    BASE_COMMIT="${FROM_COMMIT}"
else
    if ! git rev-parse HEAD~1 &>/dev/null 2>&1; then
        err "Repository has only one commit — no HEAD~1. Use --from <hash> to deploy everything."
        exit 1
    fi
    BASE_COMMIT="HEAD~1"
fi

BASE_HASH=$(git rev-parse "${BASE_COMMIT}")
BASE_MSG=$(git log -1 --pretty=format:"%h %s" "${BASE_COMMIT}")

info "Base : ${BASE_MSG}"
info "Head : ${HEAD_MSG}"

# ── Collect changed files ─────────────────────────────────────────────────────

section "Changed files"

# --diff-filter: A=Added, M=Modified, R=Renamed, C=Copied — skip D=Deleted
mapfile -t CHANGED < <(
    git diff --name-only --diff-filter=AMRC "${BASE_HASH}" "${HEAD_HASH}"
)

if [[ ${#CHANGED[@]} -eq 0 ]]; then
    warn "No file changes between ${BASE_HASH:0:7} and ${HEAD_HASH:0:7}."
    exit 0
fi

info "${#CHANGED[@]} file(s) changed:"
for f in "${CHANGED[@]}"; do
    echo "    ${f}"
done

# ── Filter out protected paths ────────────────────────────────────────────────

TO_SYNC=()
SKIPPED=()

for f in "${CHANGED[@]}"; do
    protected=false
    for pattern in "${PROTECTED[@]}"; do
        if [[ "${f}" == "${pattern}" || "${f}" == "${pattern}"* ]]; then
            protected=true
            break
        fi
    done
    if $protected; then
        SKIPPED+=("${f}")
    else
        TO_SYNC+=("${f}")
    fi
done

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    warn "Skipping protected path(s):"
    for f in "${SKIPPED[@]}"; do
        echo "    ${f}"
    done
fi

if [[ ${#TO_SYNC[@]} -eq 0 ]]; then
    warn "All changed files are protected — nothing to sync."
    exit 0
fi

# ── Determine which services need restarting ──────────────────────────────────
# Check the full changed set (TO_SYNC), not just the file being synced,
# so the decision is made once before any writes happen.

needs_restart_web=false
needs_restart_scheduler=false

if $RESTART; then
    for f in "${TO_SYNC[@]}"; do
        for trigger in "${WEB_TRIGGERS[@]}"; do
            if [[ "${f}" == "${trigger}" || "${f}" == "${trigger}"* ]]; then
                needs_restart_web=true
                break
            fi
        done
        for trigger in "${SCHEDULER_TRIGGERS[@]}"; do
            if [[ "${f}" == "${trigger}" || "${f}" == "${trigger}"* ]]; then
                needs_restart_scheduler=true
                break
            fi
        done
        # Short-circuit once both are flagged
        if $needs_restart_web && $needs_restart_scheduler; then
            break
        fi
    done
fi

# ── Dry-run output ────────────────────────────────────────────────────────────

if $DRY_RUN; then
    section "Dry run — would sync"
    for f in "${TO_SYNC[@]}"; do
        echo "    ${SOURCE_DIR}/${f}  →  ${DEST_DIR}/${f}"
    done
    echo
    section "Dry run — service restarts"
    if ! $RESTART; then
        warn "  --no-restart set, no services would be restarted."
    else
        $needs_restart_web       && info "  Would restart: pqc-monitor-web"       || warn "  No restart needed: pqc-monitor-web"
        $needs_restart_scheduler && info "  Would restart: pqc-monitor-scheduler" || warn "  No restart needed: pqc-monitor-scheduler"
    fi
    echo
    warn "Dry run complete — no files written, no services restarted."
    exit 0
fi

# ── Sync files ────────────────────────────────────────────────────────────────

section "Syncing"

ERRORS=0
for f in "${TO_SYNC[@]}"; do
    src="${SOURCE_DIR}/${f}"
    dst="${DEST_DIR}/${f}"
    dst_dir="$(dirname "${dst}")"

    if [[ ! -f "${src}" ]]; then
        warn "Source missing (skipping): ${f}"
        continue
    fi

    mkdir -p "${dst_dir}"

    if rsync -a --checksum "${src}" "${dst}"; then
        ok "${f}"
    else
        err "rsync failed for: ${f}"
        (( ERRORS++ )) || true
    fi
done

if [[ ${ERRORS} -gt 0 ]]; then
    err "${ERRORS} file(s) failed to sync."
    exit 1
fi

# ── Restart services (only if their code changed) ─────────────────────────────

if ! $RESTART; then
    warn "Skipping service restart (--no-restart)."
    section "Done"
    ok "Deployed ${#TO_SYNC[@]} file(s) from ${HEAD_HASH:0:7} to ${DEST_DIR}"
    exit 0
fi

if ! $needs_restart_web && ! $needs_restart_scheduler; then
    warn "No Python code changed — skipping service restart."
    section "Done"
    ok "Deployed ${#TO_SYNC[@]} file(s) from ${HEAD_HASH:0:7} to ${DEST_DIR}"
    exit 0
fi

section "Restarting services"

if ! command -v systemctl &>/dev/null; then
    warn "systemctl not found — skipping restart. Restart services manually."
    section "Done"
    ok "Deployed ${#TO_SYNC[@]} file(s) from ${HEAD_HASH:0:7} to ${DEST_DIR}"
    exit 0
fi

restart_service() {
    local svc="$1"
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        if systemctl restart "${svc}"; then
            ok "Restarted ${svc}"
        else
            err "Failed to restart ${svc}"
            (( ERRORS++ )) || true
        fi
    else
        warn "${svc} is not running — skipping restart."
    fi
}

# Web must restart before scheduler (scheduler Requires= web)
$needs_restart_web       && restart_service "pqc-monitor-web"       || warn "No restart needed: pqc-monitor-web"
$needs_restart_scheduler && restart_service "pqc-monitor-scheduler" || warn "No restart needed: pqc-monitor-scheduler"

if [[ ${ERRORS} -gt 0 ]]; then
    exit 1
fi

section "Done"
ok "Deployed ${#TO_SYNC[@]} file(s) from ${HEAD_HASH:0:7} to ${DEST_DIR}"
