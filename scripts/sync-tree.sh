#!/usr/bin/env bash
# PQC-Monitor: Full-tree sync from git checkout to deployment dir
# ================================================================
# Unlike scripts/deploy.sh (which syncs only the files changed in the
# last commit), this compares the ENTIRE working tree against the
# deployment directory and copies every new or changed file.
#
# The file set is taken from `git ls-files` in the source checkout, so
# .git internals and everything matched by .gitignore (runtime DBs,
# scan artefacts, logs, venvs, secrets) are excluded by construction.
#
# Local configuration files in the deployment dir (config/config.yaml,
# .env) are never overwritten unless --force is given. Runtime paths in
# the deployment dir (.venv/, data/*.db, data/scans/, data/trends/,
# logs) are never touched or pruned.
#
# Usage:
#   scripts/sync-tree.sh [OPTIONS]
#
# Options:
#   -s, --source DIR   Git checkout root   (default: parent of this script)
#   -d, --dest   DIR   Deployment target   (default: /opt/pqc-monitor)
#       --sync         Apply changes. Without it the script runs in
#                      AUDIT mode: report only, nothing is written.
#       --force        Also overwrite protected local config files
#       --prune        Delete files in dest that no longer exist in the
#                      repo (in audit mode: report what would be deleted)
#       --restart      Restart affected services after a real sync
#                      (off by default)
#   -h, --help         Show this help
#
# Examples:
#   scripts/sync-tree.sh                       # audit only
#   scripts/sync-tree.sh --prune               # audit incl. orphans
#   sudo scripts/sync-tree.sh --sync           # copy new/changed files
#   sudo scripts/sync-tree.sh --sync --prune --restart
#   sudo scripts/sync-tree.sh --sync --force   # also push config files
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2024 PQC-Monitor Contributors
# AI-assisted development: portions generated with Claude (Anthropic)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST_DIR="/opt/pqc-monitor"
APPLY=false
FORCE=false
PRUNE=false
RESTART=false

# Instance-specific files that must never be overwritten without --force.
PROTECTED=(
    "config/config.yaml"
    ".env"
)

# Dest-side paths that are never synced and never pruned, even with
# --force: runtime state owned by the deployment, not by the repo.
RUNTIME_SKIP=(
    ".venv/"
    "venv/"
    "env/"
    "data/scans/"
    "data/trends/"
    "logs/"
    "__pycache__/"
)
RUNTIME_SKIP_GLOBS=(
    "*.db" "*.sqlite3" "*.log" "*.pyc" "*.pyo" "*.key" "*.pem" "*.p12"
)

# Per-service restart triggers (same prefixes as deploy.sh).
WEB_TRIGGERS=(
    "app_factory.py" "app_routes.py" "version.py" "requirements.txt"
    "admin/" "auth/" "ct/" "dashboard/" "data/" "domain_discovery/"
    "reports/" "roadmap/" "scanner/"
)
SCHEDULER_TRIGGERS=(
    "pqc_monitor.py" "version.py" "requirements.txt"
    "ct/" "data/" "scanner/" "scheduler/"
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
    sed -n '/^# Usage/,/^# SPDX/{ /^# SPDX/d; /^#/{ s/^# \{0,2\}//; p } }' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--source)  SOURCE_DIR="$2"; shift 2 ;;
        -d|--dest)    DEST_DIR="$2";   shift 2 ;;
        --sync)       APPLY=true;      shift ;;
        --force)      FORCE=true;      shift ;;
        --prune)      PRUNE=true;      shift ;;
        --restart)    RESTART=true;    shift ;;
        -h|--help)    usage ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

is_protected() {
    local f="$1" p
    for p in "${PROTECTED[@]}"; do
        [[ "${f}" == "${p}" ]] && return 0
    done
    return 1
}

is_runtime() {
    local f="$1" p g base
    for p in "${RUNTIME_SKIP[@]}"; do
        [[ "${f}" == "${p}"* || "${f}" == *"/${p}"* ]] && return 0
    done
    base="${f##*/}"
    for g in "${RUNTIME_SKIP_GLOBS[@]}"; do
        # shellcheck disable=SC2254
        case "${base}" in ${g}) return 0 ;; esac
    done
    return 1
}

# ── Sanity checks ─────────────────────────────────────────────────────────────

section "Pre-flight"

if ! git -C "${SOURCE_DIR}" rev-parse --is-inside-work-tree &>/dev/null; then
    err "Not a git repository: ${SOURCE_DIR}"
    exit 1
fi
SOURCE_DIR="$(git -C "${SOURCE_DIR}" rev-parse --show-toplevel)"
ok "Source git repo:   ${SOURCE_DIR}"

if [[ ! -d "${DEST_DIR}" ]]; then
    err "Deployment directory does not exist: ${DEST_DIR}"
    exit 1
fi
DEST_DIR="$(cd "${DEST_DIR}" && pwd)"
ok "Deployment target: ${DEST_DIR}"

if [[ "${SOURCE_DIR}" == "${DEST_DIR}" ]]; then
    err "Source and destination are the same directory."
    exit 1
fi

if $APPLY; then
    if [[ ! -w "${DEST_DIR}" ]]; then
        err "No write permission on ${DEST_DIR} — run with sudo."
        exit 1
    fi
    info "Mode: SYNC (files will be written)"
else
    info "Mode: AUDIT (report only, nothing written)"
fi
$FORCE && warn "--force: protected config files WILL be overwritten if they differ."
$PRUNE || info "Orphan files in dest will be ignored (use --prune to remove them)."

# Preserve ownership of the deployment tree when running as root.
DEST_OWNER=""
if [[ ${EUID} -eq 0 ]]; then
    DEST_OWNER="$(stat -c '%U:%G' "${DEST_DIR}")"
    info "New files will be owned by ${DEST_OWNER}"
fi

# ── Build the repo file list ──────────────────────────────────────────────────

mapfile -d '' -t REPO_FILES < <(git -C "${SOURCE_DIR}" ls-files -z)

if [[ ${#REPO_FILES[@]} -eq 0 ]]; then
    err "git ls-files returned nothing — is the repo empty?"
    exit 1
fi

# ── Compare trees ─────────────────────────────────────────────────────────────

section "Comparing trees (${#REPO_FILES[@]} tracked files)"

NEW_FILES=(); CHANGED_FILES=(); SKIPPED_PROTECTED=(); FORCED=(); MISSING_SRC=()

for f in "${REPO_FILES[@]}"; do
    src="${SOURCE_DIR}/${f}"
    dst="${DEST_DIR}/${f}"

    # Tracked but deleted/uncommitted-removed in the working tree
    if [[ ! -f "${src}" ]]; then
        MISSING_SRC+=("${f}")
        continue
    fi

    if is_protected "${f}"; then
        if [[ -f "${dst}" ]] && ! cmp -s "${src}" "${dst}"; then
            if $FORCE; then FORCED+=("${f}"); else SKIPPED_PROTECTED+=("${f}"); fi
        elif [[ ! -f "${dst}" ]]; then
            if $FORCE; then FORCED+=("${f}"); else SKIPPED_PROTECTED+=("${f}"); fi
        fi
        continue
    fi

    if [[ ! -f "${dst}" ]]; then
        NEW_FILES+=("${f}")
    elif ! cmp -s "${src}" "${dst}"; then
        CHANGED_FILES+=("${f}")
    fi
done

# Orphans: files in dest that are neither tracked in the repo nor
# runtime/protected state.
ORPHANS=()
if $PRUNE; then
    declare -A IN_REPO=()
    for f in "${REPO_FILES[@]}"; do IN_REPO["${f}"]=1; done
    while IFS= read -r -d '' d; do
        rel="${d#"${DEST_DIR}"/}"
        [[ -n "${IN_REPO[${rel}]+x}" ]] && continue
        is_protected "${rel}" && continue
        is_runtime "${rel}" && continue
        [[ "${rel}" == .git/* || "${rel}" == .git* ]] && continue
        ORPHANS+=("${rel}")
    done < <(find "${DEST_DIR}" -type f -print0)
fi

# ── Report ────────────────────────────────────────────────────────────────────

if [[ ${#NEW_FILES[@]} -gt 0 ]]; then
    info "${#NEW_FILES[@]} new file(s):"
    printf '    + %s\n' "${NEW_FILES[@]}"
fi
if [[ ${#CHANGED_FILES[@]} -gt 0 ]]; then
    info "${#CHANGED_FILES[@]} changed file(s):"
    printf '    ~ %s\n' "${CHANGED_FILES[@]}"
fi
if [[ ${#FORCED[@]} -gt 0 ]]; then
    warn "${#FORCED[@]} protected file(s) to overwrite (--force):"
    printf '    ! %s\n' "${FORCED[@]}"
fi
if [[ ${#ORPHANS[@]} -gt 0 ]]; then
    warn "${#ORPHANS[@]} orphan(s) in dest (not in repo):"
    printf '    - %s\n' "${ORPHANS[@]}"
fi
if [[ ${#MISSING_SRC[@]} -gt 0 ]]; then
    warn "${#MISSING_SRC[@]} tracked file(s) missing from working tree (skipped):"
    printf '    ? %s\n' "${MISSING_SRC[@]}"
fi

TOTAL=$(( ${#NEW_FILES[@]} + ${#CHANGED_FILES[@]} + ${#FORCED[@]} + ${#ORPHANS[@]} ))
if [[ ${TOTAL} -eq 0 ]]; then
    ok "Trees are in sync — nothing to do."
fi

# ── Protected config file status ──────────────────────────────────────────────

section "Protected local configuration"

for p in "${PROTECTED[@]}"; do
    src="${SOURCE_DIR}/${p}"; dst="${DEST_DIR}/${p}"
    if [[ -f "${src}" && -f "${dst}" ]]; then
        if cmp -s "${src}" "${dst}"; then
            ok "${p} — identical on both sides"
        elif $FORCE; then
            warn "${p} — DIFFERS; --force set, repo copy overwrites local"
        else
            warn "${p} — DIFFERS; local copy preserved (use --force to overwrite)"
        fi
    elif [[ -f "${dst}" ]]; then
        ok "${p} — exists only in dest (local config, untouched)"
    elif [[ -f "${src}" ]]; then
        if $FORCE; then
            warn "${p} — exists only in repo; --force set, will be copied"
        else
            info "${p} — exists only in repo; not copied without --force"
        fi
    else
        info "${p} — not present on either side"
    fi
done

# ── Audit mode stops here ─────────────────────────────────────────────────────

if ! $APPLY; then
    section "Done"
    ok "Audit complete — no files written. Re-run with --sync to apply."
    exit 0
fi

if [[ ${TOTAL} -eq 0 ]]; then
    section "Done"
    exit 0
fi

# ── Apply ─────────────────────────────────────────────────────────────────────

section "Syncing"

copy_file() {
    local rel="$1"
    local src="${SOURCE_DIR}/${rel}" dst="${DEST_DIR}/${rel}"
    local dst_dir; dst_dir="$(dirname "${dst}")"
    mkdir -p "${dst_dir}"
    # -p preserves mode and timestamps; write via temp file + move for
    # atomicity so a running service never sees a half-written module.
    local tmp
    tmp="$(mktemp "${dst_dir}/.sync.XXXXXX")"
    cp -p "${src}" "${tmp}"
    [[ -n "${DEST_OWNER}" ]] && chown "${DEST_OWNER}" "${tmp}"
    mv -f "${tmp}" "${dst}"
}

ERRORS=0
for f in "${NEW_FILES[@]}" "${CHANGED_FILES[@]}" "${FORCED[@]}"; do
    [[ -z "${f}" ]] && continue
    if copy_file "${f}"; then
        ok "${f}"
    else
        err "copy failed: ${f}"
        (( ERRORS++ )) || true
    fi
done

if [[ ${#ORPHANS[@]} -gt 0 ]]; then
    section "Pruning orphans"
    for f in "${ORPHANS[@]}"; do
        if rm -f "${DEST_DIR}/${f}"; then
            ok "removed ${f}"
        else
            err "failed to remove: ${f}"
            (( ERRORS++ )) || true
        fi
    done
    # Clean up directories left empty by pruning (never the root).
    find "${DEST_DIR}" -mindepth 1 -type d -empty -delete 2>/dev/null || true
fi

if [[ ${ERRORS} -gt 0 ]]; then
    err "${ERRORS} operation(s) failed."
    exit 1
fi

# ── Optional service restart ──────────────────────────────────────────────────

if ! $RESTART; then
    section "Done"
    ok "Synced ${#NEW_FILES[@]} new, ${#CHANGED_FILES[@]} changed, ${#FORCED[@]} forced; pruned ${#ORPHANS[@]}."
    warn "Services NOT restarted (pass --restart to enable)."
    exit 0
fi

needs_web=false; needs_sched=false
for f in "${NEW_FILES[@]}" "${CHANGED_FILES[@]}" "${FORCED[@]}"; do
    [[ -z "${f}" ]] && continue
    for t in "${WEB_TRIGGERS[@]}"; do
        [[ "${f}" == "${t}" || "${f}" == "${t}"* ]] && { needs_web=true; break; }
    done
    for t in "${SCHEDULER_TRIGGERS[@]}"; do
        [[ "${f}" == "${t}" || "${f}" == "${t}"* ]] && { needs_sched=true; break; }
    done
    $needs_web && $needs_sched && break
done

section "Restarting services"

if ! command -v systemctl &>/dev/null; then
    warn "systemctl not found — restart services manually."
    exit 0
fi

restart_service() {
    local svc="$1"
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        if systemctl restart "${svc}"; then
            ok "Restarted ${svc}"
        else
            err "Failed to restart ${svc}"
            return 1
        fi
    else
        warn "${svc} is not running — skipping restart."
    fi
}

RC=0
# Web must restart before scheduler (scheduler Requires= web)
if $needs_web;   then restart_service "pqc-monitor-web"       || RC=1
else warn "No restart needed: pqc-monitor-web"; fi
if $needs_sched; then restart_service "pqc-monitor-scheduler" || RC=1
else warn "No restart needed: pqc-monitor-scheduler"; fi

section "Done"
ok "Synced ${#NEW_FILES[@]} new, ${#CHANGED_FILES[@]} changed, ${#FORCED[@]} forced; pruned ${#ORPHANS[@]}."
exit ${RC}
