#!/usr/bin/env bash
# PQC-Monitor: Linux Install Script
# SPDX-License-Identifier: GPL-3.0-or-later
# AI-assisted development: portions generated with Claude (Anthropic)
#
# Usage:
#   chmod +x install.sh && ./install.sh
#   ./install.sh --venv          (use a virtualenv instead of system pip)
#   ./install.sh --demo          (seed demo data after install)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
USE_VENV=false
SEED_DEMO=false

# ─── Parse args ─────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --venv)  USE_VENV=true ;;
        --demo)  SEED_DEMO=true ;;
        --help)
            echo "Usage: ./install.sh [--venv] [--demo]"
            echo "  --venv   Create a Python virtualenv in .venv/"
            echo "  --demo   Seed demo data after installation"
            exit 0 ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  PQC-Monitor — Installation                      ║"
echo "║  Post-Quantum Cryptography Readiness Scanner     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Check Python ────────────────────────────────────────────────
PYTHON=$(command -v python3 || command -v python || true)
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3.10+ is required but not found."
    exit 1
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "❌ Python 3.10+ required (found $PY_VERSION)"
    exit 1
fi
echo "✓ Python $PY_VERSION"

# ─── Optional virtualenv ─────────────────────────────────────────
if [ "$USE_VENV" = true ]; then
    echo "→ Creating virtualenv at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
    PYTHON="$VENV_DIR/bin/python3"
    PIP="$VENV_DIR/bin/pip"
    echo "✓ Virtualenv created. Activate with: source .venv/bin/activate"
else
    PIP=$(command -v pip3 || command -v pip || true)
    if [ -z "$PIP" ]; then
        echo "❌ pip not found. Install pip or use --venv flag."
        exit 1
    fi
fi

# ─── Install dependencies ────────────────────────────────────────
echo ""
echo "→ Installing Python dependencies..."
"$PIP" install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "✓ Dependencies installed"

# ─── Create data directories ─────────────────────────────────────
mkdir -p "$SCRIPT_DIR/data/scans" "$SCRIPT_DIR/data/trends"
echo "✓ Data directories created"

# ─── Config ──────────────────────────────────────────────────────
CONFIG_FILE="$SCRIPT_DIR/config/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    cp "$SCRIPT_DIR/config/config.yaml.example" "$CONFIG_FILE" 2>/dev/null || true
    echo "✓ Config created at config/config.yaml — edit to add API keys"
else
    echo "✓ Config file already exists"
fi

# ─── Make CLI executable ─────────────────────────────────────────
chmod +x "$SCRIPT_DIR/pqc_monitor.py"
echo "✓ pqc_monitor.py is executable"

# ─── Run tests ───────────────────────────────────────────────────
echo ""
echo "→ Running unit tests..."
"$PYTHON" -m unittest discover -s tests -p 'test_*.py' -v 2>&1 | grep -E '(OK|FAIL|ERROR|ok|FAIL)' | tail -5
echo "✓ Tests complete"

# ─── Seed demo data ──────────────────────────────────────────────
if [ "$SEED_DEMO" = true ]; then
    echo ""
    echo "→ Seeding demo data..."
    "$PYTHON" "$SCRIPT_DIR/tests/seed_demo_data.py" --runs 3
fi

# ─── Done ────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Installation complete!                           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Quick start:"
echo ""
echo "  # Discover domains for a sector/region"
echo "  python3 pqc_monitor.py discover 'financial institutions in Spain'"
echo ""
echo "  # Scan a domain list"
echo "  python3 pqc_monitor.py scan --domains domains.txt"
echo ""
echo "  # Launch dashboard"
echo "  python3 pqc_monitor.py dashboard"
echo "  # → open http://localhost:5000"
echo ""
echo "Optional:"
echo "  Set SHODAN_API_KEY env var to enable Shodan-powered scanning"
echo "  Set ANTHROPIC_API_KEY env var to enable AI domain discovery"
echo ""
