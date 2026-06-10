#!/usr/bin/env bash
# PQC-Monitor: Installation Script
# Supports both development (local) and production (VM/systemd) install modes.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# AI-assisted development: portions generated with Claude (Anthropic)
#
# Usage:
#   ./install.sh                  Development install (local venv, no systemd)
#   ./install.sh --production     Full production install under /opt/pqc-monitor
#   ./install.sh --demo           Development install + seed demo data
#   ./install.sh --production --demo

set -euo pipefail

# ── Parse arguments ──────────────────────────────────────────────────────────
PRODUCTION=false
SEED_DEMO=false
INSTALL_DIR="/opt/pqc-monitor"
RUN_USER="pqcmonitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
    case $arg in
        --production) PRODUCTION=true ;;
        --demo)       SEED_DEMO=true ;;
        --help|-h)
            echo "Usage: ./install.sh [--production] [--demo]"
            echo ""
            echo "  (no flags)    Development install in .venv/, no systemd"
            echo "  --production  Full install to /opt/pqc-monitor with systemd units"
            echo "  --demo        Seed the database with synthetic demo data"
            exit 0 ;;
    esac
done

# ── Detect version ────────────────────────────────────────────────────────────
VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "unknown")

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  PQC-Monitor v${VERSION} — Installation                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Mode: $([ "$PRODUCTION" = true ] && echo 'PRODUCTION (/opt/pqc-monitor)' || echo 'DEVELOPMENT (local)')"
echo ""

# ── Check Python ─────────────────────────────────────────────────────────────
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3.10+ is required." && exit 1
fi
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "❌ Python 3.10+ required (found $PY_MAJOR.$PY_MINOR)" && exit 1
fi
echo "✓ Python $PY_MAJOR.$PY_MINOR"

# ═══════════════════════════════════════════════════════════════════
# DEVELOPMENT MODE
# ═══════════════════════════════════════════════════════════════════
if [ "$PRODUCTION" = false ]; then
    VENV_DIR="$SCRIPT_DIR/.venv"
    echo "→ Creating virtual environment at $VENV_DIR …"
    "$PYTHON" -m venv "$VENV_DIR"
    PIP="$VENV_DIR/bin/pip"
    PY="$VENV_DIR/bin/python3"

    echo "→ Installing dependencies …"
    "$PIP" install -r "$SCRIPT_DIR/requirements.txt" --quiet

    mkdir -p "$SCRIPT_DIR/data/scans" "$SCRIPT_DIR/data/trends"
    chmod +x "$SCRIPT_DIR/pqc_monitor.py"

    if [ ! -f "$SCRIPT_DIR/config/config.yaml" ]; then
        cp "$SCRIPT_DIR/config/config.yaml.example" "$SCRIPT_DIR/config/config.yaml"
        echo "✓ Config created at config/config.yaml — edit to add API keys"
    fi

    echo "→ Running test suite …"
    "$PY" -m unittest discover -s tests -p 'test_*.py' -q 2>&1 | tail -3

    if [ "$SEED_DEMO" = true ]; then
        echo "→ Seeding demo data …"
        "$PY" "$SCRIPT_DIR/tests/seed_demo_data.py" --runs 3
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Development install complete!                           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  source .venv/bin/activate"
    echo "  python3 pqc_monitor.py dashboard"
    echo "  → http://localhost:5000"
    echo "  → Default admin: username=admin  password=changeme123"
    echo "  ⚠  Change the default password at first login!"
    echo ""
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════
# PRODUCTION MODE
# ═══════════════════════════════════════════════════════════════════
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Production install requires root. Run with sudo." && exit 1
fi

echo "→ Checking dependencies (apt) …"
for pkg in python3-venv python3-dev build-essential; do
    dpkg -s "$pkg" &>/dev/null || apt-get install -y "$pkg" -q
done
echo "✓ System packages OK"

# Create service user
if ! id "$RUN_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
    echo "✓ System user '$RUN_USER' created"
else
    echo "✓ System user '$RUN_USER' already exists"
fi

# Install directory
echo "→ Installing to $INSTALL_DIR …"
install -d -m 755 -o root   -g "$RUN_USER" "$INSTALL_DIR"
install -d -m 750 -o "$RUN_USER" -g "$RUN_USER" "$INSTALL_DIR/data"
install -d -m 750 -o "$RUN_USER" -g "$RUN_USER" "$INSTALL_DIR/data/scans"
install -d -m 750 -o "$RUN_USER" -g "$RUN_USER" "$INSTALL_DIR/data/trends"

# Copy project files (exclude dev artifacts)
rsync -a --delete \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='data/*.db' \
    --exclude='.git' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"

chown -R root:"$RUN_USER" "$INSTALL_DIR"
chmod -R o-rwx "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/pqc_monitor.py"
echo "✓ Files installed to $INSTALL_DIR"

# Virtual environment
echo "→ Creating virtual environment …"
"$PYTHON" -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
echo "✓ Python dependencies installed"

# Configuration
install -d -m 750 -o root -g "$RUN_USER" /etc/pqc-monitor

if [ ! -f /etc/pqc-monitor/config.yaml ]; then
    install -m 640 -o root -g "$RUN_USER" \
        "$INSTALL_DIR/config/config.yaml.example" \
        /etc/pqc-monitor/config.yaml
    echo "✓ Config installed at /etc/pqc-monitor/config.yaml"
    echo "  ⚠  Edit /etc/pqc-monitor/config.yaml before starting the service"
else
    echo "✓ Config already exists at /etc/pqc-monitor/config.yaml"
fi

if [ ! -f /etc/pqc-monitor/pqc-monitor.env ]; then
    install -m 640 -o root -g "$RUN_USER" \
        "$INSTALL_DIR/systemd/pqc-monitor.env" \
        /etc/pqc-monitor/pqc-monitor.env
    # Generate a random secret key
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/change-this-to-a-random-64-character-hex-string/$SECRET/" \
        /etc/pqc-monitor/pqc-monitor.env
    echo "✓ Environment file installed at /etc/pqc-monitor/pqc-monitor.env"
    echo "  ℹ  A random PQC_SECRET_KEY was generated automatically"
else
    echo "✓ Environment file already exists"
fi

# Log directory
install -d -m 750 -o "$RUN_USER" -g "$RUN_USER" /var/log/pqc-monitor

# Symlink config into install dir so the app finds it
ln -sfn /etc/pqc-monitor/config.yaml "$INSTALL_DIR/config/config.yaml" 2>/dev/null || true

# Systemd units
echo "→ Installing systemd units …"
for unit in pqc-monitor.target pqc-monitor-web.service pqc-monitor-scheduler.service; do
    install -m 644 "$INSTALL_DIR/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
echo "✓ Systemd units installed"

# Run tests
echo "→ Running test suite …"
cd "$INSTALL_DIR"
sudo -u "$RUN_USER" "$INSTALL_DIR/.venv/bin/python3" \
    -m unittest discover -s tests -p 'test_*.py' -q 2>&1 | tail -3

# Seed demo data if requested
if [ "$SEED_DEMO" = true ]; then
    echo "→ Seeding demo data …"
    sudo -u "$RUN_USER" "$INSTALL_DIR/.venv/bin/python3" \
        "$INSTALL_DIR/tests/seed_demo_data.py" --runs 3
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Production install complete!                            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Edit /etc/pqc-monitor/pqc-monitor.env"
echo "     Set PQC_SECRET_KEY (already generated), SHODAN_API_KEY, ANTHROPIC_API_KEY"
echo ""
echo "  2. Edit /etc/pqc-monitor/config.yaml"
echo "     Review database path, ports, logging level"
echo ""
echo "  3. Configure a reverse proxy (nginx/caddy) to terminate TLS"
echo "     and proxy to http://127.0.0.1:5000"
echo "     See the README for a sample nginx config"
echo ""
echo "  4. Start the services:"
echo "     sudo systemctl enable --now pqc-monitor.target"
echo ""
echo "  5. Check status:"
echo "     sudo systemctl status pqc-monitor-web"
echo "     sudo systemctl status pqc-monitor-scheduler"
echo "     journalctl -u pqc-monitor-web -f"
echo ""
echo "  Default admin: username=admin  password=changeme123"
echo "  ⚠  CHANGE THIS IMMEDIATELY after first login at /change-password"
echo ""
