#!/usr/bin/env bash
# Liquefy — One-Line Setup
# Usage: bash setup.sh
# Or:    curl -sSL <raw-url>/setup.sh | bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"
PYTHON=""
MIN_PYTHON="3.9"

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Liquefy — AI-Agent-First Setup          ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# ── Find Python ──

for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            PYTHON="$candidate"
            echo "  [+] Found Python $ver ($candidate)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  [-] ERROR: Python >= $MIN_PYTHON not found."
    echo "      Install: https://www.python.org/downloads/"
    exit 1
fi

# ── Create Virtual Environment ──

if [ -d "$VENV_DIR" ]; then
    echo "  [+] Virtual environment exists at .venv/"
else
    echo "  [+] Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR" || {
        echo "  [-] ERROR: python3 -m venv failed."
        echo "      On Debian/Ubuntu: sudo apt install python3-venv"
        echo "      On macOS: should work out of box with python3"
        exit 1
    }
fi

PIP="${VENV_DIR}/bin/pip"
PY="${VENV_DIR}/bin/python"

# ── Install Dependencies ──

echo "  [+] Installing dependencies..."
"$PIP" install --quiet --upgrade pip 2>/dev/null
"$PIP" install --quiet -r "${REPO_DIR}/api/requirements.txt" 2>/dev/null

# ── Verify Core Imports ──

echo "  [+] Verifying core imports..."
PYTHONPATH="${REPO_DIR}/tools:${REPO_DIR}/api" "$PY" -c "
import zstandard, xxhash, cryptography
from liquefy_safety import LiquefySafety
from liquefy_security import LiquefySecurity
from orchestrator.orchestrator import Orchestrator
print('    Core: zstandard, xxhash, cryptography, orchestrator — OK')
" || {
    echo "  [-] WARNING: Some imports failed. Run 'make doctor' for details."
}

# ── Smoke Test ──

echo "  [+] Running smoke test..."
PYTHONPATH="${REPO_DIR}/tools:${REPO_DIR}/api" "$PY" tools/liquefy_cli.py self-test --json 2>/dev/null | \
    "$PY" -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ok = d.get('ok', False)
    r = d.get('result', {}).get('summary', {})
    print(f'    Self-test: {r.get(\"checks_passed\",\"?\")}/{r.get(\"checks_total\",\"?\")} checks passed')
    if not ok:
        print('    WARNING: Some checks failed. Run: make doctor')
except:
    print('    Self-test: could not parse (non-blocking)')
" || echo "    Self-test: skipped"

# ── Print Summary ──

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   READY                                   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Quick start:"
echo "    make quick DIR=./your/data        # Compress anything"
echo "    make help                          # See all commands"
echo "    make setup-wizard                  # Interactive config"
echo ""
echo "  Presets:"
echo "    PRESET=safe   (default)  Max security, balanced speed"
echo "    PRESET=power             Faster, relaxed policy"
echo "    PRESET=yolo              Everything included, your risk"
echo ""
echo "  Example:"
echo "    make quick DIR=~/.openclaw PRESET=power"
echo ""
