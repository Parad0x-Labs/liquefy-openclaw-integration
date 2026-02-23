#!/usr/bin/env bash
set -euo pipefail

# Simple local source install bootstrap (macOS/Linux).
# Creates a venv, installs Python deps, and prints next commands.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${LIQUEFY_VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Install Python 3.11+ and rerun." >&2
  exit 1
fi

echo "[INFO] Liquefy local install bootstrap"
echo "[INFO] Repo: $ROOT_DIR"
echo "[INFO] Venv: $VENV_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "[STEP] Creating virtualenv..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

echo "[STEP] Installing Python dependencies..."
"$VENV_DIR/bin/python" -m pip install -U pip >/dev/null
"$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/requirements.txt"

chmod +x "$ROOT_DIR/liquefy" || true
chmod +x "$ROOT_DIR/tools/"*.py 2>/dev/null || true

cat <<EOF

[OK] Liquefy source install complete.

Next steps:
  source "$VENV_DIR/bin/activate"
  python tools/liquefy_openclaw.py --self-test --json
  ./liquefy openclaw --workspace ~/.openclaw --out ./openclaw-vault

Notes:
  - This is the source install path (works today).
  - Prebuilt zero-setup binaries are produced via GitHub Releases when release artifacts are published.
EOF
