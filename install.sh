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
if ! "$VENV_DIR/bin/python" -m pip install -U pip >/dev/null 2>&1; then
  echo "[WARN] pip upgrade skipped; continuing with the existing installer toolchain." >&2
fi
if ! "$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/requirements.txt"; then
  echo "[WARN] Dependency sync failed; keeping the existing virtualenv package set." >&2
fi
if "$VENV_DIR/bin/python" -c "import wheel" >/dev/null 2>&1; then
  echo "[STEP] Installing local package metadata..."
  if ! "$VENV_DIR/bin/python" -m pip install --quiet --no-build-isolation "$ROOT_DIR"; then
    echo "[WARN] Local package install failed; using source shims only." >&2
  fi
fi

install_python_shim() {
  local shim_name="$1"
  local module_path="$2"
  local shim_path="$VENV_DIR/bin/$shim_name"
  cat > "$shim_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$ROOT_DIR"
PYTHON_BIN="$VENV_DIR/bin/python"
if [ ! -x "\$PYTHON_BIN" ]; then
  PYTHON_BIN="${PYTHON_BIN}"
fi
exec "\$PYTHON_BIN" "\$ROOT_DIR/$module_path" "\$@"
EOF
  chmod +x "$shim_path"
}

echo "[STEP] Installing local CLI shims..."
install_python_shim "liquefy" "tools/liquefy_cli.py"
install_python_shim "liquefy-safe-run" "tools/liquefy_safe_run.py"
install_python_shim "liquefy-context-gate" "tools/liquefy_context_gate.py"

chmod +x "$ROOT_DIR/liquefy" || true
chmod +x "$ROOT_DIR/tools/"*.py 2>/dev/null || true

echo "[STEP] Running Liquefy self-test..."
if ! "$VENV_DIR/bin/python" "$ROOT_DIR/tools/liquefy_cli.py" self-test --json >/dev/null; then
  echo "[ERROR] Liquefy self-test failed after bootstrap." >&2
  exit 1
fi

cat <<EOF

[OK] Liquefy source install complete.

Next steps:
  source "$VENV_DIR/bin/activate"
  liquefy self-test --json
  liquefy context-gate --help
  ./liquefy openclaw --workspace ~/.openclaw --out ./openclaw-vault

Notes:
  - This is the source install path (works today).
  - The activated venv exposes: liquefy, liquefy-safe-run, liquefy-context-gate.
  - Prebuilt zero-setup binaries are produced via GitHub Releases when release artifacts are published.
EOF
