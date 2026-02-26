#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PY:-${REPO_ROOT}/.venv/bin/python}"

PASS_COUNT=0
FAIL_COUNT=0

die() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }

expect_success() {
  if "$@" >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    return 1
  else
    return 0
  fi
}

flip_byte() {
  local file="$1" offset="${2:-0}"
  ${PY} - <<PY
from pathlib import Path
p = Path("$file")
b = bytearray(p.read_bytes())
i = min($offset, max(0, len(b)-1))
b[i] ^= 0x01
p.write_bytes(bytes(b))
PY
}

sha_file() {
  local file="$1"
  ${PY} -c "
import hashlib, sys
h = hashlib.sha256(open('$file','rb').read()).hexdigest()
print(h)
"
}

fresh_dir() {
  local d="$1"
  rm -rf "$d"
  mkdir -p "$d"
}

kill_hard() {
  local pid="$1"
  kill -9 "$pid" 2>/dev/null || true
}

summary() {
  echo ""
  echo "==============================="
  echo "  PASS: $PASS_COUNT"
  echo "  FAIL: $FAIL_COUNT"
  echo "==============================="
  if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
  fi
}
