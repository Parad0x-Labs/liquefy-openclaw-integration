#!/usr/bin/env bash
set -euo pipefail

# Real Liquefy CLI entrypoints
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PY:-${REPO_ROOT}/.venv/bin/python}"
export PYTHONPATH="${REPO_ROOT}/tools:${REPO_ROOT}/api:${PYTHONPATH:-}"

pack_vault() {
  local src="$1" vault="$2"
  ${PY} "${REPO_ROOT}/tools/tracevault_pack.py" "$src" --out "$vault" --json
}

restore_vault() {
  local vault="$1" out="$2"
  ${PY} "${REPO_ROOT}/tools/tracevault_restore.py" "$vault" --out "$out"
}

search_vault() {
  local vault="$1" query="$2"
  ${PY} "${REPO_ROOT}/tools/tracevault_search.py" "$vault" --query "$query" --json
}

policy_audit() {
  local target="$1"
  ${PY} "${REPO_ROOT}/tools/liquefy_policy_enforcer.py" audit --dir "$target" --json
}

policy_enforce() {
  local target="$1"
  ${PY} "${REPO_ROOT}/tools/liquefy_policy_enforcer.py" enforce --dir "$target" --json
}

policy_kill() {
  local target="$1" signal_file="$2"
  ${PY} "${REPO_ROOT}/tools/liquefy_policy_enforcer.py" kill --dir "$target" --signal "$signal_file" --json
}

verify_halt() {
  local signal_file="$1"
  ${PY} "${REPO_ROOT}/tools/liquefy_policy_enforcer.py" verify-halt --signal "$signal_file" --json
}

cas_ingest() {
  local dir="$1" cas_dir="$2"
  ${PY} "${REPO_ROOT}/tools/liquefy_cas.py" ingest --dir "$dir" --cas-dir "$cas_dir" --json
}

cas_restore() {
  local manifest="$1" out="$2" cas_dir="$3"
  ${PY} "${REPO_ROOT}/tools/liquefy_cas.py" restore --manifest "$manifest" --out "$out" --cas-dir "$cas_dir" --json
}

cas_gc() {
  local cas_dir="$1"
  ${PY} "${REPO_ROOT}/tools/liquefy_cas.py" gc --cas-dir "$cas_dir" --json
}

cas_status() {
  local cas_dir="$1"
  ${PY} "${REPO_ROOT}/tools/liquefy_cas.py" status --cas-dir "$cas_dir" --json
}
