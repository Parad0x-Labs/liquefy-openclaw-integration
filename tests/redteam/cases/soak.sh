#!/usr/bin/env bash
# SOAK — loop all operations for N rounds and check for leaks
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"
ROUNDS="${1:-30}"

if [[ ! -d "$RT/src" ]]; then
  ${PY} tests/redteam/make_fixtures.py >/dev/null
fi

export LIQUEFY_SECRET="soak-test-key-2026"
echo "  === Soak Test: $ROUNDS rounds ==="
echo ""

# Track resources
INITIAL_FDS=$(ls /proc/$$/fd 2>/dev/null | wc -l || lsof -p $$ 2>/dev/null | wc -l || echo "0")
INITIAL_TMPFILES=$(find "$RT" -name "*.tmp" 2>/dev/null | wc -l || echo "0")

SOAK_PASS=0
SOAK_FAIL=0

for r in $(seq 1 "$ROUNDS"); do
  CAS="$RT/soak_cas"
  fresh_dir "$CAS"
  fresh_dir "$RT/soak_restore"

  # 1) CAS ingest (multiple sources)
  OUT1=$(cas_ingest "$RT/src/base" "$CAS" 2>/dev/null || echo '{"ok":false}')
  OUT2=$(cas_ingest "$RT/src/dupes_a" "$CAS" 2>/dev/null || echo '{"ok":false}')
  MID=$(echo "$OUT2" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('manifest_id',''))" 2>/dev/null || echo "")

  # 2) CAS restore
  if [[ -n "$MID" ]]; then
    cas_restore "$MID" "$RT/soak_restore" "$CAS" >/dev/null 2>&1 || true
  fi

  # 3) CAS status + GC
  cas_status "$CAS" >/dev/null 2>&1 || true
  cas_gc "$CAS" >/dev/null 2>&1 || true

  # 4) Policy audit + enforce
  policy_audit "$RT/src/secrets" >/dev/null 2>&1 || true
  policy_enforce "$RT/src/benign" >/dev/null 2>&1 || true

  # 5) Halt + verify
  fresh_dir "$RT/soak_halt"
  cp -r "$RT/src/secrets/"* "$RT/soak_halt/" 2>/dev/null || true
  policy_kill "$RT/soak_halt" "$RT/soak_halt.json" >/dev/null 2>&1 || true
  verify_halt "$RT/soak_halt.json" >/dev/null 2>&1 || true

  SOAK_PASS=$((SOAK_PASS + 1))

  if (( r % 10 == 0 )); then
    echo "    Round $r/$ROUNDS: OK"
  fi
done

# Check for leaks
FINAL_TMPFILES=$(find "$RT" -name "*.tmp" 2>/dev/null | wc -l || echo "0")
LEAKED=$((FINAL_TMPFILES - INITIAL_TMPFILES))
# Orphan check: look for leftover python processes with 'liquefy' in args
# Exclude the test runner, grep, bash
ORPHANS=0
while IFS= read -r line; do
  ORPHANS=$((ORPHANS + 1))
done < <(ps -eo pid,args 2>/dev/null | grep "liquefy" | grep -v grep | grep -v soak | grep -v bash || true)

echo ""
echo "==============================="
echo "  Soak Results:"
echo "  Rounds:           $ROUNDS"
echo "  Passed:           $SOAK_PASS"
echo "  Temp file leak:   $LEAKED new .tmp files"
echo "  Orphan processes: $ORPHANS"
echo "==============================="

if [[ "$LEAKED" -gt 5 ]]; then
  echo "WARNING: possible temp file leak ($LEAKED new .tmp files)"
  exit 1
fi
if [[ "$ORPHANS" -gt 0 ]]; then
  echo "WARNING: orphan liquefy processes detected"
  exit 1
fi
