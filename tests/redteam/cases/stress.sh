#!/usr/bin/env bash
# STRESS — run the full suite N times to detect flakes
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

ITERATIONS="${1:-10}"
RT="tests/redteam/tmp"

echo "  === Stress Test: $ITERATIONS iterations ==="
echo ""

PASS_RUNS=0
FAIL_RUNS=0

for i in $(seq 1 "$ITERATIONS"); do
  # Regenerate fixtures each run
  ${PY} tests/redteam/make_fixtures.py >/dev/null 2>&1

  # Run each suite silently
  FAILED=0
  bash tests/redteam/cases/dedup_p0.sh >/dev/null 2>&1 || FAILED=$((FAILED + 1))
  bash tests/redteam/cases/policy_p0.sh >/dev/null 2>&1 || FAILED=$((FAILED + 1))
  bash tests/redteam/cases/halt_p0.sh >/dev/null 2>&1 || FAILED=$((FAILED + 1))
  bash tests/redteam/cases/mutations.sh >/dev/null 2>&1 || FAILED=$((FAILED + 1))

  if [[ "$FAILED" -eq 0 ]]; then
    echo "    Run $i/$ITERATIONS: PASS"
    PASS_RUNS=$((PASS_RUNS + 1))
  else
    echo "    Run $i/$ITERATIONS: FAIL ($FAILED suites failed)"
    FAIL_RUNS=$((FAIL_RUNS + 1))
  fi
done

echo ""
echo "==============================="
echo "  Iterations:  $ITERATIONS"
echo "  Passed:      $PASS_RUNS"
echo "  Failed:      $FAIL_RUNS"
echo "  Flake rate:  $(( FAIL_RUNS * 100 / ITERATIONS ))%"
echo "==============================="

[[ "$FAIL_RUNS" -eq 0 ]] || exit 1
