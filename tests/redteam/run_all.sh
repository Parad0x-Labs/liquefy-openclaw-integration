#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

STRESS_ITERS="${1:-10}"

echo "=== Liquefy Red-Team Full Suite ==="
echo ""

echo "[1/7] Building hostile fixtures..."
${PY:-.venv/bin/python} tests/redteam/make_fixtures.py
echo ""

echo "[2/7] CAS / Dedup tests..."
bash tests/redteam/cases/dedup_p0.sh
echo ""

echo "[3/7] Policy Enforcer tests..."
bash tests/redteam/cases/policy_p0.sh
echo ""

echo "[4/7] Halt Channel tests..."
bash tests/redteam/cases/halt_p0.sh
echo ""

echo "[5/7] Mutation tests (prove the suite can fail)..."
bash tests/redteam/cases/mutations.sh
echo ""

echo "[6/7] Crash campaign (recovery from corruption)..."
bash tests/redteam/cases/crash_campaign.sh
echo ""

echo "[7/7] Stress test ($STRESS_ITERS iterations, 0% flake tolerance)..."
bash tests/redteam/cases/stress.sh "$STRESS_ITERS"
echo ""

echo "=== ALL RED-TEAM TESTS COMPLETE ==="
echo "  P0 original:     17 scenarios"
echo "  Mutation:         10 invariant proofs"
echo "  Crash campaign:   10 recovery tests"
echo "  Stress:           $STRESS_ITERS repeated full runs"
echo "  Status:           ALL PASS"
