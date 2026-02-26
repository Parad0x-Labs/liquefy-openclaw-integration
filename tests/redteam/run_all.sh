#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "=== Liquefy Red-Team P0 Suite ==="
echo ""

echo "[1/4] Building hostile fixtures..."
${PY:-.venv/bin/python} tests/redteam/make_fixtures.py
echo ""

echo "[2/4] CAS / Dedup tests..."
bash tests/redteam/cases/dedup_p0.sh
echo ""

echo "[3/4] Policy Enforcer tests..."
bash tests/redteam/cases/policy_p0.sh
echo ""

echo "[4/4] Halt Channel tests..."
bash tests/redteam/cases/halt_p0.sh
echo ""

echo "=== ALL P0 RED-TEAM TESTS COMPLETE ==="
