#!/usr/bin/env bash
# PE — Policy Enforcer red-team tests
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"

# PE-01 known secret corpus detection
if expect_failure policy_enforce "$RT/src/secrets"; then
  pass "PE-01 known secrets blocked"
else
  die "PE-01: policy enforcer did not block known secrets"
fi

# PE-02 JWT detection
if expect_failure policy_enforce "$RT/src/secrets"; then
  pass "PE-02 JWT/multiline secrets detected"
else
  die "PE-02: JWT not detected"
fi

# PE-04 false positive budget (benign corpus must pass)
if expect_success policy_enforce "$RT/src/benign"; then
  pass "PE-04 benign corpus allowed"
else
  die "PE-04: false positive on benign corpus"
fi

# PE-05 audit mode reports but doesn't block
AUDIT_OUT=$(policy_audit "$RT/src/secrets" 2>/dev/null || true)
VIOLATIONS=$(echo "$AUDIT_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('violations',0))")
[[ "$VIOLATIONS" -gt 0 ]] || die "PE-05: audit mode missed violations"
pass "PE-05 audit mode reports violations"

# PE-06 enforce blocks on critical/high
if expect_failure policy_enforce "$RT/src/secrets"; then
  pass "PE-06 enforce mode blocks critical"
else
  die "PE-06: enforce did not block"
fi

summary
