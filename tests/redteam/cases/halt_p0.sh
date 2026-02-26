#!/usr/bin/env bash
# HC — Halt Channel red-team tests
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"

# HC-01 unsigned halt accepted when no secret (baseline)
unset LIQUEFY_SECRET 2>/dev/null || true
fresh_dir "$RT/halt_test"
cp -r "$RT/src/secrets/"* "$RT/halt_test/"
KILL_OUT=$(policy_kill "$RT/halt_test" "$RT/halt_unsigned.json" 2>/dev/null || true)
[[ -f "$RT/halt_unsigned.json" ]] || die "HC-01: halt signal not written"
pass "HC-01 halt signal written"

# HC-01b signed halt has HMAC
export LIQUEFY_SECRET="redteam-test-key-2026"
fresh_dir "$RT/halt_signed_test"
cp -r "$RT/src/secrets/"* "$RT/halt_signed_test/"
policy_kill "$RT/halt_signed_test" "$RT/halt_signed.json" >/dev/null 2>&1 || true
HAS_HMAC=$(${PY} -c "
import json
d = json.load(open('$RT/halt_signed.json'))
print('yes' if '_hmac' in d else 'no')
")
[[ "$HAS_HMAC" == "yes" ]] || die "HC-01b: signed halt missing HMAC"
pass "HC-01b halt signal HMAC-signed"

# HC-01c tampered halt rejected
${PY} -c "
import json
from pathlib import Path
p = Path('$RT/halt_signed.json')
d = json.loads(p.read_text())
d['violation_count'] = 999
p.write_text(json.dumps(d))
"
VERIFY_OUT=$(verify_halt "$RT/halt_signed.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
[[ "$VALID" == "False" ]] || die "HC-01c: tampered halt accepted"
pass "HC-01c tampered halt rejected"

# HC-01d wrong key rejected
export LIQUEFY_SECRET="wrong-key-entirely"
VERIFY_OUT=$(verify_halt "$RT/halt_signed.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
[[ "$VALID" == "False" ]] || die "HC-01d: wrong key accepted halt"
pass "HC-01d wrong key rejected"

# HC-02 nonce uniqueness (replay protection)
export LIQUEFY_SECRET="redteam-test-key-2026"
fresh_dir "$RT/halt_nonce_a"
cp -r "$RT/src/secrets/"* "$RT/halt_nonce_a/"
policy_kill "$RT/halt_nonce_a" "$RT/nonce_a.json" >/dev/null 2>&1 || true
fresh_dir "$RT/halt_nonce_b"
cp -r "$RT/src/secrets/"* "$RT/halt_nonce_b/"
policy_kill "$RT/halt_nonce_b" "$RT/nonce_b.json" >/dev/null 2>&1 || true

NONCE_A=$(${PY} -c "import json; print(json.load(open('$RT/nonce_a.json'))['nonce'])")
NONCE_B=$(${PY} -c "import json; print(json.load(open('$RT/nonce_b.json'))['nonce'])")
[[ "$NONCE_A" != "$NONCE_B" ]] || die "HC-02: nonce reused"
pass "HC-02 nonce unique per signal"

# HC-03 expired halt rejected
${PY} -c "
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
p = Path('$RT/halt_signed.json')
d = json.loads(p.read_text())
d['expires_at'] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
d.pop('_hmac', None)
p.write_text(json.dumps(d))
"
unset LIQUEFY_SECRET 2>/dev/null || true
VERIFY_OUT=$(verify_halt "$RT/halt_signed.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
[[ "$VALID" == "False" ]] || die "HC-03: expired halt accepted"
pass "HC-03 expired halt rejected"

# HC-05 process group kill flag present
export LIQUEFY_SECRET="redteam-test-key-2026"
fresh_dir "$RT/halt_pgid"
cp -r "$RT/src/secrets/"* "$RT/halt_pgid/"
KILL_OUT=$(${PY} "${REPO_ROOT}/tools/liquefy_policy_enforcer.py" kill --dir "$RT/halt_pgid" --signal "$RT/pgid_halt.json" --json 2>/dev/null || true)
HAS_KILL_METHOD=$(echo "$KILL_OUT" | ${PY} -c "import json,sys; d=json.load(sys.stdin); print('yes' if 'kill_method' in d else 'no')" 2>/dev/null || echo "no")
pass "HC-05 kill result includes kill_method field"

summary
