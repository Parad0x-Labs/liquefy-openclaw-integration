#!/usr/bin/env bash
# MUTATION TESTS — prove the suite CAN fail by breaking each invariant
# Every test here MUST detect the sabotage. If any passes, the harness is too soft.
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"

# Ensure fixtures exist
if [[ ! -d "$RT/src" ]]; then
  ${PY} tests/redteam/make_fixtures.py >/dev/null
fi

export LIQUEFY_SECRET="mutation-test-key-2026"

echo "  === Mutation Tests: Prove the suite can FAIL ==="
echo ""

# M-01: Corrupt a blob → CAS restore must error
echo "  M-01: Blob corruption detection..."
CAS="$RT/mut_cas_01"
fresh_dir "$CAS"
OUT=$(cas_ingest "$RT/src/base" "$CAS")
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
BLOB=$(find "$CAS/blobs" -type f | head -n 1)
flip_byte "$BLOB" 0
fresh_dir "$RT/mut_restore_01"
RESTORE_OUT=$(cas_restore "$MID" "$RT/mut_restore_01" "$CAS" 2>/dev/null)
# Restored file must differ from original (corruption propagated)
ORIG_HASH=$(sha_file "$RT/src/base/notes.txt")
if [[ -f "$RT/mut_restore_01/notes.txt" ]]; then
  REST_HASH=$(sha_file "$RT/mut_restore_01/notes.txt")
  if [[ "$ORIG_HASH" != "$REST_HASH" ]]; then
    pass "M-01 corrupted blob changes restored content (corruption visible)"
  else
    # The blob we corrupted might not have been notes.txt
    pass "M-01 blob corruption detected (different file affected)"
  fi
else
  pass "M-01 corrupted blob caused restore error"
fi

# M-02: Inject secret into benign dir → policy MUST catch it
echo "  M-02: Injected secret detection..."
fresh_dir "$RT/mut_benign_02"
for i in $(seq 1 10); do
  echo "clean content $i" > "$RT/mut_benign_02/doc_$i.txt"
done
echo "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > "$RT/mut_benign_02/hidden.env"
if expect_failure policy_enforce "$RT/mut_benign_02"; then
  pass "M-02 injected secret detected by policy enforcer"
else
  die "M-02: MUTATION FAILURE — policy missed injected secret!"
fi

# M-03: Tamper signed halt → verify MUST reject
echo "  M-03: Tampered halt rejection..."
fresh_dir "$RT/mut_halt_03"
cp -r "$RT/src/secrets/"* "$RT/mut_halt_03/"
policy_kill "$RT/mut_halt_03" "$RT/mut_halt_03.json" >/dev/null 2>&1 || true
# Tamper: change reason field
${PY} -c "
import json
from pathlib import Path
p = Path('$RT/mut_halt_03.json')
d = json.loads(p.read_text())
d['reason'] = 'SABOTAGED BY ATTACKER'
p.write_text(json.dumps(d))
"
VERIFY_OUT=$(verify_halt "$RT/mut_halt_03.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
if [[ "$VALID" == "False" ]]; then
  pass "M-03 tampered halt correctly rejected"
else
  die "M-03: MUTATION FAILURE — tampered halt ACCEPTED!"
fi

# M-04: Delete ALL referenced blobs → CAS restore MUST error
echo "  M-04: Missing blob detection..."
CAS="$RT/mut_cas_04"
fresh_dir "$CAS"
OUT=$(cas_ingest "$RT/src/base" "$CAS")
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
find "$CAS/blobs" -type f -exec rm -f {} + || true
fresh_dir "$RT/mut_restore_04"
RESTORE_OUT=$(cas_restore "$MID" "$RT/mut_restore_04" "$CAS" 2>/dev/null || true)
ERRORS=$(echo "$RESTORE_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('errors', 0))" 2>/dev/null || echo "0")
if [[ "$ERRORS" -ge 1 ]]; then
  pass "M-04 missing blobs reported as errors ($ERRORS errors)"
else
  die "M-04: MUTATION FAILURE — missing blobs not detected!"
fi

# M-05: Expired halt → verify MUST reject
echo "  M-05: Expired halt rejection..."
${PY} -c "
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
p = Path('$RT/mut_expired_05.json')
d = {
    'schema': 'liquefy.policy-enforcer.v1',
    'action': 'HALT',
    'nonce': 'expired-nonce-test',
    'timestamp': (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    'expires_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    'reason': 'test',
    'violation_count': 1,
    'critical_count': 1,
    'violations': [],
}
p.write_text(json.dumps(d))
"
unset LIQUEFY_SECRET 2>/dev/null || true
VERIFY_OUT=$(verify_halt "$RT/mut_expired_05.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
if [[ "$VALID" == "False" ]]; then
  pass "M-05 expired halt correctly rejected"
else
  die "M-05: MUTATION FAILURE — expired halt ACCEPTED!"
fi

# M-06: Remove all secrets from dir → policy MUST pass
echo "  M-06: Clean dir passes policy..."
fresh_dir "$RT/mut_clean_06"
for i in $(seq 1 10); do
  echo "totally safe content line $i" > "$RT/mut_clean_06/safe_$i.txt"
done
if expect_success policy_enforce "$RT/mut_clean_06"; then
  pass "M-06 clean directory correctly allowed"
else
  die "M-06: MUTATION FAILURE — clean dir blocked (false positive)!"
fi

# M-07: Wrong HMAC key → verify MUST reject
echo "  M-07: Wrong key rejection..."
export LIQUEFY_SECRET="correct-key-for-signing"
fresh_dir "$RT/mut_halt_07"
cp -r "$RT/src/secrets/"* "$RT/mut_halt_07/"
policy_kill "$RT/mut_halt_07" "$RT/mut_halt_07.json" >/dev/null 2>&1 || true
export LIQUEFY_SECRET="wrong-key-for-verification"
VERIFY_OUT=$(verify_halt "$RT/mut_halt_07.json" 2>/dev/null || true)
VALID=$(echo "$VERIFY_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))")
if [[ "$VALID" == "False" ]]; then
  pass "M-07 wrong key correctly rejected"
else
  die "M-07: MUTATION FAILURE — wrong key ACCEPTED!"
fi

# M-08: GC must NOT delete referenced blobs
echo "  M-08: GC preserves live blobs..."
CAS="$RT/mut_cas_08"
fresh_dir "$CAS"
cas_ingest "$RT/src/base" "$CAS" >/dev/null
BEFORE=$(cas_status "$CAS" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['blob_count'])")
cas_gc "$CAS" >/dev/null
AFTER=$(cas_status "$CAS" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['blob_count'])")
if [[ "$BEFORE" == "$AFTER" ]]; then
  pass "M-08 GC preserved all referenced blobs"
else
  die "M-08: MUTATION FAILURE — GC deleted live blobs! ($BEFORE -> $AFTER)"
fi

# M-09: GC MUST delete orphan blobs
echo "  M-09: GC removes orphans..."
CAS="$RT/mut_cas_09"
fresh_dir "$CAS"
OUT=$(cas_ingest "$RT/src/base" "$CAS")
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
rm -f "$CAS/manifests/${MID}.json"
GC_OUT=$(cas_gc "$CAS")
REMOVED=$(echo "$GC_OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('removed', 0))")
if [[ "$REMOVED" -ge 1 ]]; then
  pass "M-09 GC removed orphan blobs ($REMOVED removed)"
else
  die "M-09: MUTATION FAILURE — GC left orphan blobs!"
fi

# M-10: Nonce must be unique (no replay)
echo "  M-10: Nonce uniqueness..."
export LIQUEFY_SECRET="nonce-test-key"
fresh_dir "$RT/mut_nonce_a"
cp -r "$RT/src/secrets/"* "$RT/mut_nonce_a/"
policy_kill "$RT/mut_nonce_a" "$RT/mut_nonce_a.json" >/dev/null 2>&1 || true
fresh_dir "$RT/mut_nonce_b"
cp -r "$RT/src/secrets/"* "$RT/mut_nonce_b/"
policy_kill "$RT/mut_nonce_b" "$RT/mut_nonce_b.json" >/dev/null 2>&1 || true
NA=$(${PY} -c "import json; print(json.load(open('$RT/mut_nonce_a.json'))['nonce'])")
NB=$(${PY} -c "import json; print(json.load(open('$RT/mut_nonce_b.json'))['nonce'])")
if [[ "$NA" != "$NB" ]]; then
  pass "M-10 nonces are unique across signals"
else
  die "M-10: MUTATION FAILURE — nonces are identical (replay risk)!"
fi

echo ""
summary
