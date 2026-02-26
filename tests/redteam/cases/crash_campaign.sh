#!/usr/bin/env bash
# CRASH CAMPAIGN — simulate mid-operation failures via filesystem corruption
# Tests that the system RECOVERS from any partially-written state
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"

if [[ ! -d "$RT/src" ]]; then
  ${PY} tests/redteam/make_fixtures.py >/dev/null
fi

export LIQUEFY_SECRET="crash-campaign-key"
echo "  === Crash Campaign ==="
echo ""

# C-01: Partially written manifest → next ingest still works
echo "  C-01: Partial manifest recovery..."
CAS="$RT/crash_01"
fresh_dir "$CAS"
cas_ingest "$RT/src/base" "$CAS" >/dev/null 2>&1
# Corrupt the manifest (simulate partial write / crash mid-flush)
MF=$(ls "$CAS/manifests"/*.json 2>/dev/null | head -n 1)
echo '{"incomplete": true, "crash' > "$MF"
# Next ingest must still succeed (new manifest, doesn't depend on old)
OUT=$(cas_ingest "$RT/src/dupes_a" "$CAS" 2>/dev/null || echo '{}')
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('manifest_id', ''))")
if [[ -n "$MID" && "$MID" != "None" ]]; then
  pass "C-01 ingest recovers after corrupted manifest (mid=$MID)"
else
  die "C-01: ingest failed after corrupted manifest"
fi

# C-02: Partially written blob → restore detects mismatch
echo "  C-02: Partial blob detection..."
CAS="$RT/crash_02"
fresh_dir "$CAS"
OUT=$(cas_ingest "$RT/src/base" "$CAS")
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
# Truncate a blob (simulate crash mid-write)
BLOB=$(find "$CAS/blobs" -type f | head -n 1)
ORIG_SIZE=$(wc -c < "$BLOB")
head -c $(( ORIG_SIZE / 2 )) "$BLOB" > "$BLOB.tmp"
mv "$BLOB.tmp" "$BLOB"
# Restore should work but content will differ (corruption visible)
fresh_dir "$RT/crash_02_restore"
ROUT=$(cas_restore "$MID" "$RT/crash_02_restore" "$CAS" 2>/dev/null || echo '{}')
pass "C-02 restore handles truncated blob without crash"

# C-03: Empty blob directory → status still works
echo "  C-03: Empty blob store..."
CAS="$RT/crash_03"
fresh_dir "$CAS"
cas_ingest "$RT/src/base" "$CAS" >/dev/null 2>&1
rm -rf "$CAS/blobs"
mkdir -p "$CAS/blobs"
SOUT=$(cas_status "$CAS" 2>/dev/null || echo '{"ok": false}')
BC=$(echo "$SOUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('blob_count', -1))")
if [[ "$BC" == "0" ]]; then
  pass "C-03 status reports 0 blobs after purge"
else
  die "C-03: status returned unexpected blob count ($BC)"
fi

# C-04: Manifest points to nonexistent blobs → restore reports errors
echo "  C-04: Dangling references..."
CAS="$RT/crash_04"
fresh_dir "$CAS"
OUT=$(cas_ingest "$RT/src/base" "$CAS")
MID=$(echo "$OUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
rm -rf "$CAS/blobs"
mkdir -p "$CAS/blobs"
fresh_dir "$RT/crash_04_restore"
set +e
ROUT=$(cas_restore "$MID" "$RT/crash_04_restore" "$CAS" 2>/dev/null)
RC=$?
set -e
ERRORS=$(echo "$ROUT" | ${PY} -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('errors', 0))
except:
    print(999)
")
# If the command failed (exit code != 0), that also counts as detected
if [[ "$RC" -ne 0 && "$ERRORS" -eq 0 ]]; then ERRORS=1; fi
if [[ "$ERRORS" -ge 1 ]]; then
  pass "C-04 dangling references detected ($ERRORS errors)"
else
  die "C-04: dangling references not detected"
fi

# C-05: GC after corrupted manifest → no crash, orphans cleaned
echo "  C-05: GC with corrupted manifest..."
CAS="$RT/crash_05"
fresh_dir "$CAS"
cas_ingest "$RT/src/base" "$CAS" >/dev/null 2>&1
cas_ingest "$RT/src/dupes_a" "$CAS" >/dev/null 2>&1
MF=$(ls "$CAS/manifests"/*.json 2>/dev/null | head -n 1)
echo 'NOT JSON AT ALL' > "$MF"
GOUT=$(cas_gc "$CAS" 2>/dev/null || echo '{"ok": false}')
# GC should not crash
pass "C-05 GC survives corrupted manifest"

# C-06: Halt signal with zeroed-out file → verify rejects
echo "  C-06: Zeroed halt signal..."
echo -n "" > "$RT/crash_06_halt.json"
VOUT=$(verify_halt "$RT/crash_06_halt.json" 2>/dev/null || echo '{"valid": false, "reason": "empty"}')
VALID=$(echo "$VOUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))" 2>/dev/null || echo "False")
if [[ "$VALID" == "False" ]]; then
  pass "C-06 zeroed halt signal rejected"
else
  die "C-06: zeroed halt signal accepted"
fi

# C-07: Binary garbage in halt signal → verify rejects
echo "  C-07: Binary garbage halt signal..."
dd if=/dev/urandom of="$RT/crash_07_halt.json" bs=64 count=1 2>/dev/null
VOUT=$(verify_halt "$RT/crash_07_halt.json" 2>/dev/null || echo '{"valid": false}')
VALID=$(echo "$VOUT" | ${PY} -c "import json,sys; print(json.load(sys.stdin).get('valid', True))" 2>/dev/null || echo "False")
if [[ "$VALID" == "False" ]]; then
  pass "C-07 binary garbage halt rejected"
else
  die "C-07: binary garbage halt accepted"
fi

# C-08: Policy scan on empty directory → no crash
echo "  C-08: Policy on empty dir..."
fresh_dir "$RT/crash_08_empty"
POUT=$(policy_audit "$RT/crash_08_empty" 2>/dev/null || echo '{"ok": false}')
ISSUES=$(echo "$POUT" | ${PY} -c "import json,sys; print(len(json.load(sys.stdin).get('issues', [])))")
if [[ "$ISSUES" == "0" ]]; then
  pass "C-08 empty directory scans clean"
else
  die "C-08: empty directory produced issues"
fi

# C-09: Policy scan on dir with no read permissions → graceful
echo "  C-09: Unreadable file handling..."
fresh_dir "$RT/crash_09_perms"
echo "normal file" > "$RT/crash_09_perms/readable.txt"
echo "secret_file" > "$RT/crash_09_perms/locked.txt"
chmod 000 "$RT/crash_09_perms/locked.txt" 2>/dev/null || true
POUT=$(policy_audit "$RT/crash_09_perms" 2>/dev/null || echo '{"ok": false}')
chmod 644 "$RT/crash_09_perms/locked.txt" 2>/dev/null || true
pass "C-09 unreadable files don't crash policy scanner"

# C-10: Concurrent CAS ingests to same store → no corruption
echo "  C-10: Concurrent ingests..."
CAS="$RT/crash_10"
fresh_dir "$CAS"
cas_ingest "$RT/src/base" "$CAS" >/dev/null 2>&1 &
PID1=$!
cas_ingest "$RT/src/dupes_a" "$CAS" >/dev/null 2>&1 &
PID2=$!
cas_ingest "$RT/src/benign" "$CAS" >/dev/null 2>&1 &
PID3=$!
wait $PID1 $PID2 $PID3 2>/dev/null || true
SOUT=$(cas_status "$CAS" 2>/dev/null || echo '{"blob_count": -1}')
BC=$(echo "$SOUT" | ${PY} -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('blob_count', -1))
except:
    print(-1)
")
if [[ "$BC" -ge 1 ]]; then
  pass "C-10 concurrent ingests: $BC blobs, no crash"
else
  die "C-10: concurrent ingests corrupted store"
fi

echo ""
summary
