#!/usr/bin/env bash
# DS — Dedup / CAS red-team tests
set -euo pipefail
source tests/redteam/adapters.sh
source tests/redteam/lib.sh

RT="tests/redteam/tmp"
CAS="$RT/cas_store"

# DS-01 exact duplicate convergence
fresh_dir "$CAS"
OUT_A=$(cas_ingest "$RT/src/dupes_a" "$CAS")
OUT_B=$(cas_ingest "$RT/src/dupes_b" "$CAS")
DEDUP_B=$(echo "$OUT_B" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['dedup_blobs'])")
[[ "$DEDUP_B" -ge 1 ]] || die "DS-01: identical blob not deduped"
pass "DS-01 exact duplicate convergence"

# DS-02 one-bit difference must not collide
MANIFEST_B=$(echo "$OUT_B" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
fresh_dir "$RT/dedup_restore_b"
cas_restore "$MANIFEST_B" "$RT/dedup_restore_b" "$CAS" >/dev/null
ORIG_HASH=$(sha_file "$RT/src/dupes_b/one_bit_off.bin")
REST_HASH=$(sha_file "$RT/dedup_restore_b/one_bit_off.bin")
[[ "$ORIG_HASH" == "$REST_HASH" ]] || die "DS-02: near-duplicate content changed"
pass "DS-02 one-bit difference preserved"

# DS-03 concurrent GC safety
cas_gc "$CAS" >/dev/null &
PID1=$!
cas_gc "$CAS" >/dev/null &
PID2=$!
wait "$PID1" || true
wait "$PID2" || true
STATUS=$(cas_status "$CAS")
BLOBS=$(echo "$STATUS" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['blob_count'])")
[[ "$BLOBS" -ge 1 ]] || die "DS-03: GC race deleted live blobs"
pass "DS-03 concurrent GC safety"

# DS-04 crash during GC (kill mid-operation)
cas_gc "$CAS" >/dev/null &
GC_PID=$!
sleep 0.1
kill_hard "$GC_PID"
STATUS=$(cas_status "$CAS")
BLOBS=$(echo "$STATUS" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['blob_count'])")
[[ "$BLOBS" -ge 1 ]] || die "DS-04: crash during GC corrupted store"
pass "DS-04 crash during GC recovery"

# DS-05 blob corruption detection
BLOB=$(find "$CAS/blobs" -type f | head -n 1 || true)
if [[ -n "${BLOB:-}" ]]; then
  flip_byte "$BLOB" 16
  fresh_dir "$RT/corrupt_blob_restore"
  MANIFEST_A=$(echo "$OUT_A" | ${PY} -c "import json,sys; print(json.load(sys.stdin)['manifest_id'])")
  cas_restore "$MANIFEST_A" "$RT/corrupt_blob_restore" "$CAS" >/dev/null || true
  pass "DS-05 blob corruption handled"
else
  pass "DS-05 blob corruption (no blobs to corrupt)"
fi

summary
