#  COMPRESSION CODEC GOLDEN RULES

## Enterprise-Grade Testing Framework

*Last Updated: December 25, 2025*

---

##  MISSION STATEMENT

**Golden Rules ensure your compression codec is production-ready:**

-  **Bit-perfect lossless** (not "mostly lossless")
-  **Bulletproof reliability** (no silent corruption)
-  **Auditable performance** (no marketing hype)
-  **Cross-platform compatibility** (works everywhere)
-  **Enterprise-grade robustness** (handles edge cases)

**If your codec fails ANY Golden Rule check, it is NOT production-ready.**

---

## 1.  BIT-PERFECT IDENTITY CHECKS

### Must-Pass Requirements (No Exceptions)

#### A. Size Equality
```bash
# Original size must equal restored size
orig_bytes == restored_bytes
```
**Failure:** Silent truncation, padding, or corruption

#### B. Cryptographic Hash Equality
```bash
# Multiple algorithms to silence skeptics
sha256(original) == sha256(restored)
blake3(original) == blake3(restored)
sha512(original) == sha512(restored)  # Optional but recommended
```
**Failure:** Any bit corruption, regardless of "visual" appearance

#### C. Byte-for-Byte Comparison
```bash
# Platform-independent diff
cmp original restored  # Unix
fc /b original restored  # Windows
diff -q original restored  # Alternative
```
**Failure:** Any single bit difference

#### D. Deterministic Decode
```bash
# Same input archive  same output hash (always)
decode(archive)  hash1
decode(archive)  hash2
assert hash1 == hash2

# Cross-platform determinism
decode_on_windows(archive)  hash_win
decode_on_linux(archive)  hash_linux
assert hash_win == hash_linux
```

---

## 2.  FORMAT-LEVEL INTEGRITY CHECKS

### Filetype-Aware Validation

#### Text Logs / CSV / JSONL
```python
# Structure preservation
orig_lines = count_lines(original)
restored_lines = count_lines(restored)
assert orig_lines == restored_lines

# Encoding preservation
orig_encoding = detect_encoding(original)
restored_encoding = detect_encoding(restored)
assert orig_encoding == restored_encoding

# Newline style preservation
orig_newlines = detect_newlines(original)  # \n vs \r\n
restored_newlines = detect_newlines(restored)
assert orig_newlines == restored_newlines

# Whitespace preservation
# Critical for logs: tabs/spaces/trailing spaces
assert whitespace_preserved(original, restored)
```

#### JSON / XML (If Lossless Claimed)
```python
# DON'T parse and re-serialize - that breaks lossless
# Check raw bytes only
assert json_bytes_identical(original, restored)

# Optional: Schema validation if available
# But NEVER reserialize - that's not lossless
```

#### Binary Formats
```python
# Magic bytes preservation
orig_magic = original[:16]
restored_magic = restored[:16]
assert orig_magic == restored_magic

# Format-specific validation
if format == "PNG":
    assert pngcheck_valid(restored)
elif format == "ZIP":
    assert zip_integrity_check(restored)
elif format == "PDF":
    assert pdf_structure_valid(restored)
```

---

## 3.  ARCHIVE-LEVEL CHECKS

### Container Format Validation

#### A. Header Sanity
```python
# Archive format validation
magic, version = parse_header(archive)
assert magic == EXPECTED_MAGIC
assert version in SUPPORTED_VERSIONS

# Metadata consistency
meta_len = read_metadata_length(archive)
assert 0 < meta_len < MAX_SANE_SIZE

# Block count validation
block_count = read_block_count(archive)
index_count = len(read_index(archive))
assert block_count == index_count
```

#### B. Block Integrity (Critical for Chunking)
```python
for each_block in archive:
    # Stored metadata validation
    stored_uncompressed_len = block.uncompressed_len
    stored_compressed_len = block.compressed_len
    stored_hash = block.hash  # SHA256 or BLAKE3

    # Runtime validation
    actual_compressed_len = len(block.compressed_data)
    assert actual_compressed_len == stored_compressed_len

    decompressed = decompress(block.compressed_data)
    actual_uncompressed_len = len(decompressed)
    assert actual_uncompressed_len == stored_uncompressed_len

    actual_hash = sha256(decompressed)
    assert actual_hash == stored_hash

# Overall file validation
final_hash = sha256(full_restored_file)
assert final_hash == stored_file_hash
```

#### C. Negative Tests (Credibility Boost)
```python
# Bit flip test
corrupted = flip_bit(archive, position=archive.size//2)
try:
    decode(corrupted)
    assert False, "Should have failed on bit flip"
except CorruptionError:
    pass  # Expected

# Truncation test
truncated = archive[:-1000]  # Remove last 1000 bytes
try:
    decode(truncated)
    assert False, "Should have failed on truncation"
except TruncationError:
    pass  # Expected

# Index corruption test
bad_archive = corrupt_index_offset(archive)
try:
    decode(bad_archive)
    assert False, "Should have failed on index corruption"
except IndexError:
    pass  # Expected
```

---

## 4.  FUZZ + PROPERTY TESTS

### Quick but Comprehensive Edge Case Testing

#### A. Random Payload Tests
```python
test_sizes = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 255, 256, 4096, 65536, 1048576]  # 1MB

for size in test_sizes:
    payload = random_bytes(size)
    compressed = compress(payload)
    restored = decompress(compressed)
    assert payload == restored, f"Failed on {size} byte payload"
```

#### B. Structured Adversarial Tests
```python
# Highly repetitive
payload = b"A" * 1000000
assert roundtrip_compress(payload)

# High entropy
payload = crypto_random_bytes(1000000)
assert roundtrip_compress(payload)

# Patterned data
payload = b"ABABAB" * 100000
assert roundtrip_compress(payload)

# Real log edge cases
payload = create_log_with_edge_cases()  # Very long lines, embedded NUL, etc.
assert roundtrip_compress(payload)
```

#### C. Crash-Only Tests
```python
# Empty file
try:
    decode(b"")
    assert False, "Should reject empty file"
except EmptyFileError:
    pass

# Wrong magic
bad_magic = EXPECTED_MAGIC[::-1] + archive[4:]
try:
    decode(bad_magic)
    assert False, "Should reject wrong magic"
except BadMagicError:
    pass

# Memory safety (don't explode)
huge_size_archive = create_archive_with_huge_declared_size()
try:
    decode(huge_size_archive)
    assert False, "Should reject impossible sizes"
except SizeError:
    pass
```

---

## 5.  PERFORMANCE & TRUTH-IN-ADVERTISING CHECKS

### No Marketing Hype - Only Facts

#### A. Correct Size Reporting
```python
# Standard methodology
original_bytes = len(original)
compressed_bytes = len(archive)
ratio = original_bytes / compressed_bytes  # 10.5x, not "10.5x faster"
savings_percent = (1 - compressed_bytes/original_bytes) * 100  # 90.5%

# Report all three
print(f"Original: {original_bytes:,} bytes")
print(f"Compressed: {compressed_bytes:,} bytes")
print(f"Ratio: {ratio:.2f}x ({savings_percent:.1f}% smaller)")
```

#### B. Proper Timing Methodology
```python
import time

# Warm-up run (JIT compilation, cache effects)
compress(original)  # Discard result

# Real timing (3 runs, report mean/min/max)
times = []
for _ in range(3):
    start = time.monotonic()
    result = compress(original)
    end = time.monotonic()
    times.append(end - start)

mean_time = sum(times) / len(times)
min_time = min(times)
max_time = max(times)

throughput = len(original) / mean_time / 1024 / 1024  # MB/s

print(f"Time: {mean_time:.3f}s (min: {min_time:.3f}, max: {max_time:.3f})")
print(f"Throughput: {throughput:.1f} MB/s")
```

#### C. Environment Disclosure
```python
import platform
import sys

print(f"OS: {platform.system()} {platform.release()}")
print(f"Python: {sys.version}")
print(f"CPU: {platform.processor()}")
print(f"RAM: {get_total_ram()} GB")
```

---

## 6.  PUBLIC-PROOF OUTPUT TEMPLATE

### What Every Demo Should Print

```
COMPRESSION CODEC VERIFICATION REPORT
=====================================

File: telemetry.jsonl (detected: JSONL)
Original: 4,194,441 bytes
SHA256: a1b2c3d4e5f6...
BLAKE3: x9y8z7w6v5u4...

Archive: telemetry.nulla (codec: NULLA v4.0)
Compressed: 312,389 bytes
SHA256: f6e5d4c3b2a1...

Restored: telemetry.restored.jsonl
Restored: 4,194,441 bytes
SHA256: a1b2c3d4e5f6...
BLAKE3: x9y8z7w6v5u4...

Byte Comparison: IDENTICAL
Ratio: 13.4x (92.5% smaller)
Savings: 3.2MB  241KB

Text Validation:
Lines: 23,922
Encoding: UTF-8
Newlines: LF (\n)

Archive Structure:
Blocks: 1
Header: Valid
Index: Consistent

Negative Tests:
Bit flip: Detected
Truncation: Detected
Index corruption: Detected

Performance (3-run average):
Compression: 2.1 MB/s (1.89s)
Decompression: 8.9 MB/s (0.47s)

Environment:
OS: Ubuntu 22.04 LTS
Python: 3.10.6
CPU: AMD Ryzen 9 5900X
RAM: 32 GB

VERIFICATION:  PASSED - ENTERPRISE READY
```

---

## 7.  NEXT UPGRADE PRIORITIES

### Highest ROI Improvements (Do These Next)

1. **Per-Block Hash Verification** - Catches localized corruption
2. **Negative Test Automation** - Bitflip/truncate must fail
3. **Cross-Platform Testing** - Windows  Linux verification
4. **Encoding Preservation** - UTF-8/Latin-1/BOM validation
5. **Fuzz Testing Framework** - Random payloads + edge cases

---

##  IMPLEMENTATION CHECKLIST

### Current Status
- [ ] Bit-perfect identity checks
- [ ] Format-level integrity
- [ ] Archive-level validation
- [ ] Fuzz testing framework
- [ ] Performance methodology
- [ ] Public-proof reporting
- [ ] Cross-platform testing

### Ready for Production When:
- [ ]  All Golden Rules pass
- [ ]  3rd party verification possible
- [ ]  Performance independently reproducible
- [ ]  No known failure modes

---

##  CONCLUSION

**Golden Rules transform "works on my machine" into "enterprise-grade software".**

**Follow them religiously. Your users' data depends on it.**

*Remember: The first time someone loses data due to a "minor bug" you didn't catch, they will never trust your code again.*

**Be Golden. Be Reliable. Be Trustworthy.**
