# Enterprise Evaluation Guide

> **Note:**
> This guide applies to the **licensed enterprise engine (Path B)**.
> If you only need to recover or verify existing archives without compression, use the **Public Decode-Only Appliance (Path C)** instead.

This guide describes how to verify the **Zero-Persistence** and **Bit-Perfect** guarantees of the Liquefy platform using the sealed decoder appliance.

---

## Path C: Public Reference Verification (no license required)

You do **not** need the sealed appliance to independently confirm a Trace Vault
archive is bit-perfect. The repository ships a real, source-visible reference
decoder, [`decompress_local.py`](../decompress_local.py), that reconstructs the
original bytes using the same in-repo engines that packed them and checks them
against the `sha256_original` recorded per-receipt in `tracevault_index.json`.

```bash
# Verify a single .null archive against its recorded original hash (writes nothing).
# Exits non-zero on any mismatch — it prints the real restored hash, never a canned result.
python decompress_local.py vault/run_001/events.jsonl.null --verify-only

# Restore an archive locally (also integrity-checked when a recorded hash exists).
python decompress_local.py vault/run_001/events.jsonl.null -o restored/events.jsonl
```

Notes:
- The decoder auto-discovers `tracevault_index.json` next to the archive to learn
  the `engine_used`, the expected `sha256_original`, and whether the blob is encrypted.
- Encrypted archives require the tenant master secret in `LIQUEFY_SECRET`.
- The decode direction is deterministic / byte-stable, so re-running always
  reproduces identical bytes even though the compress direction is not bit-stable
  across zstd builds.
- Exit codes: `0` verified/restored, `2` hash mismatch, `3` decode failure,
  `4` cannot verify (no recorded hash, or missing decryption secret).

The sealed appliance below (Path B) is a hardened, offline distribution of the
same decode guarantee for enterprise workflows — not a prerequisite for trust.

## Prerequisites

- Docker or Podman installed.
- A valid evaluation license (`liquefy.lic`).
- Access to the `parad0xlabs/liquefy-decoder:eval` container image.

## Step 1: Secure Pull
Pull the latest evaluation image from the authorized registry:

```bash
docker pull parad0xlabs/liquefy-decoder:eval
```

## Step 2: Network-Off Verification
To prove the "Blackbox" is truly autonomous, you can disable all network access before running.

```bash
# Verify integrity without network
docker run --rm --network=none --read-only --cap-drop=ALL \
  -v "$(pwd)":/data:rw \
  -v "$(pwd)/liquefy.lic":/license/liquefy.lic:ro \
  parad0xlabs/liquefy-decoder:eval \
  verify /data/sample_archive.liq --json
```

## Step 3: Local Decompression
Restore your data locally. No data ever leaves your machine.

```bash
docker run --rm --network=none --read-only --cap-drop=ALL \
  -v "$(pwd)":/data:rw \
  -v "$(pwd)/liquefy.lic":/license/liquefy.lic:ro \
  parad0xlabs/liquefy-decoder:eval \
  decompress /data/sample_archive.liq -o /data/restored.log
```

## Step 4: Bit-Perfect Proof
Verify the restored file against your original source hash:

```bash
# Compare hashes locally
sha256sum original_source.log restored.log
```

## Security & Privacy Statement

- **No Source Disclosure:** The production decoder is a hardened binary.
- **No Data Leakage:** The appliance is designed to run with `--network=none`.
- **Read-Only:** The container root filesystem is read-only; it only writes to your mounted data volume.
- **Least Privilege:** The appliance runs as a non-root user with all capabilities dropped.

## Hardened Local Execution (Recommended)

The Liquefy Decoder Appliance is designed to run in a fully isolated, offline mode.

### Linux / macOS (Docker)

```bash
docker run --rm \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  -v "$PWD":/data:rw \
  -v "$PWD/liquefy.lic":/license/liquefy.lic:ro \
  parad0xlabs/liquefy-decoder:eval \
  decompress /data/archive.null -o /data/restored.log
```

### Windows (PowerShell)

```powershell
docker run --rm `
  --network=none `
  --read-only `
  --cap-drop=ALL `
  -v ${PWD}:/data `
  -v ${PWD}\liquefy.lic:/license/liquefy.lic:ro `
  parad0xlabs/liquefy-decoder:eval `
  verify /data/archive.null
```

Notes:
- No outbound network access
- Read-only root filesystem
- Minimal Linux capabilities
- Decoder runs fully offline

---
*Note: The public repository provides documentation and verification scripts. The proprietary decoder binary is distributed only under enterprise license.*
