# Enterprise Evaluation Guide

> **Note:**
> This guide applies to the **licensed enterprise engine (Path B)**.
> If you only need to recover or verify existing archives without compression, use the **Public Decode-Only Appliance (Path C)** instead.

This guide describes how to verify the **Zero-Persistence** and **Bit-Perfect** guarantees of the Liquefy platform using the sealed decoder appliance.

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
