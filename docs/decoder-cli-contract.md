# Decoder CLI Contract (Public)

This document defines the stable CLI interface for the `liquefy-decoder` appliance. This contract ensures that enterprise automation and verification scripts remain compatible across versions.

## Commands

### `version`
Prints the version information and exits.
- **Output:** `liquefy-decoder version <version-string>`

### `decompress <archive> -o <output>`
Decompresses a `.null` or `.liq` archive to the specified output path.
- **Inputs:**
  - `<archive>`: Path to the compressed archive file.
  - `-o <output>`: Path where the restored data will be written.
- **Side Effects:** Writes restored data to disk. Overwrites existing files if permitted by environment.

### `verify <archive>`
Performs a cryptographic integrity check on the archive without full decompression.
- **Inputs:**
  - `<archive>`: Path to the compressed archive file.
  - `--json`: (Optional) Output results in machine-readable JSON format.
- **Output:**
  - Success message or JSON object with `{ "status": "verified", "hash": "..." }`.

### `license status`
Displays the current license state (validity, expiration, features).
- **Output:** Human-readable status or JSON if `--json` is provided.

## Exit Codes

The decoder uses stable exit codes for automation:

| Code | Meaning | Description |
|------|---------|-------------|
| 0    | Success | Operation completed successfully. |
| 10   | Corruption | Archive integrity check failed (data corruption). |
| 11   | License Invalid | License is missing, expired, or doesn't support the feature. |
| 12   | Unsupported Format | Archive version or compression engine not supported by this decoder. |
| 13   | Internal Error | Generic error (no sensitive debug information disclosed). |

## Output Policy

1. **Human-Readable:** Default output is designed for terminal clarity.
2. **Machine-Readable:** `--json` flag provides stable schema for orchestration.
3. **Privacy:** The decoder never prints internal engine names, tuning parameters, or proprietary heuristics.
4. **Security:** Stack traces and internal symbols are suppressed in production builds.
