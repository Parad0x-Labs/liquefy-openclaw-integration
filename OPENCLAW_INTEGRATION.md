# OpenClaw Integration Guide

Liquefy is a generic compression stack with an OpenClaw-friendly wrapper.
This repo does **not** require an OpenClaw-specific fork/edition to integrate.

## Integration Model

- Keep Liquefy core engines generic (server logs, JSONL, SQL, etc.).
- Use a thin OpenClaw integration layer for:
  - denylist defaults (credentials/config)
  - workspace scanning and staging
  - profile selection (`default`, `ratio`, `speed`)
  - machine-readable JSON outputs for plugin wrappers

## Recommended UX (Scan First)

Use scan/dry-run before packing:

```bash
python tools/liquefy_openclaw.py \
  --workspace ~/.openclaw \
  --out ./openclaw-vault \
  --dry-run --json
```

This returns a machine-readable plan with:

- eligible files (sampled list)
- denied files (sampled list + reasons)
- estimated bytes / estimated ratio / estimated savings
- optional `max-bytes-per-run` cap behavior

## Pack (Apply)

```bash
python tools/liquefy_openclaw.py \
  --workspace ~/.openclaw \
  --out ./openclaw-vault \
  --profile default \
  --verify-mode fast \
  --json
```

Profiles:

- `default`: balanced/safe baseline
- `ratio`: higher compression ratio (slower)
- `speed`: throughput-first (lower ratio)

## CLI JSON Contracts (Plugin-Friendly)

### `tools/liquefy_openclaw.py`

- `schema_version`: `liquefy.openclaw.cli.v1`
- Commands:
  - `scan` (via `--dry-run`)
  - `pack`

Stable top-level fields:

- `schema_version`
- `tool`
- `command`
- `ok`
- `profile`
- `workspace`
- `out_dir`
- `verify_mode`
- `secure`
- `dry_run`
- `result`

### `tools/tracevault_pack.py`

- `schema_version`: `liquefy.tracevault.cli.v1`
- Commands:
  - `scan` (via `--scan-only`)
  - `pack`

Use this for generic wrappers that do not need OpenClaw-specific denylist handling.

## Node / Plugin Wrapper Pattern (Recommended)

1. Run `liquefy_openclaw.py --dry-run --json`
2. Present plan to user (eligible/denied/estimated savings)
3. On explicit approval, run `liquefy_openclaw.py --json`
4. Parse JSON result and read `tracevault_index.json` for detailed receipts

## Safety Defaults

- Sensitive files are denied by default (e.g. `openclaw.json`, `.env`, keys, certs).
- Original files are **not deleted**.
- Restore remains available via `tools/tracevault_restore.py`.
- Search while compressed remains available via `tools/tracevault_search.py`.

## Example JSON File Output

You can write results to a file for wrappers/auditing:

```bash
python tools/liquefy_openclaw.py \
  --workspace ~/.openclaw \
  --out ./openclaw-vault \
  --dry-run \
  --json-file ./openclaw_scan.json
```
