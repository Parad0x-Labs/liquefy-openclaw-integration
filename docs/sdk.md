# Liquefy CLI SDK Contracts

Liquefy integrations (OpenClaw plugin, CI wrappers, internal tooling) should call the JSON modes of these CLIs and validate top-level fields before acting on results.

## Stability policy

- Top-level fields `schema_version`, `tool`, `command`, `ok` are stable within a schema version.
- New fields may be added to `result` and `error` objects.
- Existing fields are not removed or renamed without a schema version bump.
- Error `code` values are stable for automation handling.

## JSON-enabled CLIs

### `tracevault_pack.py`

- Command: `python tools/tracevault_pack.py <run_dir> --out <vault_dir> --json`
- Schema version: `liquefy.tracevault.cli.v1`
- Commands emitted:
  - `scan`
  - `pack`
  - `policy`
  - `version`
  - `self_test`
  - `doctor`

### `tracevault_restore.py`

- Command: `python tools/tracevault_restore.py <vault_dir> --out <dir> --json`
- Schema version: `liquefy.tracevault.restore.cli.v1`
- Commands emitted:
  - `restore`
  - `version`
  - `self_test`
  - `doctor`

### `liquefy_openclaw.py`

- Command: `python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault --json`
- Schema version: `liquefy.openclaw.cli.v1`
- Commands emitted:
  - `scan`
  - `pack`
  - `policy`
  - `version`
  - `self_test`
  - `doctor`

## Error codes (common)

These appear under `error.code` for restore, and as strings/messages for some pack/openclaw failures until those paths are fully normalized.

- `missing_secret`
- `missing_index`
- `restore_output_limit`
- `restore_failed`

## Policy-related behavior

- `--print-effective-policy` returns `result.effective_rules`
- `--explain <path>` returns `result.explain`
- Risky overrides are phrase-gated and visible in:
  - `result.policy`
  - `result.risk_summary`
  - `result.risky_files`

## JSON Schemas

- `schemas/liquefy.tracevault.cli.v1.json`
- `schemas/liquefy.tracevault.restore.cli.v1.json`
- `schemas/liquefy.openclaw.cli.v1.json`
- `schemas/liquefy.cli.v1.json` (unified dispatcher runtime commands)

## Recommended integration flow (OpenClaw plugin)

1. Run scan/dry-run first (`liquefy_openclaw.py --json --dry-run`)
2. Validate `ok == true`
3. Inspect `result.policy`, `result.risk_summary`
4. Only then run `--apply` (and `--secure` if `LIQUEFY_SECRET` is configured)
5. On failures, branch on `error.code` when present, else use `error` text
