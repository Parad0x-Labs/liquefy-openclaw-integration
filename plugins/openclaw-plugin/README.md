# Liquefy OpenClaw Plugin Wrapper (Scaffold)

This package is a Node.js/OpenClaw plugin wrapper for the Liquefy CLI.

Current status:
- `liquefy_scan` (read-only) tool wrapper: implemented
- `liquefy_pack_apply` (optional) tool wrapper: implemented
- JSON contract integration: implemented (shells out to `liquefy openclaw --json`)
- Publishing to npm / OpenClaw registry: not done yet

## What it does

- Exposes safe OpenClaw-facing tools with JSON schemas
- Uses Liquefy CLI safe defaults (`--dry-run` for scan path)
- Respects policy files / allow / deny / category overrides
- Supports explicit risky override phrase pass-through

## Required local dependency

You need a Liquefy CLI binary or script on the machine running the plugin.

Resolution order:
1. plugin config `binaryPath`
2. env var `LIQUEFY_OPENCLAW_BIN`
3. `liquefy` on `PATH`

## Local test

```bash
cd plugins/openclaw-plugin
npm test
```

## Notes

- This is a wrapper package. Compression/search/restore logic remains in the Liquefy CLI + Python engines.
- For a stable integration contract, see `../../docs/sdk.md` and `../../schemas/`.

