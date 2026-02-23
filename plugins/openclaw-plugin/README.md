# Liquefy OpenClaw Plugin Wrapper

This package is a Node.js/OpenClaw plugin wrapper for the Liquefy CLI. It exposes
safe OpenClaw tools (`liquefy_scan`, `liquefy_pack_apply`) and shells out to the
Liquefy CLI JSON contracts.

Status:
- `liquefy_scan` (required, read-only): implemented
- `liquefy_pack_apply` (optional / allowlist): implemented
- JSON contract integration (`liquefy openclaw --json`): implemented
- ClawHub/OpenClaw skill pack scaffold: included under `./skills/`

## What it does

- Exposes safe OpenClaw-facing tools with JSON schemas
- Uses Liquefy CLI safe defaults (`--dry-run` for scan path)
- Respects policy files / allow / deny / category overrides
- Supports explicit risky override phrase pass-through

## Install (OpenClaw users)

### 1) Install Liquefy CLI locally (source bootstrap)

```bash
git clone https://github.com/Parad0x-Labs/liquefy-openclaw-integration.git && \
  cd liquefy-openclaw-integration && \
  ./install.sh
```

### 2) Install plugin in OpenClaw (pinned)

When this package is published, prefer a pinned install:

```bash
openclaw plugins install @parad0x-labs/liquefy-openclaw-plugin@0.1.0-alpha --pin
openclaw plugins enable liquefy
openclaw gateway restart
```

### 3) First safe run (scan only)

Use the plugin tool `liquefy_scan` first, or run the CLI directly:

```bash
./.venv/bin/python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./openclaw-vault --json
```

## Required local dependency (plugin host)

You need a Liquefy CLI binary or script on the machine running the plugin.

Resolution order:
1. plugin config `binaryPath`
2. env var `LIQUEFY_OPENCLAW_BIN`
3. `liquefy` on `PATH`

The plugin intentionally does not bundle the CLI binary. This keeps the wrapper
auditable and lets operators pin/verify their Liquefy install separately.

## Security / trust posture

- Safe default is scan-first (`liquefy_scan`)
- Destructive/apply tool is optional and intended for allowlisting
- Liquefy policy denylist is enforced by default (secrets/configs blocked)
- Use pinned plugin versions (`--pin`) and verify Liquefy release checksums (`SHA256SUMS.txt`)
- Signed releases are recommended for production rollout (when available)

## Local test

```bash
cd plugins/openclaw-plugin
npm test
```

## Publish (npm)

```bash
cd plugins/openclaw-plugin
npm pack
# npm publish --access public   # when org/package permissions are ready
```

## Notes

- This is a wrapper package. Compression/search/restore logic remains in the Liquefy CLI + Python engines.
- For a stable integration contract, see `../../docs/sdk.md` and `../../schemas/`.
- ClawHub/OpenClaw skill pack scaffold lives in `./skills/liquefy-openclaw/`.
