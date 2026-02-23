# OpenClaw Plugin Publish & Trust Plan

This document defines the publish flow for the Liquefy OpenClaw plugin wrapper and the trust posture users should expect.

## Package

- npm package name: `@parad0x-labs/liquefy-openclaw-plugin`
- Plugin manifest: `plugins/openclaw-plugin/openclaw.plugin.json`
- Runtime wrapper: `plugins/openclaw-plugin/dist/*.js`
- Skill pack scaffold: `plugins/openclaw-plugin/skills/liquefy-openclaw/SKILL.md`

## Install guidance (user-facing)

Prefer pinned plugin versions:

```bash
openclaw plugins install @parad0x-labs/liquefy-openclaw-plugin@0.1.0-alpha --pin
openclaw plugins enable liquefy
openclaw gateway restart
```

Liquefy CLI itself is installed separately (source bootstrap or release binaries).

## Safe defaults

- `liquefy_scan` is read-only and required
- `liquefy_pack_apply` is optional / allowlist-oriented
- secret-safe policy denylist is enforced by default
- risky inclusion requires explicit phrase override and is recorded in JSON/report output

## Trust / supply chain

### Recommended operator checks

1. Pin plugin package version (`--pin`)
2. Verify Liquefy release checksums (`SHA256SUMS.txt`) from GitHub Releases
3. Review plugin wrapper code (`dist/index.js`, `dist/lib.js`) before enabling apply tools
4. Start with scan-only and confirm denied paths/policy output

### Release artifacts

The repository includes `build-release.yml` which builds multi-platform CLI binaries and emits checksums.
Signed releases are recommended for production rollout. If signing is not yet enabled, checksums are the minimum trust control.

## CLI contract dependency

The plugin depends on Liquefy CLI JSON outputs:
- `liquefy openclaw --json`

See:
- `docs/sdk.md`
- `schemas/liquefy.openclaw.cli.v1.json`

## Publish checklist (internal)

1. Run plugin tests (`npm test`) and Python CLI contract tests
2. Confirm `README`/`openclaw.plugin.json` match current flags and defaults
3. `npm pack` and inspect package contents
4. Publish pinned version
5. Update release notes and install docs if command flags changed
