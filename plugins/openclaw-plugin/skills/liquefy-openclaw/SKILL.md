# Liquefy OpenClaw Vaulting

Use this skill when working with OpenClaw workspaces and the Liquefy plugin is installed.

## Purpose

Provide safe-by-default compression/vault workflows for OpenClaw runs using the Liquefy plugin/CLI:
- inspect first (`liquefy_scan`)
- apply only with explicit user approval (`liquefy_pack_apply`)
- keep secret-safe policy behavior visible and auditable

## Rules

1. Prefer `liquefy_scan` first (read-only).
2. Do not request risky overrides unless the user explicitly asks to include denied paths.
3. If `liquefy_pack_apply` is used, state what paths and profile (`default|ratio|speed`) will be used.
4. If secure mode is requested, ensure `LIQUEFY_SECRET` is configured before running apply.
5. If a path is denied, explain it and point to policy controls (`--policy`, `--allow`, `--allow-category`, `--include-secrets` phrase).

## Recommended flow

1. Run `liquefy_scan` on the workspace.
2. Show estimated savings, denied paths, and policy/risk summary.
3. Ask for confirmation before any apply/pack action.
4. Run `liquefy_pack_apply` only after explicit approval.

## Example intents

- "Scan my OpenClaw workspace and show what can be compressed"
- "Pack my OpenClaw workspace using default profile"
- "Use ratio profile and a custom policy file"
- "Explain why `credentials/api.pem` was denied"

## Notes

- Liquefy CLI JSON contracts are stable and documented in `docs/sdk.md`.
- The plugin wrapper shells out to the local Liquefy CLI (`liquefy openclaw --json`).
- For production use, pin plugin version and verify Liquefy release checksums.
