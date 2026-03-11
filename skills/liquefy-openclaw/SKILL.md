---
name: liquefy-openclaw
description: Use this skill when working with Liquefy around OpenClaw, including workspace scan/pack flows, policy explanation, search/restore, guarded runs, context gate, replay blocking, native hook integration, session vaulting, and state/history guard workflows.
metadata:
  short-description: Liquefy guardrails for OpenClaw
---

# Liquefy OpenClaw

Use this skill when the user wants to:
- scan or pack an OpenClaw workspace with Liquefy
- understand why Liquefy denied a path
- search or restore from an existing Liquefy vault
- run OpenClaw with rollback, context budgeting, replay blocking, or restore-on-failure
- install or inspect native Liquefy integration inside OpenClaw
- vault OpenClaw session/state directories
- protect OpenClaw state or pulled history before risky actions

## Start Here

Default to the local Liquefy CLI:
- `liquefy openclaw --json`
- `liquefy openclaw run --json`
- `liquefy search`
- `liquefy restore`
- `liquefy safe-run --json`
- `liquefy context-gate compile --json`
- `liquefy context-gate history --json`
- `python tools/openclaw_tracevault.py`
- `python tools/liquefy_openclaw_plugin.py hook install|uninstall|status`
- `liquefy state-guard ...`
- `liquefy history-guard ...`

Optional packaged plugin path:
- if the user already has the OpenClaw plugin installed, `liquefy_scan` and `liquefy_pack_apply` are available
- do not assume those plugin tools exist in a standalone skill install

## Preflight

Before using repo-relative tools or plugin commands:
- verify `liquefy` is installed and callable
- verify repo-relative `tools/` paths exist before using `python tools/...`
- verify optional plugin tools exist before using them
- verify `LIQUEFY_SECRET` is set before any secure pack/apply flow
- prefer `--json` for commands that support it when machine-readable results matter

If a required command, repo path, or dependency is missing:
- stop and explain the missing dependency
- do not guess alternate commands
- do not pretend plugin or repo-only surfaces are available

Compatibility note:
- this standalone skill is aligned to the Liquefy OpenClaw command surface currently shipped in this repo
- check `liquefy version --json` and `liquefy openclaw --version --json` before relying on newer flags
- if the optional OpenClaw plugin is used, it expects Liquefy OpenClaw CLI `>= 1.1.0`

## Hard Rules

1. Prefer read-only scan before any write/apply action.
2. Do not ask for `--include-secrets` or risky allow-category overrides unless the user explicitly wants denied paths included.
3. If the user asks for protection on the next OpenClaw run, do not use raw `openclaw run`; prefer `liquefy openclaw run` or `liquefy safe-run`.
4. If `context-gate` reports `blocked=true`, stop and explain `block_reason` instead of trying to route around it.
5. If secure pack/apply is requested, ensure `LIQUEFY_SECRET` exists before enabling `--secure`.
6. Do not pretend the standalone skill install also installed the plugin package. Treat plugin tools as optional.
7. Do not run pack, apply, restore, hook install/uninstall, or other write-affecting operations unless the user explicitly requested that action after review.

## References

- For workflow selection and commands, read [references/workflows.md](references/workflows.md).
- For install/update truth, standalone vs plugin split, and trust posture, read [references/integration.md](references/integration.md).
- For JSON contracts and stable machine-readable fields, read [references/contracts.md](references/contracts.md).

Load only the reference file needed for the current request.

## Quick Routing

- Workspace audit or pack:
  use `liquefy openclaw` by default; only use plugin tools if the user already has the plugin enabled.
- Policy denial or override question:
  use `liquefy openclaw --explain ...` and report the matched category/reason.
- Next run must be protected:
  use `liquefy openclaw run` or `liquefy safe-run`, not raw OpenClaw.
- User wants automatic OpenClaw archival:
  use native hook install/status/uninstall via `liquefy_openclaw_plugin.py`.
- User wants specific agent session vaulting:
  use `openclaw_tracevault.py`.
- User needs restore/search on an existing vault:
  use `liquefy search` / `liquefy restore`.
- User wants filesystem/state protection outside packing:
  use `state-guard` or `history-guard`.

## Example Intents

- "Scan my OpenClaw workspace and tell me what Liquefy would pack."
- "Why did Liquefy deny `credentials/api.pem`?"
- "Run OpenClaw with replay blocking and rollback."
- "Show the context gate history for this workspace."
- "Pack this workspace with ratio profile after review."
- "Install Liquefy hooks into OpenClaw and show status."
- "Restore this OpenClaw vault and search it for a trace id."
- "Protect `wallet-state.json` before the next run."
