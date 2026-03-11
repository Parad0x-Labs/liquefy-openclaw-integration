---
name: liquefy-openclaw
description: Use this skill when working with Liquefy around OpenClaw, including plugin scan/apply flows, native hook integration, session vaulting, search/restore, policy explanation, guarded runs, context gate, replay blocking, and state/history guard workflows.
metadata:
  short-description: Liquefy guardrails for OpenClaw
---

# Liquefy OpenClaw

Use this skill when the user wants to:
- scan or pack an OpenClaw workspace with Liquefy
- install or inspect Liquefy inside OpenClaw itself
- vault OpenClaw session/state directories
- search or restore from an existing Liquefy vault
- understand why Liquefy denied a path
- run OpenClaw with rollback, context budgeting, replay blocking, or restore-on-failure
- protect OpenClaw state or pulled history before risky actions

## Start Here

- Plugin tools:
  - `liquefy_scan` for read-only workspace inspection
  - `liquefy_pack_apply` for explicit pack/apply
- Local CLI:
  - `liquefy openclaw --json`
  - `liquefy openclaw run --json`
  - `python tools/openclaw_tracevault.py`
  - `python tools/liquefy_openclaw_plugin.py hook install|uninstall|status`
  - `liquefy search`
  - `liquefy restore`
  - `liquefy safe-run --json`
  - `liquefy context-gate compile --json`
  - `liquefy context-gate history --json`
  - `liquefy state-guard ...`
  - `liquefy history-guard ...`

Current truth:
- the plugin wrapper exposes `scan` and `apply`
- hook integration, session vaulting, restore/search, state-guard, history-guard, guarded run, context gate, and replay history are local Liquefy flows, not plugin tools

## Hard Rules

1. Prefer read-only scan before any write/apply action.
2. Do not ask for `--include-secrets` or risky allow-category overrides unless the user explicitly wants denied paths included.
3. Do not pretend the OpenClaw plugin exposes guarded execution. For runtime protection, use local Liquefy CLI/native integration.
4. If the user asks for protection on the next OpenClaw run, do not use raw `openclaw run`; prefer `liquefy openclaw run` or `liquefy safe-run`.
5. If `context-gate` reports `blocked=true`, stop and explain `block_reason` instead of trying to route around it.
6. If secure pack/apply is requested, ensure `LIQUEFY_SECRET` exists before enabling `--secure`.

## References

- For workflow selection and commands, read [references/workflows.md](references/workflows.md).
- For plugin install, native hook integration, binary resolution, and trust posture, read [references/integration.md](references/integration.md).
- For JSON contracts and stable machine-readable fields, read [references/contracts.md](references/contracts.md).

Load only the reference file needed for the current request.

## Quick Routing

- Workspace audit or pack:
  use plugin `liquefy_scan` / `liquefy_pack_apply` first when the user is operating inside OpenClaw tools; otherwise use `liquefy openclaw`.
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
