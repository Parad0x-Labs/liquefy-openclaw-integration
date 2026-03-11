---
name: liquefy-openclaw
description: Use this skill when working with OpenClaw workspaces protected by Liquefy, including read-only scan/apply vault workflows, policy denial explanation, and guarded future runs with context gate, replay blocking, and rollback.
metadata:
  short-description: Liquefy guardrails for OpenClaw
---

# Liquefy OpenClaw

Use this skill when the user wants to:
- scan or pack an OpenClaw workspace with Liquefy
- understand why Liquefy denied a path
- run OpenClaw with rollback, context budgeting, or replay blocking
- inspect or report Liquefy context-gate state for an OpenClaw workspace

## Surfaces

- Plugin tools:
  - `liquefy_scan` for read-only workspace inspection
  - `liquefy_pack_apply` for explicit pack/apply
- Local CLI:
  - `liquefy openclaw --json`
  - `liquefy openclaw run --json`
  - `liquefy safe-run --json`
  - `liquefy context-gate compile --json`
  - `liquefy context-gate history --json`

Current truth:
- the plugin wrapper exposes `scan` and `apply`
- guarded run, context gate, and replay history are local Liquefy CLI flows, not plugin tools

## Hard Rules

1. Prefer read-only scan before any write/apply action.
2. Do not ask for `--include-secrets` or risky allow-category overrides unless the user explicitly wants denied paths included.
3. If the user asks for protection on the next OpenClaw run, do not use raw `openclaw run`; prefer `liquefy openclaw run` or `liquefy safe-run`.
4. If `context-gate` reports `blocked=true`, stop and explain `block_reason` instead of trying to route around it.
5. If secure pack/apply is requested, ensure `LIQUEFY_SECRET` exists before enabling `--secure`.

## Recommended Workflows

### 1. Inspect an existing workspace

Use this when the user wants a safe audit first.

- Run `liquefy_scan` if the plugin tool is available.
- Otherwise run `liquefy openclaw --workspace <workspace> --out <vault> --dry-run --json`.
- Report:
  - eligible files/bytes
  - denied paths and reasons
  - risk summary
  - profile in use (`default`, `ratio`, `speed`)

### 2. Pack a workspace after approval

Use this only after the user explicitly approves writes.

- Preferred plugin path: `liquefy_pack_apply`
- CLI fallback: `liquefy openclaw --workspace <workspace> --out <vault> --apply --json`
- Call out:
  - output directory
  - profile
  - verify mode
  - whether secure mode is enabled

### 3. Guard the next OpenClaw run

Use this when the user wants control, not just archive-after-the-fact.

1. Compile bounded context first:
   - `liquefy context-gate compile --workspace <workspace> --cmd "<run command>" --block-replay --json`
2. If blocked, explain:
   - `exact_replay_detected`
   - `required_context_exceeds_budget`
3. If clear, run the guarded path:
   - `./liquefy openclaw run --workspace <workspace> --cmd "<run command>" --json`
   - or `liquefy safe-run --workspace <workspace> --cmd "<run command>" --block-replay --json`

Default guarded-run posture:
- context capsule priming
- context gate compilation
- replay blocking
- heartbeat
- rollback on crash/policy breach/cost breach

### 4. Explain why a path was denied

- Use scan output reasons when available.
- CLI path for exact explanation:
  - `liquefy openclaw --workspace <workspace> --out <vault> --json --explain <path>`
- Point to the right control:
  - `--policy`
  - `--allow`
  - `--allow-category`
  - `--include-secrets` phrase

## Useful Facts

- Context gate writes:
  - `.liquefy/context/current/context_gate_prompt.md`
  - `.liquefy/context/current/context_gate.json`
  - `.liquefy/context/history/context_gate_history.json`
- `liquefy openclaw run` blocks exact replay by default; only disable with explicit user intent via `--allow-replay`.
- Stable contracts live in:
  - `../../docs/sdk.md`
  - `../../schemas/liquefy.openclaw.cli.v1.json`
  - `../../schemas/liquefy.context-gate.v1.json`
  - `../../schemas/liquefy.safe-run.v2.json`

## Example Intents

- "Scan my OpenClaw workspace and tell me what Liquefy would pack."
- "Why did Liquefy deny `credentials/api.pem`?"
- "Run OpenClaw with replay blocking and rollback."
- "Show the context gate history for this workspace."
- "Pack this workspace with ratio profile after review."
