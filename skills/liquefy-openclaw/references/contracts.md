# Liquefy OpenClaw Contracts

Use this file when the task needs machine-readable JSON fields, schema names, or the correct command to call from automation.

## Stable CLI contracts

- `python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault --json`
  - schema: `liquefy.openclaw.cli.v1`
  - commands: `scan`, `pack`, `policy`, `run`, `version`, `self_test`, `doctor`
- `python tools/liquefy_context_gate.py compile --workspace ~/.openclaw --cmd "openclaw run" --json`
  - schema: `liquefy.context-gate.v1`
  - commands: `compile`, `history`
- `python tools/liquefy_safe_run.py --workspace ~/.openclaw --cmd "openclaw run" --json`
  - schema: `liquefy.safe-run.v2`
- `python tools/liquefy_cli.py version --json`
  - schema: `liquefy.cli.v1`
  - used by compatibility checks and install diagnostics

## Top-level contract rules

For `liquefy_openclaw.py`, `liquefy_context_gate.py`, and `liquefy_cli.py`, validate:
- `schema_version`
- `tool`
- `command`
- `ok`

For `liquefy_safe_run.py`, current contract note:
- it emits top-level `schema` instead of `schema_version`
- stable automation fields are `schema`, `ok`, `phases`, `heartbeat_active`, `needs_rollback`, `rolled_back`
- replay-blocked runs also set `blocked == true` and `block_reason`

## Policy fields

Use these when the caller needs policy explanation:
- `result.policy`
- `result.effective_rules`
- `result.explain`
- `result.risk_summary`
- `result.risky_files`

## Guarded-run fields

Use these when the caller needs runtime-control details:
- context gate block status and `block_reason`
- replay detection status
- compiled context budget result
- rollback status from safe-run

`block_reason` values to handle directly:
- `exact_replay_detected`
- `required_context_exceeds_budget`

## Source-of-truth files

Full schema files and the longer SDK contract doc live in the Liquefy repo under:
- `schemas/`
- `docs/sdk.md`
