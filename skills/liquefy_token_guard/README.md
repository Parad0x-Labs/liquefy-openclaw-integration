# Liquefy Token Guard — ClawHub Skill

One-click token usage scan, waste audit, and budget guard for OpenClaw and other agent workspaces.

This skill does not magically lower bills by itself. It finds where your agents are wasting tokens and gives operators concrete fixes.

## Install

From ClawHub marketplace: search **"Liquefy Token Guard"** -> Install.

Or manually:
```bash
cp -r skills/liquefy_token_guard ~/.openclaw/skills/
```

## What It Does

- Scans agent traces for token usage metadata
- Detects duplicate prompts, oversized context, and expensive-model overkill
- Writes and checks token budgets
- Produces operator-facing recommendations based on NULLA-style context discipline
- Pairs with `Liquefy Archive` to compress and vault cold context safely
- Builds a deterministic context capsule so the next run can load a compact hot-path summary instead of raw trace dumps
- Can prime a workspace with a reusable bootstrap file and env contract before the next run starts

## Commands

| Command | Description |
|---------|-------------|
| `scan_now` | Scan the configured trace directory and update the local token ledger |
| `audit_now` | Detect waste: duplicate prompts, oversized context, model overkill |
| `set_budget` | Write/update token and cost budgets for the configured org |
| `build_capsule` | Build a compact context capsule with measurable reduction vs raw traces |
| `prime_next_run` | Build the capsule and install `/.liquefy/context/current/context_bootstrap.md` into the target workspace |
| `verify_capsule` | Check whether the current workspace capsule is still fresh for the present trace set |
| `scoreboard` | Show replay-aware capsule history so repeated primes do not fake new savings |
| `status` | Combined scan + report + audit summary |
| `recommend` | Produce action-focused fixes from current waste findings |
| `daily_guard` | Run the full scan/report/audit cycle and emit a compact summary |

## Configuration

Edit `config.json` or set via ClawHub skill settings:

```json
{
  "trace_dir": "~/.openclaw",
  "workspace_dir": "~/.openclaw",
  "org": "default",
  "period": "today",
  "capsule_out_dir": null,
  "daily_tokens": 500000,
  "monthly_tokens": 10000000,
  "daily_cost_usd": null,
  "monthly_cost_usd": null,
  "warn_at_percent": 80,
  "auto_scan_on_status": true
}
```

## Honest Limits

- Cost is **estimated API-equivalent cost** unless you wire exact provider billing elsewhere.
- Subscription quota is **not** inferred from token math.
- Every report now declares truth modes explicitly:
  - `exact` = explicit billed cost found in trace payloads
  - `estimated` = derived from Liquefy model price table
  - `manual` = local operator budget file, not provider quota
  - `unavailable` = no defensible source exists
- This skill reduces waste by exposing bad patterns, not by silently rewriting prompts.
- `build_capsule` is deterministic. It does not invent an LLM summary. It keeps the sharp parts and measures the reduction.
- `prime_next_run` is only automatic when runs are launched through a Liquefy-aware wrapper such as `liquefy safe-run`.
- Re-priming the same trace set does **not** count as a new win. The replay-aware scoreboard dedupes identical source fingerprints.
- `verify_capsule` marks stale capsules when the underlying trace tree changes after priming.

## Best Pairing

Use with **Liquefy Archive**:

- Token Guard finds waste and prompt bloat
- Archive moves cold artifacts out of the hot path and stores them in verified `.null` vaults
- Capsule gives the next agent run a compact bootstrap instead of replaying the whole trace directory
