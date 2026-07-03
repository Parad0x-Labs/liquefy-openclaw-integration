---
name: liquefy-token-guard
description: Token usage auditor and budget guard for OpenClaw agents — scans traces for waste (duplicate prompts, oversized context, model overkill), writes budgets, and builds a compact context capsule so the next run starts lean.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Liquefy Token Guard

Finds where your agents are wasting tokens and gives concrete fixes. Does NOT
silently rewrite prompts or guess costs — every report declares its truth mode
(`exact`, `estimated`, `manual`, or `unavailable`).

`build_capsule` is deterministic. It keeps the sharp parts and measures the
reduction — no LLM summary, no invented numbers.

## Commands

| Command | Description |
|---|---|
| `scan_now` | Scan trace directory, update token ledger |
| `audit_now` | Detect waste: duplicate prompts, oversized context, model overkill |
| `set_budget` | Write/update token and cost budgets |
| `build_capsule` | Build a compact context capsule (deterministic, measured reduction) |
| `prime_next_run` | Install capsule bootstrap for the next run |
| `status` | Combined scan + report + audit summary |
| `recommend` | Action-focused fixes from current waste findings |
| `daily_guard` | Full scan/audit cycle, compact summary |

## Install

```bash
cp -r skills/liquefy_token_guard ~/.openclaw/skills/
```

Pairs with **Liquefy Archive** — Token Guard finds waste, Archive moves cold
artifacts into verified `.null` vaults.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/liquefy_token_guard
