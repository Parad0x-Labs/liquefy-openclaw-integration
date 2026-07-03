---
name: liquefy-archive
description: Background compression and vault archival for OpenClaw workspaces — auto-packs sessions, memory, and artifacts into verified .null vaults with full MRTV proofs. Blocks credential and key leaks before archiving.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Liquefy Archive

Auto-compresses OpenClaw sessions, memory, and artifacts into verified `.null`
vaults. Runs as a daemon or on-demand sweep. Blocks credential and key leaks
before anything reaches the vault — API keys, env files, and private keys are
caught and blocked before archiving.

## Commands

| Command | Description |
|---|---|
| `archive_now` | Single sweep — compress eligible items now |
| `start_daemon` | Background archiver (auto-sweeps every 5 min) |
| `stop_daemon` | Stop the background daemon |
| `status` | Daemon state + last sweep stats |
| `daily_recap` | 24h activity summary |

## Install

```bash
cp -r skills/liquefy_archive ~/.openclaw/skills/
```

## Configuration

```json
{
  "watch_root": "~/.openclaw",
  "vault_dir": "~/.liquefy/vault",
  "size_threshold_mb": 50,
  "age_threshold_days": 7,
  "keep_active": 5,
  "prune_originals": false
}
```

Pairs with **Liquefy Token Guard** — Token Guard finds waste, Archive vaults it.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/liquefy_archive
