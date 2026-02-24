# Liquefy Archive — ClawHub Skill

One-click compression, redaction & vault archival for OpenClaw workspaces.

## Install

From ClawHub marketplace: search **"Liquefy Archive"** → Install.

Or manually:
```bash
cp -r skills/liquefy_archive ~/.openclaw/skills/
```

## What It Does

- Watches `sessions/`, `memory/`, `artifacts/` for large or old data
- Auto-packs into verified `.null` vaults with full MRTV proofs
- Blocks leaks (keys, envs, credentials) using the policy engine
- Keeps your N most recent files active and untouched
- Sends daily recaps: "Your agents produced 2.1 GB raw → 387 MB in vaults, 7 leaks blocked"

## Commands

| Command | Description |
|---------|-------------|
| `archive_now` | Single sweep — compress eligible items |
| `start_daemon` | Start background archiver (auto-sweeps every 5 min) |
| `stop_daemon` | Stop the background daemon |
| `status` | Current daemon state + last sweep stats |
| `daily_recap` | Generate 24h activity summary |

## Configuration

Edit `config.json` or set via ClawHub skill settings:

```json
{
  "watch_root": "~/.openclaw",
  "vault_dir": "~/.liquefy/vault",
  "size_threshold_mb": 50,
  "age_threshold_days": 7,
  "keep_active": 5,
  "profile": "default",
  "secure": false,
  "prune_originals": false,
  "notify": ["stdout", "telegram"],
  "poll_seconds": 300
}
```

## Notifications

Set environment variables:
- **Telegram**: `LIQUEFY_TG_BOT_TOKEN` + `LIQUEFY_TG_CHAT_ID`
- **Discord**: `LIQUEFY_DISCORD_WEBHOOK`
