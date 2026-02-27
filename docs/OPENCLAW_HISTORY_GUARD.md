# OpenClaw History Guard (Draft)

`history-guard` is a local-first control plane for high-risk external account history workflows
(email, calendar, chat, social exports).

It is designed for two goals:
1. Continuous authorized pull and vaulting of history.
2. Pre-action snapshot gating for risky commands to reduce blast radius if an agent goes rogue.

## Command Surface

```bash
./liquefy history-guard init --workspace ~/.openclaw
./liquefy history-guard set-approval-token --workspace ~/.openclaw
./liquefy history-guard pull-once --workspace ~/.openclaw --json
./liquefy history-guard watch --workspace ~/.openclaw --poll-seconds 60 --iterations 0
./liquefy history-guard gate-action --workspace ~/.openclaw --command "python do_destructive_thing.py"
./liquefy history-guard status --workspace ~/.openclaw --json
```

## Architecture

1. Provider Pull Layer
- Reads `~/.openclaw/.liquefy/history_guard.json` (or workspace-specific path).
- Executes configured `pull_command` per provider.
- Provider command writes export artifacts to `{provider_out}`.

2. Vaulting Layer
- Each pull cycle packs exported artifacts with `tracevault_pack.py`.
- Uses compression + encryption (`LIQUEFY_SECRET`) + optional signing.
- Stores vaults under `.liquefy/history_vaults/<provider>/<run_id>/`.

3. State Layer
- Persists pull/action state in `.liquefy/history_guard_state.json`.
- Tracks last success/failure, bytes exported, last vault path.

4. Anti-Nuke Gate Layer
- `gate-action` classifies command risk via regex patterns.
- For risky commands, requires approval token via env var.
- Always creates a pre-action snapshot vault of workspace before command execution.
- If command fails and `auto_recover_to_dir=true`, restores snapshot to a recovery directory.

## Approval Token Model

- Config stores only SHA-256 hash of approval token.
- Runtime reads token from env var (`approval_env_var`, default `LIQUEFY_APPROVAL_TOKEN`).
- Error codes:
  - `LIQUEFY_APPROVAL_CONFIG_MISSING`
  - `LIQUEFY_APPROVAL_REQUIRED`
  - `LIQUEFY_APPROVAL_INVALID`

## Provider Pull Contract

Provider `pull_command` supports these template variables:
- `{workspace}`
- `{provider_id}`
- `{provider_out}`
- `{state_file}`
- `{ts}`

A minimal custom provider script should:
1. Authenticate with user-authorized credentials.
2. Export history incrementally to `{provider_out}`.
3. Exit non-zero on failure.

## Constraints (Important)

- This tool can continuously capture and preserve data that platform APIs/exports expose.
- It cannot force full write-back restore to every third-party platform.
- Rogue-action prevention works only when risky operations are routed through `gate-action`.

## Safety Defaults

- Provider entries are generated disabled.
- Approval hash must be explicitly set for risky action gating.
- Encryption defaults on (`no_encrypt=false`).
- Signing defaults on (`sign=true`).

