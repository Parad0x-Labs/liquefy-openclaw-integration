# Liquefy OpenClaw Workflows

Use this file when the task is operational: pick the smallest real workflow that matches the user request.

## 1. Scan an OpenClaw workspace first

Use this when the user wants a safe audit or wants to know what would be packed.

- Preferred plugin path:
  - `liquefy_scan`
- CLI fallback:
  - `liquefy openclaw --workspace <workspace> --out <vault> --dry-run --json`

Report:
- eligible files and bytes
- denied paths and reasons
- risky files included count
- profile in use: `default`, `ratio`, or `speed`

## 2. Pack after explicit approval

Only do this after the user explicitly approves a write/apply action.

- Preferred plugin path:
  - `liquefy_pack_apply`
- CLI fallback:
  - `liquefy openclaw --workspace <workspace> --out <vault> --apply --json`

Call out:
- output directory
- profile
- verify mode
- whether `--secure` is enabled

If `--secure` is requested:
- require `LIQUEFY_SECRET`
- do not fake success if it is missing

## 3. Explain policy denial or allowed-by-override

Use this when the user asks why a path is denied or how to include it.

- Exact explanation path:
  - `liquefy openclaw --workspace <workspace> --out <vault> --json --explain <path>`
- To inspect merged policy:
  - `liquefy openclaw --workspace <workspace> --out <vault> --json --print-effective-policy`

Point to the right control:
- `--policy`
- `--allow`
- `--allow-category`
- `--include-secrets "I UNDERSTAND THIS MAY LEAK SECRETS"`

Do not suggest risky overrides unless the user explicitly wants the denied material included.

## 4. Guard the next OpenClaw run

Use this when the user wants runtime control, not just archive-after-the-fact.

Compile bounded context first:
- `liquefy context-gate compile --workspace <workspace> --cmd "<run command>" --block-replay --json`

If blocked, stop and explain:
- `exact_replay_detected`
- `required_context_exceeds_budget`

If clear, run the guarded path:
- `./liquefy openclaw run --workspace <workspace> --cmd "<run command>" --json`
- or `liquefy safe-run --workspace <workspace> --cmd "<run command>" --block-replay --json`

Default guarded-run posture:
- context capsule priming
- context gate compilation
- replay blocking
- heartbeat
- rollback on crash, policy breach, or cost breach

Context gate writes:
- `.liquefy/context/current/context_gate_prompt.md`
- `.liquefy/context/current/context_gate.json`
- `.liquefy/context/history/context_gate_history.json`

`liquefy openclaw run` blocks exact replay by default. Only disable with explicit user intent via `--allow-replay`.

## 5. Install native OpenClaw hook integration

Use this when the user wants Liquefy to archive sessions automatically inside OpenClaw.

- Install:
  - `python tools/liquefy_openclaw_plugin.py hook install --create`
- Status:
  - `python tools/liquefy_openclaw_plugin.py status --json`
- Uninstall:
  - `python tools/liquefy_openclaw_plugin.py hook uninstall`

What it does:
- writes the Liquefy config block into `openclaw.json`
- archives on session close
- can build context capsules automatically
- records local plugin state under `~/.liquefy`

Current truth:
- this is a local native integration path
- it is not the same thing as the Node OpenClaw plugin wrapper

## 6. Vault specific agent sessions

Use this when the user wants a single agent or time-sliced session archive instead of a whole workspace pack.

- List agents:
  - `python tools/openclaw_tracevault.py list`
- Pack one agent:
  - `python tools/openclaw_tracevault.py pack --agent <agent_id> --out <vault_dir>`
- Pack recent sessions only:
  - `python tools/openclaw_tracevault.py pack --agent <agent_id> --since-days 7 --out <vault_dir>`

This path is filesystem-based and denies credential paths by default.

## 7. Search or restore an existing vault

Use this after a pack already exists.

- Search while compressed:
  - `liquefy search <vault_dir> --query "<expr>"`
- Restore:
  - `liquefy restore <vault_dir> --out <dir>`

Good defaults:
- search before restore when the user needs only a small fact
- restore only when they need recovered files on disk

## 8. Protect state outside packing

Use this when the risk is mutable state or destructive provider actions, not just vaulting.

State guard:
- `liquefy state-guard init <workspace> --files wallet-state.json positions.json --strict`
- `liquefy state-guard check <workspace> --json`
- `liquefy state-guard checkpoint <workspace>`
- `liquefy state-guard recover <workspace>`

History guard:
- `liquefy history-guard init --workspace <workspace>`
- `liquefy history-guard pull-once --workspace <workspace> --json`
- `liquefy history-guard gate-action --workspace <workspace> --command "<cmd>" --json`
- `liquefy history-guard status --workspace <workspace> --json`

Use these when the user wants pre-flight blocking, checkpointing, provider history pulls, or auto-recovery around dangerous actions.
