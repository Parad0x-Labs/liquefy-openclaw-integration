# Path Safety Policy (OpenClaw + TraceVault)

Liquefy wrappers (`tools/liquefy_openclaw.py`, `tools/tracevault_pack.py`) use a shared path safety policy layer to prevent accidental packing of secrets.

## Default Behavior

- Mode: `strict`
- Obvious secret material is denied by default:
  - `.env*`
  - private keys (`.pem`, `.key`, `id_rsa*`, `id_ed25519*`, etc.)
  - wallet/seed-like files
  - OpenClaw config (`openclaw.json`)
  - `credentials/`, `auth/`, `secrets/` paths
- Risky inclusion requires an explicit confirmation phrase

## Modes

- `strict` (default): deny all risky categories
- `balanced`: deny high-risk categories, less aggressive on some cases
- `off`: disable denylist category enforcement (permissions hardening still applies)

## CLI Flags

Common flags on both wrappers:

- `--policy <file.{json,yml,yaml}>`
- `--mode strict|balanced|off`
- `--deny <glob>` (repeatable)
- `--allow <glob>` (repeatable)
- `--allow-category <CATEGORY>` (repeatable)
- `--include-secrets "I UNDERSTAND THIS MAY LEAK SECRETS"`
- `--print-effective-policy`
- `--explain <path>`

## Why `--include-secrets` Is Annoying on Purpose

Risky override must be explicit and auditable:
- exact phrase required
- visible in JSON output (`policy`, `risk_summary`, `risky_files`)
- visible in the OpenClaw report warning section

This prevents broad accidental globs from silently sweeping up secrets.

## Policy File Format

See example files:
- `../policies/strict.yml`
- `../policies/balanced.yml`
- `../policies/demo_risky.yml`

Example:

```yaml
version: 1
mode: strict
deny:
  - pattern: "**/*.env"
    reason: "ENV_FILE"
allow:
  - pattern: "workspace/demo_keys/**"
allow_categories:
  - ENV_FILE
include_risky:
  enabled: false
  require_phrase: "I UNDERSTAND THIS MAY LEAK SECRETS"
redact_output: true
```

## Audit / Debug

Use policy inspection before packing:

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault --print-effective-policy
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault --json --explain credentials/api.pem
```

The `--explain` output is intended for support/debug and future plugin integrations.

## Restore Limits (Disk Safety)

Liquefy runs locally. Limits exist to protect your machine from accidental or malicious restore bombs (for example shared vaults, CI runners, or small disks).

- Default restore cap: `2 GiB` total output bytes written
- Override (power user): `--max-output-bytes 0` to disable

Example:

```bash
python tools/tracevault_restore.py ./vault/run_001 --out ./restored/run_001
python tools/tracevault_restore.py ./vault/run_001 --out ./restored/run_001 --max-output-bytes 0
```
