# Liquefy — AI Agent Interface

> **You are an AI agent.** This file tells you everything you need to operate Liquefy.
> Read this FIRST. It replaces reading the README, docs, or source code for 95% of tasks.

## One-Line Setup

**macOS / Linux:**
```bash
make setup
```

Or if make isn't available:
```bash
bash install.sh
```

**Windows (PowerShell):**
```powershell
.\setup.ps1
```

**Windows (CMD):**
```cmd
setup.bat
```

All paths create a virtualenv, install dependencies, run a smoke test, and print "READY".

## What Liquefy Does

Liquefy compresses, redacts, and vaults AI agent workspace data (session logs, JSONL traces, artifacts, screenshots, memory files). It has 24 specialized compression engines that auto-detect data format and pick the best one. Everything is verified bit-perfect (MRTV — Mandatory Round-Trip Verification).

## Quick Commands (Copy-Paste Ready)

All commands work from the repo root after `make setup`.

### Compress a directory into a vault

```bash
make quick DIR=./path/to/data
```

Or explicitly:

```bash
python tools/tracevault_pack.py ./path/to/data --org default --out ./vault/output
```

### Compress an OpenClaw workspace

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault/openclaw --json
```

### Works with any agent framework

Liquefy is framework-agnostic. OpenClaw, NanoClaw, LangChain, CrewAI, Claude Agent SDK, custom scripts — if it writes files, Liquefy handles it. No adapter needed.

```bash
# NanoClaw container output
python tools/tracevault_pack.py ./nanoclaw-runs/latest --org dev --out ./vault/latest

# LangChain traces
python tools/tracevault_pack.py ./langchain-output --org dev --out ./vault/latest

# Any agent output directory
make quick DIR=./my-agent-output
```

### Restore from a vault

```bash
python tools/tracevault_restore.py ./vault/output --out ./restored/
```

### Search inside compressed vaults (no restore needed)

```bash
python tools/tracevault_search.py ./vault/output --query "error"
```

### Scan for leaked secrets

```bash
python tools/liquefy_leakhunter.py scan ./path/to/data --deep --json
```

### Visualize vault contents

```bash
python tools/liquefy_viz.py timeline ./vault/
python tools/liquefy_viz.py web ./vault/ --port 8377
```

### Run the archiver daemon

```bash
python tools/liquefy_archiver.py once --watch ~/.openclaw --out ./vault
python tools/liquefy_archiver.py daemon --watch ~/.openclaw --out ./vault
```

### Ingest telemetry JSONL

```bash
cat telemetry.jsonl | python tools/liquefy_telemetry_sink.py pipe --out ./vault/telemetry
```

### Sandbox-test a skill

```bash
python tools/liquefy_sandbox.py run ./skills/some_skill --timeout 60 --json
```

### Sync to Obsidian

```bash
python tools/liquefy_obsidian.py sync --vault-root ./vault --obsidian ~/Obsidian/MyVault
```

### Native OpenClaw integration (zero-config)

```bash
make openclaw-hook       # Install hooks — auto-triggers on every session close
make status              # Show integration status
# Users won't know it's there until they type: make status
```

### AI Intelligence Layer

```bash
make predict DIR=~/.openclaw         # "This agent will hit 2 GB in 3 days"
make suggest DIR=~/.openclaw         # "Switch to ratio profile, enable archiver"
make score VAULT=./vault             # Value-score every trace (high/med/low)
make prune DIR=./vault               # Auto-prune low-value, keep high-value (dry-run)
make summarize VAULT=./vault         # LLM-powered "what actually mattered today"
make migrate SRC=./old.tar.gz OUT=./vault  # Import from tar/zstd/gzip backups
```

### Fleet Coordination (Multi-Agent)

```bash
make fleet-register AGENT=agent-47 QUOTA_MB=500 PRIORITY=20
make fleet-status                    # Dashboard: all agents, usage, health
make fleet-quota AGENT=agent-47      # Check quota headroom
make fleet-ingest AGENT=agent-47 SRC=./data  # Compress for a specific agent (quota-enforced)
make fleet-merge TARGET=main-agent SOURCES='agent-1 agent-2 agent-3' STRATEGY=last_write
make fleet-gc MAX_AGE=30             # Remove old vaults, enforce quotas
```

All agents share one vault root (`~/.liquefy/fleet/`). Each gets a namespace partition.
File-level locking ensures safe concurrent access from multiple processes.
Conflict resolution: `last_write`, `largest`, `priority`, or `both` (keep-both).

### Compliance & Audit

```bash
make audit-verify                    # Verify tamper-proof hash chain is intact
make compliance VAULT=./vault ORG=acme TITLE="Q1 Audit"  # Generate HTML compliance report
make compliance-verify VAULT=./vault  # Chain integrity check (pass/fail)
make compliance-timeline VAULT=./vault # Chronological event timeline (HTML)
```

Or directly:

```bash
python tools/liquefy_compliance.py report --vault ./vault --org acme --title "Q1 Audit" --output report.html
python tools/liquefy_compliance.py verify --vault ./vault --json
python tools/liquefy_compliance.py timeline --vault ./vault --output timeline.html
```

### Vision — Screenshot Dedup (Engine #24)

Agents capture redundant screenshots. Vision deduplicates near-identical images using perceptual hashing (aHash), storing only unique frames.

```bash
make vision-scan DIR=./agent-screenshots         # Report dedup potential
make vision-pack DIR=./agent-screenshots          # Pack into VSNX vault (deduplicated)
make vision-restore SRC=./vault/vision.vsnx       # Restore all images
make vision-stats SRC=./vault/vision.vsnx         # Show dedup stats
```

Or directly:

```bash
python tools/liquefy_vision.py scan  ./agent-screenshots --json
python tools/liquefy_vision.py pack  ./agent-screenshots --out ./vault/vision.vsnx --json
python tools/liquefy_vision.py restore ./vault/vision.vsnx --out ./restored --json
python tools/liquefy_vision.py stats ./vault/vision.vsnx --json
```

Install Pillow for perceptual dedup (`pip install Pillow`). Without it, falls back to exact SHA-256 dedup.

### Token Ledger [EXPERIMENTAL]

Track, budget, and audit LLM token usage across agent runs. Parses OpenAI, Anthropic, LangChain, and generic JSONL traces.

> **EXPERIMENTAL**: Token counts are extracted from agent logs on a best-effort basis. Actual billing may differ from estimates. Use provider dashboards for exact costs.

```bash
make token-scan DIR=./agent-output                              # Scan logs for usage
make token-budget ORG=acme DAILY=500000 MONTHLY=10000000        # Set limits
make token-report ORG=acme PERIOD=today                         # Usage report
make token-audit DIR=./agent-output                             # Detect waste
```

Or directly:

```bash
python tools/liquefy_token_ledger.py scan   --dir ./agent-output --json
python tools/liquefy_token_ledger.py budget --org acme --daily 500000 --monthly 10000000
python tools/liquefy_token_ledger.py report --org acme --period today --json
python tools/liquefy_token_ledger.py audit  --dir ./agent-output --json
```

**What it detects:**
- **Duplicate prompts** — identical prompts sent multiple times (wasted tokens)
- **Oversized context** — inputs exceeding 100K tokens
- **Model overkill** — small tasks routed to expensive models (GPT-4 for 50-token outputs)
- **High input/output ratio** — sending too much context for small responses

**Cost estimates** for GPT-4, GPT-4o, GPT-4o-mini, GPT-3.5-turbo, Claude 3/3.5/4 Opus/Sonnet/Haiku. Unknown models use a conservative default.

**Budget alerts**: set daily/monthly token or cost limits per org. Reports show usage percentage and warn when approaching limits.

**Auto-detection:**
- **Unknown models** — scan and audit automatically flag models not in the cost table with the exact command to add them
- **Model switches** — audit detects when agents switch models mid-trace (e.g. gpt-4o → gpt-5) and flags for review

**28 built-in models** (GPT-3.5/4/4o/5, o1/o3, Claude 3/3.5/4/4.5/4.6, Gemini 1.5/2.0, DeepSeek V3/R1, Llama 3.3, Mistral). Expandable:

```bash
make token-models                                               # List all models + costs
python tools/liquefy_token_ledger.py models --add 'gpt-6:0.01:0.03'  # Add/update a model
```

Or drop a `model_costs.json` at `~/.liquefy/tokens/model_costs.json` or set `LIQUEFY_MODEL_COSTS` env var.

All usage data is logged to the Liquefy audit chain for tamper-proof tracking.

### Config Guard (Update Protection)

Never lose your customizations to a framework update again. Config Guard snapshots your configs, skills, prompts, and env files before an update and restores them after.

```bash
# Before update — save everything
make guard-save DIR=./my-agent LABEL="pre-v2.0"

# Run your update (git pull, npm update, pip install --upgrade, etc.)

# After update — see what got overwritten
make guard-diff DIR=./my-agent

# Restore your customizations
make guard-restore DIR=./my-agent

# Check current state
make guard-status DIR=./my-agent
```

Or directly:

```bash
python tools/liquefy_config_guard.py save    --dir ./my-agent --label "pre-v2.0" --json
python tools/liquefy_config_guard.py diff    --dir ./my-agent --json
python tools/liquefy_config_guard.py restore --dir ./my-agent --json
python tools/liquefy_config_guard.py status  --dir ./my-agent --json
```

**What it guards:** `.yaml`, `.json`, `.toml`, `.env`, `.py`, `.ts`, `.sh`, `Makefile`, `Dockerfile`, `requirements.txt`, skill files, prompt files — anything config-like.

**What it skips:** `node_modules/`, `.git/`, `__pycache__/`, `.venv/`, `dist/`, `build/`.

**Conflict handling:** If the update changed a file AND you had customizations, Config Guard saves a `.update-backup` copy so you can merge manually. Use `--force` to skip backups. Use `--dry-run` to preview without changes.

Works with any framework: OpenClaw, NanoClaw, LangChain, CrewAI, or any project directory.

### On-Chain Anchoring (Solana)

Anchor vault integrity proofs on Solana. Anyone with a Solana explorer can verify your data hasn't been tampered with — without seeing a single byte of it.

**What goes on-chain (80 bytes):**
- `vault_hash` — SHA-256 of all vault file hashes (32 bytes, truncated to 16 hex)
- `chain_tip` — latest audit chain hash (32 bytes, truncated to 16 hex)
- `key_fingerprint` — SHA-256 of encryption key (16 hex chars)

**Cost:** ~0.000005 SOL per anchor via SPL Memo program.

```bash
make vault-proof VAULT=./vault                    # Compute proof (free, offline)
make vault-anchor VAULT=./vault KEYPAIR=~/.config/solana/id.json  # Anchor on Solana
make vault-verify VAULT=./vault                   # Verify vault matches anchor
make vault-show PROOF=./vault/.anchor-proof.json  # Display proof details
```

Or directly:

```bash
python tools/liquefy_vault_anchor.py proof  --vault ./vault --json
python tools/liquefy_vault_anchor.py anchor --vault ./vault --keypair ~/.config/solana/id.json --json
python tools/liquefy_vault_anchor.py verify --vault ./vault --json
python tools/liquefy_vault_anchor.py show   --proof ./vault/.anchor-proof.json --json
```

Install `solders` and `httpx` for on-chain anchoring: `pip install solders httpx`. Proof computation works without any Solana dependencies.

### Key Backup (Disaster Recovery)

If your machine dies and `LIQUEFY_SECRET` was only an env var, your encrypted cloud backups are bricks. Back up your key:

```bash
make key-backup                        # Export key (passphrase-protected)
make key-card                          # Printable recovery card
make key-recover SRC=./backup.enc      # Recover key on new machine
make key-verify SRC=./backup.enc       # Verify backup is valid
```

Or directly:

```bash
python tools/liquefy_key_backup.py export --output key_backup.enc
python tools/liquefy_key_backup.py recover --input key_backup.enc
python tools/liquefy_key_backup.py card --output RECOVERY_CARD.txt
python tools/liquefy_key_backup.py verify --input key_backup.enc
```

The backup file is encrypted with your passphrase (AES-256-GCM, PBKDF2 600k iterations). Store it on a USB, in a password manager, or print the recovery card and put it in a safe.

### Cloud Sync (S3 / R2 / MinIO)

Sync encrypted vaults to S3-compatible storage. Cloud provider sees only opaque blobs — sovereign means encrypted everywhere.

```bash
make cloud-push VAULT=./vault BUCKET=my-backups                          # Push (incremental)
make cloud-push VAULT=./vault BUCKET=my-r2 ENDPOINT=https://xxx.r2.cloudflarestorage.com  # R2
make cloud-pull VAULT=./vault BUCKET=my-backups                          # Restore from cloud
make cloud-status VAULT=./vault BUCKET=my-backups                        # Compare local vs remote
make cloud-verify VAULT=./vault BUCKET=my-backups                        # Verify remote integrity
```

Or directly:

```bash
python tools/liquefy_cloud_sync.py push   --vault ./vault --bucket my-backups --json
python tools/liquefy_cloud_sync.py pull   --vault ./vault --bucket my-backups --json
python tools/liquefy_cloud_sync.py status --vault ./vault --bucket my-backups --json
python tools/liquefy_cloud_sync.py verify --vault ./vault --bucket my-backups --json
```

Environment variables: `LIQUEFY_S3_ENDPOINT`, `LIQUEFY_S3_BUCKET`, `LIQUEFY_S3_PREFIX`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.

## Presets (Choose Your Risk Level)

Liquefy defaults to maximum safety. Use presets to match your risk tolerance:

### SAFE (default) — recommended for production

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault --json
```

- Credentials, keys, envs: **BLOCKED**
- MRTV verification: **FULL**
- Profile: **default** (balanced ratio/speed)

### POWER — faster, still safe, includes more file types

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault \
  --mode balanced --profile speed --verify-mode fast --json
```

- Most credentials still blocked
- MRTV: fast (sampled verification)
- Profile: speed-first

### YOLO — everything included, your responsibility

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault \
  --mode off --profile ratio --verify-mode full \
  --include-secrets "I UNDERSTAND THIS MAY LEAK SECRETS" --json
```

- Nothing blocked
- Max compression ratio
- Full verification still on (non-negotiable safety net)

### Custom policy file

```bash
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./vault \
  --policy ./policies/my_policy.yml --json
```

Policy files live in `./policies/`. Examples: `strict.yml`, `balanced.yml`, `demo_risky.yml`.

## Interactive Setup

```bash
python tools/liquefy_setup.py
```

Walks you through:
1. What directories to watch
2. Risk tolerance (safe/power/yolo)
3. Encryption (on/off + secret generation)
4. Notifications (telegram/discord/off)
5. Daemon vs manual mode
6. Writes config to `~/.liquefy/config.json`

## JSON Output (Machine-Readable)

Every command supports `--json` for structured output:

```bash
python tools/tracevault_pack.py ./data --org dev --out ./vault --json
```

Returns:

```json
{
  "schema_version": "liquefy.tracevault.cli.v1",
  "command": "pack",
  "ok": true,
  "result": {
    "total_original_bytes": 104857600,
    "total_compressed_bytes": 15728640,
    "overall_ratio": 6.67,
    "files_processed": 42,
    "verify_mode": "full",
    "mrtv_all_pass": true
  }
}
```

Schema contracts are in `./schemas/`.

## Health Checks

```bash
# Are all dependencies installed?
python tools/liquefy_cli.py doctor --json

# Do all engines load and roundtrip?
python tools/liquefy_cli.py self-test --json

# What version is this?
python tools/liquefy_cli.py version --json
```

## Capabilities Summary

| Capability | Tool | Status |
|------------|------|--------|
| Compress any directory | `tracevault_pack.py` | Production |
| Restore from vault | `tracevault_restore.py` | Production |
| Search compressed data | `tracevault_search.py` | Production |
| OpenClaw workspace pack | `liquefy_openclaw.py` | Production |
| Secret/leak scanning | `liquefy_leakhunter.py` | Production |
| Background archival | `liquefy_archiver.py` | Production |
| Vault visualization | `liquefy_viz.py` | Production |
| Telemetry ingestion | `liquefy_telemetry_sink.py` | Production |
| Obsidian sync | `liquefy_obsidian.py` | Production |
| Skill sandboxing | `liquefy_sandbox.py` | Production |
| AES-256-GCM encryption | `--secure` flag | Production |
| Policy engine | `--policy` flag | Production |
| **Native OpenClaw hooks** | `liquefy_openclaw_plugin.py` | Production |
| **Bloat prediction** | `liquefy_intelligence.py predict` | Production |
| **Smart prune** | `liquefy_intelligence.py prune` | Production |
| **Value scoring** | `liquefy_intelligence.py score` | Production |
| **LLM summarization** | `liquefy_intelligence.py summarize` | Production |
| **Policy suggestions** | `liquefy_intelligence.py suggest` | Production |
| **Backup migration** | `liquefy_intelligence.py migrate` | Production |
| **Tamper-proof audit** | `liquefy_audit_chain.py` | Production |
| **Graceful degradation** | `liquefy_resilience.py` | Production |
| **Plugin ecosystem** | `plugin_loader.py` + community dirs | Production |
| **Fleet coordination** | `liquefy_fleet.py` + `liquefy_fleet_cli.py` | Production |
| **Shared namespace** | File-lock coordination, atomic index | Production |
| **Cross-agent merge** | 4 conflict resolution strategies | Production |
| **Resource quotas** | Per-agent storage/rate/session limits | Production |
| **Compliance reports** | `liquefy_compliance.py` | Production |
| **Vision dedup** | `liquefy_vision.py` (Engine #24) | Production |
| **Cloud sync (S3/R2/MinIO)** | `liquefy_cloud_sync.py` | Production |

## Compression Engines (24 total, auto-selected)

| Data Type | Engine | Typical Ratio |
|-----------|--------|---------------|
| JSON/JSONL | HyperNebula columnar | 5-7x |
| Apache logs | Repetition-aware | 6-8x |
| Syslog | Token + repetition | 5-6x |
| SQL dumps | Velocity + repetition | 7-8x |
| K8s logs | Velocity | 6-7x |
| CloudTrail | Domain-specific | 10-12x |
| VPC Flow | Columnar | 3-4x |
| Nginx logs | Token + repetition | 5-7x |
| GitHub events | Domain-specific | 4-6x |
| Windows EVTX | Domain-specific | 4-6x |
| VMware logs | Domain-specific | 5-7x |
| NetFlow | Domain-specific | 3-5x |
| Everything else | Universal + Fallback | 3-7x |
| **Screenshots/Images** | **Vision perceptual dedup** | **5-20x** |

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `LIQUEFY_PROFILE` | `default` / `ratio` / `speed` | `default` |
| `LIQUEFY_SECRET` | Master encryption secret | (none — encryption disabled) |
| `LIQUEFY_TG_BOT_TOKEN` | Telegram notifications | (none) |
| `LIQUEFY_TG_CHAT_ID` | Telegram chat ID | (none) |
| `LIQUEFY_DISCORD_WEBHOOK` | Discord notifications | (none) |
| `LIQUEFY_DISABLE_COLUMNAR` | Set to `1` to skip columnar engines | (none) |
| `LIQUEFY_FLEET_ROOT` | Fleet shared vault root | `~/.liquefy/fleet` |
| `LIQUEFY_AUDIT_DIR` | Audit chain storage directory | `~/.liquefy/audit` |
| `LIQUEFY_ORG` | Organization name for compliance reports | `default` |
| `LIQUEFY_S3_ENDPOINT` | S3 endpoint URL (for R2/MinIO) | (none) |
| `LIQUEFY_S3_BUCKET` | S3 bucket name | (none) |
| `LIQUEFY_S3_PREFIX` | S3 key prefix | `liquefy/` |

## File Layout

```
liquefy/
├── api/                    # Core engines + orchestrator + safety + security
│   ├── orchestrator/       # Engine routing, registry, contracts
│   ├── containers/         # .null vault format + bloom filters
│   ├── engines/core/       # 23 engine manifests (engine.json)
│   ├── json/               # JSON family engines (4)
│   ├── apache/             # Apache engines (2)
│   ├── syslog/             # Syslog engines (2)
│   ├── sql/                # SQL engines (3)
│   ├── k8s/                # Kubernetes engines (2)
│   ├── aws/                # CloudTrail + VPC Flow (2)
│   ├── nginx/              # Nginx engines (2)
│   ├── scm/                # GitHub engine (1)
│   ├── windows/            # Windows EVTX (1)
│   ├── vmware/             # VMware (1)
│   ├── netflow/            # NetFlow (1)
│   ├── universal/          # Universal + Fallback (2)
│   ├── vision/             # Screenshot perceptual dedup (1) — Engine #24
│   ├── liquefy_safety.py       # MRTV verification
│   ├── liquefy_security.py     # LSEC v2 encryption
│   ├── liquefy_primitives.py   # Shared varint/zigzag/bloom
│   ├── liquefy_audit_chain.py  # Tamper-proof hash-chained audit log
│   ├── liquefy_resilience.py   # Graceful degradation + self-healing
│   ├── liquefy_fleet.py        # Multi-agent fleet coordination core
│   └── orchestrator/
│       └── plugin_loader.py    # Community engine/pattern auto-discovery
├── tools/                      # CLI tools (all commands above)
│   ├── liquefy_openclaw_plugin.py  # Native OpenClaw integration
│   ├── liquefy_intelligence.py     # AI intelligence layer
│   ├── liquefy_fleet_cli.py        # Multi-agent fleet CLI
│   ├── liquefy_compliance.py       # HTML compliance report generator
│   ├── liquefy_vision.py           # Screenshot dedup CLI
│   └── liquefy_cloud_sync.py       # S3/R2/MinIO vault sync
├── api/engines/community/      # Drop-in community engines (auto-registered)
├── patterns/community/         # Drop-in leak patterns (auto-registered)
├── skills/                     # ClawHub skills
├── policies/                   # YAML policy files
├── schemas/                    # JSON schema contracts
├── tests/                      # 201 tests
└── bench/                      # Benchmarks
```

## For AI Agent Developers

If you're building an AI agent that uses Liquefy:

1. **Install**: `git clone <repo> && cd liquefy && make setup`
2. **Integrate**: Call CLI tools with `--json` flag, parse JSON output
3. **Schemas**: Validate against `./schemas/liquefy.*.json`
4. **Presets**: Use SAFE for production, POWER for development, YOLO for testing
5. **Monitor**: Use `liquefy_viz.py web` for dashboards or `liquefy_obsidian.py sync` for Obsidian
6. **Automate**: Use `liquefy_archiver.py daemon` for background archival
7. **Secure**: Run `liquefy_leakhunter.py scan --deep` before sharing any data
8. **Extend**: Drop engines into `api/engines/community/` or patterns into `patterns/community/` — auto-discovered
9. **OpenClaw Native**: Run `make openclaw-hook` once — Liquefy becomes the invisible default session store
10. **Intelligence**: Use `make predict` / `make suggest` / `make summarize` for proactive insights
11. **Compliance**: `make audit-verify` checks tamper-proof hash chain integrity. `make compliance VAULT=./vault` generates a beautiful HTML report for auditors
12. **Fleet**: Running multiple agents? Use `make fleet-register` + `make fleet-ingest` for shared namespace with quotas
13. **Vision**: Agent screenshots eating storage? `make vision-pack DIR=./screenshots` deduplicates near-identical frames (80-95% savings)
14. **Cloud Sync**: `make cloud-push VAULT=./vault BUCKET=x` syncs encrypted vaults to S3/R2/MinIO — cloud sees only opaque blobs
