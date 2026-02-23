# 🧪 Liquefy: Entropy-Native Log Analytics

![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)
![License: Commercial](https://img.shields.io/badge/License-Commercial-orange.svg)
![Conduction: 23 Engines](https://img.shields.io/badge/Conduction-23_Engines-cyan?style=flat-square)
![Verification: Bit--Perfect](https://img.shields.io/badge/Verification-Bit--Perfect-white?style=flat-square)

**Liquefy** is an enterprise-grade compression and observability engine designed for high-velocity telemetry.

---

## Trace Vault for agent runs

Agent frameworks produce trace explosions: JSONL logs, tool call outputs, HTML reports.
Trace Vault packs an entire run folder into verified `.null` archives with optional per-org encryption.
Restore is bit-perfect.

### Compression on real log formats (sub-1KB test fixtures, auto-routed)

| Fixture | Input | Output | Ratio | Engine |
|---|---|---|---|---|
| apache.log | 308 B | 250 B | 1.23x | liquefy-apache-rep-v1 |
| cloudtrail.jsonl | 424 B | 224 B | 1.89x | liquefy-json-hypernebula-v1 |
| dump.sql | 276 B | 199 B | 1.39x | liquefy-sql-velocity-v1 |
| sample.json | 393 B | 155 B | 2.54x | liquefy-json-hypernebula-v1 |
| syslog_3164.log | 198 B | 174 B | 1.14x | liquefy-syslog-rep-v1 |
| syslog_5424.log | 196 B | 159 B | 1.23x | liquefy-syslog-rep-v1 |
| vpcflow.log | 288 B | 145 B | 1.99x | liquefy-vpcflow-v1 |

Ratios improve significantly on production-scale files (MB+), where domain-specific engines exploit structural repetition.

### Quick start

```bash
# One-command local install (macOS/Linux, Apple Silicon-friendly source path)
./install.sh

# Activate the local environment
source .venv/bin/activate

# Pack a run folder
python tools/tracevault_pack.py ./runs/latest --org dev --out ./vault/latest

# Restore
python tools/tracevault_restore.py ./vault/latest --out ./restored/latest
```

### Runtime checks (binary-friendly)

```bash
# Build/runtime metadata
python tools/tracevault_pack.py --version --json

# Crypto + zstd + policy smoke checks
python tools/liquefy_openclaw.py --self-test --json

# Environment checks (paths, perms, secret requirements)
python tools/tracevault_restore.py --doctor --json
```

All three wrappers support `--version`, `--self-test`, and `--doctor` (machine-readable with `--json`).

### Drop-in for OpenClaw-style frameworks

```bash
# At end of agent run, pack the output folder
python tools/tracevault_pack.py ./openclaw/runs/latest --org dev --out ./vault/latest
```

### One-command OpenClaw workspace pack

```bash
# Whole-workspace pack with built-in credential denylist + report
./liquefy openclaw --workspace ~/.openclaw --out ./openclaw-vault --verify-mode full --workers 8
```

This command writes `OPENCLAW_LIQUEFY_REPORT.md` inside the vault output folder and keeps compressed search available via:

```bash
./liquefy search ./openclaw-vault --query "trace_id"
```

### Policy audit & safe overrides (OpenClaw + TraceVault)

```bash
# Inspect the active effective policy before packing (human-readable)
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./openclaw-vault \
  --print-effective-policy

# Explain why a path is allowed/denied (JSON, plugin-friendly)
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./openclaw-vault \
  --json --explain credentials/api.pem

# Use a shared policy file for TraceVault scans
python tools/tracevault_pack.py ./runs/latest --org dev --out ./vault/latest \
  --scan-only --policy ./policies/balanced.yml --json

# Explicit risky override (loud, audited, recorded in JSON/report)
python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./openclaw-vault \
  --json --include-secrets "I UNDERSTAND THIS MAY LEAK SECRETS"
```

Policy examples:
- `./policies/strict.yml`
- `./policies/balanced.yml`
- `./policies/demo_risky.yml`

Security docs:
- `./docs/policy.md`
- `./docs/sdk.md`
- `./SECURITY.md`
- `./THREAT_MODEL.md`

JSON schemas (plugin / SDK integration contracts):
- `./schemas/liquefy.tracevault.cli.v1.json`
- `./schemas/liquefy.tracevault.restore.cli.v1.json`
- `./schemas/liquefy.openclaw.cli.v1.json`
- `./schemas/liquefy.cli.v1.json`

Restore safety:
- `tracevault_restore.py` defaults to a `2 GiB` total output cap to prevent disk-filling accidents.
- Use `--max-output-bytes 0` to disable the cap (power-user override).
- This protects local machines/CI runners when restoring untrusted or shared vaults.

Status artifacts (generated):
- `./bench/results/LIQUEFY_STATUS_REPORT.md`
- `./bench/results/LIQUEFY_STATUS_REPORT.json`

Free for personal/private, nonprofit, and academic use (including production in those contexts). Commercial / for-profit use requires a [license](./COMMERCIAL_LICENSE.md), including monetized hosted/API offerings and paid wrappers built on Liquefy.

**Decoder is always available.** Decompression and verification never require a license, a running service, or access to this repo. Archives are self-contained. Your data is never hostage.

Not affiliated with OpenClaw or any agent framework vendor. See [docs/TRACE_VAULT.md](./docs/TRACE_VAULT.md) for details.

### OpenClaw integration (1 minute)

```bash
# Legacy agent-scoped workflow (still supported)
python tools/openclaw_tracevault.py list
python tools/openclaw_tracevault.py pack --agent <agentId> --out ./vault/openclaw/<agentId>
python tools/openclaw_tracevault.py pack --agent <agentId> --since-days 7 --out ./vault/openclaw/<agentId>
```

## ⚖️ License
Liquefy is licensed under the **Business Source License 1.1 (BUSL-1.1)**:
- **Free use (including production)**: Personal/private non-commercial, nonprofit, and academic/educational/research use are permitted under the Additional Use Grant (see `LICENSE`).
- **Commercial / for-profit use**: Requires a commercial license from Parad0x Labs (including internal company use, SaaS/hosted services, embedding, and paid-client work). See [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).
- **Change Date**: 2028-02-22 — after this date, automatically converts to **GPL-2.0-or-later**.
- **Decode-only recovery**: Always free. No license required to decompress or verify `.null` archives.

---

## 🎖️ Enterprise Certification
Liquefy is certified for **100% bit-perfect restoration**. Our comprehensive test suite covers 24 engine combinations and validates integrity against the Golden-Rule standard.

*   [**View Enterprise Evaluation Notes**](./docs/enterprise-evaluation.md)
*   [**View Technical Specification**](./docs/technical-specification.md)

---

## 🛠️ Decoder CLI (Offline Recovery)

The Liquefy decoder CLI/appliance path provides offline data recovery and verification for production `.null` archives in hardened environments.

**This repository + Docker is sufficient for offline decompression and verification. No license is required for decode-only recovery.**

### One-Command Installation
```bash
git clone https://github.com/Parad0x-Labs/liquefy-openclaw-integration.git
cd liquefy-openclaw-integration
# Source install (works today)
./install.sh

# Or use the decoder wrapper directly (Docker-backed path for decode/verify)
chmod +x ./liquefy
```

### Usage (Linux/macOS)
```bash
# Decompress a production archive
./liquefy decompress archive.null restored.log

# Verify bit-perfect integrity
./liquefy verify archive.null
```

### Windows (PowerShell)
```powershell
.\liquefy decompress archive.null restored.log
```

---

## 📂 Complete Source-Available Engine

Unlike our previous black-box releases, this repository now contains the **complete source code** for the Liquefy compression engines, orchestrator, and safety valves.

You can inspect, compile, and run the entire source-available stack locally:

### Using the Source-Available Engines

See the `api/engines` folder for the Python implementations. You can run compressions directly without Docker for non-production use under the BUSL-1.1 license terms.

### OpenClaw Plugin Wrapper (Node.js scaffold)

A Node.js OpenClaw plugin wrapper scaffold is included under:

- `./plugins/openclaw-plugin`

It exposes `liquefy_scan` (read-only) and `liquefy_pack_apply` (optional) by shelling out to the Liquefy CLI JSON contracts.
---

## 🛡️ Execution & Maintenance Policy

The decoder CLI/appliance path is built for **enterprise-grade reliability**. To ensure secure conduction and data sovereignty, the following policies are enforced:

1.  **Maintenance & Compatibility:** This build is optimized for archives generated by v3.1 cores. While decompression is never paywalled, newer archive formats may require the latest signed build of the SDK.
2.  **Execution Safety:** To prevent runtime instability, the appliance requires a standard execution environment. If unauthorized runtime hooks (e.g. `LD_PRELOAD`) are detected, the appliance fails closed.
3.  **Data Sovereignty:** All operations happen locally. No data is ever transmitted back to Parad0x Labs.

## 📊 Benchmark Notes (Read This Before Comparing)

- Liquefy results are **profile- and workload-dependent** (`default`, `ratio`, `speed`).
- `default` / `ratio` profiles are judged against zstd high-compression behavior (zstd-22 class), not zstd speed-first settings.
- `speed` profile is the fair comparison point for zstd-3/zstd-6 throughput claims.
- See the committed visuals for a public-safe summary:
  - `./liquefy_scoreboard_default.png`
  - `./liquefy_vs_zstd_openclaw_50_200.png`

---

## 🏢 Commercial License

For production use of the Licensed Work, Parad0x Labs provides a **Commercial License**.

*   **Email:** [hello@parad0xlabs.com](mailto:hello@parad0xlabs.com)
*   **X (Twitter):** [@Parad0x_Labs](https://x.com/Parad0x_Labs)

© 2026 Parad0x Labs. 🚀
