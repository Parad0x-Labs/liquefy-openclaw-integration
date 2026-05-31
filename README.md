# liquefy-openclaw-integration

24 domain-aware compression engines with hash-chained audit trails and on-chain anchoring. Built for AI agent infrastructure.

![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)
![Engines: 24](https://img.shields.io/badge/Engines-24-cyan?style=flat-square)
![Verification: Bit-Perfect](https://img.shields.io/badge/Verification-Bit--Perfect-white?style=flat-square)

Each data type gets a specialized engine. JSON, SQL, VPC flow logs, PCAP, Parquet, agent traces. Output is encrypted, verified, and restorable.

**License:** BUSL-1.1 (source-available; commercial license available separately). See LICENSE.

### How this fits the Parad0x stack

Parad0x Labs builds Web0 on Solana. **You are here: Audit.**

| Layer | Repo | Does |
|---|---|---|
| Payments | [dna-x402](https://github.com/Parad0x-Labs/dna-x402) | x402 rail: quote → pay → verify → receipt → anchor |
| Build | [dna-x402-builders](https://github.com/Parad0x-Labs/dna-x402-builders) | Hosted kit: turn any API/bot into a paid agent |
| Privacy | [Dark-Null-Protocol](https://github.com/Parad0x-Labs/Dark-Null-Protocol) | Groth16 privacy settlement, published proofs |
| Data | [liquefy](https://github.com/Parad0x-Labs/liquefy) | Columnar compression that beats Zstd + audit trails |
| Audit | [liquefy-openclaw-integration](https://github.com/Parad0x-Labs/liquefy-openclaw-integration) (this repo) | 24 engines + Solana-anchored audit trails |
| Media | [nebula-media](https://github.com/Parad0x-Labs/nebula-media) | Perceptual video re-encoding, VMAF quality proofs |
| Local AI | [nulla-local](https://github.com/Parad0x-Labs/nulla-local) | Local-first agent runtime |

**See it live**: parad0xlabs.com

## What it does

- **24 compression engines** — domain-aware codecs for JSON, logs, SQL, network captures, agent traces.
- **Bit-perfect verification** — every compress/decompress cycle verified.
- **Hash-chained audit trails** — SHA-256 chained records with Solana anchoring and automatic secret redaction.
- **Agent protection** — kill switches, context-gated runs, token budget caps, replay blocking, rollback.

## Quick start

```bash
git clone https://github.com/Parad0x-Labs/liquefy-openclaw-integration
cd liquefy-openclaw-integration
make setup && make quick DIR=~/openclaw/sessions
```

© 2026 Parad0x Labs
