---
name: dark-null-bridge
description: Archive Dark NULL ZK settlement data into encrypted Liquefy TraceVaults with optional Solana anchoring via an SPL Memo transaction. Bridges zero-knowledge proof outputs into a verifiable, tamper-evident vault.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Dark NULL Bridge

Archives Dark NULL Protocol ZK settlement data into encrypted TraceVaults.
Optional on-chain anchoring writes the SHA-256 vault-root hash to Solana as an
SPL Memo transaction — a timestamped, tamper-evident record.

## What it does

- Exports Dark NULL ZK proof outputs and settlement events as Liquefy telemetry
- Packs them into bit-perfect `.null` vaults with MRTV proofs
- Optionally anchors the vault-root hash on Solana via an SPL Memo transaction
- Prevents replay of already-settled proofs

## When to use

- Running shielded (Dark NULL) payments and need a tamper-evident audit trail
- Want on-chain proof that a ZK settlement happened, without revealing amounts or parties
- Need to export ZK settlement evidence for dispute resolution or compliance

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/plugins/dark-null
