---
name: dark-null-bridge
description: Archive Dark NULL ZK settlement data into encrypted Liquefy TraceVaults with optional Solana mainnet anchoring via receipt_anchor. Bridges zero-knowledge proof outputs into a verifiable, tamper-evident vault.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Dark NULL Bridge

Archives Dark NULL Protocol ZK settlement data into encrypted TraceVaults.
Optional on-chain anchoring via `receipt_anchor` (`6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN`)
puts the vault root permanently on Solana mainnet.

## What it does

- Exports Dark NULL ZK proof outputs and settlement events as Liquefy telemetry
- Packs them into bit-perfect `.null` vaults with MRTV proofs
- Optionally anchors the vault root hash on Solana mainnet via `receipt_anchor`
- Prevents replay of already-settled proofs

## When to use

- Running shielded (Dark NULL) payments and need a tamper-evident audit trail
- Want on-chain proof that a ZK settlement happened, without revealing amounts or parties
- Need to export ZK settlement evidence for dispute resolution or compliance

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/plugins/dark-null
