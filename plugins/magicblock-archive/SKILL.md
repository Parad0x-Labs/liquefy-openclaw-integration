---
name: magicblock-archive
description: Archive MagicBlock Ephemeral Rollup session transaction logs — compresses ER sessions into Liquefy vaults and optionally anchors the root on Solana via receipt_anchor. Fills the MagicBlock auditability gap. x402 session playback pricing included.
license: MIT
metadata:
  author: Parad0x-Labs
---

# MagicBlock Archive

Compresses MagicBlock Ephemeral Rollup (ER) session logs into Liquefy vaults
with optional Solana mainnet anchoring. Fills the MagicBlock auditability gap
by keeping a verifiable, tamper-evident record of every ER session.

x402 session playback pricing is included — charge per replay access.

## When to use

- Running MagicBlock Ephemeral Rollup sessions and need an audit trail
- Want on-chain proof of an ER session outcome without storing full logs on-chain
- Need x402-gated access to ER session history playback

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/plugins/magicblock-archive
