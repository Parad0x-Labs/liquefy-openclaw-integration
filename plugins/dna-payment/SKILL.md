---
name: dna-payment-bridge
description: Bridges DNA x402 micropayment audit logs and signed receipts into Liquefy vaults as verifiable proof artifacts. Exports audit events, converts receipts to proof artifacts, and optionally anchors each receipt hash on Solana via an SPL Memo transaction.
license: MIT
metadata:
  author: Parad0x-Labs
---

# DNA Payment Bridge

Archives DNA x402 micropayment audit events and signed receipts into Liquefy
vaults as verifiable proof artifacts.

This is a bridge, not the payment rail. It consumes exported audit events from
a running DNA x402 server and archives them with bit-perfect vault verification.
Protocol concerns (off-chain balances, disputes, slashing, Solana RPC sequencing)
stay in the upstream `dna-x402` codebase.

## What it does

- Exports DNA payment audit events as Liquefy telemetry (NDJSON)
- Converts signed payment receipts into `liquefy.dna.proof.v1` artifacts
- Carries DNA Guard events (spend blocks, replay alerts, validation failures)
- Packs everything into `.null` vaults with bit-perfect MRTV verification

## Quick start

```bash
python plugins/dna-payment/dna_bridge.py status --server http://localhost:8080
```

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/plugins/dna-payment
