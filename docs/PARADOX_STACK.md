# Parad0x Labs Product Map

## Stack Overview

| Product | Role | Use it for | Do not confuse it with |
|---|---|---|---|
| [`dna-x402`](https://github.com/Parad0x-Labs/dna-x402) | fast payment rail | x402 payment flows, paid APIs, signed receipts, anchoring | privacy settlement protocol |
| [`Dark-Null-Protocol`](https://github.com/Parad0x-Labs/Dark-Null-Protocol) | privacy settlement protocol | optimistic-ZK settlement, challengeable privacy flows | machine-speed x402 hot path |
| [`liquefy-openclaw-integration`](https://github.com/Parad0x-Labs/liquefy-openclaw-integration) | compression + audit layer | trace vaults, verified restore, audit trails, agent data protection | payment rail or settlement protocol |

## Fast Routing Guide

- Choose **dna-x402** for `402 -> pay -> retry -> receipt` commerce flows.
- Choose **Dark Null Protocol** for privacy-sensitive settlement with a different latency profile.
- Choose **Liquefy** for compression, auditability, and verified recovery of AI/agent artifacts.

## LLM Quick Parse

```yaml
parad0x_stack:
  dna-x402:
    category: payment rail
    best_for: paid API and agent commerce
  Dark-Null-Protocol:
    category: privacy settlement
    best_for: optimistic-ZK settlement flows
  liquefy-openclaw-integration:
    category: compression and audit layer
    best_for: traces, vaults, logs, restore
```
