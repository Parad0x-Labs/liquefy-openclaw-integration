---
name: web0-onboard
description: One-call web0 setup for an OpenClaw agent — checks on-chain identity, emits a paid x402 storefront config (funds to your wallet), wires receipt anchoring, and reserves a .null name-binding plan. Sell services for USDC on Solana. Read-only, non-custodial.
tags: web0, null, x402, solana, monetization, agents, openclaw
requires_openclaw: ">=2026.6.1"
---

# web0 Onboard

Set up an agent on web0 in **one call**. Tell it your payout wallet, the services
you want to sell, and (optionally) a `.null` name — it returns a complete,
validated setup your agent can act on immediately.

## What it does

`web0_onboard({ name, solanaWallet, services, network })` returns:

- **Identity** — derives your on-chain identity PDA and checks whether it's bound.
- **Storefront** — a drop-in `x402-gate` config (recipient = your wallet, per-service
  prices) so you start charging USDC on Solana right away. Funds settle to **your**
  wallet; the plugin never holds a key.
- **Receipts** — the live `receipt_anchor` program, so every sale leaves a
  permanent, verifiable trail.
- **Name plan** — if you pass a `name`, a validated `.null` binding plan that
  registers and points at your x402 endpoint **the moment the naming layer is
  live** — no re-wiring later.

## The loop it sets up

```
seller: web0_onboard(...) → enable x402-gate with the returned config → live
buyer:  pay_x402(<your endpoint>)        → quote → pay USDC → receipt
        pay_x402("yourname.null")        → (once the resolver is live) pay by name
```

## Trust model

- **Read-only.** It validates inputs, derives/checks on-chain state, and emits
  config. It never signs, never holds a key, never moves funds.
- **Non-custodial throughout.** The x402-gate it configures settles to your own
  wallet; your own signer runs every transaction.
- **Public RPC only** — `solana-rpc.publicnode.com` by default. No seized program
  IDs.

## Status

The full loop is live on Solana mainnet today: identity, a paid storefront,
receipts — **and** the `.null` naming layer (registrar `NXgQhepF…`). Register a
name, publish your x402 endpoint, and buyers can `pay_x402("yourname.null")`. Only
max-private shielded pay (sender + amount hidden) is still rolling out on devnet.

## Config (all optional defaults)

```jsonc
{
  "plugins": {
    "entries": {
      "web0-onboard": {
        "solanaWallet": "<your base58 wallet>",
        "name": "myagent",
        "network": "solana-mainnet"
      }
    }
  }
}
```

Pairs with [`x402-gate`](../../skills/x402-gate) (charge), [`x402-pay`](../../skills/x402-pay)
(pay), and [`agent-passport`](../agent-passport) (identity).
