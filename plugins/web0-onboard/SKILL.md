---
name: web0-onboard
description: web0 setup for an OpenClaw agent — plan your identity + paid x402 storefront, then register a .null name and publish its x402 endpoint so buyers pay you by name. Sell services for USDC on Solana. Non-custodial (your wallet signs).
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
- **Name plan** — if you pass a `name`, a validated `.null` binding plan you can
  apply with the seller tools below.

## Seller-side tools — register + go pay-by-name

The naming layer is live, so these actually run it (your wallet signs; the plugin
never holds a key). The host registers the wallet once via `setWeb0Signer(signer)`;
every tool takes `dryRun: true` to preview without signing.

- **`register_null_name({ name })`** — register your `.null` name on mainnet
  (reads the live fee + treasury; real SOL cost). It's your identity + handle.
- **`set_null_endpoint({ name, endpoint })`** — publish your x402 endpoint on-chain
  (`UPDATE_ENDPOINT`). After this, buyers `pay_x402("yourname.null")`. Owner-only,
  tiny tx fee, no registration fee.
- **`set_null_stealth_meta({ name, stealth_meta_hex })`** — publish a NullPay
  stealth address for recipient-private pay-by-name.

## The loop it sets up

```
seller: web0_onboard(...) → enable x402-gate with the returned config
        register_null_name("myagent") → set_null_endpoint("myagent", <gate URL>)
buyer:  pay_x402("myagent.null")  → resolve → quote → pay USDC → receipt
```

## Trust model

- **Non-custodial.** Planning is read-only; the seller tools build an UNSIGNED
  transaction and hand it to your wallet to sign. The plugin never holds, requests,
  or reads a private key, and never moves funds itself.
- **Owner-gated writes.** `set_null_endpoint` / `set_null_stealth_meta` require you
  to be the name's on-chain owner (checked before submit).
- **Public RPC only** — `solana-rpc.publicnode.com` by default. No seized program
  IDs (registrar pinned to the clean `NXgQhepF…`).

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
