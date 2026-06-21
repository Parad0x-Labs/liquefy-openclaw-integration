# @parad0x_labs/openclaw-web0-onboard 🚀

**One call sets your agent up on web0** — identity, a paid x402 storefront, receipt
anchoring, and a `.null` name-binding plan. Sell services for USDC on Solana; funds
settle to **your** wallet. Read-only, non-custodial.

```bash
npm i @parad0x_labs/openclaw-web0-onboard   # from source until published
```

> Requires OpenClaw **≥ 2026.6.1**. Never signs, never holds a key.

## The one tool

```js
web0_onboard({
  name: "myagent",                       // optional .null name
  solanaWallet: "<your base58 wallet>",  // payout wallet
  services: [
    { name: "summarize", priceUsdc: 0.02, description: "Summarize a URL" },
    { name: "translate", priceUsdc: 0.05 }
  ],
  network: "solana-mainnet"
})
```

Returns a consolidated, validated setup:

| Section | What you get |
|---|---|
| `identity` | your on-chain identity PDA + whether it's bound |
| `storefront` | drop-in `x402-gate` config (recipient = your wallet, per-service prices) |
| `receipts` | the live `receipt_anchor` program for a permanent sales trail |
| `name` | a `.null` binding plan that activates when the naming layer deploys |
| `next_steps` / `summary` | an ordered, human-readable go-live checklist |

## How it fits

```
seller: web0_onboard(...) → enable x402-gate with storefront.x402_gate_config → live
buyer:  pay_x402(<your x402 endpoint>) → quote → pay USDC → receipt
        pay_x402("myagent.null")       → pay by name (once the resolver is live)
```

The sell-and-earn loop (identity + storefront + receipts) is live on Solana
mainnet today. The `.null` name + pay-by-name bind in automatically when the web0
naming layer (registrar + resolver) deploys — no re-wiring.

## Trust model

- **Read-only orchestration** — validates inputs, checks on-chain state, emits
  config. No signing, no custody, no fund movement.
- **Public RPC only** (`solana-rpc.publicnode.com`); no seized program IDs.

Pairs with `x402-gate`, `x402-pay`, and `agent-passport`. MIT licensed.
