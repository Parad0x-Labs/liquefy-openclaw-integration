# @parad0x_labs/openclaw-web0-onboard 🚀

**One call sets your agent up on web0** — identity, a paid x402 storefront, receipt
anchoring, and a `.null` name-binding plan. Sell services for USDC on Solana; funds
settle to **your** wallet. Read-only, non-custodial.

```bash
npm i @parad0x_labs/openclaw-web0-onboard
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
| `name` | a validated `.null` binding plan you apply with the seller tools below |
| `next_steps` / `summary` | an ordered, human-readable go-live checklist |

## Seller-side tools (the naming layer is live)

Register once via `setWeb0Signer(wallet)`; your wallet signs every tx — the plugin
never holds a key. Each tool takes `dryRun: true` to preview without signing.

| Tool | Does |
|---|---|
| `register_null_name({ name })` | register your `.null` name on mainnet-beta (reads the live fee + treasury; real SOL) |
| `set_null_endpoint({ name, endpoint })` | publish your x402 endpoint on-chain — now buyers `pay_x402("yourname.null")` |
| `set_null_stealth_meta({ name, stealth_meta_hex })` | publish a stealth address for recipient-private pay-by-name |

## How it fits

```
seller: web0_onboard(...) → enable x402-gate with storefront.x402_gate_config
        register_null_name("myagent") → set_null_endpoint("myagent", <gate URL>)
buyer:  pay_x402("myagent.null")  → resolve → quote → pay USDC → receipt
```

The full loop runs on Solana mainnet-beta today (public beta, not yet audited) —
identity, storefront, receipts, **and** the `.null` naming layer (registrar
`NXgQhepF…`; self-serve registration rolling out). Register a name, publish
your x402 endpoint, and buyers `pay_x402("yourname.null")`. Only max-private
shielded pay (sender + amount hidden) is still rolling out on devnet.

## Trust model

- **Non-custodial.** Planning (`web0_onboard`) is read-only. The seller tools build
  an UNSIGNED transaction for your wallet to sign — the plugin never holds, requests,
  or reads a key, and never moves funds itself. Every write tool has `dryRun`.
- **Owner-gated** — endpoint/stealth writes require you to be the name's on-chain
  owner (checked before submit).
- **Public RPC only** (`solana-rpc.publicnode.com`); registrar pinned to the clean
  `NXgQhepF…` (never the seized pre-incident id).

Pairs with `x402-gate`, `x402-pay`, and `agent-passport`. MIT licensed.
