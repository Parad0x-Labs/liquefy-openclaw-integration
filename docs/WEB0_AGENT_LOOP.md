# The Web0 agent loop — get paid, and pay, in USDC on Solana

The point of this stack in one walkthrough: your OpenClaw agent **charges other
agents for its work and pays for theirs, in USDC on Solana mainnet-beta (public
beta, not yet audited) — non-custodial at every step**. You bring one Solana keypair you control; the skills never hold a
key.

| Step | Tool | Where |
|---|---|---|
| 1. Pay other agents / paid APIs | [`x402-pay`](../skills/x402-pay) | Solana mainnet-beta |
| 2. Charge for your agent's work | [`x402-gate`](../skills/x402-gate) | Solana mainnet-beta |
| 3. Anchor receipts on-chain | `receipt_anchor` | Solana mainnet-beta |
| 4. Keep long sessions cheap | [`context-capsule`](../skills/context-capsule) | npm |

---

## 1 · Pay other agents and paid APIs

[`x402-pay`](../skills/x402-pay) gives your agent one tool — `pay_x402(url)`. It
fetches a URL; on HTTP 402 it pays the demanded USDC on Solana and returns the
resource. Bring your own signer (the skill builds an unsigned tx, your wallet
signs) with a hard per-payment USDC cap. Real-money mainnet is **opt-in and off by
default** — set `allowMainnet: true` plus an explicit `rpcUrl` to enable it; the
network for each payment comes from the 402 challenge.

## 2 · Charge for your agent's work

[`x402-gate`](../skills/x402-gate) turns any skill or API into a paid endpoint:
mint a 402 challenge, verify the payment, then serve. With `requireOnChain: true`
you serve only after the transaction settles on-chain. Funds land directly in
your own wallet — the skill holds no keys. The paying and charging sides derive
identical receipt hashes, so the loop reconciles with no shared state.

## 3 · Anchor receipts on-chain

Anchor a 32-byte hash of anything — a payment receipt, a page manifest — on
mainnet-beta via `receipt_anchor`
(`6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN`): a permanent, verifiable trail
with no data and no keys on-chain.

## 4 · Keep long sessions cheap

A paid agent runs long conversations. [`context-capsule`](../skills/context-capsule)
(`npm i @parad0x_labs/openclaw-context-capsule`) compresses old history before
each model call — keeping decisions, errors, IDs, and values while cutting tokens
(fidelity measured on your own `~/.openclaw` sessions via `test/fidelity-bench.mjs`).

---

## Your `.null` identity — live

Your agent can own a `.null` name on Solana that doubles as its identity and its
on-chain payment address. The naming layer — registrar, auctions, and pay-by-name
— runs on **Solana mainnet-beta** (public beta; registrar `NXgQhepF…`, self-serve
registration rolling out). Each name's record stores its
x402 endpoint on-chain, so:

```
pay_x402("myagent.null")   →  resolve on mainnet-beta → read its x402 endpoint → pay
```

`x402-pay` accepts a `.null` name directly (it resolves, then pays the published
endpoint), and `mcp-server`'s `resolve_null` reads any name's owner + endpoint +
stealth meta. Register a name and publish your endpoint (`UPDATE_ENDPOINT`) to be
payable by name. Only **max-private** pay (sender + amount hidden) is still rolling
out on devnet — basic recipient-private pay-by-name is live.

## Notes

- **Non-custodial throughout.** Every skill builds transactions your own wallet
  signs; none holds a key. Spend is capped on the paying side and settles to your
  own wallet on the charging side.
- **Reach.** Agents resolve and transact on-chain directly — including pay-by-name
  against the live `.null` registrar.
- **Amounts.** USDC amounts are exact; any storage-cost figures are quoted at
  upload time by the bundler.
