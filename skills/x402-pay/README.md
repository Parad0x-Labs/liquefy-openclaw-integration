# openclaw-x402-pay — self-custody x402 payments for OpenClaw agents

> 💜 If it earns its keep, [star openclaw-skills](https://github.com/Parad0x-Labs/openclaw-skills) — stars are how agent builders find it.

Give your agent one tool — `pay_x402` — that fetches an x402-gated URL and, if it
answers HTTP **402 Payment Required**, pays for it on Solana and returns the
resource. Pairs with [`x402-gate`](../x402-gate)
(the charging side) to form the full agent-to-agent payment loop, settling in
**USDC on Solana mainnet**. Each payment stamps its receipt hash on-chain in the
transaction's SPL memo, so every settlement is publicly auditable.

## Trust model — read this first

- **Bring your own signer.** You supply an `X402Signer` (wallet adapter, hardware
  signer, KMS). The skill builds an **unsigned** transaction, hands it to your
  signer, and broadcasts the signed bytes. **It never holds, requests, or reads a
  private key.**
- **Real-money is opt-in.** `allowMainnet` defaults **false**; set it `true` to
  enable mainnet (which also requires an explicit `rpcUrl`).
- **Hard spend cap.** `maxAmountUsdc` is enforced *before any transaction is
  built*. A 402 demanding more is refused.
- **Minimal network surface.** Talks only to your configured Solana RPC and the
  target URL. No telemetry, no third-party calls. Mainnet requires an explicit
  `rpcUrl` (the public RPC is a third-party observer and unreliable for payments).
- **Cumulative cap.** `maxTotalUsdc` bounds total spend across the process — not
  just per payment — so a malicious endpoint can't drain the wallet one capped
  payment at a time. Finite default; raise it via config.
- **No double-pay.** If a confirmation is ambiguous, the result is returned as
  `pending` with the signature — never a clean error — so a retry can't pay twice.
- **Pay once, reuse.** When the gate issues a capability receipt, the client
  caches it and reuses access to that resource within its scope without paying
  again (presenter-bound, so a stolen token is useless to anyone else).

> **Non-custodial and spend-capped.** Your agent signs with its own wallet; no
> single payment exceeds the cap you set.

## Install safety

This skill runs where your signer/wallet lives. **Install with `--ignore-scripts`**
so a transitive native addon can't run install-time code on that host:

```bash
npm install --ignore-scripts @parad0x_labs/openclaw-x402-pay
```

This is **required, not optional** for a key-holding host — and free: the deps are
pure-JS (the native addons are optional and fall back, verified).

## Standalone or together

Part of [openclaw-skills](https://github.com/Parad0x-Labs/openclaw-skills).
Every skill there is a self-contained module — no imports from sibling skills,
own version, own CI lane — so installing, updating, or removing one never
breaks another.

- **Standalone:** yes — this is the *buying* side; it works against any
  x402-compliant endpoint, not just ours.
- **Pairs with:** [`x402-gate`](../x402-gate) on the *selling* agent — the two
  reconstruct identical receipt hashes with no shared state, forming the full
  agent-to-agent payment loop. Optional: [`context-capsule`](../context-capsule)
  to keep long paying sessions cheap.

## Use it

```ts
import plugin, { setX402Signer } from "@parad0x_labs/openclaw-x402-pay";

// Wire YOUR wallet in at startup. The skill only ever gets a serialized tx back.
setX402Signer({
  publicKey: myWallet.publicKey.toBase58(),
  signTransaction: async (txBase64) => myWallet.signSerialized(txBase64), // you sign
});
```

Then the agent can call the tool:

```
pay_x402({ url: "https://api.example.com/premium" })
→ { ok, status, body, paymentSignature, receiptHash, amountUsdc, payTo, network }
```

## Config

```jsonc
{
  "plugins": {
    "entries": {
      "x402-pay": {
        "maxAmountUsdc": 0.50,     // refuse any single payment above this
        "maxTotalUsdc": 50,         // cumulative cap this process (default: 100x per-payment)
        "allowMainnet": true,       // enable real-money mainnet (opt-in; default false)
        "rpcUrl": "https://..."     // REQUIRED on mainnet (a private RPC)
      }
    }
  }
}
```

| Key | Default | Description |
|---|---|---|
| `maxAmountUsdc` | `1.0` | Hard per-payment USDC cap, enforced before building any tx |
| `maxTotalUsdc` | `100 × maxAmountUsdc` | Cumulative cap across the process (finite; raise for volume) |
| `allowMainnet` | `false` | Set `true` to enable real-money mainnet payments (also needs `rpcUrl`) |
| `allowedRecipients` | — | Optional `payTo` allowlist; if set, any other recipient is refused |
| `rpcUrl` | — | Solana RPC. **Required on mainnet**; optional on devnet |

## How a payment flows

1. `pay_x402` fetches the URL. Not a 402 → returns the body, no payment.
2. On 402: parse the challenge, pick a requirement **within the cap and allowed
   network** (else refuse).
3. Build an unsigned USDC transfer (idempotent recipient-ATA create + checked
   transfer + memo carrying the receipt hash).
4. Your signer signs it. The skill broadcasts and retries the request with the
   `X-Payment` proof header.
5. Return the resource plus `{ paymentSignature, receiptHash, amountUsdc }`.

## No external @parad0x_labs dependency

The Solana-specific constants and the x402 wire types are vendored inline. Runtime
deps are only the well-known `@solana/web3.js` and `@solana/spl-token`.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-pay
