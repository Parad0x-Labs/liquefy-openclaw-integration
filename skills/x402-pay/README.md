# openclaw-x402-pay — self-custody x402 payments for OpenClaw agents

> 💜 If it earns its keep, [star openclaw-skills](https://github.com/Parad0x-Labs/openclaw-skills) — stars are how agent builders find it. (ClawHub listing: pending publish.)

Give your agent one tool — `pay_x402` — that fetches an x402-gated URL and, if it
answers HTTP **402 Payment Required**, pays for it on Solana and returns the
resource. Pairs with [`x402-gate`](../x402-gate)
(the charging side) to form the full agent-to-agent payment loop on a rail that's
**live on Solana mainnet** (program `9bPBmDNnKGxF8GTt4SqodNJZ1b9nSjoKia2ML4V5gGCF`).

## Trust model — read this first

- **Bring your own signer.** You supply an `X402Signer` (wallet adapter, hardware
  signer, KMS). The skill builds an **unsigned** transaction, hands it to your
  signer, and broadcasts the signed bytes. **It never holds, requests, or reads a
  private key.**
- **Devnet by default.** Real-money mainnet payments require `allowMainnet: true`.
- **Hard spend cap.** `maxAmountUsdc` is enforced *before any transaction is
  built*. A 402 demanding more is refused.
- **Minimal network surface.** Talks only to your configured Solana RPC and the
  target URL. No telemetry, no third-party calls.

> **Status: Public Beta.** Non-custodial, capped, **unaudited** — no external audit
> has been completed or scheduled. Do not point it at large balances.

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
        "allowMainnet": false,      // true = real money on mainnet
        "rpcUrl": "https://..."     // optional private RPC
      }
    }
  }
}
```

| Key | Default | Description |
|---|---|---|
| `maxAmountUsdc` | `1.0` | Hard per-payment USDC cap, enforced before building any tx |
| `allowMainnet` | `false` | Must be `true` to authorize mainnet (real-money) payments |
| `rpcUrl` | public RPC | Optional Solana RPC override |

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
