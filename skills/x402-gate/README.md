# openclaw-x402-gate — charge other agents with x402 on Solana

> 💜 If it earns its keep, [star openclaw-skills](https://github.com/Parad0x-Labs/openclaw-skills) — stars are how agent builders find it.

Turn any OpenClaw skill or API into a paid endpoint. Mint an HTTP **402 Payment
Required** challenge, verify the payment, then serve. Funds settle **straight to
your own wallet** on Solana — the skill holds no keys and takes no custody. Pairs
with [`x402-pay`](../x402-pay)
(the paying side) for the full agent-to-agent loop on a rail that's **live on
Solana mainnet**.

## Trust model

- **No custody.** `recipientAddress` is *your* public wallet; payments land there
  on-chain. This skill signs nothing and holds no keys.
- **Stateless.** Both tools reconstruct the same requirement from config +
  resource, so receipt hashes match the paying side with no shared state.
- **Revenue-grade option.** Set `requireOnChain: true` and a payment is accepted
  only after its transaction is **confirmed settled on Solana** — not just a
  well-formed header. The check binds to the unique receipt hash in the tx memo,
  so proofs can't be replayed against a different charge.

> **Non-custodial.** Payments settle straight to your own wallet; the skill holds
> no keys and signs nothing.

## Standalone or together

Part of [openclaw-skills](https://github.com/Parad0x-Labs/openclaw-skills).
Every skill there is a self-contained module — no imports from sibling skills,
own version, own CI lane — so installing, updating, or removing one never
breaks another.

- **Standalone:** yes — this is the *selling* side; any x402-compliant client
  can pay your gate, not just our skill.
- **Pairs with:** [`x402-pay`](../x402-pay) on the *buying* agent for the full
  loop (matching receipt hashes, no shared state). Optional:
  [`context-capsule`](../context-capsule) to keep long selling sessions cheap.

## The two tools

```
x402_challenge({ resource, description? })
  → { status: 402, body }          // send `body` to an unpaid caller

x402_verify({ header, resource })
  → { valid, payerAddress, amountUsdc, receiptHash, onChainVerified, capability? }
```

## Config

```jsonc
{
  "plugins": {
    "entries": {
      "x402-gate": {
        "recipientAddress": "YOUR_SOLANA_WALLET",      // required — where funds land
        "priceUsdc": 0.05,
        "network": "solana-mainnet",                    // default
        "challengeSecret": "<random 32+ char secret>",  // REQUIRED on mainnet
        "replayStorePath": "/var/lib/x402/replay.log",  // REQUIRED on mainnet (durable, single-instance)
        "acknowledgeSingleInstance": true,              // confirm you run ONE instance
        "rpcUrl": "https://<your-private-rpc>"          // recommended on mainnet
      }
    }
  }
}
```

| Key | Default | Description |
|---|---|---|
| `recipientAddress` | — (required) | Your wallet; payments settle here. Public key only. |
| `priceUsdc` | `0.01` | Default price per request (USDC) |
| `network` | `solana-mainnet` | Settlement network. Set `solana-devnet` to test |
| `requireOnChain` | `true` | Confirm settlement before serving. **Refused on mainnet if `false`** (header-only mode is devnet/testing only) |
| `dedupe` | `true` | Single-use payment guard. On mainnet needs a durable store (below) |
| `replayStorePath` | — | Restart-durable, **single-instance** replay store path. Required on mainnet with `dedupe` |
| `acknowledgeSingleInstance` | `false` | Attest you run ONE instance (the file store isn't shared across replicas). Required on mainnet with `dedupe` |
| `acknowledgeExternalReplayStore` | `false` | Attest you run your own shared store. Required on mainnet with `dedupe: false` |
| `requirePresenterAuth` | `true` | Caller signs the nonce with the payer key. **Forced on for mainnet** |
| `challengeSecret` | — | MACs nonces + capability tokens. **Required on mainnet** |
| `receiptScopeSeconds` | `0` | >0 issues a reusable capability token (pay once, reuse within scope) |
| `rpcUrl` | — | Solana RPC for settlement checks. Use a private node on mainnet |

> **Mainnet is fail-closed.** On `solana-mainnet` the gate refuses to serve (every
> call returns an error) unless: `requireOnChain` is true; replay is durable
> (`replayStorePath` + `acknowledgeSingleInstance`, or `dedupe: false` +
> `acknowledgeExternalReplayStore` with your own shared store); a `challengeSecret`
> and an explicit `rpcUrl` are set. Header-only mode (`requireOnChain: false`) is
> allowed only on devnet.

### Scaling: single instance vs. multiple replicas

The built-in replay store (`replayStorePath` → `FileReplayStore`) is **per-instance**:
it lives on one process's disk and is **not shared across replicas**. Running two
copies against the same path would let one settled payment be redeemed once *per
replica*. To prevent that, `FileReplayStore` takes a **single-instance lock** on
startup — a second instance pointed at the same path **refuses to start**.

- **Single instance (default):** set `replayStorePath` + `acknowledgeSingleInstance: true`. Done.
- **Multiple replicas / load-balanced:** do **not** use `replayStorePath`. Set
  `dedupe: false` + `acknowledgeExternalReplayStore: true` and enforce replay in
  your own **shared atomic store** (Redis `SETNX` / a DB unique constraint) around
  the returned `signature`/`receiptHash` before serving.

> ⚠️ **Capabilities (`receiptScopeSeconds > 0`) are single-instance only** — they
> require `dedupe: true` + `replayStorePath` + `acknowledgeSingleInstance` and the
> gate refuses them in multi-replica (`dedupe: false`) mode. `replayStorePath` must
> be **local disk**; a shared/network filesystem across hosts defeats the lock.

## Install safety

This skill runs where your seller wallet lives. **Install with `--ignore-scripts`**
so a transitive native addon can't run install-time code on that host:

```bash
npm install --ignore-scripts @parad0x_labs/openclaw-x402-gate
```

> Lands on npm with the v1.1 release. Until then, install from source (this repo,
> `skills/x402-gate`); the command above resolves once it's published.

This is **required, not optional** for a key-holding host. `--ignore-scripts` skips
any transitive native builds; the libraries fall back to pure-JS at runtime, so
nothing is lost (verified on this skill's dependency tree).

## Flow

1. Caller hits your gated capability with no payment → `x402_challenge` returns a
   402 telling them the price and your address.
2. Caller pays (e.g. via `openclaw-x402-pay`) and retries with an `X-Payment`
   header.
3. `x402_verify` checks it. With `requireOnChain`, it confirms the transaction
   settled before you serve the resource.

## Operations

- **Rate-limit `x402_verify`.** With `requireOnChain`, each call may cost one
  `getTransaction` on your metered RPC. Presenter-auth limits callers to keypair
  holders (each attempt costs them a signature) but does not rate-limit — put a
  per-source / per-payer limit in front of the endpoint so an unpaid caller can't
  run up your RPC bill.
- **Run one instance per `replayStorePath`.** The file replay store is
  single-writer; the gate refuses to start if another live process holds the lock.
  For multiple replicas, use `dedupe=false` + your own shared store (Redis/DB) and
  set `acknowledgeExternalReplayStore=true`.

## No external @parad0x_labs dependency

Constants and wire types are vendored inline. The runtime dependencies are the
well-known `@solana/web3.js` (on-chain confirmation) and `bs58` (decoding the SPL
Memo instruction for program-attested receipt binding) — both pure JS. A production
`npm audit --omit=dev --omit=peer` reports 0 high (gated at publish).

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-gate
