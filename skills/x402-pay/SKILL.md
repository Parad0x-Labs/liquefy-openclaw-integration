---
name: openclaw-x402-pay
description: Pay x402-gated APIs and AI agents on Solana — builds an unsigned payment transaction, verifies settlement on-chain, and returns a receipt hash. Hard spend cap enforced before any transaction. BYO signer, no keys held.
license: MIT
metadata:
  author: Parad0x-Labs
---

# x402 Pay

Let your OpenClaw agent **pay for x402-gated APIs, data, and other agents** on
Solana — without ever handing the skill a private key.

> **Bring your own signer.** The skill builds an *unsigned* transaction and hands
> it to a wallet/signer you control. It never holds, requests, or reads a key.

## When to use

- Your agent needs to call a paid (x402 / HTTP 402) API or buy a resource from
  another agent, and you want it to settle in USDC on Solana automatically.
- You want a hard spend cap and self-custody, not a hosted wallet.

## When NOT to use

- You haven't set a sensible `maxAmountUsdc` cap — the skill enforces one before
  any payment and will (correctly) refuse anything above it.
- You want the skill to custody keys for you. It won't, by design.

## Safety rails

- **Install with `--ignore-scripts`** (required): this skill runs where the payment
  key lives; never let a transitive native addon run install-time code on that host.
- **Real-money is opt-in**; set `allowMainnet: true` to enable mainnet (also needs `rpcUrl`).
- **Hard `maxAmountUsdc` cap**, enforced before any transaction is built.
- **Minimal network**: your Solana RPC + the target URL only. No telemetry.

> **Non-custodial and spend-capped by design** — your agent signs with its own
> wallet; no single payment exceeds your cap.

## Tools

- `pay_x402({ url, method? })` → fetches the URL; on HTTP 402, pays within your cap
  and network, then returns the resource plus `{ paymentSignature, receiptHash,
  amountUsdc }`. `url` may be a `name.null` to pay by name.
- `rep_identity()` → your agent's public reputation commitment, to bind a proof to
  this agent (hand it to a gate as `expectedAgentCommitment`). Reveals nothing secret.
- `prove_reputation({ root, minCount, minVolume, windowStart, epoch, receipts })` →
  a private proof of track record (see below).

## Private reputation (zk-rep)

Prove you hold **enough settled receipts to clear a gate** — `>= minCount` receipts
totalling `>= minVolume` since `windowStart`, in an anchored receipt tree — **without
revealing any individual amount, counterparty, or wallet**. A Groth16 proof
(`track_record.circom`, BN254) the gate verifies with `x402_rep_verify`.

- **Secret stays put.** Register your reputation key with `setReputationKey({ secret,
  agentId })` — a live capability, like the signer, never serialized into config. It
  never appears in a proof, a return value, a log, or an error.
- **Single-use.** Each proof carries a per-epoch nullifier the gate spends once.
- **Bind it.** Pass `expectedAgentCommitment` so a proof can't be transplanted to
  another agent.

Proving artifacts (the circuit `wasm`/`zkey`) are hosted and passed by path/URL
(`repWasmPath`/`repZkeyPath`), not bundled. Off-chain verification runs today; a
multi-party ceremony and on-chain trustless verification are coming next.

## Pairs with

`x402-gate` — the charging side. Together they're the full agent-to-agent payment
loop, settling in USDC on Solana mainnet.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-pay
