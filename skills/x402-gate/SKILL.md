---
name: openclaw-x402-gate
description: Charge other agents for your OpenClaw skill or API via x402 on Solana. Mint a 402 challenge, verify payment on-chain, then serve. Funds settle directly to your own wallet — no custody, no intermediary.
license: MIT
metadata:
  author: Parad0x-Labs
---

# x402 Gate

**Charge other agents** for your OpenClaw skill or API. Mint a 402 challenge,
verify the payment, then serve — funds settle straight to your own Solana wallet.

> **No custody.** Your wallet address is config; the skill signs nothing and holds
> no keys.

## When to use

- You want to monetize a skill, tool, or API by charging per-call in USDC.
- You want payments to land directly in your wallet with no intermediary custody.

## When NOT to use

- You're serving something valuable but left `requireOnChain` off — structural
  checks alone don't prove settlement. Turn it on for revenue-grade gating.
- You expected the skill to hold a balance for you. It doesn't, by design.

## Tools

- `x402_challenge({ resource, description? })` → a 402 challenge body to send an
  unpaid caller. The price is seller config (`priceUsdc`), never a caller input.
- `x402_verify({ header, resource })` → validates the payment; with
  `requireOnChain: true`, confirms the transaction settled on Solana first.
- `x402_rep_challenge()` → the reputation bar a caller must prove (see below).
- `x402_rep_verify({ proof, publicSignals, expectedAgentCommitment? })` → verifies a
  private reputation proof against your policy.

## Gate on private reputation (zk-rep)

Instead of (or alongside) charging per call, gate on **proven track record**: admit a
caller who proves it holds `>= repMinCount` settled receipts totalling `>= repMinVolume`
within `repWindowSeconds`, in an anchored receipt tree — **learning no individual amount,
counterparty, or wallet**. Set the bar in config (`repMinCount`, `repMinVolume`,
`repWindowSeconds`, `repTrustedRoots`); the caller answers with a Groth16 proof from
`x402-pay`'s `prove_reputation`.

Verification is fail-closed on every seam: the proof must cryptographically verify, clear
your policy floor, build on a **trusted** anchored root, carry a **single-use** nullifier,
and (when you pass `expectedAgentCommitment`) match the caller's bound identity. Runs
off-chain today; a multi-party ceremony and on-chain trustless verification are next.

## Safety

- **No keys, no custody** — `recipientAddress` is your public wallet.
- **Replay-resistant** — verification binds to a unique per-payment receipt hash
  carried in the on-chain memo.

> **Non-custodial** — funds settle to your own wallet; the skill holds no keys.

## Pairs with

`x402-pay` — the paying side. Together: the full agent-to-agent payment loop,
settling in USDC on Solana mainnet-beta (public beta, mainnet opt-in).

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-gate
