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

## The two tools

- `x402_challenge({ resource, priceUsdc? })` → a 402 challenge body to send an
  unpaid caller.
- `x402_verify({ header, resource })` → validates the payment; with
  `requireOnChain: true`, confirms the transaction settled on Solana first.

## Safety

- **No keys, no custody** — `recipientAddress` is your public wallet.
- **Replay-resistant** — verification binds to a unique per-payment receipt hash
  carried in the on-chain memo.

> **Non-custodial** — funds settle to your own wallet; the skill holds no keys.

## Pairs with

`x402-pay` — the paying side. Together: the full agent-to-agent payment loop,
settling in USDC on Solana mainnet.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-gate
