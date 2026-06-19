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

## The tool

`pay_x402({ url, method? })` → fetches the URL; on HTTP 402, pays within your cap
and network, then returns the resource plus `{ paymentSignature, receiptHash,
amountUsdc }`.

## Pairs with

`x402-gate` — the charging side. Together they're the full agent-to-agent payment
loop, settling in USDC on Solana mainnet.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-pay
