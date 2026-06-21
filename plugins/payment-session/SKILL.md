---
name: payment-session
description: Streaming + recurring billing for OpenClaw agents over x402 — meter pay-as-you-go usage or run a subscription, settle in batches through pay_x402, with a hard per-session spend cap. Non-custodial.
tags: x402, streaming-payments, subscription, metering, solana, agents, openclaw
requires_openclaw: ">=2026.6.1"
---

# Payment Session

x402 is discrete per-call. This adds the two billing shapes it lacks, **settled in
batches through x402** so you pay one transaction per settlement (not per tick —
the only economical way to bill micro-usage given fees + ATA rent):

- **metered** (pay-as-you-go): accrue per-use charges, settle when they cross a
  threshold.
- **subscription** (streaming): charge a fixed amount every period.

Pure accounting — it never moves money or holds a key. It tells the agent **when**
and **how much** to settle; the agent pays via `x402-pay`'s `pay_x402`. A hard
`maxTotalUsdc` lifetime cap bounds every session, so a runaway stream can't drain
past it.

## Tools

| Tool | Does |
|---|---|
| `open_payment_session` | start a `metered` or `subscription` session with a `maxTotalUsdc` cap |
| `meter_usage` | accrue pay-as-you-go usage (metered sessions) |
| `check_settlement_due` | is a payment due, and for how much? (amount is capped at remaining budget) |
| `record_settled` | record a paid settlement after `pay_x402` succeeds |
| `close_payment_session` | close; returns any final remainder to settle |

## The loop

```
open_payment_session(payee, mode, cap)
  metered:      meter_usage(...)  → check_settlement_due → if due: pay_x402(payee, amount) → record_settled
  subscription: (time passes)     → check_settlement_due → if due: pay_x402(payee, amount) → record_settled
close_payment_session  → settle any remainder
```

## Trust model

- **Non-custodial.** This plugin only does accounting; the actual USDC settlement
  is `pay_x402` (your own wallet signs). It never holds a key or moves funds.
- **Capped.** Every session carries a hard `maxTotalUsdc`; `check_settlement_due`
  never returns an amount above the remaining budget.

Pairs with [`x402-pay`](../../skills/x402-pay) (settlement) and
[`web0-onboard`](../web0-onboard) (identity + endpoint).
