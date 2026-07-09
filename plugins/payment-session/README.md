# @parad0x_labs/openclaw-payment-session ⏱️

**Streaming + recurring billing for agents over x402.** Meter pay-as-you-go usage
or run a subscription, settle in **batches** through `pay_x402` (one tx per
settlement, not per tick), with a hard per-session spend cap. Non-custodial — it
never moves money or holds a key.

```bash
npm i @parad0x_labs/openclaw-payment-session
```

> Requires OpenClaw **≥ 2026.6.1**.

## Why

x402 is discrete per-call. Per-second/per-use micropayments are uneconomical one
tx at a time (fees + ATA rent dwarf a sub-cent charge). This accrues charges and
settles them in batches — the practical way to bill streaming usage.

## Two shapes

- **metered** — `meter_usage` accrues; settle once accrued ≥ `settleAtUsdc`.
- **subscription** — charge `periodUsdc` every `periodSeconds`.

## Tools

`open_payment_session` · `meter_usage` · `check_settlement_due` · `record_settled` · `close_payment_session`

```
open_payment_session(payee="seller.null", mode="metered", settleAtUsdc=1, maxTotalUsdc=20)
→ meter_usage(usdc=0.3) … → check_settlement_due → { due:true, amount_usdc }
→ pay_x402("seller.null")  (x402-pay)            → record_settled(amount_usdc)
```

## Trust model

- **Non-custodial** — accounting only; settlement is `pay_x402` (your wallet signs).
- **Capped** — every session has a hard `maxTotalUsdc`; the due amount is always
  clamped to the remaining budget, so a runaway stream can't overspend.

Pairs with `x402-pay` (settlement), `x402-gate` (the selling side), and
`web0-onboard` (identity + endpoint). MIT licensed.
