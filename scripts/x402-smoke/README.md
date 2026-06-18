# x402 devnet smoke test

Proves `x402-gate`'s on-chain settlement check is real — that it accepts a genuine
payment and rejects a forged memo-only transaction or an underpayment.

It is self-contained: ephemeral keypairs, a throwaway SPL mint (no faucet needed),
and an airdrop of devnet SOL for fees. No mainnet, no real funds, no stored keys.

## Run

```bash
cd scripts/x402-smoke
npm install --ignore-scripts
node devnet-smoke.mjs
```

Optional: set `SOLANA_DEVNET_RPC_URL` to a private devnet RPC if the public one
rate-limits the airdrop.

## What it asserts

| Test | Transaction | Expected |
|------|-------------|----------|
| 1 | real USDC transfer + memo | **ACCEPTED** |
| 2 | memo carrying the receipt hash, pays nothing | **REJECTED** (the free-ride) |
| 3 | transfers half the price + memo | **REJECTED** (underpayment) |

All three carry the receipt-hash memo, so the pre-fix memo-only check would have
passed every one. Only the balance-delta check (now in `x402-gate/src/onchain.ts`)
rejects 2 and 3.
