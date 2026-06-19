# openclaw-x402-pay — self-custody x402 payments for OpenClaw agents

> 🔒 **Install on a wallet host with `npm install --ignore-scripts`** (or `--omit=optional`).
> This package runs where your signer key lives; `--ignore-scripts` blocks any
> transitive install-time code. The only native addons are optional and unused here,
> so nothing is lost. npm can't enforce this from inside a package — it's on you.
> [Details ↓](#install-safety)

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
- **No accidental double-pay (in-process).** An ambiguous confirmation returns
  `pending` with the signature (never a clean retryable error), and the client
  remembers that pending payment per (wallet, host, resource) and re-checks it on
  the next call instead of paying again.
- **Pay once, reuse.** When the gate issues a capability receipt, the client
  caches it and reuses access to that resource within its scope without paying
  again (presenter-bound, so a stolen token is useless to anyone else).
- **SSRF guard.** The fetch target must be http(s) and is refused if it points at
  a loopback / link-local / private / cloud-metadata host — so a prompt-injected
  agent can't turn the wallet host into an internal-network read primitive. (Literal
  hosts only; DNS names that resolve to private IPs aren't caught.) Set
  `allowInternalHosts=true` only for local-dev testing.

> **Non-custodial and spend-capped.** Your agent signs with its own wallet; no
> single payment exceeds the cap you set.

> ⚠️ **Restart durability — set `spendLedgerPath` on mainnet.** The double-pay
> guard, the cumulative `maxTotalUsdc` cap, and the distinct-recipient cap live in a
> spend ledger. With **no** `spendLedgerPath` it is in-memory and resets on restart —
> so if a payment returns `pending` and the process restarts before you reconcile
> that signature, the next call for the same resource can broadcast a **second real
> payment**. Setting `spendLedgerPath` persists the ledger to disk so all three rails
> survive a restart; on mainnet the skill **requires** it and refuses to pay without
> one. Use a single persistent process per ledger file (it is single-writer); for a
> multi-process payer fleet, front it with a shared store via a host hook.

## Install safety

This skill runs where your signer/wallet lives. **Install so no transitive native
addon can run install-time code on that host** — use either:

```bash
npm install --ignore-scripts @parad0x_labs/openclaw-x402-pay   # skips ALL install scripts
# or, equivalently for this package:
npm install --omit=optional  @parad0x_labs/openclaw-x402-pay   # skips the optional native addons
```

> Lands on npm with the v1.1 release. Until then, install from source (this repo,
> `skills/x402-pay`); the commands above resolve once it's published.

This is **required, not optional** for a key-holding host. The only transitive
native builds are `bufferutil` and `utf-8-validate` — **optional** perf addons
pulled by `@solana/web3.js`'s WebSocket stack. This skill makes only **HTTP RPC
calls** (no WebSocket subscriptions), so those addons are **never loaded at
runtime**: `--ignore-scripts` (skip the build) and `--omit=optional` (skip the
install entirely) both lose nothing.

> ⚠️ **npm cannot enforce this from inside a published package.** A dependency's
> `overrides`, `scripts`, and `.npmrc` do **not** govern your install — only your
> own root project's settings do. So this is install-command guidance you (or your
> agent runner) must apply; treat `--ignore-scripts` as policy on any wallet host.
> For maximum safety, install/build on a host that does **not** hold the signer key.

The previously-pulled, unmaintained `bigint-buffer` (advisory GHSA-3gc7-fjrx-p6mg)
is now **gone** — its only path in was `@solana/spl-token`, whose three instruction
builders are vendored here, so the runtime deps are just `@solana/web3.js` and
`bs58` (both pure JS). A production `npm audit --omit=dev --omit=peer` reports
**0 high** (gated at publish via `prepublishOnly`). Three *moderate* advisories
remain, all intrinsic to `@solana/web3.js` 1.x's own tree (`web3.js`, `jayson`,
`uuid@8.3.2` / GHSA-w5hq-g745-h8pq) — not reachable from skill code and unfixable
without web3.js 2.x (a non-drop-in rewrite); the `--audit-level=high` gate stands.

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

> `pay_x402` is intended for **idempotent** (typically GET) fetches: on a 402 it pays
> once and retries the request. It does not take a request body; the initial probe and
> the paid retry hit the same URL, so use it for safe-to-repeat reads.

## Config

```jsonc
{
  "plugins": {
    "entries": {
      "x402-pay": {
        "maxAmountUsdc": 0.50,     // refuse any single payment above this
        "maxTotalUsdc": 50,         // cumulative cap this process (default: 100x per-payment)
        "allowMainnet": true,       // enable real-money mainnet (opt-in; default false)
        "rpcUrl": "https://...",    // REQUIRED on mainnet (a private RPC)
        "spendLedgerPath": "/var/lib/x402/spend.json" // REQUIRED on mainnet (durable spend rails)
      }
    }
  }
}
```

| Key | Default | Description |
|---|---|---|
| `maxAmountUsdc` | `1.0` | Hard per-payment USDC cap, enforced before building any tx. An explicit `0` means refuse-all; the default applies only when unset |
| `maxTotalUsdc` | `100 × maxAmountUsdc` | Cumulative cap across the process (finite; raise for volume) |
| `allowMainnet` | `false` | Set `true` to enable real-money mainnet payments (also needs `rpcUrl`) |
| `allowedRecipients` | — | Optional `payTo` allowlist; if set, any other recipient is refused. Strongest fund-redirection defense — recommended on mainnet |
| `maxDistinctRecipients` | `100` | Max distinct recipients funded per process — bounds SOL spent on recipient ATA rent (USDC caps don't bound SOL) |
| `rpcUrl` | — | Solana RPC. **Required on mainnet**; optional on devnet |
| `spendLedgerPath` | — | Path to a durable spend-ledger file. Persists the cumulative cap, double-pay guard, and recipient cap across restarts. **Required on mainnet**; single-writer (one process per file) |
| `allowInternalHosts` | `false` | Turns OFF the SSRF guard (allows loopback/link-local/private hosts). Set `true` ONLY for local-dev testing against a localhost gate — never on a wallet host |

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

The Solana-specific constants, the x402 wire types, and the three SPL Token
instruction builders are vendored inline (the builders proven byte-identical to
`@solana/spl-token` in the wire tests). Runtime deps are only the well-known
`@solana/web3.js` and `bs58` — no native `bigint-buffer` / `buffer-layout` chain.

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/x402-pay
