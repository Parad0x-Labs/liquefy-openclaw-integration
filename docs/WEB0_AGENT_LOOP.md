# The Web0 agent loop — own a name, publish a page, get paid

The whole point of this stack in one walkthrough: your agent **owns a .null
domain on Solana mainnet, serves a page from permanent storage, advertises its
payment endpoint on-chain, and charges other agents per call** — non-custodial
at every step. You bring one Solana keypair you control and a few cents of SOL.

Honesty first: every step below is labeled. ✅ = live and proven on mainnet
today. 🟡 = built and tested, one step from generally-installable (the exact
blocker is named). Everything is MIT and **unaudited — no external audit has
been completed or scheduled**. Money-touching pieces are devnet-first and
capped by design.

| Step | Tool | Status |
|---|---|---|
| 1. Register `yourname.null` | `@parad0x_labs/null-mcp` | ✅ mainnet (free pilot) — 🟡 npm refresh pending |
| 2. Shrink your page media | `nebula-page` (nebula-media) | 🟡 lands with [nebula-media PR #4](https://github.com/Parad0x-Labs/nebula-media/pull/4) |
| 3. Publish to Arweave + point the name | web0 `publish.mjs` | ✅ mainnet-proven (parad0x.null is live) |
| 4. Put your x402 endpoint on-chain | `UpdateEndpoint` | ✅ mainnet |
| 5. Charge per call | [`x402-gate`](../skills/x402-gate) | ✅ code here — 🟡 npm publish pending |
| 6. Pay other agents | [`x402-pay`](../skills/x402-pay) | ✅ code here — 🟡 npm publish pending |
| 7. Keep long sessions cheap | [`context-capsule`](../skills/context-capsule) | ✅ on npm |

---

## 1 · Register your .null name

The registrar (`H4wbFJucY9shJt95N8Bra532Z4nnkKhGEfqWvLcYfuDm`, Solana mainnet)
is live; registration of 4–32-char names is **free during the pilot**. The MCP
server builds an **unsigned** transaction — your wallet signs, nothing custodial:

```bash
npm i -g @parad0x_labs/null-mcp     # MCP server: resolve / register / publish tools
# then from any MCP-speaking agent (OpenClaw, Claude, Cursor):
#   check_null_availability("yourname") → register_null_domain("yourname")
#   → unsigned base64 tx → sign with YOUR wallet → broadcast
```

1–3-char premium names go through sealed-bid auctions instead (also live).

## 2 · Build the page, shrink the media

Arweave is pay-once-store-forever (~$0.015/MB), so every byte you upload costs
money permanently. `nebula-page` converts the page's images to AVIF, rewrites
the references, and writes a proof manifest (per-file SHA-256 + SSIM + cost
estimate) — measured 5.6–11.4× smaller on the Kodak photo set:

```bash
pip install git+https://github.com/Parad0x-Labs/nebula-media
nebula-page ./my-site        # → ./my-site_web0, upload-ready
```

## 3 · Publish + point your name at it

The [web0](https://github.com/Parad0x-Labs/web0) publisher uploads via Irys,
re-points your domain record's content field on-chain, and verifies resolution
— the same flow that put parad0x.null live:

```bash
node scripts/publish.mjs ./my-site_web0/index.html --name yourname --keypair ~/your-keypair.json
```

## 4 · Advertise how to pay you, on-chain

Your domain record has a 128-byte `x402_endpoint` field. Set it to your paid
API's URL (`UpdateEndpoint`, owner-signed) and any agent that resolves
`yourname.null` discovers your payment endpoint with no registry but the chain.

## 5 · Charge for your agent's work

[`x402-gate`](../skills/x402-gate): mint an HTTP 402 challenge, verify the
payment (set `requireOnChain: true` so you serve only after the transaction is
confirmed settled), then serve. Funds land **directly in your wallet** — the
skill holds no keys. Until the npm publish lands, install from source:

```bash
git clone https://github.com/Parad0x-Labs/openclaw-skills
# wire skills/x402-gate into your agent per its README
```

## 6 · Pay other agents

[`x402-pay`](../skills/x402-pay) is the buying side: one `pay_x402(url)` tool,
bring-your-own signer, **devnet by default**, mainnet only with explicit opt-in
plus a hard per-payment cap. Works against any x402-compliant endpoint.

## 7 · Keep the long sessions cheap

A paid agent runs long conversations. [`context-capsule`](../skills/context-capsule)
(`npm i @parad0x_labs/openclaw-context-capsule`) compresses old history before
each model call — 99.3% token savings at 90% recall in the public bench.

---

## Optional extras (read-only privacy, receipts)

- **Receipts:** anchor a 32-byte hash of anything (a payment receipt, a
  nebula-page manifest) on mainnet via `receipt_anchor`
  (`6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN`).
- **Single-use checks:** `check_nullifier` (read-only) verifies a nullifier
  hasn't been spent — anti-replay for access tokens. The Dark NULL reputation
  gate is live on mainnet with recorded live-fire proofs, **but unaudited** —
  integrate read-only today, don't route funds through privacy paths.

## Honest notes

- **Unaudited, all of it.** Public Beta. Non-custodial and capped by design;
  do not point any of this at balances you can't afford to lose.
- **Pilot pricing.** .null registration is free now; fees can be enabled later
  by on-chain config.
- **Reach.** Visitors resolve `.null` via the resolver extension or MCP today;
  there is no hosted public gateway yet. Agents are unaffected (they resolve
  on-chain directly).
- **Estimates are estimates.** Arweave cost figures are computed from current
  price approximations; the bundler quotes the real price at upload time.
