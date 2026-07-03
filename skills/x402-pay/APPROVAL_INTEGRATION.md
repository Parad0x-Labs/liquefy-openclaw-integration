# Host-side payment approval — integration contract

`x402-pay` can hand every payment to the host for explicit owner approval before
a single lamport moves. This is the seam a conversational assistant uses to show
a "confirm this payment" step instead of paying autonomously.

It is **off by default** — set `requireApproval: true` in the plugin config to
turn it on. With it unset, `pay_x402` behaves exactly as before (auto-pay within
the configured caps).

## The flow

```
agent calls pay_x402(url)
        │
        ▼
requireApproval set?  ──no──►  pay within caps (unchanged path)
        │ yes
        ▼
quoteX402(url)  — read-only: fetch the 402, select the requirement
        │         (no signing, no broadcast)
        ▼
return { ok:false, approval_required:true, quote, contract }
        │
        ▼
HOST shows the quote to the owner and gets consent
   (wire this to OpenClaw's exec_approval lifecycle — see below)
        │ owner approves
        ▼
HOST re-invokes pay_x402(url, { approved:true })
        │
        ▼
pay within caps (the same payment path)
```

## The shapes

**First call returns** (when a payment is required):

```jsonc
{
  "ok": false,
  "approval_required": true,
  "quote": {
    "url": "https://api.example.null/data",
    "amount_usdc": 0.02,
    "pay_to": "<recipient base58>",
    "network": "solana-mainnet",
    "resource": "/data",
    "description": "Premium data feed"
  },
  "contract": "Re-invoke pay_x402 with approved:true once the owner confirms …"
}
```

If the URL needs no payment (HTTP ≠ 402), the first call returns the resource
directly — there is nothing to approve.

**Approved re-invocation:**

```jsonc
{ "url": "https://api.example.null/data", "approved": true }
```

## Wiring to OpenClaw's event lifecycle

OpenClaw's MCP event queue exposes an approval lifecycle
(`exec_approval_requested` → `exec_approval_resolved`) and the companion
`permissions_respond` control. Map the handoff onto it:

1. Intercept the `approval_required` result from `pay_x402`.
2. Emit your confirmation UI (e.g. a wallet modal) keyed to the `quote`.
3. On owner consent, resolve via `permissions_respond` and re-invoke `pay_x402`
   with `approved: true`.

No OpenClaw core changes are needed — this rides the existing event queue.

## Trust boundary

`approved` is **host-set, not model-set**. The host flips it to `true` only
after it has obtained real owner consent; the model is told not to set it. The
plugin provides the seam — the host enforces the gate. This mirrors the
zero-trust posture of the rest of the stack: the agent proposes, the owner's
machine authorizes.

The `quote` is produced by the same SSRF guard, byte caps, and requirement
selection as the payment path, so it can never advertise something the payment
path would refuse (over-cap amount, un-opted-in mainnet, non-USDC asset, …).
