# ⚠️ OpenClaw plugin adapter — MUST FIX before publish

**Status: the x402-pay / x402-gate payment core is sound and verified, but the
OpenClaw plugin *adapter* (how the tools are registered) is built to the WRONG
tool contract and will NOT register/run in a real OpenClaw. Do not `npm publish`
until this is fixed.**

Verified 2026-06-19 against the real published package `openclaw@2026.6.8`
(`npm pack openclaw@2026.6.8` → `package/dist/plugin-sdk/*.d.ts`).

## What's correct
- `definePluginEntry({ id, name, description, register(api) })` — valid entry
  (`OpenClawPluginDefinition.register?: (api: OpenClawPluginApi) => void`).
- `api.registerTool(...)` exists on `OpenClawPluginApi`
  (`types-Tcpca_5M.d.ts`: `registerTool(tool: AnyAgentTool | OpenClawPluginToolFactory, opts?) => void`).

## What's wrong (the hallucinated part)
We pass `registerTool({ name, description, parameters: <plain object>, handler(params) })`.
The real `ToolDefinition` / `AnyAgentTool` (`index-C8SgRuct.d.ts:1587`) requires:

| Field | Real contract | What we have |
|---|---|---|
| `label` | **required** string | missing |
| `parameters` | a **TypeBox `TSchema`** (or zod via `plugin-sdk/zod`) | plain `{ url: { type: "string" } }` object |
| execution | `execute(toolCallId, params, signal, onUpdate, ctx) => Promise<AgentToolResult>` | `handler(params) => Promise<plainObject>` |

→ Loaded into a real OpenClaw, the tool has an invalid param schema and no
`execute` → it can't be called.

## Why it slipped 6 audit rounds
- Standalone typecheck uses an `any`-level host shim (`src/types/openclaw-host.d.ts`),
  so the mismatch never surfaced.
- The adversarial audit reviewed payment/security logic, not the SDK contract.
- The sibling `context-capsule` (already on npm, "same pattern") uses
  `api.registerContextEngine(...)` — a *different* API method — so `registerTool`
  was never actually exercised.

## The fix (load-test-guided, do NOT guess again)
Port both skills from `definePluginEntry({register(api){api.registerTool(...)}})`
to **`defineToolPlugin`** (`openclaw/plugin-sdk/tool-plugin`). Its tool factory is
the idiomatic tool path and its `execute` returns `unknown`, so the existing
handler body moves into `execute(params)` almost verbatim:

```ts
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { Type } from "typebox"; // openclaw bundles typebox@1.1.39; or zod via openclaw/plugin-sdk/zod (zod@4.4.3)

export default defineToolPlugin({
  id: "x402-pay",
  name: "x402 Pay",
  description: "...",
  configSchema: /* optional TypeBox config schema; openclaw.plugin.json still carries the JSON one */,
  tools: (tool) => [
    tool({
      name: "pay_x402",
      label: "Pay x402",
      description: "...",
      parameters: Type.Object({
        url: Type.String({ description: "The x402-gated resource URL to fetch" }),
        method: Type.Optional(Type.String({ description: "HTTP method (default GET)" })),
      }),
      execute: (params /*, config, context */) => {
        // EXISTING handler body verbatim: activeSigner guard → fetchWithX402(...)
      },
    }),
  ],
});
```

- `setX402Signer(...)` export stays unchanged (host wires the signer at startup).
- `x402-gate` ports the same way: two tools `x402_challenge` + `x402_verify`,
  each `parameters: Type.Object({...})`, body → `execute`.
- The payment/settlement logic (`fetchWithX402`, the gate handlers, `selectRequirement`,
  `confirmOnChain`, the ledger/replay code) is reused verbatim — only the
  registration wrapper + the param-schema declaration change.
- Update `src/types/openclaw-host.d.ts` to also shim `openclaw/plugin-sdk/tool-plugin`
  (and the schema lib if not added as a real dep) so standalone typecheck still passes.
- Add the schema lib to `dependencies` (`typebox` exact, or rely on `openclaw` peer
  for `plugin-sdk/zod`).

## Verify (the real "100% integrated" test)
1. `mkdir scratch && cd scratch && npm install openclaw --ignore-scripts`
2. Load both skills' default exports through the real `openclaw/plugin-sdk`,
   assert each tool registers with a valid schema + a callable `execute`.
3. Stand the gate up as a tiny HTTP endpoint (challenge → verify) and drive a real
   **devnet** `pay_x402 → x402_verify` round-trip (needs devnet USDC in the test
   wallet `~/.config/solana/web0-devnet-test.json`, mint `Gh9ZwEmd…`).
4. Only then is the OpenClaw integration proven — publish after that.
