/**
 * openclaw-payment-session — streaming / recurring agent billing over x402.
 *
 * Thin host wrapper on the real OpenClaw SDK (`defineToolPlugin` + TypeBox
 * `parameters` + `execute`). All logic lives in ./session.ts (pure engine) +
 * ./tools.ts (stateful registry), both host-free + unit-tested. The session
 * registry is instantiated ONCE here so state persists across tool calls. Pure
 * accounting — this plugin never moves money or holds a key.
 */

import { Type } from "typebox";
import type { TSchema } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

import { buildSessionTools } from "./tools.js";

// One registry instance — session state persists across execute() calls.
const TOOLS = buildSessionTools();

// TypeBox parameter schemas per tool (the host validates against these).
const PARAMS: Record<string, TSchema> = {
  open_payment_session: Type.Object({
    payee: Type.String({ description: "Who gets paid — a .null name or an x402 endpoint URL." }),
    mode: Type.Union([Type.Literal("metered"), Type.Literal("subscription")], {
      description: "Billing shape: metered (pay-as-you-go) or subscription (per-period).",
    }),
    maxTotalUsdc: Type.Number({ description: "Hard lifetime cap (USDC) for this session." }),
    settleAtUsdc: Type.Optional(Type.Number({ description: "metered: settle once accrued usage reaches this many USDC." })),
    periodSeconds: Type.Optional(Type.Number({ description: "subscription: seconds per billing period." })),
    periodUsdc: Type.Optional(Type.Number({ description: "subscription: USDC charged each period." })),
  }),
  meter_usage: Type.Object({
    session_id: Type.String(),
    usdc: Type.Number({ description: "USDC value of the usage to accrue." }),
  }),
  check_settlement_due: Type.Object({ session_id: Type.String() }),
  record_settled: Type.Object({
    session_id: Type.String(),
    amount_usdc: Type.Number(),
    signature: Type.Optional(Type.String({ description: "Optional Solana tx signature of the settlement payment." })),
  }),
  close_payment_session: Type.Object({ session_id: Type.String() }),
};

export default defineToolPlugin({
  id: "payment-session",
  name: "Payment Session",
  description:
    "Streaming + recurring billing for agents over x402: meter pay-as-you-go usage " +
    "or run a subscription, settle in batches through pay_x402. Hard per-session " +
    "spend cap; non-custodial (it never moves money or holds a key).",
  tools: (tool) =>
    TOOLS.map((td) =>
      tool({
        name: td.name,
        label: td.name,
        description: td.description,
        parameters: PARAMS[td.name] ?? Type.Object({}),
        execute: (params) => td.handler(params as Record<string, unknown>),
      }),
    ),
});
