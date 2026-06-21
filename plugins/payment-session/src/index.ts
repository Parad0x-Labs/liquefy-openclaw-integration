/**
 * openclaw-payment-session — streaming / recurring agent billing over x402.
 *
 * Thin host wrapper: all logic lives in ./session.ts (pure engine) + ./tools.ts
 * (stateful registry), both host-free + unit-tested. Registers five tools that
 * meter pay-as-you-go usage or run a subscription, and tell the agent when/how
 * much to settle — the settlement itself rides x402-pay's pay_x402. Pure
 * accounting; this plugin never moves money or holds a key.
 */

// Type-only import: resolved by the OpenClaw plugin loader at runtime.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { buildSessionTools } from "./tools.js";

export default definePluginEntry({
  id: "payment-session",
  name: "Payment Session",
  description:
    "Streaming + recurring billing for agents over x402: meter pay-as-you-go usage " +
    "or run a subscription, settle in batches through pay_x402. Hard per-session " +
    "spend cap; non-custodial (it never moves money or holds a key).",

  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    for (const tool of buildSessionTools()) api.registerTool(tool);
  },
});
