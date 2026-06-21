/**
 * openclaw-web0-onboard — one-call web0 setup for OpenClaw agents.
 *
 * Thin host wrapper: all logic lives in ./onboard.ts (host-free, unit-tested).
 * Registers a single tool, `web0_onboard`, that assembles a complete web0 setup
 * — on-chain identity check, a paid x402 storefront config, receipt anchoring,
 * and a .null name-binding plan — in one call.
 *
 * Read-only: it emits config and checks on-chain state. It never signs, never
 * holds a key, never moves funds. The agent's own signer runs the x402-gate and
 * (when the naming layer is live) the registration transaction.
 */

// Type-only import: resolved by the OpenClaw plugin loader at runtime.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { buildOnboardTools, readConfig } from "./onboard.js";

export default definePluginEntry({
  id: "web0-onboard",
  name: "web0 Onboard",
  description:
    "Set up an agent on web0 in one call — identity, a paid x402 storefront, " +
    "receipt anchoring, and a .null name-binding plan. Sell services for USDC on " +
    "Solana; funds settle to your own wallet. Non-custodial, read-only orchestration.",

  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    for (const tool of buildOnboardTools(readConfig(api.config))) {
      api.registerTool(tool);
    }
  },
});
