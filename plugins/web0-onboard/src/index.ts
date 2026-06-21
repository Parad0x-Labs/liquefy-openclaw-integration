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
import { buildRegistrarTools } from "./registrar.js";
import type { Web0Signer } from "./registrar.js";

export type { Web0Signer } from "./registrar.js";

/**
 * The host registers the owner's wallet here at startup — a live signing
 * capability, never a serialized secret. The seller-side write tools
 * (register_null_name / set_null_endpoint / set_null_stealth_meta) build an
 * unsigned transaction and hand it to this signer; the plugin never holds a key.
 */
let activeSigner: Web0Signer | null = null;
export function setWeb0Signer(signer: Web0Signer): void {
  activeSigner = signer;
}

export default definePluginEntry({
  id: "web0-onboard",
  name: "web0 Onboard",
  description:
    "Set up an agent on web0 — identity, a paid x402 storefront, receipt anchoring, " +
    "and a .null name: register it, publish your x402 endpoint, get paid by name. " +
    "Sell services for USDC on Solana; funds settle to your own wallet. Non-custodial.",

  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    const cfg = readConfig(api.config);
    for (const tool of buildOnboardTools(cfg)) api.registerTool(tool);
    for (const tool of buildRegistrarTools({ solanaWallet: cfg.solanaWallet }, () => activeSigner)) {
      api.registerTool(tool);
    }
  },
});
