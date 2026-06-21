/**
 * openclaw-agent-passport — on-chain identity for OpenClaw agents.
 *
 * Thin host wrapper: all logic lives in ./passport.ts (host-free, unit-tested).
 * This file only hands the two read-only identity tools to the OpenClaw plugin
 * loader.
 *
 *   - `get_agent_passport`: this agent's identity (.null name, wallet, ETH,
 *     PDA existence checks).
 *   - `verify_agent_identity`: a DIFFERENT agent's identity, by wallet/ETH/.null.
 *
 * Trust model: READ-ONLY, public RPC only, no private keys, no seized program
 * IDs. .null name resolution wiring lands with the null-resolver deployment.
 */

// Type-only import: resolved by the OpenClaw plugin loader at runtime, same
// pattern as openclaw-x402-pay. No build-time/standalone dependency.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { buildPassportTools, readConfig } from "./passport.js";

export default definePluginEntry({
  id: "agent-passport",
  name: "Agent Passport",
  description:
    "On-chain identity for OpenClaw agents — .null name, ETH↔Solana binding, " +
    "verifiable agent identity without touching private keys.",

  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    for (const tool of buildPassportTools(readConfig(api.config))) {
      api.registerTool(tool);
    }
  },
});
