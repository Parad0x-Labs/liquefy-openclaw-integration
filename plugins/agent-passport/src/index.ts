/**
 * openclaw-agent-passport — on-chain identity for OpenClaw agents.
 *
 * Thin host wrapper on the real OpenClaw SDK (`defineToolPlugin` + TypeBox
 * `parameters` + `execute`). All logic lives in ./passport.ts (host-free,
 * unit-tested). Read-only: both tools query on-chain state; no signing, no keys.
 */

import { Type } from "typebox";
import type { TSchema } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

import { buildPassportTools, readConfig } from "./passport.js";

// Tool name/description are config-independent — build a template once for metadata.
const TEMPLATE = buildPassportTools(readConfig(undefined));
// The config-bound tools are memoized on first call (plugin config is static).
let memo: ReturnType<typeof buildPassportTools> | null = null;
const runtimeTools = (config: unknown) =>
  (memo ??= buildPassportTools(readConfig(config as Record<string, unknown> | undefined)));

const ConfigSchema = Type.Object(
  {
    solanaWallet: Type.Optional(Type.String({ description: "Agent's Solana wallet (base58)." })),
    ethAddress: Type.Optional(Type.String({ description: "Agent's ETH address (hex), optional." })),
    nullName: Type.Optional(Type.String({ description: "Agent's .null name." })),
    rpcUrl: Type.Optional(Type.String({ description: "RPC override; defaults to publicnode." })),
  },
  { additionalProperties: true },
);

const PARAMS: Record<string, TSchema> = {
  get_agent_passport: Type.Object({}),
  verify_agent_identity: Type.Object({
    target_solana_wallet: Type.Optional(Type.String({ description: "Target agent's Solana wallet (base58)." })),
    target_eth_address: Type.Optional(Type.String({ description: "Target agent's ETH address (hex)." })),
    target_null_name: Type.Optional(Type.String({ description: "Target agent's .null name (informational)." })),
  }),
};

export default defineToolPlugin({
  id: "agent-passport",
  name: "Agent Passport",
  description:
    "On-chain identity for OpenClaw agents — .null name, ETH↔Solana binding, " +
    "verifiable agent identity without touching private keys.",
  configSchema: ConfigSchema,
  tools: (tool) =>
    TEMPLATE.map((t) =>
      tool({
        name: t.name,
        label: t.name,
        description: t.description,
        parameters: PARAMS[t.name] ?? Type.Object({}),
        execute: (params, config) => {
          const rt = runtimeTools(config).find((x) => x.name === t.name);
          if (!rt) return { ok: false, error: `tool ${t.name} unavailable` };
          return rt.handler(params as Record<string, unknown>);
        },
      }),
    ),
});
