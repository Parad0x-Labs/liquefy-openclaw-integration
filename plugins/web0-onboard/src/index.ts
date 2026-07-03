/**
 * openclaw-web0-onboard — one-call web0 setup + seller-side registrar writes.
 *
 * Thin host wrapper on the real OpenClaw SDK (`defineToolPlugin` + TypeBox
 * `parameters` + `execute`). All logic lives in ./onboard.ts (plan) +
 * ./registrar.ts (register / set-endpoint / set-stealth), both host-free +
 * unit-tested. Non-custodial: the seller tools build UNSIGNED transactions for
 * the host wallet (setWeb0Signer) to sign; the plugin never holds a key.
 */

import { Type } from "typebox";
import type { TSchema } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

import { buildOnboardTools, readConfig } from "./onboard.js";
import { buildRegistrarTools } from "./registrar.js";
import type { Web0Signer } from "./registrar.js";

export type { Web0Signer } from "./registrar.js";

/**
 * The host registers the owner's wallet here at startup — a live signing
 * capability, never a serialized secret. The seller tools build an unsigned
 * transaction and hand it to this signer; the plugin never holds a key.
 */
let activeSigner: Web0Signer | null = null;
export function setWeb0Signer(signer: Web0Signer): void {
  activeSigner = signer;
}

type ToolList = ReturnType<typeof buildOnboardTools>;
const buildAll = (raw: Record<string, unknown> | undefined): ToolList => {
  const cfg = readConfig(raw);
  return [
    ...buildOnboardTools(cfg),
    ...buildRegistrarTools({ solanaWallet: cfg.solanaWallet }, () => activeSigner),
  ];
};

// Tool name/description are config-independent — build a template once for metadata.
const TEMPLATE = buildAll(undefined);
// The config-bound tools are memoized on first call (plugin config is static; the
// signer is read live via the getSigner closure, so setWeb0Signer still applies).
let memo: ToolList | null = null;
const runtimeTools = (config: unknown) => (memo ??= buildAll(config as Record<string, unknown> | undefined));

const ConfigSchema = Type.Object(
  {
    solanaWallet: Type.Optional(Type.String({ description: "Default payout Solana wallet (base58)." })),
    name: Type.Optional(Type.String({ description: "Default .null name." })),
    network: Type.Optional(
      Type.Union([Type.Literal("solana-mainnet"), Type.Literal("solana-devnet")], { description: "Settlement network." }),
    ),
    rpcUrl: Type.Optional(Type.String({ description: "RPC override." })),
  },
  { additionalProperties: true },
);

const ServiceSchema = Type.Object({
  name: Type.String(),
  priceUsdc: Type.Number(),
  description: Type.Optional(Type.String()),
});

const PARAMS: Record<string, TSchema> = {
  web0_onboard: Type.Object({
    name: Type.Optional(Type.String({ description: 'Desired .null name (e.g. "myagent").' })),
    solanaWallet: Type.Optional(Type.String({ description: "Payout Solana wallet (base58)." })),
    ethAddress: Type.Optional(Type.String({ description: "Optional ETH address to note." })),
    services: Type.Optional(Type.Array(ServiceSchema, { description: "Services to sell." })),
    network: Type.Optional(Type.Union([Type.Literal("solana-mainnet"), Type.Literal("solana-devnet")])),
  }),
  register_null_name: Type.Object({
    name: Type.String({ description: "The .null name to register (4-32 chars, a-z/0-9/-)." }),
    dryRun: Type.Optional(Type.Boolean({ description: "Preview the registration (PDA, fee) without signing." })),
  }),
  set_null_endpoint: Type.Object({
    name: Type.String({ description: "Your .null name (you must be its owner)." }),
    endpoint: Type.String({ description: "The x402 endpoint URL (<=128 bytes)." }),
    dryRun: Type.Optional(Type.Boolean({ description: "Preview without signing." })),
  }),
  set_null_stealth_meta: Type.Object({
    name: Type.String({ description: "Your .null name (you must be its owner)." }),
    stealth_meta_hex: Type.String({ description: "64 bytes as 128 hex chars: spend_pub||view_pub." }),
    dryRun: Type.Optional(Type.Boolean({ description: "Preview without signing." })),
  }),
};

export default defineToolPlugin({
  id: "web0-onboard",
  name: "web0 Onboard",
  description:
    "Set up an agent on web0 — identity, a paid x402 storefront, receipt anchoring, " +
    "and a .null name: register it, publish your x402 endpoint, get paid by name. " +
    "Sell services for USDC on Solana; funds settle to your own wallet. Non-custodial.",
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
