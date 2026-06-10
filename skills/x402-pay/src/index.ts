/**
 * openclaw-x402-pay — self-custody x402 payments for OpenClaw agents.
 *
 * Gives an agent one tool, `pay_x402`, that fetches an x402-gated URL and, if it
 * answers HTTP 402, pays for it on Solana and returns the resource.
 *
 * Trust model (v1.0.0):
 *   - BRING YOUR OWN SIGNER. The host supplies an X402Signer (wallet adapter,
 *     hardware signer, KMS). This plugin builds an UNSIGNED transaction, hands
 *     it to that signer, then broadcasts the signed bytes. It never holds,
 *     requests, or reads a private key.
 *   - DEVNET BY DEFAULT. Mainnet payments require config.allowMainnet = true.
 *   - HARD SPEND CAP. config.maxAmountUsdc is enforced before any tx is built;
 *     a 402 demanding more is refused.
 *   - NETWORK: talks only to the configured Solana RPC and the target URL.
 *     No telemetry, no third-party endpoints.
 *
 * Status: Public Beta. Non-custodial, capped, unaudited (no external audit
 * completed or scheduled) — do not point it at large balances.
 */

// Type-only import: resolved from the host OpenClaw runtime at load time, same
// pattern as @parad0x_labs/openclaw-context-capsule. No build-time dependency.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { fetchWithX402 } from "./client";
import type { X402PayConfig, X402Signer } from "./types";

export * from "./constants";
export * from "./types";
export * from "./signer";
export * from "./client";

const DEFAULT_MAX_USDC = 1.0;

/**
 * The host registers the owner's wallet here at startup. Kept out of JSON config
 * on purpose — a signer is a live capability, never a serialized secret.
 */
let activeSigner: X402Signer | null = null;
export function setX402Signer(signer: X402Signer): void {
  activeSigner = signer;
}

function readConfig(raw: Record<string, unknown> | undefined): X402PayConfig {
  const cfg = raw ?? {};
  return {
    maxAmountUsdc:
      typeof cfg.maxAmountUsdc === "number" ? cfg.maxAmountUsdc : DEFAULT_MAX_USDC,
    allowMainnet: cfg.allowMainnet === true,
    rpcUrl: typeof cfg.rpcUrl === "string" ? cfg.rpcUrl : undefined,
  };
}

export default definePluginEntry({
  id: "x402-pay",
  name: "x402 Pay",
  description:
    "Let your agent pay for x402-gated APIs, data, and other agents on Solana. " +
    "Bring your own signer — the skill never holds a private key. Devnet by " +
    "default; mainnet is explicit opt-in with a hard USDC spend cap.",
  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    const config = readConfig(api.config);

    api.registerTool({
      name: "pay_x402",
      description:
        "Fetch a URL; if it returns HTTP 402, pay the demanded USDC on Solana " +
        "(within the configured cap and network) and return the resource. " +
        "Refuses payments over the cap or on mainnet unless explicitly enabled.",
      parameters: {
        url: { type: "string", description: "The x402-gated resource URL to fetch" },
        method: { type: "string", description: "HTTP method (default GET)" },
      },
      async handler(params: Record<string, unknown>) {
        if (!activeSigner) {
          return {
            ok: false,
            error:
              "No signer configured. The host must call setX402Signer(wallet) " +
              "before pay_x402 can authorize a payment.",
          };
        }
        const url = String(params.url ?? "");
        if (!url) return { ok: false, error: "url is required" };

        const init = params.method ? { method: String(params.method) } : undefined;
        try {
          return await fetchWithX402(url, { signer: activeSigner, config, init });
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      },
    });
  },
});
