/**
 * openclaw-x402-gate — charge other agents for your skill/API with x402.
 *
 * Registers two tools:
 *   - x402_challenge: mint an HTTP 402 challenge to send to an unpaid caller.
 *   - x402_verify:    verify a submitted X-Payment header (optionally on-chain).
 *
 * Trust model (v1.0.0):
 *   - NO CUSTODY. `recipientAddress` is YOUR public wallet; funds settle straight
 *     to it on-chain. This skill holds no keys and signs nothing.
 *   - Stateless. Both tools reconstruct the same requirement from config +
 *     resource, so receipt hashes match the paying side with no shared state.
 *   - Revenue-grade gating: set requireOnChain=true so a payment is accepted only
 *     after the transaction is confirmed on Solana (not just a well-formed header).
 *
 * Non-custodial: funds settle straight to your own wallet; the skill holds no
 * keys and signs nothing.
 */

// Type-only: resolved from the host OpenClaw runtime at load time.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Connection } from "@solana/web3.js";

import { DEFAULT_RPC, type SolanaNetwork } from "./constants";
import { makeChallenge, verifyPaymentStructure } from "./gate";
import { confirmOnChain } from "./onchain";

export * from "./constants";
export * from "./types";
export * from "./gate";
export * from "./onchain";

interface GateConfig {
  recipientAddress: string;
  priceUsdc: number;
  network: SolanaNetwork;
  requireOnChain: boolean;
  rpcUrl?: string;
}

function readConfig(raw: Record<string, unknown> | undefined): GateConfig {
  const c = raw ?? {};
  return {
    recipientAddress: typeof c.recipientAddress === "string" ? c.recipientAddress : "",
    priceUsdc: typeof c.priceUsdc === "number" ? c.priceUsdc : 0.01,
    network: c.network === "solana-devnet" ? "solana-devnet" : "solana-mainnet",
    requireOnChain: c.requireOnChain !== false,
    rpcUrl: typeof c.rpcUrl === "string" ? c.rpcUrl : undefined,
  };
}

export default definePluginEntry({
  id: "x402-gate",
  name: "x402 Gate",
  description:
    "Charge other agents for your skill or API with x402 micropayments on Solana. " +
    "Mint a 402 challenge, verify the payment (optionally confirmed on-chain), then " +
    "serve. Funds go to your own wallet address — the skill holds no keys.",
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
      name: "x402_challenge",
      description:
        "Build an HTTP 402 Payment Required challenge for a resource. Return its " +
        "`body` to an unpaid caller so they know how much to pay and to which address.",
      parameters: {
        resource: { type: "string", description: "The resource id/path being charged for" },
        priceUsdc: { type: "number", description: "Override the default price (USDC)" },
        description: { type: "string", description: "Human-readable description" },
      },
      async handler(params: Record<string, unknown>) {
        if (!config.recipientAddress) {
          return { error: "gate not configured: set recipientAddress (your wallet) in plugin config" };
        }
        const resource = String(params.resource ?? "");
        if (!resource) return { error: "resource is required" };
        try {
          const { status, body } = makeChallenge({
            priceUsdc: typeof params.priceUsdc === "number" ? params.priceUsdc : config.priceUsdc,
            recipientAddress: config.recipientAddress,
            resource,
            description: params.description ? String(params.description) : undefined,
            network: config.network,
          });
          return { status, body };
        } catch (e) {
          return { error: e instanceof Error ? e.message : String(e) };
        }
      },
    });

    api.registerTool({
      name: "x402_verify",
      description:
        "Verify a submitted X-Payment header for a resource. Returns whether the " +
        "payment is valid and the receipt hash. With requireOnChain=true the " +
        "payment must also be confirmed settled on Solana before it is accepted.",
      parameters: {
        header: { type: "string", description: "The base64 X-Payment header the caller sent" },
        resource: { type: "string", description: "The resource being accessed (must match the challenge)" },
        priceUsdc: { type: "number", description: "Override the default price (USDC)" },
      },
      async handler(params: Record<string, unknown>) {
        if (!config.recipientAddress) {
          return { valid: false, error: "gate not configured: set recipientAddress in plugin config" };
        }
        const resource = String(params.resource ?? "");
        const header = params.header == null ? null : String(params.header);

        const { requirement } = makeChallenge({
          priceUsdc: typeof params.priceUsdc === "number" ? params.priceUsdc : config.priceUsdc,
          recipientAddress: config.recipientAddress,
          resource,
          network: config.network,
        });

        const structural = verifyPaymentStructure(header, requirement);
        if (!structural.valid) return structural;

        if (!config.requireOnChain) return structural;

        // Revenue-grade: confirm the payment actually settled.
        const rpcUrl = config.rpcUrl ?? DEFAULT_RPC[config.network];
        const connection = new Connection(rpcUrl, "confirmed");
        const chain = await confirmOnChain(connection, structural.signature, {
          receiptHash: structural.receiptHash,
          payTo: requirement.payTo,
          asset: requirement.asset,
          amountAtomic: requirement.maxAmountRequired,
        });
        if (!chain.confirmed) {
          return { valid: false, error: `on-chain confirmation failed: ${chain.reason}` };
        }
        return { ...structural, onChainVerified: true };
      },
    });
  },
});
