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
 *   - Replay-guarded: a verified payment is single-use (config.dedupe, default on).
 *     In-memory by default; set replayStorePath for restart-durable single-instance,
 *     or implement a ReplayStore (Redis/DB) for multi-instance.
 *   - Presenter-bound: the caller signs the gate-issued nonce with the payer key
 *     (config.requirePresenterAuth, default on), so an observer of the public
 *     on-chain payment cannot replay it to steal access.
 *
 * Non-custodial: funds settle straight to your own wallet; the skill holds no
 * keys and signs nothing.
 */

// Type-only: resolved from the host OpenClaw runtime at load time.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Connection } from "@solana/web3.js";

import { DEFAULT_RPC, type SolanaNetwork } from "./constants";
import { makeChallenge, verifyPaymentStructure, decodePaymentHeader } from "./gate";
import { confirmOnChain } from "./onchain";
import { InMemoryReplayStore, FileReplayStore, type ReplayStore } from "./replay";
import { resolveSecret, issueNonce, verifyNonce, verifyPayerSignature } from "./auth";

export * from "./constants";
export * from "./types";
export * from "./gate";
export * from "./onchain";
export * from "./replay";
export * from "./auth";

interface GateConfig {
  recipientAddress: string;
  priceUsdc: number;
  network: SolanaNetwork;
  requireOnChain: boolean;
  dedupe: boolean;
  requirePresenterAuth: boolean;
  challengeSecret?: string;
  replayStorePath?: string;
  rpcUrl?: string;
}

function readConfig(raw: Record<string, unknown> | undefined): GateConfig {
  const c = raw ?? {};
  return {
    recipientAddress: typeof c.recipientAddress === "string" ? c.recipientAddress : "",
    priceUsdc: typeof c.priceUsdc === "number" ? c.priceUsdc : 0.01,
    network: c.network === "solana-devnet" ? "solana-devnet" : "solana-mainnet",
    requireOnChain: c.requireOnChain !== false,
    dedupe: c.dedupe !== false,
    requirePresenterAuth: c.requirePresenterAuth !== false,
    challengeSecret: typeof c.challengeSecret === "string" ? c.challengeSecret : undefined,
    replayStorePath: typeof c.replayStorePath === "string" ? c.replayStorePath : undefined,
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
    const secret = resolveSecret(config.challengeSecret);
    const replayStore: ReplayStore = config.replayStorePath
      ? new FileReplayStore(config.replayStorePath)
      : new InMemoryReplayStore();
    if (config.network === "solana-mainnet" && config.dedupe && !config.replayStorePath) {
      console.warn(
        "[x402-gate] dedupe is in-memory (per-process) — replay reopens on restart/extra instances. " +
          "Set replayStorePath (single instance) or a durable ReplayStore (multi-instance).",
      );
    }
    if (config.network === "solana-mainnet" && config.requirePresenterAuth && !config.challengeSecret) {
      console.warn(
        "[x402-gate] challengeSecret not set — using an ephemeral per-process secret; " +
          "presenter-auth nonces won't verify across instances/restarts. Set challengeSecret to share it.",
      );
    }

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
          // Presenter-binding nonce: the caller signs this with the payer key.
          body.nonce = issueNonce(resource, secret, Math.floor(Date.now() / 1000));
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

        // Proof-of-presenter: the caller must prove control of the paying key by
        // signing the gate-issued nonce. Blocks replay of an observed public proof.
        if (config.requirePresenterAuth) {
          const proof = decodePaymentHeader(header as string);
          const now = Math.floor(Date.now() / 1000);
          const n = verifyNonce(proof.nonce, resource, secret, now);
          if (!n.ok) return { valid: false, error: `presenter auth failed: ${n.reason}` };
          if (!proof.payerSig || !verifyPayerSignature(proof.payerAddress, proof.nonce as string, proof.payerSig)) {
            return {
              valid: false,
              error: "presenter auth failed: payer signature invalid (presenter does not control the paying key)",
            };
          }
        }

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
        // Replay guard: a settled payment may only be redeemed once.
        if (config.dedupe && !replayStore.consume(structural.signature)) {
          return { valid: false, error: "payment already used (replay)" };
        }
        return { ...structural, onChainVerified: true };
      },
    });
  },
});
