/**
 * openclaw-x402-gate — charge other agents for your skill/API with x402.
 *
 * Registers two tools:
 *   - x402_challenge: mint an HTTP 402 challenge to send to an unpaid caller.
 *   - x402_verify:    verify a submitted X-Payment header (optionally on-chain).
 *
 * Trust model (v1.1.0):
 *   - NO CUSTODY. `recipientAddress` is YOUR public wallet; funds settle straight
 *     to it on-chain. This skill holds no keys and signs nothing.
 *   - Revenue-grade gating: requireOnChain=true (default) accepts a payment only
 *     after its Solana tx is confirmed settled (real transfer, not a header).
 *   - Presenter-bound: the caller signs the gate-issued nonce with the payer key
 *     (mandatory on mainnet) so an observer of the public on-chain payment can't
 *     replay it. The nonce also seeds the receipt hash (unique per challenge).
 *   - Replay-guarded: a verified payment is single-use. Mainnet REQUIRES a durable
 *     store (replayStorePath) — the gate refuses to serve with in-memory dedupe.
 *   - Portable receipts: with receiptScopeSeconds>0 the gate issues a capability
 *     token so the payer can reuse access within that window without re-paying.
 *
 * Non-custodial: funds settle straight to your own wallet; the skill holds no keys.
 */

// Provided by the host OpenClaw runtime at load time (declared as a peer
// dependency). definePluginEntry is a runtime value, not a type-only import.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Connection } from "@solana/web3.js";

import { DEFAULT_RPC, atomicToUsdc, type SolanaNetwork } from "./constants";
import { makeChallenge, verifyPaymentStructure, decodePaymentHeader } from "./gate";
import { confirmOnChain } from "./onchain";
import { InMemoryReplayStore, FileReplayStore, type ReplayStore } from "./replay";
import {
  resolveSecret,
  issueNonce,
  verifyNonce,
  verifyPayerSignature,
  issueCapability,
  verifyCapability,
} from "./auth";

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
  receiptScopeSeconds: number;
  acknowledgeSingleInstance: boolean;
  acknowledgeExternalReplayStore: boolean;
  challengeSecret?: string;
  replayStorePath?: string;
  rpcUrl?: string;
}

function readConfig(raw: Record<string, unknown> | undefined): GateConfig {
  const c = raw ?? {};
  const network: SolanaNetwork = c.network === "solana-devnet" ? "solana-devnet" : "solana-mainnet";
  return {
    recipientAddress: typeof c.recipientAddress === "string" ? c.recipientAddress : "",
    priceUsdc: typeof c.priceUsdc === "number" ? c.priceUsdc : 0.01,
    network,
    requireOnChain: c.requireOnChain !== false,
    dedupe: c.dedupe !== false,
    // Presenter-auth is MANDATORY on mainnet (cannot be disabled); optional on devnet.
    requirePresenterAuth: network === "solana-mainnet" ? true : c.requirePresenterAuth !== false,
    receiptScopeSeconds:
      typeof c.receiptScopeSeconds === "number" && c.receiptScopeSeconds > 0 ? c.receiptScopeSeconds : 0,
    acknowledgeSingleInstance: c.acknowledgeSingleInstance === true,
    acknowledgeExternalReplayStore: c.acknowledgeExternalReplayStore === true,
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
    "Mint a 402 challenge, verify the payment (confirmed on-chain), then serve. " +
    "Funds go to your own wallet address — the skill holds no keys.",
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

    // Fail-closed on unsafe mainnet config: surface the error from every tool call
    // (don't throw at load — that could crash the host — and don't silently degrade).
    let configError: string | null = null;
    if (config.network === "solana-mainnet") {
      if (!config.requireOnChain) {
        configError =
          "x402-gate refuses requireOnChain=false on mainnet — that serves paid content without " +
          "verifying the payment settled on-chain. Set requireOnChain=true (header-only mode is devnet/testing only).";
      } else if (config.dedupe && !config.replayStorePath) {
        configError =
          "x402-gate refuses in-memory dedupe on mainnet (replay reopens on restart). Set replayStorePath " +
          "for a restart-durable single-instance store, or dedupe=false with your own shared store.";
      } else if (config.dedupe && !config.acknowledgeSingleInstance) {
        configError =
          "x402-gate: replayStorePath (FileReplayStore) is SINGLE-INSTANCE only — running multiple replicas lets " +
          "one payment be redeemed once per replica. Set acknowledgeSingleInstance=true to confirm you run ONE " +
          "instance, or set dedupe=false with your own shared store (Redis/DB) + acknowledgeExternalReplayStore=true.";
      } else if (!config.dedupe && !config.acknowledgeExternalReplayStore) {
        configError =
          "x402-gate: dedupe=false on mainnet disables the built-in replay guard — a settled payment could be " +
          "re-redeemed within the nonce TTL. You MUST enforce replay with your own durable, shared store; set " +
          "acknowledgeExternalReplayStore=true to attest this.";
      } else if (config.requirePresenterAuth && !config.challengeSecret) {
        configError =
          "x402-gate requires challengeSecret on mainnet (presenter-auth nonces must verify across " +
          "restarts/instances). Set challengeSecret in config.";
      } else if (config.receiptScopeSeconds > 0 && !config.replayStorePath) {
        configError =
          "x402-gate requires replayStorePath on mainnet when receiptScopeSeconds>0 — capability-reuse " +
          "nonce dedupe must be durable. Set replayStorePath.";
      }
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
        if (configError) return { error: configError };
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
          // Presenter-binding nonce — the caller signs it with the payer key. The
          // same nonce seeds the receipt hash, making it unique per challenge.
          const nonce = issueNonce(resource, secret, Math.floor(Date.now() / 1000));
          body.nonce = nonce;
          body.accepts[0].extra = { ...body.accepts[0].extra, nullifierSeed: nonce };
          return { status, body };
        } catch (e) {
          return { error: e instanceof Error ? e.message : String(e) };
        }
      },
    });

    api.registerTool({
      name: "x402_verify",
      description:
        "Verify a submitted X-Payment header for a resource. With requireOnChain=true " +
        "the payment must be confirmed settled on Solana. If the caller presents a " +
        "capability token from a prior payment, access is reused within its scope.",
      parameters: {
        header: { type: "string", description: "The base64 X-Payment header the caller sent" },
        resource: { type: "string", description: "The resource being accessed (must match the challenge)" },
        priceUsdc: { type: "number", description: "Override the default price (USDC)" },
      },
      async handler(params: Record<string, unknown>) {
        try {
          if (configError) return { valid: false, error: configError };
          if (!config.recipientAddress) {
            return { valid: false, error: "gate not configured: set recipientAddress in plugin config" };
          }
          const resource = String(params.resource ?? "");
          const header = params.header == null ? null : String(params.header);
          if (!header) return { valid: false, error: "missing X-Payment header" };

          let proof;
          try {
            proof = decodePaymentHeader(header);
          } catch (e) {
            return { valid: false, error: e instanceof Error ? e.message : String(e) };
          }
          if (!proof.payerAddress) return { valid: false, error: "proof missing payerAddress" };

          const now = Math.floor(Date.now() / 1000);

          // Presenter-auth: prove control of the paying key by signing the gate's
          // nonce. Mandatory on mainnet, and ALWAYS required for capability reuse
          // (the token's only guard). Blocks replay of an observed public proof.
          const needAuth = config.requirePresenterAuth || !!proof.capability;
          if (needAuth) {
            const n = verifyNonce(proof.nonce, resource, secret, now);
            if (!n.ok) return { valid: false, error: `presenter auth failed: ${n.reason}` };
            if (!proof.payerSig || !verifyPayerSignature(proof.payerAddress, proof.nonce as string, proof.payerSig)) {
              return {
                valid: false,
                error: "presenter auth failed: payer signature invalid (presenter does not control the paying key)",
              };
            }
          }

          // Capability reuse — no new payment. The token is bound to (payer, resource);
          // presenter-auth above proves the caller is that payer. Consume the nonce so
          // a captured reuse bundle can't be replayed within its TTL.
          if (proof.capability) {
            const cap = verifyCapability(proof.capability, proof.payerAddress, resource, secret, now);
            if (!cap.ok) return { valid: false, error: `capability invalid: ${cap.reason}` };
            if (!replayStore.consume(`nonce:${proof.nonce}`)) {
              return { valid: false, error: "nonce already used" };
            }
            return {
              valid: true,
              payerAddress: proof.payerAddress,
              amountAtomic: 0,
              amountUsdc: 0,
              receiptHash: "",
              resource,
              onChainVerified: false,
              signature: "",
              reusedCapability: true,
            };
          }

          // Payment path. Reconstruct the requirement, binding the receipt hash to
          // the gate-issued nonce (used as the nullifierSeed) so it's unique per challenge.
          const { requirement } = makeChallenge({
            priceUsdc: typeof params.priceUsdc === "number" ? params.priceUsdc : config.priceUsdc,
            recipientAddress: config.recipientAddress,
            resource,
            network: config.network,
          });
          if (proof.nonce) requirement.extra = { ...requirement.extra, nullifierSeed: proof.nonce };

          const structural = verifyPaymentStructure(header, requirement);
          if (!structural.valid) return structural;

          if (!config.requireOnChain) return structural;

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

          // Trust the on-chain delta for the reported amount, not the caller header.
          const paidAtomic = Number(chain.receivedAtomic ?? structural.amountAtomic);
          const result: Record<string, unknown> = {
            ...structural,
            amountAtomic: paidAtomic,
            amountUsdc: atomicToUsdc(paidAtomic),
            onChainVerified: true,
          };
          // Portable capability: let the payer reuse this access within the scope.
          if (config.receiptScopeSeconds > 0) {
            result.capability = issueCapability(proof.payerAddress, resource, config.receiptScopeSeconds, secret, now);
          }
          return result;
        } catch (e) {
          return { valid: false, error: `x402_verify internal error: ${e instanceof Error ? e.message : String(e)}` };
        }
      },
    });
  },
});
