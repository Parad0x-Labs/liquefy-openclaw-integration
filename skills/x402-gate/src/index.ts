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
 *
 * Plugin contract: defined with `defineToolPlugin` against the real OpenClaw SDK
 * (TypeBox `parameters` + `execute(params, config, context)`). The one-time setup
 * (config validation + the single-instance replay store lock) is built lazily on
 * first tool call and shared across both tools.
 */

import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { Connection, PublicKey } from "@solana/web3.js";

import { DEFAULT_RPC, PRESENTER_AUTH_DOMAIN, atomicToUsdc, type SolanaNetwork } from "./constants";
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

interface GateState {
  config: GateConfig;
  secret: ReturnType<typeof resolveSecret>;
  configError: string | null;
  replayStore: ReplayStore;
}

/**
 * One-time gate setup, built lazily on first tool call and memoized. This is where
 * the FileReplayStore takes its single-instance lock and where unsafe config is
 * turned into a fail-closed `configError` (surfaced from every tool call rather
 * than thrown at load, which could crash the host). Config is the plugin's static
 * config, identical across calls, so memoizing on first use is correct.
 */
let gateState: GateState | null = null;
function getGateState(rawConfig: Record<string, unknown> | undefined): GateState {
  if (gateState) return gateState;

  const config = readConfig(rawConfig);
  const secret = resolveSecret(config.challengeSecret);
  let configError: string | null = null;

  // The file store takes a single-instance lock on construction; if another live
  // instance already holds the path, refuse (fail-closed) rather than run a
  // divergent dedup set that would let one payment be redeemed per replica.
  let replayStore: ReplayStore = new InMemoryReplayStore();
  if (config.replayStorePath) {
    try {
      replayStore = new FileReplayStore(config.replayStorePath);
    } catch (e) {
      configError = e instanceof Error ? e.message : String(e);
    }
  }
  // Nonces (incl. the capability-reuse nonce, whose single-use is its ONLY replay
  // guard) go through the SAME durable replayStore as signatures, so a restart can't
  // reopen replay. The store self-compacts expired nonces, so high-rate capability
  // reuse can't grow it without bound (signatures are kept permanently).

  if (!configError && config.network === "solana-mainnet") {
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
    } else if (config.requirePresenterAuth && (!config.challengeSecret || config.challengeSecret.length < 32)) {
      configError =
        "x402-gate requires a STRONG challengeSecret on mainnet (>= 32 chars; prefer a 256-bit hex/base64 " +
        "random). It is the HMAC key for nonces + capability tokens — a weak/guessable secret can be " +
        "brute-forced offline from one public challenge and used to forge capability tokens for free access.";
    } else if (config.receiptScopeSeconds > 0 && (!config.dedupe || !config.replayStorePath || !config.acknowledgeSingleInstance)) {
      configError =
        "x402-gate: capabilities (receiptScopeSeconds>0) on mainnet require dedupe=true + " +
        "replayStorePath + acknowledgeSingleInstance. Capability-reuse dedupe is single-instance " +
        "only and is NOT supported in external-store / multi-replica mode (dedupe=false) — a " +
        "settled payment would fan out to free reuse across replicas. Disable capabilities or run single-instance.";
    } else if (!config.rpcUrl) {
      configError =
        "x402-gate requires an explicit rpcUrl on mainnet — the public RPC is rate-limited and is the " +
        "trusted oracle for the settlement decision. Set a private/dedicated node.";
    }
  }
  // Validate the recipient wallet up front (clear error instead of opaque per-request failures).
  if (!configError && config.recipientAddress) {
    try {
      new PublicKey(config.recipientAddress);
    } catch {
      configError = "x402-gate: recipientAddress is not a valid Solana public key";
    }
  }
  // A present-but-malformed priceUsdc (e.g. "5" from an env/JSON pipeline) must
  // fail loud, not silently fall back to a cheap default price.
  const rawPrice = (rawConfig ?? {}).priceUsdc;
  if (!configError && rawPrice !== undefined && !(typeof rawPrice === "number" && Number.isFinite(rawPrice) && rawPrice > 0)) {
    configError = "x402-gate: priceUsdc must be a finite positive number";
  }
  // Reject a sub-atomic price up front (it would round to 0 atomic units and serve
  // for free / brick the resource) rather than failing only when a challenge is built.
  if (!configError && typeof rawPrice === "number" && Number.isFinite(rawPrice) && rawPrice > 0 && Math.round(rawPrice * 1e6) < 1) {
    configError = "x402-gate: priceUsdc is below the smallest USDC unit (0.000001) — raise it";
  }

  gateState = { config, secret, configError, replayStore };
  return gateState;
}

const ConfigSchema = Type.Object(
  {
    recipientAddress: Type.Optional(Type.String()),
    priceUsdc: Type.Optional(Type.Union([Type.Number(), Type.String()])),
    network: Type.Optional(Type.String()),
    requireOnChain: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    dedupe: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    requirePresenterAuth: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    receiptScopeSeconds: Type.Optional(Type.Union([Type.Number(), Type.String()])),
    acknowledgeSingleInstance: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    acknowledgeExternalReplayStore: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    challengeSecret: Type.Optional(Type.String()),
    replayStorePath: Type.Optional(Type.String()),
    rpcUrl: Type.Optional(Type.String()),
  },
  { additionalProperties: true },
);

const ChallengeParams = Type.Object({
  resource: Type.String({ description: "The resource id/path being charged for" }),
  description: Type.Optional(Type.String({ description: "Human-readable description" })),
});

const VerifyParams = Type.Object({
  header: Type.String({ description: "The base64 X-Payment header the caller sent" }),
  resource: Type.String({ description: "The resource being accessed (must match the challenge)" }),
});

export default defineToolPlugin({
  id: "x402-gate",
  name: "x402 Gate",
  description:
    "Charge other agents for your skill or API with x402 micropayments on Solana. " +
    "Mint a 402 challenge, verify the payment (confirmed on-chain), then serve. " +
    "Funds go to your own wallet address — the skill holds no keys.",
  configSchema: ConfigSchema,
  tools: (tool) => [
    tool({
      name: "x402_challenge",
      label: "x402 Challenge",
      description:
        "Build an HTTP 402 Payment Required challenge for a resource. Return its " +
        "`body` to an unpaid caller so they know how much to pay and to which address.",
      parameters: ChallengeParams,
      async execute(params, rawConfig) {
        const { config, secret, configError } = getGateState(rawConfig as Record<string, unknown>);
        if (configError) return { error: configError };
        if (!config.recipientAddress) {
          return { error: "gate not configured: set recipientAddress (your wallet) in plugin config" };
        }
        const resource = String(params.resource ?? "");
        if (!resource) return { error: "resource is required" };
        try {
          const { status, body } = makeChallenge({
            priceUsdc: config.priceUsdc, // price is seller config ONLY, never caller input
            recipientAddress: config.recipientAddress,
            resource,
            description: params.description ? String(params.description) : undefined,
            network: config.network,
          });
          // Presenter-binding nonce — the caller signs it with the payer key. It
          // commits resource + price, and seeds the receipt hash (unique per challenge).
          const nonce = issueNonce(resource, body.accepts[0].maxAmountRequired, secret, Math.floor(Date.now() / 1000));
          body.nonce = nonce;
          body.accepts[0].extra = { ...body.accepts[0].extra, nullifierSeed: nonce };
          return { status, body };
        } catch (e) {
          return { error: e instanceof Error ? e.message : String(e) };
        }
      },
    }),
    tool({
      name: "x402_verify",
      label: "x402 Verify",
      description:
        "Verify a submitted X-Payment header for a resource. With requireOnChain=true " +
        "the payment must be confirmed settled on Solana. If the caller presents a " +
        "capability token from a prior payment, access is reused within its scope.",
      parameters: VerifyParams,
      async execute(params, rawConfig) {
        const { config, secret, configError, replayStore } = getGateState(rawConfig as Record<string, unknown>);
        try {
          if (configError) return { valid: false, error: configError };
          if (!config.recipientAddress) {
            return { valid: false, error: "gate not configured: set recipientAddress in plugin config" };
          }
          const resource = String(params.resource ?? "");
          if (!resource) return { valid: false, error: "resource is required" };
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

          // Reconstruct the requirement from CONFIG price only (never caller input).
          // Its amount is both the settlement threshold and the value the nonce
          // commits to, so a buyer cannot redeem at a cheaper price than challenged.
          const { requirement } = makeChallenge({
            priceUsdc: config.priceUsdc,
            recipientAddress: config.recipientAddress,
            resource,
            network: config.network,
          });

          // Presenter-auth: prove control of the paying key by signing the gate's
          // nonce (which commits resource + price). Mandatory on mainnet, and ALWAYS
          // required for capability reuse. Blocks replay of an observed public proof.
          const needAuth = config.requirePresenterAuth || !!proof.capability;
          if (needAuth) {
            const n = verifyNonce(proof.nonce, resource, requirement.maxAmountRequired, secret, now);
            if (!n.ok) return { valid: false, error: `presenter auth failed: ${n.reason}` };
            if (!proof.payerSig || !verifyPayerSignature(proof.payerAddress, PRESENTER_AUTH_DOMAIN + (proof.nonce as string), proof.payerSig)) {
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
            // Single-use nonce against the DURABLE replay store (it survives restart —
            // critical here, since this reuse path has no on-chain check, so the nonce
            // is the ONLY thing stopping a captured reuse bundle from being replayed).
            // UNCONDITIONAL (not gated by config.dedupe): a captured reuse bundle must
            // be single-use on every network, including devnet where dedupe may be off.
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

          // Payment path. Bind the receipt hash to the gate-issued nonce (used as
          // the nullifierSeed) so it's unique per challenge.
          if (proof.nonce) requirement.extra = { ...requirement.extra, nullifierSeed: proof.nonce };

          const structural = verifyPaymentStructure(header, requirement);
          if (!structural.valid) return structural;

          if (!config.requireOnChain) return structural;

          const rpcUrl = config.rpcUrl ?? DEFAULT_RPC[config.network];
          if (!rpcUrl) {
            return { valid: false, error: `x402-gate: no RPC URL configured for ${config.network}` };
          }
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
          // Replay guard: a settled payment may only be redeemed once. The tx
          // signature is the collision-free primary key. Also consume the challenge
          // nonce (which seeds the receiptHash via nullifierSeed) so the receiptHash
          // is single-use too — this makes the documented receiptHash-based dedup safe
          // for integrators and forces a fresh challenge per payment (two payments on
          // one nonce would otherwise share a receiptHash).
          if (config.dedupe) {
            if (!replayStore.consume(structural.signature)) {
              return { valid: false, error: "payment already used (replay)" };
            }
            if (proof.nonce && !replayStore.consume(`nonce:${proof.nonce}`)) {
              return { valid: false, error: "challenge nonce already used — request a fresh 402 challenge per payment" };
            }
          }

          // Trust the on-chain delta for the reported amount, not the caller header.
          // (Reported as a JS number; the settlement DECISION above is BigInt-exact.
          // Number is lossless below 2^53 atomic units ≈ 9.007e9 USDC, far above any
          // single x402 payment — this is a reporting bound only, never a check.)
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
    }),
  ],
});
