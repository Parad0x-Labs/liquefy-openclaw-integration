/**
 * x402 gate — pure charging logic. Mint a 402 challenge and verify an incoming
 * payment header. No private keys, no custody: the recipient is a public address
 * you pass in, and funds settle directly to it on-chain.
 *
 * Structural verification here is synchronous and network-free. For revenue-
 * grade gating, follow it with the on-chain confirmation in ./onchain.ts.
 */

import { createHash } from "node:crypto";
import {
  MEMO_PREFIX,
  USDC_MINT,
  X402_VERSION,
  atomicToUsdc,
  usdcToAtomic,
  type SolanaNetwork,
} from "./constants";
import type {
  ChallengeOptions,
  VerifyResult,
  X402Challenge,
  X402PaymentProof,
  X402PaymentRequirement,
} from "./types";

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Receipt hash — MUST stay byte-identical to the paying side so both ends of the
 * loop derive the same value.
 */
export function receiptHashFor(payer: string, req: X402PaymentRequirement): string {
  return sha256Hex(
    [
      MEMO_PREFIX, // pinned locally, never the (untrusted) req.memoPrefix
      payer,
      req.payTo,
      req.maxAmountRequired,
      req.resource,
      req.network,
      req.extra?.nullifierSeed ?? "",
    ].join("|"),
  );
}

/** Build a single payment requirement (one entry in a 402's `accepts`). */
export function makeRequirement(opts: ChallengeOptions): X402PaymentRequirement {
  const network: SolanaNetwork = opts.network ?? "solana-mainnet";
  if (!(opts.priceUsdc > 0)) {
    throw new Error("makeRequirement: priceUsdc must be > 0");
  }
  if (!opts.recipientAddress) {
    throw new Error("makeRequirement: recipientAddress (your wallet) is required");
  }
  const atomic = usdcToAtomic(opts.priceUsdc);
  if (atomic < 1) {
    // Sub-atomic price would round to "0" — which serves content for nothing in
    // header-only mode and demands 0 on-chain. Refuse it rather than ship a free gate.
    throw new Error("makeRequirement: priceUsdc is below the smallest USDC unit (0.000001) — it would round to 0");
  }
  return {
    scheme: "exact",
    network,
    maxAmountRequired: String(atomic),
    resource: opts.resource,
    description: opts.description ?? opts.resource,
    memoPrefix: MEMO_PREFIX,
    payTo: opts.recipientAddress,
    asset: USDC_MINT[network],
    extra: {
      platformWallet: opts.platformWallet,
      platformFeePct: opts.platformFeePct,
      anchorReceipt: opts.anchorReceipt,
      platformId: opts.platformId,
      passportId: opts.passportId,
      nullifierSeed: opts.nullifierSeed,
    },
  };
}

/** Wrap a requirement into a full 402 challenge body. */
export function makeChallenge(opts: ChallengeOptions): {
  status: 402;
  body: X402Challenge;
  requirement: X402PaymentRequirement;
} {
  const requirement = makeRequirement(opts);
  return {
    status: 402,
    body: { x402Version: X402_VERSION, accepts: [requirement] },
    requirement,
  };
}

/** Decode the base64 X-Payment header into a proof object. */
export function decodePaymentHeader(header: string): X402PaymentProof {
  // Bound the unauthenticated input before decode/parse (DoS guard).
  if (header.length > 8192) {
    throw new Error("x402: X-Payment header too large");
  }
  let json: string;
  try {
    json = Buffer.from(header, "base64").toString("utf8");
  } catch {
    throw new Error("x402: X-Payment header is not valid base64");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("x402: X-Payment header is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("x402: X-Payment header is not a JSON object");
  }
  return parsed as X402PaymentProof;
}

/**
 * Structural verification — synchronous, network-free. Confirms the submitted
 * proof binds to THIS requirement (resource + amount) and derives the receipt
 * hash. Returns onChainVerified=false; pair with confirmOnChain() before serving
 * anything valuable.
 */
export function verifyPaymentStructure(
  header: string | null | undefined,
  requirement: X402PaymentRequirement,
): VerifyResult {
  if (!header) return { valid: false, error: "missing X-Payment header" };

  let proof: X402PaymentProof;
  try {
    proof = decodePaymentHeader(header);
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }

  if (!proof.signature) return { valid: false, error: "proof missing signature" };
  if (!proof.payerAddress) return { valid: false, error: "proof missing payerAddress" };
  if (proof.resource !== requirement.resource) {
    return { valid: false, error: "proof resource does not match the gated resource" };
  }

  let paid: bigint;
  let required: bigint;
  try {
    paid = BigInt(proof.amount);
    required = BigInt(requirement.maxAmountRequired);
  } catch {
    return { valid: false, error: "proof amount is not an integer" };
  }
  if (required <= 0n) {
    // Defensive: a zero/negative requirement would accept a zero payment. The
    // requirement comes from config, but never let a degenerate price serve free.
    return { valid: false, error: "requirement amount must be a positive integer" };
  }
  if (paid < required) {
    return {
      valid: false,
      error: `underpaid: ${atomicToUsdc(Number(paid))} < ${atomicToUsdc(Number(required))} USDC`,
    };
  }

  return {
    valid: true,
    payerAddress: proof.payerAddress,
    amountAtomic: Number(paid),
    amountUsdc: atomicToUsdc(Number(paid)),
    receiptHash: receiptHashFor(proof.payerAddress, requirement),
    resource: requirement.resource,
    onChainVerified: false,
    signature: proof.signature,
  };
}
