/**
 * x402 client flow: fetch a resource, and if it answers HTTP 402, pay for it
 * with the owner's signer and retry — enforcing the spend cap and the explicit
 * mainnet opt-in BEFORE any transaction is built.
 */

import { Connection } from "@solana/web3.js";
import {
  DEFAULT_RPC,
  USDC_MINT,
  atomicToUsdc,
  type SolanaNetwork,
} from "./constants";
import { payWithSigner } from "./signer";
import type {
  X402Challenge,
  X402PayConfig,
  X402PayResult,
  X402PaymentRequirement,
  X402Signer,
} from "./types";

/** Cumulative USDC spent by this process — bounds a malicious endpoint draining
 *  the wallet one capped payment at a time. Reset by restart or resetSpend(). */
let totalSpentUsdc = 0;
export function resetSpend(): void {
  totalSpentUsdc = 0;
}

/** Parse + minimally validate a 402 response body into a challenge. */
export function parseChallenge(body: string): X402Challenge {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("x402: 402 response body is not valid JSON");
  }
  const c = parsed as X402Challenge;
  if (!c || !Array.isArray(c.accepts) || c.accepts.length === 0) {
    throw new Error("x402: 402 response has no `accepts` payment options");
  }
  return c;
}

/**
 * Choose a requirement we are allowed and able to pay. Throws (refuses to pay)
 * if every option is over the cap or requires un-opted-in mainnet.
 */
export function selectRequirement(
  challenge: X402Challenge,
  config: X402PayConfig,
): X402PaymentRequirement {
  const reasons: string[] = [];

  for (const req of challenge.accepts) {
    if (req.scheme !== "exact") {
      reasons.push(`unsupported scheme "${req.scheme}"`);
      continue;
    }
    if (req.network === "solana-mainnet" && !config.allowMainnet) {
      reasons.push("mainnet payment requires allowMainnet=true (real-money opt-in)");
      continue;
    }
    // The cap is USDC-denominated (6 decimals). Refuse any other mint, or a
    // malicious challenge could name a more-valuable 6-decimal token and slip
    // a large transfer under the cap.
    if (req.asset !== USDC_MINT[req.network]) {
      reasons.push(`refusing non-USDC asset ${req.asset}`);
      continue;
    }
    if (config.allowedRecipients && config.allowedRecipients.length > 0 && !config.allowedRecipients.includes(req.payTo)) {
      reasons.push(`recipient ${req.payTo} not in allowedRecipients`);
      continue;
    }
    const usdc = atomicToUsdc(Number(req.maxAmountRequired));
    if (usdc > config.maxAmountUsdc) {
      reasons.push(`${usdc} USDC exceeds maxAmountUsdc cap of ${config.maxAmountUsdc}`);
      continue;
    }
    return req;
  }

  throw new Error(`x402: refusing to pay — ${reasons.join("; ")}`);
}

/** Build the X-Payment header value (base64 JSON proof). Field names MUST match
 *  the gate's X402PaymentProof exactly: { signature, payerAddress, amount, resource }. */
export function buildPaymentHeader(opts: {
  signature: string;
  payerAddress: string;
  amount: string;
  resource: string;
  nonce?: string;
  payerSig?: string;
}): string {
  return Buffer.from(JSON.stringify(opts), "utf8").toString("base64");
}

export interface FetchWithX402Options {
  signer: X402Signer;
  config: X402PayConfig;
  /** Passed through to fetch() for the initial + retried request */
  init?: RequestInit;
}

/**
 * Fetch `url`; if it returns 402, pay and retry once with the X-Payment header.
 * Returns the resource body plus payment metadata. Never pays more than the cap,
 * never touches mainnet unless explicitly opted in, never holds a key.
 */
export async function fetchWithX402(
  url: string,
  opts: FetchWithX402Options,
): Promise<X402PayResult> {
  const { signer, config, init } = opts;

  const first = await fetch(url, init);
  if (first.status !== 402) {
    return { ok: first.ok, status: first.status, body: await first.text() };
  }

  // Decide what (if anything) we will pay — enforced before building any tx.
  const challenge = parseChallenge(await first.text());
  const req = selectRequirement(challenge, config);
  const network: SolanaNetwork = req.network;

  // Cumulative spend rail — bound total spend across this process, not just per call.
  const reqUsdc = atomicToUsdc(Number(req.maxAmountRequired));
  if (config.maxTotalUsdc !== undefined && totalSpentUsdc + reqUsdc > config.maxTotalUsdc) {
    throw new Error(
      `x402: refusing to pay — cumulative cap reached (${totalSpentUsdc} + ${reqUsdc} > ${config.maxTotalUsdc} USDC)`,
    );
  }
  // If the gate requires presenter auth, confirm we CAN sign the nonce BEFORE we
  // spend anything — otherwise we'd pay and then be unable to redeem it.
  if (challenge.nonce && !signer.signMessage) {
    throw new Error("x402: gate requires presenter auth (a signed nonce) but the signer has no signMessage");
  }

  const rpcUrl = config.rpcUrl ?? DEFAULT_RPC[network];
  const connection = new Connection(rpcUrl, "confirmed");

  const { signature, receiptHash, amountUsdc } = await payWithSigner(
    connection,
    signer,
    req,
  );
  totalSpentUsdc += reqUsdc;

  // Presenter binding: sign the gate-issued nonce with the payer key so an
  // observer of the on-chain payment can't replay this proof for free access.
  let nonce: string | undefined;
  let payerSig: string | undefined;
  if (challenge.nonce) {
    nonce = challenge.nonce;
    payerSig = await signer.signMessage!(challenge.nonce);
  }

  const header = buildPaymentHeader({
    signature,
    payerAddress: signer.publicKey,
    amount: req.maxAmountRequired,
    resource: req.resource,
    nonce,
    payerSig,
  });

  const retried = await fetch(url, {
    ...init,
    headers: { ...(init?.headers ?? {}), "X-Payment": header },
  });

  return {
    ok: retried.ok,
    status: retried.status,
    body: await retried.text(),
    paymentSignature: signature,
    receiptHash,
    amountUsdc,
    payTo: req.payTo,
    network,
  };
}
