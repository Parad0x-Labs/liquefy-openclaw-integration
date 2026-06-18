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
 *  the wallet one capped payment at a time. Reset only by restarting the process. */
let totalSpentUsdc = 0;

/** Capability tokens held from prior payments, keyed by payer|resource, so the
 *  same resource can be reused within its scope without paying again. */
interface CachedCapability {
  token: string;
  exp: number;
}
const capabilityStore = new Map<string, CachedCapability>();
const capKey = (payer: string, resource: string): string => `${payer}|${resource}`;
const capExp = (token: string): number => {
  const n = Number(token.split(".")[0]);
  return Number.isFinite(n) ? n : 0;
};

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
  // The cap must be a finite positive number — a NaN/Infinity cap would make the
  // `usdc > cap` check below always false and silently authorize any amount.
  if (!Number.isFinite(config.maxAmountUsdc) || config.maxAmountUsdc <= 0) {
    throw new Error("x402: invalid maxAmountUsdc cap (must be a finite positive number) — refusing to pay");
  }
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
    if (!/^[0-9]+$/.test(req.maxAmountRequired) || BigInt(req.maxAmountRequired) <= 0n) {
      reasons.push(`invalid amount "${req.maxAmountRequired}" (must be a positive integer of atomic units)`);
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
  capability?: string;
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

  // Bound the untrusted 402 challenge body before reading/parsing it (DoS guard).
  if (Number(first.headers.get("content-length") ?? "0") > 65536) {
    throw new Error("x402: 402 challenge body too large");
  }
  // Decide what (if anything) we will pay — enforced before building any tx.
  const challenge = parseChallenge(await first.text());
  const req = selectRequirement(challenge, config);
  const network: SolanaNetwork = req.network;
  const nowSec = Math.floor(Date.now() / 1000);

  // Presenter auth needs message signing — confirm we can BEFORE spending anything.
  if (challenge.nonce && !signer.signMessage) {
    throw new Error("x402: gate requires presenter auth (a signed nonce) but the signer has no signMessage");
  }

  // Capability reuse: if we hold a live capability for this resource, present it
  // (signing the fresh nonce to prove the key) and skip payment entirely.
  const ckey = capKey(signer.publicKey, req.resource);
  const cached = capabilityStore.get(ckey);
  if (cached && cached.exp > nowSec + 5 && challenge.nonce && signer.signMessage) {
    const reuseSig = await signer.signMessage(challenge.nonce);
    const reuseHeader = buildPaymentHeader({
      signature: "",
      payerAddress: signer.publicKey,
      amount: "0",
      resource: req.resource,
      nonce: challenge.nonce,
      payerSig: reuseSig,
      capability: cached.token,
    });
    const reuse = await fetch(url, { ...init, headers: { ...(init?.headers ?? {}), "X-Payment": reuseHeader } });
    if (reuse.ok) {
      return { ok: true, status: reuse.status, body: await reuse.text(), payTo: req.payTo, network, reusedCapability: true };
    }
    capabilityStore.delete(ckey); // rejected / expired — fall through to a fresh payment
  }

  // Cumulative spend rail — bound total spend across this process, not just per call.
  const reqUsdc = atomicToUsdc(Number(req.maxAmountRequired));
  if (config.maxTotalUsdc !== undefined && totalSpentUsdc + reqUsdc > config.maxTotalUsdc) {
    throw new Error(
      `x402: refusing to pay — cumulative cap reached (${totalSpentUsdc} + ${reqUsdc} > ${config.maxTotalUsdc} USDC)`,
    );
  }
  if (network === "solana-mainnet" && !config.rpcUrl) {
    throw new Error(
      "x402: mainnet requires an explicit rpcUrl in config — the public RPC is a third-party observer and unreliable for real payments.",
    );
  }

  const rpcUrl = config.rpcUrl ?? DEFAULT_RPC[network];
  const connection = new Connection(rpcUrl, "confirmed");

  const { signature, receiptHash, amountUsdc, status } = await payWithSigner(connection, signer, req);

  // Ambiguous confirmation — the tx MAY have landed. Surface the signature; do NOT
  // report a clean retryable failure (a naive retry would pay a second time).
  if (status !== "confirmed") {
    return {
      ok: false,
      status: 0,
      error: `x402: payment pending on-chain confirmation — verify signature ${signature} before any retry (do not re-pay)`,
      paymentSignature: signature,
      network,
      pending: true,
    };
  }
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

  // Cache any capability the gate issued (the seller echoes x402_verify's
  // `capability` in the X-Payment-Capability response header) for later reuse.
  const capToken = retried.headers.get("X-Payment-Capability");
  if (capToken) capabilityStore.set(ckey, { token: capToken, exp: capExp(capToken) });

  return {
    ok: retried.ok,
    status: retried.status,
    body: await retried.text(),
    paymentSignature: signature,
    receiptHash,
    amountUsdc,
    payTo: req.payTo,
    network,
    capability: capToken ?? undefined,
  };
}
