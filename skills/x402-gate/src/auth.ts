/**
 * Proof-of-presenter binding for x402-gate.
 *
 * Settlement + replay protection prove a payment happened once, but the public
 * X-Payment proof (signature, payer, amount, resource) can be copied by anyone
 * who observes the on-chain payment and replayed for ACCESS theft. To stop that,
 * the gate issues a single-use nonce in the 402 challenge and the caller must
 * sign it with the PAYER's key. Only the key holder can produce that signature,
 * so an on-chain observer cannot redeem someone else's payment.
 *
 * The nonce is a self-verifying HMAC token (no server-side nonce storage): it
 * encodes the resource + expiry and is MAC'd with a server secret; verification
 * re-derives the MAC and checks expiry. Reuse of a (nonce, payment) pair is
 * stopped by the signature dedupe in replay.ts.
 */

import { createHmac, createPublicKey, verify, randomBytes, timingSafeEqual } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

const NONCE_TTL_SEC = 300; // 5 minutes to pay and present

// SPKI DER prefix for a raw 32-byte ed25519 public key (lets node verify a
// Solana pubkey without adding a crypto dependency).
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

let ephemeralSecret: Buffer | null = null;

/** Resolve the challenge secret: the configured value, else a per-process random
 *  one (fine for a single instance; set challengeSecret to share across instances). */
export function resolveSecret(configured?: string): string {
  if (configured) return configured;
  if (!ephemeralSecret) ephemeralSecret = randomBytes(32);
  return ephemeralSecret.toString("hex");
}

function mac(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

/** Issue a nonce token bound to `resource` AND `amountAtomic` (the challenged
 *  price), valid for NONCE_TTL_SEC from `nowSec`. Binding the price means a nonce
 *  issued at price X can't be redeemed against a different (e.g. tiny) price. */
export function issueNonce(resource: string, amountAtomic: string, secret: string, nowSec: number): string {
  const exp = nowSec + NONCE_TTL_SEC;
  const rand = randomBytes(12).toString("hex");
  return `${exp}.${rand}.${mac(secret, `${exp}.${rand}.${resource}.${amountAtomic}`)}`;
}

/** Verify a nonce token: well-formed, MAC matches (right issuer + resource + price), unexpired. */
export function verifyNonce(
  token: string | undefined,
  resource: string,
  amountAtomic: string,
  secret: string,
  nowSec: number,
): { ok: boolean; reason?: string } {
  if (!token) return { ok: false, reason: "missing nonce" };
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed nonce" };
  const [expStr, rand, gotMac] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp)) return { ok: false, reason: "bad nonce expiry" };
  const want = mac(secret, `${expStr}.${rand}.${resource}.${amountAtomic}`);
  const a = Buffer.from(gotMac);
  const b = Buffer.from(want);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: "nonce MAC mismatch (wrong issuer or resource)" };
  }
  if (nowSec > exp) return { ok: false, reason: "nonce expired" };
  return { ok: true };
}

/**
 * Portable capability receipt — the "pay once, reuse within scope" token.
 *
 * After a verified payment, the gate issues a self-verifying HMAC token bound to
 * (payer, resource, expiry). The buyer re-presents it on later calls to the same
 * resource and is served WITHOUT a new payment, until it expires. Reuse still
 * requires presenter-auth (a payer-key signature over a fresh nonce), so a
 * stolen token is useless to an observer. Stateless: no server storage, reuses
 * the same challengeSecret as the nonce.
 */
export function issueCapability(payerAddress: string, resource: string, scopeSec: number, secret: string, nowSec: number): string {
  const exp = nowSec + scopeSec;
  return `${exp}.${mac(secret, `cap|${payerAddress}|${resource}|${exp}`)}`;
}

/** Verify a capability token for (payerAddress, resource): MAC matches + unexpired. */
export function verifyCapability(
  token: string | undefined,
  payerAddress: string,
  resource: string,
  secret: string,
  nowSec: number,
): { ok: boolean; reason?: string } {
  if (!token) return { ok: false, reason: "missing capability" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed capability" };
  const [expStr, gotMac] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp)) return { ok: false, reason: "bad capability expiry" };
  const want = mac(secret, `cap|${payerAddress}|${resource}|${expStr}`);
  const a = Buffer.from(gotMac);
  const b = Buffer.from(want);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: "capability MAC mismatch" };
  if (nowSec > exp) return { ok: false, reason: "capability expired" };
  return { ok: true };
}

/** Verify an ed25519 signature by `payerAddress` (base58 Solana pubkey) over `message`.
 *  `sigBase64` is the 64-byte signature, base64-encoded. */
export function verifyPayerSignature(payerAddress: string, message: string, sigBase64: string): boolean {
  try {
    const raw = Buffer.from(new PublicKey(payerAddress).toBytes());
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    const sig = Buffer.from(sigBase64, "base64");
    if (sig.length !== 64) return false;
    return verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}
