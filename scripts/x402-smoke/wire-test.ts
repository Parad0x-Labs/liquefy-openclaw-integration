/**
 * Wire-contract + presenter-auth test (no network).
 *
 * 1. The buyer's payment header (x402-pay) must be accepted by the seller's
 *    structural verifier (x402-gate) — catches field-name drift (amount vs
 *    amountAtomic) that fails every real payment after funds settle.
 * 2. Presenter binding: the gate-issued nonce verifies, is bound to the resource
 *    + issuer + expiry, and only the PAYER's key can produce a valid signature
 *    over it — an observer/attacker key is rejected.
 *
 * Run: cd scripts/x402-smoke && npx tsx wire-test.ts
 */

import { createPrivateKey, sign as edSign } from "node:crypto";
import { Keypair } from "@solana/web3.js";
import { buildPaymentHeader } from "../../skills/x402-pay/src/client";
import { makeRequirement, verifyPaymentStructure, receiptHashFor } from "../../skills/x402-gate/src/gate";
import { issueNonce, verifyNonce, verifyPayerSignature, issueCapability, verifyCapability } from "../../skills/x402-gate/src/auth";

let fail = 0;
const assert = (name: string, ok: boolean, extra?: string) => {
  if (!ok) fail++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
};

// ed25519 sign with a Solana keypair's 32-byte seed (mirrors a wallet signMessage).
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function signMessage(seed32: Uint8Array, msg: string): string {
  const der = Buffer.concat([PKCS8_PREFIX, Buffer.from(seed32)]);
  const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return edSign(null, Buffer.from(msg, "utf8"), key).toString("base64");
}

const requirement = makeRequirement({
  priceUsdc: 0.05,
  recipientAddress: "9vDnXsPonRJa7yAmvwRGMAdxt8W13Qbm7HZuvauM3Ya3",
  resource: "/premium",
  network: "solana-devnet",
});
const payer = Keypair.generate();

// --- 1. wire contract: header field names must agree ---
const header = buildPaymentHeader({
  signature: "wireTestSignaturePlaceholder",
  payerAddress: payer.publicKey.toBase58(),
  amount: requirement.maxAmountRequired,
  resource: requirement.resource,
});
const res = verifyPaymentStructure(header, requirement);
assert("buyer proof passes gate structural verify (wire fields agree)", res.valid === true, res.valid ? "" : res.error);
if (res.valid) assert("amount round-trips", res.amountAtomic === Number(requirement.maxAmountRequired));
const cheap = buildPaymentHeader({ signature: "s", payerAddress: "p", amount: "1", resource: requirement.resource });
assert("underpaid proof rejected", verifyPaymentStructure(cheap, requirement).valid === false);

// --- 2. presenter auth: nonce + payer-key signature ---
const secret = "wire-test-secret";
const now = 1_000_000;
const amt = requirement.maxAmountRequired;
const nonce = issueNonce(requirement.resource, amt, secret, now);
assert("issued nonce verifies", verifyNonce(nonce, requirement.resource, amt, secret, now).ok === true);
assert("nonce rejected for wrong resource", verifyNonce(nonce, "/other", amt, secret, now).ok === false);
assert("nonce rejected for wrong price (price-binding)", verifyNonce(nonce, requirement.resource, "1", secret, now).ok === false);
assert("nonce rejected when expired", verifyNonce(nonce, requirement.resource, amt, secret, now + 100_000).ok === false);
assert("nonce rejected with wrong secret", verifyNonce(nonce, requirement.resource, amt, "other-secret", now).ok === false);

const payerSig = signMessage(payer.secretKey.slice(0, 32), nonce);
assert("payer signature verifies (presenter controls the key)", verifyPayerSignature(payer.publicKey.toBase58(), nonce, payerSig) === true);

const attacker = Keypair.generate();
const attackerSig = signMessage(attacker.secretKey.slice(0, 32), nonce);
assert("observer/attacker signature rejected (presenter binding)", verifyPayerSignature(payer.publicKey.toBase58(), nonce, attackerSig) === false);

// --- 3. portable capability receipts (pay-once-reuse) ---
const cap = issueCapability(payer.publicKey.toBase58(), requirement.resource, 3600, secret, now);
assert("capability verifies for the payer+resource", verifyCapability(cap, payer.publicKey.toBase58(), requirement.resource, secret, now).ok === true);
assert("capability rejected after expiry", verifyCapability(cap, payer.publicKey.toBase58(), requirement.resource, secret, now + 3601).ok === false);
assert("capability rejected for a different payer", verifyCapability(cap, attacker.publicKey.toBase58(), requirement.resource, secret, now).ok === false);
assert("capability rejected for a different resource", verifyCapability(cap, payer.publicKey.toBase58(), "/other", secret, now).ok === false);
assert("capability rejected with wrong secret", verifyCapability(cap, payer.publicKey.toBase58(), requirement.resource, "other-secret", now).ok === false);

// --- 4. per-challenge receipt-hash uniqueness (seed = nonce) ---
const reqA = { ...requirement, extra: { ...requirement.extra, nullifierSeed: "nonceA" } };
const reqB = { ...requirement, extra: { ...requirement.extra, nullifierSeed: "nonceB" } };
assert(
  "receipt hash is unique per nullifierSeed (per challenge)",
  receiptHashFor(payer.publicKey.toBase58(), reqA) !== receiptHashFor(payer.publicKey.toBase58(), reqB),
);

console.log(`\n${fail === 0 ? "WIRE + AUTH + CAPABILITY OK" : "FAILED"} — ${fail} failure(s)`);
process.exit(fail === 0 ? 0 : 1);
