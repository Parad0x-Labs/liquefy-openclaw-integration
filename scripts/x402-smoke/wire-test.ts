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
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Keypair, PublicKey, type TransactionInstruction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync as splGetAta,
  createAssociatedTokenAccountIdempotentInstruction as splCreateAtaIdem,
  createTransferCheckedInstruction as splTransferChecked,
} from "@solana/spl-token";
import { buildPaymentHeader, selectRequirement } from "../../skills/x402-pay/src/client";
import {
  getAssociatedTokenAddressSync as venGetAta,
  createAssociatedTokenAccountIdempotentInstruction as venCreateAtaIdem,
  createTransferCheckedInstruction as venTransferChecked,
} from "../../skills/x402-pay/src/spl";
import { SpendLedger } from "../../skills/x402-pay/src/ledger";
import type { X402PayConfig } from "../../skills/x402-pay/src/types";
import { makeRequirement, verifyPaymentStructure, receiptHashFor } from "../../skills/x402-gate/src/gate";
import { issueNonce, verifyNonce, verifyPayerSignature, issueCapability, verifyCapability } from "../../skills/x402-gate/src/auth";
import { PRESENTER_AUTH_DOMAIN } from "../../skills/x402-gate/src/constants";

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

const authMsg = PRESENTER_AUTH_DOMAIN + nonce; // domain-separated message the payer signs
const payerSig = signMessage(payer.secretKey.slice(0, 32), authMsg);
assert("payer signature verifies (presenter controls the key)", verifyPayerSignature(payer.publicKey.toBase58(), authMsg, payerSig) === true);
assert("raw-nonce signature rejected (domain separation)", verifyPayerSignature(payer.publicKey.toBase58(), authMsg, signMessage(payer.secretKey.slice(0, 32), nonce)) === false);

const attacker = Keypair.generate();
const attackerSig = signMessage(attacker.secretKey.slice(0, 32), authMsg);
assert("observer/attacker signature rejected (presenter binding)", verifyPayerSignature(payer.publicKey.toBase58(), authMsg, attackerSig) === false);

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

// --- 5. durable spend ledger survives a "restart" (round-14 double-pay fix) ---
const ledgerDir = mkdtempSync(join(tmpdir(), "x402-ledger-"));
const ledgerPath = join(ledgerDir, "spend.json");
const l1 = new SpendLedger(ledgerPath);
assert("ledger with a path reports durable", l1.durable === true);
l1.recordBroadcast("payer|host|/premium", "pendingSig123", 1000, 0.5, "RecipientOne");
const l2 = new SpendLedger(ledgerPath); // simulate process restart
assert("ledger persists cumulative spend across restart", l2.totalSpent() === 0.5);
const p5 = l2.getPending("payer|host|/premium");
assert("ledger persists pending signature across restart", p5?.signature === "pendingSig123");
assert("ledger persists pending blockhash window across restart", p5?.lastValidBlockHeight === 1000);
assert("ledger persists distinct recipients across restart", l2.hasRecipient("RecipientOne") && l2.recipientCount() === 1);
l2.clearPending("payer|host|/premium");
const l3 = new SpendLedger(ledgerPath);
assert("ledger persists a pending clear across restart", l3.getPending("payer|host|/premium") === undefined);
assert("in-memory ledger (no path) reports NOT durable", new SpendLedger().durable === false);
rmSync(ledgerDir, { recursive: true, force: true });

// --- 6. explicit maxAmountUsdc=0 / negative is refuse-all, never an open spend ---
const challenge = { x402Version: 1, accepts: [requirement] };
const baseCfg = (max: number): X402PayConfig => ({ maxAmountUsdc: max, allowMainnet: false });
const refuses = (cfg: X402PayConfig): boolean => {
  try { selectRequirement(challenge, cfg); return false; } catch { return true; }
};
assert("maxAmountUsdc=0 refuses all payment (explicit pay-nothing)", refuses(baseCfg(0)));
assert("maxAmountUsdc<0 refuses all payment", refuses(baseCfg(-1)));
assert("maxAmountUsdc=NaN refuses all payment", refuses(baseCfg(NaN)));
assert("maxAmountUsdc=Infinity refuses all payment", refuses(baseCfg(Infinity)));
assert("positive cap above price selects the requirement", !refuses(baseCfg(1)));

// --- 7. ledger fails CLOSED on a corrupt file, never silently zeroes (round-16) ---
const corruptDir = mkdtempSync(join(tmpdir(), "x402-corrupt-"));
const corruptPath = join(corruptDir, "spend.json");
writeFileSync(corruptPath, "{ this is not valid json", "utf8");
let corruptThrew = false;
try {
  new SpendLedger(corruptPath);
} catch {
  corruptThrew = true;
}
assert("corrupt ledger fails CLOSED (constructor throws, no silent zero)", corruptThrew === true);
// and a healthy round-trip after writing a real record still loads (atomic write)
writeFileSync(corruptPath, "", "utf8"); // truncate to empty to clear the bad content
rmSync(corruptPath, { force: true });
const healthy = new SpendLedger(corruptPath);
healthy.recordBroadcast("ck", "okSig", 42, 0.01, "R");
assert("atomic write round-trips after a clean start", new SpendLedger(corruptPath).getPending("ck")?.signature === "okSig");
rmSync(corruptDir, { recursive: true, force: true });

// --- 8. vendored SPL builders are byte-identical to @solana/spl-token ---
// (proves dropping the @solana/spl-token dep — and its bigint-buffer chain — did
//  not change a single byte of any payment instruction)
const ixEqual = (a: TransactionInstruction, b: TransactionInstruction): boolean =>
  a.programId.equals(b.programId) &&
  Buffer.from(a.data).equals(Buffer.from(b.data)) &&
  a.keys.length === b.keys.length &&
  a.keys.every((k, i) =>
    k.pubkey.equals(b.keys[i].pubkey) && k.isSigner === b.keys[i].isSigner && k.isWritable === b.keys[i].isWritable);

const mint = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"); // USDC mainnet
const ownerOn = payer.publicKey; // on-curve owner
const ownerOff = new PublicKey("9vDnXsPonRJa7yAmvwRGMAdxt8W13Qbm7HZuvauM3Ya3"); // may be off-curve
assert(
  "vendored ATA address == spl-token (on-curve owner)",
  venGetAta(mint, ownerOn).equals(splGetAta(mint, ownerOn)),
);
assert(
  "vendored ATA address == spl-token (off-curve allowed)",
  venGetAta(mint, ownerOff).equals(splGetAta(mint, ownerOff, true)),
);
const venAta = venGetAta(mint, ownerOff);
assert(
  "vendored createAtaIdempotent ix == spl-token",
  ixEqual(
    venCreateAtaIdem(ownerOn, venAta, ownerOff, mint),
    splCreateAtaIdem(ownerOn, venAta, ownerOff, mint),
  ),
);
assert(
  "vendored transferChecked ix == spl-token",
  ixEqual(
    venTransferChecked(venGetAta(mint, ownerOn), mint, venAta, ownerOn, 50000n, 6),
    splTransferChecked(venGetAta(mint, ownerOn), mint, venAta, ownerOn, 50000n, 6),
  ),
);

console.log(`\n${fail === 0 ? "WIRE + AUTH + CAPABILITY + LEDGER + SPL OK" : "FAILED"} — ${fail} failure(s)`);
process.exit(fail === 0 ? 0 : 1);
