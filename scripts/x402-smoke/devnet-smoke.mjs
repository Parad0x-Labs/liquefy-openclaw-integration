/**
 * x402 devnet smoke test — proves the gate verifies REAL settlement.
 *
 * Self-contained: creates a throwaway SPL mint (no faucet), runs the actual
 * pay -> verify loop on devnet, and asserts the fixed gate logic:
 *   TEST 1  real payment (transfer + memo)      -> ACCEPTED
 *   TEST 2  forged memo-only tx (pays nothing)  -> REJECTED   (the free-ride)
 *   TEST 3  underpayment (half the price)       -> REJECTED
 *
 * The memo carries the receipt hash in all three, so the OLD memo-only check
 * would have passed every one. Only the balance-delta check rejects 2 & 3 —
 * that is the fix this test exists to prove.
 *
 * confirmOnChain() below mirrors skills/x402-gate/src/onchain.ts exactly.
 *
 * Run:
 *   cd scripts/x402-smoke && npm install --ignore-scripts && node devnet-smoke.mjs
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
  LAMPORTS_PER_SOL, sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  createMint, getOrCreateAssociatedTokenAccount, mintTo,
  getAssociatedTokenAddressSync, createTransferCheckedInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";

const RPC = process.env.SOLANA_DEVNET_RPC_URL || "https://api.devnet.solana.com";
const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const MEMO_PREFIX = "null-miner-v1";
const DECIMALS = 6;

const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// mirrors gate.ts / signer.ts receiptHashFor
const receiptHashFor = (payer, req) =>
  sha256Hex([req.memoPrefix, payer, req.payTo, req.maxAmountRequired, req.resource, req.network, req.extra?.nullifierSeed ?? ""].join("|"));

// mirrors skills/x402-gate/src/onchain.ts confirmOnChain
async function confirmOnChain(conn, signature, expect) {
  if (!signature) return { confirmed: false, reason: "no signature" };
  let required;
  try { required = BigInt(expect.amountAtomic); } catch { return { confirmed: false, reason: "bad amount" }; }
  if (required <= 0n) return { confirmed: false, reason: "amount must be > 0" };

  const tx = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0, commitment: "finalized" });
  if (!tx) return { confirmed: false, reason: "not finalized / not found" };
  if (tx.meta?.err) return { confirmed: false, reason: `tx failed: ${JSON.stringify(tx.meta.err)}` };

  const logs = (tx.meta?.logMessages ?? []).join("\n");
  const receiptMemoCount = logs.split(`${MEMO_PREFIX}:`).length - 1;
  if (receiptMemoCount === 0) return { confirmed: false, reason: "no receipt memo found" };
  if (receiptMemoCount > 1) return { confirmed: false, reason: "multiple receipt memos (not a single charge)" };
  if (!logs.includes(`${MEMO_PREFIX}:${expect.receiptHash}`)) return { confirmed: false, reason: "receipt memo does not match this charge" };

  const pre = tx.meta?.preTokenBalances ?? [];
  const post = tx.meta?.postTokenBalances ?? [];
  const postEntry = post.find((b) => b.owner === expect.payTo && b.mint === expect.asset);
  if (!postEntry) return { confirmed: false, reason: "no recipient balance change", receivedAtomic: "0" };
  const preEntry = pre.find((b) => b.accountIndex === postEntry.accountIndex) ?? pre.find((b) => b.owner === expect.payTo && b.mint === expect.asset);
  const delta = BigInt(postEntry.uiTokenAmount?.amount ?? "0") - BigInt(preEntry?.uiTokenAmount?.amount ?? "0");
  if (delta < required) return { confirmed: false, reason: `short pay: ${delta} < ${required}`, receivedAtomic: delta.toString() };
  return { confirmed: true, slot: tx.slot, receivedAtomic: delta.toString() };
}

// mirrors signer.ts buildUnsignedPayment (transfer + memo), then signs+sends.
// Preflight at "confirmed" so a freshly-created mint is visible to simulation;
// finalization is awaited separately (waitFinalized) before verification.
async function payReal(conn, payer, mint, req, amountAtomic) {
  const payToPk = new PublicKey(req.payTo);
  const payerAta = getAssociatedTokenAddressSync(mint, payer.publicKey);
  const payToAta = getAssociatedTokenAddressSync(mint, payToPk);
  const receiptHash = receiptHashFor(payer.publicKey.toBase58(), req);
  const tx = new Transaction().add(
    createAssociatedTokenAccountIdempotentInstruction(payer.publicKey, payToAta, payToPk, mint),
    createTransferCheckedInstruction(payerAta, mint, payToAta, payer.publicKey, BigInt(amountAtomic), DECIMALS),
    new TransactionInstruction({ keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(`${req.memoPrefix}:${receiptHash}`, "utf8") }),
  );
  return sendAndConfirmTransaction(conn, tx, [payer], { commitment: "confirmed" });
}

// forged: stamp the memo but transfer nothing
async function payMemoOnly(conn, payer, receiptHash) {
  const tx = new Transaction().add(
    new TransactionInstruction({ keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(`${MEMO_PREFIX}:${receiptHash}`, "utf8") }),
  );
  return sendAndConfirmTransaction(conn, tx, [payer], { commitment: "confirmed" });
}

// Wait until the tx is finalized so the finalized-commitment check can see it.
async function waitFinalized(conn, sig, tries = 45) {
  for (let i = 0; i < tries; i++) {
    if (await conn.getTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "finalized" })) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
}

// Funded payer: supply a devnet wallet via PAYER_KEYPAIR for a reliable run
// (the public devnet faucet often refuses airdrops from shared hosts).
function loadPayer() {
  const path = process.env.PAYER_KEYPAIR;
  if (path) return { kp: Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, "utf8")))), supplied: true };
  return { kp: Keypair.generate(), supplied: false };
}

async function ensureFunds(conn, payer, supplied) {
  const MIN = 0.05 * LAMPORTS_PER_SOL;
  let bal = await conn.getBalance(payer.publicKey, "confirmed");
  if (bal >= MIN) { console.log(`payer balance ${(bal / LAMPORTS_PER_SOL).toFixed(3)} SOL`); return; }
  console.log(`payer balance low (${(bal / LAMPORTS_PER_SOL).toFixed(3)} SOL) — trying airdrop…`);
  try {
    await conn.confirmTransaction(await conn.requestAirdrop(payer.publicKey, LAMPORTS_PER_SOL), "confirmed");
    bal = await conn.getBalance(payer.publicKey, "confirmed");
  } catch (e) { console.error(`airdrop failed (${e.message})`); }
  if (bal < MIN) {
    console.error(`\nPayer not funded. The public devnet faucet is unreliable — run with a funded devnet wallet:`);
    console.error(`  solana airdrop 1 -u devnet && PAYER_KEYPAIR=~/.config/solana/id.json node devnet-smoke.mjs`);
    if (!supplied) console.error(`  …or fund this throwaway address with ~0.1 devnet SOL: ${payer.publicKey.toBase58()}`);
    process.exit(1);
  }
}

async function main() {
  const conn = new Connection(RPC, "confirmed");
  const { kp: payer, supplied } = loadPayer();
  const seller = Keypair.generate();
  console.log(`RPC ${RPC}`);
  console.log(`payer  ${payer.publicKey.toBase58()}${supplied ? " (supplied)" : ""}`);
  console.log(`seller ${seller.publicKey.toBase58()}\n`);
  await ensureFunds(conn, payer, supplied);

  console.log("creating throwaway test mint + minting to payer…");
  const mint = await createMint(conn, payer, payer.publicKey, null, DECIMALS);
  const payerAta = await getOrCreateAssociatedTokenAccount(conn, payer, mint, payer.publicKey);
  await mintTo(conn, payer, mint, payerAta.address, payer, 10_000_000); // 10.0 test-USDC

  const priceAtomic = "50000"; // 0.05
  const req = {
    scheme: "exact", network: "solana-devnet", maxAmountRequired: priceAtomic,
    resource: "/premium", memoPrefix: MEMO_PREFIX, payTo: seller.publicKey.toBase58(),
    asset: mint.toBase58(), extra: { nullifierSeed: `smoke-${payer.publicKey.toBase58().slice(0, 8)}` },
  };
  const receiptHash = receiptHashFor(payer.publicKey.toBase58(), req);
  const expect = { receiptHash, payTo: req.payTo, asset: req.asset, amountAtomic: req.maxAmountRequired };
  console.log(`\nprice ${priceAtomic} atomic (0.05), mint ${mint.toBase58()}`);
  console.log("(waiting for each payment to finalize before verifying — ~10-40s each)\n");

  let pass = 0, fail = 0;
  const check = (name, ok, detail) => { (ok ? pass++ : fail++); console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

  // TEST 1 — real payment accepted
  const sig1 = await payReal(conn, payer, mint, req, priceAtomic);
  await waitFinalized(conn, sig1);
  const r1 = await confirmOnChain(conn, sig1, expect);
  check("real payment ACCEPTED", r1.confirmed === true, r1.confirmed ? `credited ${r1.receivedAtomic}` : r1.reason);

  // TEST 2 — forged memo-only rejected (the free-ride)
  const sig2 = await payMemoOnly(conn, payer, receiptHash);
  await waitFinalized(conn, sig2);
  const r2 = await confirmOnChain(conn, sig2, expect);
  check("forged memo-only REJECTED", r2.confirmed === false, r2.reason);

  // TEST 3 — underpayment rejected
  const sig3 = await payReal(conn, payer, mint, req, "25000"); // half
  await waitFinalized(conn, sig3);
  const r3 = await confirmOnChain(conn, sig3, expect);
  check("underpayment REJECTED", r3.confirmed === false, r3.reason);

  console.log(`\n${fail === 0 ? "ALL GREEN" : "FAILED"} — ${pass} pass, ${fail} fail`);
  console.log("note: all three carry the receipt-hash memo, so the old memo-only check would have passed every one.");
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("fatal:", e); process.exit(1); });
