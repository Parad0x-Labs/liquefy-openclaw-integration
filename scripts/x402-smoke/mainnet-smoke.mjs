/**
 * x402 MAINNET smoke — proves a real USDC payment settles and the gate accepts it,
 * and that a forged memo-only tx is still rejected. MOVES REAL FUNDS (tiny).
 *
 * Setup:
 *   - PAYER_KEYPAIR must hold ~0.05 USDC + ~0.02 SOL.
 *   - RECIPIENT = a second address YOU own (keeps the test USDC). If unset, a
 *     throwaway recipient is used and the ~0.01 USDC + ATA rent is forfeited.
 *
 * Run:
 *   cd scripts/x402-smoke && npm install --ignore-scripts
 *   PAYER_KEYPAIR=~/.config/solana/id.json RECIPIENT=<your-2nd-address> node mainnet-smoke.mjs
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
import { getAssociatedTokenAddressSync, createTransferCheckedInstruction, createAssociatedTokenAccountIdempotentInstruction, getAccount } from "@solana/spl-token";

const RPC = process.env.SOLANA_MAINNET_RPC_URL || "https://solana-rpc.publicnode.com";
const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const MEMO_PREFIX = "null-miner-v1";
const DECIMALS = 6;
const AMOUNT = "10000"; // 0.01 USDC

const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const receiptHashFor = (payer, req) =>
  sha256Hex([req.memoPrefix, payer, req.payTo, req.maxAmountRequired, req.resource, req.network, req.extra?.nullifierSeed ?? ""].join("|"));

// mirrors skills/x402-gate/src/onchain.ts
async function confirmOnChain(conn, signature, expect) {
  if (!signature) return { confirmed: false, reason: "no signature" };
  const required = BigInt(expect.amountAtomic);
  const tx = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0, commitment: "finalized" });
  if (!tx) return { confirmed: false, reason: "not finalized / not found" };
  if (tx.meta?.err) return { confirmed: false, reason: `tx failed: ${JSON.stringify(tx.meta.err)}` };
  const logs = (tx.meta?.logMessages ?? []).join("\n");
  if (!logs.includes(expect.receiptHash)) return { confirmed: false, reason: "memo missing receipt hash" };
  const pre = tx.meta?.preTokenBalances ?? [], post = tx.meta?.postTokenBalances ?? [];
  const postEntry = post.find((b) => b.owner === expect.payTo && b.mint === expect.asset);
  if (!postEntry) return { confirmed: false, reason: "no recipient balance change", receivedAtomic: "0" };
  const preEntry = pre.find((b) => b.accountIndex === postEntry.accountIndex) ?? pre.find((b) => b.owner === expect.payTo && b.mint === expect.asset);
  const delta = BigInt(postEntry.uiTokenAmount?.amount ?? "0") - BigInt(preEntry?.uiTokenAmount?.amount ?? "0");
  if (delta < required) return { confirmed: false, reason: `short pay: ${delta} < ${required}`, receivedAtomic: delta.toString() };
  return { confirmed: true, slot: tx.slot, receivedAtomic: delta.toString() };
}

async function payReal(conn, payer, req, amountAtomic) {
  const payToPk = new PublicKey(req.payTo);
  const payerAta = getAssociatedTokenAddressSync(USDC, payer.publicKey);
  const payToAta = getAssociatedTokenAddressSync(USDC, payToPk);
  const receiptHash = receiptHashFor(payer.publicKey.toBase58(), req);
  const tx = new Transaction().add(
    createAssociatedTokenAccountIdempotentInstruction(payer.publicKey, payToAta, payToPk, USDC),
    createTransferCheckedInstruction(payerAta, USDC, payToAta, payer.publicKey, BigInt(amountAtomic), DECIMALS),
    new TransactionInstruction({ keys: [], programId: MEMO, data: Buffer.from(`${req.memoPrefix}:${receiptHash}`, "utf8") }),
  );
  return sendAndConfirmTransaction(conn, tx, [payer], { commitment: "confirmed" });
}

async function payMemoOnly(conn, payer, receiptHash) {
  return sendAndConfirmTransaction(conn, new Transaction().add(
    new TransactionInstruction({ keys: [], programId: MEMO, data: Buffer.from(`${MEMO_PREFIX}:${receiptHash}`, "utf8") }),
  ), [payer], { commitment: "confirmed" });
}

async function waitFinalized(conn, sig, tries = 45) {
  for (let i = 0; i < tries; i++) {
    if (await conn.getTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "finalized" })) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
}

async function main() {
  if (!process.env.PAYER_KEYPAIR) { console.error("set PAYER_KEYPAIR to a mainnet wallet holding ~0.05 USDC + ~0.02 SOL"); process.exit(1); }
  const conn = new Connection(RPC, "confirmed");
  const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(process.env.PAYER_KEYPAIR, "utf8"))));
  const recipient = process.env.RECIPIENT ? new PublicKey(process.env.RECIPIENT) : Keypair.generate().publicKey;
  console.log(`RPC ${RPC}`);
  console.log(`payer     ${payer.publicKey.toBase58()}`);
  console.log(`recipient ${recipient.toBase58()}${process.env.RECIPIENT ? "" : "  (throwaway — set RECIPIENT to keep the test USDC)"}\n`);

  // pre-flight balance checks
  try {
    const acc = await getAccount(conn, getAssociatedTokenAddressSync(USDC, payer.publicKey));
    console.log(`payer USDC ${(Number(acc.amount) / 1e6).toFixed(4)}, SOL ${(await conn.getBalance(payer.publicKey) / 1e9).toFixed(4)}`);
    if (acc.amount < BigInt(AMOUNT)) { console.error("payer has too little USDC"); process.exit(1); }
  } catch { console.error("payer has no USDC account — fund it with a little USDC first"); process.exit(1); }

  const req = {
    scheme: "exact", network: "solana-mainnet", maxAmountRequired: AMOUNT, resource: "/premium",
    memoPrefix: MEMO_PREFIX, payTo: recipient.toBase58(), asset: USDC.toBase58(),
    extra: { nullifierSeed: `smoke-${payer.publicKey.toBase58().slice(0, 8)}` },
  };
  const receiptHash = receiptHashFor(payer.publicKey.toBase58(), req);
  const expect = { receiptHash, payTo: req.payTo, asset: req.asset, amountAtomic: req.maxAmountRequired };
  console.log(`\npaying ${AMOUNT} atomic (0.01 USDC) — finalization wait ~10-40s each\n`);

  let pass = 0, fail = 0;
  const check = (n, ok, d) => { (ok ? pass++ : fail++); console.log(`  ${ok ? "PASS" : "FAIL"}  ${n}${d ? " — " + d : ""}`); };

  const sig1 = await payReal(conn, payer, req, AMOUNT);
  console.log(`  real payment tx ${sig1}`);
  await waitFinalized(conn, sig1);
  const r1 = await confirmOnChain(conn, sig1, expect);
  check("real payment ACCEPTED", r1.confirmed === true, r1.confirmed ? `credited ${r1.receivedAtomic}` : r1.reason);

  const sig2 = await payMemoOnly(conn, payer, receiptHash);
  await waitFinalized(conn, sig2);
  const r2 = await confirmOnChain(conn, sig2, expect);
  check("forged memo-only REJECTED", r2.confirmed === false, r2.reason);

  console.log(`\n${fail === 0 ? "ALL GREEN" : "FAILED"} — ${pass} pass, ${fail} fail`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("fatal:", e); process.exit(1); });
