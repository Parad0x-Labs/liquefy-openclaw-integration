/**
 * Protocol fee-split wire test — deterministic, network-free, against the REAL source.
 *
 * Proves agent.null's enforced 5 bps (0.05%) protocol fee end to end:
 *
 *   BUYER  (x402-pay buildUnsignedPayment): every payment carries a SECOND
 *          transferChecked leg of the pinned fee to the pinned treasury, in the SAME
 *          atomic tx as the seller leg. The fee amount + treasury are taken from local
 *          constants, NEVER from the (untrusted) challenge — so a greedy seller or a
 *          malicious challenge cannot zero, inflate, or redirect the fee.
 *
 *   GATE   (x402-gate confirmOnChain): refuses to serve (fail-closed) unless BOTH the
 *          seller-leg AND the treasury-leg deltas are satisfied on-chain. A missing or
 *          underpaid fee leg is rejected even when the challenge advertised no fee.
 *
 * The gate side is exercised with a stub Connection returning a synthetic finalized
 * tx (exact pre/post token balances + program-attested memo) so the fail-closed
 * decision is proven against the real confirmOnChain with zero network/funds. The
 * sibling devnet-smoke.mjs proves the same against a live devnet settlement.
 *
 * Run (from skills/x402-gate):
 *   node --import ./test/register.mjs --test test/fee-split.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";

import {
  buildUnsignedPayment,
  type UnsignedPayment,
} from "../../x402-pay/src/signer.ts";
import {
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from "../../x402-pay/src/spl.ts";
import {
  PROTOCOL_FEE_TREASURY as PAY_TREASURY,
  PROTOCOL_FEE_BPS as PAY_BPS,
  protocolFeeAtomic as payFee,
} from "../../x402-pay/src/constants.ts";

import { confirmOnChain } from "../src/onchain.ts";
import {
  MEMO_PREFIX,
  MEMO_PROGRAM_ID,
  PROTOCOL_FEE_TREASURY,
  PROTOCOL_FEE_BPS,
  protocolFeeAtomic as gateFee,
} from "../src/constants.ts";

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // pinned USDC mint
const TREASURY = PROTOCOL_FEE_TREASURY;

// --- stub Connection for the buyer build (only getLatestBlockhash is used) ---
const buildConn = {
  getLatestBlockhash: async () => ({
    blockhash: "11111111111111111111111111111111", // 32 zero bytes — valid placeholder
    lastValidBlockHeight: 1000,
  }),
} as any;

/** Decode the SPL TransferChecked legs of a built tx: [{ dest, amount }]. */
function transferLegs(p: UnsignedPayment): { dest: string; amount: bigint }[] {
  const tx = Transaction.from(Buffer.from(p.txBase64, "base64"));
  const legs: { dest: string; amount: bigint }[] = [];
  for (const ix of tx.instructions) {
    if (ix.programId.equals(TOKEN_PROGRAM_ID) && ix.data[0] === 12 /* TransferChecked */) {
      legs.push({ dest: ix.keys[2].pubkey.toBase58(), amount: ix.data.readBigUInt64LE(1) });
    }
  }
  return legs;
}

/** Count of SPL Memo instructions in a built tx. */
function memoCount(p: UnsignedPayment): number {
  const tx = Transaction.from(Buffer.from(p.txBase64, "base64"));
  const memoPid = new PublicKey(MEMO_PROGRAM_ID);
  return tx.instructions.filter((ix) => ix.programId.equals(memoPid)).length;
}

/** True if the tx idempotently creates an ATA owned by `owner`. */
function createsAtaFor(p: UnsignedPayment, owner: string): boolean {
  const tx = Transaction.from(Buffer.from(p.txBase64, "base64"));
  return tx.instructions.some(
    (ix) =>
      ix.programId.equals(ASSOCIATED_TOKEN_PROGRAM_ID) &&
      ix.data[0] === 1 /* CreateIdempotent */ &&
      ix.keys[2].pubkey.toBase58() === owner, // keys: [payer, ata, owner, mint, sys, token]
  );
}

/** Build a synthetic finalized tx for confirmOnChain: one program-attested memo plus
 *  post token balances (pre = empty → every credit is a delta from zero). */
function fakeTx(opts: {
  memos: string[];
  balances: { index: number; owner: string; mint: string; amount: bigint | number }[];
  err?: unknown;
}) {
  const memoPid = new PublicKey(MEMO_PROGRAM_ID);
  const keyTable: PublicKey[] = [memoPid]; // index 0 = SPL Memo program
  const compiledInstructions = opts.memos.map((m) => ({
    programIdIndex: 0,
    data: new TextEncoder().encode(m),
    accountKeyIndexes: [],
  }));
  return {
    slot: 123,
    meta: {
      err: opts.err ?? null,
      preTokenBalances: [],
      postTokenBalances: opts.balances.map((b) => ({
        accountIndex: b.index,
        mint: b.mint,
        owner: b.owner,
        uiTokenAmount: { amount: String(b.amount) },
      })),
      innerInstructions: [],
      loadedAddresses: undefined,
    },
    transaction: {
      message: {
        getAccountKeys: () => ({ get: (i: number) => keyTable[i] }),
        compiledInstructions,
      },
    },
  };
}

const RECEIPT = "a".repeat(64); // stand-in receipt hash
const MEMO = `${MEMO_PREFIX}:${RECEIPT}`;

/** Run the real confirmOnChain against a synthetic tx. */
async function verify(
  tx: unknown,
  amountAtomic: string,
  payTo: string,
  asset = USDC,
  receiptHash = RECEIPT,
) {
  const conn = { getTransaction: async () => tx } as any;
  return confirmOnChain(conn, "sig", { receiptHash, payTo, asset, amountAtomic });
}

// ---------------------------------------------------------------------------
// 0. fee math is correct, pinned, byte-identical across pay + gate
// ---------------------------------------------------------------------------
test("fee is 5 bps, rounded up, never zero, identical on both sides", () => {
  assert.equal(PAY_BPS, 5);
  assert.equal(PROTOCOL_FEE_BPS, 5);
  assert.equal(PAY_TREASURY, TREASURY, "treasury pinned identically on both sides");
  // 0.05 USDC = 50000 atomic; 5 bps of that = 50000 * 5 / 10000 = 25 atomic
  assert.equal(gateFee(50_000n), 25n, "0.05 USDC -> 25 atomic fee (5 bps)");
  assert.equal(gateFee(1_000_000n), 500n, "1 USDC -> 0.0005 USDC = 500 atomic");
  assert.equal(gateFee(1n), 1n, "any positive amount owes at least 1 atomic (ceil)");
  assert.equal(gateFee(0n), 0n, "no amount, no fee");
  for (const a of [1n, 7n, 50_000n, 999_999n, 123_456_789n]) {
    assert.equal(payFee(a), gateFee(a), `pay/gate fee agree at ${a}`);
    if (a > 0n) assert.ok(gateFee(a) >= 1n, "positive amount -> positive fee");
  }
});

// ---------------------------------------------------------------------------
// 1. BUYER: the built tx carries the seller leg AND the pinned fee leg, atomically
// ---------------------------------------------------------------------------
test("buildUnsignedPayment adds a second fee leg to the pinned treasury", async () => {
  const payer = Keypair.generate().publicKey.toBase58();
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n; // 0.05 USDC
  const req = {
    scheme: "exact" as const,
    network: "solana-devnet" as const,
    maxAmountRequired: amount.toString(),
    resource: "/premium",
    description: "x",
    memoPrefix: MEMO_PREFIX,
    payTo: seller,
    asset: USDC,
  };
  const p = await buildUnsignedPayment(buildConn, payer, req);

  const mint = new PublicKey(USDC);
  const sellerAta = getAssociatedTokenAddressSync(mint, new PublicKey(seller)).toBase58();
  const treasuryAta = getAssociatedTokenAddressSync(mint, new PublicKey(TREASURY)).toBase58();

  const legs = transferLegs(p);
  assert.equal(legs.length, 2, "exactly two transfer legs (seller + fee)");

  const sellerLeg = legs.find((l) => l.dest === sellerAta);
  const feeLeg = legs.find((l) => l.dest === treasuryAta);
  assert.ok(sellerLeg, "seller leg present");
  assert.ok(feeLeg, "fee leg to treasury present");
  assert.equal(sellerLeg!.amount, amount, "seller leg pays the full price");
  assert.equal(feeLeg!.amount, gateFee(amount), "fee leg pays exactly 5 bps");

  // metadata + structural invariants
  assert.equal(p.feeAtomic, gateFee(amount).toString());
  assert.equal(p.feeTo, TREASURY);
  assert.equal(memoCount(p), 1, "exactly one receipt memo (gate requires a single memo)");
  assert.ok(createsAtaFor(p, TREASURY), "idempotent treasury ATA create present");
  assert.ok(createsAtaFor(p, seller), "idempotent seller ATA create present");
});

// ---------------------------------------------------------------------------
// 2. BUYER pins the fee — a greedy/malicious challenge cannot alter it
// ---------------------------------------------------------------------------
test("buyer ignores challenge platformFeePct / platformWallet (pinned)", async () => {
  const payer = Keypair.generate().publicKey.toBase58();
  const seller = Keypair.generate().publicKey.toBase58();
  const attacker = Keypair.generate().publicKey.toBase58();
  const amount = 1_000_000n; // 1 USDC -> 500 atomic fee
  const mint = new PublicKey(USDC);
  const treasuryAta = getAssociatedTokenAddressSync(mint, new PublicKey(TREASURY)).toBase58();
  const attackerAta = getAssociatedTokenAddressSync(mint, new PublicKey(attacker)).toBase58();

  // greedy seller zeroes the fee AND tries to redirect it to themselves
  const greedy = await buildUnsignedPayment(buildConn, payer, {
    scheme: "exact", network: "solana-devnet", maxAmountRequired: amount.toString(),
    resource: "/r", description: "x", memoPrefix: MEMO_PREFIX, payTo: seller, asset: USDC,
    extra: { platformFeePct: 0, platformWallet: attacker },
  });
  let legs = transferLegs(greedy);
  let feeLeg = legs.find((l) => l.dest === treasuryAta);
  assert.ok(feeLeg, "fee leg STILL goes to the pinned treasury despite platformFeePct=0");
  assert.equal(feeLeg!.amount, 500n, "fee is still the pinned 5 bps, not the challenge's 0");
  assert.ok(!legs.some((l) => l.dest === attackerAta), "no leg to the attacker wallet");

  // malicious challenge tries to INFLATE the fee
  const inflate = await buildUnsignedPayment(buildConn, payer, {
    scheme: "exact", network: "solana-devnet", maxAmountRequired: amount.toString(),
    resource: "/r", description: "x", memoPrefix: MEMO_PREFIX, payTo: seller, asset: USDC,
    extra: { platformFeePct: 99, platformWallet: TREASURY },
  });
  feeLeg = transferLegs(inflate).find((l) => l.dest === treasuryAta);
  assert.equal(feeLeg!.amount, 500n, "fee can't be inflated past the pinned 5 bps");
});

// ---------------------------------------------------------------------------
// 3. GATE fail-closed: both legs required at settlement
// ---------------------------------------------------------------------------
test("gate ACCEPTS when seller leg AND fee leg both settle", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n;
  const fee = gateFee(amount);
  const tx = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount },
      { index: 2, owner: TREASURY, mint: USDC, amount: fee },
    ],
  });
  const r = await verify(tx, amount.toString(), seller);
  assert.equal(r.confirmed, true, r.reason);
  assert.equal(r.feeReceivedAtomic, fee.toString());
});

test("gate REJECTS when the fee leg is ABSENT (the bypass attempt)", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n;
  const tx = fakeTx({
    memos: [MEMO],
    balances: [{ index: 1, owner: seller, mint: USDC, amount }], // seller paid, treasury credited nothing
  });
  const r = await verify(tx, amount.toString(), seller);
  assert.equal(r.confirmed, false);
  assert.match(r.reason ?? "", /protocol fee short or absent/);
  assert.equal(r.feeReceivedAtomic, "0");
});

test("gate REJECTS when the fee leg is UNDERPAID by one atomic unit", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 1_000_000n; // fee = 500
  const fee = gateFee(amount);
  const tx = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount },
      { index: 2, owner: TREASURY, mint: USDC, amount: fee - 1n },
    ],
  });
  const r = await verify(tx, amount.toString(), seller);
  assert.equal(r.confirmed, false);
  assert.match(r.reason ?? "", /protocol fee short/);
  assert.equal(r.feeReceivedAtomic, (fee - 1n).toString());
});

test("overpaying the seller does NOT lower the fee owed (fee is on the charge)", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 1_000_000n; // fee = 500 regardless of how much the seller is overpaid
  const fee = gateFee(amount);
  // seller massively overpaid, but treasury short by 1 -> still rejected
  const bad = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount: amount * 100n },
      { index: 2, owner: TREASURY, mint: USDC, amount: fee - 1n },
    ],
  });
  assert.equal((await verify(bad, amount.toString(), seller)).confirmed, false);
  // exact fee on the charge -> accepted
  const ok = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount: amount * 100n },
      { index: 2, owner: TREASURY, mint: USDC, amount: fee },
    ],
  });
  assert.equal((await verify(ok, amount.toString(), seller)).confirmed, true);
});

// ---------------------------------------------------------------------------
// 4. existing protections still hold alongside the new fee leg
// ---------------------------------------------------------------------------
test("gate still REJECTS a short seller leg (even with the fee paid)", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n;
  const tx = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount: amount / 2n }, // underpaid seller
      { index: 2, owner: TREASURY, mint: USDC, amount: gateFee(amount) },
    ],
  });
  const r = await verify(tx, amount.toString(), seller);
  assert.equal(r.confirmed, false);
  assert.match(r.reason ?? "", /payment short or absent/);
});

test("gate still REJECTS a memo-only free-ride (no transfers at all)", async () => {
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n;
  const tx = fakeTx({ memos: [MEMO], balances: [] });
  const r = await verify(tx, amount.toString(), seller);
  assert.equal(r.confirmed, false);
  assert.match(r.reason ?? "", /payment short or absent/);
});

// ---------------------------------------------------------------------------
// 5. END TO END: a greedy seller advertises no fee, but buyer pays it and gate
//    requires it — and a buyer who strips the fee leg is refused service
// ---------------------------------------------------------------------------
test("greedy seller can't bypass: buyer-built tx satisfies the gate; stripped fee fails", async () => {
  const payer = Keypair.generate().publicKey.toBase58();
  const seller = Keypair.generate().publicKey.toBase58();
  const amount = 50_000n;
  const fee = gateFee(amount);

  // seller's challenge claims a 0% fee
  const p = await buildUnsignedPayment(buildConn, payer, {
    scheme: "exact", network: "solana-devnet", maxAmountRequired: amount.toString(),
    resource: "/premium", description: "x", memoPrefix: MEMO_PREFIX, payTo: seller, asset: USDC,
    extra: { platformFeePct: 0 },
  });
  // the buyer's tx still pays both legs -> mirror its settlement -> gate accepts
  const legs = transferLegs(p);
  const mint = new PublicKey(USDC);
  const sellerAta = getAssociatedTokenAddressSync(mint, new PublicKey(seller)).toBase58();
  const treasuryAta = getAssociatedTokenAddressSync(mint, new PublicKey(TREASURY)).toBase58();
  const sellerPaid = legs.find((l) => l.dest === sellerAta)!.amount;
  const feePaid = legs.find((l) => l.dest === treasuryAta)!.amount;
  assert.equal(feePaid, fee, "buyer paid the pinned fee even though the challenge said 0");

  const settled = fakeTx({
    memos: [MEMO],
    balances: [
      { index: 1, owner: seller, mint: USDC, amount: sellerPaid },
      { index: 2, owner: TREASURY, mint: USDC, amount: feePaid },
    ],
  });
  assert.equal((await verify(settled, amount.toString(), seller)).confirmed, true);

  // a greedy buyer who drops the fee leg is refused service
  const stripped = fakeTx({
    memos: [MEMO],
    balances: [{ index: 1, owner: seller, mint: USDC, amount: sellerPaid }],
  });
  assert.equal((await verify(stripped, amount.toString(), seller)).confirmed, false);
});
