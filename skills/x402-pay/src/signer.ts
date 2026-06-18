/**
 * BYO-signer payment construction.
 *
 * The skill builds a fully-formed but UNSIGNED Solana transaction, hands it to
 * the agent owner's `X402Signer.signTransaction` (a wallet adapter / hardware
 * signer / KMS the owner controls), then broadcasts the returned signed bytes.
 * At no point does this module hold, request, or read a private key.
 *
 * Dependencies: @solana/web3.js + @solana/spl-token (the standard, widely-used
 * Solana libs) and Node's built-in crypto. No @parad0x_labs/* runtime dependency.
 */

import { createHash } from "node:crypto";
import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  createTransferCheckedInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import {
  MEMO_PROGRAM_ID,
  MEMO_PREFIX,
  USDC_DECIMALS,
  atomicToUsdc,
  DEFAULT_PRIORITY_FEE_MICRO_LAMPORTS,
  PAYMENT_COMPUTE_UNIT_LIMIT,
} from "./constants";
import type { X402PaymentRequirement, X402Signer } from "./types";

/** SHA-256 hex of a UTF-8 string */
function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Deterministic receipt hash binding payer, recipient, amount, resource and
 * nonce — the same value gets stamped in the on-chain memo so the payment is
 * auditable later.
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

export interface UnsignedPayment {
  /** base64-serialized unsigned transaction */
  txBase64: string;
  /** SHA-256 receipt hash (hex) */
  receiptHash: string;
  amountUsdc: number;
  payTo: string;
  /** Blockhash + height the tx is bound to — used to confirm within the window. */
  blockhash: string;
  lastValidBlockHeight: number;
}

/**
 * Build the unsigned USDC payment transaction for a 402 requirement.
 * Adds an idempotent destination-ATA create (so paying a fresh recipient does
 * not fail), the checked USDC transfer, and a memo carrying the receipt hash.
 */
export async function buildUnsignedPayment(
  connection: Connection,
  payer: string,
  req: X402PaymentRequirement,
): Promise<UnsignedPayment> {
  const payerPk = new PublicKey(payer);
  const payToPk = new PublicKey(req.payTo);
  const usdcMint = new PublicKey(req.asset);
  const amountAtomic = BigInt(req.maxAmountRequired);

  const payerAta = getAssociatedTokenAddressSync(usdcMint, payerPk);
  const payToAta = getAssociatedTokenAddressSync(usdcMint, payToPk);

  const receiptHash = receiptHashFor(payer, req);

  const memoIx = new TransactionInstruction({
    keys: [],
    programId: new PublicKey(MEMO_PROGRAM_ID),
    data: Buffer.from(`${MEMO_PREFIX}:${receiptHash}`, "utf8"),
  });

  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");

  const tx = new Transaction({
    feePayer: payerPk,
    blockhash,
    lastValidBlockHeight,
  });

  tx.add(
    // priority fee + CU cap so the payment lands under mainnet congestion.
    // Fixed, local value — NEVER read from the (untrusted) 402 challenge, so a
    // malicious server cannot inflate the SOL fee charged to the payer's wallet.
    ComputeBudgetProgram.setComputeUnitLimit({ units: PAYMENT_COMPUTE_UNIT_LIMIT }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: DEFAULT_PRIORITY_FEE_MICRO_LAMPORTS }),
    // idempotent: no-op if the recipient already has a USDC account
    createAssociatedTokenAccountIdempotentInstruction(payerPk, payToAta, payToPk, usdcMint),
    createTransferCheckedInstruction(
      payerAta,
      usdcMint,
      payToAta,
      payerPk,
      amountAtomic,
      USDC_DECIMALS,
    ),
    memoIx,
  );

  const txBase64 = tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64");

  return {
    txBase64,
    receiptHash,
    amountUsdc: atomicToUsdc(Number(amountAtomic)),
    payTo: req.payTo,
    blockhash,
    lastValidBlockHeight,
  };
}

/**
 * Broadcast an already-signed transaction and confirm it within its blockhash
 * window. Confirmation is bound to {blockhash, lastValidBlockHeight} so it fails
 * deterministically on expiry rather than a blind timeout.
 *
 * Idempotency: an on-chain execution error is a CLEAN failure (no funds moved →
 * safe to retry). But an *ambiguous* outcome (the confirm RPC threw/timed out
 * after the tx may already have landed) returns status "pending" WITH the
 * signature — never a clean error — so a naive caller retry can't build and pay a
 * second transaction for the same resource.
 */
export async function broadcastSigned(
  connection: Connection,
  signedTxBase64: string,
  blockhash: string,
  lastValidBlockHeight: number,
): Promise<{ signature: string; status: "confirmed" | "pending" }> {
  const raw = Buffer.from(signedTxBase64, "base64");
  const signature = await connection.sendRawTransaction(raw, {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });

  // Confirm at FINALIZED — same commitment the gate verifies at — so when the
  // payer presents the proof the gate's on-chain check passes on the first try
  // (no confirmed-but-not-yet-finalized window that would reject a real payment).
  let res;
  try {
    res = await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "finalized");
  } catch {
    // Ambiguous (timeout / blockhash window / RPC hiccup): the tx MAY have landed.
    // Re-poll its status before deciding — do not report a clean (retryable) failure.
    const s = (await connection.getSignatureStatus(signature, { searchTransactionHistory: true })).value;
    if (s?.err) throw new Error(`transaction failed on-chain: ${JSON.stringify(s.err)}`);
    if (s?.confirmationStatus === "finalized") return { signature, status: "confirmed" };
    return { signature, status: "pending" };
  }
  if (res.value.err) {
    // Landed but execution failed → no funds moved → safe clean failure.
    throw new Error(`transaction failed on-chain: ${JSON.stringify(res.value.err)}`);
  }
  return { signature, status: "confirmed" };
}

/**
 * Full BYO-signer round: build → owner signs → broadcast.
 * status "pending" means confirmation was ambiguous — the caller MUST surface the
 * signature and must NOT retry-pay without checking it first.
 */
export async function payWithSigner(
  connection: Connection,
  signer: X402Signer,
  req: X402PaymentRequirement,
): Promise<{ signature: string; receiptHash: string; amountUsdc: number; status: "confirmed" | "pending" }> {
  const unsigned = await buildUnsignedPayment(connection, signer.publicKey, req);
  const signedTxBase64 = await signer.signTransaction(unsigned.txBase64);
  const { signature, status } = await broadcastSigned(
    connection,
    signedTxBase64,
    unsigned.blockhash,
    unsigned.lastValidBlockHeight,
  );
  return { signature, receiptHash: unsigned.receiptHash, amountUsdc: unsigned.amountUsdc, status };
}
