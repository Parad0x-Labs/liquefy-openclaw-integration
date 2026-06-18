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
      req.memoPrefix,
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
    data: Buffer.from(`${req.memoPrefix}:${receiptHash}`, "utf8"),
  });

  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");

  const tx = new Transaction({
    feePayer: payerPk,
    blockhash,
    lastValidBlockHeight,
  });

  const priorityFee =
    typeof (req.extra as Record<string, unknown> | undefined)?.priorityFeeMicroLamports === "number"
      ? Number((req.extra as Record<string, number>).priorityFeeMicroLamports)
      : DEFAULT_PRIORITY_FEE_MICRO_LAMPORTS;

  tx.add(
    // priority fee + CU cap so the payment lands under mainnet congestion
    ComputeBudgetProgram.setComputeUnitLimit({ units: PAYMENT_COMPUTE_UNIT_LIMIT }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: priorityFee }),
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
  };
}

/**
 * Broadcast an already-signed transaction. Signing happened in the owner's
 * wallet; this only submits the bytes and waits for confirmation.
 */
export async function broadcastSigned(
  connection: Connection,
  signedTxBase64: string,
): Promise<string> {
  const raw = Buffer.from(signedTxBase64, "base64");
  const signature = await connection.sendRawTransaction(raw, {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  await connection.confirmTransaction(signature, "confirmed");
  return signature;
}

/**
 * Full BYO-signer round: build → owner signs → broadcast.
 * Returns the payment signature and receipt hash.
 */
export async function payWithSigner(
  connection: Connection,
  signer: X402Signer,
  req: X402PaymentRequirement,
): Promise<{ signature: string; receiptHash: string; amountUsdc: number }> {
  const unsigned = await buildUnsignedPayment(connection, signer.publicKey, req);
  const signedTxBase64 = await signer.signTransaction(unsigned.txBase64);
  const signature = await broadcastSigned(connection, signedTxBase64);
  return { signature, receiptHash: unsigned.receiptHash, amountUsdc: unsigned.amountUsdc };
}
