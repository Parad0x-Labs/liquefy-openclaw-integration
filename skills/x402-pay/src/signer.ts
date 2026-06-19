/**
 * BYO-signer payment construction.
 *
 * The skill builds a fully-formed but UNSIGNED Solana transaction, hands it to
 * the agent owner's `X402Signer.signTransaction` (a wallet adapter / hardware
 * signer / KMS the owner controls), then broadcasts the returned signed bytes.
 * At no point does this module hold, request, or read a private key.
 *
 * Dependencies: @solana/web3.js + bs58 (both pure-JS, widely used) and Node's
 * built-in crypto. The three SPL Token instruction builders are vendored in
 * ./spl (byte-identical to @solana/spl-token, proven in the wire tests) so the
 * package does not pull the unmaintained native bigint-buffer addon. No
 * @parad0x_labs/* runtime dependency.
 */

import { createHash } from "node:crypto";
import bs58 from "bs58";
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
} from "./spl";
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
 *
 * ⚠️ UNGUARDED low-level builder. It does NOT enforce the spend cap, mainnet
 * opt-in, USDC-only asset, recipient allowlist, or distinct-recipient cap — all of
 * those live in selectRequirement()/fetchWithX402(). It also assumes USDC's 6
 * decimals for the (unchecked) req.asset. Drive payments through fetchWithX402; use
 * this directly only if you re-assert those invariants yourself first.
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
  // The vendored deriver always allows an off-curve owner, so a PDA /
  // Squads-multisig recipient is payable (the ATA address is the same either way).
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
 * The transaction signature (base58) derived LOCALLY from already-signed bytes —
 * the fee-payer's signature, which is exactly what the cluster will index this tx
 * under. Computing it from the bytes (not from sendRawTransaction's return value)
 * means the caller knows the signature BEFORE broadcast, so it can persist a
 * recheck marker write-ahead and never lose the signature if the send call throws
 * after the tx has already reached the cluster.
 */
export function signatureOf(signedTxBase64: string): string {
  const tx = Transaction.from(Buffer.from(signedTxBase64, "base64"));
  if (!tx.signature) throw new Error("signed transaction has no signature");
  return bs58.encode(tx.signature);
}

/**
 * Broadcast an already-signed transaction (whose `signature` was derived locally
 * up front) and confirm it within its blockhash window.
 *
 * Idempotency: an on-chain execution error is a CLEAN failure (no funds moved →
 * safe to retry). Any *ambiguous* outcome — the send OR the confirm threw/timed
 * out after the tx may already have landed — returns status "pending" WITH the
 * signature, never a clean error, so a naive caller retry can't build and pay a
 * second transaction for the same resource. Both the send path and the confirm
 * path re-poll getSignatureStatus before deciding.
 */
export async function broadcastSigned(
  connection: Connection,
  signedTxBase64: string,
  signature: string,
  blockhash: string,
  lastValidBlockHeight: number,
): Promise<{ signature: string; status: "confirmed" | "pending" }> {
  const raw = Buffer.from(signedTxBase64, "base64");

  // Decide an outcome from the (locally known) signature's on-chain status.
  // err -> throw (clean: failed tx moved no funds); finalized -> confirmed;
  // seen-but-not-final -> pending; not-seen-at-all -> the caller's `notSeen` choice.
  const decideFromStatus = async (
    notSeen: "throw" | "pending",
    cause?: unknown,
  ): Promise<{ signature: string; status: "confirmed" | "pending" }> => {
    const s = (await connection.getSignatureStatus(signature, { searchTransactionHistory: true })).value;
    if (s?.err) throw new Error(`transaction failed on-chain: ${JSON.stringify(s.err)}`);
    if (s?.confirmationStatus === "finalized") return { signature, status: "confirmed" };
    if (s) return { signature, status: "pending" };
    if (notSeen === "pending") return { signature, status: "pending" };
    throw cause instanceof Error ? cause : new Error(String(cause));
  };

  try {
    await connection.sendRawTransaction(raw, { skipPreflight: false, preflightCommitment: "confirmed" });
  } catch (e) {
    // The send may have reached the cluster before the error surfaced (RPC 503 /
    // timeout / socket reset under congestion). Do NOT report a clean failure — the
    // tx may be landing. If it isn't visible at all, surface "pending" anyway
    // (not a clean error): the write-ahead marker is already persisted, so a later
    // re-check reconciles it. Favor never-double-pay over a possibly-premature retry.
    return await decideFromStatus("pending", e);
  }

  // Confirm at FINALIZED — same commitment the gate verifies at — so when the payer
  // presents the proof the gate's on-chain check passes on the first try.
  let res;
  try {
    res = await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "finalized");
  } catch (e) {
    return await decideFromStatus("pending", e);
  }
  if (res.value.err) {
    // Landed but execution failed → no funds moved → safe clean failure.
    throw new Error(`transaction failed on-chain: ${JSON.stringify(res.value.err)}`);
  }
  return { signature, status: "confirmed" };
}

/**
 * Full BYO-signer round: build → owner signs → (write-ahead hook) → broadcast.
 *
 * `onBeforeBroadcast` is invoked with the locally-derived signature and the tx's
 * lastValidBlockHeight AFTER signing but BEFORE the tx is handed to the network, so
 * the caller can durably persist a recheck marker first. Invariant: once a signed
 * tx reaches sendRawTransaction, a marker that re-checks this signature is already
 * persisted — so a throw or crash during broadcast can never lose the signature and
 * let a retry pay twice.
 *
 * status "pending" means confirmation was ambiguous — the caller MUST surface the
 * signature and must NOT retry-pay without checking it first.
 */
export async function payWithSigner(
  connection: Connection,
  signer: X402Signer,
  req: X402PaymentRequirement,
  onBeforeBroadcast?: (signature: string, lastValidBlockHeight: number) => void | Promise<void>,
): Promise<{ signature: string; receiptHash: string; amountUsdc: number; status: "confirmed" | "pending" }> {
  const unsigned = await buildUnsignedPayment(connection, signer.publicKey, req);
  const signedTxBase64 = await signer.signTransaction(unsigned.txBase64);
  const signature = signatureOf(signedTxBase64); // known before any network send
  if (onBeforeBroadcast) await onBeforeBroadcast(signature, unsigned.lastValidBlockHeight);
  const { status } = await broadcastSigned(
    connection,
    signedTxBase64,
    signature,
    unsigned.blockhash,
    unsigned.lastValidBlockHeight,
  );
  return { signature, receiptHash: unsigned.receiptHash, amountUsdc: unsigned.amountUsdc, status };
}
