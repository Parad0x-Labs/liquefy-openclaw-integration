/**
 * On-chain settlement confirmation for revenue-grade gating.
 *
 * Structural verification (gate.ts) only proves the caller submitted a
 * well-formed proof bound to the resource and amount. Before serving anything
 * valuable, this confirms the payment ACTUALLY SETTLED — and proves it from the
 * transaction itself, not from a memo the caller could forge:
 *
 *   1. The signature resolves to a FINALIZED, successful transaction (finalized,
 *      not just confirmed, so it can't be rolled back after you've served).
 *   2. The recipient's token balance for the expected mint went UP by at least
 *      the required amount (the real proof that money moved).
 *   3. The transaction's memo carries the unique receipt hash, binding the
 *      payment to THIS charge (payer + recipient + amount + resource + nonce),
 *      so a payment for one resource can't be presented for another.
 *
 * REPLAY: this verifier is stateless. To stop a buyer reusing one real payment
 * for repeated access, the integrator MUST record consumed signatures (or the
 * returned receiptHash) and reject repeats. Issue a unique `nullifierSeed` per
 * challenge so each receiptHash is single-use.
 *
 * Isolated here so gate.ts stays network-free. Uses @solana/web3.js only.
 */

import type { Connection } from "@solana/web3.js";

export interface OnChainExpect {
  /** unique receipt hash for this charge (must appear in the tx memo) */
  receiptHash: string;
  /** recipient wallet — owner of the USDC token account that must be credited */
  payTo: string;
  /** expected token mint (USDC for the network) */
  asset: string;
  /** required amount in atomic units (string, e.g. "50000" = 0.05 USDC) */
  amountAtomic: string;
}

export interface OnChainResult {
  confirmed: boolean;
  reason?: string;
  slot?: number;
  /** atomic units actually credited to the recipient (for logging/receipts) */
  receivedAtomic?: string;
}

type TokenBal = {
  accountIndex: number;
  mint: string;
  owner?: string;
  uiTokenAmount?: { amount?: string };
};

/** Net change in `owner`'s total balance of `mint`, in atomic units, summed
 *  across ALL of the owner's token accounts for that mint in the tx (a recipient
 *  may hold more than one). Each post entry is paired to its own accountIndex pre
 *  entry; a freshly created account has no pre-balance, correctly treated as 0. */
function recipientDelta(
  pre: TokenBal[],
  post: TokenBal[],
  owner: string,
  mint: string,
): bigint {
  let delta = 0n;
  for (const p of post) {
    if (p.owner !== owner || p.mint !== mint) continue;
    const preEntry = pre.find((b) => b.accountIndex === p.accountIndex);
    const postAmt = BigInt(p.uiTokenAmount?.amount ?? "0");
    const preAmt = preEntry ? BigInt(preEntry.uiTokenAmount?.amount ?? "0") : 0n;
    delta += postAmt - preAmt;
  }
  return delta;
}

export async function confirmOnChain(
  connection: Connection,
  signature: string,
  expect: OnChainExpect,
): Promise<OnChainResult> {
  if (!signature) return { confirmed: false, reason: "no signature provided" };

  let required: bigint;
  try {
    required = BigInt(expect.amountAtomic);
  } catch {
    return { confirmed: false, reason: "invalid expected amount" };
  }
  if (required <= 0n) return { confirmed: false, reason: "expected amount must be > 0" };

  let tx;
  try {
    tx = await connection.getTransaction(signature, {
      maxSupportedTransactionVersion: 0,
      commitment: "finalized", // reorg-safe: only serve what can't be rolled back
    });
  } catch (e) {
    return { confirmed: false, reason: `RPC error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!tx) return { confirmed: false, reason: "transaction not finalized yet (or not found)" };
  if (tx.meta?.err) {
    return { confirmed: false, reason: `transaction failed on-chain: ${JSON.stringify(tx.meta.err)}` };
  }

  // (1) Bind to THIS charge — the unique receipt hash must be in the memo.
  const logs = tx.meta?.logMessages?.join("\n") ?? "";
  if (!logs.includes(expect.receiptHash)) {
    return { confirmed: false, reason: "memo missing the expected receipt hash (payment not bound to this charge)" };
  }

  // (2) Prove money actually moved — the recipient's token balance for the
  //     expected mint must have increased by at least the required amount. A
  //     memo alone is forgeable from public values; the balance delta is not.
  const pre = (tx.meta?.preTokenBalances ?? []) as TokenBal[];
  const post = (tx.meta?.postTokenBalances ?? []) as TokenBal[];
  const delta = recipientDelta(pre, post, expect.payTo, expect.asset);
  if (delta < required) {
    return {
      confirmed: false,
      reason: `payment short or absent: recipient credited ${delta} of required ${required} (mint ${expect.asset})`,
      receivedAtomic: delta.toString(),
    };
  }

  return { confirmed: true, slot: tx.slot, receivedAtomic: delta.toString() };
}
