/**
 * Optional on-chain confirmation for revenue-grade gating.
 *
 * Structural verification (gate.ts) only proves the caller submitted a
 * well-formed proof bound to the resource and amount. Before serving anything
 * valuable, confirm the payment actually SETTLED: the signature resolves to a
 * confirmed, successful transaction whose memo carries the unique receipt hash
 * (which is bound to payer + recipient + amount + resource + nonce, so it can't
 * be replayed against a different charge).
 *
 * Isolated here so gate.ts stays network-free. Uses @solana/web3.js only.
 */

import type { Connection } from "@solana/web3.js";

export interface OnChainResult {
  confirmed: boolean;
  reason?: string;
  slot?: number;
}

export async function confirmOnChain(
  connection: Connection,
  signature: string,
  expect: { receiptHash: string },
): Promise<OnChainResult> {
  if (!signature) return { confirmed: false, reason: "no signature provided" };

  let tx;
  try {
    tx = await connection.getTransaction(signature, {
      maxSupportedTransactionVersion: 0,
      commitment: "confirmed",
    });
  } catch (e) {
    return { confirmed: false, reason: `RPC error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!tx) return { confirmed: false, reason: "transaction not found or not yet confirmed" };
  if (tx.meta?.err) {
    return { confirmed: false, reason: `transaction failed on-chain: ${JSON.stringify(tx.meta.err)}` };
  }

  // The memo carries `${memoPrefix}:${receiptHash}`. The receipt hash is unique
  // per payment, so its presence in the confirmed tx proves THIS charge settled.
  const logs = tx.meta?.logMessages?.join("\n") ?? "";
  if (!logs.includes(expect.receiptHash)) {
    return {
      confirmed: false,
      reason: "confirmed transaction does not carry the expected receipt hash (memo mismatch)",
    };
  }

  return { confirmed: true, slot: tx.slot };
}
