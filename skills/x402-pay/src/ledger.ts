/**
 * Durable spend ledger for x402-pay.
 *
 * The cumulative spend cap, the cross-call double-pay guard (pending payments),
 * and the distinct-recipient cap are real-money safety state. Kept only in memory
 * they reset on every restart / crash / serverless cold start — which can re-arm
 * the caps and, worse, lose a 'pending' signature so a retry pays a SECOND time
 * for already-paid content. Backing them with a file (spendLedgerPath) makes them
 * survive restarts. On mainnet the skill REQUIRES a path (see client.ts).
 *
 * Crash-safety: every write is atomic — serialized to `${path}.tmp`, fsync'd, then
 * renamed over the real file (atomic on the same filesystem) — so a crash/OOM mid
 * write can never truncate the ledger. And a present-but-unparseable ledger is
 * FAIL-CLOSED (the constructor throws): we refuse to pay rather than silently reset
 * money-state to zero (which would re-open the very double-pay it exists to prevent).
 *
 * Single-process: writes are synchronous whole-state replacements. For a
 * multi-process payer fleet, supply a shared store via a host hook instead.
 */

import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync, openSync, fsyncSync, closeSync } from "node:fs";
import { dirname } from "node:path";

/** A pending (broadcast-but-unredeemed) payment: its signature plus the block
 *  height past which its blockhash is dead — so a re-check can tell "still in
 *  flight" (keep pending) from "can never land" (safe to clear and re-pay). */
interface PendingPayment {
  sig: string;
  lvbh: number;
}

interface LedgerState {
  totalSpentUsdc: number;
  pending: Record<string, PendingPayment>;
  recipients: string[]; // distinct payTo addresses funded
}

export interface PendingInfo {
  signature: string;
  lastValidBlockHeight: number;
}

export class SpendLedger {
  private state: LedgerState = { totalSpentUsdc: 0, pending: {}, recipients: [] };
  private recipientSet = new Set<string>();

  constructor(private path?: string) {
    if (path && existsSync(path)) {
      const raw = readFileSync(path, "utf8");
      let loaded: Partial<LedgerState>;
      try {
        loaded = JSON.parse(raw) as Partial<LedgerState>;
      } catch {
        // FAIL CLOSED: a present-but-corrupt ledger means we cannot trust the spend
        // cap or the pending double-pay markers. Refuse rather than silently zero
        // money-state (which would re-pay already-paid content). The operator must
        // reconcile any pending tx on-chain, then repair/remove the file.
        throw new Error(
          `x402: spend ledger ${path} is present but unparseable — refusing to pay. ` +
            `Reconcile any pending payment on-chain, then repair or remove the file.`,
        );
      }
      const pending: Record<string, PendingPayment> = {};
      if (loaded.pending && typeof loaded.pending === "object") {
        for (const [k, v] of Object.entries(loaded.pending)) {
          // Tolerate the older string-only shape (sig with no height) by treating it
          // as already past its window (lvbh 0) — it still triggers an on-chain recheck.
          if (typeof v === "string") pending[k] = { sig: v, lvbh: 0 };
          else if (v && typeof v === "object" && typeof (v as PendingPayment).sig === "string") {
            pending[k] = {
              sig: (v as PendingPayment).sig,
              lvbh: Number.isFinite((v as PendingPayment).lvbh) ? (v as PendingPayment).lvbh : 0,
            };
          }
        }
      }
      this.state = {
        totalSpentUsdc:
          typeof loaded.totalSpentUsdc === "number" && Number.isFinite(loaded.totalSpentUsdc)
            ? loaded.totalSpentUsdc
            : 0,
        pending,
        recipients: Array.isArray(loaded.recipients)
          ? loaded.recipients.filter((x): x is string => typeof x === "string")
          : [],
      };
    } else if (path) {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.recipientSet = new Set(this.state.recipients);
  }

  get durable(): boolean {
    return !!this.path;
  }

  /** Atomic, durable write: temp file -> fsync -> rename over the real file. */
  private persist(): void {
    if (!this.path) return;
    const tmp = `${this.path}.tmp`;
    const fd = openSync(tmp, "w");
    try {
      writeFileSync(fd, JSON.stringify(this.state));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
  }

  totalSpent(): number {
    return this.state.totalSpentUsdc;
  }
  addSpend(usdc: number): void {
    this.state.totalSpentUsdc += usdc;
    this.persist();
  }

  /**
   * Write-ahead record of a payment about to be broadcast: persist the pending
   * (recheck) marker + its blockhash window, count the spend toward the cumulative
   * cap, and record the recipient — all in ONE atomic durable write, BEFORE the tx
   * reaches the network. So a crash/throw during broadcast can never lose the
   * signature (double-pay) and the caps can never be re-armed by a restart mid
   * flight. Counting the spend here is conservative: over-counts only if the tx
   * never lands (the safe direction).
   */
  recordBroadcast(ckey: string, signature: string, lastValidBlockHeight: number, usdc: number, payTo: string): void {
    this.state.pending[ckey] = { sig: signature, lvbh: lastValidBlockHeight };
    this.state.totalSpentUsdc += usdc;
    if (!this.recipientSet.has(payTo)) {
      this.recipientSet.add(payTo);
      this.state.recipients.push(payTo);
    }
    this.persist();
  }

  getPending(ckey: string): PendingInfo | undefined {
    const p = this.state.pending[ckey];
    return p ? { signature: p.sig, lastValidBlockHeight: p.lvbh } : undefined;
  }
  clearPending(ckey: string): void {
    if (this.state.pending[ckey] !== undefined) {
      delete this.state.pending[ckey];
      this.persist();
    }
  }

  recipientCount(): number {
    return this.recipientSet.size;
  }
  hasRecipient(payTo: string): boolean {
    return this.recipientSet.has(payTo);
  }
  addRecipient(payTo: string): void {
    if (!this.recipientSet.has(payTo)) {
      this.recipientSet.add(payTo);
      this.state.recipients.push(payTo);
      this.persist();
    }
  }
}
