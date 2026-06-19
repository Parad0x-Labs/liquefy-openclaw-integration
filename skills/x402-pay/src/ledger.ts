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
 * Single-process: writes are synchronous appends of the whole small state. For a
 * multi-process payer fleet, supply a shared store via a host hook instead.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

interface LedgerState {
  totalSpentUsdc: number;
  pending: Record<string, string>; // ckey -> signature of an unconfirmed/unredeemed payment
  recipients: string[]; // distinct payTo addresses funded
}

export class SpendLedger {
  private state: LedgerState = { totalSpentUsdc: 0, pending: {}, recipients: [] };
  private recipientSet = new Set<string>();

  constructor(private path?: string) {
    if (path && existsSync(path)) {
      try {
        const loaded = JSON.parse(readFileSync(path, "utf8")) as Partial<LedgerState>;
        this.state = {
          totalSpentUsdc:
            typeof loaded.totalSpentUsdc === "number" && Number.isFinite(loaded.totalSpentUsdc)
              ? loaded.totalSpentUsdc
              : 0,
          pending: loaded.pending && typeof loaded.pending === "object" ? loaded.pending : {},
          recipients: Array.isArray(loaded.recipients)
            ? loaded.recipients.filter((x): x is string => typeof x === "string")
            : [],
        };
      } catch {
        /* corrupt ledger — start fresh rather than crash the payer */
      }
    } else if (path) {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.recipientSet = new Set(this.state.recipients);
  }

  get durable(): boolean {
    return !!this.path;
  }

  private persist(): void {
    if (this.path) {
      try {
        writeFileSync(this.path, JSON.stringify(this.state));
      } catch {
        /* best effort */
      }
    }
  }

  totalSpent(): number {
    return this.state.totalSpentUsdc;
  }
  addSpend(usdc: number): void {
    this.state.totalSpentUsdc += usdc;
    this.persist();
  }

  getPending(ckey: string): string | undefined {
    return this.state.pending[ckey];
  }
  setPending(ckey: string, signature: string): void {
    this.state.pending[ckey] = signature;
    this.persist();
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
