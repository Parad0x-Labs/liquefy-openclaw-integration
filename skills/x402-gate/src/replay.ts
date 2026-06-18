/**
 * Replay protection for x402-gate.
 *
 * The gate verifies a payment SETTLED, but a stateless verifier cannot stop a
 * buyer from presenting the SAME settled payment again for repeated access. The
 * seller must record consumed payments and reject repeats. Dedupe on the
 * transaction signature (globally unique) — or, if you issue a unique
 * nullifierSeed per challenge, on the receiptHash.
 *
 * The x402_verify tool uses InMemoryReplayStore by default (config.dedupe).
 * That is fine for a single process but is LOST ON RESTART and NOT shared across
 * instances — for multi-instance or restart-safe deployments, implement
 * ReplayStore over a durable backend (Redis/DB) and use ReplayGuard in your own
 * server code with config.dedupe=false on the tool.
 */

import { existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export interface ReplayStore {
  /** Record `key`. Returns true if newly recorded (allow), false if already seen (reject). */
  consume(key: string): boolean | Promise<boolean>;
}

/** In-process store with FIFO eviction so it can't grow unbounded. Eviction
 *  means a very old signature could theoretically be replayed after maxEntries
 *  newer ones — use a durable store to remove that window. */
export class InMemoryReplayStore implements ReplayStore {
  private seen = new Set<string>();
  constructor(private maxEntries = 100_000) {}
  consume(key: string): boolean {
    if (!key) return false;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    if (this.seen.size > this.maxEntries) {
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    return true;
  }
}

/** Durable single-instance store: consumed keys are appended to a file and
 *  reloaded on startup, so a restart does not reopen replay. For MULTI-instance
 *  deployments implement ReplayStore over a shared backend (Redis SETNX / a DB
 *  unique constraint) instead. No eviction — a consumed payment stays consumed. */
export class FileReplayStore implements ReplayStore {
  private seen = new Set<string>();
  constructor(private path: string) {
    if (existsSync(path)) {
      for (const line of readFileSync(path, "utf8").split("\n")) {
        const k = line.trim();
        if (k) this.seen.add(k);
      }
    } else {
      mkdirSync(dirname(path), { recursive: true });
    }
  }
  consume(key: string): boolean {
    if (!key || this.seen.has(key)) return false;
    this.seen.add(key);
    appendFileSync(this.path, key + "\n");
    return true;
  }
}

/** Wraps any ReplayStore. `use(key)` returns false if the payment was already used. */
export class ReplayGuard {
  constructor(private store: ReplayStore = new InMemoryReplayStore()) {}
  async use(key: string): Promise<boolean> {
    if (!key) return false;
    return await this.store.consume(key);
  }
}
