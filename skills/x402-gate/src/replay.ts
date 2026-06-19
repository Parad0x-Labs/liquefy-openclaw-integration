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

import { existsSync, readFileSync, appendFileSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
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

/** In-memory, TTL-pruned store for SHORT-LIVED keys whose expiry is embedded as the
 *  first dot-delimited segment of the final colon field — the gate's nonce format
 *  `<expSec>.<rand>.<hmac>` (here keyed as `nonce:<expSec>.<rand>.<hmac>`). Entries
 *  self-expire, so high-rate capability reuse (a fresh nonce per call) can't grow it
 *  without bound, unlike the permanent signature store. In-memory by design: a
 *  nonce's replay window is only its short TTL, and the durable signature store still
 *  prevents re-redeeming a settled PAYMENT across restarts. */
export class TTLReplayStore implements ReplayStore {
  private seen = new Map<string, number>(); // key -> expiry epoch seconds
  private lastSweep = 0;
  consume(key: string): boolean {
    if (!key) return false;
    const now = Math.floor(Date.now() / 1000);
    if (now > this.lastSweep) {
      // amortized prune (at most once per second) so the map can't accumulate dead keys
      for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
      this.lastSweep = now;
    }
    if (this.seen.has(key)) return false;
    const embedded = Number(key.split(":").pop()?.split(".")[0]);
    const exp = Number.isFinite(embedded) && embedded > now ? embedded : now + 600; // fallback TTL
    this.seen.set(key, exp);
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
    this.acquireLock();
  }

  /** Refuse to start if another live process ON THIS HOST already holds the store
   *  path. The file store is not shared across instances, so a second replica would
   *  diverge and let one payment be redeemed per replica. Enforced on a single host
   *  (a shared/network filesystem across hosts is NOT supported — for multi-host use
   *  dedupe=false + your own shared store). A stale lock from a dead pid is taken over. */
  private acquireLock(): void {
    const lockPath = `${this.path}.lock`;
    const pid = String(process.pid);
    try {
      writeFileSync(lockPath, pid, { flag: "wx" });
    } catch {
      let holder = "";
      try {
        holder = readFileSync(lockPath, "utf8").trim();
      } catch {
        /* ignore */
      }
      const oldPid = Number(holder);
      let alive = false;
      if (Number.isInteger(oldPid) && oldPid > 0) {
        try {
          process.kill(oldPid, 0);
          alive = true;
        } catch {
          alive = false;
        }
      }
      if (alive) {
        throw new Error(
          `x402-gate: replay store ${this.path} is held by another running instance (pid ${holder}). ` +
            `FileReplayStore is single-instance — run one instance, or use dedupe=false with your own shared store.`,
        );
      }
      writeFileSync(lockPath, pid); // stale lock (holder dead) — take it over
    }
    process.once("exit", () => {
      try {
        unlinkSync(lockPath);
      } catch {
        /* best effort */
      }
    });
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
