/**
 * Replay protection for x402-gate.
 *
 * The gate verifies a payment SETTLED, but a stateless verifier cannot stop a
 * buyer (or an observer of the public proof) from presenting the SAME proof again
 * for repeated access. The seller must record consumed keys and reject repeats.
 *
 * Two kinds of key flow through here:
 *   - tx SIGNATURES (and receiptHashes) — PERMANENT: a settled payment must never
 *     be re-redeemable, so these are kept forever.
 *   - NONCES (`nonce:<expSec>.<rand>.<hmac>`) — SHORT-LIVED: single-use anti-replay
 *     for the presenter-auth bundle (including the capability-reuse path, which has
 *     no on-chain check, so the nonce IS its only replay guard). These expire, so
 *     the store prunes them and stays bounded even under high-rate capability reuse.
 *
 * The durable FileReplayStore keeps both across restarts (mandatory on mainnet);
 * the InMemoryReplayStore is the single-process default for devnet/testing.
 */

import { existsSync, readFileSync, appendFileSync, mkdirSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

export interface ReplayStore {
  /** Record `key`. Returns true if newly recorded (allow), false if already seen (reject). */
  consume(key: string): boolean | Promise<boolean>;
}

/** Expiry (epoch seconds) for a key: a `nonce:`-style key embeds its expiry as the
 *  first dot segment of the final colon field; a bare tx signature has no ':' and is
 *  PERMANENT (Infinity). An unparseable nonce expiry falls back to a short TTL. */
function expiryForKey(key: string, now: number): number {
  if (!key.includes(":")) return Infinity; // tx signature / receiptHash — never expires
  const embedded = Number(key.split(":").pop()?.split(".")[0]);
  return Number.isFinite(embedded) ? embedded : now + 600;
}

/** In-process store. Permanent keys (signatures) are kept; expirable keys (nonces)
 *  are pruned; a FIFO cap bounds total size as an OOM backstop. LOST ON RESTART and
 *  not shared across instances — for restart-safe / mainnet use a durable store. */
export class InMemoryReplayStore implements ReplayStore {
  private seen = new Map<string, number>(); // key -> expiry epoch seconds (Infinity = permanent)
  private lastSweep = 0;
  constructor(private maxEntries = 200_000) {}
  consume(key: string): boolean {
    if (!key) return false;
    const now = Math.floor(Date.now() / 1000);
    if (now > this.lastSweep) {
      for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
      this.lastSweep = now;
    }
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) return false; // already seen, still live
    const exp = expiryForKey(key, now);
    if (exp <= now) return false; // refuse an already-expired nonce (defensive)
    this.seen.set(key, exp);
    if (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    return true;
  }
}

/** Durable single-instance store: consumed keys (+ expiry) are appended to a file
 *  and reloaded on startup, so a restart does NOT reopen replay — including for the
 *  capability-reuse nonce, whose only guard is single-use. Self-COMPACTS: expired
 *  nonces are dropped on load and periodically (atomic temp+rename), so high-rate
 *  capability reuse can't grow the file without bound; signatures are kept forever.
 *  For MULTI-instance deployments use a shared backend (Redis/DB) + dedupe=false. */
export class FileReplayStore implements ReplayStore {
  private seen = new Map<string, number>();
  private sinceCompact = 0;
  private lockPath: string;
  private onExit?: () => void;
  constructor(private path: string, private compactEvery = 5_000) {
    this.lockPath = `${path}.lock`;
    if (existsSync(path)) {
      const now = Math.floor(Date.now() / 1000);
      for (const line of readFileSync(path, "utf8").split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const tab = t.indexOf("\t");
        const k = tab === -1 ? t : t.slice(0, tab);
        const e = tab === -1 ? "" : t.slice(tab + 1);
        const exp = e === "" ? expiryForKey(k, now) : Number(e);
        if (!Number.isFinite(exp) || exp > now) this.seen.set(k, Number.isFinite(exp) ? exp : Infinity); // drop expired on load
      }
    } else {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.acquireLock();
    this.compact(); // normalize format + drop anything expired from a prior run
  }

  /** Refuse to start if another live process ON THIS HOST already holds the store
   *  path. The file store is not shared across instances, so a second replica would
   *  diverge and let one payment be redeemed per replica. A stale lock from a dead
   *  pid is taken over. (Multi-host needs dedupe=false + your own shared store.) */
  private acquireLock(): void {
    const pid = String(process.pid);
    try {
      writeFileSync(this.lockPath, pid, { flag: "wx" });
    } catch {
      let holder = "";
      try {
        holder = readFileSync(this.lockPath, "utf8").trim();
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
      writeFileSync(this.lockPath, pid); // stale lock (holder dead) — take it over
    }
    this.onExit = () => {
      try {
        unlinkSync(this.lockPath);
      } catch {
        /* best effort */
      }
    };
    process.once("exit", this.onExit);
  }

  /** Release the single-instance lock (for a graceful shutdown / handoff). */
  close(): void {
    if (this.onExit) {
      process.removeListener("exit", this.onExit);
      this.onExit();
      this.onExit = undefined;
    }
  }

  consume(key: string): boolean {
    if (!key) return false;
    const now = Math.floor(Date.now() / 1000);
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) return false; // already seen, still live
    const exp = expiryForKey(key, now);
    if (exp <= now) return false; // refuse an already-expired nonce (defensive)
    this.seen.set(key, exp);
    appendFileSync(this.path, `${key}\t${exp === Infinity ? "" : exp}\n`);
    if (++this.sinceCompact >= this.compactEvery) this.compact();
    return true;
  }

  /** Rewrite the file dropping expired nonces (signatures kept forever), atomically. */
  private compact(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, exp] of this.seen) if (exp !== Infinity && exp <= now) this.seen.delete(k);
    const data = [...this.seen].map(([k, exp]) => `${k}\t${exp === Infinity ? "" : exp}\n`).join("");
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, data);
    renameSync(tmp, this.path);
    this.sinceCompact = 0;
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
