/**
 * x402-pay — private reputation prover ("zk-rep" agent side).
 *
 * The companion to x402-gate's `verifyReputationProof`. An agent uses this to PROVE a
 * private track record — "I hold >= min_count settled receipts totalling >= min_volume
 * since window_start, in an anchored receipt Merkle tree" — with a Groth16 proof over
 * track_record.circom (BN254), revealing NO individual amount, counterparty, or wallet.
 * The gate verifies the result off-chain and learns only the aggregate bars, a single-use
 * nullifier, and the agent commitment.
 *
 * Circuit contract — track_record.circom, TrackRecord(K=4, depth=10), nPublic=6:
 *   agent_commitment    === Poseidon(secret, agent_id)
 *   reputation_nullifier === Poseidon(DOMAIN_REP=7, secret, epoch)
 *   for each of K receipts:
 *     leaf  = Poseidon(agent_commitment, amount, timestamp, counterparty, receipt_nonce)
 *     leaf  is a member of the depth-10 tree rooted at `root` (path_index 0 = leaf on left)
 *     leaf_index === the integer formed by the path_index bits
 *     timestamp >= window_start
 *   leaf_index is STRICTLY INCREASING across receipts (distinctness — no double-count)
 *   min_count <= K   and   sum(amount) >= min_volume
 * Public-signal output order:
 *   [root, min_count, min_volume, window_start, reputation_nullifier, agent_commitment]
 *
 * SECRET HYGIENE — the agent's reputation secret is a long-lived private key:
 *   - It is registered as a LIVE CAPABILITY (setReputationKey), never serialized into JSON
 *     config — mirroring this skill's BYO-signer model.
 *   - It is never logged, never echoed in an error, and never present in any return value.
 *     Only public values (proof, the 6 public signals, agent_commitment, nullifier) leave.
 *
 * TRUST GATES — stated plainly, never overclaimed:
 *   - The proving key (track_record_final.zkey) is a single-party development setup. A
 *     multi-party ceremony is required before this is mainnet trust on its own.
 *   - The proving artifacts (wasm ~2.9M, zkey ~11M) are NOT bundled in this package. Host
 *     them (e.g. on Arweave via web0) and pass their path/URL — that hosting step is the
 *     deployment gate. The verifier embeds only the 3.8K verification key.
 *   - ROOT TRUST is the load-bearing seam: a proof is only meaningful against a root the
 *     VERIFIER trusts (an anchored receipt_anchor root). The prover builds against whatever
 *     root it is handed; binding that root to an anchored source is the gate's job.
 *   - This is v1 (devnet-POC ptau): exactly K=4 receipts, depth-10 tree. Production scales
 *     to K=16 / depth-20 with a larger ceremony.
 */

import * as snarkjs from "snarkjs";
import { poseidon2, poseidon3, poseidon5 } from "poseidon-lite";

/** BN254 scalar field modulus r. Every witness value must be a canonical element of [0, r). */
export const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Reputation nullifier domain separator — must match the circuit's `var DOMAIN_REP`. */
export const DOMAIN_REP = 7n;

/** v1 circuit parameters (track_record.circom `component main = TrackRecord(4, 10)`). */
export const K = 4;
export const DEPTH = 10;

/** Upper bound for values the circuit feeds into a 64-bit comparator. track_record.circom
 *  compares timestamp/window_start and the amount sum with GreaterEqThan(64); a circomlib
 *  64-bit comparator is only sound for inputs in [0, 2^64). A larger value makes witness
 *  generation abort opaquely, so the prover rejects it here with a clean, value-free error
 *  (NOTE: this is the prover's fail-fast contract — the load-bearing soundness guard for a
 *  HOSTILE prover is a RangeCheck64 in the circuit itself, which is a re-ceremony item). */
const MAX_UINT64 = 1n << 64n;
function requireUint64(v: bigint, label: string): bigint {
  if (v >= MAX_UINT64) {
    throw new Error(`x402-rep: ${label} must be < 2^64 (it feeds a 64-bit circuit comparator)`);
  }
  return v;
}

export type FieldLike = bigint | string | number;

/** Coerce a value to a canonical in-field bigint, or throw a precise error. Used on EVERY
 *  caller-supplied number so a malformed witness fails fast and clearly here, instead of as
 *  an opaque "Assert Failed" deep inside the circuit. */
function toFr(v: FieldLike, label: string): bigint {
  let b: bigint;
  try {
    b = typeof v === "bigint" ? v : BigInt(typeof v === "number" ? Math.trunc(v) : String(v).trim());
  } catch {
    return badField(label);
  }
  if (b < 0n || b >= FIELD_MODULUS) return badField(label);
  return b;
}
function badField(label: string): never {
  // Note the LABEL only — never the value (it may be the secret or a private amount).
  throw new Error(`x402-rep: ${label} is not a canonical BN254 field element`);
}

/** Cryptographically-random field element (CSPRNG, never Math.random). Works in Node 22+
 *  and browsers via Web Crypto. Used for receipt nonces and demo identities. */
export function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let acc = 0n;
  for (const byte of bytes) acc = (acc << 8n) | BigInt(byte);
  return acc % FIELD_MODULUS;
}

// ── Reputation-key registration (a secret is a live capability, never serialized config) ──

let registeredKey: { secret: string; agentId: string } | null = null;

/** Register the agent's PRIVATE reputation key (secret, agent_id). Both are canonicalized to
 *  in-field BN254 elements — junk is rejected here, not deep inside the circuit. The secret
 *  is held only in this module; only the public agent_commitment and proofs ever leave. */
export function setReputationKey(key: { secret: FieldLike; agentId: FieldLike }): void {
  registeredKey = {
    secret: toFr(key.secret, "secret").toString(),
    agentId: toFr(key.agentId, "agentId").toString(),
  };
}

/** The registered reputation key — INCLUDING the secret — or null if none set. For trusted
 *  in-process callers only (the plugin's own tools, which feed it straight into proving).
 *  Never surface its `secret` in tool output, logs, or errors. */
export function getReputationKey(): { secret: string; agentId: string } | null {
  return registeredKey;
}

// ── Identity + leaf commitments (must match the circuit's Poseidon arities exactly) ──────

/** agent_commitment = Poseidon(secret, agent_id) — the SAME identity the access gate binds. */
export function agentCommitment(secret: FieldLike, agentId: FieldLike): string {
  return poseidon2([toFr(secret, "secret"), toFr(agentId, "agentId")]).toString();
}

/** reputation_nullifier = Poseidon(DOMAIN_REP, secret, epoch) — single-use per (secret, epoch). */
export function reputationNullifier(secret: FieldLike, epoch: FieldLike): string {
  return poseidon3([DOMAIN_REP, toFr(secret, "secret"), toFr(epoch, "epoch")]).toString();
}

/** leaf = Poseidon(agent_commitment, amount, timestamp, counterparty, receipt_nonce). */
export function receiptLeaf(args: {
  agentCommitment: FieldLike;
  amount: FieldLike;
  timestamp: FieldLike;
  counterparty: FieldLike;
  nonce: FieldLike;
}): string {
  return poseidon5([
    toFr(args.agentCommitment, "agentCommitment"),
    toFr(args.amount, "amount"),
    toFr(args.timestamp, "timestamp"),
    toFr(args.counterparty, "counterparty"),
    toFr(args.nonce, "receipt_nonce"),
  ]).toString();
}

// ── Merkle tree (depth-10, empty slots = literal 0n, matching the circuit) ───────────────

/**
 * Build the depth-`depth` Poseidon tree from sparse leaf placements (empty slots are 0n,
 * exactly as the circuit treats absent leaves). Returns levels[0..depth]; the root is
 * tree[depth][0]. Only for the LOCAL-TREE convenience path (the agent holds the full leaf
 * set, e.g. its own receipt-dag). depth-10 = 1024 slots; for production depth-20 use an
 * indexer that supplies inclusion paths directly via proveReputation().
 */
export function buildSparseTree(entries: Array<{ index: number; leaf: FieldLike }>, depth = DEPTH): bigint[][] {
  if (!Number.isInteger(depth) || depth < 1 || depth > 16) {
    throw new Error(`x402-rep: buildSparseTree depth must be 1..16 (got ${depth})`);
  }
  const size = 1 << depth;
  let level: bigint[] = new Array(size).fill(0n);
  for (const { index, leaf } of entries) {
    if (!Number.isInteger(index) || index < 0 || index >= size) {
      throw new Error(`x402-rep: leaf index ${index} out of range for depth ${depth}`);
    }
    level[index] = toFr(leaf, "leaf");
  }
  const tree: bigint[][] = [level];
  for (let d = 0; d < depth; d++) {
    const next = new Array<bigint>(level.length >> 1);
    for (let i = 0; i < next.length; i++) next[i] = poseidon2([level[2 * i], level[2 * i + 1]]);
    tree.push(next);
    level = next;
  }
  return tree;
}

/** Inclusion path for `index` from a tree built by buildSparseTree. path_index 0 = leaf-left. */
export function merklePath(tree: bigint[][], index: number, depth = DEPTH): { pathElements: string[]; pathIndex: number[] } {
  const pathElements: string[] = [];
  const pathIndex: number[] = [];
  let i = index;
  for (let d = 0; d < depth; d++) {
    const bit = i & 1;
    pathIndex.push(bit);
    pathElements.push(tree[d][bit ? i - 1 : i + 1].toString());
    i >>= 1;
  }
  return { pathElements, pathIndex };
}

/** Reconstruct a root from a leaf + its inclusion path — used as a PRE-FLIGHT check so a
 *  wrong path/root is caught here (precise error) rather than as a 0.9s circuit abort. */
function reconstructRoot(leaf: bigint, pathElements: bigint[], pathIndex: number[]): bigint {
  let cur = leaf;
  for (let d = 0; d < pathElements.length; d++) {
    const sib = pathElements[d];
    cur = pathIndex[d] === 1 ? poseidon2([sib, cur]) : poseidon2([cur, sib]);
  }
  return cur;
}

// ── Witness-ready prover (production path: paths come from the anchored-tree indexer) ────

/** One receipt with its inclusion proof against the anchored `root`. */
export interface WitnessReceipt {
  amount: FieldLike;
  timestamp: FieldLike; // unix seconds
  counterparty: FieldLike; // field element (e.g. a hash of the counterparty id)
  nonce: FieldLike; // receipt_nonce
  leafIndex: FieldLike; // position in the anchored tree
  pathElements: FieldLike[]; // `depth` sibling hashes, leaf->root
  pathIndex: number[]; // `depth` bits, 0 = leaf on left
}

export interface ProveReputationInput {
  /** The agent's reputation key (secret, agentId). If omitted, the registered key is used. */
  secret?: FieldLike;
  agentId?: FieldLike;
  epoch: FieldLike;
  /** Anchored receipt-tree root the gate must trust. */
  root: FieldLike;
  /** Public bars the proof advertises (each verified by the circuit). */
  minCount: number;
  minVolume: FieldLike;
  windowStart: number; // unix seconds; every receipt timestamp must be >= this
  /** Exactly K receipts, strictly increasing leafIndex. */
  receipts: WitnessReceipt[];
  /** Proving artifacts — a filesystem path (Node) or URL (browser). NOT bundled. */
  wasmPath: string;
  zkeyPath: string;
}

export interface ProveReputationResult {
  proof: unknown;
  /** [root, min_count, min_volume, window_start, reputation_nullifier, agent_commitment]. */
  publicSignals: string[];
  agentCommitment: string;
  reputationNullifier: string;
  root: string;
  /** Proof-generation wall time (ms), for observability. */
  provingMs: number;
}

/**
 * Generate a private reputation proof from a witness-ready receipt set. Performs full
 * pre-flight validation (so a bad witness fails fast and clearly, not as an opaque circuit
 * abort), then snarkjs.groth16.fullProve. Returns ONLY public values — no secret, agentId,
 * amount, counterparty, or nonce ever appears in the result or any error.
 *
 * The secret may be passed inline OR pre-registered via setReputationKey (preferred — a
 * secret is a live capability, not a tool argument the model fills).
 */
export async function proveReputation(
  input: ProveReputationInput,
  registered?: { secret: string; agentId: string } | null,
): Promise<ProveReputationResult> {
  const reg = registered ?? registeredKey;
  const secret = input.secret ?? reg?.secret;
  const agentId = input.agentId ?? reg?.agentId;
  if (secret == null || agentId == null) {
    throw new Error("x402-rep: no reputation key (pass secret+agentId, or call setReputationKey first)");
  }
  if (!input.wasmPath || !input.zkeyPath) {
    throw new Error("x402-rep: wasmPath and zkeyPath are required (host the artifacts; they are not bundled)");
  }

  // ── Pre-flight: shape + policy-consistency (cheap, before the 0.9s proving step) ──
  if (!Array.isArray(input.receipts) || input.receipts.length !== K) {
    throw new Error(`x402-rep: exactly ${K} receipts required for v1 (got ${Array.isArray(input.receipts) ? input.receipts.length : "non-array"})`);
  }
  if (!Number.isInteger(input.minCount) || input.minCount < 0 || input.minCount > K) {
    throw new Error(`x402-rep: minCount must be an integer in 0..${K}`);
  }
  if (!Number.isInteger(input.windowStart) || input.windowStart < 0) {
    throw new Error("x402-rep: windowStart must be a non-negative integer (unix seconds)");
  }
  // minVolume + window_start feed 64-bit comparators in the circuit; bound them here so an
  // out-of-range value is a clean pre-flight error, not an opaque proof-generation abort.
  const minVolume = requireUint64(toFr(input.minVolume, "minVolume"), "minVolume");
  const windowStart = requireUint64(BigInt(input.windowStart), "windowStart");
  const root = toFr(input.root, "root");
  const ac = agentCommitment(secret, agentId);
  const acFr = BigInt(ac);

  const amounts: bigint[] = [];
  const timestamps: bigint[] = [];
  const counterparties: bigint[] = [];
  const nonces: bigint[] = [];
  const leafIndices: bigint[] = [];
  const pathElementsAll: string[][] = [];
  const pathIndexAll: number[][] = [];
  let prevIndex = -1n;
  let sum = 0n;

  for (let i = 0; i < K; i++) {
    const r = input.receipts[i];
    if (!r || typeof r !== "object") throw new Error(`x402-rep: receipt ${i} is missing/malformed`);
    // amount + timestamp feed 64-bit comparators (sum >= min_volume; timestamp >= window_start).
    const amount = requireUint64(toFr(r.amount, `receipt[${i}].amount`), `receipt[${i}].amount`);
    const timestamp = requireUint64(toFr(r.timestamp, `receipt[${i}].timestamp`), `receipt[${i}].timestamp`);
    const counterparty = toFr(r.counterparty, `receipt[${i}].counterparty`);
    const nonce = toFr(r.nonce, `receipt[${i}].nonce`);
    const leafIndex = toFr(r.leafIndex, `receipt[${i}].leafIndex`);

    // distinctness: strictly increasing leaf_index (the circuit enforces this; reject early)
    if (leafIndex <= prevIndex) {
      throw new Error(`x402-rep: receipts must be ordered by strictly increasing leafIndex (receipt ${i})`);
    }
    if (leafIndex >= BigInt(1 << DEPTH)) {
      throw new Error(`x402-rep: receipt[${i}].leafIndex out of range for depth ${DEPTH}`);
    }
    prevIndex = leafIndex;

    // window: timestamp >= window_start (circuit GreaterEqThan; reject early)
    if (timestamp < windowStart) {
      throw new Error(`x402-rep: receipt ${i} timestamp predates windowStart (out of window)`);
    }

    // path shape
    if (!Array.isArray(r.pathElements) || r.pathElements.length !== DEPTH) {
      throw new Error(`x402-rep: receipt[${i}].pathElements must have length ${DEPTH}`);
    }
    if (!Array.isArray(r.pathIndex) || r.pathIndex.length !== DEPTH || r.pathIndex.some((b) => b !== 0 && b !== 1)) {
      throw new Error(`x402-rep: receipt[${i}].pathIndex must be ${DEPTH} bits (0|1)`);
    }
    const pe = r.pathElements.map((e, j) => toFr(e, `receipt[${i}].pathElements[${j}]`));

    // bind claimed leaf_index to the path bits (circuit enforces this)
    let bitsAsIndex = 0n;
    for (let j = 0; j < DEPTH; j++) bitsAsIndex += BigInt(r.pathIndex[j]) << BigInt(j);
    if (bitsAsIndex !== leafIndex) {
      throw new Error(`x402-rep: receipt[${i}] leafIndex does not match its pathIndex bits`);
    }

    // membership: the leaf + path must reconstruct `root` (catches wrong path/root locally)
    const leaf = poseidon5([acFr, amount, timestamp, counterparty, nonce]);
    if (reconstructRoot(leaf, pe, r.pathIndex) !== root) {
      throw new Error(`x402-rep: receipt[${i}] inclusion path does not reconstruct the given root`);
    }

    amounts.push(amount);
    timestamps.push(timestamp);
    counterparties.push(counterparty);
    nonces.push(nonce);
    leafIndices.push(leafIndex);
    pathElementsAll.push(pe.map((x) => x.toString()));
    pathIndexAll.push(r.pathIndex.slice());
    sum += amount;
  }

  // The circuit compares the accumulated sum with GreaterEqThan(64); K in-range amounts can
  // still sum past 2^64, so bound the total too (clean error vs. opaque circuit abort).
  requireUint64(sum, "total receipt amount");
  if (sum < minVolume) {
    throw new Error("x402-rep: receipts do not total minVolume (proof would fail the volume constraint)");
  }

  const nullifier = reputationNullifier(secret, input.epoch);

  // ── Assemble the circuit witness in the exact field order ──────────────────────────
  const witness = {
    root: root.toString(),
    min_count: String(input.minCount),
    min_volume: minVolume.toString(),
    window_start: windowStart.toString(),
    reputation_nullifier: nullifier,
    agent_commitment: ac,
    secret: toFr(secret, "secret").toString(),
    agent_id: toFr(agentId, "agentId").toString(),
    epoch: toFr(input.epoch, "epoch").toString(),
    amount: amounts.map((x) => x.toString()),
    timestamp: timestamps.map((x) => x.toString()),
    counterparty: counterparties.map((x) => x.toString()),
    receipt_nonce: nonces.map((x) => x.toString()),
    leaf_index: leafIndices.map((x) => x.toString()),
    path_elements: pathElementsAll,
    path_index: pathIndexAll.map((bits) => bits.map((b) => String(b))),
  };

  // ── Prove (the single expensive step) ───────────────────────────────────────────────
  const start = nowMs();
  let proof: unknown;
  let publicSignals: string[];
  try {
    const out = await snarkjs.groth16.fullProve(witness, input.wasmPath, input.zkeyPath);
    proof = out.proof;
    publicSignals = out.publicSignals;
  } catch (e) {
    // Surface a clean message; never echo the witness (it carries the secret + amounts).
    throw new Error(`x402-rep: proof generation failed (${e instanceof Error ? e.message : "unknown error"})`);
  }
  const provingMs = Math.round(nowMs() - start);

  return {
    proof,
    publicSignals,
    agentCommitment: ac,
    reputationNullifier: nullifier,
    root: root.toString(),
    provingMs,
  };
}

// ── Local-tree convenience (agent holds the full leaf set, e.g. its own receipt-dag) ─────

export interface LocalReceipt {
  amount: FieldLike;
  timestamp: FieldLike;
  counterparty: FieldLike;
  nonce: FieldLike;
  leafIndex: number; // position in the agent's depth-10 tree
}

export interface ProveReputationFromLeavesInput {
  secret?: FieldLike;
  agentId?: FieldLike;
  epoch: FieldLike;
  minCount: number;
  minVolume: FieldLike;
  windowStart: number;
  /** Exactly K of the agent's receipts to prove over (strictly increasing leafIndex). */
  myReceipts: LocalReceipt[];
  /** Any OTHER occupied leaves in the same tree (so the computed root matches the anchor). */
  otherLeaves?: Array<{ index: number; leaf: FieldLike }>;
  wasmPath: string;
  zkeyPath: string;
  depth?: number;
}

/**
 * Build the agent's receipt tree locally, derive each inclusion path, and prove. Convenience
 * for the self-anchored / dev case; production uses proveReputation() with indexer-supplied
 * paths against the on-chain-anchored root. Returns the same public-only result.
 */
export async function proveReputationFromLeaves(
  input: ProveReputationFromLeavesInput,
  registered?: { secret: string; agentId: string } | null,
): Promise<ProveReputationResult> {
  const reg = registered ?? registeredKey;
  const secret = input.secret ?? reg?.secret;
  const agentId = input.agentId ?? reg?.agentId;
  if (secret == null || agentId == null) {
    throw new Error("x402-rep: no reputation key (pass secret+agentId, or call setReputationKey first)");
  }
  const depth = input.depth ?? DEPTH;
  if (!Array.isArray(input.myReceipts) || input.myReceipts.length !== K) {
    throw new Error(`x402-rep: exactly ${K} receipts required for v1`);
  }
  const ac = BigInt(agentCommitment(secret, agentId));

  // Compute this agent's leaves, then place them + any other known leaves into the tree.
  const myLeafEntries = input.myReceipts.map((r) => ({
    index: r.leafIndex,
    leaf: poseidon5([
      ac,
      toFr(r.amount, "amount"),
      toFr(r.timestamp, "timestamp"),
      toFr(r.counterparty, "counterparty"),
      toFr(r.nonce, "receipt_nonce"),
    ]),
  }));
  const tree = buildSparseTree([...(input.otherLeaves ?? []), ...myLeafEntries], depth);
  const root = tree[depth][0];

  const receipts: WitnessReceipt[] = input.myReceipts.map((r) => {
    const { pathElements, pathIndex } = merklePath(tree, r.leafIndex, depth);
    return {
      amount: r.amount,
      timestamp: r.timestamp,
      counterparty: r.counterparty,
      nonce: r.nonce,
      leafIndex: r.leafIndex,
      pathElements,
      pathIndex,
    };
  });

  return proveReputation(
    {
      secret,
      agentId,
      epoch: input.epoch,
      root: root.toString(),
      minCount: input.minCount,
      minVolume: input.minVolume,
      windowStart: input.windowStart,
      receipts,
      wasmPath: input.wasmPath,
      zkeyPath: input.zkeyPath,
    },
    registered,
  );
}

/** Monotonic-ish wall clock; falls back to a fixed origin when performance is unavailable. */
function nowMs(): number {
  const p = (globalThis as { performance?: { now(): number } }).performance;
  return p && typeof p.now === "function" ? p.now() : 0;
}
