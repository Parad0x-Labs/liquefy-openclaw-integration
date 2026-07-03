/**
 * x402-gate — private reputation verification ("zk-rep" mode).
 *
 * A caller proves a PRIVATE track record — "I hold >= min_count settled receipts
 * totalling >= min_volume since window_start, in an anchored receipt Merkle tree" —
 * with a Groth16 proof (track_record.circom, BN254). The gate verifies it OFF-CHAIN
 * and enforces its own policy floor, learning NO individual amount, counterparty, or
 * the caller's wallet. Only the aggregate bars, a single-use nullifier, and the agent
 * commitment are revealed.
 *
 * Public-signal order (track_record.circom, nPublic = 6):
 *   [0] root                  anchored receipt Merkle root
 *   [1] min_count             proven receipt-count bar
 *   [2] min_volume            proven total-volume bar (atomic)
 *   [3] window_start          earliest receipt timestamp proven (unix seconds)
 *   [4] reputation_nullifier  Poseidon(DOMAIN_REP, secret, epoch) — single-use per epoch
 *   [5] agent_commitment      Poseidon(secret, agent_id) — same identity as the access gate
 *
 * `valid:true` is returned ONLY when ALL hold: the Groth16 proof is cryptographically
 * valid; every public signal is a canonical in-field element; the proven bars meet/exceed
 * the policy floor; the agent commitment matches the gate session (when bound); the root
 * is trusted; and the nullifier is fresh (single-use, fail-closed).
 *
 * TRUST GATES — stated plainly, never overclaimed:
 *   - The proving key is a single-party development setup. A multi-party ceremony is
 *     required before this is mainnet trust by itself.
 *   - This module is OFF-CHAIN verification. On-chain trustless verification needs a
 *     clean (non-seized) reputation-gate redeploy under the multisig — that is "next".
 *   - ROOT TRUST is the load-bearing seam: a proof against an attacker-chosen `root`
 *     proves nothing (the caller could fabricate a tree of fake receipts). The gate MUST
 *     bind `root` to a trusted source — an allowlist of anchored roots, or a rootVerifier
 *     that confirms the root is anchored on-chain (receipt_anchor). Fail-closed by default.
 *   - IDENTITY BINDING: a reputation proof is portable unless the gate pins its
 *     agent_commitment to the session that authenticated (e.g. the access proof). Pass
 *     expectedAgentCommitment to stop one agent replaying another's reputation.
 */

import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Verification key (groth16 / bn128, nPublic = 6). Read at load so the skill needs no
// JSON-import assertion; the file is co-located with the built module (copied on build).
const REP_VK: unknown = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "track_record_vk.json"), "utf8"),
);

// BN254 scalar field modulus r. A "public signal" outside [0, r) is not a canonical field
// element; we reject rather than letting it be reduced mod r downstream (defense-in-depth
// independent of the snarkjs version's own field check).
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface RepPolicy {
  /** Required receipt-count floor — the proven count bar must be >= this. */
  minCount: number;
  /** Required total-volume floor (atomic units) — the proven volume bar must be >= this. */
  minVolume: bigint | string | number;
  /** Earliest acceptable proven window_start (unix seconds). A higher proven value means
   *  more-recent receipts; the proof must show window_start >= this floor. */
  windowStartFloor: number;
  /** Allowlist of trusted anchored roots (canonical decimal field-element strings). */
  trustedRoots?: string[];
  /** Fail closed when the root is not trusted. Default true. */
  requireTrustedRoot?: boolean;
}

export interface RepVerifyOptions {
  /** Confirm a root is legitimate (e.g. anchored on-chain via receipt_anchor). */
  rootVerifier?: (root: string) => boolean | Promise<boolean>;
  /** Single-use guard for the reputation nullifier — returns true if FRESH (not seen),
   *  false if already consumed. Wire this to the gate's durable replay store. REQUIRED
   *  unless allowReplay is explicitly true. */
  consumeNullifier?: (key: string) => boolean | Promise<boolean>;
  /** Pin the proof to a known agent identity (the gate session's agent_commitment).
   *  Without this a reputation proof is portable across agents. */
  expectedAgentCommitment?: string;
  /** Explicitly opt out of single-use enforcement (e.g. a pure read-only check). Default
   *  false: with no consumeNullifier and no allowReplay, verification FAILS CLOSED. */
  allowReplay?: boolean;
}

export interface RepVerifyResult {
  valid: boolean;
  reason?: string;
  agentCommitment?: string;
  reputationNullifier?: string;
  root?: string;
  provenMinCount?: number;
  provenMinVolume?: string;
  provenWindowStart?: number;
}

const FIELD_RE = /^\d{1,78}$/; // a non-negative decimal of plausible field width
const isFieldElement = (s: unknown): s is string =>
  typeof s === "string" && FIELD_RE.test(s) && BigInt(s) < FIELD_MODULUS;

/** Validate operator policy once. Returns an error string, or null if sound. */
function validatePolicy(policy: RepPolicy): string | null {
  if (!Number.isInteger(policy.minCount) || policy.minCount < 0) return "policy.minCount must be an integer >= 0";
  if (!Number.isInteger(policy.windowStartFloor) || policy.windowStartFloor < 0) return "policy.windowStartFloor must be an integer >= 0";
  let mv: bigint;
  try {
    mv = typeof policy.minVolume === "bigint" ? policy.minVolume : BigInt(String(policy.minVolume).trim());
  } catch {
    return "policy.minVolume is not a valid integer";
  }
  if (mv < 0n) return "policy.minVolume must be >= 0";
  return null;
}

/**
 * Verify a private reputation proof and enforce the gate's policy. Returns
 * { valid:true, ... } only when every gate listed in the module docstring holds.
 * The caller is assumed hostile and to control `proof` and `publicSignals` entirely.
 */
export async function verifyReputationProof(
  proof: unknown,
  publicSignals: unknown,
  policy: RepPolicy,
  opts: RepVerifyOptions = {},
): Promise<RepVerifyResult> {
  // ── Operator-config validation (fail clean, never crash) ──────────────────────
  const policyErr = validatePolicy(policy);
  if (policyErr) return { valid: false, reason: policyErr };

  // ── Structural validation + canonicalization (never trust caller shape) ───────
  if (!Array.isArray(publicSignals) || publicSignals.length !== 6 || !publicSignals.every(isFieldElement)) {
    return { valid: false, reason: "malformed publicSignals (expected 6 in-field decimal elements)" };
  }
  if (!proof || typeof proof !== "object") {
    return { valid: false, reason: "malformed proof" };
  }
  // Canonicalize every signal (strip leading zeros etc.) so string comparisons + store
  // keys are unambiguous and cannot be split by non-canonical encodings of the same value.
  const sig = (publicSignals as string[]).map((s) => BigInt(s).toString());
  const [root, minCountS, minVolumeS, windowStartS, repNullifier, agentCommitment] = sig;

  // ── 1. Cryptographic verification (binds the 6 public values to a valid witness) ──
  let cryptoOk = false;
  try {
    cryptoOk = await snarkjs.groth16.verify(REP_VK as never, sig, proof as never);
  } catch (e) {
    return { valid: false, reason: `verify error: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!cryptoOk) {
    return { valid: false, reason: "groth16 verification failed (invalid proof)" };
  }

  // ── 2. Policy floor — proven bars must MEET OR EXCEED the gate's requirement ────
  const provenCount = Number(minCountS);
  const provenVolume = BigInt(minVolumeS);
  const provenWindow = Number(windowStartS);
  if (!Number.isSafeInteger(provenCount) || provenCount < policy.minCount) {
    return { valid: false, reason: `proven count bar ${minCountS} < required ${policy.minCount}` };
  }
  if (provenVolume < BigInt(typeof policy.minVolume === "bigint" ? policy.minVolume : String(policy.minVolume).trim())) {
    return { valid: false, reason: `proven volume bar ${minVolumeS} < required ${String(policy.minVolume)}` };
  }
  if (!Number.isSafeInteger(provenWindow) || provenWindow < policy.windowStartFloor) {
    return { valid: false, reason: `proven window_start ${windowStartS} predates required floor ${policy.windowStartFloor}` };
  }

  // ── 3. Identity binding — stop one agent replaying another's reputation ─────────
  if (opts.expectedAgentCommitment != null) {
    let expected: string;
    try {
      expected = BigInt(opts.expectedAgentCommitment).toString();
    } catch {
      return { valid: false, reason: "expectedAgentCommitment is not a field element" };
    }
    if (agentCommitment !== expected) {
      return { valid: false, reason: "agent_commitment does not match the gate session identity" };
    }
  }

  // ── 4. Root trust — a proof over an attacker-chosen tree proves nothing ─────────
  const requireRoot = policy.requireTrustedRoot !== false;
  let rootTrusted = false;
  if (policy.trustedRoots && policy.trustedRoots.some((r) => {
    try { return BigInt(r).toString() === root; } catch { return false; }
  })) {
    rootTrusted = true;
  } else if (opts.rootVerifier) {
    try {
      rootTrusted = !!(await opts.rootVerifier(root));
    } catch {
      rootTrusted = false;
    }
  }
  if (requireRoot && !rootTrusted) {
    return { valid: false, reason: "receipt root is not trusted (not allowlisted and rootVerifier absent/failed)" };
  }

  // ── 5. Single-use nullifier (anti-replay) — FAIL CLOSED ─────────────────────────
  // A captured-but-valid proof must not be redeemable twice. With no durable store wired
  // and no explicit allowReplay opt-out, refuse: silent skip would break the contract.
  // The key includes agent_commitment so the store is unambiguous per identity.
  if (!opts.consumeNullifier) {
    if (!opts.allowReplay) {
      return { valid: false, reason: "no nullifier store wired (set consumeNullifier or opts.allowReplay to opt out)" };
    }
  } else if (!(await opts.consumeNullifier(`rep:${agentCommitment}:${repNullifier}`))) {
    return { valid: false, reason: "reputation nullifier already used (replay)" };
  }

  return {
    valid: true,
    agentCommitment,
    reputationNullifier: repNullifier,
    root,
    provenMinCount: provenCount,
    provenMinVolume: minVolumeS,
    provenWindowStart: provenWindow,
  };
}

/**
 * Issue a reputation challenge: the policy bar the caller must satisfy plus the trusted
 * root(s) it must build against. The caller answers with a Groth16 reputation proof.
 */
export function repChallenge(policy: RepPolicy, opts: { domainRep?: number } = {}) {
  return {
    type: "x402-zk-rep",
    proofSystem: "groth16-bn254",
    circuit: "track_record",
    require: {
      min_count: policy.minCount,
      min_volume: String(policy.minVolume),
      window_start_floor: policy.windowStartFloor,
      domain_rep: opts.domainRep ?? 7,
    },
    trustedRoots: policy.trustedRoots ?? [],
    note:
      "Prove >= min_count settled receipts totalling >= min_volume since window_start, " +
      "in a trusted anchored receipt tree, revealing no amounts or counterparties. The " +
      "reputation nullifier is single-use per (secret, epoch); bind agent_commitment to " +
      "your session to make the proof non-transferable.",
  };
}
