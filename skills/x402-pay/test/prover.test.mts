/**
 * zk-rep END-TO-END round-trip: x402-pay PROVER  →  x402-gate VERIFIER.
 *
 * Proves the full set works together: this skill generates a real private-reputation
 * Groth16 proof (track_record.circom), and the sibling x402-gate's verifyReputationProof
 * accepts it under policy + rejects every tampered / transplanted / replayed variant.
 *
 * Run: node --experimental-strip-types test/prover.test.mts
 * Needs the proving artifacts (wasm + zkey) from the track-artifacts backup dir.
 */
import {
  proveReputation,
  proveReputationFromLeaves,
  setReputationKey,
  randomFieldElement,
  buildSparseTree,
  merklePath,
  receiptLeaf,
  agentCommitment,
  type LocalReceipt,
} from "../src/prover.ts";
// The gate side — the verifier the proof must satisfy.
import { verifyReputationProof } from "../../x402-gate/src/rep.ts";

const ART = "/Users/sauliuskruopis/Desktop/dna-x402-redeploy.BACKUP-20260621-presync/sandbox/track-artifacts";
const WASM = `${ART}/track_record.wasm`;
const ZKEY = `${ART}/track_record_final.zkey`;

let pass = 0,
  fail = 0;
const check = (name: string, cond: boolean, extra = "") => {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name} ${extra}`);
  } else {
    fail++;
    console.log(`  ✗ ${name} ${extra}`);
  }
};
async function throwsWith(name: string, fn: () => Promise<unknown>, re: RegExp) {
  try {
    await fn();
    check(name, false, "(did not throw)");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    check(name, re.test(msg), `(${msg.slice(0, 70)})`);
  }
}

// ── Scenario: an agent with 4 settled receipts totalling 17000, in-window ────────────────
const secret = randomFieldElement();
const agentId = randomFieldElement();
const epoch = 42n;
const now = 1780000000;
const windowStart = now - 90 * 86400;
const idxs = [3, 17, 88, 511]; // strictly increasing, < 2^10
const baseReceipts: LocalReceipt[] = idxs.map((leafIndex, i) => ({
  amount: 2000 + i * 1500, // 2000, 3500, 5000, 6500 -> 17000
  timestamp: now - (i + 1) * 5 * 86400,
  counterparty: randomFieldElement(),
  nonce: randomFieldElement(),
  leafIndex,
}));
const total = baseReceipts.reduce((a, r) => a + Number(r.amount), 0);

setReputationKey({ secret, agentId });
const expectedAc = agentCommitment(secret, agentId);

console.log("zk-rep round-trip — x402-pay prover -> x402-gate verifier\n");

// ── 1. POSITIVE: prove (FromLeaves) then verify under policy ──────────────────────────────
const proven = await proveReputationFromLeaves({
  epoch,
  minCount: 3,
  minVolume: 10000,
  windowStart,
  myReceipts: baseReceipts,
  wasmPath: WASM,
  zkeyPath: ZKEY,
});
const ROOT = proven.root;
const policyOk = { minCount: 3, minVolume: 10000, windowStartFloor: 1700000000, trustedRoots: [ROOT] };
const mkStore = () => {
  const s = new Set<string>();
  return (k: string) => {
    if (s.has(k)) return false;
    s.add(k);
    return true;
  };
};

const v1 = await verifyReputationProof(proven.proof, proven.publicSignals, policyOk, { consumeNullifier: mkStore() });
check("POSITIVE round-trip: prover output accepted by gate", v1.valid === true, `(proven volume=${v1.provenMinVolume}, ${proven.provingMs}ms)`);
check("prover agent_commitment == public signal[5]", proven.agentCommitment === proven.publicSignals[5] && proven.agentCommitment === expectedAc);
check("prover root == public signal[0]", proven.root === proven.publicSignals[0]);

// ── 2. IDENTITY BINDING: gate pins agent_commitment from prover ───────────────────────────
const v2a = await verifyReputationProof(proven.proof, proven.publicSignals, policyOk, {
  consumeNullifier: mkStore(),
  expectedAgentCommitment: proven.agentCommitment,
});
check("identity-bound verify accepted (matching commitment)", v2a.valid === true);
const v2b = await verifyReputationProof(proven.proof, proven.publicSignals, policyOk, {
  consumeNullifier: mkStore(),
  expectedAgentCommitment: "999999",
});
check("transplanted proof rejected (wrong expected commitment)", v2b.valid === false && /agent_commitment/i.test(v2b.reason || ""), `(${v2b.reason})`);

// ── 3. REPLAY: same proof twice through one nullifier store ────────────────────────────────
const store = mkStore();
const r3a = await verifyReputationProof(proven.proof, proven.publicSignals, policyOk, { consumeNullifier: store });
const r3b = await verifyReputationProof(proven.proof, proven.publicSignals, policyOk, { consumeNullifier: store });
check("replay rejected (nullifier single-use across round-trip)", r3a.valid === true && r3b.valid === false, `(2nd: ${r3b.reason})`);

// ── 4. ROUND-TRIP INTEGRITY: tamper a public signal after proving → gate rejects ──────────
const tampered = [...proven.publicSignals];
tampered[2] = (BigInt(proven.publicSignals[2]) + 1n).toString();
const r4 = await verifyReputationProof(proven.proof, tampered, { ...policyOk, trustedRoots: [tampered[0]] }, { consumeNullifier: mkStore() });
check("tampered public signal rejected by gate", r4.valid === false, `(${r4.reason})`);

// ── 5. UNDER-THRESHOLD: gate demands more than the proof shows ─────────────────────────────
const r5 = await verifyReputationProof(proven.proof, proven.publicSignals, { ...policyOk, minVolume: 999999999 }, { consumeNullifier: mkStore() });
check("under-threshold policy rejected (gate floor > proven)", r5.valid === false, `(${r5.reason})`);

// ── 6. SECRET HYGIENE: nothing private escapes the prover result ──────────────────────────
const blob = JSON.stringify(proven);
// Full-width private values (secret, agentId, counterparty, nonce are ~77-digit field
// elements): a substring hit anywhere in the output — including the opaque proof — would be a
// real leak; coincidental collision at this width is ~0.
const fullWidth = [
  secret.toString(),
  agentId.toString(),
  ...baseReceipts.map((r) => r.counterparty.toString()),
  ...baseReceipts.map((r) => r.nonce.toString()),
].filter((needle) => blob.includes(needle));
check("prover result leaks no secret / agentId / counterparty / nonce", fullWidth.length === 0, fullWidth.length ? `(LEAKED ${fullWidth.length})` : "");
// Individual amounts are short, so substring-scanning the random proof gives false positives;
// the meaningful guarantee is that NO individual amount appears as a value of any structured
// output field (only the aggregate min_volume bar is public). Exact match, not substring.
const outFields = [...proven.publicSignals, proven.agentCommitment, proven.reputationNullifier, proven.root];
const amountLeak = baseReceipts.map((r) => String(r.amount)).filter((a) => outFields.includes(a));
check("no individual amount appears as a structured output field", amountLeak.length === 0, amountLeak.length ? `(LEAKED ${amountLeak.length})` : "");
check("prover result has no secret/agentId fields", !("secret" in proven) && !("agentId" in (proven as object)));

// ── 7. PRE-FLIGHT: bad witnesses fail fast & clearly (no opaque circuit abort) ────────────
await throwsWith(
  "pre-flight: wrong receipt count rejected",
  () => proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: baseReceipts.slice(0, 3), wasmPath: WASM, zkeyPath: ZKEY }),
  /exactly 4/i,
);
await throwsWith(
  "pre-flight: non-increasing leafIndex rejected",
  () => {
    // Reorder two valid receipts (3, 88, 17, 511) — each path still reconstructs, but the
    // array order is non-monotonic, isolating the strict-increase guard.
    const bad = [baseReceipts[0], baseReceipts[2], baseReceipts[1], baseReceipts[3]];
    return proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: bad, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /increasing leafIndex/i,
);
await throwsWith(
  "pre-flight: out-of-window timestamp rejected",
  () => {
    const bad = baseReceipts.map((r) => ({ ...r }));
    bad[0].timestamp = windowStart - 1; // before window
    return proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: bad, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /out of window|predates/i,
);
await throwsWith(
  "pre-flight: minVolume above real total rejected",
  () => proveReputationFromLeaves({ epoch, minCount: 3, minVolume: total + 1, windowStart, myReceipts: baseReceipts, wasmPath: WASM, zkeyPath: ZKEY }),
  /total minVolume/i,
);
await throwsWith(
  "pre-flight: out-of-field secret rejected at set time",
  async () => {
    setReputationKey({ secret: "-1", agentId });
    return null;
  },
  /field|integer/i,
);
// restore a valid key for any later use
setReputationKey({ secret, agentId });

// ── 8. WITNESS-READY path: proveReputation with indexer-style supplied paths, + bad-path catch ──
const ac = BigInt(agentCommitment(secret, agentId));
const leafEntries = baseReceipts.map((r) => ({
  index: r.leafIndex,
  leaf: BigInt(receiptLeaf({ agentCommitment: ac, amount: r.amount, timestamp: r.timestamp, counterparty: r.counterparty, nonce: r.nonce })),
}));
const tree = buildSparseTree(leafEntries, 10);
const treeRoot = tree[10][0].toString();
const witnessReceipts = baseReceipts.map((r) => {
  const { pathElements, pathIndex } = merklePath(tree, r.leafIndex, 10);
  return { amount: r.amount, timestamp: r.timestamp, counterparty: r.counterparty, nonce: r.nonce, leafIndex: r.leafIndex, pathElements, pathIndex };
});
const wr = await proveReputation({ epoch, root: treeRoot, minCount: 3, minVolume: 10000, windowStart, receipts: witnessReceipts, wasmPath: WASM, zkeyPath: ZKEY });
const v8 = await verifyReputationProof(wr.proof, wr.publicSignals, { minCount: 3, minVolume: 10000, windowStartFloor: 1700000000, trustedRoots: [treeRoot] }, { consumeNullifier: mkStore() });
check("witness-ready proveReputation round-trips", v8.valid === true, `(${wr.provingMs}ms)`);
await throwsWith(
  "pre-flight: tampered inclusion path rejected before proving",
  () => {
    const broken = witnessReceipts.map((r) => ({ ...r, pathElements: r.pathElements.slice() }));
    broken[0].pathElements[0] = "1"; // wrong sibling -> won't reconstruct root
    return proveReputation({ epoch, root: treeRoot, minCount: 3, minVolume: 10000, windowStart, receipts: broken, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /reconstruct the given root/i,
);

// ── 9. 64-BIT COMPARATOR GUARDS: clean pre-flight error, not an opaque circuit abort ──────
// The circuit compares amount/timestamp/window_start/sum with GreaterEqThan(64); the prover
// must reject > 2^64 values up front (adversarial-review confirmed gap, now closed).
const TWO64 = (1n << 64n).toString();
await throwsWith(
  "guard: receipt amount >= 2^64 rejected up front",
  () => {
    const bad = baseReceipts.map((r) => ({ ...r }));
    bad[0].amount = TWO64;
    return proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: bad, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /amount must be < 2\^64/i,
);
await throwsWith(
  "guard: receipt timestamp >= 2^64 rejected up front",
  () => {
    const bad = baseReceipts.map((r) => ({ ...r }));
    bad[0].timestamp = TWO64;
    return proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: bad, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /timestamp must be < 2\^64/i,
);
await throwsWith(
  "guard: windowStart >= 2^64 rejected up front",
  () => proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart: Number(1n << 64n), myReceipts: baseReceipts, wasmPath: WASM, zkeyPath: ZKEY }),
  /windowStart must be < 2\^64/i,
);
await throwsWith(
  "guard: minVolume >= 2^64 rejected up front",
  () => proveReputationFromLeaves({ epoch, minCount: 3, minVolume: TWO64, windowStart, myReceipts: baseReceipts, wasmPath: WASM, zkeyPath: ZKEY }),
  /minVolume must be < 2\^64/i,
);
await throwsWith(
  "guard: summed amount >= 2^64 rejected (4 in-range amounts overflow the total)",
  () => {
    const big = baseReceipts.map((r) => ({ ...r, amount: (1n << 62n).toString() })); // 4 * 2^62 = 2^64
    return proveReputationFromLeaves({ epoch, minCount: 3, minVolume: 1, windowStart, myReceipts: big, wasmPath: WASM, zkeyPath: ZKEY });
  },
  /total receipt amount must be < 2\^64/i,
);

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
