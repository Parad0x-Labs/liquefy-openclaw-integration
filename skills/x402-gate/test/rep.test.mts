import { verifyReputationProof, repChallenge } from "../src/rep.ts";
import * as snarkjs from "snarkjs";
import { poseidon2, poseidon3, poseidon5 } from "poseidon-lite";
import { randomBytes } from "node:crypto";

const ART = "/Users/sauliuskruopis/Desktop/dna-x402-redeploy.BACKUP-20260621-presync/sandbox/track-artifacts";
const K = 4, DEPTH = 10, DOMAIN_REP = 7n;
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const randFr = () => BigInt("0x" + randomBytes(31).toString("hex")) % P;

// Build a real reputation witness + proof (agent with 4 receipts totalling 17000)
const secret = randFr(), agent_id = randFr(), epoch = 42n;
const agent_commitment = poseidon2([secret, agent_id]);
const reputation_nullifier = poseidon3([DOMAIN_REP, secret, epoch]);
const now = 1780000000n, window_start = now - 90n * 86400n;
const idxs = [3n, 17n, 88n, 511n];
const receipts = idxs.map((_, i) => ({ amount: BigInt(2000 + i * 1500), timestamp: now - BigInt((i + 1) * 5 * 86400), counterparty: randFr(), nonce: randFr() }));
const leaves = receipts.map(r => poseidon5([agent_commitment, r.amount, r.timestamp, r.counterparty, r.nonce]));
const total = receipts.reduce((a, r) => a + r.amount, 0n);
let level: bigint[] = new Array(1 << DEPTH).fill(0n); idxs.forEach((idx, i) => { level[Number(idx)] = leaves[i]; });
const tree = [level]; for (let d = 0; d < DEPTH; d++) { const nx = new Array(level.length >> 1); for (let i = 0; i < nx.length; i++) nx[i] = poseidon2([level[2 * i], level[2 * i + 1]]); tree.push(nx); level = nx; }
const root = tree[DEPTH][0];
const pathOf = (idx: bigint) => { const el: bigint[] = [], ix: number[] = []; let i = Number(idx); for (let d = 0; d < DEPTH; d++) { const b = i & 1; ix.push(b); el.push(tree[d][b ? i - 1 : i + 1]); i >>= 1; } return { el, ix }; };
const paths = idxs.map(pathOf);
const min_count = 3n, min_volume = total - 1n;
const input = { root: root.toString(), min_count: min_count.toString(), min_volume: min_volume.toString(), window_start: window_start.toString(), reputation_nullifier: reputation_nullifier.toString(), agent_commitment: agent_commitment.toString(), secret: secret.toString(), agent_id: agent_id.toString(), epoch: epoch.toString(), amount: receipts.map(r => r.amount.toString()), timestamp: receipts.map(r => r.timestamp.toString()), counterparty: receipts.map(r => r.counterparty.toString()), receipt_nonce: receipts.map(r => r.nonce.toString()), leaf_index: idxs.map(x => x.toString()), path_elements: paths.map(p => p.el.map(e => e.toString())), path_index: paths.map(p => p.ix.map(b => b.toString())) };

const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, `${ART}/track_record.wasm`, `${ART}/track_record_final.zkey`);
const ROOT = publicSignals[0];
const okFloor = { minCount: 3, minVolume: 10000, windowStartFloor: 1700000000, trustedRoots: [ROOT] };
const mkStore = () => { const s = new Set<string>(); return (k: string) => { if (s.has(k)) return false; s.add(k); return true; }; };

let pass = 0, fail = 0;
const check = (name: string, cond: boolean, extra = "") => { if (cond) { pass++; console.log(`  ✓ ${name} ${extra}`); } else { fail++; console.log(`  ✗ ${name} ${extra}`); } };

// POSITIVE
const r1 = await verifyReputationProof(proof, publicSignals, okFloor, { consumeNullifier: mkStore() });
check("POSITIVE: valid private-rep proof accepted", r1.valid === true, `(agentCommitment=${(r1.agentCommitment||"").slice(0,8)}…, provenVolume=${r1.provenMinVolume})`);

// NEGATIVE: under-threshold volume (gate demands more than proven)
const r2 = await verifyReputationProof(proof, publicSignals, { ...okFloor, minVolume: 999999999 }, {});
check("ATTACK under-threshold volume rejected", r2.valid === false, `(${r2.reason})`);

// NEGATIVE: untrusted root (fail-closed)
const r3 = await verifyReputationProof(proof, publicSignals, { minCount: 3, minVolume: 10000, windowStartFloor: 1700000000 }, {});
check("ATTACK untrusted/fabricated root rejected", r3.valid === false && /root/i.test(r3.reason || ""), `(${r3.reason})`);

// NEGATIVE: replay (same nullifier twice)
const store = mkStore();
const r4a = await verifyReputationProof(proof, publicSignals, okFloor, { consumeNullifier: store });
const r4b = await verifyReputationProof(proof, publicSignals, okFloor, { consumeNullifier: store });
check("ATTACK replay (nullifier reuse) rejected", r4a.valid === true && r4b.valid === false, `(2nd: ${r4b.reason})`);

// NEGATIVE: tampered public signal (inflate min_volume) — crypto verify must fail
const tampered = [...publicSignals]; tampered[2] = (BigInt(publicSignals[2]) + 1n).toString();
const r5 = await verifyReputationProof(proof, tampered, { minCount: 3, minVolume: 10000, windowStartFloor: 1700000000, trustedRoots: [tampered[0]] }, {});
check("ATTACK tampered public input rejected", r5.valid === false, `(${r5.reason})`);

// NEGATIVE: forged/garbage proof
const r6 = await verifyReputationProof({ pi_a: ["1","2","1"], pi_b: [["1","2"],["3","4"],["1","0"]], pi_c: ["5","6","1"], protocol: "groth16", curve: "bn128" }, publicSignals, okFloor, {});
check("ATTACK forged proof rejected", r6.valid === false, `(${r6.reason?.slice(0,40)})`);

// HARDEN HIGH-1: no nullifier store wired (and no explicit opt-out) -> fail-closed
const r7 = await verifyReputationProof(proof, publicSignals, okFloor, {});
check("HARDEN HIGH-1 no-store fail-closed", r7.valid === false && /nullifier store/i.test(r7.reason || ""), `(${r7.reason})`);
// HARDEN HIGH-1b: explicit allowReplay opt-out accepted
const r7b = await verifyReputationProof(proof, publicSignals, okFloor, { allowReplay: true });
check("HARDEN HIGH-1b explicit allowReplay accepted", r7b.valid === true);
// HARDEN HIGH-2: transplanted identity (wrong expected commitment) rejected
const r8 = await verifyReputationProof(proof, publicSignals, okFloor, { consumeNullifier: mkStore(), expectedAgentCommitment: "12345" });
check("HARDEN HIGH-2 identity transplant rejected", r8.valid === false && /agent_commitment/i.test(r8.reason || ""), `(${r8.reason})`);
// HARDEN HIGH-2b: matching identity accepted
const r8b = await verifyReputationProof(proof, publicSignals, okFloor, { consumeNullifier: mkStore(), expectedAgentCommitment: publicSignals[5] });
check("HARDEN HIGH-2b matching identity accepted", r8b.valid === true);
// HARDEN MED: out-of-field public signal rejected (defense-in-depth vs snarkjs version)
const FM = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const oof = [...publicSignals]; oof[0] = (BigInt(publicSignals[0]) + FM).toString();
const r9 = await verifyReputationProof(proof, oof, { ...okFloor, trustedRoots: [oof[0]] }, { consumeNullifier: mkStore() });
check("HARDEN MED out-of-field signal rejected", r9.valid === false, `(${r9.reason})`);
// HARDEN LOW: bad operator policy fails clean (no crash)
const r10 = await verifyReputationProof(proof, publicSignals, { ...okFloor, minVolume: "not-a-number" }, { consumeNullifier: mkStore() });
check("HARDEN LOW bad policy fails clean", r10.valid === false && /policy\.minVolume/i.test(r10.reason || ""), `(${r10.reason})`);

console.log(`\nchallenge sample: ${JSON.stringify(repChallenge(okFloor).require)}`);
console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
