/**
 * Unit tests for the host-free passport core (../dist/passport.js).
 *
 * Hermetic — no live RPC. Covers PDA derivation determinism + correctness,
 * the tool factory (names/params/no-arg guard), the live program IDs, and the
 * public RPC default. Run after `npm run build` (the test script builds first).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";

import {
  DARK_SECP256K1_AUTH,
  DARK_SECP256R1_VAULT,
  RECEIPT_ANCHOR,
  DEFAULT_RPC,
  PROGRAMS,
  readConfig,
  deriveEthBindingPda,
  deriveSolAgentPda,
  deriveWebAuthnVaultPda,
  buildPassportTools,
} from "../dist/passport.js";

const SEIZED = [
  "EepqzVBNuzCgD6XGiB19pDDhzFG3gUL4z1nabBYxpfjS",
  "24tmjEd1DhPW2QuPV6BzkFFHrq2PtELoLqv5cuv2Xu65",
];
const SAMPLE_ETH = "0x742d35cc6634c0532925a3b844bc454e4438f44e";
const SAMPLE_WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"; // a valid base58 pubkey

// ── program IDs / RPC ─────────────────────────────────────────────────────────

test("no seized pre-incident program ID is referenced", () => {
  for (const id of [DARK_SECP256K1_AUTH, DARK_SECP256R1_VAULT, RECEIPT_ANCHOR]) {
    assert.ok(!SEIZED.includes(id), `${id} is a seized ID and must not be used`);
  }
});

test("default RPC is the approved public node (never api.mainnet-beta)", () => {
  assert.equal(DEFAULT_RPC, "https://solana-rpc.publicnode.com");
  assert.doesNotMatch(DEFAULT_RPC, /api\.mainnet-beta\.solana\.com/);
});

test("PROGRAMS maps the three live program IDs", () => {
  assert.equal(PROGRAMS.dark_secp256k1_auth, DARK_SECP256K1_AUTH);
  assert.equal(PROGRAMS.dark_secp256r1_vault, DARK_SECP256R1_VAULT);
  assert.equal(PROGRAMS.receipt_anchor, RECEIPT_ANCHOR);
});

// ── PDA derivation ────────────────────────────────────────────────────────────

test("deriveEthBindingPda: deterministic + on dark_secp256k1_auth", () => {
  const a = deriveEthBindingPda(SAMPLE_ETH);
  const b = deriveEthBindingPda(SAMPLE_ETH);
  assert.equal(a, b, "same input must yield same PDA");
  assert.ok(a, "should derive a PDA");
  // 0x-prefixed and bare hex must agree
  assert.equal(deriveEthBindingPda(SAMPLE_ETH.slice(2)), a);
  // recompute the expected PDA independently
  const [expected] = PublicKey.findProgramAddressSync(
    [Buffer.from("eth_agent"), Buffer.from(SAMPLE_ETH.slice(2), "hex")],
    new PublicKey(DARK_SECP256K1_AUTH),
  );
  assert.equal(a, expected.toBase58());
});

test("deriveEthBindingPda: rejects malformed addresses", () => {
  assert.equal(deriveEthBindingPda("0x1234"), null);
  assert.equal(deriveEthBindingPda("not-hex-at-all"), null);
  assert.equal(deriveEthBindingPda(""), null);
});

test("deriveSolAgentPda + deriveWebAuthnVaultPda: deterministic, distinct, correct seeds", () => {
  const sol = deriveSolAgentPda(SAMPLE_WALLET);
  const vault = deriveWebAuthnVaultPda(SAMPLE_WALLET);
  assert.ok(sol && vault);
  assert.equal(sol, deriveSolAgentPda(SAMPLE_WALLET));
  assert.notEqual(sol, vault, "sol_agent and webauthn_vault PDAs must differ");

  const wallet = new PublicKey(SAMPLE_WALLET);
  const [expSol] = PublicKey.findProgramAddressSync(
    [Buffer.from("sol_agent"), wallet.toBytes()],
    new PublicKey(DARK_SECP256K1_AUTH),
  );
  const [expVault] = PublicKey.findProgramAddressSync(
    [Buffer.from("webauthn_vault"), wallet.toBytes()],
    new PublicKey(DARK_SECP256R1_VAULT),
  );
  assert.equal(sol, expSol.toBase58());
  assert.equal(vault, expVault.toBase58());
});

test("PDA derivers return null on malformed wallet", () => {
  assert.equal(deriveSolAgentPda("not-a-pubkey"), null);
  assert.equal(deriveWebAuthnVaultPda("???"), null);
});

// ── config ────────────────────────────────────────────────────────────────────

test("readConfig keeps strings, drops non-strings", () => {
  const cfg = readConfig({ solanaWallet: SAMPLE_WALLET, ethAddress: 123, nullName: "a.null" });
  assert.equal(cfg.solanaWallet, SAMPLE_WALLET);
  assert.equal(cfg.ethAddress, undefined); // 123 is not a string
  assert.equal(cfg.nullName, "a.null");
  assert.deepEqual(readConfig(undefined), {
    solanaWallet: undefined,
    ethAddress: undefined,
    nullName: undefined,
    rpcUrl: undefined,
  });
});

// ── tool factory ──────────────────────────────────────────────────────────────

test("buildPassportTools registers exactly the two read-only identity tools", () => {
  const tools = buildPassportTools(readConfig({ nullName: "me.null" }));
  assert.equal(tools.length, 2);
  const names = tools.map((t) => t.name);
  assert.deepEqual(names.sort(), ["get_agent_passport", "verify_agent_identity"]);
  for (const t of tools) {
    assert.equal(typeof t.handler, "function");
    assert.equal(typeof t.description, "string");
    assert.equal(typeof t.parameters, "object");
  }
});

test("verify_agent_identity rejects an empty target without any network call", async () => {
  const [, verify] = buildPassportTools(readConfig({}));
  const res = await verify.handler({});
  assert.equal(res.ok, false);
  assert.match(res.error, /at least one of/i);
});

test("verify_agent_identity exposes the three target params", () => {
  const [, verify] = buildPassportTools(readConfig({}));
  assert.deepEqual(
    Object.keys(verify.parameters).sort(),
    ["target_eth_address", "target_null_name", "target_solana_wallet"],
  );
});
