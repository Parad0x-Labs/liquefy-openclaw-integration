/**
 * Byte-exact tests for the registrar instruction encoders (../dist/registrar.js).
 * Hermetic — no network. Asserts the verified ABI: discriminators, data layout,
 * account order + flags, PDA derivation (known on-chain vectors), config parsing.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey, SystemProgram } from "@solana/web3.js";

import {
  NULL_REGISTRAR_MAINNET,
  IX_REGISTER,
  IX_UPDATE_ENDPOINT,
  IX_SET_STEALTH_META,
  CURRENCY_SOL,
  validateName,
  padName64,
  deriveDomainPda,
  parseRegistryConfig,
  buildRegisterIx,
  buildUpdateEndpointIx,
  buildSetStealthMetaIx,
  buildRegistrarTools,
} from "../dist/registrar.js";

const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

// ── name + PDA ────────────────────────────────────────────────────────────────

test("registrar is the clean mainnet id", () => {
  assert.equal(NULL_REGISTRAR_MAINNET, "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np");
});

test("validateName mirrors the program rules (4-32, a-z/0-9/-)", () => {
  assert.ok(validateName("myagent").ok);
  assert.ok(validateName("my-agent.null").ok); // suffix stripped
  assert.ok(!validateName("ab").ok); // too short
  assert.ok(!validateName("Bad_Name").ok); // uppercase/underscore
  assert.ok(!validateName("x".repeat(33)).ok); // too long
});

test("padName64 is 64 bytes, null-padded", () => {
  const b = padName64("web0");
  assert.equal(b.length, 64);
  assert.equal(b.subarray(0, 4).toString("utf8"), "web0");
  assert.ok(b.subarray(4).every((x) => x === 0));
});

test("deriveDomainPda matches known on-chain PDAs", () => {
  assert.equal(deriveDomainPda("web0").toBase58(), "FJ5kcbFxU6pEVdUHcpvu6hX8CYfTd4LAvhHdiPcK1FG3");
  assert.equal(deriveDomainPda("parad0x").toBase58(), "HTPbRoV9ERectjC8soyukEsr2JNUG595FLE4a6SPnmS3");
});

// ── REGISTER 0x02 ─────────────────────────────────────────────────────────────

test("buildRegisterIx (free pilot): data + 5 accounts in exact order", () => {
  const ix = buildRegisterIx({ payer: WALLET, name: "myagent" });
  // data: 0x02 | name[64] | arweave[32]=0 | currency[1]=SOL  → 98 bytes
  assert.equal(ix.data.length, 1 + 64 + 32 + 1);
  assert.equal(ix.data[0], IX_REGISTER);
  assert.equal(ix.data.subarray(1, 5).toString("utf8"), "myag".slice(0, 4)); // name starts at 1
  assert.ok(ix.data.subarray(65, 97).every((b) => b === 0)); // arweave zero
  assert.equal(ix.data[97], CURRENCY_SOL);
  assert.equal(ix.programId.toBase58(), NULL_REGISTRAR_MAINNET);

  const k = ix.keys;
  assert.equal(k.length, 5);
  assert.equal(k[0].pubkey.toBase58(), WALLET);
  assert.ok(k[0].isSigner && k[0].isWritable); // payer
  assert.ok(!k[1].isSigner && k[1].isWritable); // domain
  assert.ok(!k[2].isSigner && k[2].isWritable); // config
  assert.equal(k[3].pubkey.toBase58(), SystemProgram.programId.toBase58());
  assert.ok(!k[3].isSigner && !k[3].isWritable); // system
  assert.ok(!k[4].isSigner && k[4].isWritable); // owner_cap LAST
});

test("buildRegisterIx (SOL fee): treasury inserted before owner_cap (6 accounts)", () => {
  const treasury = "11111111111111111111111111111112";
  const ix = buildRegisterIx({ payer: WALLET, name: "myagent", treasury });
  const k = ix.keys;
  assert.equal(k.length, 6);
  assert.equal(k[4].pubkey.toBase58(), treasury); // treasury at index 4
  assert.ok(k[4].isWritable);
  // owner_cap is still last (index 5)
  assert.ok(!k[5].isSigner && k[5].isWritable);
  assert.notEqual(k[5].pubkey.toBase58(), treasury);
});

// ── UPDATE_ENDPOINT 0x06 ──────────────────────────────────────────────────────

test("buildUpdateEndpointIx: data + 2 accounts (owner signer, domain writable)", () => {
  const endpoint = "https://api.myagent.dev/x402";
  const ix = buildUpdateEndpointIx({ owner: WALLET, name: "myagent", endpoint });
  assert.equal(ix.data.length, 1 + 64 + 128); // 193
  assert.equal(ix.data[0], IX_UPDATE_ENDPOINT);
  assert.equal(ix.data.subarray(65, 65 + endpoint.length).toString("utf8"), endpoint);
  assert.ok(ix.data.subarray(65 + endpoint.length, 193).every((b) => b === 0)); // padded
  const k = ix.keys;
  assert.equal(k.length, 2);
  assert.ok(k[0].isSigner && !k[0].isWritable); // owner signs, not writable
  assert.equal(k[0].pubkey.toBase58(), WALLET);
  assert.ok(!k[1].isSigner && k[1].isWritable); // domain writable
  assert.equal(k[1].pubkey.toBase58(), deriveDomainPda("myagent").toBase58());
});

test("buildUpdateEndpointIx rejects an oversize endpoint", () => {
  assert.throws(() => buildUpdateEndpointIx({ owner: WALLET, name: "myagent", endpoint: "x".repeat(129) }), /128 bytes/);
});

// ── SET_STEALTH_META 0x0C ─────────────────────────────────────────────────────

test("buildSetStealthMetaIx: data + 3 accounts (owner, domain, system)", () => {
  const meta = "ab".repeat(64); // 64 bytes hex
  const ix = buildSetStealthMetaIx({ owner: WALLET, name: "myagent", stealthMetaHex: meta });
  assert.equal(ix.data.length, 1 + 64 + 64); // 129
  assert.equal(ix.data[0], IX_SET_STEALTH_META);
  assert.equal(ix.data.subarray(65, 129).toString("hex"), meta);
  const k = ix.keys;
  assert.equal(k.length, 3);
  assert.ok(k[0].isSigner && k[0].isWritable); // owner pays rent top-up
  assert.ok(!k[1].isSigner && k[1].isWritable); // domain
  assert.equal(k[2].pubkey.toBase58(), SystemProgram.programId.toBase58());
});

test("buildSetStealthMetaIx rejects bad hex length", () => {
  assert.throws(() => buildSetStealthMetaIx({ owner: WALLET, name: "myagent", stealthMetaHex: "abcd" }), /64 bytes/);
});

// ── config parse ──────────────────────────────────────────────────────────────

test("parseRegistryConfig reads sol_fee@33, null_fee@41, treasury@81", () => {
  const buf = Buffer.alloc(122);
  buf.writeBigUInt64LE(7_000_000n, 33); // 0.007 SOL
  buf.writeBigUInt64LE(0n, 41);
  const treasuryPk = new PublicKey(WALLET);
  treasuryPk.toBytes().forEach((b, i) => (buf[81 + i] = b));
  const cfg = parseRegistryConfig(buf);
  assert.equal(cfg.solFeeLamports, 7_000_000n);
  assert.equal(cfg.nullFeeAmount, 0n);
  assert.equal(cfg.treasury, WALLET);
});

// ── tool factory ──────────────────────────────────────────────────────────────

test("buildRegistrarTools registers the three seller tools", () => {
  const tools = buildRegistrarTools({ solanaWallet: WALLET }, () => null);
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["register_null_name", "set_null_endpoint", "set_null_stealth_meta"],
  );
});

test("set_null_endpoint rejects a non-URL endpoint without touching the network", async () => {
  const [, setEndpoint] = buildRegistrarTools({ solanaWallet: WALLET }, () => null);
  const res = await setEndpoint.handler({ name: "myagent", endpoint: "ftp://nope" });
  assert.equal(res.ok, false);
  assert.match(res.error, /http\(s\) URL/);
});

test("register_null_name errors when no payer/signer is available", async () => {
  const [register] = buildRegistrarTools({}, () => null);
  const res = await register.handler({ name: "myagent" });
  assert.equal(res.ok, false);
  assert.match(res.error, /signer|solanaWallet/);
});
