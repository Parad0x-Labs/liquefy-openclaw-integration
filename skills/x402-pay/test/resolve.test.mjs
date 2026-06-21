/**
 * Tests for .null name resolution (../dist/resolve.js). Hermetic — PDA
 * derivation is checked against KNOWN on-chain PDAs, and record parsing runs
 * on synthetic buffers. No live RPC.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";

import {
  NULL_REGISTRAR_MAINNET,
  normalizeNullName,
  isNullName,
  deriveNullDomainPda,
  parseNullDomain,
} from "../dist/resolve.js";

const SEIZED_REGISTRAR = "H4wbFJucY9shJt95N8Bra532Z4nnkKhGEfqWvLcYfuDm";

test("registrar is the clean mainnet id, never the seized one", () => {
  assert.equal(NULL_REGISTRAR_MAINNET, "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np");
  assert.notEqual(NULL_REGISTRAR_MAINNET, SEIZED_REGISTRAR);
});

test("deriveNullDomainPda matches known on-chain PDAs (with and without suffix)", () => {
  const vectors = {
    web0: "FJ5kcbFxU6pEVdUHcpvu6hX8CYfTd4LAvhHdiPcK1FG3",
    parad0x: "HTPbRoV9ERectjC8soyukEsr2JNUG595FLE4a6SPnmS3",
    agent: "AntnVqD9Kg3YZNieArNJMX7Y92ihyE136S71SHhZyYVz",
    null: "6LGKrgqdUAo1ErsHpMgZmuhRLYGzjkA7dRvsJtg8fGku",
    nulla: "5LnTqT68dERqRL7jYvPZBWsbTRrC8sR6hYaXh2q7aJbN",
  };
  for (const [name, pda] of Object.entries(vectors)) {
    assert.equal(deriveNullDomainPda(name), pda, `${name}`);
    assert.equal(deriveNullDomainPda(`${name}.null`), pda, `${name}.null`);
  }
});

test("normalizeNullName / isNullName", () => {
  assert.equal(normalizeNullName("MyAgent.null"), "myagent");
  assert.equal(normalizeNullName("web0"), "web0");
  assert.ok(isNullName("foo.null"));
  assert.ok(isNullName("FOO.NULL"));
  assert.ok(!isNullName("https://api.example.com"));
  assert.ok(!isNullName("api.example.com"));
  assert.ok(!isNullName("plainword"));
});

test("parseNullDomain reads owner + endpoint + stealth from a v2 record", () => {
  const buf = Buffer.alloc(378); // v2 size (base 314 + stealth 64)
  buf[0] = 0x4e; // 'N' discriminator
  const owner = new PublicKey("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
  owner.toBytes().forEach((b, i) => (buf[65 + i] = b));
  const endpoint = "https://api.myagent.null/x402";
  Buffer.from(endpoint, "utf8").copy(buf, 129);
  buf[314] = 0xab; // non-zero stealth meta

  const r = parseNullDomain("myagent.null", "PDA", buf);
  assert.equal(r.found, true);
  assert.equal(r.owner, owner.toBase58());
  assert.equal(r.x402Endpoint, endpoint);
  assert.ok(r.stealthMeta && r.stealthMeta.startsWith("ab"));
});

test("parseNullDomain: all-zero endpoint → null (not payable); v1 has no stealth", () => {
  const buf = Buffer.alloc(314);
  buf[0] = 0x4e;
  const r = parseNullDomain("x.null", "PDA", buf);
  assert.equal(r.found, true);
  assert.equal(r.x402Endpoint, null);
  assert.equal(r.stealthMeta, null);
});

test("parseNullDomain: wrong discriminator / too short → not found", () => {
  assert.equal(parseNullDomain("x.null", "PDA", Buffer.alloc(314)).found, false); // disc 0
  assert.equal(parseNullDomain("x.null", "PDA", Buffer.alloc(10)).found, false); // too short
});
