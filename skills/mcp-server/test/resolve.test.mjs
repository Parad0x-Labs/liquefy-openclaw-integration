/**
 * Tests for .null resolution in mcp-server (../dist/resolve.js). Hermetic — PDA
 * derivation checked against known on-chain PDAs; parsing on synthetic buffers.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";

import {
  NULL_REGISTRAR_MAINNET,
  normalizeNullName,
  deriveNullDomainPda,
  parseNullDomain,
} from "../dist/resolve.js";

test("registrar is the clean mainnet id (not the seized H4wbFJ)", () => {
  assert.equal(NULL_REGISTRAR_MAINNET, "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np");
  assert.notEqual(NULL_REGISTRAR_MAINNET, "H4wbFJucY9shJt95N8Bra532Z4nnkKhGEfqWvLcYfuDm");
});

test("deriveNullDomainPda matches known on-chain PDAs", () => {
  const vectors = {
    web0: "FJ5kcbFxU6pEVdUHcpvu6hX8CYfTd4LAvhHdiPcK1FG3",
    parad0x: "HTPbRoV9ERectjC8soyukEsr2JNUG595FLE4a6SPnmS3",
    null: "6LGKrgqdUAo1ErsHpMgZmuhRLYGzjkA7dRvsJtg8fGku",
  };
  for (const [name, pda] of Object.entries(vectors)) {
    assert.equal(deriveNullDomainPda(name), pda, name);
    assert.equal(deriveNullDomainPda(`${name}.null`), pda, `${name}.null`);
  }
  assert.equal(normalizeNullName("WEB0.null"), "web0");
});

test("parseNullDomain reads owner + endpoint; all-zero endpoint → null", () => {
  const owner = new PublicKey("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
  const buf = Buffer.alloc(378);
  buf[0] = 0x4e;
  owner.toBytes().forEach((b, i) => (buf[65 + i] = b));
  Buffer.from("https://api.x.null/pay", "utf8").copy(buf, 129);
  const r = parseNullDomain("x.null", "PDA", buf);
  assert.equal(r.found, true);
  assert.equal(r.owner, owner.toBase58());
  assert.equal(r.x402_endpoint, "https://api.x.null/pay");

  const empty = Buffer.alloc(314);
  empty[0] = 0x4e;
  assert.equal(parseNullDomain("x.null", "PDA", empty).x402_endpoint, null);
});

test("parseNullDomain: wrong discriminator → not found", () => {
  assert.equal(parseNullDomain("x.null", "PDA", Buffer.alloc(314)).found, false);
});
