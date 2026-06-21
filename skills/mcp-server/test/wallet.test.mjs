/**
 * Tests for non-custodial wallet creation helpers (../dist/wallet.js). Hermetic.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { homedir } from "os";
import { join } from "path";

import { generateWallet, publicKeyOfSecret, resolveWalletPath } from "../dist/wallet.js";

test("generateWallet → valid 64-byte secret with a matching public key", () => {
  const w = generateWallet();
  assert.equal(w.secretKey.length, 64);
  assert.ok(w.secretKey.every((b) => Number.isInteger(b) && b >= 0 && b <= 255));
  assert.equal(publicKeyOfSecret(w.secretKey), w.publicKey); // pubkey derives from the secret
  assert.notEqual(generateWallet().publicKey, w.publicKey); // unique per call
});

test("resolveWalletPath: default, label sanitization, explicit path, ~ expansion", () => {
  assert.equal(resolveWalletPath({}), join(homedir(), ".config", "solana", "web0-agent.json"));
  assert.equal(resolveWalletPath({ label: "myagent" }), join(homedir(), ".config", "solana", "myagent.json"));
  // a path-traversal label falls back to the safe default
  assert.equal(resolveWalletPath({ label: "../../evil" }), join(homedir(), ".config", "solana", "web0-agent.json"));
  assert.equal(resolveWalletPath({ path: "/tmp/k.json" }), "/tmp/k.json");
  assert.equal(resolveWalletPath({ path: "~/k.json" }), join(homedir(), "k.json"));
});
