/**
 * Tests for the approval-handoff feature (host-free pieces of ../dist/client.js)
 * plus the manifest version floor. Hermetic: the 402 quote path is exercised
 * against a local mock server; nothing is signed or broadcast.
 *
 * Run after `npm run build` (the test script builds first). The gate decision
 * (`needsApproval`) and the read-only quote (`quoteX402`) are the exact code the
 * pay_x402 handler composes, so testing them here covers the handler's branch.
 */
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { needsApproval, quoteX402 } from "../dist/client.js";

const here = dirname(fileURLToPath(import.meta.url));
const DEVNET_USDC = "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr";
const PAY_TO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

const baseConfig = { maxAmountUsdc: 1, allowMainnet: false, allowInternalHosts: true };

/** Spin up a one-shot HTTP server with a given handler; returns its base URL. */
function serve(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/data`, close: () => server.close() });
    });
  });
}

function challenge(amountAtomic) {
  return JSON.stringify({
    x402Version: 1,
    accepts: [
      {
        scheme: "exact",
        network: "solana-devnet",
        maxAmountRequired: String(amountAtomic),
        resource: "/data",
        description: "test feed",
        memoPrefix: "x",
        payTo: PAY_TO,
        asset: DEVNET_USDC,
      },
    ],
  });
}

// ── gate decision (the exact predicate the handler uses) ─────────────────────

test("needsApproval: opt-in and not yet approved → true", () => {
  assert.equal(needsApproval({ ...baseConfig, requireApproval: true }, false), true);
});

test("needsApproval: approved by host → false (proceeds to pay)", () => {
  assert.equal(needsApproval({ ...baseConfig, requireApproval: true }, true), false);
});

test("needsApproval: feature off → false (existing auto-pay path)", () => {
  assert.equal(needsApproval({ ...baseConfig, requireApproval: false }, false), false);
  assert.equal(needsApproval({ ...baseConfig }, false), false); // unset defaults off
});

// ── read-only quote (no signer is ever involved) ─────────────────────────────

test("quoteX402: 402 within cap → paymentRequired with parsed requirement", async () => {
  const srv = await serve((req, res) => {
    res.writeHead(402, { "Content-Type": "application/json" });
    res.end(challenge(10_000)); // 0.01 USDC
  });
  try {
    const q = await quoteX402(srv.url, { config: baseConfig });
    assert.equal(q.paymentRequired, true);
    assert.equal(q.amountUsdc, 0.01);
    assert.equal(q.network, "solana-devnet");
    assert.equal(q.requirement.payTo, PAY_TO);
  } finally {
    srv.close();
  }
});

test("quoteX402: non-402 → no payment required, returns body", async () => {
  const srv = await serve((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("free resource");
  });
  try {
    const q = await quoteX402(srv.url, { config: baseConfig });
    assert.equal(q.paymentRequired, false);
    assert.equal(q.body, "free resource");
  } finally {
    srv.close();
  }
});

test("quoteX402: over-cap 402 → refuses (same rule as the payment path)", async () => {
  const srv = await serve((req, res) => {
    res.writeHead(402, { "Content-Type": "application/json" });
    res.end(challenge(5_000_000)); // 5 USDC, over the 1 USDC cap
  });
  try {
    await assert.rejects(() => quoteX402(srv.url, { config: baseConfig }), /exceeds maxAmountUsdc/);
  } finally {
    srv.close();
  }
});

// ── manifest version floor (#1) ───────────────────────────────────────────────

test("manifest declares the v2026.6.1 security floor", () => {
  const manifest = JSON.parse(readFileSync(join(here, "..", "openclaw.plugin.json"), "utf8"));
  assert.equal(manifest.minOpenClawVersion, "2026.6.1");
});
