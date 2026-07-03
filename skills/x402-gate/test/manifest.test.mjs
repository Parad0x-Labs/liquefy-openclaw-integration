/**
 * Manifest guard for x402-gate. Asserts the v2026.6.1 security floor (#1) so a
 * regression that drops or lowers minOpenClawVersion fails CI. No build needed —
 * this only reads the manifest JSON.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(join(here, "..", "openclaw.plugin.json"), "utf8"));

test("x402-gate manifest declares the v2026.6.1 security floor", () => {
  assert.equal(manifest.minOpenClawVersion, "2026.6.1");
});

test("x402-gate manifest requires a recipient address (no silent custody default)", () => {
  assert.ok(manifest.configSchema?.required?.includes("recipientAddress"));
});
