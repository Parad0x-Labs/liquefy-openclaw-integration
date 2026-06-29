import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  DEFAULT_RISKY_PHRASE,
  MIN_LIQUEFY_OPENCLAW_VERSION,
  assessLiquefyCompatibility,
  buildOpenclawArgs,
  buildSpawnPlan,
  compareLiquefyVersions,
  extractLiquefyVersion,
  parseLiquefyJson,
  quoteWindowsCmdArg,
  runLiquefyOpenclaw,
} from "../dist/lib.js";

test("buildOpenclawArgs scan uses safe defaults", () => {
  const args = buildOpenclawArgs("scan", { out: "/tmp/vault" }, {});
  assert.equal(args[0], "openclaw");
  assert.ok(args.includes("--json"));
  assert.ok(args.includes("--dry-run"));
  assert.ok(!args.includes("--apply"));
});

test("buildSpawnPlan uses cmd.exe for Windows command shims", () => {
  const plan = buildSpawnPlan(
    "liquefy.cmd",
    ["openclaw", "--workspace", "C:\\Users\\Test User\\.openclaw", "--json"],
    "win32",
  );
  assert.equal(plan.windowsCmdShim, true);
  assert.match(path.basename(plan.command).toLowerCase(), /^cmd(?:\.exe)?$/);
  assert.deepEqual(plan.args.slice(0, 2), ["/d", "/c"]);
  assert.match(plan.args[2], /liquefy\.cmd/);
  assert.match(plan.args[2], /Test User/);
});

test("buildSpawnPlan leaves native executables direct on Windows", () => {
  const plan = buildSpawnPlan("liquefy.exe", ["openclaw", "--json"], "win32");
  assert.equal(plan.windowsCmdShim, false);
  assert.equal(plan.command, "liquefy.exe");
  assert.deepEqual(plan.args, ["openclaw", "--json"]);
});

test("quoteWindowsCmdArg escapes command metacharacters", () => {
  const quoted = quoteWindowsCmdArg("C:\\tmp\\a & b\\liquefy.cmd");
  assert.equal(quoted.startsWith("\""), true);
  assert.equal(quoted.endsWith("\""), true);
  assert.match(quoted, /\^&/);
});

test("buildOpenclawArgs apply includes explicit flags", () => {
  const args = buildOpenclawArgs(
    "apply",
    {
      out: "/tmp/vault",
      secure: true,
      includeSecrets: true,
      workers: 4,
      verifyMode: "fast",
    },
    { profile: "ratio" },
  );
  assert.ok(args.includes("--apply"));
  assert.ok(args.includes("--secure"));
  assert.ok(args.includes("--verify-mode"));
  assert.ok(args.includes("fast"));
  assert.ok(args.includes("--workers"));
  assert.ok(args.includes("4"));
  assert.ok(args.includes("--include-secrets"));
  assert.ok(args.includes(DEFAULT_RISKY_PHRASE));
});

test("parseLiquefyJson validates contract fields", () => {
  const payload = parseLiquefyJson(
    JSON.stringify({
      schema_version: "liquefy.openclaw.cli.v1",
      tool: "liquefy_openclaw",
      command: "scan",
      ok: true,
    }),
  );
  assert.equal(payload.ok, true);
});

test("parseLiquefyJson rejects invalid JSON", () => {
  assert.throws(() => parseLiquefyJson("{broken"), /invalid_json/);
});

test("compareLiquefyVersions handles newer and older versions", () => {
  assert.equal(compareLiquefyVersions("1.1.0", "1.1.0"), 0);
  assert.equal(compareLiquefyVersions("1.1.1", "1.1.0"), 1);
  assert.equal(compareLiquefyVersions("1.0.9", "1.1.0"), -1);
});

test("assessLiquefyCompatibility warns on older CLI versions", () => {
  const compatibility = assessLiquefyCompatibility("1.0.9", MIN_LIQUEFY_OPENCLAW_VERSION);
  assert.equal(compatibility.compatible, false);
  assert.equal(compatibility.reason, "cli_older_than_required");
  assert.equal(compatibility.warning.code, "liquefy_cli_outdated");
});

test("assessLiquefyCompatibility accepts matching CLI versions", () => {
  const compatibility = assessLiquefyCompatibility("1.1.0", MIN_LIQUEFY_OPENCLAW_VERSION);
  assert.equal(compatibility.compatible, true);
  assert.equal(compatibility.status, "ok");
  assert.equal(compatibility.warning, null);
});

test("extractLiquefyVersion reads runtime build version", () => {
  const version = extractLiquefyVersion({
    result: {
      build: {
        liquefy_version: "1.1.0",
      },
    },
  });
  assert.equal(version, "1.1.0");
});

test("runLiquefyOpenclaw executes a Windows .cmd binaryPath", async (t) => {
  if (process.platform !== "win32") {
    t.skip("Windows-only process launch smoke");
    return;
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "liquefy shim "));
  const shim = path.join(dir, "fake-liquefy.cmd");
  fs.writeFileSync(
    shim,
    [
      "@echo off",
      "echo {\"schema_version\":\"liquefy.openclaw.cli.v1\",\"tool\":\"liquefy_openclaw\",\"command\":\"version\",\"ok\":true,\"result\":{\"build\":{\"liquefy_version\":\"1.1.0\"}}}",
      "",
    ].join("\r\n"),
  );

  const payload = await runLiquefyOpenclaw(
    "scan",
    { out: path.join(dir, "vault out") },
    { binaryPath: shim, workspace: path.join(dir, "workspace with spaces") },
  );
  assert.equal(payload.ok, true);
  assert.equal(payload.compatibility.compatible, true);
});
