/**
 * End-to-end smoke test: spawn the built stdio MCP server and drive it over
 * newline-delimited JSON-RPC. Proves the server boots, lists the consent tools
 * alongside the originals, reports read-only scope, and returns a PREVIEW (no
 * transaction) for a write when PARAD0X_MCP_ALLOW_WRITE is unset.
 *
 * A throwaway keypair is injected so the write path reaches the canSubmitWrite
 * guard (rather than the no-keypair dry-run branch) — proving the guard blocks.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { Keypair } from "@solana/web3.js";

const here = dirname(fileURLToPath(import.meta.url));
const serverPath = join(here, "..", "dist", "index.js");

/** Minimal newline-delimited JSON-RPC client over a child process's stdio. */
function startServer() {
  const env = { ...process.env };
  delete env.PARAD0X_MCP_ALLOW_WRITE; // ensure writes are disabled
  env.SOLANA_KEYPAIR = JSON.stringify([...Keypair.generate().secretKey]);

  const child = spawn(process.execPath, [serverPath], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });

  const pending = new Map();
  let buf = "";
  child.stdout.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });

  let nextId = 1;
  function request(method, params) {
    const id = nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout on ${method}`)), 10_000);
      pending.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      child.stdin.write(payload);
    });
  }
  function notify(method, params) {
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  return { child, request, notify };
}

/** Unwrap an MCP tools/call result into the JSON object the tool returned. */
function toolResult(resp) {
  const text = resp.result?.content?.[0]?.text;
  assert.ok(text, "tool result should carry text content");
  return JSON.parse(text);
}

test("server boots, lists consent tools, gates writes (read-only scope)", async () => {
  const { child, request, notify } = startServer();
  try {
    const init = await request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "smoke-test", version: "0.0.0" },
    });
    assert.ok(init.result, "initialize should return a result");
    notify("notifications/initialized", {});

    // tools/list — the 3 consent tools must appear alongside the originals.
    const list = await request("tools/list", {});
    const names = (list.result?.tools ?? []).map((t) => t.name);
    for (const t of ["get_scope_status", "grant_write_consent", "revoke_write_consent"]) {
      assert.ok(names.includes(t), `tools/list missing ${t}`);
    }
    for (const t of ["x402_get_quote", "anchor_receipt", "private_compute", "get_stack_status", "resolve_null", "create_wallet"]) {
      assert.ok(names.includes(t), `tools/list missing tool ${t}`);
    }

    // get_scope_status — write mode must be OFF (env flag unset).
    const scope = toolResult(await request("tools/call", { name: "get_scope_status", arguments: {} }));
    assert.equal(scope.write_mode_enabled, false);

    // anchor_receipt with a valid hash but no ALLOW_WRITE → preview, no tx.
    const anchor = toolResult(
      await request("tools/call", {
        name: "anchor_receipt",
        arguments: { receipt_hash_hex: "a".repeat(64), confirm: true },
      }),
    );
    assert.equal(anchor.preview, true, "write must be blocked to a preview");
    assert.match(anchor.blocked_reason, /PARAD0X_MCP_ALLOW_WRITE=1/);
    assert.ok(!anchor.solana_tx, "no transaction signature should be returned");

    // create_wallet: preview writes nothing; confirm writes a key file + returns
    // ONLY the public key (the secret must never appear in the tool result).
    const walletPath = join(tmpdir(), `web0-smoke-wallet-${process.pid}.json`);
    rmSync(walletPath, { force: true });
    const wprev = toolResult(await request("tools/call", { name: "create_wallet", arguments: { path: walletPath } }));
    assert.equal(wprev.preview, true);
    assert.ok(!existsSync(walletPath), "preview must not write a key file");

    const wmade = toolResult(
      await request("tools/call", { name: "create_wallet", arguments: { path: walletPath, confirm: true } }),
    );
    try {
      assert.equal(wmade.created, true);
      assert.ok(wmade.public_key, "must return the public key");
      assert.ok(existsSync(walletPath), "confirm must write the key file");
      const secret = JSON.parse(readFileSync(walletPath, "utf8"));
      assert.equal(secret.length, 64, "key file holds a 64-byte secret");
      // the secret-key array must NOT be present anywhere in the tool result
      assert.ok(
        !JSON.stringify(wmade).includes(JSON.stringify(secret)),
        "secret key must never appear in the tool result",
      );
    } finally {
      rmSync(walletPath, { force: true });
    }
  } finally {
    child.kill();
  }
});
