import { spawn } from "node:child_process";

export const DEFAULT_RISKY_PHRASE = "I UNDERSTAND THIS MAY LEAK SECRETS";

export function buildLiquefyExecutable(config = {}) {
  return config.binaryPath || process.env.LIQUEFY_OPENCLAW_BIN || "liquefy";
}

function pushIf(args, flag, value) {
  if (value === undefined || value === null || value === "") return;
  args.push(flag, String(value));
}

export function buildOpenclawArgs(mode, input = {}, config = {}) {
  const args = ["openclaw"];
  const workspace = input.workspace || config.workspace || "~/.openclaw";
  const out = input.out || config.vaultOut;
  if (!out) {
    throw new Error("missing_out");
  }

  args.push("--workspace", String(workspace), "--out", String(out), "--json");

  const profile = input.profile || config.profile || "default";
  args.push("--profile", String(profile));

  if (config.policyFile && !input.policy) {
    args.push("--policy", String(config.policyFile));
  }
  pushIf(args, "--policy", input.policy);
  pushIf(args, "--max-bytes-per-run", input.maxBytesPerRun ?? config.maxBytesPerRun);
  pushIf(args, "--list-limit", input.listLimit ?? config.listLimit);

  if (Array.isArray(input.allow)) {
    for (const p of input.allow) args.push("--allow", String(p));
  }
  if (Array.isArray(input.deny)) {
    for (const p of input.deny) args.push("--deny", String(p));
  }
  if (Array.isArray(input.allowCategories)) {
    for (const c of input.allowCategories) args.push("--allow-category", String(c));
  }

  if (input.includeSecrets === true) {
    const phrase = input.includeSecretsPhrase || DEFAULT_RISKY_PHRASE;
    args.push("--include-secrets", phrase);
  }

  if (mode === "scan") {
    args.push("--dry-run");
    return args;
  }

  if (mode !== "apply") {
    throw new Error(`unsupported_mode:${mode}`);
  }

  args.push("--apply");
  if (input.verifyMode) args.push("--verify-mode", String(input.verifyMode));
  pushIf(args, "--workers", input.workers);

  const secure = input.secure ?? config.requireSecureByDefault ?? false;
  if (secure) args.push("--secure");

  if (input.noChunking) args.push("--no-chunking");
  if (input.unsafePermsOk) args.push("--unsafe-perms-ok");

  return args;
}

export function parseLiquefyJson(stdout) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    const err = new Error("invalid_json");
    err.raw = stdout;
    throw err;
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("invalid_payload");
  }
  if (!parsed.schema_version || !parsed.tool || !parsed.command) {
    throw new Error("missing_contract_fields");
  }
  return parsed;
}

export async function runLiquefyOpenclaw(mode, input = {}, config = {}) {
  const bin = buildLiquefyExecutable(config);
  const args = buildOpenclawArgs(mode, input, config);

  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    child.stdout.on("data", (buf) => {
      out += String(buf);
    });
    child.stderr.on("data", (buf) => {
      err += String(buf);
    });
    child.on("error", (e) => {
      reject(e);
    });
    child.on("close", (code) => {
      let payload;
      try {
        payload = parseLiquefyJson(out || "{}");
      } catch (e) {
        e.stderr = err;
        e.exitCode = code;
        reject(e);
        return;
      }
      payload._stderr = err;
      payload._exitCode = code ?? 1;
      if (payload.ok === false || (code ?? 0) !== 0) {
        const e = new Error(payload?.error?.code || "liquefy_cli_failed");
        e.payload = payload;
        reject(e);
        return;
      }
      resolve(payload);
    });
  });
}

