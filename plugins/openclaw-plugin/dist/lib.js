import { spawn } from "node:child_process";

export const DEFAULT_RISKY_PHRASE = "I UNDERSTAND THIS MAY LEAK SECRETS";
export const PLUGIN_VERSION = "0.1.0-alpha";
export const MIN_LIQUEFY_OPENCLAW_VERSION = "1.1.0";

const compatibilityCache = new Map();

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

function parseSemver(version) {
  if (typeof version !== "string") return null;
  const normalized = version.trim().replace(/^v/i, "");
  const match = normalized.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
  if (!match) return null;
  return {
    raw: normalized,
    major: Number.parseInt(match[1], 10),
    minor: Number.parseInt(match[2], 10),
    patch: Number.parseInt(match[3], 10),
    prerelease: match[4] || "",
  };
}

export function compareLiquefyVersions(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (!a || !b) return null;
  for (const key of ["major", "minor", "patch"]) {
    if (a[key] !== b[key]) return a[key] > b[key] ? 1 : -1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease > b.prerelease ? 1 : -1;
}

export function extractLiquefyVersion(payload) {
  return payload?.result?.build?.liquefy_version || null;
}

export function assessLiquefyCompatibility(cliVersion, minimumVersion = MIN_LIQUEFY_OPENCLAW_VERSION) {
  const comparison = compareLiquefyVersions(cliVersion, minimumVersion);
  if (!cliVersion) {
    return {
      status: "unknown",
      compatible: false,
      reason: "missing_cli_version",
      cli_version: null,
      minimum_cli_version: minimumVersion,
      warning: {
        code: "liquefy_cli_version_unknown",
        message: `Liquefy CLI version could not be determined; expected >= ${minimumVersion}.`,
      },
    };
  }
  if (comparison === null) {
    return {
      status: "unknown",
      compatible: false,
      reason: "unparseable_cli_version",
      cli_version: cliVersion,
      minimum_cli_version: minimumVersion,
      warning: {
        code: "liquefy_cli_version_unparseable",
        message: `Liquefy CLI version '${cliVersion}' could not be compared; expected >= ${minimumVersion}.`,
      },
    };
  }
  if (comparison < 0) {
    return {
      status: "warn",
      compatible: false,
      reason: "cli_older_than_required",
      cli_version: cliVersion,
      minimum_cli_version: minimumVersion,
      warning: {
        code: "liquefy_cli_outdated",
        message: `Liquefy CLI ${cliVersion} is older than the plugin-tested minimum ${minimumVersion}.`,
      },
    };
  }
  return {
    status: "ok",
    compatible: true,
    reason: null,
    cli_version: cliVersion,
    minimum_cli_version: minimumVersion,
    warning: null,
  };
}

function runJsonCommand(bin, args) {
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
    child.on("error", (error) => {
      reject(error);
    });
    child.on("close", (code) => {
      let payload;
      try {
        payload = parseLiquefyJson(out || "{}");
      } catch (error) {
        error.stderr = err;
        error.exitCode = code;
        reject(error);
        return;
      }
      resolve({
        payload,
        stderr: err,
        exitCode: code ?? 1,
      });
    });
  });
}

async function probeLiquefyCompatibility(bin) {
  const probeArgs = ["openclaw", "--version", "--json"];
  try {
    const probe = await runJsonCommand(bin, probeArgs);
    const cliVersion = extractLiquefyVersion(probe.payload);
    return {
      plugin_version: PLUGIN_VERSION,
      probe_command: [bin, ...probeArgs],
      ...assessLiquefyCompatibility(cliVersion),
    };
  } catch (error) {
    return {
      plugin_version: PLUGIN_VERSION,
      probe_command: [bin, ...probeArgs],
      status: "unknown",
      compatible: false,
      reason: "version_probe_failed",
      cli_version: null,
      minimum_cli_version: MIN_LIQUEFY_OPENCLAW_VERSION,
      warning: {
        code: "liquefy_cli_version_probe_failed",
        message: `Liquefy CLI compatibility probe failed; expected >= ${MIN_LIQUEFY_OPENCLAW_VERSION}.`,
      },
      error: {
        message: error?.message || String(error),
        exitCode: error?.exitCode ?? null,
        stderr: error?.stderr || "",
      },
    };
  }
}

export async function getLiquefyCompatibility(config = {}) {
  const bin = buildLiquefyExecutable(config);
  const cacheKey = JSON.stringify({
    bin,
    minimum: MIN_LIQUEFY_OPENCLAW_VERSION,
  });
  if (!compatibilityCache.has(cacheKey)) {
    compatibilityCache.set(cacheKey, probeLiquefyCompatibility(bin));
  }
  return compatibilityCache.get(cacheKey);
}

export async function runLiquefyOpenclaw(mode, input = {}, config = {}) {
  const bin = buildLiquefyExecutable(config);
  const args = buildOpenclawArgs(mode, input, config);
  const compatibility = await getLiquefyCompatibility(config);

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
      payload.compatibility = compatibility;
      if (compatibility?.warning) {
        payload.warnings = [...(Array.isArray(payload.warnings) ? payload.warnings : []), compatibility.warning];
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
