import { runLiquefyOpenclaw } from "./lib.js";

function schemaBase(description) {
  return {
    type: "object",
    additionalProperties: false,
    description,
    properties: {
      workspace: { type: "string" },
      out: { type: "string" },
      profile: { type: "string", enum: ["default", "ratio", "speed"] },
      policy: { type: "string" },
      maxBytesPerRun: { type: "integer", minimum: 0 },
      listLimit: { type: "integer", minimum: 1 },
      allow: { type: "array", items: { type: "string" } },
      deny: { type: "array", items: { type: "string" } },
      allowCategories: { type: "array", items: { type: "string" } },
      includeSecrets: { type: "boolean" },
      includeSecretsPhrase: { type: "string" }
    }
  };
}

function applySchema() {
  const s = schemaBase("Pack an OpenClaw workspace with Liquefy (explicit opt-in, optional secure mode).");
  s.properties.verifyMode = { type: "string", enum: ["full", "fast", "off"] };
  s.properties.workers = { type: "integer", minimum: 0 };
  s.properties.secure = { type: "boolean" };
  s.properties.noChunking = { type: "boolean" };
  s.properties.unsafePermsOk = { type: "boolean" };
  s.required = ["out"];
  return s;
}

function scanSchema() {
  const s = schemaBase("Read-only Liquefy workspace scan (safe default).");
  s.required = ["out"];
  return s;
}

function registerToolCompat(api, name, spec, handler, options = {}) {
  if (!api?.registerTool) return false;
  // Newer style: registerTool({ name, ...spec, handler, optional })
  if (api.registerTool.length <= 1) {
    api.registerTool({
      name,
      ...spec,
      handler,
      optional: !!options.optional,
    });
    return true;
  }
  // Legacy style fallback
  api.registerTool(name, spec, handler, options);
  return true;
}

function registerCommandCompat(api, name, handler) {
  if (!api?.registerCommand) return false;
  if (api.registerCommand.length <= 1) {
    api.registerCommand({ name, handler });
    return true;
  }
  api.registerCommand(name, handler);
  return true;
}

export default async function register(api) {
  const cfg =
    (typeof api?.getConfig === "function" ? api.getConfig("liquefy") : null) ||
    api?.config?.liquefy ||
    {};

  registerToolCompat(
    api,
    "liquefy_scan",
    {
      description: "Read-only Liquefy scan for an OpenClaw workspace (safe default; no writes).",
      inputSchema: scanSchema(),
    },
    async (input = {}) => {
      const payload = await runLiquefyOpenclaw("scan", input, cfg);
      return payload;
    },
    { optional: false },
  );

  registerToolCompat(
    api,
    "liquefy_pack_apply",
    {
      description: "Pack an OpenClaw workspace with Liquefy (explicit writes; optional secure mode).",
      inputSchema: applySchema(),
    },
    async (input = {}) => {
      const payload = await runLiquefyOpenclaw("apply", input, cfg);
      return payload;
    },
    { optional: true },
  );

  registerCommandCompat(api, "liquefy_status", async () => {
    return {
      ok: true,
      plugin: "liquefy",
      version: "0.1.0-alpha",
      tools: ["liquefy_scan", "liquefy_pack_apply"],
      defaults: {
        profile: cfg.profile || "default",
        workspace: cfg.workspace || "~/.openclaw",
        secure: !!cfg.requireSecureByDefault,
      },
      notes: [
        "liquefy_scan is read-only and safe by default",
        "liquefy_pack_apply is optional/allowlisted and shells out to Liquefy CLI JSON mode"
      ],
    };
  });
}

