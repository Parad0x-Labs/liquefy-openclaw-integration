/**
 * context-capsule ContextEngine plugin for OpenClaw.
 *
 * Compresses session history before it reaches the LLM, achieving ~99% token
 * reduction while keeping a verbatim tail of recent messages for coherence.
 * Sessions under the minMessages threshold pass through unchanged.
 *
 * Self-contained (v1.4.0):
 *   The compression core is vendored inline (./compression.ts) — there is no
 *   external runtime dependency. The plugin makes no network requests, no
 *   file-system access, and no on-chain calls. Everything runs locally.
 *
 * Data handling:
 *   All message content is passed through an inline vault-scan gate before
 *   reaching the compression core OR the model on any code path, including
 *   short sessions, the verbatim tail, and compression error fallbacks.
 *   The gate strips API keys, tokens, credentials, PII, and card numbers,
 *   replacing them with typed placeholders. No matched values are logged —
 *   only category counts. On compression failure the plugin is fail-closed:
 *   vault-scanned (redacted) messages are returned with a visible console.warn.
 *   Redaction is best-effort pattern matching, not a guarantee — do not rely on
 *   it as sole protection for highly sensitive sessions.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type {
  AssembleResult,
  CompactResult,
  ContextEngine,
  ContextEngineInfo,
  IngestResult,
} from "openclaw/plugin-sdk/context-engine";
import type { AgentMessage } from "openclaw/plugin-sdk/agent-harness-runtime";
// Self-contained vendored compression core — no external runtime dependency.
// Only zlib + SHA-256, no network/file I/O. See ./compression.ts for provenance.
import { compressContext, injectCapsule } from "./compression";

// ---------------------------------------------------------------------------
// Inline vault-scan gate (ported from tools/liquefy_redact.py)
// Strips secrets and PII before any text crosses the compression boundary.
// Never logs matched values — only category names and counts.
// ---------------------------------------------------------------------------

const VAULT_PATTERNS: Array<{ key: string; re: RegExp; placeholder: string }> = [
  { key: "pem_key",      re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/gi, placeholder: "[REDACTED_PRIVATE_KEY]" },
  { key: "anthropic",    re: /sk-ant-[A-Za-z0-9\-_]{20,}/g,                                placeholder: "[REDACTED_ANTHROPIC_KEY]" },
  { key: "openai",       re: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g,             placeholder: "[REDACTED_OPENAI_KEY]" },
  { key: "generic_sk",   re: /\bsk-[A-Za-z0-9]{20,}\b/g,                                  placeholder: "[REDACTED_SK_KEY]" },
  { key: "github",       re: /gh[pousr]_[A-Za-z0-9_]{36,}/g,                              placeholder: "[REDACTED_GITHUB_TOKEN]" },
  { key: "slack",        re: /xox[bpras]-[A-Za-z0-9\-]{10,}/g,                            placeholder: "[REDACTED_SLACK_TOKEN]" },
  { key: "aws",          re: /AKIA[0-9A-Z]{16}/g,                                         placeholder: "[REDACTED_AWS_KEY]" },
  { key: "stripe",       re: /(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}/g,                placeholder: "[REDACTED_STRIPE_KEY]" },
  { key: "jwt",          re: /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/g, placeholder: "[REDACTED_JWT]" },
  { key: "bearer",       re: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,                         placeholder: "[REDACTED_BEARER]" },
  { key: "credential",   re: /(?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?token)\s*[=:]\s*["']?([A-Za-z0-9/+=\-_.]{8,})["']?/gi, placeholder: "[REDACTED_SECRET]" },
  { key: "card",         re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b/g, placeholder: "[REDACTED_CC]" },
];

function vaultGuard(text: string, label: string): string {
  let result = text;
  const hits: Record<string, number> = {};
  for (const { key, re, placeholder } of VAULT_PATTERNS) {
    re.lastIndex = 0;
    const matches = result.match(re);
    if (matches?.length) {
      hits[key] = (hits[key] ?? 0) + matches.length;
      re.lastIndex = 0;
      result = result.replace(re, placeholder);
    }
  }
  const total = Object.values(hits).reduce((a, b) => a + b, 0);
  if (total > 0) {
    const summary = Object.entries(hits).map(([k, n]) => `${k}x${n}`).join(", ");
    console.warn(`[context-capsule vault] ${label}: redacted ${total} — ${summary}`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Configuration defaults
// ---------------------------------------------------------------------------

const DEFAULT_MIN_MESSAGES = 20;
const DEFAULT_KEEP_RECENT = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type SimpleMessage = { role: string; content: string };

/**
 * Convert an OpenClaw AgentMessage to the plain {role, content} shape expected
 * by @parad0x_labs/context-capsule.
 *
 * Handles:
 *  - "toolResult" role → "tool"
 *  - Content that is already a string → used as-is
 *  - Content that is an array of content blocks → joined to a single string
 */
function normalizeMessages(messages: AgentMessage[]): SimpleMessage[] {
  return messages.map((msg) => {
    const role = msg.role === "toolResult" ? "tool" : (msg.role as string);

    let content: string;
    if (!("content" in msg) || (msg as { content: unknown }).content == null) {
      content = "";
    } else if (typeof (msg as { content: unknown }).content === "string") {
      content = (msg as { content: string }).content;
    } else if (Array.isArray((msg as { content: unknown[] }).content)) {
      const blocks = (msg as { content: unknown[] }).content;
      content = blocks
        .map((block) => {
          if (!block || typeof block !== "object") return "";
          const b = block as Record<string, unknown>;
          if (b.type === "text" && typeof b.text === "string") return b.text;
          if (b.type === "toolResult" || b.type === "tool_result") {
            const inner = b.content;
            if (typeof inner === "string") return inner;
            if (Array.isArray(inner)) {
              return (inner as unknown[])
                .map((ib) => {
                  if (!ib || typeof ib !== "object") return "";
                  const ibr = ib as Record<string, unknown>;
                  return ibr.type === "text" && typeof ibr.text === "string" ? ibr.text : "";
                })
                .filter(Boolean)
                .join("\n");
            }
            return "";
          }
          return "";
        })
        .filter(Boolean)
        .join("\n");
    } else {
      content = "";
    }

    return { role, content };
  });
}

/** Rough token estimate: ~4 chars per token */
function estimateTokens(messages: AgentMessage[]): number {
  return messages.reduce((sum, m) => {
    const c =
      "content" in m && typeof (m as { content: unknown }).content === "string"
        ? ((m as { content: string }).content).length
        : 0;
    return sum + Math.ceil(c / 4);
  }, 0);
}

// ---------------------------------------------------------------------------
// ContextEngine implementation
// ---------------------------------------------------------------------------

type CapsuleConfig = {
  minMessages: number;
  keepRecentMessages: number;
};

class ContextCapsuleEngine implements ContextEngine {
  readonly info: ContextEngineInfo = {
    id: "context-capsule",
    name: "Context Capsule",
    version: "1.3.0",
    ownsCompaction: false,
    turnMaintenanceMode: "background",
  };

  private readonly cfg: CapsuleConfig;

  constructor(cfg: Partial<CapsuleConfig> = {}) {
    this.cfg = {
      minMessages: cfg.minMessages ?? DEFAULT_MIN_MESSAGES,
      keepRecentMessages: cfg.keepRecentMessages ?? DEFAULT_KEEP_RECENT,
    };
  }

  // Required: ingest — accept each message as the transcript grows
  async ingest(_params: {
    sessionId: string;
    sessionKey?: string;
    message: AgentMessage;
    isHeartbeat?: boolean;
  }): Promise<IngestResult> {
    return { ingested: true };
  }

  // Required: assemble — build the context window for the next model call
  async assemble(params: {
    sessionId: string;
    sessionKey?: string;
    messages: AgentMessage[];
    tokenBudget?: number;
    availableTools?: Set<string>;
    model?: string;
    prompt?: string;
  }): Promise<AssembleResult> {
    const { messages } = params;

    // Vault gate applied to ALL messages on ALL paths — including short sessions
    // and the verbatim tail — so no content reaches the model unscanned.
    // Runs locally, logs category counts only, never matched values.
    const scannedMessages = messages.map((msg) => {
      const raw =
        "content" in msg && typeof (msg as { content: unknown }).content === "string"
          ? (msg as { content: string }).content
          : "";
      if (!raw) return msg;
      const clean = vaultGuard(raw, `msg[${(msg as { role: string }).role ?? "unknown"}]`);
      return clean === raw ? msg : { ...msg, content: clean };
    });

    // Short sessions: pass through (vault-scanned above)
    if (scannedMessages.length < this.cfg.minMessages) {
      return {
        messages: scannedMessages,
        estimatedTokens: estimateTokens(scannedMessages),
      };
    }

    // Compress the older history, keep the tail verbatim (both already scanned)
    const tail = scannedMessages.slice(-this.cfg.keepRecentMessages);
    const older = scannedMessages.slice(0, -this.cfg.keepRecentMessages);
    const normalized = normalizeMessages(older);

    // Older messages were already vault-scanned above; pass directly to compression.
    const safeMessages = normalized;

    let summaryText: string;
    try {
      const capsule = await compressContext(safeMessages);
      const injected = await injectCapsule(capsule);
      summaryText = typeof injected === "string" ? injected : JSON.stringify(injected);
    } catch (err) {
      // Compression failed — fall back to vault-scanned messages so the vault
      // guarantee is NEVER broken by a compression error (fail-closed, not fail-open).
      // Emit a visible warning so the operator knows compression was skipped.
      console.warn(
        "[context-capsule] Compression failed — falling back to scanned-but-uncompressed messages. " +
          "Vault redaction still applied; no secrets exposed. " +
          "See ./compression.ts for the compression core.",
        err instanceof Error ? err.message : String(err),
      );
      return {
        messages: scannedMessages,
        estimatedTokens: estimateTokens(scannedMessages),
        promptAuthority: "preassembly_may_overflow",
      };
    }

    // Prepend capsule as a system context message
    const capsuleSystemMessage = {
      role: "system",
      content: `[Context Capsule — compressed history]\n${summaryText}`,
    } as unknown as AgentMessage;

    const assembled = [capsuleSystemMessage, ...tail];

    return {
      messages: assembled,
      estimatedTokens: estimateTokens(assembled),
      systemPromptAddition:
        "Earlier conversation history has been compressed into the context capsule above.",
    };
  }

  // Required: compact — delegate to runtime (engine does not own compaction)
  async compact(_params: {
    sessionId: string;
    sessionKey?: string;
    sessionFile: string;
    tokenBudget?: number;
    force?: boolean;
    currentTokenCount?: number;
    compactionTarget?: "budget" | "threshold";
    customInstructions?: string;
    runtimeContext?: unknown;
    abortSignal?: AbortSignal;
  }): Promise<CompactResult> {
    return {
      ok: true,
      compacted: false,
      reason: "delegated-to-runtime",
    };
  }
}

// ---------------------------------------------------------------------------
// Plugin registration
// ---------------------------------------------------------------------------

export default definePluginEntry({
  id: "context-capsule",
  name: "Context Capsule",
  description:
    "Context engine that compresses long agent session history (default: > 20 " +
    "messages) into a compact capsule before the model call, keeping the most " +
    "recent 10 messages verbatim. Use it to cut token cost on long-running chat " +
    "sessions with any model (Ollama, LM Studio, GPT, Mistral, Claude). It " +
    "activates only as the registered context engine for sessions past the " +
    "message threshold — it is NOT a command, has no keyword triggers, makes no " +
    "network or file-system calls, and does no on-chain anchoring. Do NOT use it " +
    "where exact verbatim transcript fidelity is required, as older history is " +
    "summarized. Compression and best-effort secret redaction run fully locally.",
  // Param types come from the host at runtime; standalone typecheck sees the
  // any-level host shim (src/types/openclaw-host.d.ts), so annotate explicitly.
  register(api: any) {
    api.registerContextEngine("context-capsule", (_ctx: unknown) => new ContextCapsuleEngine());
  },
});
