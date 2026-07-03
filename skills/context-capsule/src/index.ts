/**
 * context-capsule ContextEngine plugin for OpenClaw.
 *
 * Compresses older session history before it reaches the LLM, while keeping a
 * recent verbatim tail for coherence. Older turns become a bounded extractive
 * capsule containing durable facts, decisions, tasks, errors, paths, and links.
 *
 * Self-contained:
 *   The compression core is vendored inline (./compression.ts). There is no
 *   external runtime dependency. The plugin makes no network requests, no file
 *   system access, and no on-chain calls. Everything runs locally.
 *
 * Data handling:
 *   Text content is passed through an inline vault-scan gate before reaching the
 *   compression core OR the model, including short sessions, verbatim tails, and
 *   compression error fallbacks. No matched values are logged; only category
 *   counts are emitted. Redaction is best-effort pattern matching, not a formal
 *   privacy guarantee.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { delegateCompactionToRuntime } from "openclaw/plugin-sdk/core";
import type {
  AssembleResult,
  CompactResult,
  ContextEngine,
  ContextEngineInfo,
  IngestResult,
} from "openclaw/plugin-sdk/context-engine";
import type { AgentMessage } from "openclaw/plugin-sdk/agent-harness-runtime";
import { compressContext, injectCapsule } from "./compression.js";

const VAULT_PATTERNS: Array<{ key: string; re: RegExp; placeholder: string }> = [
  {
    key: "pem_key",
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/gi,
    placeholder: "[REDACTED_PRIVATE_KEY]",
  },
  { key: "anthropic", re: /sk-ant-[A-Za-z0-9\-_]{20,}/g, placeholder: "[REDACTED_ANTHROPIC_KEY]" },
  { key: "openai_project", re: /sk-proj-[A-Za-z0-9_\-]{40,}/g, placeholder: "[REDACTED_OPENAI_PROJECT_KEY]" },
  { key: "openai", re: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, placeholder: "[REDACTED_OPENAI_KEY]" },
  { key: "generic_sk", re: /\bsk-[A-Za-z0-9]{20,}\b/g, placeholder: "[REDACTED_SK_KEY]" },
  { key: "github", re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, placeholder: "[REDACTED_GITHUB_TOKEN]" },
  { key: "slack", re: /xox[bpras]-[A-Za-z0-9\-]{10,}/g, placeholder: "[REDACTED_SLACK_TOKEN]" },
  { key: "aws", re: /AKIA[0-9A-Z]{16}/g, placeholder: "[REDACTED_AWS_KEY]" },
  { key: "stripe", re: /(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}/g, placeholder: "[REDACTED_STRIPE_KEY]" },
  { key: "jwt", re: /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/g, placeholder: "[REDACTED_JWT]" },
  { key: "bearer", re: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, placeholder: "[REDACTED_BEARER]" },
  {
    key: "credential",
    re: /(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[=:]\s*["']?([A-Za-z0-9/+=\-_.]{8,})["']?/gi,
    placeholder: "[REDACTED_SECRET]",
  },
  { key: "card", re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, placeholder: "[REDACTED_CC]" },
];

const DEFAULT_MIN_MESSAGES = 20;
const DEFAULT_KEEP_RECENT = 10;
// Tuned for fidelity over raw token-cut: ~1400 tokens lands near the knee of the
// recall/compression curve (~5x reduction at ~70%+ key-signal recall on real
// sessions) instead of the old 700 (~7.5x but ~43% recall). A high compression
// ratio is worthless if the decisions, errors, and refs don't survive.
const DEFAULT_MAX_CAPSULE_TOKENS = 1400;
const DEFAULT_CAPSULE_TOKEN_RATIO = 0.14;
const DEFAULT_MIN_COMPRESS_TOKENS = 900;
const MIN_TAIL_MESSAGES = 2;

type SimpleMessage = { role: string; content: string };

type CapsuleConfig = {
  minMessages: number;
  keepRecentMessages: number;
  maxCapsuleTokens: number;
  capsuleTokenRatio: number;
  minCompressTokens: number;
};

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
    const summary = Object.entries(hits)
      .map(([k, n]) => `${k}x${n}`)
      .join(", ");
    console.warn(`[context-capsule vault] ${label}: redacted ${total} (${summary})`);
  }
  return result;
}

function numberFromConfig(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function integerFromConfig(value: unknown, fallback: number, min: number, max: number): number {
  return Math.floor(numberFromConfig(value, fallback, min, max));
}

function getOwnRecord(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object") return undefined;
  return (value as Record<string, unknown>)[key];
}

function readPluginConfig(ctx: unknown): CapsuleConfig {
  const config = getOwnRecord(getOwnRecord(getOwnRecord(ctx, "config"), "plugins"), "entries");
  const raw = getOwnRecord(config, "context-capsule");
  const record = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    minMessages: integerFromConfig(record.minMessages, DEFAULT_MIN_MESSAGES, 1, 10000),
    keepRecentMessages: integerFromConfig(record.keepRecentMessages, DEFAULT_KEEP_RECENT, 1, 200),
    maxCapsuleTokens: integerFromConfig(
      record.maxCapsuleTokens,
      DEFAULT_MAX_CAPSULE_TOKENS,
      120,
      4000,
    ),
    capsuleTokenRatio: numberFromConfig(
      record.capsuleTokenRatio,
      DEFAULT_CAPSULE_TOKEN_RATIO,
      0.01,
      0.5,
    ),
    minCompressTokens: integerFromConfig(
      record.minCompressTokens,
      DEFAULT_MIN_COMPRESS_TOKENS,
      0,
      1000000,
    ),
  };
}

function normalizeRole(role: unknown): string {
  return role === "toolResult" ? "tool" : typeof role === "string" ? role : "unknown";
}

function contentToText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      if (!block || typeof block !== "object") return "";
      const b = block as Record<string, unknown>;
      if (b.type === "text" && typeof b.text === "string") return b.text;
      if (b.type === "toolResult" || b.type === "tool_result") return contentToText(b.content);
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

function normalizeMessages(messages: AgentMessage[]): SimpleMessage[] {
  return messages.map((msg) => ({
    role: normalizeRole((msg as { role?: unknown }).role),
    content: contentToText((msg as { content?: unknown }).content),
  }));
}

function redactContent(content: unknown, label: string): { content: unknown; changed: boolean } {
  if (typeof content === "string") {
    const clean = vaultGuard(content, label);
    return { content: clean, changed: clean !== content };
  }
  if (!Array.isArray(content)) return { content, changed: false };

  let changed = false;
  const next = content.map((block, index) => {
    if (!block || typeof block !== "object") return block;
    const b = block as Record<string, unknown>;
    if (typeof b.text === "string") {
      const clean = vaultGuard(b.text, `${label}.text[${index}]`);
      if (clean !== b.text) {
        changed = true;
        return { ...b, text: clean };
      }
    }
    if ("content" in b) {
      const nested = redactContent(b.content, `${label}.content[${index}]`);
      if (nested.changed) {
        changed = true;
        return { ...b, content: nested.content };
      }
    }
    return block;
  });

  return { content: next, changed };
}

function redactMessage(msg: AgentMessage, index: number): AgentMessage {
  if (!("content" in (msg as object))) return msg;
  const role = normalizeRole((msg as { role?: unknown }).role);
  const redacted = redactContent((msg as { content?: unknown }).content, `msg[${index}:${role}]`);
  return redacted.changed ? ({ ...(msg as object), content: redacted.content } as AgentMessage) : msg;
}

/** Rough token estimate: ~4 chars per token, including text blocks. */
function estimateTokens(messages: AgentMessage[]): number {
  return normalizeMessages(messages).reduce((sum, m) => sum + Math.ceil(m.content.length / 4), 0);
}

function resolveCapsuleTokenBudget(cfg: CapsuleConfig, tokenBudget?: number): number {
  if (!Number.isFinite(tokenBudget) || !tokenBudget || tokenBudget <= 0) {
    return cfg.maxCapsuleTokens;
  }
  return Math.max(120, Math.min(cfg.maxCapsuleTokens, Math.floor(tokenBudget * cfg.capsuleTokenRatio)));
}

function resolveKeepRecentCount(params: {
  messages: AgentMessage[];
  cfg: CapsuleConfig;
  tokenBudget?: number;
}): number {
  const { messages, cfg, tokenBudget } = params;
  let keep = Math.min(cfg.keepRecentMessages, messages.length);
  if (!Number.isFinite(tokenBudget) || !tokenBudget || tokenBudget <= 0) return keep;

  const tailBudget = Math.max(600, Math.floor(tokenBudget * 0.35));
  while (keep > MIN_TAIL_MESSAGES && estimateTokens(messages.slice(-keep)) > tailBudget) {
    keep -= 1;
  }
  return keep;
}

class ContextCapsuleEngine implements ContextEngine {
  readonly info: ContextEngineInfo = {
    id: "context-capsule",
    name: "Context Capsule",
    version: "1.6.0",
    ownsCompaction: false,
    turnMaintenanceMode: "background",
  };

  private readonly cfg: CapsuleConfig;

  constructor(cfg: CapsuleConfig) {
    this.cfg = cfg;
  }

  async ingest(_params: {
    sessionId: string;
    sessionKey?: string;
    message: AgentMessage;
    isHeartbeat?: boolean;
  }): Promise<IngestResult> {
    return { ingested: true };
  }

  async assemble(params: {
    sessionId: string;
    sessionKey?: string;
    messages: AgentMessage[];
    tokenBudget?: number;
    availableTools?: Set<string>;
    model?: string;
    prompt?: string;
  }): Promise<AssembleResult> {
    const scannedMessages = params.messages.map((msg, index) => redactMessage(msg, index));
    const totalTokens = estimateTokens(scannedMessages);

    if (
      scannedMessages.length < this.cfg.minMessages ||
      totalTokens < this.cfg.minCompressTokens ||
      scannedMessages.length <= MIN_TAIL_MESSAGES
    ) {
      return {
        messages: scannedMessages,
        estimatedTokens: totalTokens,
      };
    }

    const keepRecent = resolveKeepRecentCount({
      messages: scannedMessages,
      cfg: this.cfg,
      tokenBudget: params.tokenBudget,
    });
    const tail = scannedMessages.slice(-keepRecent);
    const older = scannedMessages.slice(0, -keepRecent);
    if (older.length === 0) {
      return {
        messages: scannedMessages,
        estimatedTokens: totalTokens,
      };
    }

    const capsuleTokens = resolveCapsuleTokenBudget(this.cfg, params.tokenBudget);
    const normalized = normalizeMessages(older).filter((msg) => msg.content.trim().length > 0);
    if (normalized.length === 0) {
      return {
        messages: tail,
        estimatedTokens: estimateTokens(tail),
      };
    }

    let summaryText: string;
    try {
      const capsule = compressContext(normalized, {
        sessionId: params.sessionId,
        maxOutputTokens: capsuleTokens,
      });
      summaryText = injectCapsule(capsule, { maxOutputTokens: capsuleTokens });
    } catch (err) {
      console.warn(
        "[context-capsule] Compression failed; falling back to vault-scanned messages.",
        err instanceof Error ? err.message : String(err),
      );
      return {
        messages: scannedMessages,
        estimatedTokens: totalTokens,
        promptAuthority: "preassembly_may_overflow",
      };
    }

    // Deliver the capsule via systemPromptAddition — the ONLY supported channel
    // that reaches the model. OpenClaw's provider adapters (Anthropic, OpenAI)
    // emit only user/assistant/toolResult messages and SILENTLY DROP any other
    // role, so a role:"system" message placed in `messages` would never reach the
    // model. `messages` therefore carries only the verbatim recent tail (valid
    // roles); the compressed older history rides in systemPromptAddition, which
    // OpenClaw merges into the system prompt.
    const systemPromptAddition =
      `[Context Capsule — compressed older conversation history]\n${summaryText}\n\n` +
      "The block above is a lossy extractive capsule of earlier turns (the recent " +
      "messages below it remain verbatim). Use it for continuity; ask the user to " +
      "restate exact wording when precision matters. Anything marked superseded/~~ " +
      "was abandoned — do not act on it.";

    return {
      messages: tail,
      estimatedTokens: estimateTokens(tail) + Math.ceil(systemPromptAddition.length / 4),
      systemPromptAddition,
    };
  }

  async compact(params: Parameters<typeof delegateCompactionToRuntime>[0]): Promise<CompactResult> {
    // Transcript compaction (shrinking the stored session when it nears the model
    // context) is delegated to OpenClaw's native runtime bridge — the SAME path
    // the built-in legacy engine uses. A stub that merely returns
    // {compacted:false} is treated as a compaction FAILURE by the CLI/gateway
    // (it throws "transcript compaction failed"), which breaks long sessions.
    return await delegateCompactionToRuntime(params);
  }
}

export default definePluginEntry({
  id: "context-capsule",
  name: "Context Capsule",
  description:
    "Context engine that compresses older agent session history into a bounded, " +
    "extractive capsule before the model call, keeping recent messages verbatim. " +
    "It preserves durable facts, tasks, decisions, errors, files, commands, and " +
    "links while cutting prompt tokens on long-running sessions. Compression and " +
    "best-effort secret redaction run locally with no network or file-system access.",
  register(api: { registerContextEngine: (id: string, factory: (ctx: unknown) => ContextEngine) => void }) {
    api.registerContextEngine("context-capsule", (ctx: unknown) => new ContextCapsuleEngine(readPluginConfig(ctx)));
  },
});
