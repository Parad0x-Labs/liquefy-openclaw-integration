/**
 * Self-contained compression core for the Context Capsule skill.
 *
 * This is a VENDORED, MINIMAL SUBSET of @parad0x_labs/context-capsule —
 * only the two pure functions this plugin actually uses (compressContext +
 * injectCapsule) and their local helpers. It is bundled directly in the skill
 * so the published artifact is fully self-contained and auditable: there is no
 * external runtime dependency, and nothing here performs network I/O, file
 * access, dynamic imports, or on-chain anchoring.
 *
 * Dependencies: Node.js built-ins only — `node:zlib` (deflate) and
 * `node:crypto` (SHA-256). No third-party packages.
 *
 * Provenance: faithfully copied from
 *   github.com/Parad0x-Labs/dna-x402/tree/main/packages/context-capsule (MIT)
 * Excluded on purpose: searchCapsule, estimateSavings, intent tagging, and
 * anchorCorrectionChain (the latter is the only code path in the upstream
 * package that touches the network — it is intentionally NOT vendored here).
 */

import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";

// ── Types ───────────────────────────────────────────────────────────────────

export interface Message {
  role: string;
  content: string;
}

/** A compressed, auditable snapshot of an agent session's message history. */
export interface ContextCapsule {
  sessionId: string;
  capsuleId: string;
  originalTokenEstimate: number;
  compressedBytes: number;
  compressionRatio: string;
  topics: string[];
  merkleRoot: string;
  createdAt: number;
  compressedBase64: string;
}

export interface CompressOptions {
  sessionId?: string;
  maxOutputTokens?: number;
}

// ── Internal helpers ────────────────────────────────────────────────────────

/** SHA-256 of a UTF-8 string → Buffer */
function sha256(data: string): Buffer {
  return createHash("sha256").update(data, "utf8").digest();
}

/**
 * Build a SHA-256 Merkle root over an ordered list of leaf buffers.
 * Empty → 32-byte zero buffer. Single leaf → that leaf. Odd node duplicates.
 */
function buildMerkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return Buffer.alloc(32, 0);
  if (leaves.length === 1) return leaves[0];

  let level: Buffer[] = leaves;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // duplicate odd
      next.push(createHash("sha256").update(left).update(right).digest());
    }
    level = next;
  }
  return level[0];
}

/** Extract up to `maxTopics` noun-phrase-like tokens from message text. */
function extractTopics(messages: Message[], maxTopics = 5): string[] {
  const allText = messages.map((m) => m.content).join(" ");

  const titlePhrases = allText.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b/g) ?? [];
  const properNouns = allText.match(/\b[A-Z][a-zA-Z]{3,}\b/g) ?? [];

  const stopWords = new Set([
    "the", "and", "for", "that", "this", "with", "have", "from", "they", "will",
    "been", "were", "what", "when", "where", "which", "while", "about", "above",
    "after", "before", "between", "through", "during", "because", "should",
  ]);
  const plainWords =
    allText
      .toLowerCase()
      .match(/\b[a-z]{7,}\b/g)
      ?.filter((w) => !stopWords.has(w)) ?? [];

  const seen = new Set<string>();
  const topics: string[] = [];
  for (const raw of [...titlePhrases, ...properNouns, ...plainWords]) {
    const key = raw.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      topics.push(raw);
      if (topics.length >= maxTopics) break;
    }
  }
  return topics;
}

/** Deterministic capsule ID: sha256(sessionId + createdAt + merkleRoot) */
function buildCapsuleId(sessionId: string, createdAt: number, merkleRoot: string): string {
  return createHash("sha256")
    .update(`${sessionId}:${createdAt}:${merkleRoot}`)
    .digest("hex")
    .slice(0, 32);
}

/** Estimate token count from character length (chars / 4 approximation) */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// ── Public API (subset) ──────────────────────────────────────────────────────

/**
 * Compress a session's message history into a ContextCapsule.
 * Pure function — zlib deflate + SHA-256 only, no I/O.
 */
export function compressContext(messages: Message[], opts: CompressOptions = {}): ContextCapsule {
  if (!messages || messages.length === 0) {
    throw new Error("compressContext: messages must be a non-empty array");
  }

  const sessionId = opts.sessionId ?? `session_${Date.now()}`;
  const createdAt = Date.now();

  const jsonl = messages.map((m) => JSON.stringify(m)).join("\n");
  const compressed = deflateSync(Buffer.from(jsonl, "utf8"), { level: 9 });
  const compressedBase64 = compressed.toString("base64");

  const originalTokenEstimate = estimateTokens(jsonl);
  const originalBytes = Buffer.byteLength(jsonl, "utf8");
  const compressedBytes = compressed.length;
  const compressionRatio = `${(originalBytes / compressedBytes).toFixed(1)}x`;

  const topics = extractTopics(messages);

  const leaves = messages.map((m) => sha256(JSON.stringify(m)));
  const merkleRoot = buildMerkleRoot(leaves).toString("hex");
  const capsuleId = buildCapsuleId(sessionId, createdAt, merkleRoot);

  return {
    sessionId,
    capsuleId,
    originalTokenEstimate,
    compressedBytes,
    compressionRatio,
    topics,
    merkleRoot,
    createdAt,
    compressedBase64,
  };
}

/**
 * Generate a compact (~60–100 token) injection string that replaces full
 * history in an LLM call. Pure string builder — no I/O.
 */
export function injectCapsule(capsule: ContextCapsule): string {
  const topicList = capsule.topics.length > 0 ? capsule.topics.join(", ") : "general conversation";
  const rootShort = capsule.merkleRoot.slice(0, 12);
  return (
    `[CONTEXT CAPSULE: session ${capsule.sessionId} compressed ${capsule.compressionRatio}. ` +
    `Key topics: ${topicList}. ` +
    `Merkle: ${rootShort}... ` +
    `Full history available on request.]`
  );
}
