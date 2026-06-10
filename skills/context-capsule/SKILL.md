# Context Capsule

Compress agent session history ~99% before it hits the LLM, so you stop paying
to re-send the whole transcript on every call. Works with any model — Claude,
GPT, Ollama, Mistral, LM Studio.

> **Self-contained (v1.4.0):** The compression core is bundled directly in this
> skill (`src/compression.ts`). There is **no external runtime dependency**, and
> the plugin makes **no network, file-system, or on-chain calls**. Everything
> runs locally using only Node's built-in `zlib` and `crypto`.

> **Data handling:** Every message is scanned by an inline vault gate before it
> reaches the compression core or the model — on every code path, including short
> sessions, the verbatim tail, and the compression-failure fallback. API keys,
> tokens, credentials, PII, and card numbers are replaced with typed
> placeholders. No matched values are logged, only category counts. Redaction is
> best-effort pattern matching, **not a guarantee** — do not rely on it as the
> sole protection for highly sensitive chats.

## When to use

- Long-running agent sessions (default: more than 20 messages) where the
  transcript is large and you want to cut per-call token cost.
- Any model/provider — local or hosted.

## When NOT to use

- Sessions that require **exact, verbatim transcript fidelity**. Older history is
  summarized into a compact capsule; detail and nuance can be lost. Only the most
  recent 10 messages are kept verbatim.
- As your only safeguard for secrets/PII. The vault scan is best-effort, and the
  compressed history is injected into the **system** context position.

## How it works

Keeps the last 10 messages verbatim. Compresses everything older into a ~60-token
capsule (zlib deflate + a topic/Merkle summary). In benchmarks the agent still
answers 36 of 40 memory-recall questions correctly (90% recovery).

## Savings

|                       | Without | With     |
| --------------------- | ------- | -------- |
| Tokens per call       | 7,919   | 53       |
| Cost (Claude Sonnet)  | $0.024  | $0.00016 |
| Monthly (50 calls/day)| ~$36    | ~$0.24   |

## Install

This skill is self-contained — no extra packages to install. Register it as your
context engine in `openclaw.json`:

```jsonc
{
  "plugins": {
    "slots": { "contextEngine": "context-capsule" }
  }
}
```

Optional config (defaults shown):

```jsonc
{
  "plugins": {
    "entries": {
      "context-capsule": { "minMessages": 20, "keepRecentMessages": 10 }
    }
  }
}
```

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/context-capsule

The standalone library (`@parad0x_labs/context-capsule`) is published separately
on npm for non-OpenClaw use; this skill vendors only the two pure functions it
needs and does not depend on it at runtime.

---

💜 If Context Capsule is quietly shrinking your token bill, a ⭐ on ClawHub helps
other agent builders find it.

