---
name: context-capsule
description: Compresses older OpenClaw agent session history into a bounded, lane-change-aware context capsule — keeps recent messages verbatim, flags abandoned directions, quarantines injected instructions, and redacts secrets. Local, deterministic, any model.
---

# Context Capsule

Compress older agent session history before it hits the LLM, so long chats stop
re-sending the full transcript every turn. It keeps the recent tail verbatim and
turns older history into a bounded extractive capsule with decisions, tasks,
errors, paths, links, questions, and durable facts. Works with any model —
Claude, GPT, Ollama, Mistral, LM Studio.

**What sets it apart:**

- **Lane-change aware.** When the session pivots ("replace X with Y", "forget X,
  use Y instead"), the capsule marks the abandoned direction as superseded and
  keeps the live one — so the model never wanders back into a dropped plan. On a
  held-out pivot set it cleans 83% of abandoned subjects with **zero** wrongly
  flagged live choices.
- **High fidelity per token.** Distinctive signals — file paths, IDs, ports,
  URLs, commands, errors, decisions — are emitted as dense atoms, so the capsule
  keeps **79% of key signals at ~5× reduction and 93% at ~3.4×** on real
  sessions (measured, see `test/fidelity-bench.mjs`).

> **Self-contained (v1.6.0):** The compression core is bundled directly in this
> skill (`src/compression.ts`). There is **no external runtime dependency**, and
> the plugin makes **no network, file-system, or on-chain calls**. Everything
> runs locally using only Node's built-in `zlib` and `crypto`, and is fully
> deterministic. Capsules carry a `schema` tag (`context-capsule.v2`).

> **Protections (defense-in-depth, all CI-gated by `npm test`):**
> - **Secret redaction (every surface).** API keys (OpenAI, Anthropic, AWS,
>   Google, GitHub classic + fine-grained, GitLab, npm, Slack, Stripe, SendGrid,
>   Twilio), JWTs, PEM blocks, URL basic-auth, `DATABASE_URL=` DSNs, and
>   `key=value` credentials are detected by prefix/shape/context — never by raw
>   entropy, so public IDs (git SHAs, UUIDs, chain addresses) are untouched.
>   Redaction runs **before compression**, so no secret survives even in the zlib
>   audit blob, and again on output — the core never emits a secret even if called
>   directly. Each redaction carries a one-way **SHA-256 fingerprint**
>   (`[REDACTED_AWS_KEY#a1b2c3d4]`) so the same key is correlatable across turns
>   without ever exposing its value. Best-effort pattern matching — strong, not a
>   guarantee for the most sensitive chats.
> - **Injection quarantine** — instruction-injection patterns in older history
>   ("ignore previous instructions", "you are now…", "reveal your prompt") are
>   wrapped as inert untrusted text, never surfaced as a live instruction.
> - **Bounded work** — every extraction pass runs on size-capped input, so a
>   megabyte message or an adversarial string finishes in milliseconds instead of
>   hanging the turn.

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

Keeps the last 10 messages verbatim by default. Older history is zlib-compressed
for auditability, then converted into a model-readable extractive capsule. The
model sees compact sections for decisions/constraints, tasks, errors, files,
commands, links, questions, and durable facts. The capsule is capped by
`maxCapsuleTokens` and adapts to the host token budget with
`capsuleTokenRatio`.

## Savings

|                       | Without | With     |
| --------------------- | ------- | -------- |
| Prompt history sent   | Full transcript | Capsule + recent tail |
| Compression trigger   | N/A     | Message + token threshold |
| Runtime dependencies  | N/A     | Node built-ins only |

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
      "context-capsule": {
        "minMessages": 20,
        "keepRecentMessages": 10,
        "maxCapsuleTokens": 1400,
        "capsuleTokenRatio": 0.14,
        "minCompressTokens": 900
      }
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

