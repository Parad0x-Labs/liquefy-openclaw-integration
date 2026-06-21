# context-capsule — OpenClaw ContextEngine plugin

Self-contained OpenClaw context engine that reduces prompt tokens in long agent
sessions. It keeps the recent tail verbatim and converts older history into a
bounded, model-readable extractive capsule.

The capsule preserves high-value older context:

- decisions and constraints
- open tasks and requested work
- errors and failed attempts
- files, commands, and links
- open questions and durable facts

It also keeps a zlib-compressed payload and Merkle root for auditability, but the
LLM is given the extractive capsule, not opaque compressed bytes.

## Safety and limits

- **Lossy by design.** Older messages are not preserved verbatim in the model
  prompt. Exact wording, nuance, and low-priority details can be lost.
- **Recent context remains verbatim.** `keepRecentMessages` controls how many
  latest messages stay untouched.
- **Best-effort vault scan.** Text content is scanned for common secrets and PII
  before compression or model injection. This is useful defense-in-depth, not a
  formal guarantee.
- **No external runtime dependency.** The plugin uses only Node built-ins
  (`zlib` and `crypto`) and makes no network, file-system, or on-chain calls.

## Activation

```jsonc
// openclaw.json
{
  "plugins": {
    "slots": {
      "contextEngine": "context-capsule"
    }
  }
}
```

## Config options

| Key | Default | Description |
| --- | ---: | --- |
| `minMessages` | `20` | Sessions shorter than this pass through unchanged. |
| `keepRecentMessages` | `10` | Recent messages kept verbatim after compression. |
| `maxCapsuleTokens` | `700` | Hard cap for the injected extractive capsule. |
| `capsuleTokenRatio` | `0.08` | If OpenClaw provides a model token budget, cap the capsule to this fraction of the budget. |
| `minCompressTokens` | `900` | Estimated transcript-token floor before compression activates. |

```jsonc
{
  "plugins": {
    "entries": {
      "context-capsule": {
        "minMessages": 20,
        "keepRecentMessages": 10,
        "maxCapsuleTokens": 700,
        "capsuleTokenRatio": 0.08,
        "minCompressTokens": 900
      }
    }
  }
}
```

## Packaging

The npm/ClawHub package ships compiled `dist/` JavaScript. It does not require
TypeScript support from the host runtime.

```sh
npm run typecheck
npm test
npm pack --dry-run
```

## When to use

Use this for long-running local or hosted model sessions where resending the full
conversation is too expensive or pushes the model toward context overflow.

Do not use it for workflows where old transcript wording must remain exact. For
that, keep normal OpenClaw history or use a retrieval system that can quote the
original source.
