---
name: soul-guard
description: Detects and alerts on prompt injection backdoors in agent identity files (SOUL.md) — runs as a startup check or background watcher. Protects agent identity from silent manipulation before any instruction is loaded.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Soul Guard

Detects prompt injection backdoors in agent identity files. SOUL.md files tell
agents who they are — if one gets tampered with ("ignore previous instructions",
"you are now..."), Soul Guard catches it before it affects the agent.

Runs as a startup check (once before the agent loads its identity) or a
background watcher (re-checks on file change). Alerts on any injection pattern
or unauthorized modification.

## When to use

- Any agent that loads its identity from a SOUL.md or similar identity file
- Shared agent deployments where the identity file could be written by untrusted parties
- Any agent that needs to assert its own identity hasn't been silently overwritten

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/plugins/soul-guard
