# OpenClaw Agent Blueprints

This document describes the local agent templates shipped with Liquefy and how
they interact in OpenClaw-like runtimes (OpenClaw, NanoClaw, generic runners).

## Goal

Provide copy-ready agent starter packs that are:
- local-first
- auditable
- safe-run wrapped
- policy enforced
- vault packed with MRTV verification

## Template Source

Machine-readable catalog:

- `tools/agents/catalog.json`

CLI helper:

- `tools/liquefy_agents.py`

## Quick Usage

List templates:

```bash
python3 tools/liquefy_agents.py list
```

Show one template:

```bash
python3 tools/liquefy_agents.py show research-agent
```

Show interaction chains:

```bash
python3 tools/liquefy_agents.py map
python3 tools/liquefy_agents.py map --chain research_to_publish
```

Generate runnable scaffold:

```bash
python3 tools/liquefy_agents.py scaffold research-agent --runtime openclaw --out ./agents
```

The scaffold includes:

- `README.md` (purpose + I/O contract)
- `task.md` (editable run objective)
- `handoff_contract.json` (machine contract)
- `agent.env.example` (runtime defaults)
- `run.sh` (safe-run + pack execution path)

## Interaction Model

Built-in chains currently cover:

1. `research_to_publish`
   - `research-agent -> data-enrichment-agent -> reporting-agent`
2. `support_resolution`
   - `customer-support-agent -> ops-automation-agent -> reporting-agent`
3. `integration_backbone`
   - `openapi-tool-wrapper-agent -> workflow-orchestrator-agent -> mcp-tool-seller-agent`
4. `communications_ops`
   - `inbox-triage-agent -> email-campaign-agent -> social-publisher-agent -> reporting-agent`
5. `calendar_assist`
   - `inbox-triage-agent -> calendar-coordinator-agent`

Each handoff should preserve:

- `trace_id`
- declared input/output artifacts
- deterministic file naming

## Runtime Compatibility

Scaffolded agents support:

- `openclaw`: `openclaw run task.md`
- `nanoclaw`: `nanoclaw run task.md`
- `generic`: `python3 agent.py --task task.md`

The generated `run.sh` always applies:

1. `liquefy_safe_run.py` (snapshot, policy enforce, rollback guardrails)
2. `liquefy_openclaw.py --apply` (vault packaging + redaction + index)

## Communications Safety Defaults

Communication-facing templates (email / Telegram / social / calendar) ship with
guardrails enabled by default:

- `ACTION_MODE=draft_only` by default
- explicit approval gate for `ACTION_MODE=active`
- run/hour action caps
- optional recipient allowlist requirement
- deny-pattern list for unsafe content categories

Generated files:

- `guardrails.json` (machine-readable guard policy)
- `agent.env.example` (operational limits + approval knobs)

## Notes

- The catalog is intentionally policy-safe for public templates.
- High-risk/offensive agent categories should stay out of the default catalog.
- Extend templates by editing `tools/agents/catalog.json` and re-running scaffold.
