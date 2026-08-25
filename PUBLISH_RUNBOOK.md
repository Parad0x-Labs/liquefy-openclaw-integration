# Publish runbook — the agent install loop

Everything for the agent adoption loop is built and verified. The only thing
left is `npm publish`, which needs the Parad0x npm login. This is the
paste-and-go checklist so a publish session is mechanical.

> npm scope: `@parad0x_labs` (public). Log in once: `npm login`.

## State today (verified 2026-08-25)

All public packages are published and match the local sources:

| Package | On npm | Local / canonical | Action |
|---|---|---|---|
| `@parad0x_labs/openclaw-context-capsule` | **1.7.0** ✅ | this repo `skills/context-capsule` @ 1.7.0 | up to date — no action |
| `@parad0x_labs/null-mcp` | **0.10.0** ✅ | private packages repo `packages/null-mcp` | up to date — no action |
| `@parad0x_labs/mcp-server` | **0.1.1** ✅ | this repo `skills/mcp-server` @ 0.1.1 | up to date — no action |
| `@parad0x_labs/openclaw-x402-pay` | **2.0.0** ✅ | this repo `skills/x402-pay` @ 2.0.0 | up to date — no action |
| `@parad0x_labs/openclaw-x402-gate` | **2.0.0** ✅ | this repo `skills/x402-gate` @ 2.0.0 | up to date — no action |
| `@parad0x_labs/openclaw-agent-passport` | **0.1.0** ✅ | this repo `plugins/agent-passport` @ 0.1.0 | up to date — no action |

Before any future publish, refresh this table against `npm view
@parad0x_labs/<pkg> version` and each local `package.json`. The publish
commands below remain the mechanical reference for new versions.

## 1. Publish a new version of mcp-server

```bash
cd <openclaw-skills>/skills/mcp-server
npm install --ignore-scripts   # never run third-party lifecycle scripts on a host holding the npm token or any key
npm run build           # tsc → dist/ (verified clean)
npm publish --access public
# smoke: npx @parad0x_labs/mcp-server  → should start an MCP stdio server (11 tools: 8 stack + get_scope_status / grant_write_consent / revoke_write_consent)
```

## 2. Publish the x402 skills

```bash
cd <openclaw-skills>/skills/x402-pay  && npm publish --access public
cd <openclaw-skills>/skills/x402-gate && npm publish --access public
```

(These typecheck clean in CI; they're TS-source plugins consumed by OpenClaw —
no build step, the `files` field ships `src/`. Any local install of these uses
`npm install --ignore-scripts`, and the published READMEs tell consumers the same.)

## 2b. Publish agent-passport (on-chain identity plugin)

```bash
cd <openclaw-skills>/plugins/agent-passport
npm install --ignore-scripts
npm test                # builds + runs the hermetic passport tests (11 green)
npm publish --access public
```

(Read-only identity plugin: `get_agent_passport` + `verify_agent_identity`, public
RPC only, no seized program IDs. Ships `src/` like the x402 skills.)

## 3. After publishing — flip the catalog to live

In this repo's `README.md`, change the affected `Install` cells from
"from source — npm publish pending" to the `npm i` / `npx` command, and update
`PUBLISH_RUNBOOK.md`'s state table. (One small docs PR.)

## 4. Optional reach — ClawHub listings

The three OpenClaw plugins (`x402-pay`, `x402-gate`, `context-capsule`) carry
ClawHub-format `SKILL.md`. List them on ClawHub so claw-family agents discover
them in-client.

## Pre-publish checklist (verified 2026-08-25)
- [x] mcp-server: `solana-rpc.publicnode.com` is the default RPC (not api.mainnet-beta.solana.com)
- [x] mcp-server: consent registry is live — `grant_write_consent` actually gates writes (`canSubmitWrite`), seized program IDs guarded
- [x] x402-pay / x402-gate / agent-passport: `minOpenClawVersion: 2026.6.1` in openclaw.plugin.json
- [x] All four packages: `npm run typecheck` clean
- [x] All four packages: `npm test` green (mcp-server 11, x402-pay 7, x402-gate 2, agent-passport 11 = 31)
- [x] CI: skills-ts.yml runs typecheck + test per module (incl. agent-passport)
- [ ] Smoke test after publish: `npx @parad0x_labs/mcp-server` starts the stdio server on Node ≥ 22

---

**Notes:** the x402 skills are non-custodial by design (the agent's own signer
holds the key; the skills never hold keys or funds), presenter-bound and
replay-guarded, mainnet-default, and fail-closed on unsafe mainnet config.
Consumers should install with `--ignore-scripts` (the deps are pure-JS). An
independent third-party audit is the bar before scaled real-money volume.
