# Publish runbook — the agent install loop

Everything for the agent adoption loop is built and verified. The only thing
left is `npm publish`, which needs the Parad0x npm login. This is the
paste-and-go checklist so a publish session is mechanical.

> npm scope: `@parad0x_labs` (public). Log in once: `npm login`.

## State today (verified 2026-06-11)

| Package | On npm | Local / canonical | Action |
|---|---|---|---|
| `@parad0x_labs/openclaw-context-capsule` | **1.4.0** ✅ | this repo `skills/context-capsule` | up to date — no action |
| `@parad0x_labs/null-mcp` | **0.2.0** ⚠️ stale | private packages repo `packages/null-mcp` @ **0.6.0** | **republish 0.6.0** (the 0.2.0 on npm has pre-mainnet wiring) |
| `@parad0x_labs/mcp-server` | not published | this repo `skills/mcp-server` @ 0.1.0 | **publish** |
| `@parad0x_labs/openclaw-x402-pay` | not published | this repo `skills/x402-pay` @ 1.1.0 | **publish** |
| `@parad0x_labs/openclaw-x402-gate` | not published | this repo `skills/x402-gate` @ 1.1.0 | **publish** |

## 1. Republish null-mcp 0.6.0 (most urgent — kills the stale 0.2.0)

```bash
cd <private-packages-repo>/packages/null-mcp
npm version   # confirm package.json says 0.6.0 (NOT 0.2.0)
npm publish --access public
npm view @parad0x_labs/null-mcp version   # expect 0.6.0
```

Agents running `npx @parad0x_labs/null-mcp` currently get 0.2.0. This is the
single highest-impact publish — do it first.

## 2. Publish mcp-server

```bash
cd <openclaw-skills>/skills/mcp-server
npm install --ignore-scripts   # never run third-party lifecycle scripts on a host holding the npm token or any key
npm run build           # tsc → dist/ (verified clean)
npm publish --access public
# smoke: npx @parad0x_labs/mcp-server  → should start an MCP stdio server (8 tools)
```

## 3. Publish the x402 skills

```bash
cd <openclaw-skills>/skills/x402-pay  && npm publish --access public
cd <openclaw-skills>/skills/x402-gate && npm publish --access public
```

(These typecheck clean in CI; they're TS-source plugins consumed by OpenClaw —
no build step, the `files` field ships `src/`. Any local install of these uses
`npm install --ignore-scripts`, and the published READMEs tell consumers the same.)

## 4. After publishing — flip the catalog to live

In this repo's `README.md`, change the affected `Install` cells from
"from source — npm publish pending" to the `npm i` / `npx` command, and update
`PUBLISH_RUNBOOK.md`'s state table. (One small docs PR.)

## 5. Optional reach — ClawHub listings

The three OpenClaw plugins (`x402-pay`, `x402-gate`, `context-capsule`) carry
ClawHub-format `SKILL.md`. List them on ClawHub so claw-family agents discover
them in-client.

---

**Notes:** the x402 skills are non-custodial by design (the agent's own signer
holds the key; the skills never hold keys or funds), presenter-bound and
replay-guarded, mainnet-default, and fail-closed on unsafe mainnet config.
Consumers should install with `--ignore-scripts` (the deps are pure-JS). An
independent third-party audit is the bar before scaled real-money volume.
