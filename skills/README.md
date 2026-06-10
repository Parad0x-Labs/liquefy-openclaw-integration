# skills/ — the module standard

Every directory here is one skill, and every skill is a **self-contained
module**. The rules that keep "touch one skill" from ever breaking another:

1. **No cross-skill imports.** A skill never `import`s or `require`s a sibling
   skill. Shared constants (program IDs, wire types) are vendored into each
   skill that needs them — duplication is the price of independence, and we
   pay it on purpose.
2. **Self-describing.** Each skill ships at minimum:
   - `SKILL.md` — the OpenClaw/ClawHub skill card (when to use, when not to,
     safety rails, the tools it exposes)
   - `README.md` — human docs with a **trust model up front** and a
     **"Standalone or together"** section stating exactly what it pairs with
   - `package.json` *or* `skill.json` — install metadata, own version
3. **Own CI lane.** Workflows are path-filtered: a PR touching
   `skills/x402-pay/**` builds and tests only x402-pay. The vault appliance's
   Python CI ignores `skills/` entirely.
4. **Honest status.** Skills that can touch money state custody, caps, and
   network defaults before install instructions — and nothing here claims an
   audit (none has been completed or scheduled).
5. **Removable.** Deleting a skill directory leaves every other module and the
   vault appliance fully functional. If a deletion would break anything else,
   that's a bug in this contract.

## Current modules

| Module | Runtime | Depends on |
|---|---|---|
| `x402-pay` | TypeScript (OpenClaw plugin) | `@solana/web3.js`, `@solana/spl-token` only |
| `x402-gate` | TypeScript (OpenClaw plugin) | `@solana/web3.js` only |
| `context-capsule` | TypeScript (OpenClaw context engine) | none (Node built-ins) |
| `liquefy-openclaw` | SKILL.md pack | the vault appliance (repo root) |
| `liquefy_archive` | skill.json + Python trigger | the vault appliance (repo root) |
| `liquefy_token_guard` | skill.json + Python trigger | the vault appliance (repo root) |

The three `liquefy_*` skills are front-ends for the vault appliance at the repo
root — they depend on it (documented above), but never on each other.

## Adding a skill

Copy the shape of an existing module, keep the five rules, and add a row to
this table plus the catalog in the root README. If your skill needs another
skill's code, vendor the pieces — do not import.
