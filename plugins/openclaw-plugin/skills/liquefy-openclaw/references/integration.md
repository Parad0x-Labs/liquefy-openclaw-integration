# Liquefy OpenClaw Integration Truth

Use this file when the user asks how the OpenClaw integration is installed, what actually ships in the plugin package, or which surface is responsible for which feature.

## Packaged OpenClaw plugin wrapper

Package:
- `@parad0x-labs/liquefy-openclaw-plugin`

What the Node wrapper actually exposes:
- `liquefy_scan`
- `liquefy_pack_apply`

What it does not expose:
- `liquefy openclaw run`
- `safe-run`
- `context-gate`
- `state-guard`
- `history-guard`
- native hook install/status/uninstall

So if the user asks for guarded runtime control, use local Liquefy CLI/native integration, not the plugin wrapper.

## Binary resolution order

The plugin wrapper resolves the Liquefy executable in this order:

1. plugin config `binaryPath`
2. env var `LIQUEFY_OPENCLAW_BIN`
3. `liquefy` on `PATH`

The wrapper intentionally does not bundle the CLI binary.

## Quick install truth

Verified local source-bootstrap path:
- clone repo
- run `./install.sh`
- use the generated venv shims or `./liquefy`

That path exposes:
- `liquefy`
- `liquefy-safe-run`
- `liquefy-context-gate`

## Native OpenClaw integration

Native integration is managed by:
- `python tools/liquefy_openclaw_plugin.py hook install --create`
- `python tools/liquefy_openclaw_plugin.py status --json`
- `python tools/liquefy_openclaw_plugin.py hook uninstall`

Config search locations:
- `~/.openclaw/openclaw.json`
- `~/.config/openclaw/openclaw.json`
- `OPENCLAW_CONFIG`

Native integration writes local state under:
- `~/.liquefy/openclaw_plugin_state.json`
- `~/.liquefy/audit.jsonl`

## Secure mode

If the user requests secure pack/apply:
- `--secure` is valid on Liquefy pack/apply flows
- `LIQUEFY_SECRET` must exist
- do not say secure mode succeeded if the secret is missing

## Trust posture

Use these facts when the user asks if the integration is safe to deploy:

- plugin default posture is scan-first
- apply is explicit and should be allowlisted
- policy denylist blocks secrets and risky config paths by default
- pinned plugin versions are preferred
- Liquefy CLI should be pinned and verified separately from the wrapper

## Packaging fact

The plugin npm package includes the `skills/` directory, so anything placed under this skill folder ships with the plugin package.

## Update truth

Skill users do not live-track `main`.

What they actually get:
- the skill text and references bundled into the published plugin version
- the runtime behavior of whatever Liquefy CLI is installed on the host machine

So there are two separate update channels:
- plugin/package update:
  changes the shipped OpenClaw wrapper code and the bundled skill files
- Liquefy CLI update:
  changes the actual Python runtime behavior used by the wrapper and local commands

If a user installs from a git checkout and runs `./install.sh`, they get the version from that checkout at that moment. It does not auto-update unless they pull/reinstall.

If a user installs the npm plugin with `--pin`, they get that exact plugin version until they explicitly upgrade it.
