# Liquefy OpenClaw Integration Truth

Use this file when the user asks how the OpenClaw integration is installed, what the standalone skill gives them, or how that differs from the plugin package.

## What a standalone ClawHub install gives users

ClawHub installs the skill bundle into the OpenClaw skills directory.

That means users get:
- the `SKILL.md` instructions
- bundled reference files
- any bundled assets/scripts shipped with the skill

That does not by itself install:
- the Liquefy CLI
- the npm OpenClaw plugin wrapper
- native OpenClaw hook integration

## Required runtime dependency

For this skill to be useful, the host machine still needs Liquefy installed locally.

Verified source-bootstrap path:
- clone repo
- run `./install.sh`

That path exposes:
- `liquefy`
- `liquefy-safe-run`
- `liquefy-context-gate`

Minimum compatibility note:
- the optional plugin compatibility probe is currently aligned to Liquefy OpenClaw CLI `>= 1.1.0`
- check `liquefy version --json` and `liquefy openclaw --version --json` if behavior looks newer or older than expected

Repo-relative helper note:
- commands like `python tools/openclaw_tracevault.py` and `python tools/liquefy_openclaw_plugin.py ...` require a real Liquefy repo checkout with the `tools/` directory present
- if the user only installed the standalone skill and not the repo, those helper commands are not available

## Optional plugin path

Separate package:
- `@parad0x-labs/liquefy-openclaw-plugin`

What the Node wrapper exposes:
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

- standalone skill install is just instructions and bundled refs
- Liquefy CLI should be installed and pinned separately
- if the optional plugin is used, pin the plugin version too
- the plugin probes `liquefy openclaw --version --json` and warns when the detected local CLI is older than the plugin-tested minimum
- policy denylist blocks secrets and risky config paths by default

## Update truth

Skill users do not live-track `main`.

What they actually get:
- the skill text and references bundled into the published ClawHub version
- the runtime behavior of whatever Liquefy CLI is installed on the host machine

So there are separate update channels:
- ClawHub skill update:
  changes the published skill bundle
- Liquefy CLI update:
  changes the actual runtime behavior used by commands
- optional plugin update:
  changes the wrapper/tool surface for `liquefy_scan` and `liquefy_pack_apply`
