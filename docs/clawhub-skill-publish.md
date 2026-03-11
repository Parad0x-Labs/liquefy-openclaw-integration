# ClawHub Skill Publish Plan

This document defines the publish path for the standalone Liquefy OpenClaw skill on ClawHub.

## Skill folder

- Standalone skill bundle: `skills/liquefy-openclaw`
- Primary file: `skills/liquefy-openclaw/SKILL.md`

## What this publish gives users

- a standalone ClawHub skill install
- instructions and references for using Liquefy with OpenClaw
- no bundled Liquefy CLI runtime
- no bundled npm plugin package

Users still need Liquefy installed locally on the host machine.

## Publish commands

Official ClawHub publish flow:

```bash
clawhub publish ./skills/liquefy-openclaw \
  --slug liquefy-openclaw \
  --name "Liquefy OpenClaw" \
  --version 1.1.0 \
  --changelog "Initial public standalone skill release for Liquefy OpenClaw workflows." \
  --tags latest,openclaw,security,tracevault
```

Optional bulk path:

```bash
clawhub sync --root ./skills --all --tags latest
```

## Recommended listing posture

- keep the slug identical to the skill name: `liquefy-openclaw`
- describe it as a standalone skill for OpenClaw users who already have Liquefy installed
- point users to the separate plugin package only as an optional acceleration path

## Pre-publish checks

1. Validate the skill bundle locally.
2. Confirm the skill text does not assume plugin-only tools.
3. Confirm install docs clearly state that Liquefy CLI is a separate local dependency.
4. Publish with a real semver version and changelog.
