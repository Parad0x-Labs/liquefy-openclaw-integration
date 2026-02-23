# Security Policy

## Supported Security Posture

This repository is under active development. Security fixes are applied to the current `master` branch first.

Current notable protections:
- LSEC v2 AEAD encryption (`AES-256-GCM`) with authenticated headers (AAD)
- Fail-closed secret handling (no hardcoded fallback encryption secrets)
- Path safety policy for OpenClaw/TraceVault wrappers (denylist + explicit risky override phrase)
- Output permission hardening (`0600` files / `0700` directories where supported)
- CI benchmark regression gates and CLI JSON contract tests

## Reporting a Vulnerability

Please do not open public issues for suspected security vulnerabilities.

Send a report to:
- `hello@parad0xlabs.com`

Include:
- affected file(s) / command(s)
- proof of concept or reproduction steps
- impact assessment (data disclosure, path traversal, integrity bypass, DoS, etc.)
- environment details (OS, Python version)

We will acknowledge receipt and triage as quickly as possible.

## Scope

High-priority reports include:
- encryption/authentication bypasses
- path traversal / symlink escape in pack/restore flows
- secret leakage in logs, JSON output, or reports
- denial-of-service inputs causing unbounded memory/CPU in default paths

## Non-Goals / Known Constraints

- Performance regressions are handled through benchmark gates, not this process
- Legacy blob backward compatibility is intentionally not guaranteed (LSEC v2 only)
- Third-party ecosystem plugins (not maintained in this repo) are out of scope unless the issue is in Liquefy CLI/API contracts
