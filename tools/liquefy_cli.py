#!/usr/bin/env python3
"""
liquefy_cli.py
==============
Unified Python-first CLI for all Liquefy operations.

    liquefy pack       — Pack OpenClaw workspace into vault
    liquefy openclaw   — OpenClaw workspace scan/pack/guarded run
    liquefy restore    — Restore files from vault
    liquefy search     — Search across vaults
    liquefy policy     — Policy enforcement (audit/enforce/kill)
    liquefy safe-run   — Snapshot -> run -> enforce -> auto-rollback
    liquefy cas        — Content-addressed storage (ingest/restore/gc)
    liquefy tokens     — Token ledger (scan/budget/report/audit)
    liquefy telemetry  — Forward audit events to SIEM
    liquefy guard      — Config Guard (save/restore/diff)
    liquefy capsule    — Build compact context capsules from raw traces
    liquefy context-gate — Compile bounded runtime context and replay guard
    liquefy anchor     — On-chain vault integrity proofs
    liquefy events     — Agent event trace operations
    liquefy status     — Overall system status

Also importable as a library:
    from liquefy_cli import pack, restore, search, policy, cas
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path

from cli_runtime import doctor_checks_common, resolve_repo_root, self_test_core, version_result

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"

for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)


SUBCOMMAND_MAP = {
    "pack":      ("liquefy_openclaw",         "main",     "Pack OpenClaw workspace into vault"),
    "openclaw":  ("liquefy_openclaw",         "main",     "OpenClaw workspace scan/pack/guarded run"),
    "restore":   ("tracevault_restore",        "main",     "Restore files from vault"),
    "search":    ("liquefy_search",            "main",     "Search across vaults"),
    "agents":    ("liquefy_agents",            "main",     "Agent templates, interaction maps, scaffolding"),
    "policy":    ("liquefy_policy_enforcer",   "main",     "Policy enforcement (audit/enforce/kill/watch)"),
    "safe-run":  ("liquefy_safe_run",          "main",     "Snapshot -> run -> enforce -> auto-rollback"),
    "cas":       ("liquefy_cas",               "main",     "Content-addressed storage (ingest/restore/gc)"),
    "tokens":    ("liquefy_token_ledger",      "main",     "Token ledger (scan/budget/report/audit)"),
    "telemetry": ("liquefy_telemetry_forward", "main",     "Forward audit events to SIEM"),
    "guard":     ("liquefy_config_guard",      "main",     "Config Guard (save/restore/diff)"),
    "state-guard": ("liquefy_state_guard",     "main",     "State Guard (init/check/checkpoint/recover)"),
    "history-guard": ("liquefy_history_guard", "main",     "Continuous pull + anti-nuke action gating"),
    "redact":    ("liquefy_redact",            "main",     "PII/secret redaction before LLM ingestion"),
    "denoise":   ("liquefy_denoise",           "main",     "Log de-noising for context window optimization"),
    "capsule":   ("liquefy_context_capsule",   "main",     "Build compact context capsules from raw traces"),
    "context-gate": ("liquefy_context_gate",   "main",     "Compile bounded runtime context and replay guard"),
    "anchor":    ("liquefy_vault_anchor",      "main",     "On-chain vault integrity proofs"),
    "events":    ("liquefy_events",            "main",     "Agent event trace operations"),
    "vision":    ("liquefy_vision",            "main",     "Vision dedup engine"),
    "cloud":     ("liquefy_cloud_sync",        "main",     "Encrypted cloud sync"),
    "fleet":     ("liquefy_fleet_cli",         "main",     "Fleet management"),
    "sign":      ("liquefy_sign",              "main",     "Vault signing and verification"),
}


def _version() -> str:
    try:
        toml_path = REPO_ROOT / "pyproject.toml"
        if toml_path.exists():
            for line in toml_path.read_text().splitlines():
                if line.strip().startswith("version"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "dev"


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in SUBCOMMAND_MAP:
        subcmd = sys.argv[1]
        module_name, func_name, _ = SUBCOMMAND_MAP[subcmd]

        sys.argv = [f"liquefy {subcmd}"] + sys.argv[2:]

        try:
            mod = importlib.import_module(module_name)
            fn = getattr(mod, func_name)
            result = fn()
            sys.exit(result if isinstance(result, int) else 0)
        except SystemExit as e:
            sys.exit(e.code)
        except ImportError as e:
            print(f"Error: module '{module_name}' not found — {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif len(sys.argv) >= 2 and sys.argv[1] in ("version", "--version", "self-test", "doctor"):
        import json as _json
        raw_cmd = sys.argv[1]
        cmd = "version" if raw_cmd == "--version" else raw_cmd
        if cmd == "version":
            result = version_result(tool="liquefy", repo_root=REPO_ROOT)
        elif cmd == "self-test":
            result = self_test_core(tool="liquefy", repo_root=REPO_ROOT)
        else:
            result = doctor_checks_common(tool="liquefy", repo_root=REPO_ROOT, api_dir=REPO_ROOT / "api")
        if "--json" in sys.argv:
            print(_json.dumps({
                "schema_version": "liquefy.cli.v1",
                "tool": "liquefy",
                "command": cmd.replace("-", "_"),
                "ok": True,
                "result": result,
            }, indent=2))
        elif cmd == "version":
            print(f"liquefy {_version()}")
        else:
            print(_json.dumps(result, indent=2))
        return

    else:
        print(f"liquefy {_version()} — Local-First Agent Vault & Security Layer")
        print()
        print("Usage:  liquefy <command> [options]")
        print()
        print("Commands:")

        max_name = max(len(n) for n in SUBCOMMAND_MAP)
        for name, (_, _, desc) in SUBCOMMAND_MAP.items():
            print(f"  {name:<{max_name + 2}} {desc}")

        print()
        print("Run 'liquefy <command> --help' for detailed usage.")
        print()
        print("Environment:")
        print("  LIQUEFY_SECRET       Encryption key for secure vaults")
        print("  LIQUEFY_TRACE_ID     Correlation ID for multi-agent chains")
        print("  LIQUEFY_CAS_DIR      Content-addressed storage directory")
        print("  LIQUEFY_AUDIT_DIR    Audit chain directory")
        sys.exit(2)


if __name__ == "__main__":
    main()
