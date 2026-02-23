#!/usr/bin/env python3
"""Unified Liquefy CLI dispatcher for packaged releases."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Dict, Optional

from cli_runtime import doctor_checks_common, resolve_repo_root, self_test_core, version_result


CLI_SCHEMA_VERSION = "liquefy.cli.v1"
REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)


def _emit_json(payload: Dict, enabled: bool, json_file: Optional[Path]) -> None:
    if json_file:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if sys.platform != "win32":
            try:
                json_file.chmod(0o600)
            except OSError:
                pass
    if enabled:
        print(json.dumps(payload, indent=2))


def _runtime_main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="liquefy", description="Liquefy unified CLI")
    sub = ap.add_subparsers(dest="command")

    for name in ("version", "self-test", "doctor"):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")
        p.add_argument("--json-file", default=None)

    args, extra = ap.parse_known_args(argv)
    if extra:
        raise SystemExit(f"Unexpected arguments for '{args.command}': {' '.join(extra)}")

    enabled_json = bool(getattr(args, "json", False))
    json_file = Path(args.json_file).resolve() if getattr(args, "json_file", None) else None

    if args.command == "version":
        result = version_result(tool="liquefy", repo_root=REPO_ROOT)
        payload = {"schema_version": CLI_SCHEMA_VERSION, "tool": "liquefy", "command": "version", "ok": True, "result": result}
        _emit_json(payload, enabled_json, json_file)
        if not enabled_json:
            build = result.get("build", {})
            print(f"liquefy {build.get('liquefy_version','dev')} ({build.get('system','?')}/{build.get('machine','?')})")
        return 0

    if args.command == "self-test":
        result = self_test_core(tool="liquefy", repo_root=REPO_ROOT)
        ok = bool(result.get("summary", {}).get("ok"))
        payload = {"schema_version": CLI_SCHEMA_VERSION, "tool": "liquefy", "command": "self_test", "ok": ok, "result": result}
        _emit_json(payload, enabled_json, json_file)
        if not enabled_json:
            summary = result.get("summary", {})
            print(f"[self-test] ok={summary.get('ok')} passed={summary.get('checks_passed')}/{summary.get('checks_total')}")
        return 0 if ok else 1

    if args.command == "doctor":
        result = doctor_checks_common(tool="liquefy", repo_root=REPO_ROOT, api_dir=REPO_ROOT / "api", require_secret=False)
        ok = bool(result.get("summary", {}).get("ok"))
        payload = {"schema_version": CLI_SCHEMA_VERSION, "tool": "liquefy", "command": "doctor", "ok": ok, "result": result}
        _emit_json(payload, enabled_json, json_file)
        if not enabled_json:
            summary = result.get("summary", {})
            print(
                f"[doctor] ok={summary.get('ok')} "
                f"passed={summary.get('checks_passed')}/{summary.get('checks_total')} "
                f"errors={summary.get('errors')} warnings={summary.get('warnings')}"
            )
        return 0 if ok else 1

    raise SystemExit("Unknown runtime command")


def _dispatch_script(module_name: str, argv: list[str]) -> int:
    mod = importlib.import_module(module_name)
    old_argv = sys.argv[:]
    try:
        sys.argv = [old_argv[0]] + argv
        mod.main()
        return 0
    finally:
        sys.argv = old_argv


def main() -> None:
    if len(sys.argv) <= 1:
        print(
            "Usage: liquefy <openclaw|tracevault-pack|tracevault-restore|version|self-test|doctor> [args...]\n"
            "Aliases: pack=tracevault-pack, restore=tracevault-restore"
        )
        raise SystemExit(2)

    cmd = sys.argv[1]
    rest = sys.argv[2:]

    if cmd in {"version", "self-test", "doctor"}:
        raise SystemExit(_runtime_main(sys.argv[1:]))

    mapping = {
        "openclaw": "liquefy_openclaw",
        "tracevault-pack": "tracevault_pack",
        "tracevault-restore": "tracevault_restore",
        "pack": "tracevault_pack",
        "restore": "tracevault_restore",
    }
    module_name = mapping.get(cmd)
    if not module_name:
        raise SystemExit(f"Unknown command: {cmd}")
    raise SystemExit(_dispatch_script(module_name, rest))


if __name__ == "__main__":
    main()
