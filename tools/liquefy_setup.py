#!/usr/bin/env python3
"""
liquefy_setup.py
================
Interactive setup wizard + "quick" one-command entry point.

Commands:
    (no args)     — Interactive setup wizard: walks through config, writes ~/.liquefy/config.json
    quick <DIR>   — One-command "just do the right thing" for any directory

The wizard is designed to be run by AI agents OR humans. Every prompt has
a default, and JSON mode is available for programmatic use.

Usage:
    python tools/liquefy_setup.py                                    # Interactive wizard
    python tools/liquefy_setup.py quick ./data                       # Quick compress
    python tools/liquefy_setup.py quick ./data --preset power --json # Quick with preset
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

CONFIG_DIR = Path.home() / ".liquefy"
CONFIG_FILE = CONFIG_DIR / "config.json"
CLI_SCHEMA_VERSION = "liquefy.setup.cli.v1"

PRESETS = {
    "safe": {
        "description": "Maximum security, balanced speed (recommended for production)",
        "profile": "default",
        "verify_mode": "full",
        "policy_mode": "strict",
        "secure": False,
        "prune": False,
        "include_secrets": False,
    },
    "power": {
        "description": "Faster compression, relaxed policy, sampled verification",
        "profile": "speed",
        "verify_mode": "fast",
        "policy_mode": "balanced",
        "secure": False,
        "prune": False,
        "include_secrets": False,
    },
    "yolo": {
        "description": "Everything included, max ratio, your responsibility",
        "profile": "ratio",
        "verify_mode": "full",
        "policy_mode": "off",
        "secure": False,
        "prune": False,
        "include_secrets": True,
    },
}

AI_TIPS = [
    "Tip: Use --json on any command for machine-readable output.",
    "Tip: AGENTS.md in the repo root has copy-paste-ready commands.",
    "Tip: 'make quick DIR=./data' is the fastest path to compression.",
    "Tip: LeakHunter scans for 25+ secret patterns including OpenAI/Anthropic keys.",
    "Tip: The archiver daemon auto-cleans old data on a schedule.",
    "Tip: 'make viz-web VAULT=./vault' gives you a dark-mode dashboard.",
    "Tip: Every vault is searchable without decompression: 'make search VAULT=./vault Q=error'.",
    "Tip: Obsidian sync creates dataview-ready notes from your vaults.",
    "Tip: Sandbox any untrusted skill before installing: 'make sandbox SKILL=./skill'.",
    "Tip: Set LIQUEFY_SECRET env var to enable AES-256-GCM encryption on all vaults.",
]


def _prompt(question: str, default: str = "", choices: Optional[List[str]] = None) -> str:
    """Interactive prompt with default value."""
    if choices:
        options = "/".join(f"[{c}]" if c == default else c for c in choices)
        prompt_text = f"  {question} ({options}): "
    elif default:
        prompt_text = f"  {question} [{default}]: "
    else:
        prompt_text = f"  {question}: "

    try:
        answer = input(prompt_text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default

    if not answer:
        return default
    if choices and answer not in choices:
        print(f"    Invalid choice. Using default: {default}")
        return default
    return answer


def _generate_secret() -> str:
    return secrets.token_urlsafe(32)


def _load_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_config(config: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    if os.name != "nt":
        try:
            CONFIG_FILE.chmod(0o600)
        except OSError:
            pass


def wizard() -> int:
    """Interactive setup wizard."""
    import random

    existing = _load_config()

    print()
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║   Liquefy Setup Wizard                    ║")
    print("  ╚═══════════════════════════════════════════╝")
    print()
    print(f"  {random.choice(AI_TIPS)}")
    print()

    # Step 1: Preset
    print("  STEP 1: Choose your risk tolerance")
    print()
    for name, preset in PRESETS.items():
        marker = " *" if name == existing.get("preset", "safe") else ""
        print(f"    {name:8s} — {preset['description']}{marker}")
    print()
    preset_name = _prompt("Preset", existing.get("preset", "safe"), list(PRESETS.keys()))
    preset = PRESETS[preset_name].copy()

    # Step 2: Watch directories
    print()
    print("  STEP 2: What directories should Liquefy watch?")
    print("  (comma-separated, or press Enter for defaults)")
    print()
    default_watch = existing.get("watch_root", "~/.openclaw")
    watch_root = _prompt("Watch root", default_watch)

    default_subdirs = existing.get("subdirs", "sessions,memory,artifacts")
    subdirs = _prompt("Subdirectories (comma-separated)", default_subdirs)

    # Step 3: Output
    print()
    print("  STEP 3: Where should vaults be stored?")
    print()
    default_out = existing.get("vault_dir", "~/.liquefy/vault")
    vault_dir = _prompt("Vault directory", default_out)

    # Step 4: Encryption
    print()
    print("  STEP 4: Enable encryption? (AES-256-GCM, tenant-isolated)")
    print()
    encrypt = _prompt("Enable encryption", existing.get("encrypt", "no"), ["yes", "no"])
    secret = ""
    if encrypt == "yes":
        existing_secret = os.environ.get("LIQUEFY_SECRET", "")
        if existing_secret:
            print("    LIQUEFY_SECRET env var detected. Using it.")
            secret = existing_secret
        else:
            gen = _prompt("Generate a new secret?", "yes", ["yes", "no"])
            if gen == "yes":
                secret = _generate_secret()
                print(f"    Generated secret (save this somewhere safe):")
                print(f"    export LIQUEFY_SECRET=\"{secret}\"")
            else:
                secret = _prompt("Enter your secret (min 16 chars)")

    # Step 5: Notifications
    print()
    print("  STEP 5: Notifications (for archiver daemon)")
    print()
    notify = _prompt("Channels (comma-separated: stdout,telegram,discord)",
                     existing.get("notify", "stdout"))

    # Step 6: Archiver settings
    print()
    print("  STEP 6: Archiver thresholds")
    print()
    size_mb = _prompt("Archive files larger than (MB)", str(existing.get("size_threshold_mb", 50)))
    age_days = _prompt("Archive files older than (days)", str(existing.get("age_threshold_days", 7)))
    keep = _prompt("Keep N most recent items active", str(existing.get("keep_active", 5)))
    prune = _prompt("Delete originals after verified archive?",
                    "yes" if existing.get("prune", False) else "no", ["yes", "no"])

    # Build config
    config = {
        "schema_version": CLI_SCHEMA_VERSION,
        "preset": preset_name,
        "profile": preset["profile"],
        "verify_mode": preset["verify_mode"],
        "policy_mode": preset["policy_mode"],
        "watch_root": watch_root,
        "subdirs": subdirs,
        "vault_dir": vault_dir,
        "encrypt": encrypt == "yes",
        "notify": notify,
        "size_threshold_mb": int(size_mb),
        "age_threshold_days": int(age_days),
        "keep_active": int(keep),
        "prune": prune == "yes",
    }

    _save_config(config)

    print()
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║   Configuration Saved                     ║")
    print("  ╚═══════════════════════════════════════════╝")
    print()
    print(f"  Config: {CONFIG_FILE}")
    print(f"  Preset: {preset_name} — {preset['description']}")
    print()
    print("  Next steps:")
    print(f"    make quick DIR={watch_root}              # Compress now")
    print(f"    make daemon DIR={watch_root}             # Start auto-archiver")
    print(f"    make leak-scan DIR={watch_root}          # Scan for secrets")
    print()

    if encrypt == "yes" and secret and not os.environ.get("LIQUEFY_SECRET"):
        print("  IMPORTANT: Set your encryption secret:")
        print(f"    export LIQUEFY_SECRET=\"{secret}\"")
        print("    (Add to your shell profile for persistence)")
        print()

    return 0


# ── Quick Command ──


def cmd_quick(args: argparse.Namespace) -> int:
    """One-command 'just do the right thing' for any directory."""
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    config = _load_config()
    preset_name = getattr(args, "preset", None) or config.get("preset", "safe")
    preset = PRESETS.get(preset_name, PRESETS["safe"])

    profile = getattr(args, "profile", None) or preset["profile"]
    verify_mode = getattr(args, "verify_mode", None) or preset["verify_mode"]
    policy_mode = getattr(args, "mode", None) or preset["policy_mode"]
    vault_dir = config.get("vault_dir", "~/.liquefy/vault")
    out_dir = Path(getattr(args, "out", None) or vault_dir).expanduser().resolve() / target.name

    is_json = getattr(args, "json", False)

    if not is_json:
        import random
        print()
        print(f"  Liquefy Quick — {preset_name.upper()} preset")
        print(f"  {random.choice(AI_TIPS)}")
        print()
        print(f"  Source:  {target}")
        print(f"  Output:  {out_dir}")
        print(f"  Profile: {profile} | Verify: {verify_mode} | Policy: {policy_mode}")
        print()

    # Step 1: Leak scan
    if not is_json:
        print("  [1/3] Scanning for secrets...")

    leak_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "liquefy_leakhunter.py"),
        "scan", str(target), "--deep", "--json",
    ]
    try:
        leak_result = subprocess.run(leak_cmd, capture_output=True, text=True, timeout=120,
                                     env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}"})
        leak_data = json.loads(leak_result.stdout) if leak_result.stdout.strip() else {}
        leak_findings = leak_data.get("result", {}).get("total_findings", 0)
        leak_critical = leak_data.get("result", {}).get("critical", 0)
    except Exception:
        leak_findings = 0
        leak_critical = 0

    if not is_json:
        if leak_critical > 0:
            print(f"  *** {leak_critical} CRITICAL secrets found! Review before proceeding. ***")
            if policy_mode == "strict":
                print(f"  (strict mode: these files will be excluded)")
        elif leak_findings > 0:
            print(f"  {leak_findings} potential findings (non-critical)")
        else:
            print(f"  Clean — no secrets detected")
        print()

    # Step 2: Pack
    if not is_json:
        print("  [2/3] Compressing...")

    pack_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(target),
        "--out", str(out_dir),
        "--org", "default",
        "--profile", profile,
        "--verify-mode", verify_mode,
        "--mode", policy_mode,
        "--json",
    ]

    if preset.get("include_secrets"):
        pack_cmd.extend(["--include-secrets", "I UNDERSTAND THIS MAY LEAK SECRETS"])

    encrypt = config.get("encrypt", False) or getattr(args, "secure", False)
    if encrypt:
        secret = os.environ.get("LIQUEFY_SECRET", "")
        if secret:
            pack_cmd.extend(["--secret", secret])

    try:
        pack_result = subprocess.run(
            pack_cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}", "LIQUEFY_PROFILE": profile},
        )
        pack_data = json.loads(pack_result.stdout) if pack_result.stdout.strip() else {}
    except Exception as exc:
        if is_json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"  ERROR: {exc}")
        return 1

    pack_ok = pack_data.get("ok", False)
    result = pack_data.get("result", {})

    raw_bytes = result.get("total_original_bytes", 0)
    comp_bytes = result.get("total_compressed_bytes", 0)
    ratio = raw_bytes / max(1, comp_bytes)
    files = result.get("total_files_processed", result.get("files_processed", 0))

    # Step 3: Summary
    if not is_json:
        print(f"  [3/3] Done!")
        print()
        if pack_ok:
            print(f"  ╔═══════════════════════════════════════════╗")
            print(f"  ║   Vault Created Successfully              ║")
            print(f"  ╚═══════════════════════════════════════════╝")
            print()
            print(f"  Files:      {files}")
            print(f"  Raw:        {_fmt(raw_bytes)}")
            print(f"  Compressed: {_fmt(comp_bytes)}")
            print(f"  Ratio:      {ratio:.1f}x ({(1 - comp_bytes / max(1, raw_bytes)) * 100:.0f}% saved)")
            print(f"  Vault:      {out_dir}")
            if leak_findings > 0:
                print(f"  Leaks:      {leak_findings} findings ({leak_critical} critical)")
            print()
            print(f"  Restore:    make restore SRC={out_dir}")
            print(f"  Search:     make search VAULT={out_dir} Q=keyword")
            print(f"  Visualize:  make viz VAULT={out_dir}")
        else:
            print(f"  Pack failed. Check: {pack_result.stderr[:300] if pack_result.stderr else 'unknown error'}")
        print()
    else:
        output = {
            "schema_version": CLI_SCHEMA_VERSION,
            "command": "quick",
            "ok": pack_ok,
            "preset": preset_name,
            "result": {
                "source": str(target),
                "vault": str(out_dir),
                "files": files,
                "raw_bytes": raw_bytes,
                "compressed_bytes": comp_bytes,
                "ratio": round(ratio, 2),
                "verify_mode": verify_mode,
                "policy_mode": policy_mode,
                "profile": profile,
                "leak_findings": leak_findings,
                "leak_critical": leak_critical,
            },
        }
        print(json.dumps(output, indent=2))

    return 0 if pack_ok else 1


def _fmt(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-setup", description="Liquefy Setup Wizard + Quick Command")
    sub = ap.add_subparsers(dest="command")

    p_quick = sub.add_parser("quick", help="One-command compress any directory")
    p_quick.add_argument("target", help="Directory or file to compress")
    p_quick.add_argument("--preset", choices=["safe", "power", "yolo"], default=None)
    p_quick.add_argument("--profile", choices=["default", "ratio", "speed"], default=None)
    p_quick.add_argument("--verify-mode", choices=["full", "fast", "off"], default=None)
    p_quick.add_argument("--mode", choices=["strict", "balanced", "off"], default=None)
    p_quick.add_argument("--out", default=None, help="Override output directory")
    p_quick.add_argument("--secure", action="store_true", help="Enable encryption")
    p_quick.add_argument("--json", action="store_true")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        return wizard()

    if args.command == "quick":
        return cmd_quick(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
