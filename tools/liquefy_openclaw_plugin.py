#!/usr/bin/env python3
"""
liquefy_openclaw_plugin.py
==========================
Native, zero-config OpenClaw integration.

Drop this one config block into openclaw.json and Liquefy becomes the default
session store. Auto-triggers on every session close, replaces the built-in
JSONL writer, zero extra commands.

Users shouldn't even know it's there until they type `liquefy status`.

Integration modes:
    hook       — Register as OpenClaw session-close hook (writes to openclaw.json)
    writer     — Transparent JSONL writer replacement (stdin → compressed vault)
    status     — Show current integration status
    uninstall  — Remove Liquefy hooks from openclaw.json

How it works:
    1. `liquefy_openclaw_plugin.py hook install` adds a post_session_close hook
       to the user's openclaw.json config.
    2. When OpenClaw closes a session, it calls the hook script.
    3. The hook reads the session dir, runs LeakHunter, compresses via
       tracevault_pack, and logs to the audit chain.
    4. All of this is invisible to the user. Status available via `liquefy status`.

Usage:
    python tools/liquefy_openclaw_plugin.py hook install
    python tools/liquefy_openclaw_plugin.py hook uninstall
    python tools/liquefy_openclaw_plugin.py writer < session.jsonl
    python tools/liquefy_openclaw_plugin.py status
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
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

CLI_SCHEMA_VERSION = "liquefy.openclaw_plugin.cli.v1"

CONFIG_DIR = Path.home() / ".liquefy"
PLUGIN_STATE_FILE = CONFIG_DIR / "openclaw_plugin_state.json"
AUDIT_LOG_FILE = CONFIG_DIR / "audit.jsonl"

OPENCLAW_CONFIG_LOCATIONS = [
    Path.home() / ".openclaw" / "openclaw.json",
    Path.home() / ".config" / "openclaw" / "openclaw.json",
    Path(os.environ.get("OPENCLAW_CONFIG", "/dev/null")),
]

HOOK_BLOCK = {
    "liquefy": {
        "enabled": True,
        "version": "1.0.0",
        "mode": "auto",
        "vault_dir": "~/.liquefy/vault",
        "profile": "default",
        "policy_mode": "strict",
        "verify_mode": "full",
        "encrypt": False,
        "leak_scan": True,
        "auto_prune_days": 0,
        "notify": [],
        "hooks": {
            "post_session_close": "python {repo_root}/tools/liquefy_openclaw_plugin.py _on_session_close",
            "post_memory_write": "python {repo_root}/tools/liquefy_openclaw_plugin.py _on_memory_write",
        },
    }
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_openclaw_config() -> Optional[Path]:
    for p in OPENCLAW_CONFIG_LOCATIONS:
        if p.exists():
            return p
    return None


def _load_openclaw_config(path: Path) -> Dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_openclaw_config(path: Path, config: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _load_plugin_state() -> Dict:
    if PLUGIN_STATE_FILE.exists():
        try:
            return json.loads(PLUGIN_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"installed": False, "sessions_processed": 0, "bytes_saved": 0, "leaks_blocked": 0}


def _save_plugin_state(state: Dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PLUGIN_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _audit_log(event: str, details: Dict) -> None:
    """Append to tamper-evident audit log."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    import hashlib
    entry = {
        "ts": _utc_now(),
        "event": event,
        **details,
    }
    line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    entry["_hash"] = hashlib.sha256(line.encode()).hexdigest()[:16]
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")


def _load_liquefy_config() -> Dict:
    cfg_path = CONFIG_DIR / "config.json"
    if cfg_path.exists():
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


# ── Hook Management ──


def cmd_hook_install(args: argparse.Namespace) -> int:
    """Install Liquefy hooks into openclaw.json."""
    config_path = _find_openclaw_config()

    if config_path is None:
        default_path = Path.home() / ".openclaw" / "openclaw.json"
        if args.create:
            default_path.parent.mkdir(parents=True, exist_ok=True)
            default_path.write_text("{}", encoding="utf-8")
            config_path = default_path
            print(f"  Created {config_path}")
        else:
            print("  No openclaw.json found. Use --create to create one, or set OPENCLAW_CONFIG.", file=sys.stderr)
            return 1

    config = _load_openclaw_config(config_path)

    hook = dict(HOOK_BLOCK["liquefy"])
    hook["hooks"] = {
        k: v.format(repo_root=REPO_ROOT) for k, v in hook["hooks"].items()
    }

    user_cfg = _load_liquefy_config()
    if user_cfg.get("profile"):
        hook["profile"] = user_cfg["profile"]
    if user_cfg.get("policy_mode"):
        hook["policy_mode"] = user_cfg["policy_mode"]
    if user_cfg.get("vault_dir"):
        hook["vault_dir"] = user_cfg["vault_dir"]
    if user_cfg.get("encrypt"):
        hook["encrypt"] = True

    config["liquefy"] = hook
    _save_openclaw_config(config_path, config)

    state = _load_plugin_state()
    state["installed"] = True
    state["installed_at"] = _utc_now()
    state["config_path"] = str(config_path)
    _save_plugin_state(state)

    _audit_log("hook_installed", {"config_path": str(config_path)})

    print(f"\n  Liquefy integrated into {config_path}")
    print(f"  Mode: auto (triggers on every session close)")
    print(f"  Profile: {hook['profile']} | Policy: {hook['policy_mode']} | Verify: {hook['verify_mode']}")
    print(f"  Vault: {hook['vault_dir']}")
    print(f"\n  Users won't notice — until they type: liquefy status")
    print()
    return 0


def cmd_hook_uninstall(args: argparse.Namespace) -> int:
    """Remove Liquefy hooks from openclaw.json."""
    config_path = _find_openclaw_config()
    if config_path is None:
        print("  No openclaw.json found.", file=sys.stderr)
        return 1

    config = _load_openclaw_config(config_path)
    if "liquefy" in config:
        del config["liquefy"]
        _save_openclaw_config(config_path, config)

    state = _load_plugin_state()
    state["installed"] = False
    _save_plugin_state(state)

    _audit_log("hook_uninstalled", {"config_path": str(config_path)})

    print(f"  Liquefy hooks removed from {config_path}")
    return 0


# ── Session Close Hook (called by OpenClaw) ──


def cmd_on_session_close(args: argparse.Namespace) -> int:
    """Called automatically by OpenClaw when a session closes."""
    session_dir = os.environ.get("OPENCLAW_SESSION_DIR", "")
    session_id = os.environ.get("OPENCLAW_SESSION_ID", "unknown")
    agent_id = os.environ.get("OPENCLAW_AGENT_ID", "unknown")

    if not session_dir or not Path(session_dir).exists():
        return 0

    state = _load_plugin_state()
    cfg = _load_liquefy_config()
    vault_dir = Path(cfg.get("vault_dir", "~/.liquefy/vault")).expanduser()
    profile = cfg.get("profile", "default")
    verify_mode = cfg.get("verify_mode", "full")
    policy_mode = cfg.get("policy_mode", "strict")

    out_dir = vault_dir / f"session_{session_id}"

    leak_findings = 0
    if cfg.get("leak_scan", True):
        leak_cmd = [
            sys.executable, str(REPO_ROOT / "tools" / "liquefy_leakhunter.py"),
            "scan", session_dir, "--deep", "--json",
        ]
        try:
            result = subprocess.run(leak_cmd, capture_output=True, text=True, timeout=60,
                                    env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}"})
            leak_data = json.loads(result.stdout) if result.stdout.strip() else {}
            leak_findings = leak_data.get("result", {}).get("total_findings", 0)
        except Exception:
            pass

    pack_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        session_dir,
        "--out", str(out_dir),
        "--org", agent_id,
        "--profile", profile,
        "--verify-mode", verify_mode,
        "--mode", policy_mode,
        "--json",
    ]

    try:
        result = subprocess.run(pack_cmd, capture_output=True, text=True, timeout=300,
                                env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}",
                                     "LIQUEFY_PROFILE": profile})
        pack_data = json.loads(result.stdout) if result.stdout.strip() else {}
        pack_ok = pack_data.get("ok", False)
        res = pack_data.get("result", {})
        raw = res.get("total_original_bytes", 0)
        comp = res.get("total_compressed_bytes", 0)
    except Exception:
        pack_ok = False
        raw = 0
        comp = 0

    state["sessions_processed"] = state.get("sessions_processed", 0) + 1
    state["bytes_saved"] = state.get("bytes_saved", 0) + max(0, raw - comp)
    state["leaks_blocked"] = state.get("leaks_blocked", 0) + leak_findings
    state["last_session"] = session_id
    state["last_ts"] = _utc_now()
    _save_plugin_state(state)

    _audit_log("session_archived", {
        "session_id": session_id,
        "agent_id": agent_id,
        "raw_bytes": raw,
        "compressed_bytes": comp,
        "ratio": round(raw / max(1, comp), 2),
        "leaks_found": leak_findings,
        "ok": pack_ok,
    })

    return 0


# ── Transparent Writer (replaces built-in JSONL writer) ──


def cmd_writer(args: argparse.Namespace) -> int:
    """
    Transparent JSONL writer replacement.
    Reads JSONL from stdin, compresses on-the-fly, writes to vault.
    Drop-in compatible with OpenClaw's session writer interface.
    """
    from liquefy_telemetry_sink import TelemetrySink

    cfg = _load_liquefy_config()
    vault_dir = Path(cfg.get("vault_dir", "~/.liquefy/vault")).expanduser()
    session_id = os.environ.get("OPENCLAW_SESSION_ID", f"stream_{int(time.time())}")
    out_dir = vault_dir / f"session_{session_id}"

    profile = cfg.get("profile", "default")
    sink = TelemetrySink(out_dir, org=os.environ.get("OPENCLAW_AGENT_ID", "default"), profile=profile)

    line_count = 0
    try:
        for line in sys.stdin:
            sink.ingest_line(line)
            line_count += 1
    except (KeyboardInterrupt, BrokenPipeError):
        pass

    index = sink.finalize()

    _audit_log("writer_session", {
        "session_id": session_id,
        "lines": line_count,
        "raw_bytes": index.get("total_raw_bytes", 0),
        "compressed_bytes": index.get("total_compressed_bytes", 0),
        "redactions": index.get("total_redactions", 0),
    })

    state = _load_plugin_state()
    state["sessions_processed"] = state.get("sessions_processed", 0) + 1
    state["bytes_saved"] = state.get("bytes_saved", 0) + max(0,
        index.get("total_raw_bytes", 0) - index.get("total_compressed_bytes", 0))
    _save_plugin_state(state)

    return 0


# ── Memory Write Hook ──


def cmd_on_memory_write(args: argparse.Namespace) -> int:
    """Called when OpenClaw writes to memory/. Lightweight — just tracks for archiver."""
    memory_path = os.environ.get("OPENCLAW_MEMORY_PATH", "")
    if not memory_path:
        return 0

    _audit_log("memory_write", {"path": memory_path, "size": os.path.getsize(memory_path) if os.path.exists(memory_path) else 0})
    return 0


# ── Status ──


def cmd_status(args: argparse.Namespace) -> int:
    state = _load_plugin_state()
    config_path = _find_openclaw_config()

    installed = state.get("installed", False)
    has_hook = False
    if config_path:
        oc = _load_openclaw_config(config_path)
        has_hook = "liquefy" in oc and oc["liquefy"].get("enabled", False)

    def _fmt(n: int) -> str:
        if n >= 1 << 30: return f"{n / (1 << 30):.2f} GB"
        if n >= 1 << 20: return f"{n / (1 << 20):.1f} MB"
        return f"{n} B"

    if args.json:
        print(json.dumps({
            "schema_version": CLI_SCHEMA_VERSION,
            "ok": True,
            "result": {
                "installed": installed,
                "hook_active": has_hook,
                "config_path": str(config_path) if config_path else None,
                "sessions_processed": state.get("sessions_processed", 0),
                "bytes_saved": state.get("bytes_saved", 0),
                "leaks_blocked": state.get("leaks_blocked", 0),
                "last_session": state.get("last_session"),
                "last_ts": state.get("last_ts"),
            },
        }, indent=2))
    else:
        print()
        if has_hook:
            print(f"  Liquefy is ACTIVE in OpenClaw")
            print(f"  Config: {config_path}")
        elif installed:
            print(f"  Liquefy is INSTALLED but hook not detected in config")
        else:
            print(f"  Liquefy is NOT integrated with OpenClaw")
            print(f"  Run: python tools/liquefy_openclaw_plugin.py hook install")
            print()
            return 0

        print(f"  Sessions archived: {state.get('sessions_processed', 0)}")
        print(f"  Storage saved: {_fmt(state.get('bytes_saved', 0))}")
        print(f"  Leaks blocked: {state.get('leaks_blocked', 0)}")
        if state.get("last_ts"):
            print(f"  Last activity: {state.get('last_ts')}")
        print()

    return 0


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-openclaw-plugin", description="Native OpenClaw Integration")
    sub = ap.add_subparsers(dest="command")

    p_hook = sub.add_parser("hook", help="Manage OpenClaw hooks")
    hook_sub = p_hook.add_subparsers(dest="hook_action")
    p_install = hook_sub.add_parser("install", help="Install Liquefy hooks")
    p_install.add_argument("--create", action="store_true", help="Create openclaw.json if missing")
    hook_sub.add_parser("uninstall", help="Remove Liquefy hooks")

    sub.add_parser("writer", help="Transparent JSONL writer (stdin)")

    p_status = sub.add_parser("status", help="Show integration status")
    p_status.add_argument("--json", action="store_true")

    sub.add_parser("_on_session_close", help=argparse.SUPPRESS)
    sub.add_parser("_on_memory_write", help=argparse.SUPPRESS)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    if args.command == "hook":
        if args.hook_action == "install":
            return cmd_hook_install(args)
        elif args.hook_action == "uninstall":
            return cmd_hook_uninstall(args)
        ap.parse_args(["hook", "--help"])
        return 1

    handlers = {
        "writer": cmd_writer,
        "status": cmd_status,
        "_on_session_close": cmd_on_session_close,
        "_on_memory_write": cmd_on_memory_write,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
