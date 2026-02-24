#!/usr/bin/env python3
"""
ClawHub Skill Trigger: Liquefy Archive
=======================================
Entry point for the ClawHub native skill integration.
Handles command dispatch, config loading, daemon management, and daily recaps.

Designed for one-click install from ClawHub marketplace.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SKILL_DIR = Path(__file__).resolve().parent
REPO_ROOT = SKILL_DIR.parent.parent
ARCHIVER_SCRIPT = REPO_ROOT / "tools" / "liquefy_archiver.py"
PID_FILE = Path(os.environ.get("LIQUEFY_ARCHIVER_PID", "/tmp/liquefy_archiver.pid"))
STATE_FILE = Path(os.environ.get("LIQUEFY_ARCHIVER_STATE", "/tmp/liquefy_archiver_state.json"))
RECAP_DIR = Path(os.environ.get("LIQUEFY_RECAP_DIR", str(REPO_ROOT / ".liquefy" / "recaps")))


def _load_config() -> Dict[str, Any]:
    """Load skill config from ClawHub config path or defaults."""
    config_path = Path(os.environ.get("OPENCLAW_SKILL_CONFIG", str(SKILL_DIR / "config.json")))
    defaults = {
        "watch_root": "~/.openclaw",
        "vault_dir": "~/.liquefy/vault",
        "size_threshold_mb": 50,
        "age_threshold_days": 7,
        "keep_active": 5,
        "profile": "default",
        "secure": False,
        "prune_originals": False,
        "notify": ["stdout"],
        "poll_seconds": 300,
        "policy_mode": "strict",
    }
    if config_path.exists():
        try:
            user_cfg = json.loads(config_path.read_text(encoding="utf-8"))
            defaults.update(user_cfg)
        except Exception:
            pass
    return defaults


def _build_archiver_cmd(cfg: Dict[str, Any], command: str = "once") -> List[str]:
    cmd = [
        sys.executable, str(ARCHIVER_SCRIPT),
        command,
        "--watch", str(cfg["watch_root"]),
        "--out", str(cfg["vault_dir"]),
        "--size-mb", str(cfg["size_threshold_mb"]),
        "--age-days", str(cfg["age_threshold_days"]),
        "--keep", str(cfg["keep_active"]),
        "--profile", cfg["profile"],
        "--mode", cfg["policy_mode"],
        "--notify", ",".join(cfg.get("notify", ["stdout"])),
        "--json",
    ]
    if cfg.get("secure"):
        cmd.append("--secure")
    if cfg.get("prune_originals"):
        cmd.append("--prune")
    if command == "daemon":
        cmd.extend(["--poll", str(cfg.get("poll_seconds", 300))])
    return cmd


def _daemon_pid() -> Optional[int]:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, OSError):
        return None


def cmd_archive_now(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run a single archival sweep."""
    cmd = _build_archiver_cmd(cfg, "once")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": result.stderr[:500]}


def cmd_start_daemon(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Start the background archiver daemon."""
    pid = _daemon_pid()
    if pid:
        return {"ok": True, "status": "already_running", "pid": pid}

    cmd = _build_archiver_cmd(cfg, "daemon")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(1)
    return {"ok": True, "status": "started", "pid": proc.pid}


def cmd_stop_daemon(_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Stop the running archiver daemon."""
    pid = _daemon_pid()
    if not pid:
        return {"ok": True, "status": "not_running"}

    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except OSError:
                PID_FILE.unlink(missing_ok=True)
                return {"ok": True, "status": "stopped", "pid": pid}
        os.kill(pid, signal.SIGKILL)
        PID_FILE.unlink(missing_ok=True)
        return {"ok": True, "status": "killed", "pid": pid}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def cmd_status(_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Get current daemon status."""
    pid = _daemon_pid()
    state: Dict[str, Any] = {"pid": pid, "running": pid is not None}

    if STATE_FILE.exists():
        try:
            state.update(json.loads(STATE_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass

    return {"ok": True, "status": state}


def cmd_daily_recap(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Generate daily recap of archival activity."""
    RECAP_DIR.mkdir(parents=True, exist_ok=True)

    vault_dir = Path(cfg["vault_dir"]).expanduser().resolve()
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    total_raw = 0
    total_comp = 0
    vaults_created = 0
    leaks_blocked = 0

    if vault_dir.exists():
        for vdir in vault_dir.iterdir():
            index_file = vdir / "tracevault_index.json" if vdir.is_dir() else None
            if index_file and index_file.exists():
                try:
                    mtime = datetime.fromtimestamp(index_file.stat().st_mtime, tz=timezone.utc)
                    if mtime >= yesterday:
                        idx = json.loads(index_file.read_text(encoding="utf-8"))
                        for receipt in idx.get("receipts", []):
                            total_raw += receipt.get("original_bytes", 0)
                            total_comp += receipt.get("compressed_bytes", 0)
                        vaults_created += 1
                except Exception:
                    pass

    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            leaks_blocked = state.get("leaks_blocked", 0)
        except Exception:
            pass

    def _fmt(n: int) -> str:
        if n >= 1 << 30:
            return f"{n / (1 << 30):.1f} GB"
        if n >= 1 << 20:
            return f"{n / (1 << 20):.1f} MB"
        return f"{n} B"

    savings_pct = round((1 - total_comp / max(1, total_raw)) * 100, 1) if total_raw > 0 else 0

    recap = {
        "date": now.strftime("%Y-%m-%d"),
        "period": "24h",
        "raw_produced": _fmt(total_raw),
        "compressed_stored": _fmt(total_comp),
        "savings_pct": savings_pct,
        "vaults_created": vaults_created,
        "leaks_blocked": leaks_blocked,
        "message": (
            f"Your agents produced {_fmt(total_raw)} raw -> {_fmt(total_comp)} in vaults, "
            f"{leaks_blocked} leaks blocked, {vaults_created} sessions archived."
        ),
    }

    recap_file = RECAP_DIR / f"recap_{now.strftime('%Y%m%d')}.json"
    recap_file.write_text(json.dumps(recap, indent=2), encoding="utf-8")

    return {"ok": True, "recap": recap}


COMMANDS = {
    "archive_now": cmd_archive_now,
    "start_daemon": cmd_start_daemon,
    "stop_daemon": cmd_stop_daemon,
    "status": cmd_status,
    "daily_recap": cmd_daily_recap,
}


def main() -> int:
    """ClawHub skill entry point. Command passed via OPENCLAW_SKILL_COMMAND env or argv[1]."""
    command = os.environ.get("OPENCLAW_SKILL_COMMAND") or (sys.argv[1] if len(sys.argv) > 1 else "status")
    cfg = _load_config()

    handler = COMMANDS.get(command)
    if not handler:
        print(json.dumps({"ok": False, "error": f"Unknown command: {command}"}))
        return 1

    result = handler(cfg)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
