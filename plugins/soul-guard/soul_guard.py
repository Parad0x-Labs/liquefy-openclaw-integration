"""
soul_guard.py -- SOUL.md integrity guard plugin for OpenClaw agents.

Attack vector: Prompt injection can write backdoors to ~/.openclaw/SOUL.md,
the agent's persistent identity/memory file. This plugin detects and alerts
on unauthorized modifications, making it the primary mitigation for this
attack class.

Usage:
    python3 soul_guard.py init    -- establish baseline hash
    python3 soul_guard.py check   -- verify current SOUL.md against baseline
    python3 soul_guard.py watch   -- start background watcher daemon
    python3 soul_guard.py restore -- restore SOUL.md from most recent backup

API:
    soul_guard_init(openclaw_dir)   -> dict
    soul_guard_check(openclaw_dir)  -> dict
    soul_guard_watch(openclaw_dir, callback, interval_sec) -> threading.Thread
    soul_guard_restore(openclaw_dir, backup_dir) -> dict
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

BASELINE_FILENAME = ".soul_guard_baseline"
MAX_BACKUPS = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _expand(path):
    return Path(os.path.expanduser(path))


def _soul_path(openclaw_dir):
    return _expand(openclaw_dir) / "SOUL.md"


def _baseline_path(openclaw_dir):
    return _expand(openclaw_dir) / BASELINE_FILENAME


def _sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_lines(file_path):
    try:
        return file_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []


def _delta_lines(soul_path, baseline_data):
    baseline_lines = set(baseline_data.get("snapshot_lines", []))
    current_lines = _read_lines(soul_path)
    current_set = set(current_lines)
    added = ["+ " + ln for ln in current_lines if ln not in baseline_lines]
    removed = ["- " + ln for ln in baseline_data.get("snapshot_lines", []) if ln not in current_set]
    return removed + added


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def soul_guard_init(openclaw_dir="~/.openclaw"):
    """
    Establish a baseline hash for SOUL.md.

    Reads SOUL.md if it exists, computes SHA-256, and writes a hidden
    baseline file (.soul_guard_baseline) with hash + timestamp.
    Also takes an initial backup in ~/.openclaw_backups.

    Returns:
        {"baseline_hash": str, "path": str, "protected": True, "timestamp": str}
    """
    soul_path = _soul_path(openclaw_dir)
    openclaw_expanded = _expand(openclaw_dir)
    openclaw_expanded.mkdir(parents=True, exist_ok=True)

    if not soul_path.exists():
        soul_path.write_text("", encoding="utf-8")

    baseline_hash = _sha256(soul_path)
    snapshot_lines = _read_lines(soul_path)
    timestamp = datetime.now(timezone.utc).isoformat()

    baseline_data = {
        "baseline_hash": baseline_hash,
        "path": str(soul_path),
        "timestamp": timestamp,
        "snapshot_lines": snapshot_lines,
    }

    baseline_file = _baseline_path(openclaw_dir)
    baseline_file.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")

    _create_backup(soul_path, "~/.openclaw_backups")

    return {
        "baseline_hash": baseline_hash,
        "path": str(soul_path),
        "protected": True,
        "timestamp": timestamp,
    }


def soul_guard_check(openclaw_dir="~/.openclaw"):
    """
    Compare current SOUL.md hash against the stored baseline.

    Returns tampered dict or intact dict.
    Raises FileNotFoundError if no baseline exists (run init first).
    """
    soul_path = _soul_path(openclaw_dir)
    baseline_file = _baseline_path(openclaw_dir)

    if not baseline_file.exists():
        raise FileNotFoundError(
            "No baseline found at {}. Run soul_guard_init() first.".format(baseline_file)
        )

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    original_hash = baseline_data["baseline_hash"]

    if not soul_path.exists():
        return {
            "tampered": True,
            "original_hash": original_hash,
            "current_hash": None,
            "delta_lines": ["(SOUL.md has been deleted)"],
            "baseline_timestamp": baseline_data.get("timestamp"),
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

    current_hash = _sha256(soul_path)
    checked_at = datetime.now(timezone.utc).isoformat()

    if current_hash != original_hash:
        delta = _delta_lines(soul_path, baseline_data)
        return {
            "tampered": True,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "delta_lines": delta,
            "baseline_timestamp": baseline_data.get("timestamp"),
            "detected_at": checked_at,
        }

    return {"tampered": False, "hash": current_hash, "checked_at": checked_at}


def soul_guard_watch(openclaw_dir="~/.openclaw", callback=None, interval_sec=5.0):
    """
    Start a background daemon thread polling SOUL.md every interval_sec seconds.

    On tamper detection: calls callback(event) or prints ALERT to stderr.
    Thread is a daemon -- stops when main process exits.
    Stop explicitly via: thread.stop_event.set()

    Returns: threading.Thread with .stop_event attribute.
    """
    stop_event = threading.Event()

    def _default_callback(event):
        lines = "\n".join("    " + ln for ln in event.get("delta_lines", []))
        print(
            "\n[SOUL-GUARD ALERT] SOUL.md tampered at {}!\n"
            "  original hash : {}\n"
            "  current  hash : {}\n"
            "  changed lines :\n{}".format(
                event.get("detected_at"),
                event.get("original_hash"),
                event.get("current_hash"),
                lines,
            ),
            file=sys.stderr, flush=True,
        )

    effective_callback = callback if callback is not None else _default_callback

    def _watch_loop():
        print(
            "[soul-guard] Watching {} every {}s ...".format(_soul_path(openclaw_dir), interval_sec),
            file=sys.stderr, flush=True,
        )
        last_tamper_hash = None
        while not stop_event.is_set():
            try:
                result = soul_guard_check(openclaw_dir)
                if result.get("tampered"):
                    cur = result.get("current_hash")
                    if cur != last_tamper_hash:
                        last_tamper_hash = cur
                        effective_callback(result)
                else:
                    last_tamper_hash = None
            except FileNotFoundError as exc:
                print("[soul-guard] WARNING: {}".format(exc), file=sys.stderr, flush=True)
            except Exception as exc:
                print("[soul-guard] ERROR: {}".format(exc), file=sys.stderr, flush=True)
            stop_event.wait(interval_sec)

    thread = threading.Thread(target=_watch_loop, daemon=True, name="soul-guard-watcher")
    thread.stop_event = stop_event
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# Backup / restore
# ---------------------------------------------------------------------------

def _create_backup(soul_path, backup_dir):
    if not soul_path.exists():
        return None
    bdir = _expand(backup_dir)
    bdir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = bdir / "SOUL.md.{}".format(timestamp)
    shutil.copy2(soul_path, dest)
    backups = sorted(bdir.glob("SOUL.md.*"))
    for old in backups[:-MAX_BACKUPS]:
        try:
            old.unlink()
        except Exception:
            pass
    return dest


def soul_guard_restore(openclaw_dir="~/.openclaw", backup_dir="~/.openclaw_backups"):
    """
    Restore SOUL.md from the most recent backup (keeps last 10).

    Re-baselines after restore so the watcher does not immediately re-alert.

    Returns:
        {"restored": True, "backup_used": str, "restored_at": str}
    Raises:
        FileNotFoundError: if no backups exist.
    """
    bdir = _expand(backup_dir)
    backups = sorted(bdir.glob("SOUL.md.*")) if bdir.exists() else []
    if not backups:
        raise FileNotFoundError("No backups found in {}. Cannot restore.".format(bdir))

    latest_backup = backups[-1]
    soul_path = _soul_path(openclaw_dir)
    _expand(openclaw_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy2(latest_backup, soul_path)
    soul_guard_init(openclaw_dir)

    restored_at = datetime.now(timezone.utc).isoformat()
    print(
        "[soul-guard] SOUL.md restored from {} at {}".format(latest_backup, restored_at),
        file=sys.stderr, flush=True,
    )
    return {"restored": True, "backup_used": str(latest_backup), "restored_at": restored_at}


# ---------------------------------------------------------------------------
# CLI __main__
# ---------------------------------------------------------------------------

def _usage():
    print(
        "Usage: python3 soul_guard.py <command> [openclaw_dir]\n\n"
        "Commands:\n"
        "  init    -- establish baseline hash for SOUL.md\n"
        "  check   -- verify SOUL.md against baseline (exit 1 if tampered)\n"
        "  watch   -- start foreground watcher (Ctrl-C to stop)\n"
        "  restore -- restore SOUL.md from most recent backup\n\n"
        "openclaw_dir defaults to ~/.openclaw\n",
        file=sys.stderr,
    )


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        _usage()
        sys.exit(0)

    command = args[0]
    openclaw_dir = args[1] if len(args) > 1 else "~/.openclaw"

    if command == "init":
        result = soul_guard_init(openclaw_dir)
        print(json.dumps(result, indent=2))

    elif command == "check":
        try:
            result = soul_guard_check(openclaw_dir)
        except FileNotFoundError as exc:
            print("ERROR: {}".format(exc), file=sys.stderr)
            sys.exit(2)
        print(json.dumps(result, indent=2))
        if result.get("tampered"):
            print("\n[SOUL-GUARD] ALERT: SOUL.md has been tampered with!", file=sys.stderr)
            sys.exit(1)
        else:
            print("\n[SOUL-GUARD] OK: SOUL.md integrity verified.", file=sys.stderr)
            sys.exit(0)

    elif command == "watch":
        try:
            soul_guard_check(openclaw_dir)
        except FileNotFoundError:
            print("[soul-guard] No baseline found -- running init first ...", file=sys.stderr)
            soul_guard_init(openclaw_dir)
        thread = soul_guard_watch(openclaw_dir)
        print("[soul-guard] Watcher running. Press Ctrl-C to stop.", file=sys.stderr)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            thread.stop_event.set()
            print("\n[soul-guard] Watcher stopped.", file=sys.stderr)

    elif command == "restore":
        try:
            result = soul_guard_restore(openclaw_dir)
            print(json.dumps(result, indent=2))
        except FileNotFoundError as exc:
            print("ERROR: {}".format(exc), file=sys.stderr)
            sys.exit(2)

    else:
        print("Unknown command: {!r}".format(command), file=sys.stderr)
        _usage()
        sys.exit(1)