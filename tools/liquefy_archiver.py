#!/usr/bin/env python3
"""
liquefy_archiver.py
===================
Background archiver daemon for OpenClaw / generic workspaces.

Watches configurable directories (sessions/, memory/, artifacts/ by default).
Auto-packs anything > threshold-MB or older than N days into .null vaults
with full redaction + MRTV proofs.  Keeps last N active files untouched.

Modes:
    daemon   — long-running watchdog (systemd / launchd / tmux)
    once     — single sweep then exit (cron-friendly)
    status   — print current daemon state as JSON
    install  — emit systemd / launchd unit file

Notifications:
    --notify telegram  — post summary to Telegram bot
    --notify discord   — post summary to Discord webhook
    --notify stdout    — human-readable summary to stdout (default)

Usage:
    python tools/liquefy_archiver.py daemon --watch ~/.openclaw --out ./vault
    python tools/liquefy_archiver.py once   --watch ~/.openclaw --out ./vault
    python tools/liquefy_archiver.py status
    python tools/liquefy_archiver.py install --type systemd
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import platform
import signal
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root, version_result

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

from path_policy import (
    PathPolicy,
    default_policy,
    classify_risky_path,
    redact_risky_rows,
)

CLI_SCHEMA_VERSION = "liquefy.archiver.cli.v1"

DEFAULT_WATCH_SUBDIRS = ["sessions", "memory", "artifacts"]
DEFAULT_SIZE_THRESHOLD_MB = 50
DEFAULT_AGE_THRESHOLD_DAYS = 7
DEFAULT_KEEP_ACTIVE = 5
DEFAULT_POLL_SECONDS = 300  # 5 min

PID_FILE = Path(os.environ.get("LIQUEFY_ARCHIVER_PID", "/tmp/liquefy_archiver.pid"))
STATE_FILE = Path(os.environ.get("LIQUEFY_ARCHIVER_STATE", "/tmp/liquefy_archiver_state.json"))


@dataclass
class ArchiveCandidate:
    path: Path
    size_bytes: int
    age_days: float
    reason: str  # "size" | "age" | "both"


@dataclass
class ArchiveResult:
    source: str
    vault_path: str
    raw_bytes: int
    compressed_bytes: int
    ratio: float
    mrtv_ok: bool
    leaks_blocked: int
    pruned: bool


@dataclass
class SweepSummary:
    ts: str
    candidates_found: int
    archived: int
    pruned: int
    raw_bytes_total: int
    compressed_bytes_total: int
    leaks_blocked: int
    errors: List[str] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(path: Path) -> float:
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return 0.0
    return (time.time() - mtime) / 86400.0


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _find_candidates(
    watch_dirs: List[Path],
    size_threshold_bytes: int,
    age_threshold_days: float,
    keep_active: int,
) -> List[ArchiveCandidate]:
    candidates: List[ArchiveCandidate] = []

    for watch_dir in watch_dirs:
        if not watch_dir.exists():
            continue

        items = sorted(watch_dir.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        active_kept = 0

        for item in items:
            if not item.exists():
                continue
            if item.name.startswith("."):
                continue

            if active_kept < keep_active:
                active_kept += 1
                continue

            if item.is_file():
                sz = _file_size(item)
                age = _age_days(item)
            elif item.is_dir():
                sz = _dir_size(item)
                age = _age_days(item)
            else:
                continue

            reasons = []
            if sz >= size_threshold_bytes:
                reasons.append("size")
            if age >= age_threshold_days:
                reasons.append("age")

            if reasons:
                candidates.append(ArchiveCandidate(
                    path=item,
                    size_bytes=sz,
                    age_days=round(age, 2),
                    reason="+".join(reasons),
                ))

    return candidates


def _leak_scan_quick(path: Path, policy: PathPolicy) -> List[Dict[str, str]]:
    """Quick leak scan on a single file/dir using policy classification."""
    leaks: List[Dict[str, str]] = []
    root = path.parent if path.is_file() else path

    targets = [path] if path.is_file() else list(path.rglob("*"))
    for f in targets:
        if not f.is_file():
            continue
        result = classify_risky_path(f, root)
        if result is not None:
            category, reason = result
            leaks.append({"file": str(f), "category": category, "reason": reason})
    return leaks


async def _pack_candidate(
    candidate: ArchiveCandidate,
    out_dir: Path,
    policy: PathPolicy,
    org: str,
    profile: str,
    secure: bool,
) -> ArchiveResult:
    """Pack a single candidate using tracevault_pack subprocess."""
    source = str(candidate.path)
    vault_name = candidate.path.name.replace(" ", "_")
    vault_out = out_dir / vault_name

    leaks = _leak_scan_quick(candidate.path, policy)
    leaks_blocked = len(leaks)

    cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        source,
        "--out", str(vault_out),
        "--org", org,
        "--profile", profile,
        "--verify-mode", "full",
        "--json",
    ]
    if secure:
        secret = os.environ.get("LIQUEFY_SECRET", "")
        if secret:
            cmd.extend(["--secret", secret])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LIQUEFY_PROFILE": profile},
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        if proc.returncode == 0:
            try:
                result_data = json.loads(stdout.decode("utf-8", errors="replace"))
                res = result_data.get("result", {})
                raw_bytes = res.get("total_original_bytes", candidate.size_bytes)
                comp_bytes = res.get("total_compressed_bytes", 0)
            except (json.JSONDecodeError, KeyError):
                raw_bytes = candidate.size_bytes
                comp_bytes = 0

            ratio = raw_bytes / max(1, comp_bytes)
            return ArchiveResult(
                source=source,
                vault_path=str(vault_out),
                raw_bytes=raw_bytes,
                compressed_bytes=comp_bytes,
                ratio=round(ratio, 2),
                mrtv_ok=True,
                leaks_blocked=leaks_blocked,
                pruned=False,
            )
        else:
            raise RuntimeError(stderr.decode("utf-8", errors="replace")[:500])
    except asyncio.TimeoutError:
        raise RuntimeError(f"Pack timeout for {source}")


def _prune_source(candidate: ArchiveCandidate, dry_run: bool) -> bool:
    """Remove original after successful vault creation."""
    if dry_run:
        return False
    try:
        if candidate.path.is_file():
            candidate.path.unlink()
        elif candidate.path.is_dir():
            import shutil
            shutil.rmtree(candidate.path)
        return True
    except OSError:
        return False


async def sweep(
    watch_dirs: List[Path],
    out_dir: Path,
    *,
    size_threshold_mb: float,
    age_threshold_days: float,
    keep_active: int,
    org: str,
    profile: str,
    secure: bool,
    prune: bool,
    dry_run: bool,
    policy: PathPolicy,
) -> SweepSummary:
    """Perform a single archival sweep."""
    size_threshold_bytes = int(size_threshold_mb * 1024 * 1024)
    candidates = _find_candidates(watch_dirs, size_threshold_bytes, age_threshold_days, keep_active)

    summary = SweepSummary(
        ts=_utc_now(),
        candidates_found=len(candidates),
        archived=0,
        pruned=0,
        raw_bytes_total=0,
        compressed_bytes_total=0,
        leaks_blocked=0,
    )

    if dry_run:
        for c in candidates:
            summary.results.append({
                "source": str(c.path),
                "size_bytes": c.size_bytes,
                "age_days": c.age_days,
                "reason": c.reason,
                "action": "would_archive",
            })
        return summary

    out_dir.mkdir(parents=True, exist_ok=True)

    for candidate in candidates:
        try:
            result = await _pack_candidate(candidate, out_dir, policy, org, profile, secure)
            summary.archived += 1
            summary.raw_bytes_total += result.raw_bytes
            summary.compressed_bytes_total += result.compressed_bytes
            summary.leaks_blocked += result.leaks_blocked

            if prune and result.mrtv_ok:
                if _prune_source(candidate, dry_run):
                    result.pruned = True
                    summary.pruned += 1

            summary.results.append({
                "source": result.source,
                "vault_path": result.vault_path,
                "raw_bytes": result.raw_bytes,
                "compressed_bytes": result.compressed_bytes,
                "ratio": result.ratio,
                "mrtv_ok": result.mrtv_ok,
                "leaks_blocked": result.leaks_blocked,
                "pruned": result.pruned,
            })
        except Exception as exc:
            summary.errors.append(f"{candidate.path}: {exc}")

    return summary


def _format_bytes(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KB"
    return f"{n} B"


def _human_summary(s: SweepSummary) -> str:
    lines = [
        f"Liquefy Archiver Sweep @ {s.ts}",
        f"  Candidates found: {s.candidates_found}",
        f"  Archived: {s.archived}",
        f"  Raw: {_format_bytes(s.raw_bytes_total)} -> Compressed: {_format_bytes(s.compressed_bytes_total)}",
    ]
    if s.raw_bytes_total > 0:
        ratio = s.raw_bytes_total / max(1, s.compressed_bytes_total)
        lines.append(f"  Ratio: {ratio:.1f}x")
    lines.append(f"  Leaks blocked: {s.leaks_blocked}")
    lines.append(f"  Pruned: {s.pruned}")
    if s.errors:
        lines.append(f"  Errors: {len(s.errors)}")
        for e in s.errors[:3]:
            lines.append(f"    - {e[:120]}")
    return "\n".join(lines)


# ── Notification Backends ──


def _notify_stdout(summary: SweepSummary) -> None:
    print(_human_summary(summary))


def _notify_telegram(summary: SweepSummary) -> None:
    bot_token = os.environ.get("LIQUEFY_TG_BOT_TOKEN", "")
    chat_id = os.environ.get("LIQUEFY_TG_CHAT_ID", "")
    if not bot_token or not chat_id:
        print("[archiver] LIQUEFY_TG_BOT_TOKEN / LIQUEFY_TG_CHAT_ID not set, skipping Telegram", file=sys.stderr)
        return
    import urllib.request
    text = _human_summary(summary)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as exc:
        print(f"[archiver] Telegram notify failed: {exc}", file=sys.stderr)


def _notify_discord(summary: SweepSummary) -> None:
    webhook_url = os.environ.get("LIQUEFY_DISCORD_WEBHOOK", "")
    if not webhook_url:
        print("[archiver] LIQUEFY_DISCORD_WEBHOOK not set, skipping Discord", file=sys.stderr)
        return
    import urllib.request
    text = _human_summary(summary)
    payload = json.dumps({"content": f"```\n{text}\n```"}).encode()
    req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as exc:
        print(f"[archiver] Discord notify failed: {exc}", file=sys.stderr)


NOTIFIERS = {
    "stdout": _notify_stdout,
    "telegram": _notify_telegram,
    "discord": _notify_discord,
}


def _send_notifications(summary: SweepSummary, channels: List[str]) -> None:
    for ch in channels:
        fn = NOTIFIERS.get(ch)
        if fn:
            try:
                fn(summary)
            except Exception as exc:
                print(f"[archiver] notify {ch} error: {exc}", file=sys.stderr)


# ── Daemon Loop ──


async def daemon_loop(args: argparse.Namespace) -> None:
    """Long-running daemon that sweeps periodically."""
    watch_dirs = _resolve_watch_dirs(args.watch, args.subdirs)
    out_dir = Path(args.out).resolve()
    policy = default_policy(mode=getattr(args, "mode", "strict") or "strict")
    channels = (args.notify or "stdout").split(",")

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    running = True
    def _handle_signal(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    print(f"[archiver] daemon started pid={os.getpid()} poll={args.poll}s", file=sys.stderr)

    while running:
        try:
            summary = await sweep(
                watch_dirs, out_dir,
                size_threshold_mb=args.size_mb,
                age_threshold_days=args.age_days,
                keep_active=args.keep,
                org=args.org,
                profile=args.profile,
                secure=args.secure,
                prune=args.prune,
                dry_run=False,
                policy=policy,
            )

            state = {
                "pid": os.getpid(),
                "last_sweep": summary.ts,
                "archived": summary.archived,
                "raw_bytes": summary.raw_bytes_total,
                "compressed_bytes": summary.compressed_bytes_total,
                "leaks_blocked": summary.leaks_blocked,
                "errors": len(summary.errors),
            }
            STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

            if summary.archived > 0 or summary.errors:
                _send_notifications(summary, channels)
        except Exception as exc:
            print(f"[archiver] sweep error: {exc}", file=sys.stderr)

        for _ in range(int(args.poll)):
            if not running:
                break
            await asyncio.sleep(1)

    PID_FILE.unlink(missing_ok=True)
    print("[archiver] daemon stopped", file=sys.stderr)


# ── Service Unit Generation ──


def _systemd_unit(args: argparse.Namespace) -> str:
    python = sys.executable
    script = str(Path(__file__).resolve())
    watch = args.watch or "~/.openclaw"
    out = args.out or "~/.liquefy/vault"
    return textwrap.dedent(f"""\
        [Unit]
        Description=Liquefy Archiver Daemon
        After=network.target

        [Service]
        Type=simple
        ExecStart={python} {script} daemon --watch {watch} --out {out} --poll {args.poll} --prune
        Restart=on-failure
        RestartSec=30
        Environment=LIQUEFY_PROFILE=default
        Environment=LIQUEFY_SECRET=
        Environment=LIQUEFY_TG_BOT_TOKEN=
        Environment=LIQUEFY_TG_CHAT_ID=
        Environment=LIQUEFY_DISCORD_WEBHOOK=
        WorkingDirectory={REPO_ROOT}

        [Install]
        WantedBy=multi-user.target
    """)


def _launchd_plist(args: argparse.Namespace) -> str:
    python = sys.executable
    script = str(Path(__file__).resolve())
    watch = args.watch or "~/.openclaw"
    out = args.out or "~/.liquefy/vault"
    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.parad0x.liquefy.archiver</string>
            <key>ProgramArguments</key>
            <array>
                <string>{python}</string>
                <string>{script}</string>
                <string>daemon</string>
                <string>--watch</string>
                <string>{watch}</string>
                <string>--out</string>
                <string>{out}</string>
                <string>--poll</string>
                <string>{args.poll}</string>
                <string>--prune</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>WorkingDirectory</key>
            <string>{REPO_ROOT}</string>
        </dict>
        </plist>
    """)


# ── Helpers ──


def _resolve_watch_dirs(watch_root: str, subdirs: Optional[List[str]]) -> List[Path]:
    root = Path(watch_root).expanduser().resolve()
    if subdirs:
        return [root / sd for sd in subdirs]
    return [root / sd for sd in DEFAULT_WATCH_SUBDIRS]


def _emit_json(payload: Dict, enabled: bool, json_file: Optional[str]) -> None:
    if json_file:
        p = Path(json_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if enabled:
        print(json.dumps(payload, indent=2))


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-archiver", description="Liquefy Archiver Daemon")
    sub = ap.add_subparsers(dest="command")

    # daemon
    p_daemon = sub.add_parser("daemon", help="Run long-lived archiver daemon")
    _add_common_args(p_daemon)
    p_daemon.add_argument("--poll", type=int, default=DEFAULT_POLL_SECONDS, help="Seconds between sweeps")

    # once
    p_once = sub.add_parser("once", help="Single sweep then exit")
    _add_common_args(p_once)
    p_once.add_argument("--dry-run", action="store_true", help="List candidates without archiving")

    # status
    p_status = sub.add_parser("status", help="Print daemon status")
    p_status.add_argument("--json", action="store_true")

    # install
    p_install = sub.add_parser("install", help="Emit service unit file")
    p_install.add_argument("--type", choices=["systemd", "launchd"], default=_default_service_type())
    _add_common_args(p_install)

    return ap


def _default_service_type() -> str:
    return "launchd" if platform.system() == "Darwin" else "systemd"


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--watch", default="~/.openclaw", help="Root directory to watch")
    parser.add_argument("--subdirs", nargs="*", default=None, help="Subdirectories to scan (default: sessions memory artifacts)")
    parser.add_argument("--out", default="~/.liquefy/vault", help="Vault output directory")
    parser.add_argument("--size-mb", type=float, default=DEFAULT_SIZE_THRESHOLD_MB, help="Size threshold in MB")
    parser.add_argument("--age-days", type=float, default=DEFAULT_AGE_THRESHOLD_DAYS, help="Age threshold in days")
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP_ACTIVE, help="Keep N most recent items active")
    parser.add_argument("--org", default="default", help="Organization ID for vault metadata")
    parser.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")
    parser.add_argument("--secure", action="store_true", help="Enable LSEC v2 encryption")
    parser.add_argument("--prune", action="store_true", help="Delete originals after successful archival + MRTV")
    parser.add_argument("--notify", default="stdout", help="Notification channels (comma-separated: stdout,telegram,discord)")
    parser.add_argument("--mode", choices=["strict", "balanced", "off"], default="strict", help="Path policy mode")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--json-file", default=None)


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    if args.command == "status":
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        else:
            state = {"pid": None, "status": "not_running"}

        pid = state.get("pid")
        if pid:
            try:
                os.kill(pid, 0)
                state["status"] = "running"
            except OSError:
                state["status"] = "stale"
        else:
            state["status"] = "not_running"

        payload = {"schema_version": CLI_SCHEMA_VERSION, "command": "status", "ok": True, "result": state}
        enabled = getattr(args, "json", False)
        if enabled:
            print(json.dumps(payload, indent=2))
        else:
            status = state.get("status", "unknown")
            print(f"Archiver: {status} (pid={state.get('pid', 'N/A')}, last_sweep={state.get('last_sweep', 'never')})")
        return 0

    if args.command == "install":
        if args.type == "systemd":
            unit = _systemd_unit(args)
            print(unit)
            print("# Save to: /etc/systemd/system/liquefy-archiver.service", file=sys.stderr)
            print("# Then: sudo systemctl daemon-reload && sudo systemctl enable --now liquefy-archiver", file=sys.stderr)
        else:
            plist = _launchd_plist(args)
            print(plist)
            print("# Save to: ~/Library/LaunchAgents/com.parad0x.liquefy.archiver.plist", file=sys.stderr)
            print("# Then: launchctl load ~/Library/LaunchAgents/com.parad0x.liquefy.archiver.plist", file=sys.stderr)
        return 0

    if args.command == "daemon":
        asyncio.run(daemon_loop(args))
        return 0

    if args.command == "once":
        watch_dirs = _resolve_watch_dirs(args.watch, args.subdirs)
        out_dir = Path(args.out).expanduser().resolve()
        policy = default_policy(mode=getattr(args, "mode", "strict") or "strict")
        channels = (args.notify or "stdout").split(",")

        summary = asyncio.run(sweep(
            watch_dirs, out_dir,
            size_threshold_mb=args.size_mb,
            age_threshold_days=args.age_days,
            keep_active=args.keep,
            org=args.org,
            profile=args.profile,
            secure=args.secure,
            prune=args.prune,
            dry_run=getattr(args, "dry_run", False),
            policy=policy,
        ))

        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "command": "once",
            "ok": len(summary.errors) == 0,
            "result": {
                "ts": summary.ts,
                "candidates_found": summary.candidates_found,
                "archived": summary.archived,
                "pruned": summary.pruned,
                "raw_bytes_total": summary.raw_bytes_total,
                "compressed_bytes_total": summary.compressed_bytes_total,
                "leaks_blocked": summary.leaks_blocked,
                "errors": summary.errors,
                "items": summary.results,
            },
        }

        enabled = getattr(args, "json", False)
        _emit_json(payload, enabled, getattr(args, "json_file", None))

        if not enabled:
            _send_notifications(summary, channels)

        return 0 if not summary.errors else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
