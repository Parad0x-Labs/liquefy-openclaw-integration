#!/usr/bin/env python3
"""
openclaw_tracevault.py
======================
Pack OpenClaw agent sessions into Liquefy vault archives.
Integrates at the filesystem boundary -- no OpenClaw plugin APIs.

Usage:
    python tools/openclaw_tracevault.py list [--state-dir <path>]
    python tools/openclaw_tracevault.py pack --agent <id> --out <dir> [--state-dir <path>] [--since-days N] [--include-logs] [--dry-run]
    python tools/openclaw_tracevault.py pack-latest --agent <id> --out <dir> [--state-dir <path>] [--include-logs] [--dry-run]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files and directories that must never be packed.
# OpenClaw stores credentials, tokens, and keys in these locations.
DENYLIST_DIRS = {
    "credentials",
}

DENYLIST_FILES = {
    "openclaw.json",
    "auth-profiles.json",
    "oauth.json",
    ".env",
    "id_rsa",
    "tokens",
    "secrets",
}

DENYLIST_EXTENSIONS = {
    ".key",
    ".pem",
}


def resolve_state_dir(explicit: str = None) -> Path:
    """Resolve OpenClaw state directory."""
    if explicit:
        return Path(explicit).resolve()
    env = os.environ.get("OPENCLAW_STATE_DIR")
    if env:
        return Path(env).resolve()
    return Path.home() / ".openclaw"


def is_denied(path: Path, relative_to: Path) -> bool:
    """Check if a file matches the denylist."""
    rel = path.relative_to(relative_to)

    # Directory denylist
    for part in rel.parts:
        if part in DENYLIST_DIRS:
            return True

    # File name denylist
    if path.name in DENYLIST_FILES:
        return True

    # Extension denylist
    if path.suffix.lower() in DENYLIST_EXTENSIONS:
        return True

    return False


def cmd_list(state_dir: Path):
    """List detected OpenClaw agents."""
    agents_dir = state_dir / "agents"
    if not agents_dir.exists():
        print(f"No agents directory found at {agents_dir}")
        return

    agent_ids = sorted(
        d.name for d in agents_dir.iterdir()
        if d.is_dir() and (d / "sessions").exists()
    )

    if not agent_ids:
        print(f"No agents with sessions found in {agents_dir}")
        return

    print(f"OpenClaw state: {state_dir}")
    print(f"Agents found:   {len(agent_ids)}\n")
    for aid in agent_ids:
        sessions_dir = agents_dir / aid / "sessions"
        count = sum(1 for f in sessions_dir.glob("*.jsonl") if f.is_file())
        print(f"  {aid}  ({count} sessions)")


def _collect_files(agent_dir, state_dir, sessions_dir, cutoff, include_logs):
    """Collect files to pack, returning (included, excluded) lists."""
    included = []
    excluded = []

    for f in sorted(sessions_dir.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(agent_dir)
        if is_denied(f, state_dir):
            excluded.append((str(rel), "denylist"))
            continue
        if cutoff and f.stat().st_mtime < cutoff:
            excluded.append((str(rel), "too old"))
            continue
        included.append((f, rel))

    if include_logs:
        for log_pattern in ("*.log", "logs/*.log"):
            for f in agent_dir.glob(log_pattern):
                if not f.is_file():
                    continue
                rel = f.relative_to(agent_dir)
                if is_denied(f, state_dir):
                    excluded.append((str(rel), "denylist"))
                    continue
                included.append((f, rel))

    return included, excluded


def _print_stats(out_dir):
    """Print post-pack stats from the vault index."""
    index_path = out_dir / "tracevault_index.json"
    if not index_path.exists():
        return

    idx = json.loads(index_path.read_text())
    receipts = idx.get("receipts", [])
    big_groups = idx.get("bigfile_groups", [])
    total_in = idx.get("input_bytes", 0)
    total_out = idx.get("output_bytes", 0)
    ratio = idx.get("ratio", 0)
    packed_files = idx.get("files_processed", len(receipts) + len(big_groups))

    print(f"\n--- Vault Stats ---")
    print(f"  Sessions packed : {packed_files}")
    print(f"  Input           : {total_in:,} bytes")
    print(f"  Output          : {total_out:,} bytes")
    print(f"  Ratio           : {ratio}x")
    if big_groups:
        print(f"  Chunked files   : {len(big_groups)}")

    combined = list(receipts) + [
        {
            "run_relpath": g.get("run_relpath", "?"),
            "original_bytes": g.get("original_bytes", 0),
            "engine_used": "chunked-multi-engine",
        }
        for g in big_groups
    ]

    if combined:
        top = sorted(combined, key=lambda r: r.get("original_bytes", 0), reverse=True)[:5]
        print(f"  Top files:")
        for r in top:
            name = r.get("run_relpath", "?")
            orig = r.get("original_bytes", 0)
            eng = r.get("engine_used", "?")
            print(f"    {name:40s}  {orig:>8,} B  {eng}")

    print(f"  Index           : {index_path}")


def cmd_pack(
    state_dir: Path,
    agent_id: str,
    out_dir: Path,
    since_days: int = None,
    include_logs: bool = False,
    dry_run: bool = False,
):
    """Pack agent sessions into a vault archive."""
    agent_dir = state_dir / "agents" / agent_id
    sessions_dir = agent_dir / "sessions"

    if not sessions_dir.exists():
        print(f"No sessions directory at {sessions_dir}")
        sys.exit(1)

    cutoff = None
    if since_days is not None:
        cutoff = time.time() - (since_days * 86400)

    included, excluded = _collect_files(
        agent_dir, state_dir, sessions_dir, cutoff, include_logs
    )

    if dry_run:
        print(f"[DRY RUN] Agent: {agent_id}")
        print(f"[DRY RUN] State: {state_dir}\n")
        if included:
            print(f"  INCLUDE ({len(included)} files):")
            for _, rel in included:
                print(f"    + {rel}")
        if excluded:
            print(f"\n  EXCLUDE ({len(excluded)} files):")
            for name, reason in excluded:
                print(f"    - {name}  ({reason})")
        if not included:
            print("  Nothing to pack.")
        return

    if not included:
        print(f"No files to pack for agent '{agent_id}'")
        if since_days is not None:
            print(f"  (filtered to last {since_days} days)")
        return

    # Build staging directory
    staging = Path(tempfile.mkdtemp(prefix="openclaw_vault_"))

    try:
        for f, rel in included:
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)

        print(f"Staged {len(included)} files for agent '{agent_id}'")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "tracevault_pack.py"),
            str(staging),
            "--org", f"openclaw_{agent_id}",
            "--out", str(out_dir),
        ]
        subprocess.run(cmd, check=True)

        _print_stats(out_dir)

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def cmd_pack_latest(
    state_dir: Path,
    agent_id: str,
    out_dir: Path,
    include_logs: bool = False,
    dry_run: bool = False,
):
    """Pack only the most recent session file."""
    agent_dir = state_dir / "agents" / agent_id
    sessions_dir = agent_dir / "sessions"

    if not sessions_dir.exists():
        print(f"No sessions directory at {sessions_dir}")
        sys.exit(1)

    session_files = sorted(
        (f for f in sessions_dir.glob("*.jsonl") if f.is_file()),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )

    if not session_files:
        print(f"No session files found for agent '{agent_id}'")
        return

    latest = session_files[0]
    rel = latest.relative_to(agent_dir)

    if dry_run:
        print(f"[DRY RUN] Agent: {agent_id}")
        print(f"[DRY RUN] Latest session: {rel}")
        print(f"[DRY RUN] Modified: {time.ctime(latest.stat().st_mtime)}")
        return

    # Stage just the one file
    staging = Path(tempfile.mkdtemp(prefix="openclaw_vault_"))

    try:
        dest = staging / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(latest, dest)

        print(f"Packing latest session: {rel}")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "tracevault_pack.py"),
            str(staging),
            "--org", f"openclaw_{agent_id}",
            "--out", str(out_dir),
        ]
        subprocess.run(cmd, check=True)

        _print_stats(out_dir)

    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="Pack OpenClaw agent sessions into Liquefy vault archives."
    )
    sub = parser.add_subparsers(dest="command")

    # list
    p_list = sub.add_parser("list", help="List detected agents")
    p_list.add_argument("--state-dir", default=None, help="OpenClaw state directory")

    # pack
    p_pack = sub.add_parser("pack", help="Pack agent sessions")
    p_pack.add_argument("--agent", required=True, help="Agent ID to pack")
    p_pack.add_argument("--out", required=True, help="Output vault directory")
    p_pack.add_argument("--state-dir", default=None, help="OpenClaw state directory")
    p_pack.add_argument("--since-days", type=int, default=None, help="Only pack sessions modified in last N days")
    p_pack.add_argument("--include-logs", action="store_true", help="Include gateway/agent logs (off by default)")
    p_pack.add_argument("--dry-run", action="store_true", help="Show what would be included/excluded without packing")

    # pack-latest
    p_latest = sub.add_parser("pack-latest", help="Pack only the most recent session")
    p_latest.add_argument("--agent", required=True, help="Agent ID")
    p_latest.add_argument("--out", required=True, help="Output vault directory")
    p_latest.add_argument("--state-dir", default=None, help="OpenClaw state directory")
    p_latest.add_argument("--include-logs", action="store_true", help="Include gateway/agent logs")
    p_latest.add_argument("--dry-run", action="store_true", help="Show what would be packed without packing")

    args = parser.parse_args()

    if args.command == "list":
        state = resolve_state_dir(args.state_dir)
        cmd_list(state)

    elif args.command == "pack":
        state = resolve_state_dir(args.state_dir)
        cmd_pack(
            state_dir=state,
            agent_id=args.agent,
            out_dir=Path(args.out).resolve(),
            since_days=args.since_days,
            include_logs=args.include_logs,
            dry_run=args.dry_run,
        )

    elif args.command == "pack-latest":
        state = resolve_state_dir(args.state_dir)
        cmd_pack_latest(
            state_dir=state,
            agent_id=args.agent,
            out_dir=Path(args.out).resolve(),
            include_logs=args.include_logs,
            dry_run=args.dry_run,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
