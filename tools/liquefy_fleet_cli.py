#!/usr/bin/env python3
"""
liquefy_fleet_cli.py
====================
Multi-agent fleet coordination CLI.

"I run 47 agents and they all talk to the same .null index."

Commands:
    register    — Register an agent with quotas
    deregister  — Remove an agent (optionally purge data)
    status      — Fleet-wide dashboard
    quota       — Check agent quota / usage
    ingest      — Compress a directory on behalf of an agent (quota-enforced)
    merge       — Merge vaults from multiple agents into one
    gc          — Fleet-wide garbage collection
    heartbeat   — Update agent heartbeat

Usage:
    python tools/liquefy_fleet_cli.py register --fleet ./vault --agent agent-47 --quota-mb 500
    python tools/liquefy_fleet_cli.py status --fleet ./vault
    python tools/liquefy_fleet_cli.py ingest --fleet ./vault --agent agent-47 --src ./data
    python tools/liquefy_fleet_cli.py merge --fleet ./vault --target main-agent --sources agent-1 agent-2
    python tools/liquefy_fleet_cli.py gc --fleet ./vault --max-age 30 --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

from liquefy_fleet import Fleet, MergeStrategy, _fmt_bytes

CLI_SCHEMA_VERSION = "liquefy.fleet.cli.v1"
DEFAULT_FLEET_ROOT = os.environ.get("LIQUEFY_FLEET_ROOT", str(Path.home() / ".liquefy" / "fleet"))


def _fleet(args: argparse.Namespace) -> Fleet:
    return Fleet(args.fleet)


# ── Commands ──


def cmd_register(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    tags = {}
    if args.tags:
        for t in args.tags:
            k, _, v = t.partition("=")
            tags[k] = v

    state = fleet.register_agent(
        args.agent,
        quota_mb=args.quota_mb,
        max_files=args.max_files,
        max_sessions_per_day=args.max_sessions,
        priority=args.priority,
        tags=tags,
    )

    if args.json:
        print(json.dumps({
            "schema_version": CLI_SCHEMA_VERSION,
            "command": "register",
            "ok": True,
            "agent_id": state.agent_id,
            "status": state.status,
            "quota_mb": args.quota_mb,
            "namespace": str(fleet.agent_namespace(args.agent)),
        }, indent=2))
    else:
        print(f"\n  Registered agent: {state.agent_id}")
        print(f"  Status: {state.status}")
        print(f"  Namespace: {fleet.agent_namespace(args.agent)}")
        if args.quota_mb:
            print(f"  Quota: {args.quota_mb} MB")
        if args.max_sessions:
            print(f"  Max sessions/day: {args.max_sessions}")
        print(f"  Priority: {args.priority}")
        print()

    return 0


def cmd_deregister(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    ok = fleet.deregister_agent(args.agent, purge=args.purge)

    if args.json:
        print(json.dumps({"ok": ok, "agent_id": args.agent, "purged": args.purge}, indent=2))
    else:
        if ok:
            print(f"  Agent '{args.agent}' deregistered" + (" (data purged)" if args.purge else ""))
        else:
            print(f"  Agent '{args.agent}' not found")

    return 0 if ok else 1


def cmd_status(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    result = fleet.status()

    if args.json:
        result["schema_version"] = CLI_SCHEMA_VERSION
        result["command"] = "status"
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Fleet Dashboard: {result['fleet_root']}")
        print(f"  Agents: {result['agent_count']} | Vaults: {result['total_vaults']} | "
              f"Storage: {result['total_human']} | Files: {result['total_files']}")
        print()

        if result["agents"]:
            print(f"  {'Agent':<20} {'Status':<12} {'Health':<10} {'Storage':>10} {'Quota%':>7} {'Vaults':>7} {'Today':>6}")
            print(f"  {'─'*20} {'─'*12} {'─'*10} {'─'*10} {'─'*7} {'─'*7} {'─'*6}")

            for a in result["agents"]:
                quota_str = f"{a['quota_pct']}%" if a['quota_pct'] is not None else "∞"
                health_color = "\033[92m" if a["health"] == "healthy" else (
                    "\033[93m" if a["health"] == "stale" else "\033[91m"
                )
                print(f"  {a['agent_id']:<20} {a['status']:<12} "
                      f"{health_color}{a['health']:<10}\033[0m "
                      f"{a['usage_human']:>10} {quota_str:>7} "
                      f"{a['vault_count']:>7} {a['sessions_today']:>6}")

            print()

        if result["recent_merges"]:
            print(f"  Recent merges: {result['recent_merges']}")
        if result["recent_gc"]:
            print(f"  GC operations: {result['recent_gc']}")
        print()

    return 0


def cmd_quota(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    result = fleet.check_quota(args.agent)

    if args.json:
        result["schema_version"] = CLI_SCHEMA_VERSION
        result["command"] = "quota"
        result["agent_id"] = args.agent
        print(json.dumps(result, indent=2))
    else:
        if result["allowed"]:
            print(f"\n  Agent '{args.agent}': WITHIN QUOTA")
            print(f"  Usage: {_fmt_bytes(result.get('usage_bytes', 0))}")
            if result.get("headroom_bytes") is not None:
                print(f"  Headroom: {_fmt_bytes(result['headroom_bytes'])}")
        else:
            print(f"\n  Agent '{args.agent}': QUOTA EXCEEDED")
            print(f"  Reason: {result.get('reason', '?')}")
            for v in result.get("violations", []):
                print(f"    - {v}")
            print(f"\n  Fix: Increase quota or run: make fleet-gc")
        print()

    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Compress a directory on behalf of an agent, respecting quotas."""
    fleet = _fleet(args)

    quota_check = fleet.check_quota(args.agent)
    if not quota_check["allowed"]:
        if args.json:
            print(json.dumps({
                "ok": False,
                "error": "quota_exceeded",
                "details": quota_check,
            }, indent=2))
        else:
            print(f"  BLOCKED: Agent '{args.agent}' is over quota")
            for v in quota_check.get("violations", []):
                print(f"    - {v}")
        return 1

    agent_ns = fleet.agent_namespace(args.agent)
    session_name = args.session or f"session_{int(__import__('time').time())}"
    out_dir = agent_ns / session_name

    profile = args.profile or os.environ.get("LIQUEFY_PROFILE", "default")
    pack_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(Path(args.src).expanduser().resolve()),
        "--out", str(out_dir),
        "--org", args.agent,
        "--profile", profile,
        "--verify-mode", args.verify_mode,
        "--mode", args.policy_mode,
        "--json",
    ]

    with fleet.lock(args.agent):
        result = subprocess.run(
            pack_cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}", "LIQUEFY_PROFILE": profile},
        )

    try:
        pack_data = json.loads(result.stdout)
    except Exception:
        pack_data = {"ok": False, "stderr": result.stderr[:500]}

    if pack_data.get("ok"):
        fleet.record_session(args.agent, session_name)

    if args.json:
        pack_data["schema_version"] = CLI_SCHEMA_VERSION
        pack_data["command"] = "ingest"
        pack_data["agent_id"] = args.agent
        pack_data["session"] = session_name
        print(json.dumps(pack_data, indent=2))
    else:
        if pack_data.get("ok"):
            res = pack_data.get("result", {})
            raw = res.get("total_original_bytes", 0)
            comp = res.get("total_compressed_bytes", 0)
            ratio = raw / max(1, comp)
            print(f"\n  Ingested for agent '{args.agent}'")
            print(f"  Session: {session_name}")
            print(f"  {_fmt_bytes(raw)} -> {_fmt_bytes(comp)} ({ratio:.1f}x)")
        else:
            print(f"  Ingest failed: {pack_data.get('stderr', pack_data)[:200]}")
        print()

    return 0 if pack_data.get("ok") else 1


def cmd_merge(args: argparse.Namespace) -> int:
    fleet = _fleet(args)

    strategy_map = {
        "last_write": MergeStrategy.LAST_WRITE_WINS,
        "largest": MergeStrategy.LARGEST_WINS,
        "priority": MergeStrategy.HIGHEST_PRIORITY,
        "both": MergeStrategy.KEEP_BOTH,
    }
    strategy = strategy_map.get(args.strategy, MergeStrategy.LAST_WRITE_WINS)

    result = fleet.merge_vaults(
        args.target,
        args.sources,
        strategy=strategy,
        dry_run=args.dry_run,
    )

    if args.json:
        result["schema_version"] = CLI_SCHEMA_VERSION
        result["command"] = "merge"
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Merge {'(DRY RUN) ' if args.dry_run else ''}into '{args.target}'")
        print(f"  Sources: {', '.join(args.sources)}")
        print(f"  Strategy: {args.strategy}")
        print(f"  Merged: {result['merged_vaults']} vaults")
        if result["conflicts"]:
            print(f"  Conflicts: {result['conflicts']}")
            for c in result.get("conflict_details", [])[:5]:
                print(f"    {c['path']}: {c['agent_a']} vs {c['agent_b']} -> {c['winner']}")
        if result.get("skipped_agents"):
            print(f"  Skipped: {', '.join(result['skipped_agents'])}")
        print()

    return 0


def cmd_gc(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    result = fleet.gc(
        max_age_days=args.max_age,
        respect_quotas=not args.no_quota,
        dry_run=args.dry_run,
    )

    if args.json:
        result["schema_version"] = CLI_SCHEMA_VERSION
        result["command"] = "gc"
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Fleet GC {'(DRY RUN) ' if args.dry_run else ''}")
        print(f"  Freed: {result['freed_human']}")
        print(f"  Removed vaults: {len(result['removed_vaults'])}")
        if result["removed_agents"]:
            print(f"  Removed agents: {', '.join(result['removed_agents'])}")
        for rv in result["removed_vaults"][:10]:
            reason = rv.get("reason", f"age={rv.get('age_days', '?')}d")
            print(f"    {rv['agent']}/{rv['vault']}: {_fmt_bytes(rv['bytes'])} ({reason})")
        print()

    return 0


def cmd_heartbeat(args: argparse.Namespace) -> int:
    fleet = _fleet(args)
    fleet.heartbeat(args.agent)
    if args.json:
        print(json.dumps({"ok": True, "agent_id": args.agent}, indent=2))
    else:
        print(f"  Heartbeat updated for '{args.agent}'")
    return 0


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-fleet", description="Multi-Agent Fleet Coordination")
    ap.add_argument("--fleet", default=DEFAULT_FLEET_ROOT, help="Fleet vault root (or set LIQUEFY_FLEET_ROOT)")
    sub = ap.add_subparsers(dest="command")

    p = sub.add_parser("register", help="Register an agent")
    p.add_argument("--agent", required=True, help="Agent ID")
    p.add_argument("--quota-mb", type=int, default=0, help="Storage quota in MB (0=unlimited)")
    p.add_argument("--max-files", type=int, default=0, help="Max file count (0=unlimited)")
    p.add_argument("--max-sessions", type=int, default=0, help="Max sessions per day (0=unlimited)")
    p.add_argument("--priority", type=int, default=10, help="Agent priority (higher=more important)")
    p.add_argument("--tags", nargs="*", help="Key=value tags (e.g., team=backend role=qa)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("deregister", help="Remove an agent")
    p.add_argument("--agent", required=True, help="Agent ID")
    p.add_argument("--purge", action="store_true", help="Delete all vault data")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("status", help="Fleet-wide status dashboard")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("quota", help="Check agent quota")
    p.add_argument("--agent", required=True, help="Agent ID")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("ingest", help="Compress directory for an agent")
    p.add_argument("--agent", required=True, help="Agent ID")
    p.add_argument("--src", required=True, help="Source directory")
    p.add_argument("--session", default=None, help="Session name (auto-generated if omitted)")
    p.add_argument("--profile", default=None, choices=["default", "ratio", "speed"])
    p.add_argument("--verify-mode", default="full", choices=["full", "fast", "off"])
    p.add_argument("--policy-mode", default="strict", choices=["strict", "balanced", "off"])
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("merge", help="Merge vaults across agents")
    p.add_argument("--target", required=True, help="Target agent ID")
    p.add_argument("--sources", nargs="+", required=True, help="Source agent IDs")
    p.add_argument("--strategy", default="last_write",
                   choices=["last_write", "largest", "priority", "both"])
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("gc", help="Fleet-wide garbage collection")
    p.add_argument("--max-age", type=int, default=0, help="Remove vaults older than N days")
    p.add_argument("--no-quota", action="store_true", help="Skip quota enforcement")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("heartbeat", help="Update agent heartbeat")
    p.add_argument("--agent", required=True, help="Agent ID")
    p.add_argument("--json", action="store_true")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    handlers = {
        "register": cmd_register,
        "deregister": cmd_deregister,
        "status": cmd_status,
        "quota": cmd_quota,
        "ingest": cmd_ingest,
        "merge": cmd_merge,
        "gc": cmd_gc,
        "heartbeat": cmd_heartbeat,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
