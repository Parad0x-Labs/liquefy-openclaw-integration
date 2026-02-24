#!/usr/bin/env python3
"""
liquefy_sandbox.py
==================
Skill Sandbox Tester — run any ClawHub skill in an isolated sandbox,
capture its trace to an isolated vault, auto-redact scan, approve/reject.

Uses firejail (Linux) or sandbox-exec (macOS) for process isolation.
Falls back to a restricted subprocess with limited env if neither is available.

Commands:
    run       — run a skill in sandbox, capture trace, scan, report
    approve   — mark a sandboxed skill run as approved
    reject    — mark a sandboxed skill run as rejected + quarantine artifacts
    list      — list previous sandbox runs

Usage:
    python tools/liquefy_sandbox.py run ./skills/my_skill --timeout 60
    python tools/liquefy_sandbox.py list
    python tools/liquefy_sandbox.py approve --run-id abc123
    python tools/liquefy_sandbox.py reject  --run-id abc123
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
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

CLI_SCHEMA_VERSION = "liquefy.sandbox.cli.v1"

SANDBOX_BASE = Path(os.environ.get("LIQUEFY_SANDBOX_DIR", str(REPO_ROOT / ".liquefy" / "sandbox")))

ENV_ALLOWLIST = {
    "PATH", "HOME", "USER", "LANG", "TERM", "SHELL",
    "PYTHONPATH", "VIRTUAL_ENV",
    "LIQUEFY_PROFILE",
}

ENV_DENYLIST = {
    "LIQUEFY_SECRET", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "SLACK_TOKEN", "DISCORD_TOKEN", "DATABASE_URL",
    "STRIPE_SECRET_KEY", "TELEGRAM_BOT_TOKEN",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id() -> str:
    return hashlib.sha256(f"{time.time()}{os.getpid()}".encode()).hexdigest()[:12]


def _sanitized_env() -> Dict[str, str]:
    """Build a minimal environment for sandboxed execution."""
    env = {}
    for key, value in os.environ.items():
        if key in ENV_DENYLIST:
            continue
        if key in ENV_ALLOWLIST or key.startswith("LC_"):
            env[key] = value
    return env


def _has_firejail() -> bool:
    return shutil.which("firejail") is not None


def _has_sandbox_exec() -> bool:
    return platform.system() == "Darwin" and shutil.which("sandbox-exec") is not None


def _firejail_cmd(skill_dir: Path, entry: str, work_dir: Path, timeout: int) -> List[str]:
    return [
        "firejail",
        "--quiet",
        "--noprofile",
        "--private=" + str(work_dir),
        "--read-only=" + str(skill_dir),
        "--noroot",
        "--nosound",
        "--no3d",
        "--net=none",
        "--timeout=" + str(timeout),
        sys.executable, str(skill_dir / entry),
    ]


def _sandbox_exec_cmd(skill_dir: Path, entry: str, work_dir: Path, timeout: int) -> List[str]:
    profile = (
        '(version 1)\n'
        '(allow default)\n'
        '(deny network*)\n'
        f'(deny file-write* (subpath "/"))\n'
        f'(allow file-write* (subpath "{work_dir}"))\n'
        f'(allow file-read* (subpath "{skill_dir}"))\n'
        f'(allow file-read* (subpath "{work_dir}"))\n'
    )
    profile_file = work_dir / ".sandbox_profile"
    profile_file.write_text(profile, encoding="utf-8")
    return [
        "sandbox-exec", "-f", str(profile_file),
        sys.executable, str(skill_dir / entry),
    ]


def _fallback_cmd(skill_dir: Path, entry: str, work_dir: Path) -> List[str]:
    return [sys.executable, str(skill_dir / entry)]


def _find_entry(skill_dir: Path) -> str:
    """Determine skill entry point from skill.json or defaults."""
    manifest = skill_dir / "skill.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            return data.get("entry", "trigger.py")
        except Exception:
            pass

    for candidate in ("trigger.py", "main.py", "skill.py", "__main__.py"):
        if (skill_dir / candidate).exists():
            return candidate

    raise FileNotFoundError(f"No entry point found in {skill_dir}")


def cmd_run(args: argparse.Namespace) -> int:
    """Run a skill in sandbox, capture trace, scan for leaks, report."""
    skill_dir = Path(args.skill).expanduser().resolve()
    if not skill_dir.exists():
        print(f"Skill not found: {skill_dir}", file=sys.stderr)
        return 1

    try:
        entry = _find_entry(skill_dir)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    rid = _run_id()
    run_dir = SANDBOX_BASE / rid
    work_dir = run_dir / "workspace"
    trace_dir = run_dir / "trace"
    work_dir.mkdir(parents=True, exist_ok=True)
    trace_dir.mkdir(parents=True, exist_ok=True)

    shutil.copytree(skill_dir, work_dir / "skill", dirs_exist_ok=True)

    env = _sanitized_env()
    env["LIQUEFY_SANDBOX"] = "1"
    env["LIQUEFY_SANDBOX_RUN_ID"] = rid
    env["OPENCLAW_SKILL_COMMAND"] = args.command_name or "status"

    if _has_firejail():
        cmd = _firejail_cmd(skill_dir, entry, work_dir, args.timeout)
        isolation = "firejail"
    elif _has_sandbox_exec():
        cmd = _sandbox_exec_cmd(skill_dir, entry, work_dir, args.timeout)
        isolation = "sandbox-exec"
    else:
        cmd = _fallback_cmd(skill_dir, entry, work_dir)
        isolation = "restricted-subprocess"

    print(f"[sandbox] run_id={rid} isolation={isolation} skill={skill_dir.name}", file=sys.stderr)
    print(f"[sandbox] entry={entry} timeout={args.timeout}s", file=sys.stderr)

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout,
            env=env,
            cwd=str(work_dir),
        )
        elapsed = time.time() - start
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        elapsed = args.timeout
        exit_code = -1
        stdout = ""
        stderr = f"TIMEOUT after {args.timeout}s"

    (trace_dir / "stdout.log").write_text(stdout, encoding="utf-8")
    (trace_dir / "stderr.log").write_text(stderr, encoding="utf-8")

    leak_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "liquefy_leakhunter.py"),
        "scan", str(work_dir),
        "--deep",
        "--json",
    ]
    try:
        leak_result = subprocess.run(leak_cmd, capture_output=True, text=True, timeout=120)
        leak_data = json.loads(leak_result.stdout) if leak_result.stdout.strip() else {}
    except Exception:
        leak_data = {"error": "leak scan failed"}

    leak_findings = leak_data.get("result", {}).get("total_findings", 0)
    leak_critical = leak_data.get("result", {}).get("critical", 0)

    vault_cmd = [
        sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(work_dir),
        "--out", str(trace_dir / "vault"),
        "--org", "sandbox",
        "--profile", "default",
        "--verify-mode", "full",
        "--json",
    ]
    try:
        subprocess.run(vault_cmd, capture_output=True, text=True, timeout=120)
    except Exception:
        pass

    run_meta = {
        "run_id": rid,
        "skill": skill_dir.name,
        "entry": entry,
        "isolation": isolation,
        "ts": _utc_now(),
        "elapsed_seconds": round(elapsed, 2),
        "exit_code": exit_code,
        "status": "completed" if exit_code == 0 else ("timeout" if exit_code == -1 else "failed"),
        "leak_findings": leak_findings,
        "leak_critical": leak_critical,
        "verdict": "pending",
        "stdout_lines": len(stdout.splitlines()),
        "stderr_lines": len(stderr.splitlines()),
    }

    (run_dir / "run_meta.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

    (trace_dir / "leak_scan.json").write_text(json.dumps(leak_data, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps({"ok": True, "result": run_meta}, indent=2))
    else:
        print(f"\n{'═' * 60}")
        print(f"  SANDBOX RUN COMPLETE")
        print(f"{'═' * 60}")
        print(f"  Run ID:     {rid}")
        print(f"  Skill:      {skill_dir.name}")
        print(f"  Isolation:  {isolation}")
        print(f"  Exit Code:  {exit_code}")
        print(f"  Duration:   {elapsed:.1f}s")
        print(f"  Leaks:      {leak_findings} ({leak_critical} critical)")
        print(f"  Verdict:    PENDING — run 'approve' or 'reject'")
        if leak_critical > 0:
            print(f"\n  *** CRITICAL LEAKS DETECTED — review before approving ***")
        print(f"\n  Trace: {trace_dir}")
        print()

    return 0 if exit_code == 0 and leak_critical == 0 else 1


def cmd_approve(args: argparse.Namespace) -> int:
    run_dir = SANDBOX_BASE / args.run_id
    meta_path = run_dir / "run_meta.json"
    if not meta_path.exists():
        print(f"Run not found: {args.run_id}", file=sys.stderr)
        return 1

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["verdict"] = "approved"
    meta["verdict_ts"] = _utc_now()
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Run {args.run_id} APPROVED")
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    run_dir = SANDBOX_BASE / args.run_id
    meta_path = run_dir / "run_meta.json"
    if not meta_path.exists():
        print(f"Run not found: {args.run_id}", file=sys.stderr)
        return 1

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["verdict"] = "rejected"
    meta["verdict_ts"] = _utc_now()
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    quarantine_dir = run_dir / "quarantined"
    workspace = run_dir / "workspace"
    if workspace.exists():
        shutil.move(str(workspace), str(quarantine_dir))

    print(f"Run {args.run_id} REJECTED — workspace quarantined")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if not SANDBOX_BASE.exists():
        print("No sandbox runs found")
        return 0

    runs = []
    for run_dir in sorted(SANDBOX_BASE.iterdir(), reverse=True):
        meta_path = run_dir / "run_meta.json"
        if meta_path.exists():
            try:
                runs.append(json.loads(meta_path.read_text(encoding="utf-8")))
            except Exception:
                pass

    if args.json:
        print(json.dumps({"ok": True, "runs": runs}, indent=2))
    else:
        if not runs:
            print("No sandbox runs found")
            return 0

        print(f"\n{'Run ID':<14} {'Skill':<20} {'Status':<10} {'Verdict':<10} {'Leaks':<6} {'Time'}")
        print(f"{'─' * 14} {'─' * 20} {'─' * 10} {'─' * 10} {'─' * 6} {'─' * 20}")
        for r in runs[:20]:
            print(f"{r['run_id']:<14} {r['skill']:<20} {r['status']:<10} "
                  f"{r['verdict']:<10} {r['leak_findings']:<6} {r.get('ts', '?')}")
        print()

    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-sandbox", description="Liquefy Skill Sandbox Tester")
    sub = ap.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="Run a skill in sandbox")
    p_run.add_argument("skill", help="Path to skill directory")
    p_run.add_argument("--timeout", type=int, default=60, help="Max execution time in seconds")
    p_run.add_argument("--command-name", default="status", help="Skill command to invoke")
    p_run.add_argument("--json", action="store_true")

    p_approve = sub.add_parser("approve", help="Approve a sandbox run")
    p_approve.add_argument("--run-id", required=True)

    p_reject = sub.add_parser("reject", help="Reject a sandbox run")
    p_reject.add_argument("--run-id", required=True)

    p_list = sub.add_parser("list", help="List sandbox runs")
    p_list.add_argument("--json", action="store_true")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    handlers = {
        "run": cmd_run,
        "approve": cmd_approve,
        "reject": cmd_reject,
        "list": cmd_list,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
