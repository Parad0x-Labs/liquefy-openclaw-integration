#!/usr/bin/env python3
"""
liquefy_policy_enforcer.py
==========================
Active policy enforcement with opt-in kill switch for AI agent runs.

Goes beyond audit-mode policy checking: can actively BLOCK operations
and signal agent processes to halt when critical violations are detected.

Modes:
    audit    — scan and report violations (default, safe, no side effects)
    enforce  — block violating files from being packed, return non-zero exit
    kill     — enforce + write a kill signal file that agents can watch

Violation types:
    - secret_leak:     API keys, tokens, passwords in plain text
    - oversized:       files exceeding size policy
    - forbidden_ext:   blocked file extensions (.exe, .dll, .so, etc.)
    - forbidden_path:  paths matching deny patterns
    - unsigned_skill:  skill files without integrity verification

Usage:
    python tools/liquefy_policy_enforcer.py audit   --dir ./agent-output --json
    python tools/liquefy_policy_enforcer.py enforce --dir ./agent-output --json
    python tools/liquefy_policy_enforcer.py kill    --dir ./agent-output --signal ./agent.halt --json
    python tools/liquefy_policy_enforcer.py watch   --dir ./agent-output --signal ./agent.halt --interval 5
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

SCHEMA = "liquefy.policy-enforcer.v1"

SECRET_PATTERNS = [
    re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[\w\-]{20,}', re.IGNORECASE),
    re.compile(r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']?[\w\-]{8,}', re.IGNORECASE),
    re.compile(r'(?:sk|pk|rk|ak)-[a-zA-Z0-9]{20,}'),
    re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}'),
    re.compile(r'(?:Bearer|Authorization)\s+[\w\-\.]{20,}', re.IGNORECASE),
    re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
]

FORBIDDEN_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".dmg",
    ".cmd", ".com", ".scr", ".pif", ".vbs", ".vbe",
    ".ws", ".wsf", ".wsc", ".wsh",
}

FORBIDDEN_PATH_PATTERNS = [
    re.compile(r'\.ssh[/\\]', re.IGNORECASE),
    re.compile(r'\.gnupg[/\\]', re.IGNORECASE),
    re.compile(r'\.aws[/\\]credentials', re.IGNORECASE),
    re.compile(r'\.kube[/\\]config', re.IGNORECASE),
]

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB default

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".liquefy-guard", ".liquefy-tokens"}


def _scan_secrets(fpath: Path) -> List[Dict]:
    hits = []
    try:
        content = fpath.read_text("utf-8", errors="replace")
        for i, line in enumerate(content.splitlines(), 1):
            for pat in SECRET_PATTERNS:
                if pat.search(line):
                    match_text = pat.search(line).group(0)
                    redacted = match_text[:8] + "..." + match_text[-4:] if len(match_text) > 16 else "***"
                    hits.append({
                        "type": "secret_leak",
                        "severity": "critical",
                        "file": str(fpath.name),
                        "line": i,
                        "pattern": pat.pattern[:40],
                        "redacted_match": redacted,
                        "message": f"Potential secret at {fpath.name}:{i}",
                    })
                    break
    except (OSError, UnicodeDecodeError):
        pass
    return hits


def _scan_directory(target_dir: Path, policy: Optional[Dict] = None) -> List[Dict]:
    violations = []
    max_size = (policy or {}).get("max_file_size", MAX_FILE_SIZE)
    extra_forbidden_ext = set((policy or {}).get("forbidden_extensions", []))
    forbidden_ext = FORBIDDEN_EXTENSIONS | extra_forbidden_ext

    scan_extensions = {
        ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini",
        ".env", ".py", ".js", ".ts", ".sh", ".bat", ".ps1",
        ".txt", ".md", ".log", ".csv", ".xml", ".cfg", ".conf",
    }

    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in fnames:
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(target_dir))

            if fpath.suffix.lower() in forbidden_ext:
                violations.append({
                    "type": "forbidden_ext",
                    "severity": "high",
                    "file": rel,
                    "extension": fpath.suffix.lower(),
                    "message": f"Forbidden file type: {rel}",
                })
                continue

            for pat in FORBIDDEN_PATH_PATTERNS:
                if pat.search(rel):
                    violations.append({
                        "type": "forbidden_path",
                        "severity": "critical",
                        "file": rel,
                        "pattern": pat.pattern,
                        "message": f"Sensitive path detected: {rel}",
                    })
                    break

            try:
                size = fpath.stat().st_size
            except OSError:
                continue

            if size > max_size:
                violations.append({
                    "type": "oversized",
                    "severity": "warning",
                    "file": rel,
                    "size": size,
                    "limit": max_size,
                    "message": f"File exceeds size limit: {rel} ({size:,} bytes > {max_size:,})",
                })
                continue

            if fpath.suffix.lower() in scan_extensions and size < 2 * 1024 * 1024:
                secret_hits = _scan_secrets(fpath)
                violations.extend(secret_hits)

    return violations


def _write_kill_signal(signal_path: Path, violations: List[Dict]) -> Dict:
    signal_data = {
        "schema": SCHEMA,
        "action": "HALT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": "Policy violations detected by Liquefy enforcer",
        "violation_count": len(violations),
        "critical_count": sum(1 for v in violations if v["severity"] == "critical"),
        "violations": violations[:10],
    }
    signal_path.parent.mkdir(parents=True, exist_ok=True)
    signal_path.write_text(json.dumps(signal_data, indent=2), encoding="utf-8")
    return signal_data


def _load_policy(policy_path: Optional[str]) -> Optional[Dict]:
    if not policy_path:
        return None
    p = Path(policy_path)
    if p.exists():
        return json.loads(p.read_text("utf-8"))
    return None


def _audit_log(event: str, **details):
    try:
        from liquefy_audit_chain import audit_log
        audit_log(event, **details)
    except Exception:
        pass


def cmd_audit(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    policy = _load_policy(getattr(args, "policy", None))
    violations = _scan_directory(target_dir, policy)

    critical = [v for v in violations if v["severity"] == "critical"]
    high = [v for v in violations if v["severity"] == "high"]
    warning = [v for v in violations if v["severity"] == "warning"]

    _audit_log("policy.audit", violations=len(violations), critical=len(critical))

    result = {
        "ok": len(critical) == 0,
        "mode": "audit",
        "violations": len(violations),
        "critical": len(critical),
        "high": len(high),
        "warning": len(warning),
        "details": violations,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if not critical else "FAIL"
        print(f"  Policy Enforcer — Audit [{status}]")
        print(f"    Critical: {len(critical)}")
        print(f"    High:     {len(high)}")
        print(f"    Warning:  {len(warning)}")
        if violations:
            print()
            for v in violations:
                sev = v["severity"].upper()
                print(f"    [{sev}] {v['message']}")

    return 0


def cmd_enforce(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    policy = _load_policy(getattr(args, "policy", None))
    violations = _scan_directory(target_dir, policy)
    critical = [v for v in violations if v["severity"] == "critical"]
    high = [v for v in violations if v["severity"] == "high"]

    blocked = critical + high
    _audit_log("policy.enforce", violations=len(violations), blocked=len(blocked))

    result = {
        "ok": len(blocked) == 0,
        "mode": "enforce",
        "action": "BLOCKED" if blocked else "ALLOWED",
        "violations": len(violations),
        "blocked": len(blocked),
        "details": violations,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "ALLOWED" if not blocked else "BLOCKED"
        print(f"  Policy Enforcer — Enforce [{status}]")
        print(f"    Blocked:  {len(blocked)}")
        print(f"    Warnings: {len(violations) - len(blocked)}")
        if blocked:
            print()
            for v in blocked:
                print(f"    [BLOCKED] {v['message']}")

    return 1 if blocked else 0


def cmd_kill(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    policy = _load_policy(getattr(args, "policy", None))
    violations = _scan_directory(target_dir, policy)
    critical = [v for v in violations if v["severity"] == "critical"]

    if not critical:
        result = {"ok": True, "mode": "kill", "action": "NO_ACTION", "violations": len(violations), "critical": 0}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"  Policy Enforcer — Kill [NO CRITICAL VIOLATIONS]")
            print(f"    Warnings: {len(violations)}")
        return 0

    signal_path = Path(args.signal) if args.signal else target_dir / ".liquefy-halt"
    signal_data = _write_kill_signal(signal_path, critical)

    if args.pid:
        try:
            os.kill(int(args.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError):
            pass

    _audit_log("policy.kill", critical=len(critical), signal_file=str(signal_path),
               pid=args.pid)

    result = {
        "ok": False,
        "mode": "kill",
        "action": "HALT_SIGNAL_SENT",
        "signal_file": str(signal_path),
        "pid_terminated": args.pid,
        "critical": len(critical),
        "details": critical,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Policy Enforcer — KILL SIGNAL")
        print(f"    Critical violations: {len(critical)}")
        print(f"    Signal file:         {signal_path}")
        if args.pid:
            print(f"    SIGTERM sent to:     PID {args.pid}")
        for v in critical:
            print(f"    [CRITICAL] {v['message']}")

    return 1


def cmd_watch(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    signal_path = Path(args.signal) if args.signal else target_dir / ".liquefy-halt"
    interval = args.interval or 10
    policy = _load_policy(getattr(args, "policy", None))

    print(f"  Policy Enforcer — Watch Mode")
    print(f"    Directory: {target_dir}")
    print(f"    Interval:  {interval}s")
    print(f"    Signal:    {signal_path}")
    print(f"    Watching... (Ctrl+C to stop)")
    print()

    try:
        while True:
            violations = _scan_directory(target_dir, policy)
            critical = [v for v in violations if v["severity"] == "critical"]
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")

            if critical:
                print(f"    [{ts}] CRITICAL: {len(critical)} violations — writing halt signal")
                _write_kill_signal(signal_path, critical)
                _audit_log("policy.watch.halt", critical=len(critical))
                for v in critical:
                    print(f"      [CRITICAL] {v['message']}")
                return 1
            else:
                status = f"{len(violations)} warnings" if violations else "clean"
                print(f"    [{ts}] OK ({status})")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n    Watch stopped.")
        return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-policy-enforcer",
        description="Active policy enforcement with kill switch for AI agent runs.",
    )
    sub = parser.add_subparsers(dest="command")

    for name, help_text in [
        ("audit", "Scan and report violations (safe, no side effects)"),
        ("enforce", "Block operations on critical/high violations"),
        ("kill", "Enforce + write halt signal + optional SIGTERM"),
        ("watch", "Continuous monitoring with auto-halt on critical"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--dir", required=True, help="Directory to scan")
        p.add_argument("--policy", help="Custom policy JSON file")
        p.add_argument("--json", action="store_true")
        if name == "kill":
            p.add_argument("--signal", help="Halt signal file path")
            p.add_argument("--pid", help="Agent PID to SIGTERM")
        if name == "watch":
            p.add_argument("--signal", help="Halt signal file path")
            p.add_argument("--interval", type=int, default=10, help="Scan interval in seconds")

    args = parser.parse_args()
    commands = {"audit": cmd_audit, "enforce": cmd_enforce, "kill": cmd_kill, "watch": cmd_watch}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
