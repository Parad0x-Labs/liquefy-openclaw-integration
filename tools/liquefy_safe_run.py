#!/usr/bin/env python3
"""
liquefy_safe_run.py
===================
Automated rollback wrapper for AI agent execution.

Pattern: snapshot -> run -> if halt signal -> auto-restore.

Wraps any agent command with pre-flight state capture and automatic
rollback on policy violations or crashes.

Usage:
    python tools/liquefy_safe_run.py --workspace ~/.openclaw --cmd "openclaw run task.md" --json
    python tools/liquefy_safe_run.py --workspace ~/.openclaw --cmd "python agent.py" --policy ./policies/strict.yml
    python tools/liquefy_safe_run.py --workspace ~/.openclaw --cmd "openclaw run" --sentinels SOUL.md,HEARTBEAT.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

SCHEMA = "liquefy.safe-run.v2"
SNAPSHOT_DIR_NAME = ".liquefy-safe-run"
HEARTBEAT_FILE = ".liquefy-heartbeat"
HEARTBEAT_INTERVAL = 5  # seconds

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}


def _file_sha256(fpath: Path) -> str:
    h = hashlib.sha256()
    with fpath.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_workspace(workspace: Path, snapshot_dir: Path) -> Dict:
    """Capture full state of workspace for rollback."""
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    manifest = {}
    file_count = 0
    total_bytes = 0

    for root, dirs, fnames in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d != SNAPSHOT_DIR_NAME]
        for fname in fnames:
            src = Path(root) / fname
            rel = str(src.relative_to(workspace))
            try:
                size = src.stat().st_size
                sha = _file_sha256(src)
                dest = snapshot_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                manifest[rel] = {"sha256": sha, "size": size}
                file_count += 1
                total_bytes += size
            except (OSError, PermissionError):
                continue

    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "files": manifest,
    }
    (snapshot_dir / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _hash_sentinel_files(workspace: Path, sentinels: List[str]) -> Dict[str, str]:
    """Hash specific critical files before the run."""
    hashes = {}
    for name in sentinels:
        fpath = workspace / name
        if fpath.exists():
            hashes[name] = _file_sha256(fpath)
        else:
            hashes[name] = "MISSING"
    return hashes


def _check_sentinels(workspace: Path, sentinels: List[str], pre_hashes: Dict[str, str]) -> List[Dict]:
    """Compare sentinel files post-run. Return list of tampered files."""
    tampered = []
    for name in sentinels:
        fpath = workspace / name
        pre = pre_hashes.get(name, "MISSING")
        if fpath.exists():
            post = _file_sha256(fpath)
        else:
            post = "MISSING"

        if pre != post:
            tampered.append({
                "file": name,
                "pre_hash": pre[:16],
                "post_hash": post[:16],
                "status": "DELETED" if post == "MISSING" else ("CREATED" if pre == "MISSING" else "MODIFIED"),
            })
    return tampered


def _restore_workspace(workspace: Path, snapshot_dir: Path) -> Dict:
    """Restore workspace to pre-run snapshot state."""
    manifest_file = snapshot_dir / "manifest.json"
    if not manifest_file.exists():
        return {"ok": False, "error": "No snapshot manifest found"}

    manifest = json.loads(manifest_file.read_text("utf-8"))
    restored = 0
    errors = 0

    current_files = set()
    for root, dirs, fnames in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d != SNAPSHOT_DIR_NAME]
        for fname in fnames:
            src = Path(root) / fname
            rel = str(src.relative_to(workspace))
            current_files.add(rel)

    for rel in current_files - set(manifest["files"].keys()):
        try:
            (workspace / rel).unlink()
        except OSError:
            pass

    for rel, info in manifest["files"].items():
        src = snapshot_dir / rel
        dest = workspace / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            restored += 1
        except (OSError, PermissionError):
            errors += 1

    return {"ok": errors == 0, "restored": restored, "errors": errors}


def _run_enforcer(workspace: Path, policy: Optional[str] = None, trace_id: Optional[str] = None) -> Dict:
    """Run policy enforcer against workspace post-run."""
    cmd = [
        sys.executable, str(TOOLS_DIR / "liquefy_policy_enforcer.py"),
        "enforce", "--dir", str(workspace), "--json",
    ]
    if policy:
        cmd.extend(["--policy", policy])
    if trace_id:
        cmd.extend(["--trace-id", trace_id])

    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{TOOLS_DIR}:{API_DIR}:{env.get('PYTHONPATH', '')}"
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        return json.loads(proc.stdout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _start_heartbeat(workspace: Path) -> Optional[int]:
    """Spawn a background heartbeat writer. Returns PID or None."""
    hb_path = workspace / HEARTBEAT_FILE
    try:
        import threading

        def _writer():
            while True:
                try:
                    hb_path.write_text(json.dumps({
                        "pid": os.getpid(),
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "interval_s": HEARTBEAT_INTERVAL,
                    }), encoding="utf-8")
                except OSError:
                    break
                time.sleep(HEARTBEAT_INTERVAL)

        t = threading.Thread(target=_writer, daemon=True)
        t.start()
        return os.getpid()
    except Exception:
        return None


def _stop_heartbeat(workspace: Path):
    hb = workspace / HEARTBEAT_FILE
    try:
        hb.unlink(missing_ok=True)
    except OSError:
        pass


def _check_token_cost(workspace: Path, max_cost: float) -> Optional[Dict]:
    """Post-run check: scan workspace for token usage, return overspend info."""
    try:
        from liquefy_token_ledger import _scan_file, _estimate_cost
    except ImportError:
        return None

    total_cost = 0.0
    total_tokens = 0
    for root, dirs, fnames in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d != SNAPSHOT_DIR_NAME]
        for fname in fnames:
            fpath = Path(root) / fname
            if fpath.suffix in (".json", ".jsonl", ".log", ".txt"):
                try:
                    entries = _scan_file(fpath)
                    for e in entries:
                        total_tokens += e.get("total_tokens", 0)
                        model = e.get("model", "unknown") or "unknown"
                        cost = _estimate_cost(
                            model,
                            e.get("input_tokens", 0),
                            e.get("output_tokens", 0),
                        )
                        total_cost += cost
                except Exception:
                    continue

    if total_cost > max_cost:
        return {
            "exceeded": True,
            "total_cost_usd": round(total_cost, 6),
            "max_cost_usd": max_cost,
            "total_tokens": total_tokens,
        }
    return {
        "exceeded": False,
        "total_cost_usd": round(total_cost, 6),
        "max_cost_usd": max_cost,
        "total_tokens": total_tokens,
    }


def _audit_log(event: str, **details):
    try:
        from liquefy_audit_chain import audit_log
        audit_log(event, **details)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(
        prog="liquefy-safe-run",
        description="Automated rollback wrapper: snapshot -> run -> enforce -> restore on violation.",
    )
    ap.add_argument("--workspace", required=True, help="Agent workspace to protect")
    ap.add_argument("--cmd", required=True, help="Agent command to execute")
    ap.add_argument("--policy", help="Policy file for enforcement")
    ap.add_argument("--trace-id", help="Correlation ID for multi-agent tracing")
    ap.add_argument("--sentinels", default="",
                    help="Comma-separated critical files to monitor (e.g. SOUL.md,HEARTBEAT.md,auth-profiles.json)")
    ap.add_argument("--timeout", type=int, default=300, help="Agent command timeout in seconds")
    ap.add_argument("--max-cost", type=float,
                    help="Kill and rollback if agent run exceeds this USD cost (requires token metadata in logs)")
    ap.add_argument("--heartbeat", action="store_true",
                    help="Write a heartbeat file so agents can verify monitoring is alive")
    ap.add_argument("--no-restore", action="store_true", help="Report violations but skip auto-restore")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        result = {"ok": False, "error": f"Workspace not found: {workspace}"}
        print(json.dumps(result, indent=2) if args.json else f"ERROR: {result['error']}")
        return 1

    trace_id = args.trace_id or os.environ.get("LIQUEFY_TRACE_ID")
    sentinels = [s.strip() for s in args.sentinels.split(",") if s.strip()]
    snapshot_dir = workspace / SNAPSHOT_DIR_NAME

    # ── Phase 1: Pre-flight snapshot ──
    snapshot_meta = _snapshot_workspace(workspace, snapshot_dir)
    pre_sentinel_hashes = _hash_sentinel_files(workspace, sentinels) if sentinels else {}

    _audit_log("safe_run.snapshot", files=snapshot_meta["file_count"],
               bytes=snapshot_meta["total_bytes"],
               **({"trace_id": trace_id} if trace_id else {}))

    if not args.json:
        print(f"  Safe Run — Snapshot")
        print(f"    Files:  {snapshot_meta['file_count']}")
        print(f"    Bytes:  {snapshot_meta['total_bytes']:,}")
        if sentinels:
            print(f"    Sentinels: {', '.join(sentinels)}")
        print()

    # ── Phase 1b: Start heartbeat (Dead Man's Switch) ──
    hb_pid = None
    if args.heartbeat:
        hb_pid = _start_heartbeat(workspace)
        if not args.json and hb_pid:
            print(f"  Safe Run — Heartbeat active (every {HEARTBEAT_INTERVAL}s)")
            print(f"    File: {workspace / HEARTBEAT_FILE}")
            print()

    # ── Phase 2: Execute agent command ──
    start = time.time()
    try:
        proc = subprocess.run(
            args.cmd, shell=True, timeout=args.timeout,
            capture_output=True, text=True, cwd=str(workspace),
        )
        exit_code = proc.returncode
        agent_stdout = proc.stdout[-2000:] if proc.stdout else ""
        agent_stderr = proc.stderr[-2000:] if proc.stderr else ""
    except subprocess.TimeoutExpired:
        exit_code = -1
        agent_stdout = ""
        agent_stderr = "TIMEOUT"
    except Exception as e:
        exit_code = -2
        agent_stdout = ""
        agent_stderr = str(e)

    elapsed = round(time.time() - start, 2)
    agent_crashed = exit_code != 0

    if not args.json:
        status = "OK" if not agent_crashed else f"FAILED (exit {exit_code})"
        print(f"  Safe Run — Execute [{status}]")
        print(f"    Command:  {args.cmd}")
        print(f"    Duration: {elapsed}s")
        print()

    # ── Phase 2b: Stop heartbeat ──
    if hb_pid:
        _stop_heartbeat(workspace)

    # ── Phase 3: Post-run enforcement ──
    enforce_result = _run_enforcer(workspace, args.policy, trace_id)
    policy_blocked = not enforce_result.get("ok", True)

    sentinel_tampered = []
    if sentinels:
        sentinel_tampered = _check_sentinels(workspace, sentinels, pre_sentinel_hashes)

    # ── Phase 3b: Token cost enforcement ──
    cost_result = None
    cost_exceeded = False
    if args.max_cost is not None:
        cost_result = _check_token_cost(workspace, args.max_cost)
        if cost_result and cost_result.get("exceeded"):
            cost_exceeded = True
            if not args.json:
                print(f"  Safe Run — Cost EXCEEDED")
                print(f"    Spent:   ${cost_result['total_cost_usd']:.4f}")
                print(f"    Limit:   ${args.max_cost:.4f}")
                print(f"    Tokens:  {cost_result['total_tokens']:,}")
                print()
            _audit_log("safe_run.cost_exceeded",
                       cost_usd=cost_result["total_cost_usd"],
                       limit_usd=args.max_cost,
                       tokens=cost_result["total_tokens"],
                       **({"trace_id": trace_id} if trace_id else {}))
        elif cost_result and not args.json:
            print(f"  Safe Run — Cost OK (${cost_result['total_cost_usd']:.4f} / ${args.max_cost:.4f})")
            print()

    needs_rollback = agent_crashed or policy_blocked or len(sentinel_tampered) > 0 or cost_exceeded

    if not args.json:
        if policy_blocked:
            print(f"  Safe Run — Policy BLOCKED")
            print(f"    Violations: {enforce_result.get('violations', '?')}")
        if sentinel_tampered:
            print(f"  Safe Run — Sentinel TAMPERED")
            for t in sentinel_tampered:
                print(f"    [{t['status']}] {t['file']}")
        if not needs_rollback:
            print(f"  Safe Run — All Clear")
        print()

    # ── Phase 4: Auto-restore if needed ──
    restore_result = None
    if needs_rollback and not args.no_restore:
        restore_result = _restore_workspace(workspace, snapshot_dir)
        _audit_log("safe_run.rollback",
                   reason="policy_violation" if policy_blocked else ("sentinel_tampered" if sentinel_tampered else "agent_crash"),
                   restored=restore_result.get("restored", 0),
                   **({"trace_id": trace_id} if trace_id else {}))

        if not args.json:
            status = "OK" if restore_result["ok"] else "PARTIAL"
            print(f"  Safe Run — Rollback [{status}]")
            print(f"    Restored: {restore_result.get('restored', 0)} files")
            if restore_result.get("errors"):
                print(f"    Errors:   {restore_result['errors']}")
    elif needs_rollback:
        if not args.json:
            print(f"  Safe Run — Rollback SKIPPED (--no-restore)")

    _audit_log("safe_run.complete",
               agent_exit=exit_code, policy_blocked=policy_blocked,
               sentinel_tampered=len(sentinel_tampered), rolled_back=restore_result is not None,
               **({"trace_id": trace_id} if trace_id else {}))

    result = {
        "schema": SCHEMA,
        "ok": not needs_rollback,
        **({"trace_id": trace_id} if trace_id else {}),
        "phases": {
            "snapshot": {"files": snapshot_meta["file_count"], "bytes": snapshot_meta["total_bytes"]},
            "execute": {"exit_code": exit_code, "duration_s": elapsed, "crashed": agent_crashed},
            "enforce": enforce_result,
            "sentinels": {"monitored": sentinels, "tampered": sentinel_tampered},
            **({"cost": cost_result} if cost_result else {}),
            "rollback": restore_result,
        },
        "heartbeat_active": hb_pid is not None,
        "needs_rollback": needs_rollback,
        "rolled_back": restore_result is not None and restore_result.get("ok", False),
    }

    if args.json:
        print(json.dumps(result, indent=2))

    if needs_rollback:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        return 1

    shutil.rmtree(snapshot_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
