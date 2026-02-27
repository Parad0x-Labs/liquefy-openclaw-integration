#!/usr/bin/env python3
"""
liquefy_state_guard.py
======================
Persistent state protection for AI agents.

Prevents the "session reset amnesia" problem: agents lose wallet balances,
trade history, or other critical state when conversations reset, because
the data only lived in the context window.

State Guard enforces a simple discipline:
    - Critical state files are declared in a manifest
    - Before each run: verify all state files exist and are fresh
    - After each run: checkpoint state with SHA-256 hashes
    - On drift/corruption: warn or block the agent from acting

Commands:
    init      <workspace>           Create .liquefy-state-manifest.json
    check     <workspace>           Pre-flight: verify state files exist & match
    checkpoint <workspace>          Post-flight: record current state hashes
    status    <workspace>           Show state health dashboard
    recover   <workspace>           Restore last checkpointed state from backup
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

CLI_SCHEMA = "liquefy.state-guard.v1"
MANIFEST_NAME = ".liquefy-state-manifest.json"
CHECKPOINT_DIR = ".liquefy-state-checkpoints"

DEFAULT_STATE_FILES = [
    "wallet-state.json",
    "balances.json",
    "trade-history.jsonl",
    "positions.json",
    "credentials-meta.json",
    "agent-memory.json",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_sha256(fpath: Path) -> str:
    h = hashlib.sha256()
    with fpath.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    payload = {
        "schema_version": CLI_SCHEMA,
        "tool": "liquefy_state_guard",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    print(json.dumps(payload, indent=2))


def _load_manifest(workspace: Path) -> Optional[Dict[str, Any]]:
    mf = workspace / MANIFEST_NAME
    if not mf.exists():
        return None
    return json.loads(mf.read_text(encoding="utf-8"))


def _save_manifest(workspace: Path, manifest: Dict[str, Any]) -> Path:
    mf = workspace / MANIFEST_NAME
    mf.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return mf


def _discover_state_files(workspace: Path) -> List[str]:
    """Auto-detect state files that exist in the workspace."""
    found = []
    for candidate in DEFAULT_STATE_FILES:
        if (workspace / candidate).exists():
            found.append(candidate)
    for p in workspace.rglob("*-state.json"):
        rel = str(p.relative_to(workspace))
        if rel not in found and not rel.startswith("."):
            found.append(rel)
    for p in workspace.rglob("*-history.jsonl"):
        rel = str(p.relative_to(workspace))
        if rel not in found and not rel.startswith("."):
            found.append(rel)
    return sorted(set(found))


def _hash_state(workspace: Path, files: List[str]) -> Dict[str, Dict[str, Any]]:
    """Hash all declared state files, return per-file status."""
    result: Dict[str, Dict[str, Any]] = {}
    for rel in files:
        fpath = workspace / rel
        if fpath.exists():
            result[rel] = {
                "exists": True,
                "sha256": _file_sha256(fpath),
                "size_bytes": fpath.stat().st_size,
                "mtime": fpath.stat().st_mtime,
            }
        else:
            result[rel] = {"exists": False, "sha256": None, "size_bytes": 0, "mtime": None}
    return result


def cmd_init(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        if args.json:
            _emit("init", False, {"error": f"Workspace not found: {workspace}"})
        else:
            print(f"ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 1

    discovered = _discover_state_files(workspace)
    extra = [f for f in (args.files or []) if f not in discovered]
    all_files = sorted(set(discovered + extra))

    state_hashes = _hash_state(workspace, all_files)

    manifest = {
        "schema": "liquefy.state-manifest.v1",
        "created_utc": _utc_now(),
        "updated_utc": _utc_now(),
        "workspace": str(workspace),
        "critical_files": all_files,
        "policy": {
            "require_all_present": args.strict,
            "block_on_drift": args.strict,
            "max_staleness_seconds": args.max_stale or 3600,
        },
        "last_checkpoint": state_hashes,
    }

    mf_path = _save_manifest(workspace, manifest)

    if args.json:
        _emit("init", True, {
            "manifest_path": str(mf_path),
            "critical_files": all_files,
            "discovered": len(discovered),
            "added": len(extra),
            "files_present": sum(1 for v in state_hashes.values() if v["exists"]),
        })
    else:
        print(f"State Guard initialized: {mf_path}")
        print(f"  {len(all_files)} critical files declared ({sum(1 for v in state_hashes.values() if v['exists'])} present)")
        for f in all_files:
            status = "OK" if state_hashes[f]["exists"] else "MISSING"
            print(f"  [{status}] {f}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    manifest = _load_manifest(workspace)
    if not manifest:
        if args.json:
            _emit("check", False, {"error": "No state manifest. Run `state-guard init` first."})
        else:
            print("ERROR: no state manifest. Run `liquefy state-guard init` first.", file=sys.stderr)
        return 1

    files = manifest.get("critical_files", [])
    policy = manifest.get("policy", {})
    last_cp = manifest.get("last_checkpoint", {})
    current = _hash_state(workspace, files)

    issues: List[Dict[str, Any]] = []
    for rel in files:
        cur = current[rel]
        prev = last_cp.get(rel, {})

        if not cur["exists"]:
            issues.append({"file": rel, "issue": "missing", "severity": "critical"})
            continue

        if prev.get("sha256") and cur["sha256"] != prev["sha256"]:
            issues.append({
                "file": rel,
                "issue": "drifted",
                "severity": "warning",
                "previous_sha256": prev["sha256"],
                "current_sha256": cur["sha256"],
            })

        max_stale = policy.get("max_staleness_seconds", 3600)
        if cur["mtime"] and (time.time() - cur["mtime"]) > max_stale:
            issues.append({
                "file": rel,
                "issue": "stale",
                "severity": "warning",
                "age_seconds": round(time.time() - cur["mtime"]),
                "max_seconds": max_stale,
            })

    critical_count = sum(1 for i in issues if i["severity"] == "critical")
    require_all = policy.get("require_all_present", False)
    block_on_drift = policy.get("block_on_drift", False)
    drift_count = sum(1 for i in issues if i["issue"] == "drifted")

    ok = True
    if require_all and critical_count > 0:
        ok = False
    if block_on_drift and drift_count > 0:
        ok = False

    result = {
        "files_declared": len(files),
        "files_present": sum(1 for v in current.values() if v["exists"]),
        "issues": issues,
        "critical_missing": critical_count,
        "drifted": drift_count,
        "stale": sum(1 for i in issues if i["issue"] == "stale"),
        "policy_verdict": "PASS" if ok else "BLOCK",
        "state_hashes": current,
    }

    if args.json:
        _emit("check", ok, result)
    else:
        verdict = "PASS" if ok else "BLOCK"
        print(f"State Guard check: {verdict}")
        print(f"  {result['files_present']}/{result['files_declared']} files present")
        if issues:
            for i in issues:
                sev = i["severity"].upper()
                print(f"  [{sev}] {i['file']}: {i['issue']}")
        else:
            print("  All state files healthy.")

    return 0 if ok else 1


def cmd_checkpoint(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    manifest = _load_manifest(workspace)
    if not manifest:
        if args.json:
            _emit("checkpoint", False, {"error": "No state manifest. Run `state-guard init` first."})
        else:
            print("ERROR: no state manifest.", file=sys.stderr)
        return 1

    files = manifest.get("critical_files", [])
    current = _hash_state(workspace, files)

    cp_dir = workspace / CHECKPOINT_DIR
    cp_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cp_name = f"checkpoint-{ts}"
    cp_path = cp_dir / cp_name
    cp_path.mkdir(parents=True, exist_ok=True)

    backed_up: List[str] = []
    for rel in files:
        src = workspace / rel
        if src.exists():
            dst = cp_path / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            backed_up.append(rel)

    manifest["last_checkpoint"] = current
    manifest["updated_utc"] = _utc_now()
    manifest["last_checkpoint_dir"] = str(cp_path)
    _save_manifest(workspace, manifest)

    result = {
        "checkpoint": str(cp_path),
        "files_backed_up": backed_up,
        "state_hashes": current,
    }

    if args.json:
        _emit("checkpoint", True, result)
    else:
        print(f"Checkpoint saved: {cp_path}")
        print(f"  {len(backed_up)} files backed up")
        for f in backed_up:
            print(f"  - {f} ({current[f]['sha256'][:12]}...)")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    manifest = _load_manifest(workspace)
    if not manifest:
        if args.json:
            _emit("status", False, {"error": "No state manifest."})
        else:
            print("No state manifest found.", file=sys.stderr)
        return 1

    files = manifest.get("critical_files", [])
    current = _hash_state(workspace, files)
    last_cp = manifest.get("last_checkpoint", {})

    cp_dir = workspace / CHECKPOINT_DIR
    checkpoints = sorted(cp_dir.iterdir()) if cp_dir.exists() else []

    file_status = []
    for rel in files:
        cur = current[rel]
        prev = last_cp.get(rel, {})
        status = "ok"
        if not cur["exists"]:
            status = "missing"
        elif prev.get("sha256") and cur["sha256"] != prev["sha256"]:
            status = "drifted"
        file_status.append({
            "file": rel,
            "status": status,
            "sha256": cur.get("sha256"),
            "size_bytes": cur.get("size_bytes", 0),
        })

    result = {
        "workspace": str(workspace),
        "manifest_updated": manifest.get("updated_utc"),
        "files": file_status,
        "checkpoints_count": len(checkpoints),
        "last_checkpoint_dir": manifest.get("last_checkpoint_dir"),
        "policy": manifest.get("policy", {}),
    }

    if args.json:
        _emit("status", True, result)
    else:
        print(f"State Guard — {workspace}")
        print(f"  Last updated: {manifest.get('updated_utc', 'never')}")
        print(f"  Checkpoints: {len(checkpoints)}")
        print(f"  Files:")
        for fs in file_status:
            tag = {"ok": "OK", "missing": "MISSING", "drifted": "DRIFTED"}.get(fs["status"], fs["status"])
            print(f"    [{tag}] {fs['file']}")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    manifest = _load_manifest(workspace)
    if not manifest:
        if args.json:
            _emit("recover", False, {"error": "No state manifest."})
        else:
            print("ERROR: no state manifest.", file=sys.stderr)
        return 1

    cp_dir_str = manifest.get("last_checkpoint_dir")
    if not cp_dir_str:
        if args.json:
            _emit("recover", False, {"error": "No checkpoint found. Run `state-guard checkpoint` first."})
        else:
            print("ERROR: no checkpoint found.", file=sys.stderr)
        return 1

    cp_path = Path(cp_dir_str)
    if not cp_path.is_dir():
        if args.json:
            _emit("recover", False, {"error": f"Checkpoint dir missing: {cp_path}"})
        else:
            print(f"ERROR: checkpoint dir missing: {cp_path}", file=sys.stderr)
        return 1

    restored: List[str] = []
    skipped: List[str] = []
    for rel in manifest.get("critical_files", []):
        src = cp_path / rel
        dst = workspace / rel
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            restored.append(rel)
        else:
            skipped.append(rel)

    current = _hash_state(workspace, manifest.get("critical_files", []))
    manifest["last_checkpoint"] = current
    manifest["updated_utc"] = _utc_now()
    _save_manifest(workspace, manifest)

    result = {
        "recovered_from": str(cp_path),
        "restored": restored,
        "skipped": skipped,
        "state_hashes": current,
    }

    if args.json:
        _emit("recover", True, result)
    else:
        print(f"Recovered from: {cp_path}")
        print(f"  {len(restored)} files restored, {len(skipped)} skipped")
        for f in restored:
            print(f"  + {f}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-state-guard",
        description="Persistent state protection for AI agents",
    )
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_init = sub.add_parser("init", help="Create state manifest for a workspace")
    p_init.add_argument("workspace", help="Agent workspace directory")
    p_init.add_argument("--files", nargs="*", help="Additional state files to track")
    p_init.add_argument("--strict", action="store_true", help="Block agent if any state file is missing or drifted")
    p_init.add_argument("--max-stale", type=int, help="Max staleness in seconds (default 3600)")
    p_init.add_argument("--json", action="store_true")
    p_init.set_defaults(fn=cmd_init)

    p_check = sub.add_parser("check", help="Pre-flight: verify state files exist and match")
    p_check.add_argument("workspace")
    p_check.add_argument("--json", action="store_true")
    p_check.set_defaults(fn=cmd_check)

    p_cp = sub.add_parser("checkpoint", help="Post-flight: record current state hashes + backup")
    p_cp.add_argument("workspace")
    p_cp.add_argument("--json", action="store_true")
    p_cp.set_defaults(fn=cmd_checkpoint)

    p_status = sub.add_parser("status", help="Show state health dashboard")
    p_status.add_argument("workspace")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(fn=cmd_status)

    p_recover = sub.add_parser("recover", help="Restore last checkpointed state")
    p_recover.add_argument("workspace")
    p_recover.add_argument("--json", action="store_true")
    p_recover.set_defaults(fn=cmd_recover)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
