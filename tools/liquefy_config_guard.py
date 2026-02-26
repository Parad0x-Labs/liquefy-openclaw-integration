#!/usr/bin/env python3
"""
liquefy_config_guard.py
=======================
Snapshot, restore, and diff user customizations across framework updates.

Solves the universal "update overwrites my configs" problem for any agent
framework (OpenClaw, NanoClaw, LangChain, CrewAI, etc.).

Workflow:
    1. save    — fingerprint + vault all customized files before update
    2. restore — after update, merge back overwritten customizations
    3. diff    — show what changed between your snapshot and current state
    4. status  — list guarded files and their current state (unchanged/modified/deleted)

Guard snapshots are stored in `.liquefy-guard/` inside the target directory
and tracked in the Liquefy audit chain.

Usage:
    python tools/liquefy_config_guard.py save    --dir ./my-agent
    python tools/liquefy_config_guard.py restore --dir ./my-agent
    python tools/liquefy_config_guard.py diff    --dir ./my-agent
    python tools/liquefy_config_guard.py status  --dir ./my-agent
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
from typing import Any, Dict, List, Optional, Set, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

GUARD_DIR = ".liquefy-guard"
MANIFEST_FILE = "manifest.json"
SCHEMA = "liquefy.config-guard.v1"

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".env.local", ".env.production",
    ".xml", ".properties",
    ".md", ".txt", ".rst",
    ".py", ".js", ".ts", ".sh", ".bat", ".ps1",
    ".dockerfile", ".dockerignore",
    ".gitignore", ".npmrc", ".nvmrc",
    ".cursorrules",
}

CONFIG_FILENAMES = {
    "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "package.json", "tsconfig.json", "pyproject.toml", "setup.cfg",
    "requirements.txt", "Pipfile", ".env", ".env.local",
    "Cargo.toml", "go.mod", "go.sum",
    "AGENTS.md", "SKILL.md", "RULES.md",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".liquefy-guard", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "target", "vendor",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB per file


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _is_config_file(path: Path) -> bool:
    if path.name in CONFIG_FILENAMES:
        return True
    if path.suffix.lower() in CONFIG_EXTENSIONS:
        return True
    return False


def _collect_files(target_dir: Path, patterns: Optional[List[str]] = None) -> List[Path]:
    """Collect config/customization files from a directory."""
    files = []
    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            if fpath.stat().st_size > MAX_FILE_SIZE:
                continue
            if patterns:
                rel = str(fpath.relative_to(target_dir))
                if any(_match_pattern(rel, p) for p in patterns):
                    files.append(fpath)
            elif _is_config_file(fpath):
                files.append(fpath)
    return files


def _match_pattern(rel_path: str, pattern: str) -> bool:
    """Simple glob-like matching: *.yaml, configs/*, etc."""
    import fnmatch
    return fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(Path(rel_path).name, pattern)


def _guard_dir(target_dir: Path) -> Path:
    return target_dir / GUARD_DIR


def _load_manifest(target_dir: Path) -> Optional[Dict]:
    mf = _guard_dir(target_dir) / MANIFEST_FILE
    if mf.exists():
        return json.loads(mf.read_text("utf-8"))
    return None


def _save_manifest(target_dir: Path, manifest: Dict) -> Path:
    gd = _guard_dir(target_dir)
    gd.mkdir(parents=True, exist_ok=True)
    mf = gd / MANIFEST_FILE
    mf.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return mf


def _audit_log(event: str, **details):
    try:
        from liquefy_audit_chain import audit_log
        audit_log(event, **details)
    except Exception:
        pass


def cmd_save(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    patterns = args.include if hasattr(args, "include") and args.include else None
    files = _collect_files(target_dir, patterns)

    if not files:
        msg = "No config files found to guard."
        if not args.json:
            print(f"  {msg}")
            print(f"  Use --include '*.yaml' '*.json' to specify patterns.")
        else:
            print(json.dumps({"ok": False, "error": msg}))
        return 1

    gd = _guard_dir(target_dir)
    snapshot_dir = gd / "snapshot"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    file_entries = {}
    total_bytes = 0
    for fpath in files:
        rel = str(fpath.relative_to(target_dir))
        sha = _file_sha256(fpath)
        size = fpath.stat().st_size
        total_bytes += size

        dest = snapshot_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fpath, dest)

        file_entries[rel] = {
            "sha256": sha,
            "size": size,
            "mtime": fpath.stat().st_mtime,
        }

    manifest = {
        "schema": SCHEMA,
        "version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "directory": str(target_dir),
        "files": file_entries,
        "file_count": len(file_entries),
        "total_bytes": total_bytes,
        "label": args.label if hasattr(args, "label") and args.label else None,
    }

    mf_path = _save_manifest(target_dir, manifest)
    _audit_log("config_guard.save", file_count=len(file_entries), total_bytes=total_bytes)

    if args.json:
        print(json.dumps({"ok": True, **manifest, "guard_dir": str(gd)}, indent=2))
    else:
        print(f"  Config Guard — {len(file_entries)} files saved")
        print(f"    Directory:  {target_dir}")
        print(f"    Total:      {total_bytes:,} bytes")
        print(f"    Snapshot:   {snapshot_dir}")
        if manifest["label"]:
            print(f"    Label:      {manifest['label']}")
        print()
        print(f"  Now safe to update. Restore with:")
        print(f"    python tools/liquefy_config_guard.py restore --dir {target_dir}")

    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    manifest = _load_manifest(target_dir)

    if not manifest:
        msg = "No guard snapshot found. Run 'save' first."
        if args.json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"  {msg}")
        return 1

    snapshot_dir = _guard_dir(target_dir) / "snapshot"
    if not snapshot_dir.exists():
        print(json.dumps({"ok": False, "error": "Snapshot directory missing"}))
        return 1

    restored = []
    skipped = []
    conflicts = []

    for rel, entry in manifest["files"].items():
        snap_file = snapshot_dir / rel
        live_file = target_dir / rel

        if not snap_file.exists():
            skipped.append({"file": rel, "reason": "snapshot_missing"})
            continue

        if live_file.exists():
            live_sha = _file_sha256(live_file)
            if live_sha == entry["sha256"]:
                skipped.append({"file": rel, "reason": "unchanged"})
                continue

        if args.dry_run:
            if live_file.exists():
                conflicts.append(rel)
            else:
                restored.append(rel)
            continue

        live_file.parent.mkdir(parents=True, exist_ok=True)

        if live_file.exists() and not args.force:
            live_sha = _file_sha256(live_file)
            snap_sha = _file_sha256(snap_file)
            if live_sha != entry["sha256"] and live_sha != snap_sha:
                backup = live_file.with_suffix(live_file.suffix + ".update-backup")
                shutil.copy2(live_file, backup)
                conflicts.append(rel)

        shutil.copy2(snap_file, live_file)
        restored.append(rel)

    _audit_log("config_guard.restore",
               restored=len(restored), skipped=len(skipped), conflicts=len(conflicts))

    result = {
        "ok": True,
        "restored": len(restored),
        "skipped": len(skipped),
        "conflicts": len(conflicts),
        "dry_run": args.dry_run,
    }

    if args.json:
        result["restored_files"] = restored
        result["skipped_files"] = skipped
        result["conflict_files"] = conflicts
        print(json.dumps(result, indent=2))
    else:
        mode = " (DRY RUN)" if args.dry_run else ""
        print(f"  Config Guard — Restore{mode}")
        print(f"    Restored:   {len(restored)}")
        print(f"    Skipped:    {len(skipped)} (unchanged)")
        print(f"    Conflicts:  {len(conflicts)}")
        if conflicts:
            print()
            print(f"  Conflict files (update backup saved as .update-backup):")
            for c in conflicts:
                print(f"    {c}")
        if restored:
            print()
            for r in restored[:10]:
                print(f"    + {r}")
            if len(restored) > 10:
                print(f"    ... and {len(restored) - 10} more")

    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    manifest = _load_manifest(target_dir)

    if not manifest:
        msg = "No guard snapshot found. Run 'save' first."
        if args.json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"  {msg}")
        return 1

    snapshot_dir = _guard_dir(target_dir) / "snapshot"
    changed = []
    deleted = []
    unchanged = []

    for rel, entry in manifest["files"].items():
        live_file = target_dir / rel
        if not live_file.exists():
            deleted.append(rel)
            continue

        live_sha = _file_sha256(live_file)
        if live_sha != entry["sha256"]:
            snap_file = snapshot_dir / rel
            diff_entry = {"file": rel, "old_sha": entry["sha256"][:16], "new_sha": live_sha[:16]}

            if snap_file.exists() and live_file.exists():
                try:
                    old_lines = snap_file.read_text("utf-8", errors="replace").splitlines()
                    new_lines = live_file.read_text("utf-8", errors="replace").splitlines()
                    diff_entry["lines_added"] = len([l for l in new_lines if l not in old_lines])
                    diff_entry["lines_removed"] = len([l for l in old_lines if l not in new_lines])
                except Exception:
                    pass

            changed.append(diff_entry)
        else:
            unchanged.append(rel)

    result = {
        "ok": True,
        "changed": len(changed),
        "deleted": len(deleted),
        "unchanged": len(unchanged),
        "total": len(manifest["files"]),
        "snapshot_time": manifest["timestamp"],
    }

    if args.json:
        result["changed_files"] = changed
        result["deleted_files"] = deleted
        print(json.dumps(result, indent=2))
    else:
        print(f"  Config Guard — Diff")
        print(f"    Snapshot:   {manifest['timestamp']}")
        print(f"    Changed:    {len(changed)}")
        print(f"    Deleted:    {len(deleted)}")
        print(f"    Unchanged:  {len(unchanged)}")

        if changed:
            print()
            print(f"  Modified files:")
            for c in changed:
                extra = ""
                if "lines_added" in c:
                    extra = f"  (+{c['lines_added']} -{c['lines_removed']})"
                print(f"    ~ {c['file']}{extra}")

        if deleted:
            print()
            print(f"  Deleted files:")
            for d in deleted:
                print(f"    - {d}")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    manifest = _load_manifest(target_dir)

    if not manifest:
        msg = "No guard snapshot found. Run 'save' first."
        if args.json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"  {msg}")
        return 1

    statuses = {}
    for rel, entry in manifest["files"].items():
        live_file = target_dir / rel
        if not live_file.exists():
            statuses[rel] = "deleted"
        elif _file_sha256(live_file) != entry["sha256"]:
            statuses[rel] = "modified"
        else:
            statuses[rel] = "unchanged"

    counts = {"unchanged": 0, "modified": 0, "deleted": 0}
    for s in statuses.values():
        counts[s] += 1

    result = {
        "ok": True,
        "snapshot_time": manifest["timestamp"],
        "label": manifest.get("label"),
        **counts,
        "total": len(statuses),
    }

    if args.json:
        result["files"] = statuses
        print(json.dumps(result, indent=2))
    else:
        print(f"  Config Guard — Status")
        print(f"    Snapshot:   {manifest['timestamp']}")
        if manifest.get("label"):
            print(f"    Label:      {manifest['label']}")
        print(f"    Unchanged:  {counts['unchanged']}")
        print(f"    Modified:   {counts['modified']}")
        print(f"    Deleted:    {counts['deleted']}")
        print(f"    Total:      {len(statuses)}")

        modified = [f for f, s in statuses.items() if s == "modified"]
        deleted = [f for f, s in statuses.items() if s == "deleted"]
        if modified:
            print()
            for m in modified:
                print(f"    ~ {m}")
        if deleted:
            for d in deleted:
                print(f"    - {d}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-config-guard",
        description="Snapshot, restore, and diff customizations across updates.",
    )
    sub = parser.add_subparsers(dest="command")

    p_save = sub.add_parser("save", help="Snapshot config files before update")
    p_save.add_argument("--dir", required=True, help="Target directory to guard")
    p_save.add_argument("--include", nargs="+", help="File patterns to include (e.g. '*.yaml' 'configs/*')")
    p_save.add_argument("--label", help="Label for this snapshot (e.g. 'pre-v2.0-update')")
    p_save.add_argument("--json", action="store_true")

    p_restore = sub.add_parser("restore", help="Restore customizations after update")
    p_restore.add_argument("--dir", required=True, help="Target directory")
    p_restore.add_argument("--force", action="store_true", help="Overwrite without backup")
    p_restore.add_argument("--dry-run", action="store_true", help="Show what would be restored")
    p_restore.add_argument("--json", action="store_true")

    p_diff = sub.add_parser("diff", help="Show changes since snapshot")
    p_diff.add_argument("--dir", required=True, help="Target directory")
    p_diff.add_argument("--json", action="store_true")

    p_status = sub.add_parser("status", help="Show guarded file statuses")
    p_status.add_argument("--dir", required=True, help="Target directory")
    p_status.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"save": cmd_save, "restore": cmd_restore, "diff": cmd_diff, "status": cmd_status}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
