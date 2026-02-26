#!/usr/bin/env python3
"""
liquefy_cas.py
==============
Content-Addressed Storage (CAS) for cross-run vault deduplication.

Instead of writing full vault copies every run, blobs are stored once
by their SHA-256 hash. Vaults become lightweight manifests pointing
to shared blobs. Repeated agent runs (same screenshots, prompts,
configs, tool outputs) share storage automatically.

Architecture:
    ~/.liquefy/cas/
        blobs/
            ab/cd1234...  (first 2 chars as shard dir)
        manifests/
            vault-2026-02-25T10:00:00Z.json

Usage:
    python tools/liquefy_cas.py ingest  --dir ./agent-output --json
    python tools/liquefy_cas.py restore --manifest <id> --out ./restored --json
    python tools/liquefy_cas.py status  --json
    python tools/liquefy_cas.py gc      --json
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
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

SCHEMA = "liquefy.cas.v1"
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv",
             ".liquefy-safe-run", ".liquefy-guard", ".liquefy-tokens"}


def _default_cas_dir() -> Path:
    return Path(os.environ.get("LIQUEFY_CAS_DIR", str(Path.home() / ".liquefy" / "cas")))


def _blob_dir(cas_dir: Path) -> Path:
    return cas_dir / "blobs"


def _manifest_dir(cas_dir: Path) -> Path:
    return cas_dir / "manifests"


def _file_sha256(fpath: Path) -> str:
    h = hashlib.sha256()
    with fpath.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _blob_path(cas_dir: Path, sha: str) -> Path:
    return _blob_dir(cas_dir) / sha[:2] / sha


def _store_blob(cas_dir: Path, fpath: Path, sha: str) -> Tuple[bool, int]:
    """Store a blob if not already present. Returns (is_new, size_bytes)."""
    bp = _blob_path(cas_dir, sha)
    size = fpath.stat().st_size
    if bp.exists():
        return False, size
    bp.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fpath, bp)
    return True, size


def _retrieve_blob(cas_dir: Path, sha: str, dest: Path):
    bp = _blob_path(cas_dir, sha)
    if not bp.exists():
        raise FileNotFoundError(f"Blob not found: {sha}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bp, dest)


def ingest_directory(target_dir: Path, cas_dir: Optional[Path] = None,
                     trace_id: Optional[str] = None, label: Optional[str] = None) -> Dict:
    """Ingest a directory into CAS. Returns manifest."""
    cas = cas_dir or _default_cas_dir()
    _blob_dir(cas).mkdir(parents=True, exist_ok=True)
    _manifest_dir(cas).mkdir(parents=True, exist_ok=True)

    entries = {}
    total_bytes = 0
    new_bytes = 0
    dedup_bytes = 0
    new_blobs = 0
    dedup_blobs = 0

    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in fnames:
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(target_dir))
            try:
                sha = _file_sha256(fpath)
                is_new, size = _store_blob(cas, fpath, sha)
                entries[rel] = {
                    "sha256": sha,
                    "size": size,
                }
                total_bytes += size
                if is_new:
                    new_bytes += size
                    new_blobs += 1
                else:
                    dedup_bytes += size
                    dedup_blobs += 1
            except (OSError, PermissionError):
                continue

    ts = datetime.now(timezone.utc).isoformat()
    manifest_id = hashlib.sha256(f"{ts}:{target_dir}:{len(entries)}".encode()).hexdigest()[:16]

    manifest = {
        "schema": SCHEMA,
        "manifest_id": manifest_id,
        "timestamp": ts,
        "source_dir": str(target_dir),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "new_bytes": new_bytes,
        "dedup_bytes": dedup_bytes,
        "new_blobs": new_blobs,
        "dedup_blobs": dedup_blobs,
        "dedup_ratio": round(dedup_bytes / max(1, total_bytes) * 100, 1),
        "files": entries,
    }
    if trace_id:
        manifest["trace_id"] = trace_id
    if label:
        manifest["label"] = label

    mf_path = _manifest_dir(cas) / f"{manifest_id}.json"
    mf_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    try:
        from liquefy_audit_chain import audit_log
        audit_log("cas.ingest", manifest_id=manifest_id, files=len(entries),
                  total_bytes=total_bytes, new_bytes=new_bytes, dedup_bytes=dedup_bytes,
                  **({"trace_id": trace_id} if trace_id else {}))
    except Exception:
        pass

    return manifest


def restore_manifest(manifest_id: str, out_dir: Path, cas_dir: Optional[Path] = None) -> Dict:
    """Restore a vault from a manifest."""
    cas = cas_dir or _default_cas_dir()
    mf_path = _manifest_dir(cas) / f"{manifest_id}.json"
    if not mf_path.exists():
        return {"ok": False, "error": f"Manifest not found: {manifest_id}"}

    try:
        manifest = json.loads(mf_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return {"ok": False, "error": f"Corrupt manifest: {e}"}
    out_dir.mkdir(parents=True, exist_ok=True)

    restored = 0
    errors = 0
    for rel, info in manifest["files"].items():
        dest = out_dir / rel
        try:
            _retrieve_blob(cas, info["sha256"], dest)
            restored += 1
        except (FileNotFoundError, OSError):
            errors += 1

    return {"ok": errors == 0, "restored": restored, "errors": errors, "manifest_id": manifest_id}


def get_status(cas_dir: Optional[Path] = None) -> Dict:
    """Get CAS statistics."""
    cas = cas_dir or _default_cas_dir()
    blob_base = _blob_dir(cas)
    manifest_base = _manifest_dir(cas)

    blob_count = 0
    blob_bytes = 0
    if blob_base.exists():
        for shard in blob_base.iterdir():
            if shard.is_dir():
                for blob in shard.iterdir():
                    if blob.is_file():
                        blob_count += 1
                        blob_bytes += blob.stat().st_size

    manifest_count = 0
    total_logical_bytes = 0
    if manifest_base.exists():
        for mf in manifest_base.iterdir():
            if mf.suffix == ".json":
                manifest_count += 1
                try:
                    m = json.loads(mf.read_text("utf-8"))
                    total_logical_bytes += m.get("total_bytes", 0)
                except Exception:
                    pass

    dedup_savings = max(0, total_logical_bytes - blob_bytes)

    return {
        "ok": True,
        "cas_dir": str(cas),
        "blob_count": blob_count,
        "blob_bytes": blob_bytes,
        "manifest_count": manifest_count,
        "total_logical_bytes": total_logical_bytes,
        "dedup_savings_bytes": dedup_savings,
        "dedup_savings_percent": round(dedup_savings / max(1, total_logical_bytes) * 100, 1),
    }


def garbage_collect(cas_dir: Optional[Path] = None) -> Dict:
    """Remove blobs not referenced by any manifest."""
    cas = cas_dir or _default_cas_dir()
    manifest_base = _manifest_dir(cas)
    blob_base = _blob_dir(cas)

    referenced: set = set()
    if manifest_base.exists():
        for mf in manifest_base.iterdir():
            if mf.suffix == ".json":
                try:
                    m = json.loads(mf.read_text("utf-8"))
                    for info in m.get("files", {}).values():
                        referenced.add(info["sha256"])
                except Exception:
                    pass

    removed = 0
    freed_bytes = 0
    if blob_base.exists():
        for shard in blob_base.iterdir():
            if shard.is_dir():
                for blob in shard.iterdir():
                    if blob.is_file() and blob.name not in referenced:
                        freed_bytes += blob.stat().st_size
                        blob.unlink()
                        removed += 1
                if not any(shard.iterdir()):
                    shard.rmdir()

    return {"ok": True, "removed": removed, "freed_bytes": freed_bytes}


def cmd_ingest(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    cas = Path(args.cas_dir) if args.cas_dir else None
    trace_id = args.trace_id or os.environ.get("LIQUEFY_TRACE_ID")
    manifest = ingest_directory(target_dir, cas, trace_id, getattr(args, "label", None))

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(f"  CAS Ingest")
        print(f"    Manifest:  {manifest['manifest_id']}")
        print(f"    Files:     {manifest['file_count']}")
        print(f"    New:       {manifest['new_blobs']} blobs ({manifest['new_bytes']:,} bytes)")
        print(f"    Dedup:     {manifest['dedup_blobs']} blobs ({manifest['dedup_bytes']:,} bytes)")
        print(f"    Savings:   {manifest['dedup_ratio']}%")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    out_dir = Path(args.out).resolve()
    cas = Path(args.cas_dir) if args.cas_dir else None
    result = restore_manifest(args.manifest, out_dir, cas)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["ok"]:
            print(f"  CAS Restore — OK")
            print(f"    Restored: {result['restored']} files")
        else:
            print(f"  CAS Restore — FAILED")
            err_msg = result.get('error') or f"{result.get('errors', 0)} errors"
            print(f"    Error: {err_msg}")
    return 0 if result["ok"] else 1


def cmd_status(args: argparse.Namespace) -> int:
    cas = Path(args.cas_dir) if args.cas_dir else None
    status = get_status(cas)

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print(f"  CAS Status")
        print(f"    Blobs:       {status['blob_count']} ({status['blob_bytes']:,} bytes)")
        print(f"    Manifests:   {status['manifest_count']}")
        print(f"    Logical:     {status['total_logical_bytes']:,} bytes")
        print(f"    Savings:     {status['dedup_savings_bytes']:,} bytes ({status['dedup_savings_percent']}%)")
    return 0


def cmd_gc(args: argparse.Namespace) -> int:
    cas = Path(args.cas_dir) if args.cas_dir else None
    result = garbage_collect(cas)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  CAS Garbage Collect")
        print(f"    Removed: {result['removed']} orphan blobs")
        print(f"    Freed:   {result['freed_bytes']:,} bytes")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-cas",
        description="Content-Addressed Storage for cross-run vault deduplication.",
    )
    sub = parser.add_subparsers(dest="command")

    p_ingest = sub.add_parser("ingest", help="Ingest directory into CAS")
    p_ingest.add_argument("--dir", required=True, help="Directory to ingest")
    p_ingest.add_argument("--cas-dir", help="CAS root (default: ~/.liquefy/cas)")
    p_ingest.add_argument("--trace-id", help="Correlation ID")
    p_ingest.add_argument("--label", help="Human-readable label for this vault")
    p_ingest.add_argument("--json", action="store_true")

    p_restore = sub.add_parser("restore", help="Restore vault from manifest")
    p_restore.add_argument("--manifest", required=True, help="Manifest ID")
    p_restore.add_argument("--out", required=True, help="Output directory")
    p_restore.add_argument("--cas-dir", help="CAS root")
    p_restore.add_argument("--json", action="store_true")

    p_status = sub.add_parser("status", help="Show CAS statistics")
    p_status.add_argument("--cas-dir", help="CAS root")
    p_status.add_argument("--json", action="store_true")

    p_gc = sub.add_parser("gc", help="Remove unreferenced blobs")
    p_gc.add_argument("--cas-dir", help="CAS root")
    p_gc.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"ingest": cmd_ingest, "restore": cmd_restore, "status": cmd_status, "gc": cmd_gc}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
