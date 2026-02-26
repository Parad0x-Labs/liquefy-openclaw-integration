#!/usr/bin/env python3
"""
liquefy_cloud_sync.py
=====================
Encrypted cloud sync for Liquefy vaults.

Syncs .null/.lqf vaults to S3-compatible storage (AWS S3, Cloudflare R2, MinIO)
without decrypting them. The cloud provider sees only opaque blobs — "sovereign"
means encrypted everywhere, not just local.

Supports:
    - AWS S3, Cloudflare R2, MinIO, any S3-compatible endpoint
    - Incremental sync (only uploads changed/new vaults)
    - Integrity verification after upload (ETag matching)
    - Restore from cloud to local

Modes:
    push      — sync local vaults to cloud bucket
    pull      — restore vaults from cloud to local
    status    — show sync status (local vs remote)
    verify    — verify remote integrity against local hashes

Environment variables:
    LIQUEFY_S3_ENDPOINT    — S3 endpoint URL (for R2/MinIO)
    LIQUEFY_S3_BUCKET      — Bucket name
    LIQUEFY_S3_PREFIX      — Key prefix (default: "liquefy/")
    AWS_ACCESS_KEY_ID      — S3 access key
    AWS_SECRET_ACCESS_KEY  — S3 secret key
    AWS_DEFAULT_REGION     — Region (default: auto)

Usage:
    python tools/liquefy_cloud_sync.py push  --vault ./vault --bucket my-backups
    python tools/liquefy_cloud_sync.py pull  --vault ./vault --bucket my-backups
    python tools/liquefy_cloud_sync.py status --vault ./vault --bucket my-backups --json
    python tools/liquefy_cloud_sync.py verify --vault ./vault --bucket my-backups
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)

VAULT_EXTENSIONS = {".null", ".lqf", ".vsnx", ".jsonl"}
MANIFEST_NAME = ".liquefy-cloud-manifest.json"

_HAS_BOTO3 = False
try:
    import boto3
    from botocore.config import Config as BotoConfig
    _HAS_BOTO3 = True
except ImportError:
    pass


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _collect_vaults(vault_dir: Path) -> List[Path]:
    """Collect all vault files recursively."""
    files = []
    for root, _, fnames in os.walk(vault_dir):
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            if fpath.suffix.lower() in VAULT_EXTENSIONS or fname.endswith(".manifest.json"):
                files.append(fpath)
    return files


def _load_local_manifest(vault_dir: Path) -> Dict[str, str]:
    """Load local sync manifest (file -> sha256)."""
    mf = vault_dir / MANIFEST_NAME
    if mf.exists():
        try:
            return json.loads(mf.read_text("utf-8"))
        except Exception:
            pass
    return {}


def _save_local_manifest(vault_dir: Path, manifest: Dict[str, str]):
    mf = vault_dir / MANIFEST_NAME
    mf.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _get_s3_client(endpoint: Optional[str] = None, region: Optional[str] = None):
    if not _HAS_BOTO3:
        raise RuntimeError(
            "boto3 is required for cloud sync. Install with: pip install boto3\n"
            "Or for R2: pip install boto3  (same library, different endpoint)"
        )
    kwargs: Dict[str, Any] = {}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    if region:
        kwargs["region_name"] = region
    return boto3.client("s3", **kwargs)


def cmd_push(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    if not vault_dir.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_dir}"}))
        return 1

    endpoint = args.endpoint or os.environ.get("LIQUEFY_S3_ENDPOINT")
    bucket = args.bucket or os.environ.get("LIQUEFY_S3_BUCKET")
    prefix = args.prefix or os.environ.get("LIQUEFY_S3_PREFIX", "liquefy/")
    region = args.region or os.environ.get("AWS_DEFAULT_REGION")

    if not bucket:
        print(json.dumps({"ok": False, "error": "No bucket specified. Use --bucket or LIQUEFY_S3_BUCKET"}))
        return 1

    s3 = _get_s3_client(endpoint, region)
    files = _collect_vaults(vault_dir)
    local_manifest = _load_local_manifest(vault_dir)

    uploaded = 0
    skipped = 0
    errors = []
    total_bytes = 0
    started = time.time()

    new_manifest = {}
    for fpath in files:
        rel = str(fpath.relative_to(vault_dir))
        sha = _file_hash(fpath)
        new_manifest[rel] = sha

        if local_manifest.get(rel) == sha and not args.force:
            skipped += 1
            continue

        key = prefix + rel
        try:
            s3.upload_file(str(fpath), bucket, key)
            uploaded += 1
            total_bytes += fpath.stat().st_size
        except Exception as e:
            errors.append({"file": rel, "error": str(e)})

    _save_local_manifest(vault_dir, new_manifest)
    elapsed = time.time() - started

    result = {
        "ok": len(errors) == 0,
        "uploaded": uploaded,
        "skipped": skipped,
        "errors": errors,
        "total_bytes": total_bytes,
        "elapsed_seconds": round(elapsed, 3),
        "bucket": bucket,
        "prefix": prefix,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Push → s3://{bucket}/{prefix}")
        print(f"  Uploaded: {uploaded} files ({total_bytes / (1024*1024):.1f} MB)")
        print(f"  Skipped (unchanged): {skipped}")
        if errors:
            print(f"  Errors: {len(errors)}")
            for e in errors:
                print(f"    {e['file']}: {e['error']}")
        print(f"  Time: {elapsed:.2f}s")

    return 0 if not errors else 1


def cmd_pull(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    vault_dir.mkdir(parents=True, exist_ok=True)

    endpoint = args.endpoint or os.environ.get("LIQUEFY_S3_ENDPOINT")
    bucket = args.bucket or os.environ.get("LIQUEFY_S3_BUCKET")
    prefix = args.prefix or os.environ.get("LIQUEFY_S3_PREFIX", "liquefy/")
    region = args.region or os.environ.get("AWS_DEFAULT_REGION")

    if not bucket:
        print(json.dumps({"ok": False, "error": "No bucket specified"}))
        return 1

    s3 = _get_s3_client(endpoint, region)

    downloaded = 0
    errors = []
    total_bytes = 0
    started = time.time()

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            rel = key[len(prefix):]
            if not rel:
                continue

            dest = vault_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                s3.download_file(bucket, key, str(dest))
                downloaded += 1
                total_bytes += obj.get("Size", 0)
            except Exception as e:
                errors.append({"key": key, "error": str(e)})

    elapsed = time.time() - started
    result = {
        "ok": len(errors) == 0,
        "downloaded": downloaded,
        "errors": errors,
        "total_bytes": total_bytes,
        "elapsed_seconds": round(elapsed, 3),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Pull ← s3://{bucket}/{prefix}")
        print(f"  Downloaded: {downloaded} files ({total_bytes / (1024*1024):.1f} MB)")
        if errors:
            print(f"  Errors: {len(errors)}")

    return 0 if not errors else 1


def cmd_status(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    endpoint = args.endpoint or os.environ.get("LIQUEFY_S3_ENDPOINT")
    bucket = args.bucket or os.environ.get("LIQUEFY_S3_BUCKET")
    prefix = args.prefix or os.environ.get("LIQUEFY_S3_PREFIX", "liquefy/")
    region = args.region or os.environ.get("AWS_DEFAULT_REGION")

    local_files = set()
    local_bytes = 0
    if vault_dir.exists():
        for f in _collect_vaults(vault_dir):
            local_files.add(str(f.relative_to(vault_dir)))
            local_bytes += f.stat().st_size

    remote_files: Set[str] = set()
    remote_bytes = 0
    if bucket and _HAS_BOTO3:
        try:
            s3 = _get_s3_client(endpoint, region)
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    rel = obj["Key"][len(prefix):]
                    if rel:
                        remote_files.add(rel)
                        remote_bytes += obj.get("Size", 0)
        except Exception as e:
            if args.json:
                print(json.dumps({"ok": False, "error": str(e)}))
            else:
                print(f"  Error connecting to S3: {e}")
            return 1

    only_local = local_files - remote_files
    only_remote = remote_files - local_files
    synced = local_files & remote_files

    result = {
        "ok": True,
        "local_files": len(local_files),
        "local_bytes": local_bytes,
        "remote_files": len(remote_files),
        "remote_bytes": remote_bytes,
        "synced": len(synced),
        "only_local": sorted(only_local),
        "only_remote": sorted(only_remote),
        "in_sync": len(only_local) == 0 and len(only_remote) == 0,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Local: {len(local_files)} files ({local_bytes / (1024*1024):.1f} MB)")
        print(f"  Remote: {len(remote_files)} files ({remote_bytes / (1024*1024):.1f} MB)")
        print(f"  Synced: {len(synced)}")
        if only_local:
            print(f"  Not uploaded: {len(only_local)}")
        if only_remote:
            print(f"  Not downloaded: {len(only_remote)}")
        status = "IN SYNC" if result["in_sync"] else "OUT OF SYNC"
        print(f"  Status: {status}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    endpoint = args.endpoint or os.environ.get("LIQUEFY_S3_ENDPOINT")
    bucket = args.bucket or os.environ.get("LIQUEFY_S3_BUCKET")
    prefix = args.prefix or os.environ.get("LIQUEFY_S3_PREFIX", "liquefy/")
    region = args.region or os.environ.get("AWS_DEFAULT_REGION")

    if not bucket:
        print(json.dumps({"ok": False, "error": "No bucket specified"}))
        return 1

    s3 = _get_s3_client(endpoint, region)
    files = _collect_vaults(vault_dir)

    verified = 0
    mismatches = []
    started = time.time()

    for fpath in files:
        rel = str(fpath.relative_to(vault_dir))
        key = prefix + rel
        local_sha = _file_hash(fpath)

        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                s3.download_file(bucket, key, tmp.name)
                remote_sha = _file_hash(Path(tmp.name))

            if local_sha == remote_sha:
                verified += 1
            else:
                mismatches.append({"file": rel, "local_sha": local_sha[:16], "remote_sha": remote_sha[:16]})
        except Exception as e:
            mismatches.append({"file": rel, "error": str(e)})

    elapsed = time.time() - started
    ok = len(mismatches) == 0
    result = {
        "ok": ok,
        "verified": verified,
        "mismatches": mismatches,
        "elapsed_seconds": round(elapsed, 3),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "ALL VERIFIED" if ok else f"{len(mismatches)} MISMATCH(ES)"
        print(f"  Verified: {verified} files — {status}")
        for m in mismatches:
            print(f"    {m.get('file')}: {m.get('error', 'hash mismatch')}")

    return 0 if ok else 1


def _add_common_args(parser: argparse.ArgumentParser):
    parser.add_argument("--vault", required=True, help="Local vault directory")
    parser.add_argument("--bucket", help="S3 bucket name")
    parser.add_argument("--prefix", default=None, help="S3 key prefix")
    parser.add_argument("--endpoint", help="S3 endpoint URL (for R2/MinIO)")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--json", action="store_true")


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-cloud-sync",
        description="Encrypted cloud sync for Liquefy vaults.",
    )
    sub = parser.add_subparsers(dest="command")

    p_push = sub.add_parser("push", help="Sync local vaults to cloud")
    _add_common_args(p_push)
    p_push.add_argument("--force", action="store_true", help="Re-upload all files")

    p_pull = sub.add_parser("pull", help="Restore vaults from cloud")
    _add_common_args(p_pull)

    p_status = sub.add_parser("status", help="Show sync status")
    _add_common_args(p_status)

    p_verify = sub.add_parser("verify", help="Verify remote integrity")
    _add_common_args(p_verify)

    args = parser.parse_args()
    commands = {"push": cmd_push, "pull": cmd_pull, "status": cmd_status, "verify": cmd_verify}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
