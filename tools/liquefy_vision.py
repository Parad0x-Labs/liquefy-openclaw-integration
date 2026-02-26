#!/usr/bin/env python3
"""
liquefy_vision.py
=================
Perceptual dedup tool for agent screenshots and visual artifacts.

Scans directories for images, deduplicates near-identical screenshots using
perceptual hashing, and packs unique frames into a compact VSNX vault.

Modes:
    scan      — scan a directory for image files, report dedup potential
    pack      — deduplicate and pack images into a VSNX vault
    restore   — restore all images from a VSNX vault
    stats     — show stats from an existing VSNX vault

Usage:
    python tools/liquefy_vision.py scan  ./agent-screenshots
    python tools/liquefy_vision.py pack  ./agent-screenshots --out ./vault/vision.vsnx
    python tools/liquefy_vision.py restore ./vault/vision.vsnx --out ./restored
    python tools/liquefy_vision.py stats ./vault/vision.vsnx --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from vision.liquefy_vision_v1 import LiquefyVisionV1

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff", ".tif", ".screenshot"}


def _collect_images(src_dir: Path) -> List[Tuple[str, bytes]]:
    """Collect all image files from a directory."""
    images = []
    for root, _, files in os.walk(src_dir):
        for fname in sorted(files):
            if Path(fname).suffix.lower() in IMAGE_EXTS:
                fpath = Path(root) / fname
                try:
                    data = fpath.read_bytes()
                    rel = fpath.relative_to(src_dir)
                    images.append((str(rel), data))
                except (OSError, PermissionError):
                    pass
    return images


def cmd_scan(args: argparse.Namespace) -> int:
    src = Path(args.directory).resolve()
    if not src.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {src}"}))
        return 1

    images = _collect_images(src)
    if not images:
        result = {"ok": True, "total_images": 0, "message": "No images found"}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("  No images found in directory.")
        return 0

    engine = LiquefyVisionV1(hamming_threshold=args.threshold)

    import hashlib
    sha_groups: Dict[str, List[str]] = {}
    for fname, data in images:
        h = hashlib.sha256(data).hexdigest()
        sha_groups.setdefault(h, []).append(fname)

    exact_dupes = sum(len(v) - 1 for v in sha_groups.values() if len(v) > 1)
    unique_sha = len(sha_groups)
    total_bytes = sum(len(d) for _, d in images)

    result = {
        "ok": True,
        "total_images": len(images),
        "total_bytes": total_bytes,
        "unique_by_content": unique_sha,
        "exact_duplicates": exact_dupes,
        "estimated_savings_pct": round(exact_dupes / max(len(images), 1) * 100, 1),
        "perceptual_mode": engine._perceptual_hash(images[0][1]) is not None if images else False,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Images found: {len(images)}")
        print(f"  Total size: {total_bytes / (1024*1024):.1f} MB")
        print(f"  Unique (exact): {unique_sha}")
        print(f"  Exact duplicates: {exact_dupes}")
        print(f"  Estimated savings: {result['estimated_savings_pct']}%")
        mode = "perceptual (Pillow)" if result["perceptual_mode"] else "exact-only (install Pillow for perceptual)"
        print(f"  Dedup mode: {mode}")

    return 0


def cmd_pack(args: argparse.Namespace) -> int:
    src = Path(args.directory).resolve()
    if not src.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {src}"}))
        return 1

    images = _collect_images(src)
    if not images:
        print(json.dumps({"ok": True, "message": "No images to pack"}))
        return 0

    engine = LiquefyVisionV1(level=args.level, hamming_threshold=args.threshold)
    started = time.time()
    packed = engine.compress_batch(images)
    elapsed = time.time() - started

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(packed)

    total_original = sum(len(d) for _, d in images)
    result = {
        "ok": True,
        "output": str(out),
        "total_images": len(images),
        "original_bytes": total_original,
        "packed_bytes": len(packed),
        "ratio": round(total_original / max(len(packed), 1), 2),
        "savings_pct": round((1 - len(packed) / max(total_original, 1)) * 100, 1),
        "elapsed_seconds": round(elapsed, 3),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Packed {len(images)} images → {out}")
        print(f"  {total_original / (1024*1024):.1f} MB → {len(packed) / (1024*1024):.1f} MB ({result['ratio']}x)")
        print(f"  Savings: {result['savings_pct']}%")
        print(f"  Time: {elapsed:.2f}s")

    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    vault_path = Path(args.vault).resolve()
    if not vault_path.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_path}"}))
        return 1

    data = vault_path.read_bytes()
    engine = LiquefyVisionV1()

    try:
        files = engine.decompress_batch(data)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for fname, raw in files:
        dest = out_dir / fname
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)

    result = {"ok": True, "restored": len(files), "output": str(out_dir)}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Restored {len(files)} images → {out_dir}")

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    vault_path = Path(args.vault).resolve()
    if not vault_path.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_path}"}))
        return 1

    data = vault_path.read_bytes()
    engine = LiquefyVisionV1()
    stats = engine.stats(data)

    if args.json:
        print(json.dumps({"ok": True, **stats}, indent=2))
    else:
        print(f"  Total files: {stats.get('total_files', '?')}")
        print(f"  Unique stored: {stats.get('unique_files', '?')}")
        print(f"  Deduplicated: {stats.get('dedup_files', '?')}")
        print(f"  Original: {stats.get('original_bytes', 0) / (1024*1024):.1f} MB")
        print(f"  Stored: {stats.get('stored_bytes', 0) / (1024*1024):.1f} MB")
        print(f"  Ratio: {stats.get('ratio', '?')}x")
        print(f"  Savings: {stats.get('savings_pct', '?')}%")
        print(f"  Mode: {stats.get('mode', '?')}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-vision",
        description="Perceptual dedup for agent screenshots.",
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan directory for dedup potential")
    p_scan.add_argument("directory", help="Directory with images")
    p_scan.add_argument("--threshold", type=int, default=10, help="Hamming distance threshold (default 10)")
    p_scan.add_argument("--json", action="store_true")

    p_pack = sub.add_parser("pack", help="Deduplicate and pack images")
    p_pack.add_argument("directory", help="Directory with images")
    p_pack.add_argument("--out", default="./vault/vision.vsnx", help="Output vault path")
    p_pack.add_argument("--level", type=int, default=9, help="Zstd compression level")
    p_pack.add_argument("--threshold", type=int, default=10, help="Hamming distance threshold")
    p_pack.add_argument("--json", action="store_true")

    p_restore = sub.add_parser("restore", help="Restore images from VSNX vault")
    p_restore.add_argument("vault", help="Path to .vsnx vault file")
    p_restore.add_argument("--out", default="./restored", help="Output directory")
    p_restore.add_argument("--json", action="store_true")

    p_stats = sub.add_parser("stats", help="Show vault stats")
    p_stats.add_argument("vault", help="Path to .vsnx vault file")
    p_stats.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"scan": cmd_scan, "pack": cmd_pack, "restore": cmd_restore, "stats": cmd_stats}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
