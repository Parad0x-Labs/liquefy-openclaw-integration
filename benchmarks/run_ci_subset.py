#!/usr/bin/env python3
"""Deterministic, lightweight benchmark subset for CI regression checks."""
import argparse
import csv
import hashlib
import os
import sys
import time
from pathlib import Path
from statistics import median
from typing import Dict, List

import zstandard as zstd


REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "api"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from orchestrator.engine_map import get_engine_instance


FIXTURE_MATRIX = [
    {
        "label": "generic_json_hyperfriendly_1024",
        "path": REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "generic_json_hyperfriendly_1024.jsonl",
        "engine_id": "liquefy-json-hypernebula-v1",
    },
    {
        "label": "vpcflow_canonical_256",
        "path": REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "vpcflow_canonical_256.log",
        "engine_id": "liquefy-vpcflow-v1",
    },
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def set_profile(profile: str):
    if profile == "default":
        os.environ.pop("LIQUEFY_PROFILE", None)
    else:
        os.environ["LIQUEFY_PROFILE"] = profile


def bench_liquefy(engine_id: str, raw: bytes, profile: str, runs: int) -> Dict[str, object]:
    set_profile(profile)
    input_sha = sha256_bytes(raw)
    comp_times: List[float] = []
    decomp_times: List[float] = []
    output_sizes: List[int] = []
    prefix_hex = ""

    for _ in range(max(1, runs)):
        engine = get_engine_instance(engine_id)
        if engine is None:
            raise RuntimeError(f"engine not found: {engine_id}")

        t0 = time.perf_counter()
        comp = engine.compress(raw)
        t1 = time.perf_counter()
        out = engine.decompress(comp)
        t2 = time.perf_counter()

        if out != raw:
            raise RuntimeError(f"roundtrip mismatch for {engine_id}/{profile}")
        if sha256_bytes(out) != input_sha:
            raise RuntimeError(f"hash mismatch for {engine_id}/{profile}")

        comp_times.append(t1 - t0)
        decomp_times.append(t2 - t1)
        output_sizes.append(len(comp))
        prefix_hex = comp[:8].hex()

    out_bytes = output_sizes[0]
    if any(sz != out_bytes for sz in output_sizes):
        raise RuntimeError(f"nondeterministic output size for {engine_id}/{profile}: {output_sizes}")

    mb = len(raw) / (1024 * 1024)
    return {
        "method": "liquefy",
        "engine_id": engine_id,
        "profile": profile,
        "level": "",
        "input_bytes": len(raw),
        "output_bytes": out_bytes,
        "ratio": len(raw) / max(1, out_bytes),
        "compress_mb_s": mb / max(1e-9, median(comp_times)),
        "decompress_mb_s": mb / max(1e-9, median(decomp_times)),
        "prefix_hex": prefix_hex,
        "byteperfect": "PASS",
    }


def bench_zstd(raw: bytes, level: int, runs: int) -> Dict[str, object]:
    input_sha = sha256_bytes(raw)
    cctx = zstd.ZstdCompressor(level=level, threads=1)
    dctx = zstd.ZstdDecompressor()
    comp_times: List[float] = []
    decomp_times: List[float] = []
    output_sizes: List[int] = []
    prefix_hex = ""

    for _ in range(max(1, runs)):
        t0 = time.perf_counter()
        comp = cctx.compress(raw)
        t1 = time.perf_counter()
        out = dctx.decompress(comp)
        t2 = time.perf_counter()
        if sha256_bytes(out) != input_sha:
            raise RuntimeError(f"zstd-{level} hash mismatch")
        comp_times.append(t1 - t0)
        decomp_times.append(t2 - t1)
        output_sizes.append(len(comp))
        prefix_hex = comp[:8].hex()

    out_bytes = output_sizes[0]
    mb = len(raw) / (1024 * 1024)
    return {
        "method": "zstd",
        "engine_id": "zstd",
        "profile": "",
        "level": str(level),
        "input_bytes": len(raw),
        "output_bytes": out_bytes,
        "ratio": len(raw) / max(1, out_bytes),
        "compress_mb_s": mb / max(1e-9, median(comp_times)),
        "decompress_mb_s": mb / max(1e-9, median(decomp_times)),
        "prefix_hex": prefix_hex,
        "byteperfect": "PASS",
    }


def main():
    ap = argparse.ArgumentParser(description="Run small deterministic CI benchmark subset.")
    ap.add_argument("--out", default=str(REPO_ROOT / "benchmarks" / "latest_ci.csv"))
    ap.add_argument("--runs", type=int, default=3, help="Median-of-N benchmark runs per row.")
    args = ap.parse_args()
    # Keep CI subset results reproducible across runners.
    os.environ["LIQUEFY_DETERMINISTIC"] = "1"
    os.environ.setdefault("ZSTD_NBTHREADS", "1")
    os.environ.setdefault("OMP_NUM_THREADS", "1")

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, object]] = []
    for fixture in FIXTURE_MATRIX:
        raw = fixture["path"].read_bytes()
        for profile in ("default", "ratio", "speed"):
            row = bench_liquefy(fixture["engine_id"], raw, profile, args.runs)
            row["fixture"] = fixture["label"]
            rows.append(row)
        for level in (3, 6, 19, 22):
            row = bench_zstd(raw, level, args.runs)
            row["fixture"] = fixture["label"]
            rows.append(row)

    fieldnames = [
        "fixture",
        "method",
        "engine_id",
        "profile",
        "level",
        "input_bytes",
        "output_bytes",
        "ratio",
        "compress_mb_s",
        "decompress_mb_s",
        "prefix_hex",
        "byteperfect",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            row = dict(row)
            row["ratio"] = f"{float(row['ratio']):.4f}"
            row["compress_mb_s"] = f"{float(row['compress_mb_s']):.4f}"
            row["decompress_mb_s"] = f"{float(row['decompress_mb_s']):.4f}"
            w.writerow(row)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
