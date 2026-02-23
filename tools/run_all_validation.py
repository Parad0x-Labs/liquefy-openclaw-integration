#!/usr/bin/env python3
"""
run_all_validation.py
=====================
Run compile checks, unit tests, smoke e2e, and benchmark in one command.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run(cmd, env=None):
    print("\n>>>", " ".join(cmd))
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    subprocess.run(cmd, cwd=REPO_ROOT, check=True, env=full_env)


def main():
    parser = argparse.ArgumentParser(description="Run full Liquefy validation suite.")
    parser.add_argument(
        "--bench-sizes",
        nargs="+",
        default=["medium"],
        help="Dataset sizes passed to bench/run_bench.py --sizes.",
    )
    parser.add_argument(
        "--bench-runs",
        type=int,
        default=1,
        help="Runs per benchmark method (median is used).",
    )
    parser.add_argument(
        "--skip-bench",
        action="store_true",
        help="Skip benchmark stage.",
    )
    parser.add_argument(
        "--skip-matrix",
        action="store_true",
        help="Skip format-matrix benchmark stage.",
    )
    parser.add_argument(
        "--matrix-openclaw-size",
        default="200mb",
        help="OpenClaw dataset size for format matrix.",
    )
    parser.add_argument(
        "--matrix-server-mb",
        type=int,
        default=50,
        help="Per-file target size (MB) for realistic server-suite matrix.",
    )
    parser.add_argument(
        "--matrix-server-seed",
        type=int,
        default=20260223,
        help="Seed for realistic server-suite generation.",
    )
    parser.add_argument(
        "--matrix-verify-mode",
        choices=["full", "fast", "off"],
        default="fast",
        help="Liquefy verify mode for format matrix.",
    )
    parser.add_argument(
        "--liquefy-profile",
        choices=["default", "ratio", "speed"],
        default=os.environ.get("LIQUEFY_PROFILE", "default"),
        help="Optional Liquefy engine profile passed into benchmarks.",
    )
    args = parser.parse_args()

    run(
        [sys.executable, "-m", "compileall", "api"],
        env={"PYTHONPYCACHEPREFIX": "/tmp/pycache"},
    )
    run([sys.executable, "-m", "pytest", "tests", "-v"])
    run([sys.executable, "tools/smoke_e2e.py"])

    if not args.skip_matrix:
        run([
            sys.executable,
            "bench/run_format_matrix.py",
            "--openclaw-size",
            args.matrix_openclaw_size,
            "--server-target-mb",
            str(args.matrix_server_mb),
            "--server-mode",
            "realistic",
            "--server-seed",
            str(args.matrix_server_seed),
            "--verify-mode",
            args.matrix_verify_mode,
            "--liquefy-profile",
            args.liquefy_profile,
        ])
        run([
            sys.executable,
            "bench/report_engines_not_beating.py",
            "--csv",
            "bench/results/format_matrix.csv",
            "--out",
            "bench/results/ENGINES_NOT_BEATING_ZSTD.md",
        ])
        run([
            sys.executable,
            "bench/report_engines_not_beating_zstd22.py",
            "--csv",
            "bench/results/format_matrix.csv",
            "--out",
            "bench/results/ENGINES_NOT_BEATING_ZSTD22.md",
        ])

    if not args.skip_bench:
        bench_cmd = [
            sys.executable,
            "bench/run_bench.py",
            "--sizes",
            *args.bench_sizes,
            "--runs",
            str(args.bench_runs),
            "--liquefy-profile",
            args.liquefy_profile,
        ]
        run(bench_cmd)

    print("\n[PASS] Validation sequence completed")


if __name__ == "__main__":
    main()
