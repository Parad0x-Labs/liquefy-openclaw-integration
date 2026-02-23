#!/usr/bin/env python3
"""Generate an OpenClaw-like corpus and emit Discord-ready benchmark artifacts.

This helper is designed for the "show it on a big trace dataset" workflow:
1) generate a synthetic OpenClaw-like corpus (e.g. medium2g ~= 2 GiB)
2) run bench/run_bench.py for one or more Liquefy profiles
3) snapshot the generated bench CSV/REPORT files per profile
4) emit a Discord-ready Markdown summary and a compact card PNG (default+ratio)

Notes:
- The generated dataset is synthetic OpenClaw-like data, not private user traces.
- bench/run_bench.py writes to bench/results/bench.csv and REPORT.md; this script snapshots
  those files after each profile run so results are preserved.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "bench"
RESULTS_DIR = BENCH_DIR / "results"


def _run(cmd: List[str], *, env: Dict[str, str] | None = None) -> None:
    print("[RUN]", " ".join(cmd))
    res = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if res.returncode != 0:
        raise SystemExit(res.returncode)


def _ensure_dataset(size: str) -> None:
    run_dir = BENCH_DIR / "datasets" / "openclaw_like" / size / "run_0001"
    if run_dir.exists():
        print(f"[OK] Dataset exists: {run_dir}")
        return
    _run([sys.executable, str(BENCH_DIR / "generate_data.py"), "--sizes", size])


def _snapshot_bench_outputs(*, size: str, profile: str, suffix: str) -> Tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    src_csv = RESULTS_DIR / "bench.csv"
    src_md = RESULTS_DIR / "REPORT.md"
    if not src_csv.exists() or not src_md.exists():
        raise SystemExit("MISSING_BENCH_OUTPUT: expected bench/results/bench.csv and REPORT.md")
    out_csv = RESULTS_DIR / f"bench_openclaw_{size}_{profile}_{suffix}.csv"
    out_md = RESULTS_DIR / f"REPORT_openclaw_{size}_{profile}_{suffix}.md"
    shutil.copy2(src_csv, out_csv)
    shutil.copy2(src_md, out_md)
    return out_csv, out_md


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _method_key(row: Dict[str, str]) -> str:
    method = str(row.get("Method", "")).strip()
    if method == "Liquefy (.null)":
        return "liquefy"
    if method.startswith("zstd -"):
        lvl = str(row.get("Level", "")).strip()
        try:
            return f"zstd-{int(float(lvl))}"
        except Exception:
            return method.lower().replace(" ", "_")
    return method.lower().replace(" ", "_")


def _index_rows(rows: Iterable[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for row in rows:
        out[_method_key(row)] = row
    return out


def _f(v: str, default: float = 0.0) -> float:
    s = str(v).strip()
    if not s:
        return default
    if s.endswith("x"):
        s = s[:-1]
    try:
        return float(s)
    except Exception:
        return default


def _build_discord_markdown(
    *,
    size: str,
    profile_csvs: Dict[str, Path],
    zstd_levels: List[int],
) -> str:
    profile_rows: Dict[str, Dict[str, Dict[str, str]]] = {
        p: _index_rows(_read_csv(csv_path)) for p, csv_path in profile_csvs.items()
    }

    # zstd rows should be identical across profile runs; prefer default then any.
    zstd_index: Dict[str, Dict[str, str]] = {}
    for preferred in ("default", "ratio", "speed"):
        if preferred in profile_rows:
            for k, row in profile_rows[preferred].items():
                if k.startswith("zstd-") and k not in zstd_index:
                    zstd_index[k] = row

    liq_profiles = [p for p in ("default", "ratio", "speed") if p in profile_rows]

    # Pick a baseline for speedup callouts
    z22 = zstd_index.get("zstd-22")

    lines: List[str] = []
    lines.append(f"Real OpenClaw-like benchmark (`{size}` synthetic corpus, local run)")
    lines.append("")
    lines.append("Validation: byte-perfect restore ✅ | search while compressed ✅")
    lines.append("")
    lines.append("```")
    lines.append(f"{'Method':<20} {'Ratio':>8} {'Comp MB/s':>10} {'Rest MB/s':>10} {'Hash':>6} {'Search':>6}")
    lines.append("-" * 70)

    for profile in liq_profiles:
        row = profile_rows[profile].get("liquefy")
        if not row:
            continue
        lines.append(
            f"{('Liquefy ' + profile):<20} "
            f"{row.get('Ratio','?'):>8} "
            f"{row.get('Compress MB/s','?'):>10} "
            f"{row.get('Restore MB/s','?'):>10} "
            f"{row.get('Hash Verify','?'):>6} "
            f"{row.get('Search Check','?'):>6}"
        )

    for lvl in zstd_levels:
        row = zstd_index.get(f"zstd-{lvl}")
        if not row:
            continue
        lines.append(
            f"{('zstd-' + str(lvl)):<20} "
            f"{row.get('Ratio','?'):>8} "
            f"{row.get('Compress MB/s','?'):>10} "
            f"{row.get('Restore MB/s','?'):>10} "
            f"{row.get('Hash Verify','?'):>6} "
            f"{row.get('Search Check','?'):>6}"
        )
    lines.append("```")

    if z22:
        z22_comp = _f(z22.get("Compress MB/s", "0"))
        if z22_comp > 0:
            lines.append("")
            lines.append("Speedup vs zstd-22 (compression MB/s):")
            for profile in liq_profiles:
                liq = profile_rows[profile].get("liquefy")
                if not liq:
                    continue
                liq_comp = _f(liq.get("Compress MB/s", "0"))
                if liq_comp > 0:
                    lines.append(f"- Liquefy `{profile}`: {(liq_comp / z22_comp):.1f}x")

    lines.append("")
    lines.append("Notes:")
    lines.append("- Dataset is synthetic OpenClaw-like data generated by `bench/generate_data.py` (not private traces).")
    lines.append("- Profiles are workload-dependent (`default`, `ratio`, `speed`).")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate + benchmark an OpenClaw-like 2GB corpus and emit Discord-ready outputs.")
    ap.add_argument("--size", default="medium2g", help="OpenClaw-like dataset size key (default: medium2g ~= 2GiB)")
    ap.add_argument("--profiles", nargs="+", default=["default", "ratio"], choices=["default", "ratio", "speed"])
    ap.add_argument("--zstd-levels", nargs="+", type=int, default=[3, 6, 19, 22])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--verify-mode", choices=["full", "fast", "off"], default="full")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--skip-generate", action="store_true")
    ap.add_argument("--generate-only", action="store_true")
    ap.add_argument("--no-card", action="store_true", help="Skip PNG card generation")
    args = ap.parse_args()

    if not args.skip_generate:
        _ensure_dataset(args.size)
    if args.generate_only:
        print(f"[OK] Generated/verified dataset only: bench/datasets/openclaw_like/{args.size}/run_0001")
        return

    suffix = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    profile_csvs: Dict[str, Path] = {}
    profile_mds: Dict[str, Path] = {}

    for profile in args.profiles:
        cmd = [
            sys.executable,
            str(BENCH_DIR / "run_bench.py"),
            "--sizes",
            args.size,
            "--runs",
            str(args.runs),
            "--liquefy-profile",
            profile,
            "--liquefy-verify-mode",
            args.verify_mode,
            "--liquefy-workers",
            str(args.workers),
            "--zstd-levels",
            *[str(x) for x in args.zstd_levels],
        ]
        _run(cmd)
        csv_path, md_path = _snapshot_bench_outputs(size=args.size, profile=profile, suffix=suffix)
        profile_csvs[profile] = csv_path
        profile_mds[profile] = md_path
        print(f"[OK] Snapshotted {profile}: {csv_path.name}, {md_path.name}")

    discord_md = _build_discord_markdown(size=args.size, profile_csvs=profile_csvs, zstd_levels=args.zstd_levels)
    discord_md_path = RESULTS_DIR / f"DISCORD_openclaw_{args.size}_{suffix}.md"
    discord_md_path.write_text(discord_md, encoding="utf-8")
    print(f"[OK] Wrote Discord summary: {discord_md_path}")

    if not args.no_card and {"default", "ratio"}.issubset(profile_csvs.keys()):
        out_png = REPO_ROOT / f"liquefy_vs_zstd_openclaw_{args.size}.png"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "make_openclaw_bench_card.py"),
            "--default-csv",
            str(profile_csvs["default"]),
            "--ratio-csv",
            str(profile_csvs["ratio"]),
            "--out",
            str(out_png),
            "--title",
            f"Liquefy vs zstd — OpenClaw {args.size} (full verify)",
        ]
        try:
            _run(cmd)
        except Exception as exc:
            print(f"[WARN] Card generation skipped/failed: {exc}")
        else:
            print(f"[OK] Wrote card PNG: {out_png}")

    print("\n=== Discord copy/paste preview ===\n")
    print(discord_md)
    print("Artifacts:")
    for p, csv_path in profile_csvs.items():
        print(f"- {p} CSV: {csv_path}")
        print(f"- {p} report: {profile_mds[p]}")
    print(f"- Discord markdown: {discord_md_path}")


if __name__ == "__main__":
    main()
