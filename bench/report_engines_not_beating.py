#!/usr/bin/env python3
"""
Generate a focused report of Liquefy engines that do not beat zstd-19 on ratio.
"""

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple


def parse_ratio(text: str) -> float:
    value = (text or "").strip()
    if value.endswith("x"):
        value = value[:-1]
    return float(value or 0.0)


def parse_float(text: str) -> float:
    return float((text or "0").strip())


def load_rows(csv_path: Path):
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def generate(rows, baseline_method: str):
    baseline: Dict[Tuple[str, str], dict] = {}
    for row in rows:
        if row.get("method") == baseline_method:
            key = (row.get("scenario", ""), row.get("file_label", ""))
            baseline[key] = row

    stats = defaultdict(lambda: {
        "files": 0,
        "ratio_wins": 0,
        "comp_wins": 0,
        "decomp_wins": 0,
        "out_delta_bytes_sum": 0.0,
        "out_delta_pct_sum": 0.0,
        "ratio_delta_pct_sum": 0.0,
        "comp_delta_pct_sum": 0.0,
        "decomp_delta_pct_sum": 0.0,
    })

    for row in rows:
        if row.get("method") != "Liquefy (.null)":
            continue
        engine = row.get("engine_used", "unknown")
        key = (row.get("scenario", ""), row.get("file_label", ""))
        base = baseline.get(key)
        if base is None:
            continue

        liq_out = parse_float(row.get("output_bytes", "0"))
        liq_ratio = parse_ratio(row.get("ratio", "0"))
        liq_comp = parse_float(row.get("compress_mb_s", "0"))
        liq_decomp = parse_float(row.get("decompress_mb_s", "0"))

        z_out = max(1.0, parse_float(base.get("output_bytes", "0")))
        z_ratio = max(1e-12, parse_ratio(base.get("ratio", "0")))
        z_comp = max(1e-12, parse_float(base.get("compress_mb_s", "0")))
        z_decomp = max(1e-12, parse_float(base.get("decompress_mb_s", "0")))

        out_delta_bytes = liq_out - z_out
        out_delta_pct = ((liq_out / z_out) - 1.0) * 100.0
        ratio_delta_pct = ((liq_ratio / z_ratio) - 1.0) * 100.0
        comp_delta_pct = ((liq_comp / z_comp) - 1.0) * 100.0
        decomp_delta_pct = ((liq_decomp / z_decomp) - 1.0) * 100.0

        slot = stats[engine]
        slot["files"] += 1
        # Output bytes is the most stable/precise ratio comparator.
        slot["ratio_wins"] += int(liq_out < z_out)
        slot["comp_wins"] += int(liq_comp > z_comp)
        slot["decomp_wins"] += int(liq_decomp > z_decomp)
        slot["out_delta_bytes_sum"] += out_delta_bytes
        slot["out_delta_pct_sum"] += out_delta_pct
        slot["ratio_delta_pct_sum"] += ratio_delta_pct
        slot["comp_delta_pct_sum"] += comp_delta_pct
        slot["decomp_delta_pct_sum"] += decomp_delta_pct

    losers = []
    for engine, slot in stats.items():
        files = max(1, slot["files"])
        ratio_wins = slot["ratio_wins"]
        if ratio_wins >= slot["files"]:
            continue
        losers.append({
            "engine": engine,
            "files": slot["files"],
            "ratio_wins": ratio_wins,
            "comp_wins": slot["comp_wins"],
            "decomp_wins": slot["decomp_wins"],
            "avg_out_delta_bytes": slot["out_delta_bytes_sum"] / files,
            "avg_out_delta_pct": slot["out_delta_pct_sum"] / files,
            "avg_ratio_delta_pct": slot["ratio_delta_pct_sum"] / files,
            "avg_comp_delta_pct": slot["comp_delta_pct_sum"] / files,
            "avg_decomp_delta_pct": slot["decomp_delta_pct_sum"] / files,
        })

    losers.sort(key=lambda x: x["avg_out_delta_pct"], reverse=True)
    return losers


def write_report(out_path: Path, source_csv_name: str, losers):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(f"# Engines Not Beating zstd-19 ({source_csv_name})\n\n")
        if not losers:
            f.write("All Liquefy engines beat zstd-19 on ratio for this matrix.\n")
            return

        f.write("| Engine | Files | Ratio Wins | Avg Output Δ Bytes | Avg Output Δ % | Avg Ratio Δ % | Comp Wins | Avg Comp Δ % | Decomp Wins | Avg Decomp Δ % |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for row in losers:
            f.write(
                f"| {row['engine']} | {row['files']} | {row['ratio_wins']}/{row['files']} | "
                f"{row['avg_out_delta_bytes']:.1f} | {row['avg_out_delta_pct']:.2f}% | "
                f"{row['avg_ratio_delta_pct']:.2f}% | {row['comp_wins']}/{row['files']} | "
                f"{row['avg_comp_delta_pct']:.2f}% | {row['decomp_wins']}/{row['files']} | "
                f"{row['avg_decomp_delta_pct']:.2f}% |\n"
            )

        f.write(
            "\nNote: output-byte delta is the primary fairness metric. "
            "Ratio deltas can look exaggerated when compressed outputs are very small.\n"
        )


def main():
    ap = argparse.ArgumentParser(description="Build ENGINES_NOT_BEATING_ZSTD.md from format matrix CSV.")
    ap.add_argument("--csv", required=True, help="Path to format_matrix CSV")
    ap.add_argument("--out", required=True, help="Path to markdown output")
    ap.add_argument("--baseline-method", default="zstd -19", help="Baseline method name in CSV")
    args = ap.parse_args()

    csv_path = Path(args.csv).resolve()
    rows = load_rows(csv_path)
    losers = generate(rows, baseline_method=args.baseline_method)
    write_report(Path(args.out).resolve(), csv_path.name, losers)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
