#!/usr/bin/env python3
"""
Build a markdown report listing files where Liquefy ratio is below zstd-22.
"""

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple


def parse_ratio(cell: str) -> float:
    val = (cell or "").strip()
    if val.endswith("x"):
        val = val[:-1]
    try:
        return float(val)
    except Exception:
        return 0.0


def build_rows(csv_path: Path):
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    grouped: Dict[Tuple[str, str], Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in rows:
        key = (row.get("scenario", ""), row.get("file_label", ""))
        grouped[key][row.get("method", "")] = row
    return grouped


def main():
    ap = argparse.ArgumentParser(description="Build ENGINES_NOT_BEATING_ZSTD22.md from format matrix CSV.")
    ap.add_argument("--csv", required=True, help="Path to format_matrix CSV")
    ap.add_argument("--out", required=True, help="Path to markdown output")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    out_path = Path(args.out)
    grouped = build_rows(csv_path)

    lines = [
        f"# Engines Not Beating zstd-22 ({csv_path.name})",
        "",
    ]

    entries = []
    for (scenario, label), methods in sorted(grouped.items()):
        liq = methods.get("Liquefy (.null)")
        z22 = methods.get("zstd -22")
        if not liq or not z22:
            continue

        liq_ratio = parse_ratio(liq.get("ratio", "0"))
        z22_ratio = parse_ratio(z22.get("ratio", "0"))
        if liq_ratio + 1e-12 < z22_ratio:
            delta_pct = ((liq_ratio - z22_ratio) / z22_ratio * 100.0) if z22_ratio else 0.0
            entries.append({
                "scenario": scenario,
                "file": label,
                "engine": liq.get("engine_used", ""),
                "liq_ratio": liq_ratio,
                "z22_ratio": z22_ratio,
                "delta_pct": delta_pct,
                "liq_speed": liq.get("compress_mb_s", "0"),
                "z22_speed": z22.get("compress_mb_s", "0"),
            })

    if not entries:
        lines.append("All Liquefy engines beat zstd-22 on ratio for this matrix.")
    else:
        lines.extend([
            "| Scenario | File | Liquefy Engine | Liquefy Ratio | zstd-22 Ratio | Ratio Delta % | Liquefy MB/s | zstd-22 MB/s |",
            "|---|---|---|---:|---:|---:|---:|---:|",
        ])
        for e in entries:
            lines.append(
                f"| {e['scenario']} | {e['file']} | {e['engine']} | {e['liq_ratio']:.2f}x | "
                f"{e['z22_ratio']:.2f}x | {e['delta_pct']:.2f}% | {e['liq_speed']} | {e['z22_speed']} |"
            )

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
