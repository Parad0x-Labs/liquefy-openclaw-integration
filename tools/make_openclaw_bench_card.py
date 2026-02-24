#!/usr/bin/env python3
"""Render a compact OpenClaw 50/200 benchmark comparison image for X/social."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import matplotlib.pyplot as plt
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"MISSING_DEPENDENCY: install matplotlib ({exc})")


def _to_float_text(v: str) -> float:
    s = str(v).strip()
    if s.endswith("x"):
        s = s[:-1]
    return float(s)


def _read_rows(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _method_key(row: Dict[str, str]) -> str:
    m = row.get("Method", "").strip()
    if m == "Liquefy (.null)":
        return "liquefy"
    if m.startswith("zstd -"):
        try:
            return f"zstd-{int(float(row.get('Level', '0')))}"
        except Exception:
            return m.lower().replace(" ", "")
    return m.lower().replace(" ", "_")


def _build_index(rows: List[Dict[str, str]]) -> Dict[Tuple[str, str], Dict[str, str]]:
    out: Dict[Tuple[str, str], Dict[str, str]] = {}
    for row in rows:
        if str(row.get("Hash Verify", "")).upper() != "PASS":
            continue
        out[(row.get("Size", ""), _method_key(row))] = row
    return out


def _fmt_ratio(row: Dict[str, str] | None) -> str:
    if not row:
        return "—"
    return str(row.get("Ratio", "—"))


def _fmt_mbs(row: Dict[str, str] | None, col: str) -> str:
    if not row:
        return "—"
    try:
        return f"{float(row.get(col, 'nan')):.1f}"
    except Exception:
        return "—"


def _speedup(a: Dict[str, str] | None, b: Dict[str, str] | None, col: str) -> str:
    if not a or not b:
        return "—"
    try:
        av = float(a.get(col, "nan"))
        bv = float(b.get(col, "nan"))
        if av <= 0 or bv <= 0:
            return "—"
        return f"{(av / bv):.1f}x"
    except Exception:
        return "—"


def _num(row: Dict[str, str] | None, col: str) -> float | None:
    if not row:
        return None
    try:
        return _to_float_text(str(row.get(col, "")))
    except Exception:
        return None


def _cmp_color(a: float | None, b: float | None, tie_pct: float = 0.02) -> str:
    """Green/yellow/red for higher-is-better comparisons."""
    if a is None or b is None or b <= 0:
        return "#FFFFFF"
    d = (a - b) / b
    if d > tie_pct:
        return "#DFF3E4"  # green
    if d < -tie_pct:
        return "#F8D7DA"  # red
    return "#FFF3CD"  # yellow


def _cmp_speedup_color(speedup_text: str, tie_pct: float = 0.02) -> str:
    if not speedup_text or speedup_text == "—":
        return "#FFFFFF"
    try:
        v = _to_float_text(speedup_text)
    except Exception:
        return "#FFFFFF"
    if v > 1.0 + tie_pct:
        return "#DFF3E4"
    if v < 1.0 - tie_pct:
        return "#F8D7DA"
    return "#FFF3CD"


def _render_table(out_path: Path, title: str, rows: List[List[str]], cell_colors: List[List[str]] | None = None) -> None:
    col_labels = [
        "Size",
        "Liquefy\nDefault Ratio",
        "Liquefy\nDefault MB/s",
        "Liquefy\nRatio Ratio",
        "Liquefy\nRatio MB/s",
        "zstd-19\nRatio",
        "zstd-19\nMB/s",
        "zstd-22\nRatio",
        "zstd-22\nMB/s",
        "Def vs z22\nSpeedup",
        "Ratio vs z22\nSpeedup",
        "Restore note",
    ]

    nrows = max(1, len(rows))
    ncols = len(col_labels)
    fig_w = min(24, max(14, ncols * 1.4))
    fig_h = max(3.4, nrows * 0.75 + 1.8)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=200)
    ax.axis("off")
    table = ax.table(
        cellText=rows,
        colLabels=col_labels,
        loc="upper center",
        bbox=[0.0, 0.0, 1.0, 0.85],
        cellLoc="center",
        colLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.6)
    table.scale(1, 1.22)
    try:
        table.auto_set_column_width(col=list(range(ncols)))
    except Exception:
        pass

    for (r, c), cell in table.get_celld().items():
        if r == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#E8EDF5")
        elif cell_colors and (r - 1) < len(cell_colors) and c < len(cell_colors[r - 1]):
            color = cell_colors[r - 1][c]
            if color:
                cell.set_facecolor(color)
        if r != 0 and c in (0, 11):
            cell.get_text().set_ha("left")

    ax.set_title(title, fontsize=14, weight="bold", pad=6)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--default-csv", required=True, help="Default profile OpenClaw bench CSV")
    ap.add_argument("--ratio-csv", required=True, help="Ratio profile OpenClaw bench CSV")
    ap.add_argument("--out", required=True, help="Output PNG path")
    ap.add_argument("--title", default="Liquefy vs zstd — OpenClaw 50/200 (full verify)")
    args = ap.parse_args()

    default_rows = _build_index(_read_rows(Path(args.default_csv)))
    ratio_rows = _build_index(_read_rows(Path(args.ratio_csv)))

    sizes = []
    for key in list(default_rows.keys()) + list(ratio_rows.keys()):
        if key[0] not in sizes:
            sizes.append(key[0])
    # Prefer numeric-ish size order if present.
    sizes = sorted(sizes, key=lambda s: (len(s), s))

    rendered: List[List[str]] = []
    color_rows: List[List[str]] = []
    for size in sizes:
        d_liq = default_rows.get((size, "liquefy"))
        r_liq = ratio_rows.get((size, "liquefy"))
        # zstd rows are identical across profile CSVs; prefer default then ratio.
        z19 = default_rows.get((size, "zstd-19")) or ratio_rows.get((size, "zstd-19"))
        z22 = default_rows.get((size, "zstd-22")) or ratio_rows.get((size, "zstd-22"))

        restore_note = "zstd faster restore"
        if d_liq and z22:
            try:
                liq_restore = float(d_liq.get("Restore MB/s", "nan"))
                z22_restore = float(z22.get("Restore MB/s", "nan"))
                if liq_restore > z22_restore:
                    restore_note = "Liquefy faster restore"
            except Exception:
                pass

        row_vals = [
            size,
            _fmt_ratio(d_liq),
            _fmt_mbs(d_liq, "Compress MB/s"),
            _fmt_ratio(r_liq),
            _fmt_mbs(r_liq, "Compress MB/s"),
            _fmt_ratio(z19),
            _fmt_mbs(z19, "Compress MB/s"),
            _fmt_ratio(z22),
            _fmt_mbs(z22, "Compress MB/s"),
            _speedup(d_liq, z22, "Compress MB/s"),
            _speedup(r_liq, z22, "Compress MB/s"),
            restore_note,
        ]
        rendered.append(row_vals)

        # Color policy:
        # - Default ratio/MBps compare vs zstd-19 (practical baseline)
        # - Ratio profile ratio/MBps compare vs zstd-22 (max-ratio baseline)
        # - Speedup columns compare vs 1.0x
        d_ratio = _num(d_liq, "Ratio")
        d_mbs = _num(d_liq, "Compress MB/s")
        r_ratio = _num(r_liq, "Ratio")
        r_mbs = _num(r_liq, "Compress MB/s")
        z19_ratio = _num(z19, "Ratio")
        z19_mbs = _num(z19, "Compress MB/s")
        z22_ratio = _num(z22, "Ratio")
        z22_mbs = _num(z22, "Compress MB/s")
        def_vs_z22 = row_vals[9]
        ratio_vs_z22 = row_vals[10]
        color_rows.append([
            "#FFFFFF",                         # Size
            _cmp_color(d_ratio, z19_ratio),    # Liquefy default ratio vs zstd-19 ratio
            _cmp_color(d_mbs, z19_mbs),        # Liquefy default speed vs zstd-19 speed
            _cmp_color(r_ratio, z22_ratio),    # Liquefy ratio ratio vs zstd-22 ratio
            _cmp_color(r_mbs, z22_mbs),        # Liquefy ratio speed vs zstd-22 speed
            "#F2F2F2",                         # zstd-19 ratio (baseline)
            "#F2F2F2",                         # zstd-19 speed (baseline)
            "#F2F2F2",                         # zstd-22 ratio (baseline)
            "#F2F2F2",                         # zstd-22 speed (baseline)
            _cmp_speedup_color(def_vs_z22),    # default speedup vs z22
            _cmp_speedup_color(ratio_vs_z22),  # ratio speedup vs z22
            "#FFFFFF",                         # restore note
        ])

    _render_table(Path(args.out), args.title, rendered, cell_colors=color_rows)
    print(f"[OK] wrote {args.out}")


if __name__ == "__main__":
    main()
