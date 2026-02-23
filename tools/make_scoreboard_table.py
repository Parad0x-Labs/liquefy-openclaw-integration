#!/usr/bin/env python3
"""Render a color-coded scoreboard table PNG from SCOREBOARD.csv."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    import pandas as pd
    import matplotlib.pyplot as plt
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "MISSING_DEPENDENCY: install pandas + matplotlib to use this script "
        f"({exc})"
    )


def _to_float(x):
    if x is None:
        return None
    if isinstance(x, (int, float)):
        v = float(x)
        return None if v != v else v
    if hasattr(x, "item"):
        try:
            v = float(x.item())
            return None if v != v else v
        except Exception:
            pass
    s = str(x).strip()
    if not s or s.lower() == "nan":
        return None
    try:
        v = float(s)
        return None if v != v else v
    except Exception:
        return None


def _fmt_pct(x):
    v = _to_float(x)
    return "—" if v is None else f"{v:.1f}%"


def _shorten_fixture(f: str) -> str:
    f = str(f)
    prefixes = [
        "server_suite/",
        "openclaw/",
        "openclaw_bench/",
    ]
    for p in prefixes:
        if f.startswith(p):
            return f[len(p):]
    return f


def _label_color(label: str) -> str:
    l = str(label or "")
    if l.startswith("WIN_"):
        return "#D8F3DC"  # green
    if l == "TIE_OK":
        return "#FFF3BF"  # yellow
    if l == "FAIL":
        return "#FFD6D6"  # red
    return "#FFFFFF"


def _delta_color(val, *, inverse: bool = False, win_pct: float | None = None, tie_pct: float | None = None) -> str:
    v = _to_float(val)
    if v is None:
        return "#F5F5F5"
    # For end2end delta, lower (more negative) is better.
    score = -v if inverse else v
    if win_pct is not None and score >= win_pct:
        return "#C7F9CC"
    if score > 0:
        return "#E9FCEB"
    if tie_pct is not None and score >= -abs(tie_pct):
        return "#FFF6CC"
    if score < 0:
        return "#FFE3E3"
    return "#F7F7F7"


def _profile_cell_na(profile: str, col_key: str) -> bool:
    """Grey out columns that are not part of the profile's decision policy."""
    p = str(profile or "").lower()
    if p in {"default", "ratio"} and col_key in {"speed_vs_zstd6_pct", "speed_vs_zstd3_pct"}:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Render color-coded Liquefy scoreboard table.")
    ap.add_argument("--csv", required=True, help="Path to SCOREBOARD.csv")
    ap.add_argument("--out", required=True, help="Output PNG path")
    ap.add_argument("--title", default="Liquefy War Room Scoreboard")
    ap.add_argument("--profiles", default="", help="Optional comma-separated profiles (default,ratio,speed)")
    ap.add_argument("--source-types", default="", help="Optional comma-separated source types")
    ap.add_argument("--max-rows", type=int, default=0, help="Optional max rows after sorting (0=all)")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    out_path = Path(args.out)
    profiles_filter = [x.strip() for x in args.profiles.split(",") if x.strip()]
    source_filter = [x.strip() for x in args.source_types.split(",") if x.strip()]

    df = pd.read_csv(csv_path)
    required = {
        "source_type",
        "fixture",
        "profile",
        "engine_id",
        "ratio_vs_zstd22_pct",
        "speed_vs_zstd6_pct",
        "speed_vs_zstd3_pct",
        "speed_vs_zstd22_pct",
        "end2end_time_vs_zstd22_pct",
        "win_label",
    }
    missing = sorted(required - set(df.columns))
    if missing:
        raise SystemExit(f"CSV missing columns: {missing}")

    if profiles_filter:
        df = df[df["profile"].astype(str).isin(profiles_filter)].copy()
    if source_filter:
        df = df[df["source_type"].astype(str).isin(source_filter)].copy()
    if df.empty:
        raise SystemExit("No rows after filtering.")

    # Stable, useful ordering: FAIL first, then ties, then wins; group by profile/source/fixture.
    label_order = {"FAIL": 0, "TIE_OK": 1, "WIN_WORKFLOW": 2, "WIN_SPEED": 3, "WIN_RATIO": 4, "WIN_RATIO+SPEED": 5}
    prof_order = {"default": 0, "ratio": 1, "speed": 2}
    df["_label_ord"] = df["win_label"].map(lambda x: label_order.get(str(x), 99))
    df["_profile_ord"] = df["profile"].map(lambda x: prof_order.get(str(x), 99))
    df["_fixture_short"] = df["fixture"].map(_shorten_fixture)
    df = df.sort_values(["_label_ord", "_profile_ord", "source_type", "_fixture_short", "engine_id"]).copy()
    if args.max_rows and args.max_rows > 0:
        df = df.head(args.max_rows).copy()

    display_cols = [
        "source_type",
        "_fixture_short",
        "profile",
        "engine_id",
        "ratio_vs_zstd22_pct",
        "speed_vs_zstd6_pct",
        "speed_vs_zstd3_pct",
        "speed_vs_zstd22_pct",
        "end2end_time_vs_zstd22_pct",
        "win_label",
    ]
    col_labels = [
        "Source",
        "Fixture",
        "Profile",
        "Engine",
        "Ratio vs z22",
        "Speed vs z6",
        "Speed vs z3",
        "Speed vs z22",
        "E2E Time vs z22",
        "Label",
    ]

    cell_rows = []
    for _, r in df.iterrows():
        profile = str(r["profile"])
        s6_text = "n/a" if _profile_cell_na(profile, "speed_vs_zstd6_pct") else _fmt_pct(r["speed_vs_zstd6_pct"])
        s3_text = "n/a" if _profile_cell_na(profile, "speed_vs_zstd3_pct") else _fmt_pct(r["speed_vs_zstd3_pct"])
        cell_rows.append([
            str(r["source_type"]),
            str(r["_fixture_short"]),
            profile,
            str(r["engine_id"]),
            _fmt_pct(r["ratio_vs_zstd22_pct"]),
            s6_text,
            s3_text,
            _fmt_pct(r["speed_vs_zstd22_pct"]),
            _fmt_pct(r["end2end_time_vs_zstd22_pct"]),
            str(r["win_label"]),
        ])

    nrows = len(cell_rows)
    ncols = len(col_labels)
    fig_w = min(26, max(14, ncols * 1.8))
    fig_h = min(22, max(5.5, nrows * 0.34 + 1.7))

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=180)
    ax.axis("off")
    table = ax.table(
        cellText=cell_rows,
        colLabels=col_labels,
        loc="upper center",
        cellLoc="center",
        colLoc="center",
        bbox=[0.0, 0.0, 1.0, 0.90],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.2)
    table.scale(1, 1.12)
    try:
        table.auto_set_column_width(col=list(range(ncols)))
    except Exception:
        pass

    # Column indexes in rendered table
    idx_ratio = 4
    idx_s6 = 5
    idx_s3 = 6
    idx_s22 = 7
    idx_e2e = 8
    idx_label = 9

    for (r, c), cell in table.get_celld().items():
        if r == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#E8EDF5")
            continue

        row_idx = r - 1
        src_row = df.iloc[row_idx]

        # Left-align text-heavy columns
        if c in (0, 1, 3):
            cell.get_text().set_ha("left")

        if c == idx_ratio:
            cell.set_facecolor(_delta_color(src_row["ratio_vs_zstd22_pct"], win_pct=2.0, tie_pct=2.0))
        elif c == idx_e2e:
            # lower end-to-end time is better => inverse
            cell.set_facecolor(_delta_color(src_row["end2end_time_vs_zstd22_pct"], inverse=True, win_pct=20.0, tie_pct=20.0))
        elif c == idx_label:
            cell.set_facecolor(_label_color(src_row["win_label"]))
            cell.set_text_props(weight="bold")

    # Explicit delta cell coloring (avoid brittle column mapping tricks)
    for row_i, (_, src_row) in enumerate(df.iterrows(), start=1):
        profile = str(src_row["profile"])
        if _profile_cell_na(profile, "speed_vs_zstd6_pct"):
            table[row_i, idx_s6].set_facecolor("#EAEAEA")
            table[row_i, idx_s6].get_text().set_color("#666666")
        else:
            table[row_i, idx_s6].set_facecolor(_delta_color(src_row["speed_vs_zstd6_pct"], win_pct=20.0, tie_pct=20.0))
        if _profile_cell_na(profile, "speed_vs_zstd3_pct"):
            table[row_i, idx_s3].set_facecolor("#EAEAEA")
            table[row_i, idx_s3].get_text().set_color("#666666")
        else:
            table[row_i, idx_s3].set_facecolor(_delta_color(src_row["speed_vs_zstd3_pct"], win_pct=20.0, tie_pct=20.0))
        table[row_i, idx_s22].set_facecolor(_delta_color(src_row["speed_vs_zstd22_pct"], win_pct=20.0, tie_pct=20.0))

    ax.set_title(args.title, fontsize=14, weight="bold", pad=6)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    print(f"[OK] wrote {out_path}")


if __name__ == "__main__":
    main()
