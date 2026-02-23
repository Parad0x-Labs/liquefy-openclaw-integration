#!/usr/bin/env python3
"""Render a postable PNG comparison table from Liquefy/zstd benchmark CSVs."""

from __future__ import annotations

import argparse
import re
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
        try:
            v = float(x)
        except Exception:
            return None
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
    s = s.rstrip("xX")
    try:
        return float(s)
    except Exception:
        return None


def _normalize_level_text(x) -> str:
    s = "" if x is None else str(x).strip()
    if not s or s.lower() == "nan":
        return ""
    m = re.fullmatch(r"(\d+)\.0+", s)
    if m:
        return m.group(1)
    return s


def fmt_ratio(x):
    v = _to_float(x)
    return f"{v:.2f}x" if v is not None else "—"


def fmt_mbs(x):
    v = _to_float(x)
    return f"{v:.1f}" if v is not None else "—"


def normalize_columns(df: "pd.DataFrame") -> "pd.DataFrame":
    out = df.copy()
    if "fixture" not in out.columns:
        if "file_label" in out.columns:
            out["fixture"] = out["file_label"]
        else:
            raise SystemExit("CSV missing fixture/file_label column")
    if "engine_id" not in out.columns:
        if "engine_used" in out.columns:
            out["engine_id"] = out["engine_used"]
        else:
            out["engine_id"] = ""
    if "profile" not in out.columns:
        out["profile"] = "default"
    if "byteperfect" not in out.columns:
        if "hash_verify" in out.columns:
            out["byteperfect"] = out["hash_verify"]
        else:
            out["byteperfect"] = "PASS"
    return out


def normalize_methods(df: "pd.DataFrame") -> "pd.DataFrame":
    out = df.copy()
    out["method"] = out["method"].astype(str)
    out["level"] = out.get("level", "").map(_normalize_level_text)
    out["method_norm"] = ""
    out["zstd_level_norm"] = ""

    for idx, row in out.iterrows():
        method = str(row.get("method", "")).strip().lower()
        level = _normalize_level_text(row.get("level", ""))

        if method in {"liquefy", "liquefy (.null)"}:
            out.at[idx, "method_norm"] = "liquefy"
            continue

        if method == "zstd":
            out.at[idx, "method_norm"] = "zstd"
            out.at[idx, "zstd_level_norm"] = level
            continue

        m = re.match(r"zstd\s*-\s*(\d+)", method)
        if m:
            out.at[idx, "method_norm"] = "zstd"
            out.at[idx, "zstd_level_norm"] = m.group(1)
            continue

        out.at[idx, "method_norm"] = "other"

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Benchmark CSV (CI subset or full matrix CSV)")
    ap.add_argument("--out", required=True, help="Output PNG path")
    ap.add_argument("--title", default="Liquefy vs zstd (lvl 19/22)")
    ap.add_argument("--levels", default="19,22", help="Comma-separated zstd levels (default: 19,22)")
    ap.add_argument("--fixtures", default="", help="Optional comma-separated fixture filter")
    ap.add_argument(
        "--profiles",
        default="",
        help="Optional comma-separated Liquefy profile filter (e.g. default,ratio,speed)",
    )
    ap.add_argument(
        "--profile-label",
        default="",
        help="Override displayed Liquefy profile label when source CSV has no profile column (e.g. ratio).",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv)
    out_path = Path(args.out)
    levels = [s.strip() for s in args.levels.split(",") if s.strip()]
    fixtures_filter = [s.strip() for s in args.fixtures.split(",") if s.strip()]
    profiles_filter = [s.strip() for s in args.profiles.split(",") if s.strip()]

    df = pd.read_csv(csv_path)
    df = normalize_columns(df)
    if args.profile_label.strip():
        # Useful for full matrix CSVs that represent a single profile per file and do not carry a profile column.
        df["profile"] = str(args.profile_label).strip()
    required = {"fixture", "method", "engine_id", "profile", "level", "ratio", "compress_mb_s", "byteperfect"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SystemExit(f"CSV missing columns: {missing}")

    df = df[df["byteperfect"].astype(str).str.upper().eq("PASS")].copy()
    if fixtures_filter:
        df = df[df["fixture"].astype(str).isin(fixtures_filter)].copy()

    df = normalize_methods(df)
    df = df[df["method_norm"].isin(["liquefy", "zstd"])].copy()

    liq = df[df["method_norm"] == "liquefy"].copy()
    zstd = df[(df["method_norm"] == "zstd") & (df["zstd_level_norm"].isin(levels))].copy()
    if profiles_filter:
        liq = liq[liq["profile"].astype(str).isin(profiles_filter)].copy()

    if liq.empty:
        raise SystemExit("No Liquefy rows found in CSV after filtering.")

    # Liquefy is per fixture/profile. zstd rows in CI subset have blank profile, so we align by fixture.
    key_cols = ["fixture", "profile"]
    liq_key = liq[key_cols + ["engine_id", "ratio", "compress_mb_s"]].rename(
        columns={"ratio": "liq_ratio", "compress_mb_s": "liq_mb_s"}
    )

    zstd_profile_nonblank = (
        zstd["profile"].fillna("").astype(str).str.strip().replace("nan", "").ne("").any()
        if not zstd.empty else False
    )
    if zstd_profile_nonblank:
        zstd_key_cols = ["fixture", "profile"]
        zstd_p = zstd[zstd_key_cols + ["zstd_level_norm", "ratio", "compress_mb_s"]].copy()
        zstd_ratio = zstd_p.pivot_table(index=zstd_key_cols, columns="zstd_level_norm", values="ratio", aggfunc="first")
        zstd_mbs = zstd_p.pivot_table(index=zstd_key_cols, columns="zstd_level_norm", values="compress_mb_s", aggfunc="first")
        base = liq_key.set_index(key_cols)
        for lv in levels:
            base[f"zstd{lv}_ratio"] = zstd_ratio.get(lv)
            base[f"zstd{lv}_mb_s"] = zstd_mbs.get(lv)
        base = base.reset_index()
    else:
        zstd_key_cols = ["fixture"]
        zstd_p = zstd[zstd_key_cols + ["zstd_level_norm", "ratio", "compress_mb_s"]].copy()
        zstd_ratio = zstd_p.pivot_table(index=zstd_key_cols, columns="zstd_level_norm", values="ratio", aggfunc="first")
        zstd_mbs = zstd_p.pivot_table(index=zstd_key_cols, columns="zstd_level_norm", values="compress_mb_s", aggfunc="first")
        base = liq_key.set_index(key_cols)
        # Map zstd rows by fixture to each Liquefy profile row.
        fixture_index = base.index.get_level_values("fixture")
        for lv in levels:
            ratio_map = zstd_ratio.get(lv).to_dict() if lv in zstd_ratio.columns else {}
            mbs_map = zstd_mbs.get(lv).to_dict() if lv in zstd_mbs.columns else {}
            base[f"zstd{lv}_ratio"] = [ratio_map.get(fx) for fx in fixture_index]
            base[f"zstd{lv}_mb_s"] = [mbs_map.get(fx) for fx in fixture_index]
        base = base.reset_index()

    base["format"] = base["fixture"].astype(str)
    prof_order = {"default": 0, "ratio": 1, "speed": 2}
    base["_p"] = base["profile"].map(lambda x: prof_order.get(str(x), 99))
    base = base.sort_values(["format", "engine_id", "_p"]).drop(columns=["_p"])

    col_labels = ["Format", "Engine", "Profile", "Liquefy\nRatio", "Liquefy\nMB/s"]
    for lv in levels:
        col_labels += [f"zstd-{lv}\nRatio", f"zstd-{lv}\nMB/s"]

    cell_rows = []
    for _, r in base.iterrows():
        row = [
            r["format"],
            r["engine_id"],
            r["profile"],
            fmt_ratio(r.get("liq_ratio")),
            fmt_mbs(r.get("liq_mb_s")),
        ]
        for lv in levels:
            row += [fmt_ratio(r.get(f"zstd{lv}_ratio")), fmt_mbs(r.get(f"zstd{lv}_mb_s"))]
        cell_rows.append(row)

    nrows = max(1, len(cell_rows))
    ncols = len(col_labels)
    fig_w = min(22, max(10, ncols * 1.55))
    fig_h = min(14, max(2.4, nrows * 0.38 + 1.2))

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=200)
    ax.axis("off")
    table = ax.table(
        cellText=cell_rows,
        colLabels=col_labels,
        loc="upper center",
        cellLoc="center",
        colLoc="center",
        bbox=[0.0, 0.0, 1.0, 0.86],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.8)
    table.scale(1, 1.18)
    try:
        table.auto_set_column_width(col=list(range(ncols)))
    except Exception:
        pass

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#E8EDF5")
        if row != 0 and col in (0, 1):
            cell.get_text().set_ha("left")

    ax.set_title(args.title, fontsize=14, weight="bold", pad=6)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    print(f"[OK] wrote {out_path}")


if __name__ == "__main__":
    main()
