#!/usr/bin/env python3
"""Generate a compact Liquefy status report from benchmark/scoreboard artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _f(cell: Optional[str]) -> Optional[float]:
    if cell is None:
        return None
    s = str(cell).strip()
    if not s:
        return None
    if s.endswith(("x", "X")):
        s = s[:-1]
    try:
        return float(s)
    except Exception:
        return None


def _pick_openclaw_rows(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, Dict[str, float]]]:
    out: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(dict)
    for r in rows:
        size = str(r.get("Size", "")).strip()
        method = str(r.get("Method", "")).strip().lower()
        if not size:
            continue
        if method.startswith("liquefy"):
            key = "liquefy"
        elif method.startswith("zstd -19"):
            key = "zstd19"
        elif method.startswith("zstd -22"):
            key = "zstd22"
        else:
            continue
        out[size][key] = {
            "ratio": _f(r.get("Ratio")) or 0.0,
            "compress_mb_s": _f(r.get("Compress MB/s")) or 0.0,
            "restore_mb_s": _f(r.get("Restore MB/s")) or 0.0,
            "input_bytes": _f(r.get("Input Bytes")) or 0.0,
            "output_bytes": _f(r.get("Output Bytes")) or 0.0,
        }
    return out


def _compute_speedups(table: Dict[str, Dict[str, Dict[str, float]]]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for size, methods in table.items():
        liq = methods.get("liquefy")
        z22 = methods.get("zstd22")
        z19 = methods.get("zstd19")
        if not liq:
            continue
        row: Dict[str, float] = {}
        if z22 and z22.get("compress_mb_s", 0) > 0:
            row["compress_speedup_vs_zstd22"] = liq["compress_mb_s"] / z22["compress_mb_s"]
            row["ratio_delta_vs_zstd22_pct"] = ((liq["ratio"] / z22["ratio"]) - 1.0) * 100.0 if z22["ratio"] else 0.0
        if z19 and z19.get("compress_mb_s", 0) > 0:
            row["compress_speedup_vs_zstd19"] = liq["compress_mb_s"] / z19["compress_mb_s"]
            row["ratio_delta_vs_zstd19_pct"] = ((liq["ratio"] / z19["ratio"]) - 1.0) * 100.0 if z19["ratio"] else 0.0
        out[size] = row
    return out


def _safe_read_scoreboard_counts(scoreboard_csv: Path) -> Dict[str, object]:
    rows = _read_csv(scoreboard_csv)
    labels = Counter(r.get("win_label", "") for r in rows)
    by_profile = defaultdict(Counter)
    for r in rows:
        by_profile[r.get("profile", "")][r.get("win_label", "")] += 1
    return {
        "rows_total_liquefy": sum(labels.values()),
        "labels": dict(labels),
        "by_profile": {k: dict(v) for k, v in by_profile.items()},
    }


def build_report_payload(args) -> Dict[str, object]:
    scoreboard_csv = Path(args.scoreboard_csv)
    openclaw_default_csv = Path(args.openclaw_default_csv)
    openclaw_ratio_csv = Path(args.openclaw_ratio_csv)

    scoreboard = _safe_read_scoreboard_counts(scoreboard_csv)
    openclaw_default = _pick_openclaw_rows(_read_csv(openclaw_default_csv))
    openclaw_ratio = _pick_openclaw_rows(_read_csv(openclaw_ratio_csv))
    openclaw_default_speedups = _compute_speedups(openclaw_default)
    openclaw_ratio_speedups = _compute_speedups(openclaw_ratio)

    assets = {
        "scoreboard_csv": str(scoreboard_csv),
        "scoreboard_summary_md": str(Path(args.scoreboard_summary_md)),
        "scoreboard_default_png": str(Path(args.scoreboard_default_png)),
        "scoreboard_heatmap_png": str(Path(args.scoreboard_heatmap_png)),
        "openclaw_card_png": str(Path(args.openclaw_card_png)),
    }

    return {
        "schema_version": "liquefy.status.report.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(REPO_ROOT),
        "scoreboard": scoreboard,
        "openclaw_50_200": {
            "default_profile": openclaw_default,
            "ratio_profile": openclaw_ratio,
            "default_speedups": openclaw_default_speedups,
            "ratio_speedups": openclaw_ratio_speedups,
        },
        "security_and_policy": {
            "lsec_version": 2,
            "default_restore_output_cap_bytes": 2 * 1024 * 1024 * 1024,
            "policy_modes": ["strict", "balanced", "off"],
            "risky_override_phrase_required": True,
            "fail_closed_secret": True,
        },
        "artifacts": assets,
    }


def write_markdown(path: Path, payload: Dict[str, object]) -> None:
    sc = payload["scoreboard"]
    oc = payload["openclaw_50_200"]
    lines = [
        "# Liquefy Status Report",
        "",
        f"- Generated (UTC): `{payload['generated_at_utc']}`",
        f"- Scoreboard rows (Liquefy): `{sc['rows_total_liquefy']}`",
        "",
        "## War-Room Scoreboard",
        "",
    ]
    labels = sc.get("labels", {})
    for k in ("FAIL", "TIE_OK", "WIN_RATIO", "WIN_RATIO+SPEED", "WIN_SPEED", "WIN_WORKFLOW"):
        lines.append(f"- `{k}`: **{int(labels.get(k, 0))}**")
    lines.extend(["", "### By Profile", ""])
    by_profile = sc.get("by_profile", {})
    for profile in sorted(by_profile):
        parts = [f"{label}={count}" for label, count in sorted(by_profile[profile].items())]
        lines.append(f"- `{profile}`: " + ", ".join(parts))

    lines.extend(["", "## OpenClaw 50/200MB (Full Verify)", ""])
    for profile_key, speedup_key, label in (
        ("default_profile", "default_speedups", "Default"),
        ("ratio_profile", "ratio_speedups", "Ratio"),
    ):
        lines.append(f"### {label} Profile")
        lines.append("")
        tbl = oc.get(profile_key, {})
        sps = oc.get(speedup_key, {})
        for size in ("50mb", "200mb"):
            row = tbl.get(size, {})
            liq = row.get("liquefy", {})
            z22 = row.get("zstd22", {})
            sp = sps.get(size, {})
            if not liq:
                continue
            lines.append(
                f"- `{size}`: Liquefy `{liq.get('ratio', 0):.2f}x` @ `{liq.get('compress_mb_s', 0):.1f} MB/s`"
                + (f", zstd-22 `{z22.get('ratio', 0):.2f}x` @ `{z22.get('compress_mb_s', 0):.1f} MB/s`" if z22 else "")
                + (f", speedup vs zstd-22 **{sp.get('compress_speedup_vs_zstd22', 0):.1f}x**" if sp else "")
            )
        lines.append("")

    sec = payload["security_and_policy"]
    lines.extend([
        "## Security / Policy",
        "",
        f"- `LSEC v{sec['lsec_version']}` (AES-256-GCM, fail-closed secrets, audit metadata encrypted)",
        f"- Restore output cap default: `{sec['default_restore_output_cap_bytes']}` bytes (`2 GiB`)",
        f"- Policy modes: {', '.join('`'+m+'`' for m in sec['policy_modes'])}",
        f"- Risky override phrase required: `{sec['risky_override_phrase_required']}`",
        "",
        "## Key Artifacts",
        "",
    ])
    for k, v in payload["artifacts"].items():
        lines.append(f"- `{k}`: `{v}`")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate consolidated Liquefy status report (JSON + Markdown).")
    ap.add_argument("--scoreboard-csv", default=str(REPO_ROOT / "bench" / "results" / "SCOREBOARD.csv"))
    ap.add_argument("--scoreboard-summary-md", default=str(REPO_ROOT / "bench" / "results" / "SCOREBOARD_SUMMARY.md"))
    ap.add_argument("--openclaw-default-csv", default=str(REPO_ROOT / "bench" / "results" / "bench_openclaw_50mb_200mb_full_verify_workers8_20260223.csv"))
    ap.add_argument("--openclaw-ratio-csv", default=str(REPO_ROOT / "bench" / "results" / "bench_openclaw_50mb_200mb_full_verify_workers8_ratio_profile_20260223.csv"))
    ap.add_argument("--scoreboard-default-png", default=str(REPO_ROOT / "liquefy_scoreboard_default.png"))
    ap.add_argument("--scoreboard-heatmap-png", default=str(REPO_ROOT / "liquefy_scoreboard_heatmap.png"))
    ap.add_argument("--openclaw-card-png", default=str(REPO_ROOT / "liquefy_vs_zstd_openclaw_50_200.png"))
    ap.add_argument("--out-json", default=str(REPO_ROOT / "bench" / "results" / "LIQUEFY_STATUS_REPORT.json"))
    ap.add_argument("--out-md", default=str(REPO_ROOT / "bench" / "results" / "LIQUEFY_STATUS_REPORT.md"))
    args = ap.parse_args()

    payload = build_report_payload(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_markdown(out_md, payload)
    print(f"[OK] wrote {out_json}")
    print(f"[OK] wrote {out_md}")


if __name__ == "__main__":
    main()
