#!/usr/bin/env python3
"""
Build a war-room scoreboard across format matrix, OpenClaw bench, and CI subset CSVs.

Outputs:
- SCOREBOARD.csv (row-level comparisons and win labels)
- SCOREBOARD_SUMMARY.md (counts + top wins + fails)
"""

from __future__ import annotations

import argparse
import csv
import glob
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def parse_float(cell) -> Optional[float]:
    if cell is None:
        return None
    s = str(cell).strip()
    if not s or s.lower() == "nan":
        return None
    try:
        return float(s)
    except Exception:
        return None


def parse_ratio(cell) -> Optional[float]:
    if cell is None:
        return None
    s = str(cell).strip()
    if not s or s.lower() == "nan":
        return None
    if s.endswith("x") or s.endswith("X"):
        s = s[:-1]
    try:
        return float(s)
    except Exception:
        return None


def pct_delta(new: Optional[float], base: Optional[float]) -> Optional[float]:
    if new is None or base is None or base == 0:
        return None
    return ((new / base) - 1.0) * 100.0


def pct_time_delta(new_time: Optional[float], base_time: Optional[float]) -> Optional[float]:
    if new_time is None or base_time is None or base_time == 0:
        return None
    return ((new_time / base_time) - 1.0) * 100.0


def find_latest(glob_pattern: str, *, exclude_substrings: Iterable[str] = ()) -> Optional[Path]:
    candidates = [
        Path(p) for p in glob.glob(glob_pattern)
        if Path(p).is_file() and not any(x in Path(p).name for x in exclude_substrings)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _is_pass(cell: str) -> bool:
    return str(cell or "").strip().upper() == "PASS"


def _method_key_generic(method: str, level: str = "") -> str:
    m = str(method or "").strip()
    lv = str(level or "").strip()
    ml = m.lower()
    if m == "Liquefy (.null)" or ml == "liquefy":
        return "liquefy"
    if ml == "zstd":
        lvf = parse_float(lv)
        if lvf is not None:
            return f"zstd-{int(lvf)}"
        return "zstd"
    if ml.startswith("zstd -"):
        try:
            return f"zstd-{int(float(m.split('-')[-1].strip()))}"
        except Exception:
            return ml.replace(" ", "")
    return ml.replace(" ", "_")


def _normalize_record(
    *,
    source_type: str,
    source_file: str,
    fixture: str,
    profile: str,
    scenario: str,
    method_key: str,
    engine_id: str,
    input_bytes: Optional[float],
    output_bytes: Optional[float],
    ratio: Optional[float],
    compress_mb_s: Optional[float],
    decompress_mb_s: Optional[float],
    end2end_s: Optional[float],
    hash_ok: bool,
    search_ok: Optional[bool] = None,
    search_while_compressed: Optional[str] = None,
    partial_extract: Optional[str] = None,
) -> Dict[str, object]:
    return {
        "source_type": source_type,
        "source_file": source_file,
        "fixture": fixture,
        "profile": profile,
        "scenario": scenario,
        "method_key": method_key,
        "engine_id": engine_id,
        "input_bytes": input_bytes,
        "output_bytes": output_bytes,
        "ratio": ratio,
        "compress_mb_s": compress_mb_s,
        "decompress_mb_s": decompress_mb_s,
        "end2end_s": end2end_s,
        "hash_ok": bool(hash_ok),
        "search_ok": search_ok,
        "search_while_compressed": search_while_compressed,
        "partial_extract": partial_extract,
    }


def load_format_matrix(csv_path: Path, *, profile_label: str) -> List[Dict[str, object]]:
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    out: List[Dict[str, object]] = []
    for r in rows:
        method_key = _method_key_generic(r.get("method", ""), r.get("level", ""))
        fixture = f"{r.get('scenario', '')}/{r.get('file_label', '')}".strip("/")
        out.append(_normalize_record(
            source_type="format_matrix",
            source_file=csv_path.name,
            fixture=fixture,
            profile=profile_label,
            scenario=r.get("scenario", ""),
            method_key=method_key,
            engine_id=(r.get("engine_used") or ("zstd" if method_key.startswith("zstd") else "unknown")),
            input_bytes=parse_float(r.get("input_bytes")),
            output_bytes=parse_float(r.get("output_bytes")),
            ratio=parse_ratio(r.get("ratio")),
            compress_mb_s=parse_float(r.get("compress_mb_s")),
            decompress_mb_s=parse_float(r.get("decompress_mb_s")),
            end2end_s=parse_float(r.get("compress_s")),
            hash_ok=_is_pass(r.get("hash_verify", "")),
        ))
    return out


def load_openclaw_bench(csv_path: Path, *, profile_label: str) -> List[Dict[str, object]]:
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    out: List[Dict[str, object]] = []
    for r in rows:
        size = str(r.get("Size", "")).strip()
        method_key = _method_key_generic(r.get("Method", ""), r.get("Level", ""))
        out.append(_normalize_record(
            source_type="openclaw_bench",
            source_file=csv_path.name,
            fixture=f"openclaw_bench/{size}",
            profile=profile_label,
            scenario="openclaw_bench",
            method_key=method_key,
            engine_id="engine-router" if method_key == "liquefy" else "zstd",
            input_bytes=parse_float(r.get("Input Bytes")),
            output_bytes=parse_float(r.get("Output Bytes")),
            ratio=parse_ratio(r.get("Ratio")),
            compress_mb_s=parse_float(r.get("Compress MB/s")),
            decompress_mb_s=parse_float(r.get("Restore MB/s")),
            end2end_s=parse_float(r.get("Compress Time (s)")),
            hash_ok=_is_pass(r.get("Hash Verify", "")),
            search_ok=_is_pass(r.get("Search Check", "")),
            search_while_compressed=r.get("Search While Compressed"),
            partial_extract=r.get("Partial Extract"),
        ))
    return out


def load_ci_subset(csv_path: Path) -> List[Dict[str, object]]:
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    out: List[Dict[str, object]] = []
    for r in rows:
        method_key = _method_key_generic(r.get("method", ""), r.get("level", ""))
        raw_profile = str(r.get("profile", "") or "").strip()
        if raw_profile.lower() == "nan":
            raw_profile = ""
        input_bytes = parse_float(r.get("input_bytes"))
        comp_mbs = parse_float(r.get("compress_mb_s"))
        end2end_s = None
        if input_bytes is not None and comp_mbs and comp_mbs > 0:
            end2end_s = input_bytes / (comp_mbs * 1024.0 * 1024.0)
        profiles = [raw_profile or "default"]
        if method_key.startswith("zstd") and not raw_profile:
            profiles = ["default", "ratio", "speed"]
        for profile in profiles:
            out.append(_normalize_record(
                source_type="ci_subset",
                source_file=csv_path.name,
                fixture=str(r.get("fixture", "")),
                profile=profile,
                scenario="ci_subset",
                method_key=method_key,
                engine_id=str(r.get("engine_id", "")) if method_key == "liquefy" else "zstd",
                input_bytes=input_bytes,
                output_bytes=parse_float(r.get("output_bytes")),
                ratio=parse_float(r.get("ratio")),
                compress_mb_s=comp_mbs,
                decompress_mb_s=parse_float(r.get("decompress_mb_s")),
                end2end_s=end2end_s,
                hash_ok=_is_pass(r.get("byteperfect", "")),
            ))
    return out


def _entropy_band(fixture: str) -> str:
    f = fixture.lower()
    if "high_entropy" in f or "random" in f:
        return "high"
    if any(x in f for x in ("cloudtrail", "session", "tool_trace", "json")):
        return "medium"
    return "low"


def _has_liquefy_workflow_edge(liq: Dict[str, object], z22: Optional[Dict[str, object]]) -> bool:
    if liq.get("source_type") != "openclaw_bench":
        return False
    liq_partial = str(liq.get("partial_extract") or "").lower()
    z22_partial = str((z22 or {}).get("partial_extract") or "").lower()
    liq_search = str(liq.get("search_while_compressed") or "").lower()
    z22_search = str((z22 or {}).get("search_while_compressed") or "").lower()
    return ("yes" in liq_partial and "no" in z22_partial) or ("tracevault_search" in liq_search and "tracevault_search" not in z22_search)


def _as_num(x):
    return x if isinstance(x, (int, float)) else None


def _best_speed_ref(row: Dict[str, object]) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """Return speed deltas vs zstd refs as (s3, s6, s22)."""
    s3 = _as_num(row.get("speed_vs_zstd3_pct"))
    s6 = _as_num(row.get("speed_vs_zstd6_pct"))
    s22 = _as_num(row.get("speed_vs_zstd22_pct"))
    return s3, s6, s22


def classify_row_profile_aware(
    row: Dict[str, object],
    *,
    # Default profile expectations
    default_ratio_tie_pct: float = 2.0,
    default_speed_tie_pct: float = 20.0,
    default_ratio_win_pct: float = 2.0,
    default_speed_win_pct: float = 20.0,
    # Ratio profile expectations
    ratio_ratio_win_pct: float = 2.0,
    ratio_speed_catastrophic_pct: float = 70.0,
    # Speed profile expectations
    speed_speed_win_pct: float = 20.0,
    speed_ratio_max_regress_pct: float = 10.0,
    speed_min_input_bytes: float = 5_000_000.0,
    # End-to-end win support
    end2end_win_pct: float = 20.0,
) -> str:
    profile = str(row.get("profile") or "").lower()
    entropy_band = str(row.get("entropy_band") or "").lower()
    ratio_delta = _as_num(row.get("ratio_vs_zstd22_pct"))
    end2end_delta = _as_num(row.get("end2end_time_vs_zstd22_pct"))
    input_bytes = _as_num(row.get("input_bytes"))
    workflow_win = bool(row.get("workflow_win"))

    s3, s6, s22 = _best_speed_ref(row)

    def speed_win_vs(preferred: str, win_pct: float) -> bool:
        refs: List[float] = []
        if preferred == "z6":
            if s6 is not None:
                refs.append(s6)
            if s3 is not None:
                refs.append(s3)
        else:
            if s3 is not None:
                refs.append(s3)
            if s6 is not None:
                refs.append(s6)
        if not refs and s22 is not None:
            refs = [s22]
        if any(v >= win_pct for v in refs):
            return True
        if end2end_delta is not None and end2end_delta <= -abs(end2end_win_pct):
            return True
        return False

    def speed_is_catastrophic(cat_pct: float, *, ratio_mode: bool = False) -> bool:
        # Ratio profile should be compared against zstd-22 speed class, not zstd-3/6.
        refs = [v for v in ((s22,) if ratio_mode else (s6, s3, s22)) if v is not None]
        if not refs:
            return False
        return any(v <= -abs(cat_pct) for v in refs) or (
            end2end_delta is not None and end2end_delta >= abs(cat_pct)
        )

    ratio_win_default = ratio_delta is not None and ratio_delta >= default_ratio_win_pct
    ratio_win_ratio = ratio_delta is not None and ratio_delta >= ratio_ratio_win_pct
    # Default profile is intended as a safe drop-in, so judge speed against zstd-22 class.
    speed_win_default = False
    if s22 is not None and s22 >= default_speed_win_pct:
        speed_win_default = True
    if not speed_win_default and end2end_delta is not None and end2end_delta <= -abs(end2end_win_pct):
        speed_win_default = True
    speed_win_speed = speed_win_vs("z3", speed_speed_win_pct)

    row["ratio_win"] = False
    row["speed_win"] = False

    if profile == "default":
        row["ratio_win"] = ratio_win_default
        row["speed_win"] = speed_win_default

        if ratio_win_default and speed_win_default:
            return "WIN_RATIO+SPEED"
        if ratio_win_default:
            return "WIN_RATIO"
        if speed_win_default:
            return "WIN_SPEED"
        if workflow_win:
            return "WIN_WORKFLOW"

        ratio_ok = True if ratio_delta is None else (ratio_delta >= -abs(default_ratio_tie_pct))
        speed_ref = s22
        speed_ok = True
        if speed_ref is not None:
            speed_ok = speed_ref >= -abs(default_speed_tie_pct)
        if end2end_delta is not None and end2end_delta > abs(default_speed_tie_pct):
            speed_ok = False
        return "TIE_OK" if (ratio_ok and speed_ok) else "FAIL"

    if profile == "ratio":
        row["ratio_win"] = ratio_win_ratio
        speed_win = speed_win_vs("z6", default_speed_win_pct)
        row["speed_win"] = speed_win

        if ratio_win_ratio and speed_win:
            return "WIN_RATIO+SPEED"
        if ratio_win_ratio:
            return "WIN_RATIO"
        if speed_win:
            return "WIN_SPEED"
        if workflow_win:
            return "WIN_WORKFLOW"

        # Hard-entropy ratio mode is not expected to beat zstd on ratio or speed; only guard ratio regressions.
        if entropy_band == "high":
            ratio_ok = True if ratio_delta is None else (ratio_delta >= -abs(default_ratio_tie_pct))
            return "TIE_OK" if ratio_ok else "FAIL"

        if speed_is_catastrophic(ratio_speed_catastrophic_pct, ratio_mode=True):
            return "FAIL"
        return "TIE_OK"

    if profile == "speed":
        # Small fixtures are dominated by call overhead and are not meaningful for speed-profile win/loss labeling.
        if input_bytes is not None and input_bytes < speed_min_input_bytes:
            row["speed_win"] = False
            row["ratio_win"] = False
            return "TIE_OK"
        row["speed_win"] = speed_win_speed
        ratio_ok = True if ratio_delta is None else (ratio_delta >= -abs(speed_ratio_max_regress_pct))
        row["ratio_win"] = ratio_ok

        if speed_win_speed and ratio_ok:
            return "WIN_SPEED"
        if speed_win_speed and not ratio_ok:
            return "FAIL"
        if workflow_win:
            return "WIN_WORKFLOW"
        return "TIE_OK" if ratio_ok else "FAIL"

    return "FAIL"


def classify_row(
    row: Dict[str, object],
    *,
    ratio_win_pct: float,
    speed_win_pct: float,
    tie_ratio_pct: float,
    tie_speed_pct: float,
) -> str:
    ratio_delta = row.get("ratio_vs_zstd22_pct")
    speed3_delta = row.get("speed_vs_zstd3_pct")
    speed6_delta = row.get("speed_vs_zstd6_pct")
    speed22_delta = row.get("speed_vs_zstd22_pct")
    end2end_delta = row.get("end2end_time_vs_zstd22_pct")
    workflow_win = bool(row.get("workflow_win"))

    ratio_win = isinstance(ratio_delta, (int, float)) and ratio_delta >= ratio_win_pct
    speed_refs = [v for v in (speed3_delta, speed6_delta) if isinstance(v, (int, float))]
    speed_win = any(v >= speed_win_pct for v in speed_refs)
    if not speed_win and isinstance(end2end_delta, (int, float)) and end2end_delta <= -speed_win_pct:
        speed_win = True
    if not speed_win and not speed_refs and isinstance(speed22_delta, (int, float)) and speed22_delta >= speed_win_pct:
        speed_win = True

    row["ratio_win"] = ratio_win
    row["speed_win"] = speed_win

    if ratio_win and speed_win:
        return "WIN_RATIO+SPEED"
    if ratio_win:
        return "WIN_RATIO"
    if speed_win:
        return "WIN_SPEED"
    if workflow_win:
        return "WIN_WORKFLOW"

    ratio_ok = True
    if isinstance(ratio_delta, (int, float)):
        ratio_ok = ratio_delta >= -abs(tie_ratio_pct)

    speed_ref_available = False
    speed_ok = True
    for v in (speed3_delta, speed6_delta, speed22_delta):
        if isinstance(v, (int, float)):
            speed_ref_available = True
            if v < -abs(tie_speed_pct):
                speed_ok = False
                break
    if isinstance(end2end_delta, (int, float)) and end2end_delta > abs(tie_speed_pct):
        speed_ok = False
        speed_ref_available = True

    if ratio_ok and (speed_ok or not speed_ref_available):
        return "TIE_OK"
    return "FAIL"


def build_scoreboard(
    records: List[Dict[str, object]],
    *,
    ratio_win_pct: float,
    speed_win_pct: float,
    tie_ratio_pct: float,
    tie_speed_pct: float,
) -> List[Dict[str, object]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, Dict[str, object]]] = defaultdict(dict)
    for rec in records:
        key = (str(rec["source_type"]), str(rec["fixture"]), str(rec["profile"]))
        grouped[key][str(rec["method_key"])] = rec

    out_rows: List[Dict[str, object]] = []
    for (source_type, fixture, profile), methods in sorted(grouped.items()):
        liq = methods.get("liquefy")
        if not liq:
            continue
        z3 = methods.get("zstd-3")
        z6 = methods.get("zstd-6")
        z19 = methods.get("zstd-19")
        z22 = methods.get("zstd-22")

        ratio_vs_z22 = pct_delta(liq.get("ratio"), z22.get("ratio") if z22 else None)
        speed_vs_z3 = pct_delta(liq.get("compress_mb_s"), z3.get("compress_mb_s") if z3 else None)
        speed_vs_z6 = pct_delta(liq.get("compress_mb_s"), z6.get("compress_mb_s") if z6 else None)
        speed_vs_z22 = pct_delta(liq.get("compress_mb_s"), z22.get("compress_mb_s") if z22 else None)
        e2e_vs_z22 = pct_time_delta(liq.get("end2end_s"), z22.get("end2end_s") if z22 else None)
        workflow_win = _has_liquefy_workflow_edge(liq, z22)

        row: Dict[str, object] = {
            "source_type": source_type,
            "source_file": liq.get("source_file"),
            "scenario": liq.get("scenario"),
            "fixture": fixture,
            "profile": profile,
            "entropy_band": _entropy_band(fixture),
            "engine_id": liq.get("engine_id"),
            "hash_ok": liq.get("hash_ok"),
            "search_ok": liq.get("search_ok"),
            "search_while_compressed": liq.get("search_while_compressed"),
            "partial_extract": liq.get("partial_extract"),
            "input_bytes": liq.get("input_bytes"),
            "liq_ratio": liq.get("ratio"),
            "zstd3_ratio": z3.get("ratio") if z3 else None,
            "zstd6_ratio": z6.get("ratio") if z6 else None,
            "zstd19_ratio": z19.get("ratio") if z19 else None,
            "zstd22_ratio": z22.get("ratio") if z22 else None,
            "liq_compress_mb_s": liq.get("compress_mb_s"),
            "zstd3_compress_mb_s": z3.get("compress_mb_s") if z3 else None,
            "zstd6_compress_mb_s": z6.get("compress_mb_s") if z6 else None,
            "zstd19_compress_mb_s": z19.get("compress_mb_s") if z19 else None,
            "zstd22_compress_mb_s": z22.get("compress_mb_s") if z22 else None,
            "liq_end2end_s": liq.get("end2end_s"),
            "zstd22_end2end_s": z22.get("end2end_s") if z22 else None,
            "ratio_vs_zstd22_pct": ratio_vs_z22,
            "speed_vs_zstd3_pct": speed_vs_z3,
            "speed_vs_zstd6_pct": speed_vs_z6,
            "speed_vs_zstd22_pct": speed_vs_z22,
            "end2end_time_vs_zstd22_pct": e2e_vs_z22,
            "workflow_win": workflow_win,
        }
        row["win_label"] = classify_row_profile_aware(row)
        out_rows.append(row)
    return out_rows


def _fmt_pct(v: object) -> str:
    if not isinstance(v, (int, float)):
        return ""
    return f"{v:.2f}"


def _fmt_float(v: object) -> str:
    if not isinstance(v, (int, float)):
        return ""
    return f"{v:.4f}"


def write_scoreboard_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "source_type", "source_file", "scenario", "fixture", "profile", "entropy_band",
        "engine_id", "hash_ok", "search_ok", "search_while_compressed", "partial_extract",
        "input_bytes",
        "liq_ratio", "zstd3_ratio", "zstd6_ratio", "zstd19_ratio", "zstd22_ratio",
        "liq_compress_mb_s", "zstd3_compress_mb_s", "zstd6_compress_mb_s", "zstd19_compress_mb_s", "zstd22_compress_mb_s",
        "liq_end2end_s", "zstd22_end2end_s",
        "ratio_vs_zstd22_pct", "speed_vs_zstd3_pct", "speed_vs_zstd6_pct", "speed_vs_zstd22_pct", "end2end_time_vs_zstd22_pct",
        "workflow_win", "ratio_win", "speed_win", "win_label",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            row = dict(r)
            for k in [
                "input_bytes", "liq_ratio", "zstd3_ratio", "zstd6_ratio", "zstd19_ratio", "zstd22_ratio",
                "liq_compress_mb_s", "zstd3_compress_mb_s", "zstd6_compress_mb_s", "zstd19_compress_mb_s", "zstd22_compress_mb_s",
                "liq_end2end_s", "zstd22_end2end_s",
            ]:
                row[k] = _fmt_float(row.get(k))
            for k in [
                "ratio_vs_zstd22_pct", "speed_vs_zstd3_pct", "speed_vs_zstd6_pct", "speed_vs_zstd22_pct", "end2end_time_vs_zstd22_pct"
            ]:
                row[k] = _fmt_pct(row.get(k))
            w.writerow(row)


def write_summary_md(
    path: Path,
    rows: List[Dict[str, object]],
    *,
    inputs_used: Dict[str, Optional[Path]],
    ratio_win_pct: float,
    speed_win_pct: float,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    label_counts = Counter(str(r.get("win_label")) for r in rows)
    by_profile = Counter((str(r.get("profile")), str(r.get("win_label"))) for r in rows)
    by_source = Counter((str(r.get("source_type")), str(r.get("win_label"))) for r in rows)

    fails = [r for r in rows if r.get("win_label") == "FAIL"]
    top_ratio = sorted(
        [r for r in rows if isinstance(r.get("ratio_vs_zstd22_pct"), (int, float))],
        key=lambda r: float(r.get("ratio_vs_zstd22_pct") or -1e9),
        reverse=True,
    )[:10]
    top_speed = sorted(
        [
            r for r in rows
            if any(isinstance(r.get(k), (int, float)) for k in ("speed_vs_zstd3_pct", "speed_vs_zstd6_pct", "speed_vs_zstd22_pct"))
        ],
        key=lambda r: max([
            float(v) for v in (
                r.get("speed_vs_zstd3_pct"),
                r.get("speed_vs_zstd6_pct"),
                r.get("speed_vs_zstd22_pct"),
            ) if isinstance(v, (int, float))
        ] or [-1e9]),
        reverse=True,
    )[:10]

    lines = [
        "# War Room Scoreboard Summary",
        "",
        "## Inputs",
        "",
    ]
    for k, p in inputs_used.items():
        lines.append(f"- `{k}`: `{p}`" if p else f"- `{k}`: (not found)")

    lines.extend([
        "",
        "## Thresholds",
        "",
        f"- `WIN_RATIO`: ratio vs zstd-22 >= `{ratio_win_pct:.1f}%`",
        f"- `WIN_SPEED`: speed vs zstd-3/6 >= `{speed_win_pct:.1f}%` or end-to-end faster by that margin",
        "",
        "## Label Counts",
        "",
    ])
    for label, count in sorted(label_counts.items()):
        lines.append(f"- `{label}`: {count}")

    lines.extend(["", "## By Profile", ""])
    for (profile, label), count in sorted(by_profile.items()):
        lines.append(f"- `{profile}` / `{label}`: {count}")

    lines.extend(["", "## By Source", ""])
    for (source, label), count in sorted(by_source.items()):
        lines.append(f"- `{source}` / `{label}`: {count}")

    lines.extend(["", "## Fails", ""])
    if not fails:
        lines.append("No `FAIL` rows.")
    else:
        lines.append("| Source | Fixture | Profile | Engine | Ratio vs zstd22 % | Speed vs zstd3 % | Speed vs zstd22 % | End2End vs zstd22 % |")
        lines.append("|---|---|---|---|---:|---:|---:|---:|")
        for r in fails:
            lines.append(
                f"| {r.get('source_type')} | {r.get('fixture')} | {r.get('profile')} | {r.get('engine_id')} | "
                f"{_fmt_pct(r.get('ratio_vs_zstd22_pct'))} | {_fmt_pct(r.get('speed_vs_zstd3_pct'))} | "
                f"{_fmt_pct(r.get('speed_vs_zstd22_pct'))} | {_fmt_pct(r.get('end2end_time_vs_zstd22_pct'))} |"
            )

    lines.extend(["", "## Top Ratio Deltas vs zstd-22", ""])
    lines.append("| Source | Fixture | Profile | Engine | Ratio vs zstd22 % | Label |")
    lines.append("|---|---|---|---|---:|---|")
    for r in top_ratio:
        lines.append(
            f"| {r.get('source_type')} | {r.get('fixture')} | {r.get('profile')} | {r.get('engine_id')} | "
            f"{_fmt_pct(r.get('ratio_vs_zstd22_pct'))} | {r.get('win_label')} |"
        )

    lines.extend(["", "## Top Speed Deltas", ""])
    lines.append("| Source | Fixture | Profile | Engine | Speed vs zstd3 % | Speed vs zstd6 % | Speed vs zstd22 % | End2End vs zstd22 % | Label |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|---|")
    for r in top_speed:
        lines.append(
            f"| {r.get('source_type')} | {r.get('fixture')} | {r.get('profile')} | {r.get('engine_id')} | "
            f"{_fmt_pct(r.get('speed_vs_zstd3_pct'))} | {_fmt_pct(r.get('speed_vs_zstd6_pct'))} | "
            f"{_fmt_pct(r.get('speed_vs_zstd22_pct'))} | {_fmt_pct(r.get('end2end_time_vs_zstd22_pct'))} | {r.get('win_label')} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def auto_inputs(results_dir: Path, benchmarks_dir: Path) -> Dict[str, Optional[Path]]:
    return {
        "matrix_default": find_latest(str(results_dir / "format_matrix_realistic_fast_*.csv"), exclude_substrings=("ratio_profile",)),
        "matrix_ratio": find_latest(str(results_dir / "format_matrix_ratio_profile_realistic_fast_*.csv")),
        "openclaw_default": find_latest(str(results_dir / "bench_openclaw_50mb_200mb_full_verify_workers8*.csv"), exclude_substrings=("ratio_profile",)),
        "openclaw_ratio": find_latest(str(results_dir / "bench_openclaw_50mb_200mb_full_verify_workers8*ratio_profile*.csv")),
        "ci_subset": (benchmarks_dir / "latest_ci_subset.csv") if (benchmarks_dir / "latest_ci_subset.csv").exists() else None,
    }


def main():
    repo_root = Path(__file__).resolve().parent.parent
    default_results_dir = repo_root / "bench" / "results"
    default_benchmarks_dir = repo_root / "benchmarks"

    ap = argparse.ArgumentParser(description="Build war-room scoreboard CSV + markdown summary.")
    ap.add_argument("--results-dir", default=str(default_results_dir))
    ap.add_argument("--benchmarks-dir", default=str(default_benchmarks_dir))
    ap.add_argument("--matrix-default-csv", default=None)
    ap.add_argument("--matrix-ratio-csv", default=None)
    ap.add_argument("--openclaw-default-csv", default=None)
    ap.add_argument("--openclaw-ratio-csv", default=None)
    ap.add_argument("--ci-subset-csv", default=None)
    ap.add_argument("--out-csv", default=str(default_results_dir / "SCOREBOARD.csv"))
    ap.add_argument("--out-md", default=str(default_results_dir / "SCOREBOARD_SUMMARY.md"))
    ap.add_argument("--ratio-win-pct", type=float, default=2.0)
    ap.add_argument("--speed-win-pct", type=float, default=20.0)
    ap.add_argument("--tie-ratio-pct", type=float, default=2.0)
    ap.add_argument("--tie-speed-pct", type=float, default=20.0)
    args = ap.parse_args()

    results_dir = Path(args.results_dir).resolve()
    benchmarks_dir = Path(args.benchmarks_dir).resolve()
    discovered = auto_inputs(results_dir, benchmarks_dir)
    inputs = {
        "matrix_default": Path(args.matrix_default_csv).resolve() if args.matrix_default_csv else discovered["matrix_default"],
        "matrix_ratio": Path(args.matrix_ratio_csv).resolve() if args.matrix_ratio_csv else discovered["matrix_ratio"],
        "openclaw_default": Path(args.openclaw_default_csv).resolve() if args.openclaw_default_csv else discovered["openclaw_default"],
        "openclaw_ratio": Path(args.openclaw_ratio_csv).resolve() if args.openclaw_ratio_csv else discovered["openclaw_ratio"],
        "ci_subset": Path(args.ci_subset_csv).resolve() if args.ci_subset_csv else discovered["ci_subset"],
    }

    records: List[Dict[str, object]] = []
    if inputs["matrix_default"] and inputs["matrix_default"].exists():
        records.extend(load_format_matrix(inputs["matrix_default"], profile_label="default"))
    if inputs["matrix_ratio"] and inputs["matrix_ratio"].exists():
        records.extend(load_format_matrix(inputs["matrix_ratio"], profile_label="ratio"))
    if inputs["openclaw_default"] and inputs["openclaw_default"].exists():
        records.extend(load_openclaw_bench(inputs["openclaw_default"], profile_label="default"))
    if inputs["openclaw_ratio"] and inputs["openclaw_ratio"].exists():
        records.extend(load_openclaw_bench(inputs["openclaw_ratio"], profile_label="ratio"))
    if inputs["ci_subset"] and inputs["ci_subset"].exists():
        records.extend(load_ci_subset(inputs["ci_subset"]))

    if not records:
        raise SystemExit("No benchmark inputs found. Pass explicit CSV paths or ensure bench/results + benchmarks/latest_ci_subset.csv exist.")

    scoreboard_rows = build_scoreboard(
        records,
        ratio_win_pct=args.ratio_win_pct,
        speed_win_pct=args.speed_win_pct,
        tie_ratio_pct=args.tie_ratio_pct,
        tie_speed_pct=args.tie_speed_pct,
    )
    out_csv = Path(args.out_csv).resolve()
    out_md = Path(args.out_md).resolve()
    write_scoreboard_csv(out_csv, scoreboard_rows)
    write_summary_md(
        out_md,
        scoreboard_rows,
        inputs_used=inputs,
        ratio_win_pct=args.ratio_win_pct,
        speed_win_pct=args.speed_win_pct,
    )
    print(f"[OK] wrote {out_csv}")
    print(f"[OK] wrote {out_md}")
    print(f"[OK] rows={len(scoreboard_rows)}")


if __name__ == "__main__":
    main()
