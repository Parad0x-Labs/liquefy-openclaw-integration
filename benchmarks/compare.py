#!/usr/bin/env python3
"""Compare CI subset benchmark CSVs and fail on configured regressions."""
import argparse
import csv
from pathlib import Path


def load_rows(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    out = {}
    dups = []
    for i, row in enumerate(rows, start=2):
        key = (
            row.get("fixture", ""),
            row.get("method", ""),
            row.get("engine_id", ""),
            row.get("profile", ""),
            row.get("level", ""),
        )
        if key in out:
            dups.append((key, i))
        out[key] = row
    if dups:
        sample = "; ".join([f"{fmt_key(k)} @ line {ln}" for k, ln in dups[:5]])
        raise SystemExit(f"[FAIL] Duplicate benchmark rows detected in {path}: {len(dups)} (e.g., {sample})")
    return out


def pct_delta(new: float, old: float) -> float:
    if old == 0.0:
        if new == 0.0:
            return 0.0
        return float("inf")
    return ((new - old) / old) * 100.0


def fmt_key(key) -> str:
    fixture, method, engine_id, profile, level = key
    return f"{fixture}/method={method}/engine={engine_id}/profile={profile}/level={level}"


def parse_float(row, field: str, row_name: str) -> float:
    try:
        return float(row[field])
    except Exception:
        raise SystemExit(
            f"[FAIL] {row_name}: field '{field}' is missing or not a float (value={row.get(field)!r})"
        )


def main():
    ap = argparse.ArgumentParser(description="Compare benchmark subset CSV against baseline.")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--latest", required=True)
    ap.add_argument("--max-ratio-regression-pct", type=float, default=5.0)
    ap.add_argument("--max-speed-regression-pct", type=float, default=25.0)
    ap.add_argument("--max-default-ratio-regression-pct", type=float, default=None)
    ap.add_argument("--max-ratio-profile-ratio-regression-pct", type=float, default=None)
    ap.add_argument("--max-default-speed-regression-pct", type=float, default=None)
    ap.add_argument("--max-ratio-profile-speed-regression-pct", type=float, default=None)
    ap.add_argument("--max-speed-profile-speed-regression-pct", type=float, default=None)
    ap.add_argument(
        "--min-bytes-for-speed-check",
        type=int,
        default=0,
        help="Skip speed regression checks for rows with input_bytes below this threshold.",
    )
    ap.add_argument("--fail-on-extra", action="store_true")
    args = ap.parse_args()

    baseline = load_rows(Path(args.baseline))
    latest = load_rows(Path(args.latest))

    def_thr_ratio = args.max_ratio_regression_pct
    def_thr_speed = args.max_speed_regression_pct
    thr_default_ratio = (
        args.max_default_ratio_regression_pct
        if args.max_default_ratio_regression_pct is not None
        else def_thr_ratio
    )
    thr_ratio_ratio = (
        args.max_ratio_profile_ratio_regression_pct
        if args.max_ratio_profile_ratio_regression_pct is not None
        else def_thr_ratio
    )
    thr_default_speed = args.max_default_speed_regression_pct
    thr_ratio_speed = args.max_ratio_profile_speed_regression_pct
    thr_speed_speed = (
        args.max_speed_profile_speed_regression_pct
        if args.max_speed_profile_speed_regression_pct is not None
        else def_thr_speed
    )

    failures = []
    warnings = []

    missing = sorted(set(baseline.keys()) - set(latest.keys()))
    extra = sorted(set(latest.keys()) - set(baseline.keys()))
    def _sample_keys(keys):
        return ", ".join(fmt_key(k) for k in keys[:5])
    if missing:
        failures.append(
            f"Missing rows in latest CSV: {len(missing)} (e.g., {_sample_keys(missing)})"
        )
    if extra:
        msg = f"Extra rows in latest CSV: {len(extra)} (e.g., {_sample_keys(extra)})"
        if args.fail_on_extra:
            failures.append(msg)
        else:
            warnings.append(msg)

    for key in sorted(set(baseline.keys()) & set(latest.keys())):
        b = baseline[key]
        n = latest[key]
        row_name = fmt_key(key)

        if n.get("byteperfect") != "PASS":
            failures.append(f"{row_name}: byteperfect != PASS")
            continue

        b_ratio = parse_float(b, "ratio", row_name)
        n_ratio = parse_float(n, "ratio", row_name)
        b_comp = parse_float(b, "compress_mb_s", row_name)
        n_comp = parse_float(n, "compress_mb_s", row_name)
        row_input_bytes = None
        try:
            row_input_bytes = int(float(n.get("input_bytes", b.get("input_bytes", "0"))))
        except Exception:
            row_input_bytes = None

        def speed_checks_enabled() -> bool:
            if row_input_bytes is None:
                return True
            return row_input_bytes >= max(0, int(args.min_bytes_for_speed_check))

        if key[1] == "liquefy":
            profile = key[3]
            if profile == "default":
                d = pct_delta(n_ratio, b_ratio)
                if d < -abs(thr_default_ratio):
                    failures.append(
                        f"{row_name}: ratio regression {d:.2f}% (baseline {b_ratio:.4f}, latest {n_ratio:.4f})"
                    )
                if thr_default_speed is not None and speed_checks_enabled():
                    d = pct_delta(n_comp, b_comp)
                    if d < -abs(thr_default_speed):
                        failures.append(
                            f"{row_name}: default speed regression {d:.2f}% "
                            f"(baseline {b_comp:.4f}, latest {n_comp:.4f} MB/s)"
                        )
            elif profile == "ratio":
                d = pct_delta(n_ratio, b_ratio)
                if d < -abs(thr_ratio_ratio):
                    failures.append(
                        f"{row_name}: ratio regression {d:.2f}% (baseline {b_ratio:.4f}, latest {n_ratio:.4f})"
                    )
                if thr_ratio_speed is not None and speed_checks_enabled():
                    d = pct_delta(n_comp, b_comp)
                    if d < -abs(thr_ratio_speed):
                        failures.append(
                            f"{row_name}: ratio-profile speed regression {d:.2f}% "
                            f"(baseline {b_comp:.4f}, latest {n_comp:.4f} MB/s)"
                        )
            elif profile == "speed":
                if speed_checks_enabled():
                    d = pct_delta(n_comp, b_comp)
                    if d < -abs(thr_speed_speed):
                        failures.append(
                            f"{row_name}: speed regression {d:.2f}% (baseline {b_comp:.4f}, latest {n_comp:.4f} MB/s)"
                        )

    for w in warnings:
        print(f"[WARN] {w}")
    if failures:
        for f in failures:
            print(f"[FAIL] {f}")
        raise SystemExit(1)
    print("[OK] Benchmark subset compare passed")


if __name__ == "__main__":
    main()
