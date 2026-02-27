#!/usr/bin/env python3
"""
liquefy_denoise.py
==================
Semantic log de-noising for LLM context window optimization.

Strips routine noise (heartbeats, health checks, status 200s, keep-alives)
from log data BEFORE it enters an LLM context window, keeping only the
lines that matter: errors, warnings, state changes, anomalies.

Reduces context window token cost by 60-95% on typical agent/server logs.

Commands:
    filter    <path>     Filter noise, output only signal lines
    stats     <path>     Estimate noise ratio without filtering
    extract   <path>     Extract error/warning clusters around trace IDs
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
CLI_SCHEMA = "liquefy.denoise.v1"

# ── Noise patterns: lines matching these are routine and can be dropped ──

NOISE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("http_200", re.compile(r'(?i)\b(?:status[_\s:=]*200|HTTP/\d\.\d"\s*200|200\s+OK)\b')),
    ("http_204", re.compile(r'(?i)\b(?:status[_\s:=]*204|HTTP/\d\.\d"\s*204|204\s+No Content)\b')),
    ("http_304", re.compile(r'(?i)\b(?:status[_\s:=]*304|HTTP/\d\.\d"\s*304|304\s+Not Modified)\b')),
    ("heartbeat", re.compile(r'(?i)\b(?:heartbeat|health[_\s]?check|keep[_\-]?alive|ping|pong|alive)\b')),
    ("health_endpoint", re.compile(r'(?:GET|POST|HEAD)\s+/(?:health|healthz|ready|readyz|livez|status|ping)\b')),
    ("routine_poll", re.compile(r'(?i)\b(?:polling|poll[_\s]?interval|scheduled[_\s]?check|cron[_\s]?tick)\b')),
    ("metrics_scrape", re.compile(r'(?:GET|POST)\s+/(?:metrics|prometheus|_metrics)\b')),
    ("debug_trace", re.compile(r'(?i)^(?:TRACE|DEBUG)\s')),
    ("empty_result", re.compile(r'(?i)\b(?:no[_\s]?results?|0 results?|empty[_\s]?response|nothing[_\s]?found)\b')),
    ("connection_ok", re.compile(r'(?i)\b(?:connection[_\s]?(?:established|ok|accepted|opened)|connected\s+to)\b')),
    ("session_refresh", re.compile(r'(?i)\b(?:session[_\s]?refresh|token[_\s]?refresh(?:ed)?|renew(?:ed|ing)?[_\s]?(?:session|token))\b')),
    ("cache_hit", re.compile(r'(?i)\b(?:cache[_\s]?hit|served[_\s]?from[_\s]?cache|cached[_\s]?response)\b')),
    ("static_asset", re.compile(r'(?i)\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)\b')),
]

# ── Signal patterns: lines matching these are ALWAYS kept ──

SIGNAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("error", re.compile(r'(?i)\b(?:error|err|fatal|panic|exception|traceback|failed|failure)\b')),
    ("warning", re.compile(r'(?i)\b(?:warn(?:ing)?|deprecated|timeout|timed[_\s]?out|retry|retrying)\b')),
    ("http_4xx", re.compile(r'(?i)\b(?:status[_\s:=]*4\d{2}|HTTP/\d\.\d"\s*4\d{2}|4\d{2}\s+(?:Bad|Unauthorized|Forbidden|Not Found))\b')),
    ("http_5xx", re.compile(r'(?i)\b(?:status[_\s:=]*5\d{2}|HTTP/\d\.\d"\s*5\d{2}|5\d{2}\s+(?:Internal|Bad Gateway|Service))\b')),
    ("crash", re.compile(r'(?i)\b(?:crash(?:ed)?|segfault|SIGSEGV|SIGKILL|SIGABRT|OOM|out[_\s]?of[_\s]?memory)\b')),
    ("security", re.compile(r'(?i)\b(?:unauthorized|forbidden|denied|blocked|rejected|invalid[_\s]?(?:token|key|auth)|breach)\b')),
    ("state_change", re.compile(r'(?i)\b(?:started|stopped|restarted|deployed|migrated|rollback|scaled|terminated|shutdown)\b')),
    ("money", re.compile(r'(?i)\b(?:payment|charge|refund|invoice|billing|transfer(?:red)?|withdraw|deposit|balance)\b')),
    ("data_loss", re.compile(r'(?i)\b(?:corrupt(?:ed|ion)?|data[_\s]?loss|truncat(?:ed|ion)|missing[_\s]?(?:data|file|record))\b')),
]

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache"}
MAX_FILE_BYTES = 100 * 1024 * 1024
LOG_EXTENSIONS = {".log", ".txt", ".jsonl", ".ndjson", ".csv", ".tsv", ".json"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    payload = {
        "schema_version": CLI_SCHEMA,
        "tool": "liquefy_denoise",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    print(json.dumps(payload, indent=2))


def _is_log_file(path: Path) -> bool:
    if path.suffix.lower() in LOG_EXTENSIONS:
        return True
    name_lower = path.name.lower()
    return any(kw in name_lower for kw in ("log", "trace", "event", "audit", "access"))


def _collect_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size <= MAX_FILE_BYTES and _is_log_file(fpath):
                    files.append(fpath)
            except OSError:
                continue
    return sorted(files)


def _classify_line(line: str) -> Tuple[str, Optional[str]]:
    """Returns ('signal'|'noise'|'neutral', matched_pattern_name)."""
    for name, pattern in SIGNAL_PATTERNS:
        if pattern.search(line):
            return "signal", name
    for name, pattern in NOISE_PATTERNS:
        if pattern.search(line):
            return "noise", name
    return "neutral", None


def _filter_lines(
    lines: List[str],
    context: int = 2,
    keep_neutral: bool = False,
) -> Tuple[List[str], Dict[str, int], Dict[str, int]]:
    """Filter noise, keep signal + context lines around signals."""
    n = len(lines)
    classifications = [_classify_line(line) for line in lines]

    keep_mask = [False] * n
    signal_counts: Dict[str, int] = {}
    noise_counts: Dict[str, int] = {}

    for i, (cls, name) in enumerate(classifications):
        if cls == "signal":
            signal_counts[name] = signal_counts.get(name, 0) + 1
            for j in range(max(0, i - context), min(n, i + context + 1)):
                keep_mask[j] = True
        elif cls == "noise":
            noise_counts[name] = noise_counts.get(name, 0) + 1
        elif cls == "neutral" and keep_neutral:
            keep_mask[i] = True

    kept = []
    prev_kept = True
    for i, line in enumerate(lines):
        if keep_mask[i]:
            if not prev_kept:
                kept.append(f"... [{i - last_skip_start} lines filtered] ...")
            kept.append(line)
            prev_kept = True
        else:
            if prev_kept:
                last_skip_start = i
            prev_kept = False

    if not prev_kept and lines:
        kept.append(f"... [{n - last_skip_start} lines filtered] ...")

    return kept, signal_counts, noise_counts


def cmd_filter(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("filter", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).expanduser().resolve() if args.out else None
    context = max(0, args.context)
    files = _collect_files(target)

    file_results = []
    total_input_lines = 0
    total_output_lines = 0

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.split("\n")
        total_input_lines += len(lines)

        kept, signal_counts, noise_counts = _filter_lines(
            lines, context=context, keep_neutral=args.keep_neutral,
        )
        total_output_lines += len(kept)
        reduction = round((1 - len(kept) / max(len(lines), 1)) * 100, 1)

        rel = str(fpath.relative_to(target)) if target.is_dir() else fpath.name

        if out_dir:
            if target.is_dir():
                dest = out_dir / fpath.relative_to(target)
            else:
                dest = out_dir / fpath.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("\n".join(kept), encoding="utf-8")
        elif not args.json:
            for line in kept:
                print(line)

        file_results.append({
            "file": rel,
            "input_lines": len(lines),
            "output_lines": len(kept),
            "reduction_pct": reduction,
            "signal_types": dict(sorted(signal_counts.items(), key=lambda x: -x[1])),
            "noise_types": dict(sorted(noise_counts.items(), key=lambda x: -x[1])),
        })

    overall_reduction = round((1 - total_output_lines / max(total_input_lines, 1)) * 100, 1)

    result = {
        "target": str(target),
        "out_dir": str(out_dir) if out_dir else "(stdout)",
        "files_processed": len(files),
        "total_input_lines": total_input_lines,
        "total_output_lines": total_output_lines,
        "overall_reduction_pct": overall_reduction,
        "context_lines": context,
        "files": file_results,
    }

    if args.json:
        _emit("filter", True, result)
    elif out_dir:
        print(f"Filtered {len(files)} files: {total_input_lines} -> {total_output_lines} lines ({overall_reduction}% reduction)")

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("stats", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    files = _collect_files(target)
    total_lines = 0
    total_signal = 0
    total_noise = 0
    total_neutral = 0
    type_counts: Dict[str, int] = {}

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in content.split("\n"):
            total_lines += 1
            cls, name = _classify_line(line)
            if cls == "signal":
                total_signal += 1
                if name:
                    type_counts[name] = type_counts.get(name, 0) + 1
            elif cls == "noise":
                total_noise += 1
                if name:
                    type_counts[name] = type_counts.get(name, 0) + 1
            else:
                total_neutral += 1

    noise_pct = round(total_noise / max(total_lines, 1) * 100, 1)
    signal_pct = round(total_signal / max(total_lines, 1) * 100, 1)

    result = {
        "target": str(target),
        "files_scanned": len(files),
        "total_lines": total_lines,
        "signal_lines": total_signal,
        "noise_lines": total_noise,
        "neutral_lines": total_neutral,
        "noise_pct": noise_pct,
        "signal_pct": signal_pct,
        "estimated_reduction_pct": noise_pct,
        "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
    }

    if args.json:
        _emit("stats", True, result)
    else:
        print(f"De-noise stats: {len(files)} files, {total_lines:,} lines")
        print(f"  Signal: {total_signal:,} ({signal_pct}%)")
        print(f"  Noise:  {total_noise:,} ({noise_pct}%)")
        print(f"  Neutral: {total_neutral:,}")
        print(f"  Estimated context reduction: ~{noise_pct}%")

    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("extract", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    trace_id = args.trace_id
    context = max(0, args.context)
    files = _collect_files(target)

    clusters: List[Dict[str, Any]] = []
    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = content.split("\n")
        rel = str(fpath.relative_to(target)) if target.is_dir() else fpath.name

        for i, line in enumerate(lines):
            if trace_id not in line:
                continue
            cls, name = _classify_line(line)
            if cls != "signal":
                continue
            start = max(0, i - context)
            end = min(len(lines), i + context + 1)
            clusters.append({
                "file": rel,
                "line": i + 1,
                "signal_type": name,
                "context": lines[start:end],
            })

    result = {
        "target": str(target),
        "trace_id": trace_id,
        "files_scanned": len(files),
        "clusters_found": len(clusters),
        "clusters": clusters[:100],
    }

    if args.json:
        _emit("extract", True, result)
    else:
        print(f"Extract: {len(clusters)} error/warning clusters for trace_id={trace_id}")
        for c in clusters[:20]:
            print(f"\n  {c['file']}:{c['line']} [{c['signal_type']}]")
            for ctx_line in c["context"]:
                print(f"    {ctx_line}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-denoise",
        description="Semantic log de-noising for LLM context window optimization",
    )
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_filter = sub.add_parser("filter", help="Filter noise, output only signal + context")
    p_filter.add_argument("path", help="Log file or directory")
    p_filter.add_argument("--out", help="Output directory (omit for stdout)")
    p_filter.add_argument("--context", type=int, default=3, help="Context lines around signals")
    p_filter.add_argument("--keep-neutral", action="store_true", help="Keep lines that are neither signal nor noise")
    p_filter.add_argument("--json", action="store_true")
    p_filter.set_defaults(fn=cmd_filter)

    p_stats = sub.add_parser("stats", help="Estimate noise ratio without filtering")
    p_stats.add_argument("path")
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(fn=cmd_stats)

    p_extract = sub.add_parser("extract", help="Extract error clusters around a trace ID")
    p_extract.add_argument("path")
    p_extract.add_argument("--trace-id", required=True, help="Trace/correlation ID to search for")
    p_extract.add_argument("--context", type=int, default=5, help="Context lines around matches")
    p_extract.add_argument("--json", action="store_true")
    p_extract.set_defaults(fn=cmd_extract)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
