#!/usr/bin/env python3
"""
liquefy_intelligence.py
=======================
AI-powered intelligence layer for Liquefy.

Proactive smarts on top of the reactive compression/redaction pipeline:

    predict     — Predict bloat 24h/72h in advance per agent workspace
    summarize   — LLM-powered vault summary ("what actually mattered today")
    score       — Value-score traces (high/medium/low) for smart pruning
    prune       — Auto-prune low-value traces while keeping high-value ones
    suggest     — Suggest policy tweaks based on usage patterns
    migrate     — Import from raw zstd/tar/gzip backups into Liquefy vaults

Usage:
    python tools/liquefy_intelligence.py predict ~/.openclaw
    python tools/liquefy_intelligence.py summarize ./vault --api-key $OPENAI_API_KEY
    python tools/liquefy_intelligence.py score ./vault
    python tools/liquefy_intelligence.py prune ./vault --max-age 30 --min-score 0.3
    python tools/liquefy_intelligence.py suggest ~/.openclaw
    python tools/liquefy_intelligence.py migrate ./backup.tar.gz --out ./vault
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tarfile
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

CLI_SCHEMA_VERSION = "liquefy.intelligence.cli.v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt(n: int) -> str:
    if n >= 1 << 30: return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20: return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10: return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


def _load_vault_index(vault_dir: Path) -> Optional[Dict]:
    index_path = vault_dir / "tracevault_index.json"
    if not index_path.exists():
        index_path = vault_dir / "telemetry_index.json"
    if not index_path.exists():
        return None
    try:
        return json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_all_vaults(root: Path) -> List[Tuple[Path, Dict]]:
    vaults = []
    idx = _load_vault_index(root)
    if idx:
        vaults.append((root, idx))
    else:
        for sub in sorted(root.iterdir()) if root.is_dir() else []:
            if sub.is_dir():
                idx = _load_vault_index(sub)
                if idx:
                    vaults.append((sub, idx))
    return vaults


# ── Bloat Prediction ──


def cmd_predict(args: argparse.Namespace) -> int:
    """Predict workspace bloat based on growth rate analysis."""
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    daily_sizes: Dict[str, int] = defaultdict(int)
    now = time.time()

    for f in target.rglob("*"):
        if not f.is_file():
            continue
        try:
            mtime = f.stat().st_mtime
            age_days = (now - mtime) / 86400
            if age_days > 30:
                continue
            day_key = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
            daily_sizes[day_key] += f.stat().st_size
        except OSError:
            continue

    if len(daily_sizes) < 2:
        print("  Not enough data to predict (need >= 2 days of activity)")
        return 0

    sorted_days = sorted(daily_sizes.items())
    recent_7d = [v for k, v in sorted_days[-7:]]
    avg_daily_bytes = sum(recent_7d) / max(1, len(recent_7d))

    total_current = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())

    predict_24h = total_current + avg_daily_bytes
    predict_72h = total_current + avg_daily_bytes * 3
    predict_7d = total_current + avg_daily_bytes * 7

    days_to_1gb = max(0, (1 << 30) - total_current) / max(1, avg_daily_bytes) if avg_daily_bytes > 0 else float("inf")
    days_to_5gb = max(0, (5 << 30) - total_current) / max(1, avg_daily_bytes) if avg_daily_bytes > 0 else float("inf")

    if args.json:
        print(json.dumps({
            "schema_version": CLI_SCHEMA_VERSION,
            "command": "predict",
            "ok": True,
            "result": {
                "current_bytes": total_current,
                "avg_daily_bytes": int(avg_daily_bytes),
                "predict_24h": int(predict_24h),
                "predict_72h": int(predict_72h),
                "predict_7d": int(predict_7d),
                "days_to_1gb": round(days_to_1gb, 1) if days_to_1gb < 9999 else None,
                "days_to_5gb": round(days_to_5gb, 1) if days_to_5gb < 9999 else None,
                "data_points": len(daily_sizes),
                "recommendation": _predict_recommendation(total_current, avg_daily_bytes),
            }
        }, indent=2))
    else:
        print(f"\n  Bloat Prediction: {target.name}")
        print(f"  Current size: {_fmt(total_current)}")
        print(f"  Daily growth: ~{_fmt(int(avg_daily_bytes))}/day (last {len(recent_7d)} days)")
        print()
        print(f"  In 24h:  {_fmt(int(predict_24h))}")
        print(f"  In 72h:  {_fmt(int(predict_72h))}")
        print(f"  In 7d:   {_fmt(int(predict_7d))}")
        if days_to_1gb < 365:
            print(f"  Hits 1 GB in: ~{days_to_1gb:.0f} days")
        if days_to_5gb < 365:
            print(f"  Hits 5 GB in: ~{days_to_5gb:.0f} days")
        print()
        rec = _predict_recommendation(total_current, avg_daily_bytes)
        print(f"  Recommendation: {rec}")
        print()

    return 0


def _predict_recommendation(current: int, daily: int) -> str:
    if daily > 500 * 1024 * 1024:
        return "CRITICAL — >500 MB/day. Enable archiver daemon immediately: make daemon"
    if daily > 100 * 1024 * 1024:
        return "HIGH — >100 MB/day. Schedule daily archival: make archiver"
    if daily > 10 * 1024 * 1024:
        return "MODERATE — >10 MB/day. Weekly archival recommended: make archiver"
    if current > 1 << 30:
        return "CLEANUP — Current size >1 GB. Run: make quick DIR=<path> PRESET=power"
    return "LOW — Growth rate is manageable. Monitor with: make predict"


# ── Value Scoring ──


VALUE_SIGNALS = {
    "error": 0.8,
    "exception": 0.8,
    "traceback": 0.7,
    "failed": 0.6,
    "warning": 0.4,
    "critical": 0.9,
    "success": 0.2,
    "debug": 0.1,
    "tool_call": 0.5,
    "function_call": 0.5,
    "user_message": 0.6,
    "assistant_message": 0.3,
    "memory_update": 0.7,
    "skill_install": 0.8,
    "decision": 0.7,
    "plan": 0.5,
}


def _score_file(path: Path) -> Tuple[float, Dict[str, int]]:
    """Score a file's value based on content signals. Returns (score, signal_counts)."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:100_000]
    except OSError:
        return 0.0, {}

    signals: Dict[str, int] = {}
    content_lower = content.lower()

    for signal, weight in VALUE_SIGNALS.items():
        count = content_lower.count(signal)
        if count > 0:
            signals[signal] = count

    if not signals:
        return 0.1, {}

    weighted_sum = sum(VALUE_SIGNALS[s] * min(count, 10) for s, count in signals.items())
    max_possible = sum(w * 10 for w in VALUE_SIGNALS.values())
    score = min(1.0, weighted_sum / max(1, max_possible) * 5)

    name = path.name.lower()
    if "memory" in name or "decision" in name:
        score = min(1.0, score + 0.3)
    if "debug" in name or "verbose" in name:
        score = max(0.0, score - 0.2)

    return round(score, 3), signals


def cmd_score(args: argparse.Namespace) -> int:
    """Value-score all files in a vault or directory."""
    target = Path(args.target).expanduser().resolve()
    vaults = _load_all_vaults(target)

    results: List[Dict] = []

    if vaults:
        for vault_path, index in vaults:
            for r in index.get("receipts", []):
                rpath = r.get("run_relpath", "?")
                raw = r.get("original_bytes", 0)
                results.append({
                    "file": rpath,
                    "raw_bytes": raw,
                    "score": 0.5,
                    "vault": vault_path.name,
                    "signals": {},
                })
    else:
        for f in sorted(target.rglob("*")):
            if not f.is_file():
                continue
            score, signals = _score_file(f)
            results.append({
                "file": str(f.relative_to(target)),
                "raw_bytes": f.stat().st_size,
                "score": score,
                "signals": signals,
            })

    results.sort(key=lambda r: r["score"], reverse=True)

    if args.json:
        print(json.dumps({"ok": True, "result": {"files": results[:100]}}, indent=2))
    else:
        print(f"\n  Value Scores: {target.name}")
        print(f"  {'File':<45} {'Size':>8} {'Score':>6} {'Top Signal'}")
        print(f"  {'─' * 45} {'─' * 8} {'─' * 6} {'─' * 20}")
        for r in results[:30]:
            name = r["file"]
            if len(name) > 43: name = name[:40] + "..."
            top_signal = max(r.get("signals", {"none": 0}), key=r.get("signals", {"none": 0}).get, default="—")
            color = "\033[92m" if r["score"] >= 0.6 else ("\033[93m" if r["score"] >= 0.3 else "\033[91m")
            print(f"  {name:<45} {_fmt(r['raw_bytes']):>8} {color}{r['score']:>5.2f}\033[0m  {top_signal}")
        print()

    return 0


# ── Smart Prune ──


def cmd_prune(args: argparse.Namespace) -> int:
    """Auto-prune low-value traces based on age and value score."""
    target = Path(args.target).expanduser().resolve()
    max_age_days = args.max_age
    min_score = args.min_score

    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    now = time.time()
    candidates: List[Dict] = []
    keep: List[Dict] = []

    for f in sorted(target.rglob("*")):
        if not f.is_file():
            continue
        try:
            age_days = (now - f.stat().st_mtime) / 86400
        except OSError:
            continue

        score, signals = _score_file(f)
        entry = {"path": f, "age_days": round(age_days, 1), "score": score, "size": f.stat().st_size}

        if age_days >= max_age_days and score < min_score:
            candidates.append(entry)
        else:
            keep.append(entry)

    total_prune_bytes = sum(c["size"] for c in candidates)

    if args.dry_run or not candidates:
        print(f"\n  Smart Prune: {target.name}")
        print(f"  Candidates for pruning: {len(candidates)} ({_fmt(total_prune_bytes)})")
        print(f"  Files to keep: {len(keep)}")
        if candidates:
            print(f"\n  Would prune:")
            for c in candidates[:10]:
                print(f"    {c['path'].name:40s} age={c['age_days']:.0f}d  score={c['score']:.2f}  {_fmt(c['size'])}")
            if len(candidates) > 10:
                print(f"    ... and {len(candidates) - 10} more")
        print()
        return 0

    pruned = 0
    for c in candidates:
        try:
            c["path"].unlink()
            pruned += 1
        except OSError:
            pass

    print(f"  Pruned {pruned}/{len(candidates)} files ({_fmt(total_prune_bytes)})")
    return 0


# ── LLM Summarize ──


def cmd_summarize(args: argparse.Namespace) -> int:
    """LLM-powered vault summary — 'what actually mattered today'."""
    target = Path(args.target).expanduser().resolve()
    vaults = _load_all_vaults(target)

    context_parts: List[str] = []
    for vault_path, index in vaults:
        meta = index.get("metadata", {})
        receipts = index.get("receipts", [])
        raw = sum(r.get("original_bytes", 0) for r in receipts)
        comp = sum(r.get("compressed_bytes", 0) for r in receipts)
        ratio = raw / max(1, comp)

        context_parts.append(
            f"Vault '{vault_path.name}': {len(receipts)} files, "
            f"{_fmt(raw)} raw → {_fmt(comp)} ({ratio:.1f}x), "
            f"packed at {meta.get('packed_at', '?')}, "
            f"engines: {set(r.get('engine_id', '?') for r in receipts)}"
        )

        denied = meta.get("denied_files", [])
        if denied:
            context_parts.append(f"  Blocked {len(denied)} risky files")

    context = "\n".join(context_parts)

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY", "")

    if api_key:
        summary = _llm_summarize(context, api_key, args.model)
    else:
        summary = _local_summarize(context, vaults)

    if args.json:
        print(json.dumps({"ok": True, "result": {"summary": summary, "source": "llm" if api_key else "local"}}, indent=2))
    else:
        print(f"\n  Daily Summary")
        print(f"  {'═' * 60}")
        print(f"  {summary}")
        print()

    return 0


def _llm_summarize(context: str, api_key: str, model: str = "gpt-4o-mini") -> str:
    """Call OpenAI API for intelligent summarization."""
    import urllib.request
    prompt = (
        "You are an AI agent assistant analyzing compressed vault data. "
        "Summarize what actually mattered today in 3-5 bullet points. "
        "Focus on: key decisions made, errors encountered, data volume patterns, "
        "and security events (leaks blocked). Be concise and actionable.\n\n"
        f"Vault data:\n{context[:4000]}"
    )

    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500,
        "temperature": 0.3,
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except Exception as exc:
        return f"LLM summarization failed ({exc}). Falling back to local analysis."


def _local_summarize(context: str, vaults: List[Tuple[Path, Dict]]) -> str:
    """Local heuristic summarization when no LLM API key is available."""
    total_raw = 0
    total_comp = 0
    total_files = 0
    total_denied = 0
    engines: Dict[str, int] = {}

    for _, index in vaults:
        for r in index.get("receipts", []):
            total_raw += r.get("original_bytes", 0)
            total_comp += r.get("compressed_bytes", 0)
            total_files += 1
            eid = r.get("engine_id", "?")
            engines[eid] = engines.get(eid, 0) + 1
        total_denied += len(index.get("metadata", {}).get("denied_files", []))

    ratio = total_raw / max(1, total_comp)
    top_engine = max(engines, key=engines.get) if engines else "none"

    lines = [
        f"Processed {total_files} files across {len(vaults)} vaults.",
        f"Total: {_fmt(total_raw)} raw → {_fmt(total_comp)} compressed ({ratio:.1f}x).",
        f"Top engine: {top_engine} ({engines.get(top_engine, 0)} files).",
    ]
    if total_denied:
        lines.append(f"Blocked {total_denied} risky files (credentials/keys).")
    lines.append("Set OPENAI_API_KEY for AI-powered summaries with actionable insights.")
    return "\n  ".join(lines)


# ── Policy Suggestions ──


def cmd_suggest(args: argparse.Namespace) -> int:
    """Suggest policy tweaks based on usage patterns."""
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    suggestions: List[Dict[str, str]] = []

    total_size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    file_count = sum(1 for f in target.rglob("*") if f.is_file())
    ext_counts: Dict[str, int] = defaultdict(int)
    ext_sizes: Dict[str, int] = defaultdict(int)

    for f in target.rglob("*"):
        if f.is_file():
            ext = f.suffix.lower() or ".noext"
            ext_counts[ext] += 1
            try:
                ext_sizes[ext] += f.stat().st_size
            except OSError:
                pass

    if total_size > 2 << 30:
        suggestions.append({
            "priority": "high",
            "suggestion": "Enable archiver daemon — workspace is >2 GB",
            "command": "make daemon",
        })

    jsonl_pct = ext_sizes.get(".jsonl", 0) / max(1, total_size)
    if jsonl_pct > 0.7:
        suggestions.append({
            "priority": "medium",
            "suggestion": "JSONL-heavy workspace — switch to 'ratio' profile for better compression",
            "command": "LIQUEFY_PROFILE=ratio",
        })

    if ext_counts.get(".log", 0) > 50:
        suggestions.append({
            "priority": "medium",
            "suggestion": "Many log files detected — enable age-based archival (7 days)",
            "command": "make archiver --age-days 7",
        })

    large_files = [f for f in target.rglob("*") if f.is_file() and f.stat().st_size > 100 * 1024 * 1024]
    if large_files:
        suggestions.append({
            "priority": "high",
            "suggestion": f"{len(large_files)} files >100 MB — enable size-based archival",
            "command": "make archiver --size-mb 100",
        })

    from path_policy import classify_risky_path
    risky_count = 0
    for f in target.rglob("*"):
        if f.is_file():
            result = classify_risky_path(f, target)
            if result:
                risky_count += 1
    if risky_count > 0:
        suggestions.append({
            "priority": "critical",
            "suggestion": f"{risky_count} risky files found — run leak scan immediately",
            "command": "make leak-scan DIR=" + str(target),
        })

    if not suggestions:
        suggestions.append({
            "priority": "info",
            "suggestion": "Workspace looks healthy. No changes recommended.",
            "command": "",
        })

    if args.json:
        print(json.dumps({"ok": True, "result": {"suggestions": suggestions}}, indent=2))
    else:
        print(f"\n  Policy Suggestions for: {target.name}")
        print(f"  Size: {_fmt(total_size)} | Files: {file_count}")
        print()
        for s in suggestions:
            icon = {"critical": "!!!", "high": "!!", "medium": "!", "info": "."}.get(s["priority"], " ")
            print(f"  [{icon}] {s['suggestion']}")
            if s["command"]:
                print(f"       {s['command']}")
        print()

    return 0


# ── Migration from raw zstd/tar/gzip ──


def cmd_migrate(args: argparse.Namespace) -> int:
    """Import from raw zstd/tar/gzip backups into Liquefy vaults."""
    source = Path(args.source).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()

    if not source.exists():
        print(f"Source not found: {source}", file=sys.stderr)
        return 1

    import tempfile
    with tempfile.TemporaryDirectory(prefix="liquefy_migrate_") as tmp:
        tmp_path = Path(tmp)
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        suffix = source.suffix.lower()
        name = source.name.lower()

        if suffix in (".tar", ".tgz") or name.endswith(".tar.gz") or name.endswith(".tar.zst"):
            print(f"  Extracting {source.name}...")
            try:
                if name.endswith(".tar.zst") or name.endswith(".zst"):
                    import zstandard as zstd
                    dctx = zstd.ZstdDecompressor()
                    with source.open("rb") as fin:
                        with tarfile.open(fileobj=dctx.stream_reader(fin)) as tar:
                            tar.extractall(extract_dir, filter="data")
                else:
                    with tarfile.open(source) as tar:
                        tar.extractall(extract_dir, filter="data")
            except Exception as exc:
                print(f"  Extract failed: {exc}", file=sys.stderr)
                return 1

        elif suffix in (".zst",):
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            out_file = extract_dir / source.stem
            with source.open("rb") as fin:
                out_file.write_bytes(dctx.decompress(fin.read()))

        elif suffix in (".gz", ".gzip"):
            import gzip
            out_file = extract_dir / source.stem
            with gzip.open(source, "rb") as fin:
                out_file.write_bytes(fin.read())

        else:
            shutil.copytree(source, extract_dir / source.name) if source.is_dir() else shutil.copy2(source, extract_dir)

        file_count = sum(1 for f in extract_dir.rglob("*") if f.is_file())
        total_size = sum(f.stat().st_size for f in extract_dir.rglob("*") if f.is_file())
        print(f"  Extracted {file_count} files ({_fmt(total_size)})")

        print(f"  Packing into Liquefy vault...")
        pack_cmd = [
            sys.executable, str(REPO_ROOT / "tools" / "tracevault_pack.py"),
            str(extract_dir),
            "--out", str(out),
            "--org", "migrated",
            "--profile", args.profile,
            "--verify-mode", "full",
            "--json",
        ]

        result = subprocess.run(
            pack_cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": f"{TOOLS_DIR}:{API_DIR}"},
        )

        try:
            pack_data = json.loads(result.stdout)
            comp = pack_data.get("result", {}).get("total_compressed_bytes", 0)
            ratio = total_size / max(1, comp)
            print(f"  Migration complete: {_fmt(total_size)} -> {_fmt(comp)} ({ratio:.1f}x)")
            print(f"  Vault: {out}")
        except Exception:
            print(f"  Pack output: {result.stdout[:300]}")
            if result.returncode != 0:
                print(f"  Errors: {result.stderr[:300]}", file=sys.stderr)

    return 0


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-intelligence", description="Liquefy AI Intelligence Layer")
    sub = ap.add_subparsers(dest="command")

    p = sub.add_parser("predict", help="Predict workspace bloat")
    p.add_argument("target", help="Directory to analyze")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("summarize", help="LLM-powered vault summary")
    p.add_argument("target", help="Vault root")
    p.add_argument("--api-key", default=None, help="OpenAI API key (or set OPENAI_API_KEY)")
    p.add_argument("--model", default="gpt-4o-mini", help="LLM model to use")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("score", help="Value-score traces")
    p.add_argument("target", help="Vault or directory")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("prune", help="Smart-prune low-value traces")
    p.add_argument("target", help="Directory to prune")
    p.add_argument("--max-age", type=int, default=30, help="Max age in days")
    p.add_argument("--min-score", type=float, default=0.3, help="Min value score to keep")
    p.add_argument("--dry-run", action="store_true", help="Preview without deleting")

    p = sub.add_parser("suggest", help="Suggest policy tweaks")
    p.add_argument("target", help="Workspace to analyze")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("migrate", help="Import from tar/zstd/gzip backups")
    p.add_argument("source", help="Source archive or directory")
    p.add_argument("--out", required=True, help="Output vault directory")
    p.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    handlers = {
        "predict": cmd_predict,
        "summarize": cmd_summarize,
        "score": cmd_score,
        "prune": cmd_prune,
        "suggest": cmd_suggest,
        "migrate": cmd_migrate,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
