#!/usr/bin/env python3
"""
liquefy_context_capsule.py
==========================
Build a compact, deterministic context capsule from raw agent traces.

This is the bridge between Liquefy vaulting and token discipline:
- scans raw traces/logs
- keeps the hot-path facts that actually matter
- pushes cold/repetitive artifacts out of the prompt surface
- emits measurable reduction numbers

Commands:
    build   --dir <trace_dir> [--out <file-or-dir>] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

from liquefy_denoise import _collect_files as _collect_log_files, _filter_lines
from liquefy_token_ledger import _estimate_cost, _scan_directory as _scan_token_entries, _summarize_truth

CLI_SCHEMA = "liquefy.context-capsule.v1"
TEXT_SCAN_EXTENSIONS = {".log", ".txt", ".md", ".csv", ".tsv"}
JSON_SCAN_EXTENSIONS = {".jsonl", ".ndjson", ".json"}
MAX_RELEVANT_ITEMS = 24
MAX_COLD_ITEMS = 64
MAX_TEXT_SNIPPET = 220
MAX_JSON_SNIPPET = 320
WORKSPACE_CONTEXT_DIR = Path(".liquefy") / "context" / "current"
WORKSPACE_CONTEXT_HISTORY_DIR = Path(".liquefy") / "context" / "history"
BOOTSTRAP_FILENAME = "context_bootstrap.md"
MANIFEST_FILENAME = "context_manifest.json"
SCOREBOARD_FILENAME = "context_scoreboard.json"
TRACE_FINGERPRINT_MODE = "metadata_tree_v1"
SKIP_SCAN_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".liquefy",
    ".liquefy-tokens",
    ".liquefy-safe-run",
}
HIGH_PRIORITY_PATTERN = re.compile(
    r"(?i)\b(error|fatal|panic|exception|traceback|failed|failure|denied|blocked|unauthorized|security)\b"
)
MID_PRIORITY_PATTERN = re.compile(r"(?i)\b(warn|retry|timeout|tool|model|prompt|context|budget|token)\b")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    payload = {
        "schema_version": CLI_SCHEMA,
        "tool": "liquefy_context_capsule",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    print(json.dumps(payload, indent=2))


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except Exception:
        return repr(value)


def _trim(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _stringify_payload(value: Any, limit: int = MAX_JSON_SNIPPET) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return _trim(value, limit)
    return _trim(_safe_json(value), limit)


def _parse_json_file(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        if path.suffix.lower() == ".json":
            raw = json.loads(path.read_text("utf-8", errors="replace"))
            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                if isinstance(item, dict):
                    records.append(item)
            return records

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    records.append(item)
    except (OSError, json.JSONDecodeError):
        pass
    return records


def _guess_timestamp(record: Dict[str, Any]) -> Optional[str]:
    for key in ("timestamp", "ts", "eventTime", "time", "created_at", "createdAt"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _guess_event_name(record: Dict[str, Any]) -> str:
    for key in ("event", "eventName", "type", "kind", "action", "name"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    if record.get("tool"):
        return f"tool:{record['tool']}"
    if record.get("model"):
        return f"model:{record['model']}"
    return "record"


def _guess_severity(summary: str) -> Tuple[int, str]:
    if HIGH_PRIORITY_PATTERN.search(summary):
        return 90, "high"
    if MID_PRIORITY_PATTERN.search(summary):
        return 60, "medium"
    return 30, "low"


def _build_record_summary(record: Dict[str, Any], source: Path) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    event_name = _guess_event_name(record)
    model = record.get("model") or record.get("model_name")
    tool = record.get("tool") or record.get("tool_name")
    prompt = record.get("prompt")
    if prompt is None and record.get("messages"):
        prompt = record.get("messages")
    if prompt is None and record.get("input"):
        prompt = record.get("input")
    output = record.get("output") or record.get("result") or record.get("response")

    parts = [event_name]
    if model:
        parts.append(f"model={model}")
    if tool:
        parts.append(f"tool={tool}")

    prompt_text = _stringify_payload(prompt, 180)
    output_text = _stringify_payload(output, 140)
    if prompt_text:
        parts.append(f"input={prompt_text}")
    if output_text and output_text != "{}":
        parts.append(f"output={output_text}")

    if record.get("duration_ms") is not None:
        parts.append(f"duration_ms={record['duration_ms']}")
    if record.get("status") is not None:
        parts.append(f"status={record['status']}")

    summary = _trim(" | ".join(parts), MAX_JSON_SNIPPET)
    return summary, str(model).lower() if model else None, str(tool) if tool else None, prompt_text or None


def _collect_record_moments(target_dir: Path) -> Tuple[List[Dict[str, Any]], Counter, Counter, int, int]:
    moments: List[Dict[str, Any]] = []
    model_counts: Counter = Counter()
    tool_counts: Counter = Counter()
    files_scanned = 0
    records_seen = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
        for fname in sorted(files):
            path = Path(root) / fname
            if path.suffix.lower() not in JSON_SCAN_EXTENSIONS:
                continue
            files_scanned += 1
            for record in _parse_json_file(path):
                records_seen += 1
                summary, model, tool, prompt_text = _build_record_summary(record, path)
                priority, tier = _guess_severity(summary)
                moment = {
                    "source": str(path.relative_to(target_dir)),
                    "ts": _guess_timestamp(record),
                    "tier": tier,
                    "priority": priority,
                    "kind": _guess_event_name(record),
                    "summary": summary,
                }
                if model:
                    moment["model"] = model
                    model_counts[model] += 1
                if tool:
                    moment["tool"] = tool
                    tool_counts[tool] += 1
                if prompt_text:
                    moment["prompt_preview"] = prompt_text
                moments.append(moment)
    return moments, model_counts, tool_counts, files_scanned, records_seen


def _collect_text_signal_moments(target_dir: Path) -> Tuple[List[Dict[str, Any]], int, int]:
    moments: List[Dict[str, Any]] = []
    files_scanned = 0
    total_kept_lines = 0
    for path in _collect_log_files(target_dir):
        if path.suffix.lower() not in TEXT_SCAN_EXTENSIONS:
            continue
        files_scanned += 1
        try:
            content = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        kept, signal_counts, _noise_counts = _filter_lines(lines, context=1, keep_neutral=False)
        total_kept_lines += len(kept)
        if not signal_counts:
            continue
        for line in kept[:8]:
            if not line or line.startswith("... ["):
                continue
            priority, tier = _guess_severity(line)
            moments.append({
                "source": str(path.relative_to(target_dir)),
                "ts": None,
                "tier": tier,
                "priority": priority,
                "kind": "log_signal",
                "summary": _trim(line, MAX_TEXT_SNIPPET),
            })
    return moments, files_scanned, total_kept_lines


def _detect_issues(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    prompt_hashes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        if entry.get("prompt_hash"):
            prompt_hashes[entry["prompt_hash"]].append(entry)
    for prompt_hash, dupes in prompt_hashes.items():
        if len(dupes) > 1:
            wasted = sum(item.get("total_tokens", 0) for item in dupes[1:])
            issues.append({
                "type": "duplicate_prompt",
                "severity": "warning",
                "count": len(dupes),
                "wasted_tokens": wasted,
                "message": f"Identical prompt sent {len(dupes)} times",
            })
    for entry in entries:
        if entry.get("input_tokens", 0) > 100000:
            issues.append({
                "type": "oversized_context",
                "severity": "warning",
                "tokens": entry.get("input_tokens", 0),
                "message": f"Oversized input: {entry.get('input_tokens', 0):,} tokens",
            })
    expensive_models = {"gpt-4", "claude-3-opus", "claude-4-opus"}
    for entry in entries:
        model = entry.get("model", "")
        if any(token in model for token in expensive_models):
            if entry.get("output_tokens", 0) < 50 and entry.get("input_tokens", 0) < 500:
                issues.append({
                    "type": "model_overkill",
                    "severity": "info",
                    "message": f"Small task on expensive model {model}",
                })
    ratios = [
        entry.get("input_tokens", 0) / max(entry.get("output_tokens", 0), 1)
        for entry in entries
        if entry.get("output_tokens", 0) > 0
    ]
    if ratios:
        avg_ratio = sum(ratios) / len(ratios)
        if avg_ratio > 20:
            issues.append({
                "type": "high_input_ratio",
                "severity": "info",
                "message": f"Average input/output ratio is {avg_ratio:.1f}x",
            })
    return issues


def _build_recommendations(issues: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    issue_types = {issue["type"] for issue in issues}
    recommendations: List[Dict[str, str]] = []
    if "duplicate_prompt" in issue_types:
        recommendations.append({
            "title": "Collapse repeated prompts",
            "action": "Cache exact prompt/context pairs or dedupe retries before they hit the model.",
        })
    if "oversized_context" in issue_types:
        recommendations.append({
            "title": "Split hot and cold context",
            "action": "Keep a tiny bootstrap in-prompt and push stale traces into the cold capsule.",
        })
    if "model_overkill" in issue_types:
        recommendations.append({
            "title": "Downshift cheap tasks",
            "action": "Route short extraction/summarization passes onto cheaper models first.",
        })
    if "high_input_ratio" in issue_types:
        recommendations.append({
            "title": "Send summaries, not transcript dumps",
            "action": "Use the capsule output as the first context block instead of replaying full logs.",
        })
    if not recommendations:
        recommendations.append({
            "title": "Usage looks disciplined",
            "action": "Persist this capsule and feed it forward instead of raw trace history.",
        })
    return recommendations


def _sorted_top(counter: Counter, limit: int = 6, key_name: str = "name") -> List[Dict[str, Any]]:
    return [{key_name: name, "count": count} for name, count in counter.most_common(limit)]


def _select_relevant_moments(moments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = sorted(
        moments,
        key=lambda item: (
            -int(item.get("priority", 0)),
            "" if item.get("ts") is None else str(item.get("ts")),
            item.get("source", ""),
            item.get("summary", ""),
        ),
    )
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in ranked:
        key = (item.get("source"), item.get("kind"), item.get("summary"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= MAX_RELEVANT_ITEMS:
            break
    return deduped


def _build_cold_paths(target_dir: Path, relevant_sources: Iterable[str]) -> List[Dict[str, Any]]:
    relevant_set = set(relevant_sources)
    cold: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
        for fname in sorted(files):
            path = Path(root) / fname
            rel = str(path.relative_to(target_dir))
            if rel in relevant_set:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            cold.append({
                "path": rel,
                "bytes": size,
                "reason": "cold_candidate",
            })
    cold.sort(key=lambda item: (-item["bytes"], item["path"]))
    return cold[:MAX_COLD_ITEMS]


def _resolve_output_paths(target_dir: Path, out_arg: Optional[str]) -> Tuple[Path, Path]:
    if out_arg:
        out_path = Path(out_arg).expanduser()
        if out_path.suffix.lower() == ".json":
            json_path = out_path
            md_path = out_path.with_suffix(".md")
            return json_path, md_path
        out_dir = out_path
    else:
        out_dir = target_dir / ".liquefy"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / "context_capsule.json", out_dir / "context_capsule.md"


def _workspace_context_paths(workspace: Path) -> Dict[str, Path]:
    base = workspace / WORKSPACE_CONTEXT_DIR
    history = workspace / WORKSPACE_CONTEXT_HISTORY_DIR
    return {
        "dir": base,
        "history_dir": history,
        "json": base / "context_capsule.json",
        "markdown": base / "context_capsule.md",
        "bootstrap": base / BOOTSTRAP_FILENAME,
        "manifest": base / MANIFEST_FILENAME,
        "scoreboard": history / SCOREBOARD_FILENAME,
    }


def _trace_source_manifest(target_dir: Path) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    total_bytes = 0
    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
        for fname in sorted(fnames):
            path = Path(root) / fname
            rel = str(path.relative_to(target_dir))
            try:
                stat = path.stat()
            except OSError:
                continue
            mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
            files.append({
                "path": rel,
                "bytes": int(stat.st_size),
                "mtime_ns": mtime_ns,
            })
            total_bytes += int(stat.st_size)
    encoded = json.dumps(files, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    fingerprint = hashlib.sha256(encoded).hexdigest()
    return {
        "mode": TRACE_FINGERPRINT_MODE,
        "fingerprint": fingerprint,
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def _load_scoreboard(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": "liquefy.context-scoreboard.v1",
            "generated_at_utc": _utc_now(),
            "entries": [],
            "summary": {},
        }
    try:
        payload = json.loads(path.read_text("utf-8"))
        if isinstance(payload, dict):
            payload.setdefault("entries", [])
            payload.setdefault("summary", {})
            payload.setdefault("schema_version", "liquefy.context-scoreboard.v1")
            return payload
    except (OSError, json.JSONDecodeError):
        pass
    return {
        "schema_version": "liquefy.context-scoreboard.v1",
        "generated_at_utc": _utc_now(),
        "entries": [],
        "summary": {},
    }


def _scoreboard_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    unique_runs = len(entries)
    total_prime_events = sum(int(item.get("seen_count", 1)) for item in entries)
    reductions = sorted(float(item.get("reduction_pct", 0.0)) for item in entries)
    cumulative_raw_chars = sum(int(item.get("raw_chars", 0)) for item in entries)
    cumulative_capsule_chars = sum(int(item.get("capsule_chars", 0)) for item in entries)
    cumulative_chars_saved = max(0, cumulative_raw_chars - cumulative_capsule_chars)
    exact_cost_observed_usd = round(sum(float(item.get("cost_exact_usd", 0.0)) for item in entries), 4)
    estimated_cost_observed_usd = round(sum(float(item.get("cost_estimated_usd", 0.0)) for item in entries), 4)
    return {
        "unique_runs": unique_runs,
        "total_prime_events": total_prime_events,
        "fresh_prime_events": unique_runs,
        "replayed_prime_events": max(0, total_prime_events - unique_runs),
        "median_reduction_pct": float(median(reductions)) if reductions else 0.0,
        "best_reduction_pct": reductions[-1] if reductions else 0.0,
        "worst_reduction_pct": reductions[0] if reductions else 0.0,
        "cumulative_raw_chars": cumulative_raw_chars,
        "cumulative_capsule_chars": cumulative_capsule_chars,
        "cumulative_chars_saved": cumulative_chars_saved,
        "approx_prompt_tokens_saved": int(round(cumulative_chars_saved / 4)) if cumulative_chars_saved else 0,
        "approx_prompt_tokens_saved_method": "chars_div_4_heuristic",
        "exact_cost_observed_usd": exact_cost_observed_usd,
        "estimated_cost_observed_usd": estimated_cost_observed_usd,
    }


def _update_scoreboard(path: Path, trace_dir: Path, capsule: Dict[str, Any]) -> Dict[str, Any]:
    scoreboard = _load_scoreboard(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary = capsule["summary"]
    truth_cost = (summary.get("truth") or {}).get("cost") or {}
    entry = {
        "trace_fingerprint": summary["trace_fingerprint"],
        "trace_fingerprint_mode": summary["trace_fingerprint_mode"],
        "trace_dir": str(trace_dir),
        "first_generated_at_utc": capsule["generated_at_utc"],
        "last_generated_at_utc": capsule["generated_at_utc"],
        "seen_count": 1,
        "raw_chars": summary["raw_chars"],
        "capsule_chars": summary["capsule_chars"],
        "artifact_chars": summary["artifact_chars"],
        "reduction_pct": summary["reduction_pct"],
        "token_entries": summary["token_entries"],
        "total_tokens": summary["total_tokens"],
        "cost_usd": summary["cost_usd"],
        "estimated_cost_usd": summary["estimated_cost_usd"],
        "cost_exact_usd": truth_cost.get("exact_usd", 0.0),
        "cost_estimated_usd": truth_cost.get("estimated_usd", 0.0),
        "cost_truth_mode": truth_cost.get("mode", "unavailable"),
        "top_models": capsule["bootstrap"].get("top_models", [])[:3],
        "top_tools": capsule["bootstrap"].get("top_tools", [])[:3],
    }

    replay_detected = False
    for existing in scoreboard["entries"]:
        if existing.get("trace_fingerprint") == entry["trace_fingerprint"]:
            existing["last_generated_at_utc"] = capsule["generated_at_utc"]
            existing["seen_count"] = int(existing.get("seen_count", 1)) + 1
            replay_detected = True
            break
    else:
        scoreboard["entries"].append(entry)

    scoreboard["generated_at_utc"] = _utc_now()
    scoreboard["summary"] = _scoreboard_summary(scoreboard["entries"])
    path.write_text(json.dumps(scoreboard, indent=2), encoding="utf-8")
    return {
        "path": str(path),
        "replay_detected": replay_detected,
        "summary": scoreboard["summary"],
    }


def inspect_workspace_capsule(workspace: Path, trace_dir: Optional[Path] = None) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    paths = _workspace_context_paths(workspace)
    manifest_path = paths["manifest"]
    if not manifest_path.exists():
        return {
            "ok": True,
            "status": "missing",
            "detail": "No primed capsule manifest exists in this workspace yet.",
            "workspace": str(workspace),
        }

    manifest = json.loads(manifest_path.read_text("utf-8"))
    resolved_trace_dir = Path(trace_dir or manifest.get("trace_dir") or workspace).expanduser().resolve()
    if not resolved_trace_dir.exists():
        return {
            "ok": True,
            "status": "missing_trace_dir",
            "detail": "The trace directory recorded for this capsule no longer exists.",
            "workspace": str(workspace),
            "trace_dir": str(resolved_trace_dir),
            "manifest_file": str(manifest_path),
        }

    current_manifest = _trace_source_manifest(resolved_trace_dir)
    saved_fingerprint = manifest.get("trace_fingerprint")
    saved_mode = manifest.get("trace_fingerprint_mode", TRACE_FINGERPRINT_MODE)
    is_fresh = saved_fingerprint == current_manifest["fingerprint"] and saved_mode == current_manifest["mode"]
    return {
        "ok": True,
        "status": "fresh" if is_fresh else "stale",
        "detail": (
            "Current trace metadata matches the primed capsule source."
            if is_fresh
            else "Trace metadata changed after the capsule was generated; re-prime before claiming new savings."
        ),
        "workspace": str(workspace),
        "trace_dir": str(resolved_trace_dir),
        "manifest_file": str(manifest_path),
        "saved_trace_fingerprint": saved_fingerprint,
        "current_trace_fingerprint": current_manifest["fingerprint"],
        "trace_fingerprint_mode": current_manifest["mode"],
        "trace_fingerprint_match": is_fresh,
    }


def load_scoreboard(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    paths = _workspace_context_paths(workspace)
    data = _load_scoreboard(paths["scoreboard"])
    return {
        "ok": True,
        "workspace": str(workspace),
        "scoreboard_file": str(paths["scoreboard"]),
        "summary": data.get("summary", {}),
        "entries": data.get("entries", []),
    }


def _prompt_bootstrap(summary: Dict[str, Any], relevant: List[Dict[str, Any]], recommendations: List[Dict[str, str]]) -> str:
    lines = [
        "LIQUEFY CONTEXT CAPSULE",
        f"trace_dir: {summary['trace_dir']}",
        f"reduction_pct: {summary['reduction_pct']}",
        f"token_entries: {summary['token_entries']}",
        f"cost_usd: {summary['cost_usd']}",
        f"estimated_cost_usd: {summary['estimated_cost_usd']}",
        f"cost_truth_mode: {summary['truth']['cost']['mode']}",
        "important_moments:",
    ]
    for item in relevant[:10]:
        lines.append(f"- {item['summary']}")
    lines.append("recommended_operator_moves:")
    for item in recommendations[:5]:
        lines.append(f"- {item['title']}: {item['action']}")
    return "\n".join(lines)


def _render_markdown(capsule: Dict[str, Any]) -> str:
    summary = capsule["summary"]
    bootstrap = capsule["bootstrap"]
    relevant = capsule["relevant"]
    cold = capsule["cold"]
    recommendations = capsule["recommendations"]
    top_models = ", ".join(
        f"{row['model']} ({row['count']})" for row in bootstrap["top_models"]
    ) or "none"
    top_tools = ", ".join(
        f"{row['tool']} ({row['count']})" for row in bootstrap["top_tools"]
    ) or "none"

    lines = [
        "# Liquefy Context Capsule",
        "",
        f"Generated: {capsule['generated_at_utc']}",
        "",
        "## Summary",
        f"- Trace dir: `{summary['trace_dir']}`",
        f"- Files scanned: {summary['files_scanned']}",
        f"- JSON/text records seen: {summary['records_seen']}",
        f"- Token entries: {summary['token_entries']}",
        f"- Cost shown: ${summary['cost_usd']:.4f}",
        f"- Estimated cost only: ${summary['estimated_cost_usd']:.4f}",
        f"- Cost truth: {summary['truth']['cost']['mode']} ({summary['truth']['cost']['source']})",
        f"- Quota truth: {summary['truth']['quota']['mode']} ({summary['truth']['quota']['source']})",
        f"- Raw chars: {summary['raw_chars']:,}",
        f"- Prompt chars: {summary['capsule_chars']:,}",
        f"- Artifact chars: {summary['artifact_chars']:,}",
        f"- Reduction: {summary['reduction_pct']}%",
        "",
        "## Bootstrap",
        f"- Top models: {top_models}",
        f"- Top tools: {top_tools}",
        f"- Waste issues: {len(bootstrap['issues'])}",
        "",
        "## Relevant",
    ]
    for item in relevant:
        source = item.get("source", "unknown")
        ts = item.get("ts") or "n/a"
        lines.append(f"- [{item.get('tier', 'low')}] `{source}` @ `{ts}` — {item['summary']}")
    lines.append("")
    lines.append("## Recommendations")
    for item in recommendations:
        lines.append(f"- **{item['title']}** — {item['action']}")
    lines.append("")
    lines.append("## Cold Candidates")
    for item in cold:
        lines.append(f"- `{item['path']}` ({item['bytes']} bytes) — {item['reason']}")
    lines.append("")
    lines.append("## Prompt Bootstrap")
    lines.append("```")
    lines.append(capsule["prompt_bootstrap"])
    lines.append("```")
    return "\n".join(lines) + "\n"


def build_capsule(target_dir: Path, out_arg: Optional[str] = None) -> Dict[str, Any]:
    target_dir = target_dir.expanduser().resolve()
    if not target_dir.exists():
        raise FileNotFoundError(f"Path not found: {target_dir}")

    record_moments, model_counts, tool_counts, json_files_scanned, records_seen = _collect_record_moments(target_dir)
    text_moments, text_files_scanned, kept_text_lines = _collect_text_signal_moments(target_dir)
    token_entries = _scan_token_entries(target_dir)
    issues = _detect_issues(token_entries)

    all_moments = record_moments + text_moments
    relevant = _select_relevant_moments(all_moments)
    cold = _build_cold_paths(target_dir, (item.get("source", "") for item in relevant))
    recommendations = _build_recommendations(issues)

    total_input = sum(entry.get("input_tokens", 0) for entry in token_entries)
    total_output = sum(entry.get("output_tokens", 0) for entry in token_entries)
    estimated_cost = sum(_estimate_cost(entry.get("model", "unknown"), entry.get("input_tokens", 0), entry.get("output_tokens", 0)) for entry in token_entries)
    source_manifest = _trace_source_manifest(target_dir)
    raw_chars = source_manifest["total_bytes"]

    bootstrap = {
        "top_models": _sorted_top(model_counts, key_name="model"),
        "top_tools": _sorted_top(tool_counts, key_name="tool"),
        "issues": issues,
        "kept_text_lines": kept_text_lines,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
    }

    truth = _summarize_truth(token_entries, base_dir=target_dir)
    summary = {
        "trace_dir": str(target_dir),
        "files_scanned": json_files_scanned + text_files_scanned,
        "records_seen": records_seen,
        "token_entries": len(token_entries),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "cost_usd": round(truth["cost"]["usd"], 4),
        "estimated_cost_usd": round(estimated_cost, 4),
        "issues_found": len(issues),
        "raw_chars": raw_chars,
        "artifact_chars": 0,
        "capsule_chars": 0,
        "reduction_pct": 0.0,
        "trace_fingerprint": source_manifest["fingerprint"],
        "trace_fingerprint_mode": source_manifest["mode"],
        "trace_file_count": source_manifest["file_count"],
        "truth": truth,
    }

    capsule: Dict[str, Any] = {
        "schema_version": CLI_SCHEMA,
        "generated_at_utc": _utc_now(),
        "summary": summary,
        "bootstrap": bootstrap,
        "relevant": relevant,
        "cold": cold,
        "recommendations": recommendations,
    }
    for _ in range(2):
        capsule["prompt_bootstrap"] = _prompt_bootstrap(summary, relevant, recommendations)
        capsule_json_preview = _safe_json({
            "summary": summary,
            "bootstrap": bootstrap,
            "relevant": relevant,
            "cold": cold,
            "recommendations": recommendations,
            "prompt_bootstrap": capsule["prompt_bootstrap"],
        })
        prompt_chars = len(capsule["prompt_bootstrap"])
        artifact_chars = len(capsule_json_preview)
        reduction = round((1 - (prompt_chars / max(raw_chars, 1))) * 100, 1) if raw_chars else 0.0
        summary["capsule_chars"] = prompt_chars
        summary["artifact_chars"] = artifact_chars
        summary["reduction_pct"] = max(0.0, reduction)

    json_path, md_path = _resolve_output_paths(target_dir, out_arg)
    json_path.write_text(json.dumps(capsule, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(capsule), encoding="utf-8")

    summary["json_path"] = str(json_path)
    summary["markdown_path"] = str(md_path)
    return capsule


def prime_workspace(workspace: Path, trace_dir: Optional[Path] = None) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    if not workspace.exists():
        raise FileNotFoundError(f"Workspace not found: {workspace}")
    trace_root = (trace_dir or workspace).expanduser().resolve()
    if not trace_root.exists():
        raise FileNotFoundError(f"Trace path not found: {trace_root}")

    paths = _workspace_context_paths(workspace)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    paths["history_dir"].mkdir(parents=True, exist_ok=True)

    capsule = build_capsule(trace_root, str(paths["dir"]))
    paths["bootstrap"].write_text(capsule["prompt_bootstrap"] + "\n", encoding="utf-8")
    scoreboard = _update_scoreboard(paths["scoreboard"], trace_root, capsule)

    manifest = {
        "schema_version": CLI_SCHEMA,
        "generated_at_utc": capsule["generated_at_utc"],
        "workspace": str(workspace),
        "trace_dir": str(trace_root),
        "trace_fingerprint": capsule["summary"]["trace_fingerprint"],
        "trace_fingerprint_mode": capsule["summary"]["trace_fingerprint_mode"],
        "reduction_pct": capsule["summary"]["reduction_pct"],
        "token_entries": capsule["summary"]["token_entries"],
        "total_tokens": capsule["summary"]["total_tokens"],
        "estimated_cost_usd": capsule["summary"]["estimated_cost_usd"],
        "bootstrap_file": str(paths["bootstrap"]),
        "capsule_json": str(paths["json"]),
        "capsule_markdown": str(paths["markdown"]),
        "replay_detected": scoreboard["replay_detected"],
        "scoreboard_file": scoreboard["path"],
        "env": {
            "LIQUEFY_CONTEXT_BOOTSTRAP_FILE": str(paths["bootstrap"]),
            "LIQUEFY_CONTEXT_CAPSULE_JSON": str(paths["json"]),
            "LIQUEFY_CONTEXT_CAPSULE_MARKDOWN": str(paths["markdown"]),
            "LIQUEFY_CONTEXT_REDUCTION_PCT": str(capsule["summary"]["reduction_pct"]),
        },
    }
    paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "schema_version": CLI_SCHEMA,
        "generated_at_utc": capsule["generated_at_utc"],
        "workspace": str(workspace),
        "trace_dir": str(trace_root),
        "reduction_pct": capsule["summary"]["reduction_pct"],
        "token_entries": capsule["summary"]["token_entries"],
        "total_tokens": capsule["summary"]["total_tokens"],
        "estimated_cost_usd": capsule["summary"]["estimated_cost_usd"],
        "bootstrap_file": str(paths["bootstrap"]),
        "capsule_json": str(paths["json"]),
        "capsule_markdown": str(paths["markdown"]),
        "manifest_file": str(paths["manifest"]),
        "trace_fingerprint": capsule["summary"]["trace_fingerprint"],
        "trace_fingerprint_mode": capsule["summary"]["trace_fingerprint_mode"],
        "replay_detected": scoreboard["replay_detected"],
        "scoreboard": scoreboard,
        "env": manifest["env"],
    }


def cmd_build(args: argparse.Namespace) -> int:
    try:
        capsule = build_capsule(Path(args.dir), args.out)
    except FileNotFoundError as exc:
        if args.json:
            _emit("build", False, {"error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    result = capsule["summary"].copy()
    result.update({
        "top_models": capsule["bootstrap"]["top_models"],
        "top_tools": capsule["bootstrap"]["top_tools"],
        "recommendations": capsule["recommendations"],
    })
    if args.json:
        _emit("build", True, result)
    else:
        print("  Liquefy Context Capsule")
        print(f"    Trace dir:        {result['trace_dir']}")
        print(f"    Files scanned:    {result['files_scanned']}")
        print(f"    Token entries:    {result['token_entries']}")
        print(f"    Estimated cost:   ${result['estimated_cost_usd']:.4f}")
        print(f"    Prompt chars:     {result['capsule_chars']:,}")
        print(f"    Artifact chars:   {result['artifact_chars']:,}")
        print(f"    Reduction:        {result['reduction_pct']}%")
        print(f"    JSON:             {result['json_path']}")
        print(f"    Markdown:         {result['markdown_path']}")
    return 0


def cmd_prime(args: argparse.Namespace) -> int:
    try:
        result = prime_workspace(
            Path(args.workspace),
            Path(args.trace_dir).expanduser() if args.trace_dir else None,
        )
    except FileNotFoundError as exc:
        if args.json:
            _emit("prime", False, {"error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _emit("prime", True, result)
    else:
        print("  Liquefy Context Prime")
        print(f"    Workspace:        {result['workspace']}")
        print(f"    Trace dir:        {result['trace_dir']}")
        print(f"    Reduction:        {result['reduction_pct']}%")
        print(f"    Token entries:    {result['token_entries']}")
        print(f"    Bootstrap file:   {result['bootstrap_file']}")
        print(f"    Capsule JSON:     {result['capsule_json']}")
        print(f"    Capsule Markdown: {result['capsule_markdown']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    result = inspect_workspace_capsule(
        Path(args.workspace),
        Path(args.trace_dir).expanduser() if args.trace_dir else None,
    )
    if args.json:
        _emit("verify", bool(result.get("ok")), result)
    else:
        print("  Liquefy Context Verify")
        print(f"    Workspace:        {result['workspace']}")
        if result.get("trace_dir"):
            print(f"    Trace dir:        {result['trace_dir']}")
        print(f"    Status:           {result['status']}")
        print(f"    Detail:           {result['detail']}")
    return 0 if result.get("ok") else 1


def cmd_scoreboard(args: argparse.Namespace) -> int:
    result = load_scoreboard(Path(args.workspace))
    if args.json:
        _emit("scoreboard", True, result)
    else:
        summary = result.get("summary", {})
        print("  Liquefy Context Scoreboard")
        print(f"    Workspace:        {result['workspace']}")
        print(f"    Unique runs:      {summary.get('unique_runs', 0)}")
        print(f"    Prime events:     {summary.get('total_prime_events', 0)}")
        print(f"    Replayed:         {summary.get('replayed_prime_events', 0)}")
        print(f"    Median reduction: {summary.get('median_reduction_pct', 0.0)}%")
        print(f"    Best reduction:   {summary.get('best_reduction_pct', 0.0)}%")
        print(f"    Saved chars:      {summary.get('cumulative_chars_saved', 0):,}")
        print(f"    Saved tokens~:    {summary.get('approx_prompt_tokens_saved', 0):,}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-context-capsule",
        description="Build a compact context capsule from raw agent traces.",
    )
    sub = ap.add_subparsers(dest="command")

    p_build = sub.add_parser("build", help="Build a context capsule")
    p_build.add_argument("--dir", required=True, help="Trace/log directory to scan")
    p_build.add_argument("--out", help="Output .json file or output directory")
    p_build.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_build.set_defaults(fn=cmd_build)

    p_prime = sub.add_parser("prime", help="Build and install a reusable capsule bootstrap into a workspace")
    p_prime.add_argument("--workspace", required=True, help="Workspace that should receive the primed bootstrap files")
    p_prime.add_argument("--trace-dir", help="Optional trace/log directory to scan instead of the workspace")
    p_prime.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_prime.set_defaults(fn=cmd_prime)

    p_verify = sub.add_parser("verify", help="Check whether a primed capsule is still fresh for the current trace set")
    p_verify.add_argument("--workspace", required=True, help="Workspace with the primed capsule")
    p_verify.add_argument("--trace-dir", help="Optional trace/log directory to compare against the saved capsule manifest")
    p_verify.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_verify.set_defaults(fn=cmd_verify)

    p_scoreboard = sub.add_parser("scoreboard", help="Show replay-aware capsule savings history for a workspace")
    p_scoreboard.add_argument("--workspace", required=True, help="Workspace with capsule history")
    p_scoreboard.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_scoreboard.set_defaults(fn=cmd_scoreboard)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "fn"):
        parser.print_help(sys.stderr)
        return 2
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
