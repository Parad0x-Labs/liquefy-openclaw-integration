#!/usr/bin/env python3
"""
liquefy_context_gate.py
=======================
Compile a bounded, explainable context pack for the next agent run.

The goal is not more reporting. The goal is to move context discipline into the
hot path:
- rank context blocks by importance
- fit them under a hard prompt budget
- emit a manifest explaining every included/omitted block
- detect exact replay of the same command+context bundle
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

try:
    from liquefy_context_capsule import inspect_workspace_capsule
except Exception:  # pragma: no cover - defensive import guard
    inspect_workspace_capsule = None


SCHEMA = "liquefy.context-gate.v1"
HISTORY_SCHEMA = "liquefy.context-gate.history.v1"
CURRENT_CONTEXT_DIR = Path(".liquefy") / "context" / "current"
HISTORY_CONTEXT_DIR = Path(".liquefy") / "context" / "history"
CAPSULE_JSON_FILENAME = "context_capsule.json"
CAPSULE_MANIFEST_FILENAME = "context_manifest.json"
BOOTSTRAP_FILENAME = "context_bootstrap.md"
GATE_JSON_FILENAME = "context_gate.json"
GATE_PROMPT_FILENAME = "context_gate_prompt.md"
GATE_HISTORY_FILENAME = "context_gate_history.json"
DEFAULT_REQUIRED_FILES = ("SOUL.md", "HEARTBEAT.md")
DEFAULT_OPTIONAL_FILES = ("auth-profiles.json",)
DEFAULT_BUDGET_TOKENS = 2400
DEFAULT_REPLAY_WINDOW_HOURS = 24.0
MAX_BLOCK_CHARS = 2200
MAX_BOOTSTRAP_CHARS = 3600
MAX_OPTIONAL_BLOCKS = 24
SECRET_FIELD_RE = re.compile(r"(secret|token|password|api[_-]?key|private[_-]?key)", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _trim(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: max(0, limit - 3)] + "..."


def _estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(math.ceil(len(text) / 4)))


def _context_paths(workspace: Path) -> Dict[str, Path]:
    current = workspace / CURRENT_CONTEXT_DIR
    history = workspace / HISTORY_CONTEXT_DIR
    return {
        "current_dir": current,
        "history_dir": history,
        "capsule_json": current / CAPSULE_JSON_FILENAME,
        "capsule_manifest": current / CAPSULE_MANIFEST_FILENAME,
        "bootstrap": current / BOOTSTRAP_FILENAME,
        "gate_json": current / GATE_JSON_FILENAME,
        "gate_prompt": current / GATE_PROMPT_FILENAME,
        "gate_history": history / GATE_HISTORY_FILENAME,
    }


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except Exception:
        return repr(value)


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_text(path: Path, limit: int) -> str:
    try:
        return _trim(path.read_text("utf-8", errors="replace"), limit)
    except OSError:
        return ""


def _redacted_profile_summary(path: Path) -> str:
    payload = _load_json(path)
    if not payload:
        return _read_text(path, 400)

    providers = set()
    profile_keys = []

    def _walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and SECRET_FIELD_RE.search(key):
                    continue
                if isinstance(key, str) and key.lower() in {"provider", "provider_name", "vendor"} and isinstance(item, str):
                    providers.add(item.strip().lower())
                _walk(item)
            return
        if isinstance(value, list):
            for item in value:
                _walk(item)

    if isinstance(payload, dict):
        profile_keys = [key for key in payload.keys() if not SECRET_FIELD_RE.search(str(key))]
    _walk(payload)

    parts = []
    if providers:
        parts.append("providers=" + ", ".join(sorted(providers)))
    if profile_keys:
        parts.append("profiles=" + ", ".join(sorted(str(key) for key in profile_keys[:8])))
    if not parts:
        parts.append("workspace profile present (secret fields omitted)")
    return "; ".join(parts)


def _make_block(
    *,
    label: str,
    kind: str,
    text: str,
    source: str,
    required: bool,
    priority: int,
) -> Optional[Dict[str, Any]]:
    cleaned = text.strip()
    if not cleaned:
        return None
    token_estimate = _estimate_tokens(cleaned)
    return {
        "label": label,
        "kind": kind,
        "source": source,
        "required": bool(required),
        "priority": int(priority),
        "text": cleaned,
        "token_estimate": token_estimate,
        "content_hash": _sha256_text(cleaned),
    }


def _capsule_optional_blocks(capsule: Dict[str, Any]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    bootstrap = capsule.get("bootstrap") or {}
    summary = capsule.get("summary") or {}
    relevant = capsule.get("relevant") or []
    recommendations = capsule.get("recommendations") or []

    top_models = bootstrap.get("top_models") or []
    top_tools = bootstrap.get("top_tools") or []
    issues = bootstrap.get("issues") or []

    if top_models or top_tools:
        model_text = ", ".join(f"{row['model']} ({row['count']})" for row in top_models[:4]) or "none"
        tool_text = ", ".join(f"{row['tool']} ({row['count']})" for row in top_tools[:4]) or "none"
        block = _make_block(
            label="Hot Path Summary",
            kind="summary",
            text=f"Top models: {model_text}\nTop tools: {tool_text}\nTrace fingerprint: {summary.get('trace_fingerprint', 'unknown')}",
            source="context_capsule.json",
            required=False,
            priority=78,
        )
        if block:
            blocks.append(block)

    for issue in issues[:8]:
        block = _make_block(
            label=f"Issue: {issue.get('type', 'unknown')}",
            kind="issue",
            text=issue.get("message", "issue detected"),
            source="context_capsule.json",
            required=False,
            priority=88 if issue.get("severity") == "warning" else 68,
        )
        if block:
            blocks.append(block)

    for item in relevant[:MAX_OPTIONAL_BLOCKS]:
        block = _make_block(
            label=f"Relevant: {item.get('kind', 'event')}",
            kind="relevant",
            text=item.get("summary", ""),
            source=item.get("source", "context_capsule.json"),
            required=False,
            priority=int(item.get("priority", 50)),
        )
        if block:
            blocks.append(block)

    for item in recommendations[:6]:
        block = _make_block(
            label=f"Recommendation: {item.get('title', 'move')}",
            kind="recommendation",
            text=f"{item.get('title', 'Move')}: {item.get('action', '')}",
            source="context_capsule.json",
            required=False,
            priority=72,
        )
        if block:
            blocks.append(block)

    return blocks


def _required_blocks(workspace: Path, command: str, paths: Dict[str, Path]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    command_preview = _trim(command, 240)
    block = _make_block(
        label="Requested Command",
        kind="command",
        text=f"Execute: {command_preview}",
        source="runtime",
        required=True,
        priority=200,
    )
    if block:
        blocks.append(block)

    for fname in DEFAULT_REQUIRED_FILES:
        fpath = workspace / fname
        if not fpath.exists():
            continue
        label = "Workspace Identity" if fname == "SOUL.md" else "Heartbeat Contract"
        block = _make_block(
            label=label,
            kind="sentinel",
            text=_read_text(fpath, MAX_BLOCK_CHARS),
            source=fname,
            required=True,
            priority=180 if fname == "SOUL.md" else 160,
        )
        if block:
            blocks.append(block)

    bootstrap_text = _read_text(paths["bootstrap"], MAX_BOOTSTRAP_CHARS)
    if bootstrap_text:
        block = _make_block(
            label="Primed Bootstrap",
            kind="bootstrap",
            text=bootstrap_text,
            source=str(paths["bootstrap"].name),
            required=True,
            priority=170,
        )
        if block:
            blocks.append(block)

    optional_profile = workspace / DEFAULT_OPTIONAL_FILES[0]
    if optional_profile.exists():
        block = _make_block(
            label="Provider Profile Summary",
            kind="profile",
            text=_redacted_profile_summary(optional_profile),
            source=optional_profile.name,
            required=False,
            priority=82,
        )
        if block:
            blocks.append(block)

    return blocks


def _compile_context(required: List[Dict[str, Any]], optional: List[Dict[str, Any]], token_budget: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    included: List[Dict[str, Any]] = []
    omitted: List[Dict[str, Any]] = []
    used_tokens = 0

    for block in required:
        if used_tokens + block["token_estimate"] > token_budget:
            omitted.append({**block, "omit_reason": "required_context_exceeds_budget"})
            continue
        included.append(block)
        used_tokens += block["token_estimate"]

    required_omissions = [block for block in omitted if block.get("required")]
    if required_omissions:
        return included, omitted + [{**block, "omit_reason": "required_context_exceeds_budget"} for block in optional], ""

    ranked_optional = sorted(optional, key=lambda item: (-item["priority"], item["label"], item["content_hash"]))
    for block in ranked_optional:
        if used_tokens + block["token_estimate"] > token_budget:
            omitted.append({**block, "omit_reason": "token_budget"})
            continue
        included.append(block)
        used_tokens += block["token_estimate"]

    sections = []
    for block in included:
        sections.append(f"## {block['label']}\n{block['text']}")
    return included, omitted, "\n\n".join(sections).strip() + ("\n" if included else "")


def _load_history(path: Path) -> Dict[str, Any]:
    payload = _load_json(path)
    if payload:
        payload.setdefault("schema_version", HISTORY_SCHEMA)
        payload.setdefault("entries", [])
        return payload
    return {
        "schema_version": HISTORY_SCHEMA,
        "updated_at_utc": _utc_now(),
        "entries": [],
    }


def _parse_utc(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _record_history(
    path: Path,
    *,
    context_fingerprint: str,
    command_hash: str,
    compiled_prompt_hash: str,
    trace_fingerprint: str,
    token_budget: int,
    included_blocks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    history = _load_history(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = _utc_now()
    entry = None
    for item in history["entries"]:
        if item.get("context_fingerprint") == context_fingerprint:
            entry = item
            break
    replay_detected = entry is not None
    if entry is None:
        entry = {
            "context_fingerprint": context_fingerprint,
            "command_hash": command_hash,
            "compiled_prompt_hash": compiled_prompt_hash,
            "trace_fingerprint": trace_fingerprint,
            "first_seen_utc": now,
            "last_seen_utc": now,
            "seen_count": 1,
            "last_budget_tokens": token_budget,
            "last_included_blocks": len(included_blocks),
        }
        history["entries"].append(entry)
    else:
        entry["last_seen_utc"] = now
        entry["seen_count"] = int(entry.get("seen_count", 1)) + 1
        entry["last_budget_tokens"] = token_budget
        entry["last_included_blocks"] = len(included_blocks)

    history["entries"] = sorted(
        history["entries"],
        key=lambda item: item.get("last_seen_utc", ""),
        reverse=True,
    )[:512]
    history["updated_at_utc"] = now
    path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return {
        "history_file": str(path),
        "replay_detected": replay_detected,
        "entry": entry,
    }


def _replay_window_hit(entry: Dict[str, Any], replay_window_hours: float) -> bool:
    if replay_window_hours <= 0:
        return True
    last_seen = _parse_utc(str(entry.get("last_seen_utc", "")))
    if last_seen is None:
        return False
    return datetime.now(timezone.utc) - last_seen <= timedelta(hours=float(replay_window_hours))


def compile_context_gate(
    workspace: Path,
    command: str,
    *,
    token_budget: int = DEFAULT_BUDGET_TOKENS,
    block_replay: bool = False,
    replay_window_hours: float = DEFAULT_REPLAY_WINDOW_HOURS,
    trace_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    if not workspace.exists():
        raise FileNotFoundError(f"Workspace not found: {workspace}")
    if token_budget <= 0:
        raise ValueError("token_budget must be > 0")

    paths = _context_paths(workspace)
    paths["current_dir"].mkdir(parents=True, exist_ok=True)
    paths["history_dir"].mkdir(parents=True, exist_ok=True)

    capsule = _load_json(paths["capsule_json"]) or {}
    capsule_manifest = _load_json(paths["capsule_manifest"]) or {}
    capsule_state = None
    resolved_trace_dir = None
    if inspect_workspace_capsule is not None:
        try:
            resolved_trace_dir = Path(trace_dir).expanduser().resolve() if trace_dir else None
            capsule_state = inspect_workspace_capsule(workspace, resolved_trace_dir)
        except Exception:
            capsule_state = None
    effective_trace_dir = str(workspace)
    if resolved_trace_dir is not None:
        effective_trace_dir = str(resolved_trace_dir)
    elif isinstance(capsule_state, dict) and capsule_state.get("trace_dir"):
        effective_trace_dir = str(capsule_state["trace_dir"])

    required_blocks = _required_blocks(workspace, command, paths)
    optional_blocks = _capsule_optional_blocks(capsule)
    optional_required = [block for block in required_blocks if not block.get("required")]
    strict_required = [block for block in required_blocks if block.get("required")]
    included, omitted, compiled_prompt = _compile_context(strict_required, optional_required + optional_blocks, token_budget)

    blocked = False
    block_reason = None
    if not compiled_prompt:
        blocked = True
        block_reason = "required_context_exceeds_budget"

    compiled_prompt_hash = _sha256_text(compiled_prompt) if compiled_prompt else ""
    command_hash = _sha256_text(command)
    trace_fingerprint = (
        str((capsule.get("summary") or {}).get("trace_fingerprint"))
        or str(capsule_manifest.get("trace_fingerprint"))
        or "missing"
    )
    context_fingerprint = _sha256_text(
        _safe_json({
            "compiled_prompt_hash": compiled_prompt_hash,
            "command_hash": command_hash,
            "trace_fingerprint": trace_fingerprint,
        })
    )
    history_result = _record_history(
        paths["gate_history"],
        context_fingerprint=context_fingerprint,
        command_hash=command_hash,
        compiled_prompt_hash=compiled_prompt_hash,
        trace_fingerprint=trace_fingerprint,
        token_budget=token_budget,
        included_blocks=included,
    )

    replay_detected = bool(history_result["replay_detected"])
    replay_within_window = replay_detected and _replay_window_hit(history_result["entry"], replay_window_hours)
    if not blocked and block_replay and replay_within_window:
        blocked = True
        block_reason = "exact_replay_detected"

    summary = {
        "workspace": str(workspace),
        "trace_dir": effective_trace_dir,
        "token_budget": int(token_budget),
        "included_blocks": len(included),
        "omitted_blocks": len(omitted),
        "included_tokens": sum(block["token_estimate"] for block in included),
        "omitted_tokens": sum(block["token_estimate"] for block in omitted),
        "trace_fingerprint": trace_fingerprint,
        "compiled_prompt_hash": compiled_prompt_hash,
        "context_fingerprint": context_fingerprint,
        "replay_detected": replay_detected,
        "replay_within_window": replay_within_window,
        "replay_window_hours": float(replay_window_hours),
        "blocked": blocked,
        "block_reason": block_reason,
        "capsule_status": (capsule_state or {}).get("status") if isinstance(capsule_state, dict) else None,
    }

    payload = {
        "schema_version": SCHEMA,
        "generated_at_utc": _utc_now(),
        "summary": summary,
        "included": [
            {
                "label": block["label"],
                "kind": block["kind"],
                "source": block["source"],
                "required": block["required"],
                "priority": block["priority"],
                "token_estimate": block["token_estimate"],
                "content_hash": block["content_hash"],
            }
            for block in included
        ],
        "omitted": [
            {
                "label": block["label"],
                "kind": block["kind"],
                "source": block["source"],
                "required": block["required"],
                "priority": block["priority"],
                "token_estimate": block["token_estimate"],
                "content_hash": block["content_hash"],
                "omit_reason": block.get("omit_reason", "unknown"),
            }
            for block in omitted
        ],
        "capsule_state": capsule_state,
        "history": {
            "history_file": history_result["history_file"],
            "seen_count": int(history_result["entry"].get("seen_count", 1)),
        },
    }

    paths["gate_prompt"].write_text(compiled_prompt, encoding="utf-8")
    paths["gate_json"].write_text(json.dumps(payload, indent=2), encoding="utf-8")

    env = {
        "LIQUEFY_CONTEXT_GATE_FILE": str(paths["gate_prompt"]),
        "LIQUEFY_CONTEXT_GATE_JSON": str(paths["gate_json"]),
        "LIQUEFY_CONTEXT_GATE_BUDGET_TOKENS": str(token_budget),
        "LIQUEFY_CONTEXT_GATE_REPLAY": "1" if replay_detected else "0",
        "LIQUEFY_CONTEXT_GATE_CONTEXT_FINGERPRINT": context_fingerprint,
    }

    return {
        "schema_version": SCHEMA,
        "generated_at_utc": payload["generated_at_utc"],
        "workspace": str(workspace),
        "trace_dir": summary["trace_dir"],
        "token_budget": token_budget,
        "included_tokens": summary["included_tokens"],
        "included_blocks": summary["included_blocks"],
        "omitted_blocks": summary["omitted_blocks"],
        "blocked": blocked,
        "block_reason": block_reason,
        "replay_detected": replay_detected,
        "replay_within_window": replay_within_window,
        "capsule_status": summary["capsule_status"],
        "context_fingerprint": context_fingerprint,
        "compiled_prompt_hash": compiled_prompt_hash,
        "prompt_file": str(paths["gate_prompt"]),
        "json_file": str(paths["gate_json"]),
        "history_file": history_result["history_file"],
        "env": env,
    }


def context_gate_history(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    paths = _context_paths(workspace)
    history = _load_history(paths["gate_history"])
    return {
        "ok": True,
        "workspace": str(workspace),
        "history_file": str(paths["gate_history"]),
        "entries": history.get("entries", []),
    }


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    print(json.dumps({
        "schema_version": SCHEMA,
        "tool": "liquefy_context_gate",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }, indent=2))


def cmd_compile(args: argparse.Namespace) -> int:
    try:
        result = compile_context_gate(
            Path(args.workspace),
            args.cmd,
            token_budget=args.token_budget,
            block_replay=bool(args.block_replay),
            replay_window_hours=float(args.replay_window_hours),
            trace_dir=Path(args.trace_dir).expanduser() if args.trace_dir else None,
        )
    except (FileNotFoundError, ValueError) as exc:
        if args.json:
            _emit("compile", False, {"error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _emit("compile", not result["blocked"], result)
    else:
        status = "BLOCKED" if result["blocked"] else "READY"
        print(f"  Liquefy Context Gate [{status}]")
        print(f"    Workspace:        {result['workspace']}")
        print(f"    Budget tokens:    {result['token_budget']}")
        print(f"    Included tokens:  {result['included_tokens']}")
        print(f"    Included blocks:  {result['included_blocks']}")
        print(f"    Omitted blocks:   {result['omitted_blocks']}")
        print(f"    Replay detected:  {result['replay_detected']}")
        if result["blocked"]:
            print(f"    Block reason:     {result['block_reason']}")
        print(f"    Prompt file:      {result['prompt_file']}")
        print(f"    JSON file:        {result['json_file']}")
    return 1 if result["blocked"] else 0


def cmd_history(args: argparse.Namespace) -> int:
    result = context_gate_history(Path(args.workspace))
    if args.json:
        _emit("history", True, result)
    else:
        print("  Liquefy Context Gate History")
        print(f"    Workspace:        {result['workspace']}")
        print(f"    History file:     {result['history_file']}")
        print(f"    Entries:          {len(result['entries'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="liquefy-context-gate",
        description="Compile bounded runtime context and detect replay before execution.",
    )
    sub = parser.add_subparsers(dest="command")

    p_compile = sub.add_parser("compile", help="Compile context under a hard token budget")
    p_compile.add_argument("--workspace", required=True, help="Workspace with primed context artifacts")
    p_compile.add_argument("--cmd", required=True, help="Command that will execute with this context")
    p_compile.add_argument("--trace-dir", help="Optional trace/log directory used to inspect capsule freshness")
    p_compile.add_argument("--token-budget", type=int, default=DEFAULT_BUDGET_TOKENS, help="Approximate prompt token budget")
    p_compile.add_argument("--block-replay", action="store_true", help="Block exact replay inside the replay window")
    p_compile.add_argument("--replay-window-hours", type=float, default=DEFAULT_REPLAY_WINDOW_HOURS, help="Window used to classify exact replay")
    p_compile.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_compile.set_defaults(fn=cmd_compile)

    p_history = sub.add_parser("history", help="Show context gate replay history for a workspace")
    p_history.add_argument("--workspace", required=True, help="Workspace with context gate history")
    p_history.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_history.set_defaults(fn=cmd_history)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "fn"):
        parser.print_help(sys.stderr)
        return 2
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
