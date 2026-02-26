#!/usr/bin/env python3
"""
liquefy_events.py
=================
Structured agent event schema and trace operations.

Canonical trace model for agent-native operations:
    agent_id, session_id, parent/child span IDs, model call metadata,
    tool call I/O refs, token/cost/time, error/retry/escalation markers,
    prompt hash, context hash.

Usage:
    python tools/liquefy_events.py emit   --agent-id a1 --session-id s1 --event model_call --model gpt-4o --input-tokens 500
    python tools/liquefy_events.py query  --session-id s1 --json
    python tools/liquefy_events.py spans  --session-id s1 --json
    python tools/liquefy_events.py stats  --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

SCHEMA = "liquefy.events.v1"

EVENT_TYPES = {
    "model_call", "tool_call", "tool_result", "agent_start", "agent_end",
    "session_start", "session_end", "error", "retry", "escalation",
    "handoff", "checkpoint", "policy_violation", "custom",
}


def _events_dir() -> Path:
    d = Path(os.environ.get("LIQUEFY_EVENTS_DIR", str(Path.home() / ".liquefy" / "events")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _session_file(session_id: str) -> Path:
    return _events_dir() / f"{session_id}.jsonl"


def _prompt_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _span_id() -> str:
    return uuid.uuid4().hex[:12]


def emit_event(
    agent_id: str,
    session_id: str,
    event_type: str,
    span_id: Optional[str] = None,
    parent_span_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    model: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    cost_usd: Optional[float] = None,
    duration_ms: Optional[int] = None,
    tool_name: Optional[str] = None,
    tool_input_ref: Optional[str] = None,
    tool_output_ref: Optional[str] = None,
    prompt_hash: Optional[str] = None,
    context_hash: Optional[str] = None,
    error: Optional[str] = None,
    retry_count: Optional[int] = None,
    metadata: Optional[Dict] = None,
) -> Dict:
    """Emit a structured agent event to the session trace."""
    sid = span_id or _span_id()
    ts = datetime.now(timezone.utc).isoformat()

    event = {
        "schema": SCHEMA,
        "ts": ts,
        "agent_id": agent_id,
        "session_id": session_id,
        "span_id": sid,
        "event": event_type,
    }

    if parent_span_id:
        event["parent_span_id"] = parent_span_id
    if trace_id:
        event["trace_id"] = trace_id

    if model:
        event["model"] = model
    if input_tokens is not None:
        event["input_tokens"] = input_tokens
    if output_tokens is not None:
        event["output_tokens"] = output_tokens
    if cost_usd is not None:
        event["cost_usd"] = cost_usd
    if duration_ms is not None:
        event["duration_ms"] = duration_ms

    if tool_name:
        event["tool_name"] = tool_name
    if tool_input_ref:
        event["tool_input_ref"] = tool_input_ref
    if tool_output_ref:
        event["tool_output_ref"] = tool_output_ref

    if prompt_hash:
        event["prompt_hash"] = prompt_hash
    if context_hash:
        event["context_hash"] = context_hash

    if error:
        event["error"] = error
    if retry_count is not None:
        event["retry_count"] = retry_count
    if metadata:
        event["metadata"] = metadata

    sf = _session_file(session_id)
    with sf.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")

    return event


def query_session(session_id: str, event_type: Optional[str] = None,
                  limit: int = 100) -> List[Dict]:
    sf = _session_file(session_id)
    if not sf.exists():
        return []

    events = []
    with sf.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if event_type is None or e.get("event") == event_type:
                    events.append(e)
            except json.JSONDecodeError:
                continue

    return events[-limit:]


def build_span_tree(session_id: str) -> Dict:
    """Build a parent-child span tree from session events."""
    events = query_session(session_id, limit=10000)
    spans: Dict[str, Dict] = {}
    roots: List[str] = []

    for e in events:
        sid = e.get("span_id", "")
        if sid not in spans:
            spans[sid] = {"span_id": sid, "events": [], "children": []}
        spans[sid]["events"].append(e)

        parent = e.get("parent_span_id")
        if parent:
            if parent not in spans:
                spans[parent] = {"span_id": parent, "events": [], "children": []}
            if sid not in spans[parent]["children"]:
                spans[parent]["children"].append(sid)
        elif sid not in roots:
            roots.append(sid)

    return {"session_id": session_id, "root_spans": roots, "spans": spans, "total_events": len(events)}


def session_stats(session_id: str) -> Dict:
    events = query_session(session_id, limit=100000)
    if not events:
        return {"ok": False, "error": "Session not found or empty"}

    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0
    total_duration = 0
    model_calls = 0
    tool_calls = 0
    errors = 0
    retries = 0
    models_used: set = set()
    tools_used: set = set()
    prompt_hashes: set = set()

    for e in events:
        if e.get("event") == "model_call":
            model_calls += 1
            total_input_tokens += e.get("input_tokens", 0)
            total_output_tokens += e.get("output_tokens", 0)
            total_cost += e.get("cost_usd", 0)
            total_duration += e.get("duration_ms", 0)
            if e.get("model"):
                models_used.add(e["model"])
            if e.get("prompt_hash"):
                prompt_hashes.add(e["prompt_hash"])
        elif e.get("event") == "tool_call":
            tool_calls += 1
            if e.get("tool_name"):
                tools_used.add(e["tool_name"])
        elif e.get("event") == "error":
            errors += 1
        elif e.get("event") == "retry":
            retries += 1

    unique_prompts = len(prompt_hashes)
    duplicate_prompts = model_calls - unique_prompts if model_calls > unique_prompts else 0

    return {
        "ok": True,
        "session_id": session_id,
        "total_events": len(events),
        "model_calls": model_calls,
        "tool_calls": tool_calls,
        "errors": errors,
        "retries": retries,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_cost_usd": round(total_cost, 6),
        "total_duration_ms": total_duration,
        "models_used": sorted(models_used),
        "tools_used": sorted(tools_used),
        "unique_prompts": unique_prompts,
        "duplicate_prompts": duplicate_prompts,
    }


def list_sessions() -> List[Dict]:
    """List all known sessions."""
    events_dir = _events_dir()
    sessions = []
    for f in sorted(events_dir.glob("*.jsonl")):
        sid = f.stem
        size = f.stat().st_size
        line_count = sum(1 for _ in f.open())
        sessions.append({"session_id": sid, "events": line_count, "bytes": size})
    return sessions


def cmd_emit(args: argparse.Namespace) -> int:
    trace_id = args.trace_id or os.environ.get("LIQUEFY_TRACE_ID")
    ph = _prompt_hash(args.prompt) if args.prompt else None

    event = emit_event(
        agent_id=args.agent_id,
        session_id=args.session_id,
        event_type=args.event,
        parent_span_id=args.parent_span,
        trace_id=trace_id,
        model=args.model,
        input_tokens=args.input_tokens,
        output_tokens=args.output_tokens,
        duration_ms=args.duration_ms,
        tool_name=args.tool_name,
        prompt_hash=ph,
        error=args.error,
    )

    if args.json:
        print(json.dumps(event, indent=2))
    else:
        print(f"  Event emitted: {event['event']} (span: {event['span_id']})")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    events = query_session(args.session_id, args.event_type, args.limit)
    if args.json:
        print(json.dumps(events, indent=2))
    else:
        print(f"  Session {args.session_id}: {len(events)} events")
        for e in events:
            ts = e.get("ts", "?")[:19]
            print(f"    [{ts}] {e.get('event')} span={e.get('span_id', '?')[:8]}")
    return 0


def cmd_spans(args: argparse.Namespace) -> int:
    tree = build_span_tree(args.session_id)
    if args.json:
        print(json.dumps(tree, indent=2, default=str))
    else:
        print(f"  Session {args.session_id}: {tree['total_events']} events, {len(tree['root_spans'])} root spans")
        for root_id in tree["root_spans"]:
            _print_span_tree(tree["spans"], root_id, indent=4)
    return 0


def _print_span_tree(spans: Dict, span_id: str, indent: int = 0):
    span = spans.get(span_id, {})
    events = span.get("events", [])
    first = events[0] if events else {}
    label = first.get("event", "?")
    model = first.get("model", "")
    tool = first.get("tool_name", "")
    detail = model or tool or ""
    prefix = " " * indent
    print(f"{prefix}{span_id[:8]} [{label}] {detail}")
    for child_id in span.get("children", []):
        _print_span_tree(spans, child_id, indent + 2)


def cmd_stats(args: argparse.Namespace) -> int:
    if args.session_id:
        stats = session_stats(args.session_id)
    else:
        sessions = list_sessions()
        stats = {"ok": True, "sessions": sessions, "total": len(sessions)}

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        if args.session_id:
            if not stats.get("ok"):
                print(f"  Session not found: {args.session_id}")
                return 1
            print(f"  Session Stats: {args.session_id}")
            print(f"    Events:        {stats['total_events']}")
            print(f"    Model calls:   {stats['model_calls']}")
            print(f"    Tool calls:    {stats['tool_calls']}")
            print(f"    Errors:        {stats['errors']}")
            print(f"    Input tokens:  {stats['total_input_tokens']:,}")
            print(f"    Output tokens: {stats['total_output_tokens']:,}")
            print(f"    Cost:          ${stats['total_cost_usd']:.4f}")
            print(f"    Dup prompts:   {stats['duplicate_prompts']}")
        else:
            print(f"  Sessions: {stats['total']}")
            for s in stats.get("sessions", []):
                print(f"    {s['session_id']}: {s['events']} events")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-events",
        description="Structured agent event traces with span tree.",
    )
    sub = parser.add_subparsers(dest="command")

    p_emit = sub.add_parser("emit", help="Emit a structured agent event")
    p_emit.add_argument("--agent-id", required=True)
    p_emit.add_argument("--session-id", required=True)
    p_emit.add_argument("--event", required=True, help=f"Event type: {', '.join(sorted(EVENT_TYPES))}")
    p_emit.add_argument("--parent-span", help="Parent span ID")
    p_emit.add_argument("--trace-id", help="Multi-agent correlation ID")
    p_emit.add_argument("--model", help="Model name")
    p_emit.add_argument("--input-tokens", type=int)
    p_emit.add_argument("--output-tokens", type=int)
    p_emit.add_argument("--duration-ms", type=int)
    p_emit.add_argument("--tool-name", help="Tool name for tool_call events")
    p_emit.add_argument("--prompt", help="Prompt text (hashed, not stored)")
    p_emit.add_argument("--error", help="Error message")
    p_emit.add_argument("--json", action="store_true")

    p_query = sub.add_parser("query", help="Query session events")
    p_query.add_argument("--session-id", required=True)
    p_query.add_argument("--event-type", help="Filter by event type")
    p_query.add_argument("--limit", type=int, default=100)
    p_query.add_argument("--json", action="store_true")

    p_spans = sub.add_parser("spans", help="Build span tree from session")
    p_spans.add_argument("--session-id", required=True)
    p_spans.add_argument("--json", action="store_true")

    p_stats = sub.add_parser("stats", help="Session statistics or list all")
    p_stats.add_argument("--session-id", help="Specific session (omit for list)")
    p_stats.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"emit": cmd_emit, "query": cmd_query, "spans": cmd_spans, "stats": cmd_stats}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
