"""Tests for liquefy_events.py — structured agent event traces."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_events import (
    emit_event,
    query_session,
    build_span_tree,
    session_stats,
    list_sessions,
    _prompt_hash,
    _span_id,
    SCHEMA,
)


@pytest.fixture(autouse=True)
def isolated_events(tmp_path, monkeypatch):
    events_dir = tmp_path / "events"
    events_dir.mkdir()
    monkeypatch.setenv("LIQUEFY_EVENTS_DIR", str(events_dir))
    return events_dir


class TestEmitEvent:
    def test_basic_emit(self):
        e = emit_event("agent-1", "sess-1", "model_call", model="gpt-4o",
                       input_tokens=500, output_tokens=100)
        assert e["schema"] == SCHEMA
        assert e["agent_id"] == "agent-1"
        assert e["session_id"] == "sess-1"
        assert e["event"] == "model_call"
        assert e["model"] == "gpt-4o"
        assert e["input_tokens"] == 500
        assert len(e["span_id"]) == 12

    def test_with_parent_span(self):
        parent = emit_event("a1", "s1", "agent_start")
        child = emit_event("a1", "s1", "model_call", parent_span_id=parent["span_id"])
        assert child["parent_span_id"] == parent["span_id"]

    def test_with_trace_id(self):
        e = emit_event("a1", "s1", "tool_call", trace_id="chain-42", tool_name="browser")
        assert e["trace_id"] == "chain-42"
        assert e["tool_name"] == "browser"

    def test_with_prompt_hash(self):
        e = emit_event("a1", "s1", "model_call", prompt_hash=_prompt_hash("hello world"))
        assert len(e["prompt_hash"]) == 16

    def test_error_event(self):
        e = emit_event("a1", "s1", "error", error="timeout after 30s", retry_count=2)
        assert e["error"] == "timeout after 30s"
        assert e["retry_count"] == 2

    def test_persists_to_file(self, isolated_events):
        emit_event("a1", "s1", "model_call")
        emit_event("a1", "s1", "tool_call")
        sf = isolated_events / "s1.jsonl"
        assert sf.exists()
        lines = sf.read_text().strip().split("\n")
        assert len(lines) == 2


class TestQuerySession:
    def test_query_all(self):
        emit_event("a1", "s1", "model_call")
        emit_event("a1", "s1", "tool_call")
        emit_event("a1", "s1", "model_call")
        events = query_session("s1")
        assert len(events) == 3

    def test_query_by_type(self):
        emit_event("a1", "s1", "model_call")
        emit_event("a1", "s1", "tool_call")
        emit_event("a1", "s1", "model_call")
        events = query_session("s1", event_type="tool_call")
        assert len(events) == 1

    def test_query_empty_session(self):
        events = query_session("nonexistent")
        assert events == []

    def test_query_limit(self):
        for i in range(10):
            emit_event("a1", "s1", "model_call")
        events = query_session("s1", limit=3)
        assert len(events) == 3


class TestSpanTree:
    def test_flat_spans(self):
        emit_event("a1", "s1", "model_call")
        emit_event("a1", "s1", "tool_call")
        tree = build_span_tree("s1")
        assert tree["total_events"] == 2
        assert len(tree["root_spans"]) == 2

    def test_parent_child(self):
        parent = emit_event("a1", "s1", "agent_start")
        emit_event("a1", "s1", "model_call", parent_span_id=parent["span_id"])
        emit_event("a1", "s1", "tool_call", parent_span_id=parent["span_id"])
        tree = build_span_tree("s1")
        assert len(tree["root_spans"]) == 1
        root = tree["spans"][parent["span_id"]]
        assert len(root["children"]) == 2


class TestSessionStats:
    def test_basic_stats(self):
        emit_event("a1", "s1", "model_call", model="gpt-4o",
                   input_tokens=1000, output_tokens=200, cost_usd=0.01, duration_ms=500,
                   prompt_hash=_prompt_hash("prompt1"))
        emit_event("a1", "s1", "model_call", model="gpt-4o",
                   input_tokens=800, output_tokens=150, cost_usd=0.008, duration_ms=400,
                   prompt_hash=_prompt_hash("prompt2"))
        emit_event("a1", "s1", "tool_call", tool_name="browser")
        emit_event("a1", "s1", "error", error="timeout")

        stats = session_stats("s1")
        assert stats["ok"] is True
        assert stats["model_calls"] == 2
        assert stats["tool_calls"] == 1
        assert stats["errors"] == 1
        assert stats["total_input_tokens"] == 1800
        assert stats["total_output_tokens"] == 350
        assert stats["models_used"] == ["gpt-4o"]
        assert stats["tools_used"] == ["browser"]

    def test_duplicate_prompt_detection(self):
        ph = _prompt_hash("same prompt")
        emit_event("a1", "s1", "model_call", prompt_hash=ph)
        emit_event("a1", "s1", "model_call", prompt_hash=ph)
        emit_event("a1", "s1", "model_call", prompt_hash=_prompt_hash("different"))

        stats = session_stats("s1")
        assert stats["unique_prompts"] == 2
        assert stats["duplicate_prompts"] == 1

    def test_empty_session(self):
        stats = session_stats("nonexistent")
        assert stats["ok"] is False


class TestListSessions:
    def test_lists_sessions(self):
        emit_event("a1", "s1", "model_call")
        emit_event("a1", "s2", "model_call")
        emit_event("a1", "s2", "tool_call")
        sessions = list_sessions()
        assert len(sessions) == 2
        s2 = next(s for s in sessions if s["session_id"] == "s2")
        assert s2["events"] == 2


class TestHelpers:
    def test_prompt_hash_deterministic(self):
        h1 = _prompt_hash("hello world")
        h2 = _prompt_hash("hello world")
        assert h1 == h2
        assert len(h1) == 16

    def test_prompt_hash_different(self):
        assert _prompt_hash("a") != _prompt_hash("b")

    def test_span_id_unique(self):
        ids = {_span_id() for _ in range(100)}
        assert len(ids) == 100
