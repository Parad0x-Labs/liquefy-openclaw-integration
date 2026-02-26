"""Tests for liquefy_telemetry_forward.py — SIEM forwarding."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_telemetry_forward import (
    _format_event,
    _load_events_from,
    _send_file,
    _load_state,
    _save_state,
    cmd_test,
    cmd_status,
    SCHEMA,
)


class _Args:
    def __init__(self, **kwargs):
        self.json = True
        self.webhook = None
        self.syslog = None
        self.file = None
        self.token = None
        self.interval = 10
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture
def chain_file(tmp_path):
    chain = tmp_path / "chain.jsonl"
    entries = [
        {"seq": 0, "ts": "2026-02-25T10:00:00Z", "event": "compress", "_hash": "aaa"},
        {"seq": 1, "ts": "2026-02-25T10:01:00Z", "event": "verify", "_hash": "bbb"},
        {"seq": 2, "ts": "2026-02-25T10:02:00Z", "event": "pack", "_hash": "ccc"},
    ]
    with chain.open("w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return chain


class TestFormatEvent:
    def test_has_schema(self):
        event = {"seq": 0, "ts": "2026-01-01T00:00:00Z", "event": "test"}
        formatted = _format_event(event)
        assert formatted["schema"] == SCHEMA
        assert formatted["source"] == "liquefy"
        assert formatted["event"] == "test"

    def test_preserves_data(self):
        event = {"seq": 5, "ts": "2026-01-01T00:00:00Z", "event": "compress", "extra": "value"}
        formatted = _format_event(event)
        assert formatted["data"]["extra"] == "value"
        assert formatted["seq"] == 5

    def test_includes_trace_id(self):
        event = {"seq": 0, "ts": "2026-01-01T00:00:00Z", "event": "pack", "trace_id": "agent-chain-99"}
        formatted = _format_event(event)
        assert formatted["trace_id"] == "agent-chain-99"

    def test_omits_trace_id_when_absent(self):
        event = {"seq": 0, "ts": "2026-01-01T00:00:00Z", "event": "pack"}
        formatted = _format_event(event)
        assert "trace_id" not in formatted


class TestLoadEvents:
    def test_load_all(self, chain_file):
        events = _load_events_from(chain_file, 0)
        assert len(events) == 3

    def test_load_from_cursor(self, chain_file):
        events = _load_events_from(chain_file, 2)
        assert len(events) == 1
        assert events[0]["seq"] == 2

    def test_cursor_past_end(self, chain_file):
        events = _load_events_from(chain_file, 100)
        assert len(events) == 0


class TestSendFile:
    def test_creates_file(self, tmp_path):
        outfile = tmp_path / "events.jsonl"
        events = [
            {"event": "test1", "ts": "2026-01-01T00:00:00Z"},
            {"event": "test2", "ts": "2026-01-01T00:01:00Z"},
        ]
        result = _send_file(outfile, events)
        assert result["ok"] is True
        assert result["sent"] == 2
        assert outfile.exists()
        lines = outfile.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_appends_to_existing(self, tmp_path):
        outfile = tmp_path / "events.jsonl"
        outfile.write_text('{"event": "old"}\n')
        events = [{"event": "new"}]
        result = _send_file(outfile, events)
        assert result["ok"] is True
        lines = outfile.read_text().strip().split("\n")
        assert len(lines) == 2


class TestState:
    def test_load_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        state = _load_state()
        assert state["cursor"] == 0
        assert state["events_sent"] == 0

    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        state = {"cursor": 5, "last_push": "2026-01-01T00:00:00Z", "events_sent": 100, "errors": 2}
        _save_state(state)
        loaded = _load_state()
        assert loaded["cursor"] == 5
        assert loaded["events_sent"] == 100


class TestCmdTest:
    def test_file_destination(self, tmp_path, capsys):
        outfile = tmp_path / "test_events.jsonl"
        args = _Args(file=str(outfile))
        ret = cmd_test(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True
        assert outfile.exists()

    def test_no_destination_fails(self, capsys):
        args = _Args()
        ret = cmd_test(args)
        assert ret == 1


class TestCmdStatus:
    def test_status_no_chain(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        args = _Args()
        ret = cmd_status(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True
        assert output["cursor"] == 0
