#!/usr/bin/env python3
"""Tests for OpenClaw Trace Vault integration."""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from openclaw_tracevault import resolve_state_dir, is_denied, cmd_list

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "openclaw_state"


class TestDenylist:
    """Denylist must block credentials, keys, and config files."""

    def test_credentials_dir_blocked(self):
        p = FIXTURES / "credentials" / "api_keys.txt"
        assert is_denied(p, FIXTURES) is True

    def test_openclaw_json_blocked(self):
        p = FIXTURES / "openclaw.json"
        assert is_denied(p, FIXTURES) is True

    def test_key_extension_blocked(self):
        fake = FIXTURES / "agents" / "a1" / "server.key"
        assert is_denied(fake, FIXTURES) is True

    def test_pem_extension_blocked(self):
        fake = FIXTURES / "agents" / "a1" / "cert.pem"
        assert is_denied(fake, FIXTURES) is True

    def test_env_file_blocked(self):
        fake = FIXTURES / ".env"
        assert is_denied(fake, FIXTURES) is True

    def test_session_file_allowed(self):
        p = FIXTURES / "agents" / "a1" / "sessions" / "session1.jsonl"
        assert is_denied(p, FIXTURES) is False

    def test_nested_session_allowed(self):
        p = FIXTURES / "agents" / "a1" / "sessions" / "session2.jsonl"
        assert is_denied(p, FIXTURES) is False


class TestResolveStateDir:
    """State dir resolution: explicit > env > default."""

    def test_explicit_wins(self, tmp_path):
        result = resolve_state_dir(str(tmp_path))
        assert result == tmp_path.resolve()

    def test_env_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENCLAW_STATE_DIR", str(tmp_path))
        result = resolve_state_dir(None)
        assert result == tmp_path.resolve()

    def test_default_home(self, monkeypatch):
        monkeypatch.delenv("OPENCLAW_STATE_DIR", raising=False)
        result = resolve_state_dir(None)
        assert result == Path.home() / ".openclaw"


class TestListAgents:
    """List command should detect agents with sessions."""

    def test_lists_agent_a1(self, capsys):
        cmd_list(FIXTURES)
        out = capsys.readouterr().out
        assert "a1" in out
        assert "2 sessions" in out
