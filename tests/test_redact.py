"""Tests for liquefy_redact.py — PII and secret redaction."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

from liquefy_redact import (
    _build_active_patterns,
    _redact_content,
    _redact_line,
    cmd_apply,
    cmd_profile,
    cmd_scan,
)


def _ns(**kw):
    from types import SimpleNamespace
    defaults = {"json": False, "categories": None, "include_wallets": False, "out": None}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestRedactLine:
    def test_email_redacted(self):
        line = "Contact user@example.com for details"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_EMAIL]" in result
        assert "user@example.com" not in result
        assert any(h["type"] == "email" for h in hits)

    def test_ipv4_redacted(self):
        line = "Server at 192.168.1.100 responded"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_IP]" in result
        assert "192.168.1.100" not in result

    def test_aws_key_redacted(self):
        line = "key=AKIAIOSFODNN7EXAMPLE"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_AWS_KEY]" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_github_token_redacted(self):
        line = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_GITHUB_TOKEN]" in result

    def test_bearer_token_redacted(self):
        line = 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc'
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_BEARER]" in result

    def test_generic_secret_redacted(self):
        line = 'password=SuperSecretPass123!'
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_SECRET]" in result
        assert "SuperSecretPass123!" not in result

    def test_eth_address_redacted(self):
        line = "Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_ETH_ADDR]" in result

    def test_ssn_redacted(self):
        line = "SSN: 123-45-6789"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_SSN]" in result
        assert "123-45-6789" not in result

    def test_clean_line_unchanged(self):
        line = "This is a normal log line with no PII"
        patterns = _build_active_patterns()
        result, hits = _redact_line(line, patterns)
        assert result == line
        assert len(hits) == 0

    def test_solana_not_redacted_by_default(self):
        line = "Addr: 7nYBm5mPkWoVdzDBSoTXhF7xHMbVuy7PoGfWGkJFBETz"
        patterns = _build_active_patterns(include_wallets=False)
        result, hits = _redact_line(line, patterns)
        assert "REDACTED_SOL_ADDR" not in result

    def test_solana_redacted_with_flag(self):
        line = "Addr: 7nYBm5mPkWoVdzDBSoTXhF7xHMbVuy7PoGfWGkJFBETz"
        patterns = _build_active_patterns(include_wallets=True)
        result, hits = _redact_line(line, patterns)
        assert "[REDACTED_SOL_ADDR]" in result


class TestRedactContent:
    def test_multi_line(self):
        content = "user@test.com logged in\nIP: 10.0.0.1\nAll good"
        patterns = _build_active_patterns()
        result, hits = _redact_content(content, patterns)
        assert "[REDACTED_EMAIL]" in result
        assert "[REDACTED_IP]" in result
        assert "All good" in result
        assert len(hits) >= 2

    def test_category_filter(self):
        content = "user@test.com and 10.0.0.1"
        patterns = _build_active_patterns(categories=["email"])
        result, hits = _redact_content(content, patterns)
        assert "[REDACTED_EMAIL]" in result
        assert "10.0.0.1" in result


class TestScanCommand:
    def test_scan_finds_pii(self, tmp_path, capsys):
        (tmp_path / "data.log").write_text("user@example.com connected from 10.0.0.5\n")
        rc = cmd_scan(_ns(path=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"]
        assert out["result"]["total_hits"] >= 2
        assert out["result"]["files_with_pii"] == 1

    def test_scan_clean_dir(self, tmp_path, capsys):
        (tmp_path / "clean.log").write_text("nothing sensitive here\n")
        rc = cmd_scan(_ns(path=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["total_hits"] == 0


class TestApplyCommand:
    def test_apply_to_output_dir(self, tmp_path, capsys):
        src = tmp_path / "src"
        src.mkdir()
        (src / "data.log").write_text("Email: admin@corp.com\nServer: 172.16.0.1\nOK\n")
        out = tmp_path / "redacted"

        rc = cmd_apply(_ns(path=str(src), out=str(out), json=True))
        assert rc == 0
        result = json.loads(capsys.readouterr().out)
        assert result["result"]["files_redacted"] == 1

        redacted_content = (out / "data.log").read_text()
        assert "admin@corp.com" not in redacted_content
        assert "172.16.0.1" not in redacted_content
        assert "[REDACTED_EMAIL]" in redacted_content
        assert "[REDACTED_IP]" in redacted_content
        assert "OK" in redacted_content

    def test_apply_preserves_clean_files(self, tmp_path, capsys):
        src = tmp_path / "src"
        src.mkdir()
        (src / "clean.log").write_text("All systems normal\n")
        out = tmp_path / "out"

        cmd_apply(_ns(path=str(src), out=str(out), json=True))
        assert (out / "clean.log").read_text() == "All systems normal\n"


class TestProfileCommand:
    def test_profile_reports_density(self, tmp_path, capsys):
        (tmp_path / "mixed.log").write_text(
            "user@a.com\n10.0.0.1\nclean\nuser@b.com\n"
        )
        rc = cmd_profile(_ns(path=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["files_with_pii"] == 1
        assert out["result"]["density_hits_per_file"] > 0
        assert "email" in out["result"]["type_breakdown"]
