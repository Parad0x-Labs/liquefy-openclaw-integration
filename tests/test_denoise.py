"""Tests for liquefy_denoise.py — semantic log de-noising."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

from liquefy_denoise import (
    _classify_line,
    _filter_lines,
    cmd_extract,
    cmd_filter,
    cmd_stats,
)


def _ns(**kw):
    from types import SimpleNamespace
    defaults = {"json": False, "out": None, "context": 3, "keep_neutral": False, "trace_id": None}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestClassifyLine:
    def test_error_is_signal(self):
        cls, name = _classify_line("2026-02-25 ERROR: database connection failed")
        assert cls == "signal"
        assert name == "error"

    def test_warning_is_signal(self):
        cls, name = _classify_line("WARN: request timed out after 30s")
        assert cls == "signal"
        assert name == "warning"

    def test_500_is_signal(self):
        cls, name = _classify_line('GET /api/users HTTP/1.1" 500 Internal Server Error')
        assert cls == "signal"
        assert name in ("http_5xx", "error")

    def test_403_is_signal(self):
        cls, name = _classify_line('POST /admin HTTP/1.1" 403 Forbidden')
        assert cls == "signal"
        assert name == "http_4xx"

    def test_200_is_noise(self):
        cls, name = _classify_line('GET /api/health HTTP/1.1" 200 OK')
        assert cls == "noise"

    def test_heartbeat_is_noise(self):
        cls, name = _classify_line("2026-02-25 10:00:00 heartbeat ok")
        assert cls == "noise"
        assert name == "heartbeat"

    def test_health_endpoint_is_noise(self):
        cls, name = _classify_line("GET /healthz 200 0.002s")
        assert cls == "noise"
        assert name == "health_endpoint"

    def test_debug_is_noise(self):
        cls, name = _classify_line("DEBUG entering function parse_config")
        assert cls == "noise"
        assert name == "debug_trace"

    def test_static_asset_is_noise(self):
        cls, name = _classify_line("GET /assets/style.css 200 0.5ms")
        assert cls == "noise"

    def test_normal_line_is_neutral(self):
        cls, name = _classify_line("Processing batch 42 of 100")
        assert cls == "neutral"
        assert name is None

    def test_payment_is_signal(self):
        cls, name = _classify_line("Payment of $450,000 processed for user lobster")
        assert cls == "signal"
        assert name == "money"

    def test_crash_is_signal(self):
        cls, name = _classify_line("Process crashed with SIGSEGV")
        assert cls == "signal"
        assert name == "crash"

    def test_security_is_signal(self):
        cls, name = _classify_line("Request denied: invalid token")
        assert cls == "signal"
        assert name == "security"


class TestFilterLines:
    def test_keeps_errors_drops_noise(self):
        lines = [
            "GET /health 200 OK",
            "GET /health 200 OK",
            "GET /health 200 OK",
            "ERROR: disk full",
            "GET /health 200 OK",
            "GET /health 200 OK",
        ]
        kept, signals, noise = _filter_lines(lines, context=1)
        assert any("ERROR" in l for l in kept)
        assert signals.get("error", 0) == 1
        assert noise.get("http_200", 0) + noise.get("health_endpoint", 0) > 0
        assert len(kept) < len(lines)

    def test_context_preserved(self):
        lines = [
            "line 0 normal",
            "line 1 normal",
            "line 2 ERROR crash happened",
            "line 3 stack trace here",
            "line 4 normal",
        ]
        kept, _, _ = _filter_lines(lines, context=2)
        error_kept = [l for l in kept if "ERROR" in l]
        assert len(error_kept) == 1
        context_kept = [l for l in kept if "line 1" in l or "line 3" in l]
        assert len(context_kept) >= 1

    def test_all_noise_produces_summary(self):
        lines = ["heartbeat ok"] * 100
        kept, _, noise = _filter_lines(lines, context=0)
        assert len(kept) <= 2
        assert noise.get("heartbeat", 0) == 100

    def test_all_signal_kept(self):
        lines = [
            "ERROR: first failure",
            "WARN: retrying",
            "ERROR: second failure",
        ]
        kept, signals, _ = _filter_lines(lines, context=0)
        assert sum(1 for l in kept if "ERROR" in l or "WARN" in l) == 3


class TestFilterCommand:
    def test_filter_to_output_dir(self, tmp_path, capsys):
        src = tmp_path / "logs"
        src.mkdir()
        (src / "server.log").write_text(
            "GET /healthz 200\n" * 50 +
            "ERROR: connection refused\n" +
            "GET /healthz 200\n" * 50
        )
        out = tmp_path / "filtered"
        rc = cmd_filter(_ns(path=str(src), out=str(out), json=True, context=2))
        assert rc == 0
        result = json.loads(capsys.readouterr().out)
        assert result["result"]["overall_reduction_pct"] > 50
        filtered = (out / "server.log").read_text()
        assert "ERROR" in filtered
        assert filtered.count("GET /healthz 200") < 50


class TestStatsCommand:
    def test_stats_reports_ratios(self, tmp_path, capsys):
        (tmp_path / "app.log").write_text(
            "heartbeat ok\n" * 90 +
            "ERROR: something broke\n" * 5 +
            "processing item\n" * 5
        )
        rc = cmd_stats(_ns(path=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["noise_pct"] > 80
        assert out["result"]["signal_lines"] == 5


class TestExtractCommand:
    def test_extract_by_trace_id(self, tmp_path, capsys):
        (tmp_path / "trace.log").write_text(
            "normal line\n"
            "trace-abc ERROR: handler failed\n"
            "trace-abc stack: line 42\n"
            "unrelated line\n"
            "trace-xyz ERROR: different issue\n"
        )
        rc = cmd_extract(_ns(
            path=str(tmp_path), trace_id="trace-abc", context=1, json=True,
        ))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["clusters_found"] == 1
        cluster = out["result"]["clusters"][0]
        assert cluster["signal_type"] == "error"
        assert any("trace-abc" in line for line in cluster["context"])
