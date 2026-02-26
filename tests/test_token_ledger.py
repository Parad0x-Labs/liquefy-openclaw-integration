"""Tests for liquefy_token_ledger.py — token usage tracking [EXPERIMENTAL]."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_token_ledger import (
    _extract_usage_from_line,
    _scan_file,
    _scan_directory,
    _estimate_cost,
    _normalize_model,
    _load_model_costs,
    BUILTIN_MODEL_COSTS_PER_1K,
    cmd_scan,
    cmd_budget,
    cmd_report,
    cmd_audit,
    cmd_models,
)


class _Args:
    def __init__(self, **kwargs):
        self.json = True
        self.dir = ""
        self.org = "default"
        self.daily = None
        self.monthly = None
        self.daily_cost = None
        self.monthly_cost = None
        self.warn = None
        self.period = "all"
        for k, v in kwargs.items():
            setattr(self, k, v)


def _openai_entry(prompt_tokens=100, completion_tokens=50, model="gpt-4o"):
    return {
        "model": model,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def _anthropic_entry(input_tokens=200, output_tokens=80, model="claude-3.5-sonnet"):
    return {
        "model": model,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    }


class TestExtractUsage:
    def test_openai_format(self):
        data = _openai_entry(100, 50, "gpt-4o")
        result = _extract_usage_from_line(data)
        assert result is not None
        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 50
        assert result["total_tokens"] == 150
        assert "gpt-4o" in result["model"]

    def test_anthropic_format(self):
        data = _anthropic_entry(200, 80, "claude-3.5-sonnet")
        result = _extract_usage_from_line(data)
        assert result is not None
        assert result["input_tokens"] == 200
        assert result["output_tokens"] == 80

    def test_nested_response_usage(self):
        data = {"response": {"model": "gpt-4", "usage": {"prompt_tokens": 50, "completion_tokens": 25, "total_tokens": 75}}}
        result = _extract_usage_from_line(data)
        assert result is not None
        assert result["total_tokens"] == 75

    def test_no_usage_returns_none(self):
        data = {"message": "hello", "role": "user"}
        result = _extract_usage_from_line(data)
        assert result is None

    def test_zero_tokens_returns_none(self):
        data = {"usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        result = _extract_usage_from_line(data)
        assert result is None

    def test_prompt_hash_generated(self):
        data = {**_openai_entry(), "messages": [{"role": "user", "content": "hello"}]}
        result = _extract_usage_from_line(data)
        assert result["prompt_hash"] is not None
        assert len(result["prompt_hash"]) == 16

    def test_same_prompt_same_hash(self):
        msg = [{"role": "user", "content": "test prompt"}]
        r1 = _extract_usage_from_line({**_openai_entry(), "messages": msg})
        r2 = _extract_usage_from_line({**_openai_entry(), "messages": msg})
        assert r1["prompt_hash"] == r2["prompt_hash"]

    def test_different_prompt_different_hash(self):
        r1 = _extract_usage_from_line({**_openai_entry(), "messages": [{"role": "user", "content": "a"}]})
        r2 = _extract_usage_from_line({**_openai_entry(), "messages": [{"role": "user", "content": "b"}]})
        assert r1["prompt_hash"] != r2["prompt_hash"]


class TestEstimateCost:
    def test_gpt4o_cost(self):
        cost = _estimate_cost("gpt-4o", 1000, 1000)
        assert cost > 0
        mini_cost = _estimate_cost("gpt-4o-mini", 1000, 1000)
        assert cost > mini_cost

    def test_gpt4o_mini_cheaper(self):
        c1 = _estimate_cost("gpt-4", 1000, 1000)
        c2 = _estimate_cost("gpt-4o-mini", 1000, 1000)
        assert c2 < c1

    def test_unknown_model_uses_default(self):
        cost = _estimate_cost("some-random-model", 1000, 1000)
        assert cost > 0

    def test_zero_tokens_zero_cost(self):
        assert _estimate_cost("gpt-4o", 0, 0) == 0.0


class TestNormalizeModel:
    def test_lowercase(self):
        assert _normalize_model("GPT-4o") == "gpt-4o"

    def test_underscore_to_dash(self):
        assert _normalize_model("gpt_4_turbo") == "gpt-4-turbo"

    def test_empty_string(self):
        assert _normalize_model("") == "unknown"

    def test_whitespace(self):
        assert _normalize_model("  gpt-4o  ") == "gpt-4o"


class TestScanFile:
    def test_scan_jsonl(self, tmp_path):
        f = tmp_path / "trace.jsonl"
        lines = [json.dumps(_openai_entry(100, 50)) + "\n", json.dumps(_openai_entry(200, 100)) + "\n"]
        f.write_text("".join(lines))
        entries = _scan_file(f)
        assert len(entries) == 2
        assert entries[0]["input_tokens"] == 100
        assert entries[1]["input_tokens"] == 200

    def test_scan_json_array(self, tmp_path):
        f = tmp_path / "trace.json"
        data = [_openai_entry(100, 50), _openai_entry(200, 100)]
        f.write_text(json.dumps(data))
        entries = _scan_file(f)
        assert len(entries) == 2

    def test_scan_mixed_lines(self, tmp_path):
        f = tmp_path / "trace.jsonl"
        lines = [
            json.dumps({"message": "hello"}) + "\n",
            json.dumps(_openai_entry(100, 50)) + "\n",
            "not json at all\n",
            json.dumps(_anthropic_entry(200, 80)) + "\n",
        ]
        f.write_text("".join(lines))
        entries = _scan_file(f)
        assert len(entries) == 2

    def test_scan_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        entries = _scan_file(f)
        assert len(entries) == 0


class TestScanDirectory:
    def test_finds_nested_logs(self, tmp_path):
        sub = tmp_path / "runs" / "run_001"
        sub.mkdir(parents=True)
        (sub / "trace.jsonl").write_text(json.dumps(_openai_entry(100, 50)) + "\n")
        (sub / "log.jsonl").write_text(json.dumps(_anthropic_entry(200, 80)) + "\n")
        entries = _scan_directory(tmp_path)
        assert len(entries) == 2

    def test_skips_venv(self, tmp_path):
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "trace.jsonl").write_text(json.dumps(_openai_entry()) + "\n")
        (tmp_path / "real.jsonl").write_text(json.dumps(_openai_entry()) + "\n")
        entries = _scan_directory(tmp_path)
        assert len(entries) == 1

    def test_empty_dir(self, tmp_path):
        entries = _scan_directory(tmp_path)
        assert len(entries) == 0


class TestCmdScan:
    def test_scan_with_data(self, tmp_path, capsys):
        (tmp_path / "trace.jsonl").write_text(
            json.dumps(_openai_entry(1000, 500, "gpt-4o")) + "\n"
            + json.dumps(_openai_entry(2000, 1000, "gpt-4o")) + "\n"
        )
        args = _Args(dir=str(tmp_path))
        ret = cmd_scan(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True
        assert output["experimental"] is True
        assert output["entries"] == 2
        assert output["total_tokens"] == 4500
        assert output["estimated_cost_usd"] > 0

    def test_scan_empty(self, tmp_path, capsys):
        args = _Args(dir=str(tmp_path))
        ret = cmd_scan(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["entries"] == 0

    def test_scan_nonexistent(self, tmp_path, capsys):
        args = _Args(dir=str(tmp_path / "nope"))
        ret = cmd_scan(args)
        assert ret == 1


class TestCmdBudget:
    def test_set_budget(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        args = _Args(org="acme", daily=500000, monthly=10000000)
        ret = cmd_budget(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True
        assert output["daily_tokens"] == 500000

    def test_budget_file_created(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        args = _Args(org="test", daily=100000)
        cmd_budget(args)
        budget_path = tmp_path / ".liquefy" / "tokens" / "budgets.json"
        assert budget_path.exists()
        data = json.loads(budget_path.read_text())
        assert "test" in data


class TestCmdAudit:
    def test_detects_duplicate_prompts(self, tmp_path, capsys):
        msg = [{"role": "user", "content": "same prompt"}]
        lines = [json.dumps({**_openai_entry(500, 100), "messages": msg}) + "\n"] * 5
        (tmp_path / "trace.jsonl").write_text("".join(lines))

        args = _Args(dir=str(tmp_path))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["issues_found"] >= 1
        assert any(i["type"] == "duplicate_prompt" for i in output["issues"])

    def test_detects_oversized_context(self, tmp_path, capsys):
        (tmp_path / "trace.jsonl").write_text(
            json.dumps(_openai_entry(150000, 500)) + "\n"
        )
        args = _Args(dir=str(tmp_path))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert any(i["type"] == "oversized_context" for i in output["issues"])

    def test_detects_model_overkill(self, tmp_path, capsys):
        (tmp_path / "trace.jsonl").write_text(
            json.dumps(_openai_entry(100, 20, "gpt-4")) + "\n"
        )
        args = _Args(dir=str(tmp_path))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert any(i["type"] == "model_overkill" for i in output["issues"])

    def test_clean_usage_no_issues(self, tmp_path, capsys):
        (tmp_path / "trace.jsonl").write_text(
            json.dumps(_openai_entry(2000, 500, "gpt-4o-mini")) + "\n"
        )
        args = _Args(dir=str(tmp_path))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["wasted_tokens"] == 0

    def test_empty_dir(self, tmp_path, capsys):
        args = _Args(dir=str(tmp_path))
        ret = cmd_audit(args)
        assert ret == 0


class TestModelCosts:
    def test_builtin_has_gpt5(self):
        assert "gpt-5" in BUILTIN_MODEL_COSTS_PER_1K

    def test_builtin_has_claude_4_6(self):
        assert "claude-4.6-opus" in BUILTIN_MODEL_COSTS_PER_1K

    def test_builtin_has_gemini(self):
        assert "gemini-2.0-flash" in BUILTIN_MODEL_COSTS_PER_1K

    def test_builtin_has_deepseek(self):
        assert "deepseek-r1" in BUILTIN_MODEL_COSTS_PER_1K

    def test_load_merges_custom(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        custom_dir = tmp_path / ".liquefy" / "tokens"
        custom_dir.mkdir(parents=True)
        (custom_dir / "model_costs.json").write_text(json.dumps({
            "my-custom-model": {"input": 0.001, "output": 0.002},
        }))
        costs = _load_model_costs()
        assert "my-custom-model" in costs
        assert "gpt-4o" in costs

    def test_custom_overrides_builtin(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        custom_dir = tmp_path / ".liquefy" / "tokens"
        custom_dir.mkdir(parents=True)
        (custom_dir / "model_costs.json").write_text(json.dumps({
            "gpt-4o": {"input": 0.999, "output": 0.999},
        }))
        costs = _load_model_costs()
        assert costs["gpt-4o"]["input"] == 0.999

    def test_env_var_override(self, tmp_path, monkeypatch):
        custom_file = tmp_path / "my_costs.json"
        custom_file.write_text(json.dumps({
            "env-model": {"input": 0.01, "output": 0.02},
        }))
        monkeypatch.setenv("LIQUEFY_MODEL_COSTS", str(custom_file))
        costs = _load_model_costs()
        assert "env-model" in costs

    def test_cmd_models_list(self, capsys):
        args = _Args(add=None)
        ret = cmd_models(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True
        assert output["builtin_models"] > 20
        assert "gpt-5" in output["models"]

    def test_cmd_models_add(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        args = _Args(add="future-model:0.01:0.03")
        ret = cmd_models(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["added"] == "future-model"
        custom_file = tmp_path / ".liquefy" / "tokens" / "model_costs.json"
        assert custom_file.exists()
        data = json.loads(custom_file.read_text())
        assert "future-model" in data
