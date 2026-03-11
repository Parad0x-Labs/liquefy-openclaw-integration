from __future__ import annotations

import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "skills" / "liquefy_token_guard"))

import trigger as token_guard


def _openai_entry(prompt_tokens=100, completion_tokens=50, model="gpt-4o", messages=None):
    payload = {
        "model": model,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }
    if messages is not None:
        payload["messages"] = messages
    return payload


def _write_config(
    tmp_path: Path,
    trace_dir: Path,
    workspace_dir: Path | None = None,
    *,
    apply_budget_on_status: bool = False,
) -> Path:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "trace_dir": str(trace_dir),
        "workspace_dir": str(workspace_dir or trace_dir),
        "org": "acme",
        "period": "today",
        "capsule_out_dir": str(tmp_path / "capsules"),
        "daily_tokens": 1000,
        "monthly_tokens": 5000,
        "warn_at_percent": 80,
        "auto_scan_on_status": True,
        "apply_budget_on_status": apply_budget_on_status,
    }), encoding="utf-8")
    return config_path


def test_status_combines_scan_report_and_audit(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "trace.jsonl").write_text(
        json.dumps(_openai_entry(200, 50, "gpt-4o-mini")) + "\n",
        encoding="utf-8",
    )
    config_path = _write_config(tmp_path, trace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    budget_result = token_guard.cmd_set_budget(token_guard._load_config())
    assert budget_result["ok"] is True

    result = token_guard.cmd_status(token_guard._load_config())
    assert result["ok"] is True
    assert result["scan"]["ok"] is True
    assert result["report"]["ok"] is True
    assert result["audit"]["ok"] is True
    assert "recommendations" in result
    assert result["report"]["truth"]["quota"]["mode"] == "manual"
    assert result["capsule_state"]["status"] in {"missing", "fresh"}
    assert result["scoreboard"]["ok"] is True


def test_status_does_not_write_budget_without_opt_in(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "trace.jsonl").write_text(
        json.dumps(_openai_entry(200, 50, "gpt-4o-mini")) + "\n",
        encoding="utf-8",
    )
    config_path = _write_config(tmp_path, trace_dir, apply_budget_on_status=False)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_status(token_guard._load_config())
    assert result["ok"] is True
    assert result["report"]["truth"]["quota"]["mode"] == "unavailable"
    assert not (tmp_path / ".liquefy" / "tokens" / "budgets.json").exists()


def test_recommend_flags_duplicate_prompt_waste(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    msg = [{"role": "user", "content": "same prompt"}]
    lines = [json.dumps(_openai_entry(500, 100, "gpt-4o", messages=msg)) + "\n"] * 3
    (trace_dir / "trace.jsonl").write_text("".join(lines), encoding="utf-8")
    config_path = _write_config(tmp_path, trace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_recommend(token_guard._load_config())
    assert result["ok"] is True
    titles = [item["title"] for item in result["recommendations"]]
    assert "Dedupe repeated prompts" in titles


def test_set_budget_writes_budget_file(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    config_path = _write_config(tmp_path, trace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_set_budget(token_guard._load_config())
    assert result["ok"] is True
    budget_file = tmp_path / ".liquefy" / "tokens" / "budgets.json"
    assert budget_file.exists()


def test_build_capsule_emits_reduction_report(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "repeat me"}],
        "usage": {"prompt_tokens": 200, "completion_tokens": 40, "total_tokens": 240},
        "output": {"text": "ok"},
    }
    (trace_dir / "trace.jsonl").write_text(
        json.dumps(payload) + "\n" + json.dumps(payload) + "\n",
        encoding="utf-8",
    )
    config_path = _write_config(tmp_path, trace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_build_capsule(token_guard._load_config())
    assert result["ok"] is True
    assert result["result"]["reduction_pct"] >= 0
    assert Path(result["result"]["json_path"]).exists()


def test_prime_next_run_installs_bootstrap(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (trace_dir / "trace.jsonl").write_text(
        json.dumps(_openai_entry(300, 60, "gpt-4o-mini")) + "\n",
        encoding="utf-8",
    )
    config_path = _write_config(tmp_path, trace_dir, workspace_dir=workspace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_prime_next_run(token_guard._load_config())
    assert result["ok"] is True
    assert Path(result["result"]["bootstrap_file"]).exists()
    assert Path(result["result"]["manifest_file"]).exists()
    assert result["result"]["scoreboard"]["summary"]["unique_runs"] == 1


def test_daily_guard_marks_estimated_cost_truth_in_message(tmp_path, monkeypatch):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "trace.jsonl").write_text(
        json.dumps(_openai_entry(300, 60, "gpt-4o-mini")) + "\n",
        encoding="utf-8",
    )
    config_path = _write_config(tmp_path, trace_dir)
    monkeypatch.setenv("OPENCLAW_SKILL_CONFIG", str(config_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = token_guard.cmd_daily_guard(token_guard._load_config())
    assert result["ok"] is True
    assert "cost truth estimated" in result["message"]
