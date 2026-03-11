from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from liquefy_context_capsule import prime_workspace
from liquefy_context_gate import compile_context_gate, context_gate_history


def _make_workspace(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    history = workspace / "history"
    history.mkdir(parents=True)
    (workspace / "SOUL.md").write_text("You are helpful but ruthless about context waste.\n", encoding="utf-8")
    (workspace / "HEARTBEAT.md").write_text("interval: 30s\nsentinel: required\n", encoding="utf-8")
    (workspace / "auth-profiles.json").write_text(json.dumps({
        "default": {"provider": "openai", "model": "gpt-4o-mini"},
    }), encoding="utf-8")
    (history / "session.jsonl").write_text(
        "\n".join(
            [
                json.dumps({
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "summarize the same trace again"}],
                    "usage": {"prompt_tokens": 1800, "completion_tokens": 120, "total_tokens": 1920},
                    "output": {"text": "done"},
                })
                for _ in range(3)
            ]
        ) + "\n",
        encoding="utf-8",
    )
    return workspace, history


def test_compile_context_gate_writes_manifest_and_env(tmp_path):
    workspace, history = _make_workspace(tmp_path)
    prime_workspace(workspace, history)

    result = compile_context_gate(
        workspace,
        "openclaw run task.md",
        token_budget=1200,
        block_replay=False,
        trace_dir=history,
    )

    assert result["blocked"] is False
    assert result["included_tokens"] <= 1200
    assert result["included_blocks"] >= 2
    assert Path(result["prompt_file"]).exists()
    assert Path(result["json_file"]).exists()
    assert Path(result["history_file"]).exists()
    assert Path(result["env"]["LIQUEFY_CONTEXT_GATE_FILE"]).exists()
    payload = json.loads(Path(result["json_file"]).read_text(encoding="utf-8"))
    assert payload["summary"]["context_fingerprint"] == result["context_fingerprint"]


def test_context_gate_blocks_exact_replay_when_enabled(tmp_path):
    workspace, history = _make_workspace(tmp_path)
    prime_workspace(workspace, history)

    first = compile_context_gate(
        workspace,
        "openclaw run task.md",
        token_budget=1200,
        block_replay=True,
        trace_dir=history,
    )
    second = compile_context_gate(
        workspace,
        "openclaw run task.md",
        token_budget=1200,
        block_replay=True,
        trace_dir=history,
    )

    assert first["blocked"] is False
    assert first["replay_detected"] is False
    assert second["replay_detected"] is True
    assert second["replay_within_window"] is True
    assert second["blocked"] is True
    assert second["block_reason"] == "exact_replay_detected"


def test_context_gate_blocks_when_required_context_cannot_fit(tmp_path):
    workspace, history = _make_workspace(tmp_path)
    prime_workspace(workspace, history)

    result = compile_context_gate(
        workspace,
        "openclaw run task.md",
        token_budget=10,
        block_replay=False,
        trace_dir=history,
    )

    assert result["blocked"] is True
    assert result["block_reason"] == "required_context_exceeds_budget"


def test_context_gate_history_reports_seen_entries(tmp_path):
    workspace, history = _make_workspace(tmp_path)
    prime_workspace(workspace, history)
    compile_context_gate(workspace, "openclaw run task.md", token_budget=1200, trace_dir=history)

    result = context_gate_history(workspace)
    assert result["ok"] is True
    assert len(result["entries"]) == 1
    assert result["entries"][0]["seen_count"] == 1
