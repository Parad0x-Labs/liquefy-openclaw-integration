from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from liquefy_context_capsule import BOOTSTRAP_FILENAME, build_capsule, inspect_workspace_capsule, load_scoreboard, prime_workspace


def _usage_entry(prompt_tokens: int, completion_tokens: int, *, model: str = "gpt-4o", prompt: str = "same prompt"):
    return {
        "event": "model_call",
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
        "output": {"text": "ok"},
    }


def test_build_capsule_reduces_trace_surface(tmp_path: Path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()

    repeated = [json.dumps(_usage_entry(1200, 80)) + "\n" for _ in range(3)]
    tool_call = json.dumps({
        "eventName": "ToolCall",
        "tool": "web_search",
        "input": {"query": "liquefy capsule"},
        "output": {"results": 4},
        "duration_ms": 142,
        "eventTime": "2026-03-11T12:00:00Z",
    }) + "\n"
    (trace_dir / "session.jsonl").write_text("".join(repeated) + tool_call, encoding="utf-8")

    noise_lines = ["heartbeat ok" for _ in range(200)]
    noise_lines.append("ERROR database timeout on upstream")
    (trace_dir / "worker.log").write_text("\n".join(noise_lines) + "\n", encoding="utf-8")

    capsule = build_capsule(trace_dir, str(tmp_path / "capsule_out"))
    summary = capsule["summary"]

    assert summary["token_entries"] == 3
    assert summary["reduction_pct"] > 50
    assert Path(summary["json_path"]).exists()
    assert Path(summary["markdown_path"]).exists()
    assert any(item["tool"] == "web_search" for item in capsule["bootstrap"]["top_tools"])
    assert any("Identical prompt sent 3 times" in issue["message"] for issue in capsule["bootstrap"]["issues"])
    assert any(rec["title"] == "Collapse repeated prompts" for rec in capsule["recommendations"])
    assert "LIQUEFY CONTEXT CAPSULE" in capsule["prompt_bootstrap"]
    assert capsule["summary"]["truth"]["cost"]["mode"] == "estimated"


def test_build_capsule_collects_text_signals_without_token_metadata(tmp_path: Path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "app.log").write_text(
        "heartbeat ok\nheartbeat ok\nWARN retrying after timeout\nERROR worker failed\n",
        encoding="utf-8",
    )

    capsule = build_capsule(trace_dir)
    relevant = capsule["relevant"]
    assert relevant
    assert any(item["kind"] == "log_signal" for item in relevant)
    assert capsule["summary"]["files_scanned"] >= 1


def test_prime_workspace_installs_bootstrap_files(tmp_path: Path):
    workspace = tmp_path / "workspace"
    trace_dir = workspace / "trace"
    trace_dir.mkdir(parents=True)
    (trace_dir / "session.jsonl").write_text(
        json.dumps(_usage_entry(500, 50, prompt="repeat me")) + "\n",
        encoding="utf-8",
    )

    primed = prime_workspace(workspace, trace_dir)
    bootstrap = Path(primed["bootstrap_file"])
    manifest = Path(primed["manifest_file"])

    assert bootstrap.exists()
    assert bootstrap.name == BOOTSTRAP_FILENAME
    assert "LIQUEFY CONTEXT CAPSULE" in bootstrap.read_text(encoding="utf-8")
    assert manifest.exists()
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["env"]["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"] == str(bootstrap)


def test_build_capsule_is_deterministic_for_same_trace(tmp_path: Path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "session.jsonl").write_text(
        "".join(
            [
                json.dumps(_usage_entry(1200, 80, prompt="repeatable prompt")) + "\n",
                json.dumps(_usage_entry(1200, 80, prompt="repeatable prompt")) + "\n",
                json.dumps(
                    {
                        "eventName": "ToolCall",
                        "tool": "file_read",
                        "input": {"path": "foo.md"},
                        "output": {"bytes": 128},
                    }
                )
                + "\n",
            ]
        ),
        encoding="utf-8",
    )
    (trace_dir / "worker.log").write_text(
        "heartbeat ok\nWARN retrying after timeout\nERROR upstream failed\n",
        encoding="utf-8",
    )

    first = build_capsule(trace_dir, str(tmp_path / "out1"))
    second = build_capsule(trace_dir, str(tmp_path / "out2"))

    assert first["prompt_bootstrap"] == second["prompt_bootstrap"]
    assert first["summary"]["reduction_pct"] == second["summary"]["reduction_pct"]
    assert first["summary"]["total_tokens"] == second["summary"]["total_tokens"]
    assert first["recommendations"] == second["recommendations"]
    assert first["bootstrap"]["top_tools"] == second["bootstrap"]["top_tools"]


def test_prime_workspace_records_replay_aware_scoreboard(tmp_path: Path):
    workspace = tmp_path / "workspace"
    trace_dir = workspace / "history"
    trace_dir.mkdir(parents=True)
    (trace_dir / "session.jsonl").write_text(
        json.dumps(_usage_entry(700, 70, prompt="same prompt")) + "\n",
        encoding="utf-8",
    )

    first = prime_workspace(workspace, trace_dir)
    second = prime_workspace(workspace, trace_dir)
    scoreboard = load_scoreboard(workspace)

    assert first["replay_detected"] is False
    assert second["replay_detected"] is True
    assert scoreboard["summary"]["unique_runs"] == 1
    assert scoreboard["summary"]["total_prime_events"] == 2
    assert scoreboard["summary"]["replayed_prime_events"] == 1


def test_verify_detects_stale_capsule_when_trace_changes(tmp_path: Path):
    workspace = tmp_path / "workspace"
    trace_dir = workspace / "history"
    trace_dir.mkdir(parents=True)
    session = trace_dir / "session.jsonl"
    session.write_text(
        json.dumps(_usage_entry(500, 50, prompt="first")) + "\n",
        encoding="utf-8",
    )

    prime_workspace(workspace, trace_dir)
    fresh = inspect_workspace_capsule(workspace, trace_dir)
    assert fresh["status"] == "fresh"

    session.write_text(
        json.dumps(_usage_entry(800, 80, prompt="changed")) + "\n",
        encoding="utf-8",
    )
    stale = inspect_workspace_capsule(workspace, trace_dir)
    assert stale["status"] == "stale"
    assert stale["trace_fingerprint_match"] is False
