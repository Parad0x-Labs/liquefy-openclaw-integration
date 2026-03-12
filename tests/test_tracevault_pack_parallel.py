from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _make_jsonl_rows(lines: int) -> str:
    rows = []
    for idx in range(lines):
        rows.append(
            json.dumps(
                {
                    "eventVersion": "1.08",
                    "session": f"sess_{idx % 7}",
                    "trace": f"trace_{idx}",
                    "tool": "bash" if idx % 2 else "web_search",
                    "payload": {
                        "status": "success",
                        "data": "A" * 512,
                        "tokens_in": 1000 + idx,
                        "tokens_out": 200 + (idx % 31),
                    },
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(rows) + "\n"


def test_tracevault_pack_parallel_json_files_succeeds(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "sessions").mkdir(parents=True)
    (run_dir / "tool_trace").mkdir(parents=True)
    (run_dir / "sessions" / "session_0001.jsonl").write_text(_make_jsonl_rows(1500), encoding="utf-8")
    (run_dir / "sessions" / "session_0002.jsonl").write_text(_make_jsonl_rows(1500), encoding="utf-8")
    (run_dir / "tool_trace" / "tool_trace.jsonl").write_text(_make_jsonl_rows(1800), encoding="utf-8")

    out_dir = tmp_path / "vault"
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "tracevault_pack.py"),
            str(run_dir),
            "--org",
            "bench",
            "--out",
            str(out_dir),
            "--no-encrypt",
            "--verify-mode",
            "fast",
            "--workers",
            "4",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    result = payload["result"]
    assert result["files_processed"] == 3
    assert result["files_skipped"] == 0
