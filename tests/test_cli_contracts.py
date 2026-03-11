#!/usr/bin/env python3
"""CLI JSON contract tests for plugin-facing scan/dry-run commands."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_json(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        raise AssertionError(f"stdout was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


def _run_json_no_check(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    payload = None
    if proc.stdout.strip():
        try:
            payload = json.loads(proc.stdout)
        except Exception as exc:
            raise AssertionError(f"stdout was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc, payload


def _make_guarded_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
    (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
    (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")
    return workspace


def test_tracevault_pack_scan_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(REPO_ROOT / "tools" / "fixtures"),
        "--out", "/tmp/tracevault_cli_contract_scan",
        "--scan-only",
        "--profile", "speed",
        "--json",
    ])

    assert payload["schema_version"] == "liquefy.tracevault.cli.v1"
    assert payload["tool"] == "tracevault_pack"
    assert payload["command"] == "scan"
    assert payload["ok"] is True
    assert payload["profile"] == "speed"
    result = payload["result"]
    assert isinstance(result, dict)
    assert result["version"] == "tracevault-scan-v1"
    assert isinstance(result.get("included"), list)
    assert isinstance(result.get("skipped"), list)
    assert isinstance(result.get("path_policy_skipped"), list)
    assert result.get("touched_paths") == []


def test_tracevault_pack_runtime_version_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        "--version",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.tracevault.cli.v1"
    assert payload["tool"] == "tracevault_pack"
    assert payload["command"] == "version"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-version-v1"
    assert "build" in payload["result"]


def test_tracevault_pack_runtime_doctor_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        "--doctor",
        "--scan-only",
        "--json",
    ])
    assert payload["command"] == "doctor"
    assert payload["ok"] is True
    result = payload["result"]
    assert result["version"] == "liquefy-cli-doctor-v1"
    assert "summary" in result and "checks" in result


def test_tracevault_pack_print_effective_policy_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(REPO_ROOT / "tools" / "fixtures"),
        "--out", "/tmp/tracevault_cli_contract_policy",
        "--json",
        "--print-effective-policy",
    ])
    assert payload["schema_version"] == "liquefy.tracevault.cli.v1"
    assert payload["tool"] == "tracevault_pack"
    assert payload["command"] == "policy"
    assert payload["ok"] is True
    result = payload["result"]
    assert result["policy"]["mode"] == "strict"
    eff = result["effective_rules"]
    assert isinstance(eff["deny"], list)
    assert isinstance(eff["allow"], list)
    assert isinstance(eff["allow_categories"], list)
    assert isinstance(eff["precedence"], list)


def test_tracevault_pack_explain_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(REPO_ROOT / "tools" / "fixtures"),
        "--out", "/tmp/tracevault_cli_contract_explain",
        "--json",
        "--explain", "demo.pem",
    ])
    assert payload["command"] == "policy"
    explain = payload["result"]["explain"]
    assert explain["decision"] == "DENY"
    assert explain["reason_code"] == "PRIVATE_KEY_FILE"
    assert explain["requires_override"] is True
    assert explain["category"] == "PRIVATE_KEY_FILE"
    assert isinstance(explain.get("matched_rule"), dict)


def test_tracevault_restore_json_reports_output_limit(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "sample.txt").write_text("hello world\n" * 8, encoding="utf-8")
    vault_dir = tmp_path / "vault"
    out_dir = tmp_path / "restore"

    pack_payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(run_dir),
        "--out", str(vault_dir),
        "--no-encrypt",
        "--no-verify",
        "--json",
    ])
    assert pack_payload["ok"] is True

    proc, payload = _run_json_no_check([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_restore.py"),
        str(vault_dir),
        "--out", str(out_dir),
        "--json",
        "--max-output-bytes", "1",
    ])
    assert proc.returncode != 0
    assert payload is not None
    assert payload["schema_version"] == "liquefy.tracevault.restore.cli.v1"
    assert payload["tool"] == "tracevault_restore"
    assert payload["command"] == "restore"
    assert payload["ok"] is False
    assert payload["exit_code"] == 1
    assert payload["vault_name"] == vault_dir.name
    assert payload["out_dir_name"] == out_dir.name
    assert payload["error"]["code"] == "restore_output_limit"
    assert payload["error"]["max_output_bytes"] == 1


def test_tracevault_restore_runtime_self_test_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_restore.py"),
        "--self-test",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.tracevault.restore.cli.v1"
    assert payload["tool"] == "tracevault_restore"
    assert payload["command"] == "self_test"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-self-test-v1"


def test_liquefy_openclaw_dry_run_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_scan",
        "--dry-run",
        "--profile", "ratio",
        "--json",
    ])

    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "scan"
    assert payload["ok"] is True
    assert payload["dry_run"] is True
    assert payload["profile"] == "ratio"
    result = payload["result"]
    assert result["version"] == "openclaw-scan-v1"
    assert result.get("touched_paths") == []
    summary = result["summary"]
    assert "denied_files_count" in summary
    assert "eligible_files" in summary
    denied = result["denied_files"]
    assert isinstance(denied, list)
    if denied:
        assert "reason" in denied[0]


def test_liquefy_openclaw_runtime_doctor_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--doctor",
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_doctor",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "doctor"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-doctor-v1"


def test_liquefy_openclaw_run_command_is_declared_in_schema():
    schema = json.loads((REPO_ROOT / "schemas" / "liquefy.openclaw.cli.v1.json").read_text(encoding="utf-8"))
    assert "run" in schema["properties"]["command"]["enum"]


def test_liquefy_openclaw_print_effective_policy_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_policy",
        "--json",
        "--print-effective-policy",
    ])
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "policy"
    assert payload["ok"] is True
    eff = payload["result"]["effective_rules"]
    assert isinstance(eff["deny"], list)
    assert isinstance(eff["precedence"], list)


def test_liquefy_openclaw_explain_allow_category_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_explain",
        "--json",
        "--allow-category", "ENV_FILE",
        "--explain", ".env",
    ])
    assert payload["command"] == "policy"
    explain = payload["result"]["explain"]
    assert explain["decision"] == "ALLOW"
    assert explain["category"] == "ENV_FILE"
    assert explain["reason_code"] in {"allow_category", "allow_rule", "not_denied_by_mode"}


def test_liquefy_context_gate_compile_json_contract(tmp_path):
    workspace = _make_guarded_workspace(tmp_path)
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_context_gate.py"),
        "compile",
        "--workspace", str(workspace),
        "--cmd", "openclaw run",
        "--json",
    ])

    assert payload["schema_version"] == "liquefy.context-gate.v1"
    assert payload["tool"] == "liquefy_context_gate"
    assert payload["command"] == "compile"
    assert payload["ok"] is True
    result = payload["result"]
    assert result["blocked"] is False
    assert Path(result["prompt_file"]).exists()
    assert Path(result["json_file"]).exists()


def test_liquefy_context_gate_history_json_contract(tmp_path):
    workspace = _make_guarded_workspace(tmp_path)
    _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_context_gate.py"),
        "compile",
        "--workspace", str(workspace),
        "--cmd", "openclaw run",
        "--json",
    ])

    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_context_gate.py"),
        "history",
        "--workspace", str(workspace),
        "--json",
    ])

    assert payload["schema_version"] == "liquefy.context-gate.v1"
    assert payload["tool"] == "liquefy_context_gate"
    assert payload["command"] == "history"
    assert payload["ok"] is True
    assert len(payload["result"]["entries"]) == 1


def test_liquefy_safe_run_json_contract(tmp_path):
    workspace = _make_guarded_workspace(tmp_path)
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_safe_run.py"),
        "--workspace", str(workspace),
        "--cmd", f"{shlex.quote(sys.executable)} -c {shlex.quote('print(123)')}",
        "--no-capsule",
        "--json",
    ])

    assert payload["schema"] == "liquefy.safe-run.v2"
    assert payload["ok"] is True
    assert payload["heartbeat_active"] is False
    assert payload["needs_rollback"] is False
    assert payload["phases"]["context_gate"]["ok"] is True
    assert payload["phases"]["context_gate"]["blocked"] is False


def test_tracevault_pack_json_pack_requires_secret():
    env = dict(os.environ)
    env.pop("LIQUEFY_SECRET", None)
    proc, payload = _run_json_no_check([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(REPO_ROOT / "tools" / "fixtures"),
        "--out", "/tmp/tracevault_cli_contract_pack_missing_secret",
        "--json",
    ], env=env)

    assert proc.returncode != 0
    assert payload is not None
    assert payload["schema_version"] == "liquefy.tracevault.cli.v1"
    assert payload["tool"] == "tracevault_pack"
    assert payload["command"] == "pack"
    assert payload["ok"] is False
    assert "MISSING_SECRET" in payload["error"]


def test_tracevault_pack_include_secrets_requires_exact_phrase():
    proc, payload = _run_json_no_check([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(REPO_ROOT / "tools" / "fixtures"),
        "--out", "/tmp/tracevault_cli_contract_bad_phrase",
        "--scan-only",
        "--json",
        "--include-secrets", "nope",
    ])
    assert proc.returncode != 0
    assert payload is not None
    assert payload["tool"] == "tracevault_pack"
    assert payload["ok"] is False
    assert "OVERRIDE_PHRASE_REQUIRED" in payload["error"]


def test_tracevault_pack_json_pack_writes_manifest_metadata_signature_and_hash_cache(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "note.txt").write_text("hello world\n" * 32, encoding="utf-8")
    out_dir = tmp_path / "vault"

    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_pack.py"),
        str(run_dir),
        "--out", str(out_dir),
        "--no-encrypt",
        "--no-verify",
        "--hash-cache",
        "--sign",
        "--json",
    ])
    assert payload["ok"] is True
    result = payload["result"]
    manifest_path = Path(result["manifest_path"])
    run_metadata_path = Path(result["run_metadata_path"])
    sig_path = Path(result["signature_path"])
    assert manifest_path.exists()
    assert run_metadata_path.exists()
    assert sig_path.exists()
    assert result["hash_cache_enabled"] is True
    assert result["signed"] is True
    assert (run_dir / ".liquefy" / "hash_cache.json").exists()


def test_liquefy_sign_cli_json_contract(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "tracevault_index.json").write_text(json.dumps({"version": "tracevault-index-v2"}), encoding="utf-8")
    (vault / "vault_manifest.json").write_text(json.dumps({"vault_id": "v1", "included": []}), encoding="utf-8")
    (vault / "run_metadata.json").write_text(json.dumps({"vault_id": "v1"}), encoding="utf-8")
    key_path = tmp_path / "signing.key"

    sign_payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_sign.py"),
        "sign",
        str(vault),
        "--key-path", str(key_path),
        "--json",
    ])
    assert sign_payload["schema_version"] == "liquefy.sign.cli.v1"
    assert sign_payload["tool"] == "liquefy_sign"
    assert sign_payload["command"] == "sign"
    assert sign_payload["ok"] is True

    verify_payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_sign.py"),
        "verify-signature",
        str(vault),
        "--key-path", str(key_path),
        "--json",
    ])
    assert verify_payload["schema_version"] == "liquefy.sign.cli.v1"
    assert verify_payload["tool"] == "liquefy_sign"
    assert verify_payload["command"] == "verify-signature"
    assert verify_payload["ok"] is True


def test_liquefy_openclaw_secure_pack_requires_secret_json():
    env = dict(os.environ)
    env.pop("LIQUEFY_SECRET", None)
    proc, payload = _run_json_no_check([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_pack_missing_secret",
        "--apply",
        "--secure",
        "--json",
    ], env=env)

    assert proc.returncode != 0
    assert payload is not None
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "pack"
    assert payload["ok"] is False
    assert payload["secure"] is True
    assert "MISSING_SECRET" in payload["error"]


def test_liquefy_openclaw_include_secrets_requires_exact_phrase():
    proc, payload = _run_json_no_check([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_bad_phrase",
        "--dry-run",
        "--json",
        "--include-secrets", "nope",
    ])
    assert proc.returncode != 0
    assert payload is not None
    assert payload["ok"] is False
    assert "OVERRIDE_PHRASE_REQUIRED" in payload["error"]


def test_liquefy_openclaw_include_secrets_with_phrase_reports_risky_files():
    phrase = "I UNDERSTAND THIS MAY LEAK SECRETS"
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "--workspace", str(REPO_ROOT / "tests" / "fixtures" / "openclaw_state"),
        "--out", "/tmp/openclaw_cli_contract_good_phrase",
        "--dry-run",
        "--json",
        "--include-secrets", phrase,
    ])
    assert payload["ok"] is True
    result = payload["result"]
    assert result["policy"]["include_secrets"] is True
    assert result["policy"]["include_secrets_phrase_ok"] is True
    assert result["risk_summary"]["risky_files_included"] >= 2
    assert isinstance(result.get("risky_files"), list)


def test_liquefy_openclaw_run_json_contract(tmp_path):
    workspace = tmp_path / "openclaw_run_contract"
    workspace.mkdir()
    (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
    (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
    (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")
    (workspace / "trace.jsonl").write_text(
        json.dumps(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "repeat me"}],
                "usage": {"prompt_tokens": 600, "completion_tokens": 60, "total_tokens": 660},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    payload_file = workspace / "seen_env.json"
    code = (
        "import json, os, pathlib; "
        "keys=['LIQUEFY_CONTEXT_BOOTSTRAP_FILE','LIQUEFY_CONTEXT_CAPSULE_JSON','LIQUEFY_CONTEXT_REDUCTION_PCT','LIQUEFY_CONTEXT_GATE_FILE','LIQUEFY_CONTEXT_GATE_JSON']; "
        f"pathlib.Path({str(payload_file)!r}).write_text(json.dumps({{k: os.environ.get(k) for k in keys}}))"
    )
    wrapped_cmd = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"

    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
        "run",
        "--workspace", str(workspace),
        "--cmd", wrapped_cmd,
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "run"
    assert payload["ok"] is True
    assert payload["wrapper"] == "liquefy_safe_run"
    assert payload["defaults"]["capsule_enabled"] is True
    assert payload["defaults"]["context_gate_enabled"] is True
    assert payload["defaults"]["replay_blocking_enabled"] is True
    assert payload["result"]["ok"] is True
    assert payload["result"]["phases"]["prime_context"]["ok"] is True
    assert payload["result"]["phases"]["capsule_state"]["status"] == "fresh"
    assert payload["result"]["phases"]["context_gate"]["ok"] is True
    assert payload["result"]["phases"]["context_gate"]["blocked"] is False
    assert payload["result"]["heartbeat_active"] is True
    seen_env = json.loads(payload_file.read_text(encoding="utf-8"))
    assert Path(seen_env["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"]).exists()
    assert Path(seen_env["LIQUEFY_CONTEXT_GATE_FILE"]).exists()


def test_unified_liquefy_cli_version_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_cli.py"),
        "version",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.cli.v1"
    assert payload["tool"] == "liquefy"
    assert payload["command"] == "version"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-version-v1"


def test_unified_liquefy_cli_self_test_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_cli.py"),
        "self-test",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.cli.v1"
    assert payload["tool"] == "liquefy"
    assert payload["command"] == "self_test"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-self-test-v1"


def test_unified_liquefy_cli_doctor_json_contract():
    payload = _run_json([
        sys.executable,
        str(REPO_ROOT / "tools" / "liquefy_cli.py"),
        "doctor",
        "--json",
    ])
    assert payload["schema_version"] == "liquefy.cli.v1"
    assert payload["tool"] == "liquefy"
    assert payload["command"] == "doctor"
    assert payload["ok"] is True
    assert payload["result"]["version"] == "liquefy-cli-doctor-v1"
