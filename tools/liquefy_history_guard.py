#!/usr/bin/env python3
"""
liquefy_history_guard.py
========================
Continuous backup + anti-nuke guard for external comms/data platforms.

What it does:
- Pull authorized exports from configured providers on a schedule.
- Pack pulled exports into Liquefy vaults (compression + encryption + optional signing).
- Gate risky actions with pre-action snapshots and approval token checks.

This tool is local-first and does not call external APIs directly. It runs user-provided
provider pull commands that write exported data to local paths.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"

CLI_SCHEMA_VERSION = "liquefy.history-guard.cli.v1"
CONFIG_SCHEMA = "liquefy.history-guard.config.v1"
STATE_SCHEMA = "liquefy.history-guard.state.v1"

DEFAULT_RISKY_PATTERNS = [
    r"\bdelete\b",
    r"\bremove\b",
    r"\brm\b",
    r"\bpurge\b",
    r"\bwipe\b",
    r"\bdrop\b",
    r"\bban\b",
    r"\bkick\b",
    r"\brevoke\b",
    r"\bdisable\b",
]


@dataclass
class CommandResult:
    rc: int
    command: str
    stdout_tail: str
    stderr_tail: str
    duration_ms: int



def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")



def _compact_tail(text: str, max_chars: int = 2000) -> str:
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]



def _emit(command: str, ok: bool, result: Dict[str, Any], json_file: Optional[Path] = None) -> None:
    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "liquefy_history_guard",
        "command": command,
        "ok": bool(ok),
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    rendered = json.dumps(payload, indent=2)
    if json_file is not None:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        json_file.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)



def _default_paths(workspace: Path) -> Dict[str, Path]:
    liq = workspace / ".liquefy"
    return {
        "config": liq / "history_guard.json",
        "state": liq / "history_guard_state.json",
    }



def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))



def _save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")



def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()



def _safe_provider_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "-", raw.strip())
    return cleaned[:96] or "provider"



def _validate_config(cfg: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if cfg.get("schema") != CONFIG_SCHEMA:
        errors.append(f"invalid schema: {cfg.get('schema')}")

    providers = cfg.get("providers", [])
    if not isinstance(providers, list):
        errors.append("providers must be a list")
        return errors

    seen: set[str] = set()
    for p in providers:
        pid = str(p.get("id", "")).strip()
        if not pid:
            errors.append("provider id is required")
            continue
        if pid in seen:
            errors.append(f"duplicate provider id: {pid}")
        seen.add(pid)
        if not isinstance(p.get("pull_command", ""), str):
            errors.append(f"provider {pid}: pull_command must be a string")
    return errors



def _load_config(workspace: Path, config_path: Optional[Path] = None) -> tuple[Optional[Dict[str, Any]], Optional[Path], Optional[str]]:
    paths = _default_paths(workspace)
    cpath = config_path or paths["config"]
    if not cpath.exists():
        return None, cpath, f"config not found: {cpath}"

    try:
        cfg = _load_json(cpath)
    except Exception as exc:
        return None, cpath, f"invalid config JSON: {exc}"

    errors = _validate_config(cfg)
    if errors:
        return None, cpath, "config validation failed: " + "; ".join(errors)

    return cfg, cpath, None



def _load_state(state_path: Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {
            "schema": STATE_SCHEMA,
            "schema_version": 1,
            "created_at_utc": _utc_now(),
            "updated_at_utc": _utc_now(),
            "providers": {},
            "actions": [],
        }
    try:
        obj = _load_json(state_path)
        if obj.get("schema") != STATE_SCHEMA:
            raise ValueError("bad schema")
        return obj
    except Exception:
        return {
            "schema": STATE_SCHEMA,
            "schema_version": 1,
            "created_at_utc": _utc_now(),
            "updated_at_utc": _utc_now(),
            "providers": {},
            "actions": [],
        }



def _save_state(state_path: Path, state: Dict[str, Any]) -> None:
    state["updated_at_utc"] = _utc_now()
    _save_json(state_path, state)



def _run_shell(command: str, cwd: Path, env: Dict[str, str]) -> CommandResult:
    started = time.time()
    proc = subprocess.run(
        command,
        shell=True,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    dur = int((time.time() - started) * 1000)
    return CommandResult(
        rc=proc.returncode,
        command=command,
        stdout_tail=_compact_tail(proc.stdout),
        stderr_tail=_compact_tail(proc.stderr),
        duration_ms=dur,
    )



def _build_tracevault_pack_cmd(
    source_dir: Path,
    out_dir: Path,
    cfg: Dict[str, Any],
    json_path: Path,
) -> List[str]:
    cmd: List[str] = [
        sys.executable,
        str(TOOLS_DIR / "tracevault_pack.py"),
        str(source_dir),
        "--out",
        str(out_dir),
        "--org",
        str(cfg.get("org", "history-guard")),
        "--verify-mode",
        str(cfg.get("verify_mode", "fast")),
        "--profile",
        str(cfg.get("profile", "default")),
        "--mode",
        str(cfg.get("policy_mode", "strict")),
        "--json",
        "--json-file",
        str(json_path),
    ]

    policy = str(cfg.get("policy", "")).strip()
    if policy:
        cmd.extend(["--policy", policy])

    if bool(cfg.get("hash_cache", True)):
        cmd.append("--hash-cache")
    else:
        cmd.append("--no-hash-cache")

    if bool(cfg.get("no_encrypt", False)):
        cmd.append("--no-encrypt")

    if bool(cfg.get("sign", False)):
        cmd.append("--sign")

    return cmd



def _run_tracevault_pack(source_dir: Path, out_dir: Path, cfg: Dict[str, Any]) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / ".pack_result.json"
    cmd = _build_tracevault_pack_cmd(source_dir, out_dir, cfg, json_path)

    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    duration_ms = int((time.time() - started) * 1000)

    payload: Dict[str, Any] = {
        "pack_command": " ".join(shlex.quote(x) for x in cmd),
        "returncode": proc.returncode,
        "duration_ms": duration_ms,
        "stdout_tail": _compact_tail(proc.stdout),
        "stderr_tail": _compact_tail(proc.stderr),
    }

    if json_path.exists():
        try:
            payload["pack_json"] = _load_json(json_path)
        except Exception as exc:
            payload["pack_json_error"] = str(exc)
    return payload



def _run_tracevault_restore(vault_dir: Path, out_dir: Path) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "tracevault_restore.py"),
        str(vault_dir),
        "--out",
        str(out_dir),
        "--json",
    ]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    duration_ms = int((time.time() - started) * 1000)

    payload: Dict[str, Any] = {
        "restore_command": " ".join(shlex.quote(x) for x in cmd),
        "returncode": proc.returncode,
        "duration_ms": duration_ms,
        "stdout_tail": _compact_tail(proc.stdout),
        "stderr_tail": _compact_tail(proc.stderr),
    }

    try:
        payload["restore_json"] = json.loads(proc.stdout) if proc.stdout.strip() else None
    except Exception:
        payload["restore_json"] = None
    return payload


def _run_fallback_snapshot(workspace: Path, snapshot_dir: Path) -> Dict[str, Any]:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    archive_path = snapshot_dir / "workspace_snapshot.tar.gz"
    started = time.time()
    try:
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(str(workspace), arcname=workspace.name)
    except Exception as exc:
        return {
            "ok": False,
            "method": "tar-gz",
            "archive_path": str(archive_path),
            "error": str(exc),
            "duration_ms": int((time.time() - started) * 1000),
        }

    return {
        "ok": True,
        "method": "tar-gz",
        "archive_path": str(archive_path),
        "archive_bytes": archive_path.stat().st_size if archive_path.exists() else 0,
        "duration_ms": int((time.time() - started) * 1000),
    }



def _collect_files(root: Path) -> List[Path]:
    if not root.exists():
        return []
    return sorted([p for p in root.rglob("*") if p.is_file()])



def _count_total_bytes(files: List[Path]) -> int:
    total = 0
    for f in files:
        try:
            total += f.stat().st_size
        except OSError:
            pass
    return total



def _selected_providers(cfg: Dict[str, Any], provider_filters: Optional[List[str]]) -> List[Dict[str, Any]]:
    providers = cfg.get("providers", [])
    enabled = [p for p in providers if bool(p.get("enabled", True))]
    if provider_filters:
        wanted = set(provider_filters)
        return [p for p in enabled if p.get("id") in wanted]
    return enabled



def _provider_interval_seconds(provider: Dict[str, Any], cfg: Dict[str, Any]) -> int:
    if provider.get("interval_seconds") is not None:
        try:
            return max(10, int(provider["interval_seconds"]))
        except Exception:
            pass
    try:
        return max(10, int(cfg.get("default_interval_seconds", 300)))
    except Exception:
        return 300



def _provider_due(provider: Dict[str, Any], state: Dict[str, Any], cfg: Dict[str, Any], force: bool) -> bool:
    if force:
        return True
    pid = str(provider.get("id"))
    pstate = state.get("providers", {}).get(pid, {})
    last_ts = pstate.get("last_pull_unix")
    if not isinstance(last_ts, (int, float)):
        return True
    interval = _provider_interval_seconds(provider, cfg)
    return (time.time() - float(last_ts)) >= interval



def _provider_export_dir(workspace: Path, cfg: Dict[str, Any], provider_id: str, run_id: str) -> Path:
    root = Path(str(cfg.get("export_root", workspace / ".liquefy" / "provider_exports"))).expanduser()
    if not root.is_absolute():
        root = workspace / root
    return root / provider_id / run_id



def _provider_vault_dir(workspace: Path, cfg: Dict[str, Any], provider_id: str, run_id: str) -> Path:
    root = Path(str(cfg.get("vault_root", workspace / ".liquefy" / "history_vaults"))).expanduser()
    if not root.is_absolute():
        root = workspace / root
    return root / provider_id / run_id


def _snapshot_vault_dir(workspace: Path, cfg: Dict[str, Any], run_id: str) -> Path:
    raw = str(cfg.get("snapshot_vault_root", "/tmp/liquefy-history-guard-snapshots")).strip()
    root = Path(raw).expanduser()
    if not root.is_absolute():
        root = workspace / root

    # Prevent recursive self-pack by forcing snapshot output outside source workspace.
    try:
        workspace_resolved = workspace.resolve()
        root_resolved = root.resolve()
        if workspace_resolved == root_resolved or workspace_resolved in root_resolved.parents:
            root = Path("/tmp") / "liquefy-history-guard-snapshots"
    except Exception:
        root = Path("/tmp") / "liquefy-history-guard-snapshots"

    return root / workspace.name / run_id



def _render_pull_command(template: str, workspace: Path, provider_id: str, provider_out: Path, state_path: Path) -> str:
    # Do explicit token replacement so JSON braces in shell snippets are preserved.
    rendered = template
    tokens = {
        "{workspace}": str(workspace),
        "{provider_id}": provider_id,
        "{provider_out}": str(provider_out),
        "{state_file}": str(state_path),
        "{ts}": _utc_now(),
    }
    for token, value in tokens.items():
        rendered = rendered.replace(token, value)
    return rendered



def _run_provider_once(
    workspace: Path,
    provider: Dict[str, Any],
    cfg: Dict[str, Any],
    state_path: Path,
) -> Dict[str, Any]:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    provider_id = _safe_provider_id(str(provider.get("id", "provider")))
    export_dir = _provider_export_dir(workspace, cfg, provider_id, run_id)
    vault_dir = _provider_vault_dir(workspace, cfg, provider_id, run_id)
    export_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "LIQUEFY_PROVIDER_ID": provider_id,
            "LIQUEFY_PROVIDER_OUT": str(export_dir),
            "LIQUEFY_WORKSPACE": str(workspace),
        }
    )

    pull_template = str(provider.get("pull_command", "")).strip()
    if not pull_template:
        return {
            "provider_id": provider_id,
            "ok": False,
            "run_id": run_id,
            "error": "missing pull_command",
            "export_dir": str(export_dir),
        }

    pull_cmd = _render_pull_command(pull_template, workspace, provider_id, export_dir, state_path)
    pull_result = _run_shell(pull_cmd, cwd=workspace, env=env)

    files = _collect_files(export_dir)
    bytes_total = _count_total_bytes(files)
    if pull_result.rc != 0:
        return {
            "provider_id": provider_id,
            "ok": False,
            "run_id": run_id,
            "export_dir": str(export_dir),
            "vault_dir": str(vault_dir),
            "files_exported": len(files),
            "exported_bytes": bytes_total,
            "pull": {
                "command": pull_result.command,
                "returncode": pull_result.rc,
                "duration_ms": pull_result.duration_ms,
                "stdout_tail": pull_result.stdout_tail,
                "stderr_tail": pull_result.stderr_tail,
            },
            "error": "pull_command_failed",
        }

    pack_result = _run_tracevault_pack(export_dir, vault_dir, cfg)
    pack_ok = bool(pack_result.get("returncode") == 0)

    return {
        "provider_id": provider_id,
        "ok": pack_ok,
        "run_id": run_id,
        "export_dir": str(export_dir),
        "vault_dir": str(vault_dir),
        "files_exported": len(files),
        "exported_bytes": bytes_total,
        "pull": {
            "command": pull_result.command,
            "returncode": pull_result.rc,
            "duration_ms": pull_result.duration_ms,
            "stdout_tail": pull_result.stdout_tail,
            "stderr_tail": pull_result.stderr_tail,
        },
        "pack": pack_result,
        "error": None if pack_ok else "pack_failed",
    }



def _update_provider_state(state: Dict[str, Any], run: Dict[str, Any]) -> None:
    providers = state.setdefault("providers", {})
    pid = str(run.get("provider_id", ""))
    pstate = providers.setdefault(pid, {})
    pstate.update(
        {
            "last_run_id": run.get("run_id"),
            "last_pull_unix": int(time.time()),
            "last_pull_utc": _utc_now(),
            "last_ok": bool(run.get("ok", False)),
            "last_export_dir": run.get("export_dir"),
            "last_vault_dir": run.get("vault_dir"),
            "last_files_exported": int(run.get("files_exported", 0)),
            "last_exported_bytes": int(run.get("exported_bytes", 0)),
            "last_error": run.get("error"),
        }
    )



def _risk_match(command: str, patterns: List[str]) -> List[str]:
    low = command.lower()
    hits: List[str] = []
    for pat in patterns:
        try:
            if re.search(pat, low):
                hits.append(pat)
        except re.error:
            # treat malformed pattern as a plain substring to avoid bricking configs
            if pat.lower() in low:
                hits.append(pat)
    return hits



def _verify_approval(cfg: Dict[str, Any], env: Dict[str, str]) -> tuple[bool, str]:
    expected_hash = str(cfg.get("approval_token_sha256", "")).strip()
    if not expected_hash:
        return False, "LIQUEFY_APPROVAL_CONFIG_MISSING"

    env_var = str(cfg.get("approval_env_var", "LIQUEFY_APPROVAL_TOKEN"))
    provided = env.get(env_var, "")
    if not provided:
        return False, "LIQUEFY_APPROVAL_REQUIRED"

    provided_hash = _hash_token(provided)
    if not hmac.compare_digest(expected_hash, provided_hash):
        return False, "LIQUEFY_APPROVAL_INVALID"

    return True, ""



def cmd_init(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    paths = _default_paths(workspace)
    config_path = Path(args.config).expanduser().resolve() if args.config else paths["config"]

    existing = config_path.exists()
    if existing and not args.force:
        result = {
            "error": f"config already exists: {config_path}",
            "hint": "pass --force to overwrite",
        }
        if args.json:
            _emit("init", False, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(result["error"], file=sys.stderr)
        return 1

    template = {
        "schema": CONFIG_SCHEMA,
        "schema_version": 1,
        "created_at_utc": _utc_now(),
        "workspace": str(workspace),
        "org": "history-guard",
        "profile": "default",
        "verify_mode": "fast",
        "policy_mode": "strict",
        "policy": "",
        "hash_cache": True,
        "no_encrypt": False,
        "sign": True,
        "default_interval_seconds": 300,
        "vault_root": str(workspace / ".liquefy" / "history_vaults"),
        "snapshot_vault_root": "/tmp/liquefy-history-guard-snapshots",
        "export_root": str(workspace / ".liquefy" / "provider_exports"),
        "approval_env_var": "LIQUEFY_APPROVAL_TOKEN",
        "approval_token_sha256": "",
        "risky_patterns": DEFAULT_RISKY_PATTERNS,
        "auto_recover_to_dir": True,
        "providers": [
            {
                "id": "gmail",
                "type": "email",
                "enabled": False,
                "interval_seconds": 300,
                "pull_command": "python3 exporters/gmail_pull.py --out {provider_out}",
                "notes": "Write exported files under {provider_out}.",
            },
            {
                "id": "calendar",
                "type": "calendar",
                "enabled": False,
                "interval_seconds": 300,
                "pull_command": "python3 exporters/calendar_pull.py --out {provider_out}",
                "notes": "Use read-only token where possible.",
            },
            {
                "id": "discord",
                "type": "chat",
                "enabled": False,
                "interval_seconds": 600,
                "pull_command": "python3 exporters/discord_pull.py --out {provider_out}",
                "notes": "Prefer export endpoints to scraping.",
            },
            {
                "id": "telegram",
                "type": "chat",
                "enabled": False,
                "interval_seconds": 600,
                "pull_command": "python3 exporters/telegram_pull.py --out {provider_out}",
                "notes": "Use official export tooling / bot logs.",
            },
            {
                "id": "x",
                "type": "social",
                "enabled": False,
                "interval_seconds": 900,
                "pull_command": "python3 exporters/x_pull.py --out {provider_out}",
                "notes": "Archive posts/messages where API permits.",
            },
            {
                "id": "instagram",
                "type": "social",
                "enabled": False,
                "interval_seconds": 900,
                "pull_command": "python3 exporters/instagram_pull.py --out {provider_out}",
                "notes": "Archive media + metadata exports.",
            },
        ],
    }

    _save_json(config_path, template)

    state_path = _default_paths(workspace)["state"]
    if not state_path.exists():
        _save_state(state_path, _load_state(state_path))

    result = {
        "config_path": str(config_path),
        "state_path": str(state_path),
        "providers": [p["id"] for p in template["providers"]],
        "next_steps": [
            f"edit {config_path} provider pull_command values",
            "run set-approval-token before gate-action on risky commands",
            "ensure LIQUEFY_SECRET is set unless no_encrypt=true",
        ],
    }
    if args.json:
        _emit("init", True, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"history-guard initialized: {config_path}")
        print(f"state file: {state_path}")
        print("providers:")
        for pid in result["providers"]:
            print(f"  - {pid}")
    return 0



def cmd_set_approval_token(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("set-approval-token", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1
    assert cfg is not None
    assert cpath is not None

    token: str = ""
    if args.token:
        token = args.token
    elif args.token_env:
        token = os.environ.get(args.token_env, "")
    else:
        token = getpass("approval token: ")
        confirm = getpass("confirm token: ")
        if token != confirm:
            res = {"error": "token mismatch"}
            if args.json:
                _emit("set-approval-token", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
            else:
                print("token mismatch", file=sys.stderr)
            return 1

    if len(token) < 8:
        res = {"error": "token too short (min 8 chars)"}
        if args.json:
            _emit("set-approval-token", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(res["error"], file=sys.stderr)
        return 1

    cfg["approval_token_sha256"] = _hash_token(token)
    cfg["approval_token_set_at_utc"] = _utc_now()
    _save_json(cpath, cfg)

    res = {
        "config_path": str(cpath),
        "approval_env_var": cfg.get("approval_env_var", "LIQUEFY_APPROVAL_TOKEN"),
        "hash_prefix": cfg["approval_token_sha256"][:12],
    }
    if args.json:
        _emit("set-approval-token", True, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"approval token hash saved in {cpath}")
    return 0



def _execute_pull_cycle(args: argparse.Namespace, cfg: Dict[str, Any], cpath: Path, state_path: Path) -> Dict[str, Any]:
    state = _load_state(state_path)

    providers = _selected_providers(cfg, args.providers)
    runs: List[Dict[str, Any]] = []

    for provider in providers:
        if not _provider_due(provider, state, cfg, force=bool(args.force)):
            runs.append(
                {
                    "provider_id": str(provider.get("id")),
                    "ok": True,
                    "skipped": True,
                    "reason": "interval_not_due",
                }
            )
            continue

        run = _run_provider_once(workspace=Path(cfg.get("workspace", ".")).expanduser().resolve(), provider=provider, cfg=cfg, state_path=state_path)
        runs.append(run)
        _update_provider_state(state, run)

    state_actions = state.setdefault("actions", [])
    state_actions.append(
        {
            "ts": _utc_now(),
            "type": "pull-cycle",
            "providers": [r.get("provider_id") for r in runs],
            "ok": all(bool(r.get("ok", False)) for r in runs if not r.get("skipped")),
            "config_path": str(cpath),
        }
    )
    # Keep tail bounded
    if len(state_actions) > 5000:
        del state_actions[:-5000]

    _save_state(state_path, state)

    return {
        "workspace": cfg.get("workspace"),
        "config_path": str(cpath),
        "state_path": str(state_path),
        "providers_selected": [p.get("id") for p in providers],
        "runs": runs,
        "ok_count": sum(1 for r in runs if r.get("ok") and not r.get("skipped")),
        "fail_count": sum(1 for r in runs if (not r.get("ok")) and not r.get("skipped")),
        "skipped_count": sum(1 for r in runs if r.get("skipped")),
    }



def cmd_pull_once(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("pull-once", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1

    assert cfg is not None
    assert cpath is not None
    cfg["workspace"] = str(workspace)

    state_path = _default_paths(workspace)["state"]
    result = _execute_pull_cycle(args, cfg, cpath, state_path)
    ok = result["fail_count"] == 0

    if args.json:
        _emit("pull-once", ok, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"pull-once: providers={len(result['providers_selected'])} ok={result['ok_count']} fail={result['fail_count']} skipped={result['skipped_count']}")
        for run in result["runs"]:
            pid = run.get("provider_id")
            if run.get("skipped"):
                print(f"  - {pid}: skipped ({run.get('reason')})")
            elif run.get("ok"):
                print(f"  - {pid}: ok files={run.get('files_exported', 0)} bytes={run.get('exported_bytes', 0)}")
            else:
                print(f"  - {pid}: FAIL error={run.get('error')}")

    return 0 if ok else 1



def cmd_watch(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("watch", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1

    assert cfg is not None
    assert cpath is not None
    cfg["workspace"] = str(workspace)
    state_path = _default_paths(workspace)["state"]

    iterations = int(args.iterations)
    poll_seconds = max(5, int(args.poll_seconds))
    all_cycles: List[Dict[str, Any]] = []

    i = 0
    try:
        while iterations <= 0 or i < iterations:
            i += 1
            cycle = _execute_pull_cycle(args, cfg, cpath, state_path)
            cycle["iteration"] = i
            all_cycles.append(cycle)

            if args.json:
                _emit("watch-cycle", cycle["fail_count"] == 0, cycle)
            else:
                print(f"[watch] cycle={i} ok={cycle['ok_count']} fail={cycle['fail_count']} skipped={cycle['skipped_count']}")

            if iterations > 0 and i >= iterations:
                break
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        if not args.json:
            print("stopped by user")

    final = {
        "workspace": str(workspace),
        "config_path": str(cpath),
        "state_path": str(state_path),
        "iterations_requested": iterations,
        "iterations_completed": len(all_cycles),
        "poll_seconds": poll_seconds,
        "cycle_failures": sum(1 for c in all_cycles if c.get("fail_count", 0) > 0),
    }

    if args.json:
        _emit("watch", final["cycle_failures"] == 0, final, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(
            f"watch complete: iterations={final['iterations_completed']} "
            f"cycle_failures={final['cycle_failures']}"
        )

    return 0 if final["cycle_failures"] == 0 else 1



def cmd_gate_action(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("gate-action", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1

    assert cfg is not None
    assert cpath is not None
    cfg["workspace"] = str(workspace)

    action_cmd = str(args.command).strip()
    if not action_cmd:
        res = {"error": "missing --command"}
        if args.json:
            _emit("gate-action", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print("missing --command", file=sys.stderr)
        return 1

    risky_patterns = list(cfg.get("risky_patterns", DEFAULT_RISKY_PATTERNS))
    risky_hits = _risk_match(action_cmd, risky_patterns)
    risky = len(risky_hits) > 0

    approval_ok = True
    approval_error = ""
    if risky:
        approval_ok, approval_error = _verify_approval(cfg, os.environ)
        if not approval_ok:
            res = {
                "workspace": str(workspace),
                "command": action_cmd,
                "risky": True,
                "risk_matches": risky_hits,
                "error_code": approval_error,
                "hint": f"set {cfg.get('approval_env_var', 'LIQUEFY_APPROVAL_TOKEN')} and configure approval token hash",
            }
            if args.json:
                _emit("gate-action", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
            else:
                print(f"blocked: {approval_error}", file=sys.stderr)
            return 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_dir = _snapshot_vault_dir(workspace, cfg, run_id)

    # Snapshot before action (front-run safety)
    snapshot_pack = _run_tracevault_pack(workspace, snapshot_dir, cfg)
    snapshot_ok = snapshot_pack.get("returncode") == 0
    snapshot_fallback: Optional[Dict[str, Any]] = None
    if not snapshot_ok:
        snapshot_fallback = _run_fallback_snapshot(workspace, snapshot_dir)
        snapshot_ok = bool(snapshot_fallback.get("ok", False))

    action_result = {
        "command": action_cmd,
        "returncode": None,
        "duration_ms": 0,
        "stdout_tail": "",
        "stderr_tail": "",
    }

    if snapshot_ok:
        res = _run_shell(action_cmd, cwd=workspace, env=os.environ.copy())
        action_result = {
            "command": res.command,
            "returncode": res.rc,
            "duration_ms": res.duration_ms,
            "stdout_tail": res.stdout_tail,
            "stderr_tail": res.stderr_tail,
        }
    else:
        action_result["stderr_tail"] = "blocked: pre-action snapshot failed"

    recovery = None
    if action_result["returncode"] not in (None, 0) and bool(cfg.get("auto_recover_to_dir", True)):
        recovery_dir = workspace / ".liquefy" / "recovery" / run_id
        if snapshot_pack.get("returncode") == 0:
            recovery = _run_tracevault_restore(snapshot_dir, recovery_dir)
        elif snapshot_fallback and snapshot_fallback.get("ok"):
            archive = Path(str(snapshot_fallback.get("archive_path", "")))
            started = time.time()
            try:
                recovery_dir.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive, "r:gz") as tf:
                    tf.extractall(path=recovery_dir)
                recovery = {
                    "method": "tar-gz",
                    "returncode": 0,
                    "duration_ms": int((time.time() - started) * 1000),
                    "archive_path": str(archive),
                    "out_dir": str(recovery_dir),
                }
            except Exception as exc:
                recovery = {
                    "method": "tar-gz",
                    "returncode": 1,
                    "duration_ms": int((time.time() - started) * 1000),
                    "archive_path": str(archive),
                    "out_dir": str(recovery_dir),
                    "error": str(exc),
                }

    state_path = _default_paths(workspace)["state"]
    state = _load_state(state_path)
    actions = state.setdefault("actions", [])
    actions.append(
        {
            "ts": _utc_now(),
            "type": "gate-action",
            "command": action_cmd,
            "risky": risky,
            "risk_matches": risky_hits,
            "approval_ok": approval_ok,
            "snapshot_dir": str(snapshot_dir),
            "snapshot_ok": snapshot_ok,
            "action_rc": action_result.get("returncode"),
        }
    )
    if len(actions) > 5000:
        del actions[:-5000]
    _save_state(state_path, state)

    ok = snapshot_ok and action_result.get("returncode") == 0
    result = {
        "workspace": str(workspace),
        "config_path": str(cpath),
        "state_path": str(state_path),
        "command": action_cmd,
        "risky": risky,
        "risk_matches": risky_hits,
        "approval_ok": approval_ok,
        "snapshot": {
            "vault_dir": str(snapshot_dir),
            "ok": snapshot_ok,
            "pack": snapshot_pack,
            "fallback": snapshot_fallback,
        },
        "action": action_result,
        "recovery": recovery,
    }

    if args.json:
        _emit("gate-action", ok, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"gate-action: snapshot_ok={snapshot_ok} action_rc={action_result.get('returncode')}")
        print(f"  command: {action_cmd}")
        if risky:
            print(f"  risky matches: {', '.join(risky_hits)}")

    return 0 if ok else 1



def cmd_status(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("status", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1

    assert cfg is not None
    assert cpath is not None
    state_path = _default_paths(workspace)["state"]
    state = _load_state(state_path)

    provider_states = state.get("providers", {})
    providers_cfg = {str(p.get("id")): p for p in cfg.get("providers", [])}

    providers = []
    for pid, pdata in sorted(provider_states.items()):
        pcfg = providers_cfg.get(pid, {})
        providers.append(
            {
                "provider_id": pid,
                "enabled": bool(pcfg.get("enabled", False)),
                "type": pcfg.get("type"),
                "last_ok": pdata.get("last_ok"),
                "last_pull_utc": pdata.get("last_pull_utc"),
                "last_files_exported": pdata.get("last_files_exported", 0),
                "last_exported_bytes": pdata.get("last_exported_bytes", 0),
                "last_error": pdata.get("last_error"),
                "last_vault_dir": pdata.get("last_vault_dir"),
            }
        )

    # Include configured providers that have no state yet.
    for pid, pcfg in sorted(providers_cfg.items()):
        if pid in provider_states:
            continue
        providers.append(
            {
                "provider_id": pid,
                "enabled": bool(pcfg.get("enabled", False)),
                "type": pcfg.get("type"),
                "last_ok": None,
                "last_pull_utc": None,
                "last_files_exported": 0,
                "last_exported_bytes": 0,
                "last_error": None,
                "last_vault_dir": None,
            }
        )

    result = {
        "workspace": str(workspace),
        "config_path": str(cpath),
        "state_path": str(state_path),
        "approval_env_var": cfg.get("approval_env_var", "LIQUEFY_APPROVAL_TOKEN"),
        "approval_configured": bool(str(cfg.get("approval_token_sha256", "")).strip()),
        "providers": providers,
        "actions_recorded": len(state.get("actions", [])),
    }

    if args.json:
        _emit("status", True, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"history-guard status: {workspace}")
        print(f"  config: {cpath}")
        print(f"  state:  {state_path}")
        print(f"  approval configured: {result['approval_configured']}")
        for p in providers:
            print(
                f"  - {p['provider_id']}: enabled={p['enabled']} "
                f"last_ok={p['last_ok']} last_pull={p['last_pull_utc']} "
                f"bytes={p['last_exported_bytes']}"
            )

    return 0



def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-history-guard",
        description="Continuous pull + anti-nuke guard for external account history",
    )
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_init = sub.add_parser("init", help="Create history-guard config template")
    p_init.add_argument("--workspace", required=True, help="Workspace root for config/state")
    p_init.add_argument("--config", default=None, help="Optional explicit config path")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    p_init.add_argument("--json", action="store_true")
    p_init.add_argument("--json-file", default=None)
    p_init.set_defaults(fn=cmd_init)

    p_token = sub.add_parser("set-approval-token", help="Store approval token hash in config")
    p_token.add_argument("--workspace", required=True)
    p_token.add_argument("--config", default=None)
    p_token.add_argument("--token", default=None, help="Token value (avoid in shell history)")
    p_token.add_argument("--token-env", default=None, help="Read token from env var name")
    p_token.add_argument("--json", action="store_true")
    p_token.add_argument("--json-file", default=None)
    p_token.set_defaults(fn=cmd_set_approval_token)

    p_pull = sub.add_parser("pull-once", help="Run one provider pull cycle and pack exports")
    p_pull.add_argument("--workspace", required=True)
    p_pull.add_argument("--config", default=None)
    p_pull.add_argument("--providers", nargs="*", help="Optional provider IDs subset")
    p_pull.add_argument("--force", action="store_true", help="Ignore per-provider interval and pull now")
    p_pull.add_argument("--json", action="store_true")
    p_pull.add_argument("--json-file", default=None)
    p_pull.set_defaults(fn=cmd_pull_once)

    p_watch = sub.add_parser("watch", help="Run continuous pull cycles")
    p_watch.add_argument("--workspace", required=True)
    p_watch.add_argument("--config", default=None)
    p_watch.add_argument("--providers", nargs="*", help="Optional provider IDs subset")
    p_watch.add_argument("--force", action="store_true", help="Ignore interval checks")
    p_watch.add_argument("--poll-seconds", type=int, default=60)
    p_watch.add_argument("--iterations", type=int, default=0, help="0 = run forever")
    p_watch.add_argument("--json", action="store_true")
    p_watch.add_argument("--json-file", default=None)
    p_watch.set_defaults(fn=cmd_watch)

    p_gate = sub.add_parser("gate-action", help="Pre-action snapshot + approval gate for risky commands")
    p_gate.add_argument("--workspace", required=True)
    p_gate.add_argument("--config", default=None)
    p_gate.add_argument("--command", required=True, help="Action command to run under guard")
    p_gate.add_argument("--json", action="store_true")
    p_gate.add_argument("--json-file", default=None)
    p_gate.set_defaults(fn=cmd_gate_action)

    p_status = sub.add_parser("status", help="Show provider pull and action-gate status")
    p_status.add_argument("--workspace", required=True)
    p_status.add_argument("--config", default=None)
    p_status.add_argument("--json", action="store_true")
    p_status.add_argument("--json-file", default=None)
    p_status.set_defaults(fn=cmd_status)

    return ap



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    rc = int(args.fn(args))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
