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



def _resolve_vault_root(workspace: Path, cfg: Dict[str, Any]) -> Path:
    root = Path(str(cfg.get("vault_root", workspace / ".liquefy" / "history_vaults"))).expanduser()
    if not root.is_absolute():
        root = workspace / root
    return root


def _resolve_snapshot_root(workspace: Path, cfg: Dict[str, Any]) -> Path:
    raw = str(cfg.get("snapshot_vault_root", "/tmp/liquefy-history-guard-snapshots")).strip()
    root = Path(raw).expanduser()
    if not root.is_absolute():
        root = workspace / root
    try:
        workspace_resolved = workspace.resolve()
        root_resolved = root.resolve()
        if workspace_resolved == root_resolved or workspace_resolved in root_resolved.parents:
            root = Path("/tmp") / "liquefy-history-guard-snapshots"
    except Exception:
        root = Path("/tmp") / "liquefy-history-guard-snapshots"
    return root / workspace.name


def _build_history_graph(
    workspace: Path,
    cfg: Dict[str, Any],
    state: Dict[str, Any],
    max_runs_per_provider: int,
    max_actions: int,
) -> Dict[str, Any]:
    providers_cfg = sorted(cfg.get("providers", []), key=lambda p: str(p.get("id", "")))
    state_providers = state.get("providers", {})
    actions = list(state.get("actions", []))

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set[str] = set()

    def add_node(node: Dict[str, Any]) -> None:
        nid = str(node.get("id", "")).strip()
        if not nid or nid in seen_nodes:
            return
        seen_nodes.add(nid)
        nodes.append(node)

    def add_edge(source: str, target: str, rel: str, weight: float = 1.0) -> None:
        edges.append({"source": source, "target": target, "rel": rel, "weight": float(weight)})

    workspace_node_id = f"workspace:{workspace}"
    add_node(
        {
            "id": workspace_node_id,
            "kind": "workspace",
            "label": workspace.name or "workspace",
            "path": str(workspace),
        }
    )

    vault_root = _resolve_vault_root(workspace, cfg)
    snapshot_root = _resolve_snapshot_root(workspace, cfg)

    for provider in providers_cfg:
        provider_id = _safe_provider_id(str(provider.get("id", "")))
        provider_node_id = f"provider:{provider_id}"
        provider_state = state_providers.get(provider_id, {})
        add_node(
            {
                "id": provider_node_id,
                "kind": "provider",
                "label": provider_id,
                "provider_type": str(provider.get("type", "unknown")),
                "enabled": bool(provider.get("enabled", False)),
                "interval_seconds": int(_provider_interval_seconds(provider, cfg)),
                "last_ok": provider_state.get("last_ok"),
                "last_pull_utc": provider_state.get("last_pull_utc"),
                "last_files_exported": int(provider_state.get("last_files_exported", 0)),
                "last_exported_bytes": int(provider_state.get("last_exported_bytes", 0)),
            }
        )
        add_edge(workspace_node_id, provider_node_id, "configured_provider")

        provider_runs_root = vault_root / provider_id
        run_dirs: List[Path] = []
        if provider_runs_root.exists():
            run_dirs = sorted(
                [p for p in provider_runs_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
                key=lambda p: p.name,
                reverse=True,
            )
        for run_dir in run_dirs[: max(1, int(max_runs_per_provider))]:
            run_node_id = f"vault_run:{provider_id}:{run_dir.name}"
            try:
                vault_bytes = _count_total_bytes(_collect_files(run_dir))
            except Exception:
                vault_bytes = 0
            add_node(
                {
                    "id": run_node_id,
                    "kind": "vault_run",
                    "label": run_dir.name,
                    "provider_id": provider_id,
                    "path": str(run_dir),
                    "vault_bytes": int(vault_bytes),
                }
            )
            add_edge(provider_node_id, run_node_id, "vault_run")

    for idx, action in enumerate(actions[-max(1, int(max_actions)) :], start=1):
        a_type = str(action.get("type", "action"))
        action_id = f"action:{idx}:{str(action.get('ts', 'unknown'))}:{a_type}"
        add_node(
            {
                "id": action_id,
                "kind": "action",
                "label": a_type,
                "ts": action.get("ts"),
                "command": action.get("command"),
                "risky": bool(action.get("risky", False)),
                "approval_ok": action.get("approval_ok"),
                "action_rc": action.get("action_rc"),
            }
        )
        add_edge(workspace_node_id, action_id, "recorded_action")

        snap_dir = str(action.get("snapshot_dir", "")).strip()
        if snap_dir:
            snap_name = Path(snap_dir).name
            snap_id = f"snapshot:{snap_name}"
            add_node(
                {
                    "id": snap_id,
                    "kind": "snapshot",
                    "label": snap_name,
                    "path": snap_dir,
                }
            )
            add_edge(action_id, snap_id, "snapshot")

    # Include latest snapshot directories even if actions were trimmed.
    snap_dirs: List[Path] = []
    if snapshot_root.exists():
        snap_dirs = sorted(
            [p for p in snapshot_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
            key=lambda p: p.name,
            reverse=True,
        )
    for snap_dir in snap_dirs[: max(1, int(max_actions))]:
        snap_name = snap_dir.name
        snap_id = f"snapshot:{snap_name}"
        if snap_id in seen_nodes:
            continue
        add_node(
            {
                "id": snap_id,
                "kind": "snapshot",
                "label": snap_name,
                "path": str(snap_dir),
            }
        )
        add_edge(workspace_node_id, snap_id, "snapshot_dir")

    nodes_sorted = sorted(nodes, key=lambda n: str(n.get("id", "")))
    edges_sorted = sorted(
        edges,
        key=lambda e: (str(e.get("source", "")), str(e.get("target", "")), str(e.get("rel", ""))),
    )
    node_kinds: Dict[str, int] = {}
    for node in nodes_sorted:
        kind = str(node.get("kind", "unknown"))
        node_kinds[kind] = node_kinds.get(kind, 0) + 1

    return {
        "schema": "liquefy.history_graph.v1",
        "schema_version": 1,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "vault_root": str(vault_root),
        "snapshot_root": str(snapshot_root),
        "node_count": len(nodes_sorted),
        "edge_count": len(edges_sorted),
        "node_kinds": node_kinds,
        "nodes": nodes_sorted,
        "edges": edges_sorted,
    }


def cmd_export_graph(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    cfg, cpath, err = _load_config(workspace, Path(args.config).expanduser().resolve() if args.config else None)
    if err:
        res = {"error": err}
        if args.json:
            _emit("export-graph", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(err, file=sys.stderr)
        return 1

    assert cfg is not None
    assert cpath is not None
    state_path = _default_paths(workspace)["state"]
    state = _load_state(state_path)
    graph = _build_history_graph(
        workspace=workspace,
        cfg=cfg,
        state=state,
        max_runs_per_provider=max(1, int(args.max_runs_per_provider)),
        max_actions=max(1, int(args.max_actions)),
    )

    out_path = Path(args.out).expanduser().resolve() if args.out else (workspace / ".liquefy" / "history_graph.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")

    result = {
        "workspace": str(workspace),
        "config_path": str(cpath),
        "state_path": str(state_path),
        "out_path": str(out_path),
        "graph": graph,
    }
    if args.json:
        _emit("export-graph", True, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"export-graph: wrote {out_path}")
        print(f"  nodes={graph['node_count']} edges={graph['edge_count']}")
    return 0


def _render_graph_html(graph: Dict[str, Any], title: str) -> str:
    graph_json = json.dumps(graph, separators=(",", ":")).replace("</", "<\\/")
    safe_title = str(title).replace("<", "&lt;").replace(">", "&gt;")
    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>__TITLE__</title>
  <style>
    :root {
      --bg: #0d1117;
      --fg: #d6dde6;
      --muted: #8b949e;
      --edge: #39414a;
      --workspace: #58a6ff;
      --provider: #2ea043;
      --vault: #f2cc60;
      --action: #ff7b72;
      --snapshot: #a371f7;
      --other: #8b949e;
      --panel: rgba(13, 17, 23, 0.92);
      --border: #2b3440;
      --accent: #58a6ff;
    }
    html, body {
      margin: 0;
      width: 100%;
      height: 100%;
      background: var(--bg);
      color: var(--fg);
      font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    body {
      display: flex;
      flex-direction: column;
    }
    #topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 14px;
      border-bottom: 1px solid #222a33;
      background: #0d1117;
    }
    #title {
      font-weight: 700;
      font-size: 15px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    #meta {
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      text-align: right;
    }
    #stage {
      position: relative;
      flex: 1;
      min-height: 600px;
      overflow: hidden;
      background:
        radial-gradient(1200px 800px at 20% -10%, rgba(88,166,255,0.10), transparent 65%),
        radial-gradient(1000px 700px at 120% 20%, rgba(163,113,247,0.08), transparent 65%),
        var(--bg);
    }
    #graph {
      width: 100%;
      height: 100%;
      display: block;
      cursor: grab;
    }
    #graph.dragging {
      cursor: grabbing;
    }
    .panel {
      position: absolute;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.25);
      backdrop-filter: blur(6px);
    }
    #controls {
      left: 12px;
      top: 12px;
      padding: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      max-width: 650px;
    }
    #controls button {
      background: #1f2937;
      color: var(--fg);
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 6px 9px;
      font-size: 12px;
      cursor: pointer;
    }
    #controls button:hover {
      border-color: var(--accent);
    }
    #legend {
      right: 12px;
      top: 12px;
      padding: 10px 12px;
      min-width: 190px;
    }
    .lg {
      display: flex;
      align-items: center;
      margin: 4px 0;
      color: var(--muted);
      font-size: 12px;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      margin-right: 8px;
      border: 1px solid rgba(255,255,255,0.25);
    }
    #notes {
      right: 12px;
      bottom: 12px;
      width: 320px;
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    #notes h4 {
      margin: 0;
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    #selectedNode {
      font-size: 12px;
      color: var(--fg);
      padding: 6px 8px;
      border: 1px solid #374151;
      border-radius: 8px;
      background: rgba(0,0,0,0.2);
      min-height: 18px;
      word-break: break-all;
    }
    #noteText {
      width: 100%;
      min-height: 120px;
      resize: vertical;
      background: rgba(0,0,0,0.25);
      color: var(--fg);
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 8px;
      box-sizing: border-box;
      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    #noteActions {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    #noteActions button {
      background: #1f2937;
      color: var(--fg);
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 6px 8px;
      font-size: 11px;
      cursor: pointer;
    }
    #help {
      color: var(--muted);
      font-size: 11px;
      line-height: 1.35;
    }
    @media (max-width: 980px) {
      #legend, #notes {
        position: static;
        margin: 12px;
      }
      #stage {
        overflow: auto;
      }
    }
  </style>
</head>
<body>
  <div id="topbar">
    <div id="title">__TITLE__</div>
    <div id="meta"></div>
  </div>
  <div id="stage">
    <canvas id="graph"></canvas>
    <div id="controls" class="panel">
      <button id="btnResetView">Reset View</button>
      <button id="btnCenter">Center</button>
      <button id="btnShuffle">Re-layout</button>
      <button id="btnPause">Pause Physics</button>
      <button id="btnResume">Resume Physics</button>
    </div>
    <div id="legend" class="panel">
      <div class="lg"><span class="dot" style="background: var(--workspace)"></span>workspace</div>
      <div class="lg"><span class="dot" style="background: var(--provider)"></span>provider</div>
      <div class="lg"><span class="dot" style="background: var(--vault)"></span>vault_run</div>
      <div class="lg"><span class="dot" style="background: var(--action)"></span>action</div>
      <div class="lg"><span class="dot" style="background: var(--snapshot)"></span>snapshot</div>
      <div class="lg"><span class="dot" style="background: var(--other)"></span>other</div>
    </div>
    <div id="notes" class="panel">
      <h4>Node Notes</h4>
      <div id="selectedNode">No node selected</div>
      <textarea id="noteText" placeholder="Attach notes to the selected node..."></textarea>
      <div id="noteActions">
        <button id="saveNote">Save note</button>
        <button id="clearNote">Clear note</button>
        <button id="exportNotes">Export notes</button>
      </div>
      <div id="help">
        Controls: Drag node = move. Drag empty = rotate. Shift+drag or middle/right drag = pan.
        Scroll = zoom. Connections stay attached while rearranging.
      </div>
    </div>
  </div>
  <script>
  const graph = __GRAPH_JSON__;
  const canvas = document.getElementById("graph");
  const ctx = canvas.getContext("2d");
  const meta = document.getElementById("meta");
  const selectedNodeEl = document.getElementById("selectedNode");
  const noteTextEl = document.getElementById("noteText");
  const btnSaveNote = document.getElementById("saveNote");
  const btnClearNote = document.getElementById("clearNote");
  const btnExportNotes = document.getElementById("exportNotes");
  const btnResetView = document.getElementById("btnResetView");
  const btnCenter = document.getElementById("btnCenter");
  const btnShuffle = document.getElementById("btnShuffle");
  const btnPause = document.getElementById("btnPause");
  const btnResume = document.getElementById("btnResume");

  const kindColor = {
    workspace: "#58a6ff",
    provider: "#2ea043",
    vault_run: "#f2cc60",
    action: "#ff7b72",
    snapshot: "#a371f7",
    other: "#8b949e",
  };

  function hashKey(s) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16);
  }

  const notesStoreKey = "liquefy-history-graph-notes:" + hashKey(String(graph.workspace || "workspace"));
  let notesMap = {};
  try {
    const raw = localStorage.getItem(notesStoreKey);
    if (raw) {
      notesMap = JSON.parse(raw);
      if (!notesMap || typeof notesMap !== "object") notesMap = {};
    }
  } catch (_) {
    notesMap = {};
  }

  function persistNotes() {
    try {
      localStorage.setItem(notesStoreKey, JSON.stringify(notesMap));
    } catch (_) {}
  }

  const width = () => canvas.clientWidth || 1200;
  const height = () => canvas.clientHeight || 720;
  const rand = (seed => () => (seed = (seed * 16807) % 2147483647) / 2147483647)(42);

  const nodes = (graph.nodes || []).map((n, i) => {
    const ring = Math.max(1, Math.sqrt(graph.nodes.length || 1));
    const angle = (i / Math.max(1, graph.nodes.length)) * Math.PI * 2;
    const radius = 120 + (i % Math.ceil(ring)) * 35;
    return {
      ...n,
      x: Math.cos(angle) * radius + (rand() - 0.5) * 40,
      y: Math.sin(angle) * radius + (rand() - 0.5) * 40,
      z: (rand() - 0.5) * 220,
      vx: 0,
      vy: 0,
      vz: 0,
      fixed: false,
    };
  });

  const byId = new Map(nodes.map(n => [n.id, n]));
  const edges = (graph.edges || [])
    .map(e => ({ ...e, a: byId.get(e.source), b: byId.get(e.target) }))
    .filter(e => e.a && e.b);

  let camera = {
    rotX: 0.52,
    rotY: 0.58,
    panX: 0,
    panY: 0,
    zoom: 1.0,
    depth: 720,
  };
  let physicsPaused = false;
  let selectedNode = null;
  let dragMode = "none"; // none | node | rotate | pan
  let lastMouse = { x: 0, y: 0 };

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(canvas.clientWidth * dpr);
    canvas.height = Math.floor(canvas.clientHeight * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  window.addEventListener("resize", resize);

  function project(node) {
    const cosY = Math.cos(camera.rotY), sinY = Math.sin(camera.rotY);
    const cosX = Math.cos(camera.rotX), sinX = Math.sin(camera.rotX);
    const x1 = node.x * cosY + node.z * sinY;
    const z1 = -node.x * sinY + node.z * cosY;
    const y2 = node.y * cosX - z1 * sinX;
    const z2 = node.y * sinX + z1 * cosX;
    const p = camera.depth / (camera.depth + z2 + 420);
    const sx = width() / 2 + camera.panX + x1 * p * camera.zoom;
    const sy = height() / 2 + camera.panY + y2 * p * camera.zoom;
    const r = Math.max(3.5, Math.min(14, 5.5 * p * camera.zoom));
    return { sx, sy, p, z: z2, r };
  }

  function pickNode(mx, my) {
    let best = null;
    let bestDist = Infinity;
    for (const n of nodes) {
      const pr = project(n);
      const dx = pr.sx - mx;
      const dy = pr.sy - my;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist <= pr.r + 5 && dist < bestDist) {
        best = n;
        bestDist = dist;
      }
    }
    return best;
  }

  function updateSelectedNodeUI() {
    if (!selectedNode) {
      selectedNodeEl.textContent = "No node selected";
      noteTextEl.value = "";
      return;
    }
    selectedNodeEl.textContent = `${selectedNode.label || selectedNode.id} (${selectedNode.kind || "other"})`;
    noteTextEl.value = String(notesMap[selectedNode.id] || "");
  }

  btnSaveNote.addEventListener("click", () => {
    if (!selectedNode) return;
    const val = String(noteTextEl.value || "").trim();
    if (val) notesMap[selectedNode.id] = val;
    else delete notesMap[selectedNode.id];
    persistNotes();
  });
  btnClearNote.addEventListener("click", () => {
    if (!selectedNode) return;
    delete notesMap[selectedNode.id];
    noteTextEl.value = "";
    persistNotes();
  });
  btnExportNotes.addEventListener("click", () => {
    const payload = {
      schema: "liquefy.history_graph_notes.v1",
      schema_version: 1,
      workspace: graph.workspace || null,
      generated_at_utc: new Date().toISOString(),
      notes: notesMap,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "history_graph_notes.json";
    a.click();
    URL.revokeObjectURL(url);
  });

  btnResetView.addEventListener("click", () => {
    camera = { rotX: 0.52, rotY: 0.58, panX: 0, panY: 0, zoom: 1.0, depth: 720 };
  });
  btnCenter.addEventListener("click", () => {
    camera.panX = 0;
    camera.panY = 0;
  });
  btnShuffle.addEventListener("click", () => {
    for (const n of nodes) {
      n.x += (rand() - 0.5) * 140;
      n.y += (rand() - 0.5) * 140;
      n.z += (rand() - 0.5) * 140;
    }
  });
  btnPause.addEventListener("click", () => { physicsPaused = true; });
  btnResume.addEventListener("click", () => { physicsPaused = false; });

  canvas.addEventListener("contextmenu", (e) => e.preventDefault());
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const delta = Math.sign(e.deltaY);
    const factor = delta > 0 ? 0.92 : 1.09;
    camera.zoom = Math.max(0.25, Math.min(4.0, camera.zoom * factor));
  }, { passive: false });

  canvas.addEventListener("mousedown", (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    lastMouse = { x: mx, y: my };

    const picked = pickNode(mx, my);
    if (picked && e.button === 0 && !e.shiftKey) {
      selectedNode = picked;
      selectedNode.fixed = true;
      dragMode = "node";
      updateSelectedNodeUI();
      canvas.classList.add("dragging");
      return;
    }

    if (e.button === 1 || e.button === 2 || e.shiftKey) dragMode = "pan";
    else dragMode = "rotate";
    canvas.classList.add("dragging");
  });

  window.addEventListener("mouseup", () => {
    if (selectedNode) selectedNode.fixed = false;
    dragMode = "none";
    canvas.classList.remove("dragging");
  });

  window.addEventListener("mousemove", (e) => {
    if (dragMode === "none") return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const dx = mx - lastMouse.x;
    const dy = my - lastMouse.y;
    lastMouse = { x: mx, y: my };

    if (dragMode === "rotate") {
      camera.rotY += dx * 0.008;
      camera.rotX += dy * 0.008;
      camera.rotX = Math.max(-1.35, Math.min(1.35, camera.rotX));
      return;
    }
    if (dragMode === "pan") {
      camera.panX += dx;
      camera.panY += dy;
      return;
    }
    if (dragMode === "node" && selectedNode) {
      const pr = project(selectedNode);
      const k = Math.max(0.15, pr.p * camera.zoom);
      selectedNode.x += dx / k;
      selectedNode.y += dy / k;
      selectedNode.vx = 0;
      selectedNode.vy = 0;
      selectedNode.vz = 0;
    }
  });

  function tick() {
    if (physicsPaused) return;
    for (const n of nodes) {
      if (n.fixed) continue;
      n.vx *= 0.87;
      n.vy *= 0.87;
      n.vz *= 0.87;
    }

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dz = b.z - a.z;
        const d2 = dx * dx + dy * dy + dz * dz + 0.01;
        const rep = 2200 / d2;
        const fx = rep * dx;
        const fy = rep * dy;
        const fz = rep * dz;
        if (!a.fixed) { a.vx -= fx; a.vy -= fy; a.vz -= fz; }
        if (!b.fixed) { b.vx += fx; b.vy += fy; b.vz += fz; }
      }
    }

    for (const e of edges) {
      const dx = e.b.x - e.a.x;
      const dy = e.b.y - e.a.y;
      const dz = e.b.z - e.a.z;
      const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
      const target = 130;
      const force = (dist - target) * 0.012;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      const fz = (dz / dist) * force;
      if (!e.a.fixed) { e.a.vx += fx; e.a.vy += fy; e.a.vz += fz; }
      if (!e.b.fixed) { e.b.vx -= fx; e.b.vy -= fy; e.b.vz -= fz; }
    }

    for (const n of nodes) {
      if (n.fixed) continue;
      n.x += n.vx;
      n.y += n.vy;
      n.z += n.vz;
      n.x = Math.max(-1400, Math.min(1400, n.x));
      n.y = Math.max(-1400, Math.min(1400, n.y));
      n.z = Math.max(-1400, Math.min(1400, n.z));
    }
  }

  function draw() {
    const w = width();
    const h = height();
    ctx.clearRect(0, 0, w, h);
    const projected = new Map();
    for (const n of nodes) projected.set(n.id, project(n));

    const edgeDraw = edges.map(e => ({
      e,
      a: projected.get(e.a.id),
      b: projected.get(e.b.id),
    })).filter(x => x.a && x.b);
    edgeDraw.sort((x, y) => ((x.a.z + x.b.z) - (y.a.z + y.b.z)));

    for (const row of edgeDraw) {
      const depth = Math.max(0.12, Math.min(0.95, (row.a.p + row.b.p) / 2));
      ctx.strokeStyle = "rgba(57,65,74," + depth.toFixed(3) + ")";
      ctx.lineWidth = 0.8 + 0.9 * depth;
      ctx.beginPath();
      ctx.moveTo(row.a.sx, row.a.sy);
      ctx.lineTo(row.b.sx, row.b.sy);
      ctx.stroke();
    }

    const nodeDraw = nodes.map(n => ({ n, p: projected.get(n.id) })).filter(x => x.p);
    nodeDraw.sort((a, b) => a.p.z - b.p.z);
    for (const row of nodeDraw) {
      const n = row.n;
      const p = row.p;
      const color = kindColor[n.kind] || kindColor.other;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(p.sx, p.sy, p.r, 0, Math.PI * 2);
      ctx.fill();
      if (selectedNode && selectedNode.id === n.id) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, p.r + 2.2, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.fillStyle = "rgba(214,221,230," + Math.max(0.45, Math.min(1, p.p)).toFixed(3) + ")";
      ctx.font = "11px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif";
      ctx.fillText(String(n.label || n.id), p.sx + p.r + 4, p.sy + 3);
    }
  }

  function frame() {
    tick();
    draw();
    requestAnimationFrame(frame);
  }

  meta.textContent = `nodes=${nodes.length} edges=${edges.length} generated=${graph.generated_at_utc || "n/a"} notes_key=${notesStoreKey}`;
  resize();
  updateSelectedNodeUI();
  requestAnimationFrame(frame);
  </script>
</body>
</html>
"""
    return template.replace("__TITLE__", safe_title).replace("__GRAPH_JSON__", graph_json)


def cmd_render_graph(args: argparse.Namespace) -> int:
    in_path = Path(args.input).expanduser().resolve()
    if not in_path.exists():
        res = {"error": f"input graph not found: {in_path}"}
        if args.json:
            _emit("render-graph", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(res["error"], file=sys.stderr)
        return 1

    try:
        payload = json.loads(in_path.read_text(encoding="utf-8"))
    except Exception as exc:
        res = {"error": f"failed to parse input graph JSON: {exc}"}
        if args.json:
            _emit("render-graph", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(res["error"], file=sys.stderr)
        return 1

    graph = payload
    if isinstance(payload, dict) and "result" in payload and isinstance(payload.get("result"), dict):
        maybe_graph = payload["result"].get("graph")
        if isinstance(maybe_graph, dict):
            graph = maybe_graph

    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        res = {"error": "input JSON does not contain graph nodes/edges"}
        if args.json:
            _emit("render-graph", False, res, Path(args.json_file).expanduser().resolve() if args.json_file else None)
        else:
            print(res["error"], file=sys.stderr)
        return 1

    out_path = Path(args.out).expanduser().resolve() if args.out else in_path.with_suffix(".html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = _render_graph_html(graph, str(args.title))
    out_path.write_text(html, encoding="utf-8")

    result = {
        "input_path": str(in_path),
        "out_path": str(out_path),
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "title": str(args.title),
    }
    if args.json:
        _emit("render-graph", True, result, Path(args.json_file).expanduser().resolve() if args.json_file else None)
    else:
        print(f"render-graph: wrote {out_path}")
        print(f"  nodes={result['node_count']} edges={result['edge_count']}")
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

    p_graph = sub.add_parser("export-graph", help="Export history/provider relationships as graph JSON")
    p_graph.add_argument("--workspace", required=True)
    p_graph.add_argument("--config", default=None)
    p_graph.add_argument("--out", default=None, help="Output graph JSON path")
    p_graph.add_argument("--max-runs-per-provider", type=int, default=20)
    p_graph.add_argument("--max-actions", type=int, default=100)
    p_graph.add_argument("--json", action="store_true")
    p_graph.add_argument("--json-file", default=None)
    p_graph.set_defaults(fn=cmd_export_graph)

    p_render = sub.add_parser("render-graph", help="Render graph JSON to a standalone interactive HTML file")
    p_render.add_argument("--in", dest="input", required=True, help="Input graph JSON path")
    p_render.add_argument("--out", default=None, help="Output HTML path")
    p_render.add_argument("--title", default="Liquefy History Guard Graph")
    p_render.add_argument("--json", action="store_true")
    p_render.add_argument("--json-file", default=None)
    p_render.set_defaults(fn=cmd_render_graph)

    return ap



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    rc = int(args.fn(args))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
