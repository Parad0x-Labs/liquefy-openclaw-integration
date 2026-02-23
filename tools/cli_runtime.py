#!/usr/bin/env python3
"""Shared runtime helpers for Liquefy CLI wrappers."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional


def resolve_repo_root(script_file: str) -> Path:
    """Resolve repo root for source and PyInstaller-frozen execution."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        root = Path(meipass)
        if (root / "api").exists():
            return root
        if (root / "_internal" / "api").exists():
            return root / "_internal"
    return Path(script_file).resolve().parent.parent


def get_build_info(tool: str, repo_root: Path) -> Dict[str, Any]:
    try:
        import zstandard as zstd  # type: ignore
        zstd_ver = zstd.__version__
    except Exception:
        zstd_ver = None
    try:
        import cryptography  # type: ignore
        crypto_ver = getattr(cryptography, "__version__", None)
    except Exception:
        crypto_ver = None

    return {
        "tool": tool,
        "liquefy_version": os.environ.get("LIQUEFY_BUILD_VERSION", "dev"),
        "build_commit": os.environ.get("GITHUB_SHA") or os.environ.get("LIQUEFY_BUILD_COMMIT") or "",
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "repo_root": str(repo_root),
        "components": {
            "zstandard": zstd_ver,
            "cryptography": crypto_ver,
        },
    }


def _check(name: str, ok: bool, severity: str = "error", **extra: Any) -> Dict[str, Any]:
    row = {"name": name, "ok": bool(ok), "severity": severity}
    row.update(extra)
    return row


def summarize_checks(checks: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    checks = list(checks)
    errors = sum(1 for c in checks if not c.get("ok") and c.get("severity") == "error")
    warnings = sum(1 for c in checks if not c.get("ok") and c.get("severity") == "warning")
    return {
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.get("ok")),
        "errors": errors,
        "warnings": warnings,
        "ok": errors == 0,
    }


def group_or_world_writable(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def doctor_checks_common(
    *,
    tool: str,
    repo_root: Path,
    api_dir: Optional[Path] = None,
    run_dir: Optional[Path] = None,
    workspace: Optional[Path] = None,
    vault_dir: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    policy_path: Optional[Path] = None,
    require_secret: bool = False,
    secret_env: str = "LIQUEFY_SECRET",
    unsafe_perms_ok: bool = False,
    extra_checks: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    checks.append(_check("repo_root_exists", repo_root.exists(), path=str(repo_root)))
    if api_dir is not None:
        checks.append(_check("api_dir_exists", api_dir.exists(), path=str(api_dir)))
    checks.append(_check("tool_name", True, severity="info", tool=tool))

    def _path_check(name: str, p: Optional[Path], expect_dir: bool = True, required: bool = False):
        if p is None:
            if required:
                checks.append(_check(name, False, path="", detail="missing"))
            return
        exists = p.exists()
        ok = exists and (p.is_dir() if expect_dir else p.is_file())
        sev = "error" if required else "warning"
        checks.append(_check(name, ok if exists else (not required), severity=sev, path=str(p), exists=exists))

    _path_check("run_dir", run_dir, expect_dir=True, required=False)
    _path_check("workspace", workspace, expect_dir=True, required=False)
    _path_check("vault_dir", vault_dir, expect_dir=True, required=False)
    _path_check("policy_file", policy_path, expect_dir=False, required=False)

    if out_dir is not None:
        if out_dir.exists():
            ok = out_dir.is_dir()
            detail = None
            if ok and group_or_world_writable(out_dir) and not unsafe_perms_ok:
                ok = False
                detail = "group/world-writable (use --unsafe-perms-ok to override)"
            checks.append(_check("out_dir", ok, severity="warning", path=str(out_dir), detail=detail))
        else:
            checks.append(_check("out_dir", True, severity="info", path=str(out_dir), detail="will be created"))

    secret_present = bool(os.environ.get(secret_env))
    if require_secret:
        checks.append(_check("secret_present", secret_present, severity="error", env=secret_env))
    else:
        checks.append(_check("secret_present", secret_present, severity="info", env=secret_env, detail="required only for encrypted/apply paths"))

    if extra_checks:
        checks.extend(extra_checks)

    return {
        "version": "liquefy-cli-doctor-v1",
        "build": get_build_info(tool, repo_root),
        "checks": checks,
        "summary": summarize_checks(checks),
    }


def self_test_core(*, tool: str, repo_root: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    started = time.time()
    payload = b"liquefy-self-test::" + os.urandom(32)

    # zstd roundtrip
    try:
        import zstandard as zstd  # type: ignore
        cctx = zstd.ZstdCompressor(level=3)
        dctx = zstd.ZstdDecompressor()
        comp = cctx.compress(payload)
        out = dctx.decompress(comp)
        checks.append(_check("zstd_roundtrip", out == payload, comp_bytes=len(comp)))
    except Exception as exc:
        checks.append(_check("zstd_roundtrip", False, detail=str(exc)))

    # LSEC v2 roundtrip
    try:
        api_dir = repo_root / "api"
        if str(api_dir) not in sys.path:
            sys.path.insert(0, str(api_dir))
        from liquefy_security import LiquefySecurity  # type: ignore

        sec = LiquefySecurity(master_secret="liquefy_self_test_secret_32bytes!!")
        blob = sec.seal(payload, "selftest", {"kind": "self-test"})
        out, meta = sec.unseal(blob, "selftest")
        audit_hidden = b'"meta"' not in blob and b'"ts"' not in blob
        checks.append(_check("lsec_v2_roundtrip", out == payload and isinstance(meta, dict)))
        checks.append(_check("lsec_v2_audit_not_plaintext", audit_hidden))
    except Exception as exc:
        checks.append(_check("lsec_v2_roundtrip", False, detail=str(exc)))

    # policy engine parse/default
    try:
        tools_dir = repo_root / "tools"
        if str(tools_dir) not in sys.path:
            sys.path.insert(0, str(tools_dir))
        from path_policy import default_policy  # type: ignore

        pol = default_policy(mode="strict", source="self-test")
        checks.append(_check("path_policy_default", getattr(pol, "mode", None) == "strict"))
    except Exception as exc:
        checks.append(_check("path_policy_default", False, detail=str(exc)))

    return {
        "version": "liquefy-cli-self-test-v1",
        "build": get_build_info(tool, repo_root),
        "summary": summarize_checks(checks),
        "checks": checks,
        "duration_seconds": round(time.time() - started, 3),
        "fingerprint_sha256": hashlib.sha256(payload).hexdigest(),
    }


def version_result(*, tool: str, repo_root: Path) -> Dict[str, Any]:
    return {
        "version": "liquefy-cli-version-v1",
        "build": get_build_info(tool, repo_root),
    }


def make_policy_namespace(
    *,
    policy: Optional[str] = None,
    mode: Optional[str] = None,
    deny: Optional[List[str]] = None,
    allow: Optional[List[str]] = None,
    allow_category: Optional[List[str]] = None,
    include_secrets: Optional[str] = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        policy=policy,
        mode=mode,
        deny=deny or [],
        allow=allow or [],
        allow_category=allow_category or [],
        include_secrets=include_secrets,
        print_effective_policy=False,
        explain=None,
    )


def write_json_private_default(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass
