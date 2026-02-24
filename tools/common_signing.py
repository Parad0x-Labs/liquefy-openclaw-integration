#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_SIGNED = ("tracevault_index.json", "vault_manifest.json", "run_metadata.json", "AI_SUMMARY.json")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _default_key_path() -> Path:
    env = os.environ.get("LIQUEFY_SIGNING_KEY_PATH")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".liquefy" / "signing.key").resolve()


def _ensure_key(key_path: Optional[Path] = None) -> Path:
    kp = Path(key_path).resolve() if key_path else _default_key_path()
    kp.parent.mkdir(parents=True, exist_ok=True)
    if not kp.exists():
        kp.write_bytes(secrets.token_bytes(32))
        if os.name != "nt":
            try:
                kp.chmod(0o600)
            except OSError:
                pass
    return kp


def _resolve_key_path_for_vault(vault_dir: Path, key_path: Optional[Path] = None) -> Path:
    if key_path is not None:
        return Path(key_path).resolve()
    primary = _default_key_path()
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        if primary.exists():
            return primary
        # Probe writability before choosing the default path.
        with open(primary, "ab"):
            pass
        return primary
    except Exception:
        local = (Path(vault_dir).resolve() / ".liquefy" / "signing.key").resolve()
        local.parent.mkdir(parents=True, exist_ok=True)
        return local


def _read_key(key_path: Optional[Path] = None) -> bytes:
    kp = _ensure_key(key_path)
    return kp.read_bytes()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_bytes(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def sign_vault_artifacts(vault_dir: Path, *, key_path: Optional[Path] = None, signed_files: Iterable[str] = DEFAULT_SIGNED) -> Dict[str, object]:
    vault_dir = Path(vault_dir).resolve()
    key_file = _resolve_key_path_for_vault(vault_dir, key_path)
    key = _read_key(key_file)
    key_id = hashlib.sha256(key).hexdigest()[:16]

    entries: List[Dict[str, object]] = []
    for rel in signed_files:
        p = vault_dir / rel
        if not p.exists() or not p.is_file():
            continue
        raw = p.read_bytes()
        entries.append(
            {
                "path": rel,
                "bytes": len(raw),
                "sha256": _sha256_file(p),
                "hmac_sha256": _sign_bytes(key, raw),
            }
        )

    entries.sort(key=lambda x: str(x["path"]))
    payload = {
        "schema": "liquefy.signature",
        "schema_version": "v1",
        "generated_at_utc": _utc_now(),
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "key_path": str(key_file),
        "signed_files": entries,
    }
    sig_dir = vault_dir / ".liquefy"
    sig_dir.mkdir(parents=True, exist_ok=True)
    sig_path = sig_dir / "signature.json"
    sig_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    if os.name != "nt":
        try:
            sig_path.chmod(0o600)
        except OSError:
            pass
    return {"signature_path": str(sig_path), **payload}


def verify_vault_signature(vault_dir: Path, *, key_path: Optional[Path] = None) -> Dict[str, object]:
    vault_dir = Path(vault_dir).resolve()
    sig_path = vault_dir / ".liquefy" / "signature.json"
    if not sig_path.exists():
        return {"ok": False, "error": "SIGNATURE_NOT_FOUND", "checks": []}
    try:
        sig = json.loads(sig_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": f"SIGNATURE_PARSE_ERROR: {exc}", "checks": []}

    resolved_key_path = None
    if key_path is not None:
        resolved_key_path = Path(key_path).resolve()
    else:
        sig_key = sig.get("key_path")
        if isinstance(sig_key, str) and sig_key.strip():
            resolved_key_path = Path(sig_key).expanduser().resolve()
    key = _read_key(resolved_key_path)
    checks: List[Dict[str, object]] = []
    ok = True
    for row in sig.get("signed_files", []):
        rel = str(row.get("path", ""))
        p = vault_dir / rel
        exists = p.exists() and p.is_file()
        check = {"path": rel, "exists": exists, "ok": False}
        if not exists:
            ok = False
            checks.append(check)
            continue
        raw = p.read_bytes()
        sha = _sha256_file(p)
        mac = _sign_bytes(key, raw)
        check["sha256_ok"] = sha == str(row.get("sha256", ""))
        check["signature_ok"] = mac == str(row.get("hmac_sha256", ""))
        check["ok"] = bool(check["sha256_ok"] and check["signature_ok"])
        if not check["ok"]:
            ok = False
        checks.append(check)
    return {
        "ok": ok,
        "algorithm": sig.get("algorithm"),
        "key_id": sig.get("key_id"),
        "signature_path": str(sig_path),
        "checks": checks,
    }
