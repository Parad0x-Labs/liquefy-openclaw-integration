#!/usr/bin/env python3
from pathlib import Path
import json
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from common_signing import sign_vault_artifacts, verify_vault_signature  # type: ignore


def _write_vault_files(vault_dir: Path):
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "tracevault_index.json").write_text(json.dumps({"version": "tracevault-index-v2"}), encoding="utf-8")
    (vault_dir / "vault_manifest.json").write_text(json.dumps({"vault_id": "v1", "included": []}), encoding="utf-8")
    (vault_dir / "run_metadata.json").write_text(json.dumps({"vault_id": "v1"}), encoding="utf-8")


def test_sign_and_verify_roundtrip(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "signing.key"
    _write_vault_files(vault)

    res = sign_vault_artifacts(vault, key_path=key)
    assert Path(res["signature_path"]).exists()
    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is True
    assert all(c.get("ok") for c in verify["checks"])


def test_sign_verify_detects_tamper(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "signing.key"
    _write_vault_files(vault)
    sign_vault_artifacts(vault, key_path=key)

    (vault / "run_metadata.json").write_text(json.dumps({"vault_id": "v1", "tampered": True}), encoding="utf-8")
    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is False
    assert any(not c.get("ok") for c in verify["checks"])
