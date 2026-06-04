#!/usr/bin/env python3
"""End-to-end tests for the public reference decoder (decompress_local.py).

These assert the decoder is *real*: it packs the bundled fixtures into a genuine
Trace Vault with tools/tracevault_pack.py, then independently reconstructs each
.null archive and checks the restored bytes against the receipt's
sha256_original. A self-attesting stub cannot pass these.

Covered:
  * --verify-only exits 0 and the printed/recorded hashes match (per receipt).
  * -o restore is byte-identical to the original source file (per receipt).
  * decode is deterministic / byte-stable across runs.
  * a corrupted archive fails verification with a NON-ZERO exit.
  * a wrong expected hash yields a clean MISMATCH (exit 2), not a fabricated pass.
  * the `decompress <archive> <output>` subcommand (tracevault_restore decoder
    contract) restores byte-identically.
  * encrypted archives round-trip with LIQUEFY_SECRET, and fail closed without it.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DECODER = REPO_ROOT / "decompress_local.py"
PACK = REPO_ROOT / "tools" / "tracevault_pack.py"
FIXTURES_DIR = REPO_ROOT / "tools" / "fixtures"

# Exit codes mirrored from decompress_local.py.
EXIT_OK = 0
EXIT_MISMATCH = 2
EXIT_DECODE_FAIL = 3
TEST_SECRET = "unit_test_master_secret_at_least_16_bytes"


def _run(args, env=None):
    return subprocess.run(
        [sys.executable, str(DECODER), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _pack(run_dir: Path, out_dir: Path, encrypt: bool, env=None):
    cmd = [sys.executable, str(PACK), str(run_dir), "--out", str(out_dir), "--json"]
    if not encrypt:
        cmd.append("--no-encrypt")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, f"pack failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload.get("ok") is True, payload
    index = json.loads((out_dir / "tracevault_index.json").read_text(encoding="utf-8"))
    assert index.get("receipts"), "no receipts produced"
    return index


@pytest.fixture(scope="module")
def plain_vault(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("vault_plain")
    index = _pack(FIXTURES_DIR, out_dir, encrypt=False)
    return out_dir, index


def _source_path(run_relpath: str) -> Path:
    return FIXTURES_DIR / run_relpath


def test_verify_only_passes_for_every_receipt(plain_vault):
    vault_dir, index = plain_vault
    for receipt in index["receipts"]:
        archive = Path(receipt["output_path"])
        assert archive.is_file()
        proc = _run([str(archive), "--verify-only"])
        assert proc.returncode == EXIT_OK, (
            f"verify failed for {archive.name}\n{proc.stdout}\n{proc.stderr}"
        )
        # The decoder must print the real recorded hash, not a canned string.
        assert receipt["sha256_original"] in proc.stdout
        assert "[VERIFIED]" in proc.stdout


def test_restore_is_byte_identical_for_every_receipt(plain_vault, tmp_path):
    vault_dir, index = plain_vault
    for receipt in index["receipts"]:
        archive = Path(receipt["output_path"])
        out = tmp_path / ("restored__" + archive.name)
        proc = _run([str(archive), "-o", str(out)])
        assert proc.returncode == EXIT_OK, f"{proc.stdout}\n{proc.stderr}"
        original = _source_path(receipt["run_relpath"])
        assert out.read_bytes() == original.read_bytes(), (
            f"restored bytes differ from original for {receipt['run_relpath']}"
        )
        # Independent confirmation against the recorded hash.
        import hashlib
        assert hashlib.sha256(out.read_bytes()).hexdigest() == receipt["sha256_original"]


def test_decode_is_deterministic(plain_vault, tmp_path):
    vault_dir, index = plain_vault
    archive = Path(index["receipts"][0]["output_path"])
    out1 = tmp_path / "d1.bin"
    out2 = tmp_path / "d2.bin"
    assert _run([str(archive), "-o", str(out1)]).returncode == EXIT_OK
    assert _run([str(archive), "-o", str(out2)]).returncode == EXIT_OK
    assert out1.read_bytes() == out2.read_bytes(), "decode is not byte-stable across runs"


def test_subcommand_form_matches_restore_contract(plain_vault, tmp_path):
    """`decompress <archive> <output>` is how tracevault_restore drives the decoder."""
    vault_dir, index = plain_vault
    receipt = index["receipts"][0]
    archive = Path(receipt["output_path"])
    out = tmp_path / "subcmd.bin"
    proc = _run(["decompress", str(archive), str(out)])
    assert proc.returncode == EXIT_OK, f"{proc.stdout}\n{proc.stderr}"
    assert out.read_bytes() == _source_path(receipt["run_relpath"]).read_bytes()


def test_wrong_expected_hash_reports_clean_mismatch(plain_vault):
    vault_dir, index = plain_vault
    archive = Path(index["receipts"][0]["output_path"])
    proc = _run([
        str(archive),
        "--verify-only",
        "--expected-sha256", "00" * 32,
    ])
    assert proc.returncode == EXIT_MISMATCH, f"{proc.stdout}\n{proc.stderr}"
    assert "[MISMATCH]" in proc.stdout
    assert "[VERIFIED]" not in proc.stdout


def test_corrupted_archive_fails_verification(plain_vault, tmp_path):
    vault_dir, index = plain_vault
    # Copy the whole vault so we can corrupt without disturbing the shared fixture.
    tampered_dir = tmp_path / "tampered_vault"
    shutil.copytree(vault_dir, tampered_dir)
    receipt = index["receipts"][0]
    archive = tampered_dir / Path(receipt["output_path"]).name

    blob = bytearray(archive.read_bytes())
    blob[-1] ^= 0xFF  # flip the last byte
    archive.write_bytes(bytes(blob))

    proc = _run([str(archive), "--verify-only"])
    # Either decode fails outright or the hash mismatches — never a pass.
    assert proc.returncode != EXIT_OK, f"corrupt archive verified!\n{proc.stdout}"
    assert proc.returncode in (EXIT_MISMATCH, EXIT_DECODE_FAIL)
    assert "[VERIFIED]" not in proc.stdout


def test_encrypted_roundtrip_with_and_without_secret(tmp_path):
    env = dict(os.environ)
    env["LIQUEFY_SECRET"] = TEST_SECRET
    out_dir = tmp_path / "vault_enc"
    index = _pack(FIXTURES_DIR, out_dir, encrypt=True, env=env)

    receipt = index["receipts"][0]
    assert receipt["encrypted"] is True
    archive = Path(receipt["output_path"])

    # With the secret: verifies and restores byte-identically.
    proc = _run([str(archive), "--verify-only"], env=env)
    assert proc.returncode == EXIT_OK, f"{proc.stdout}\n{proc.stderr}"
    assert "Encrypted: yes" in proc.stdout

    restored = tmp_path / "enc_restored.bin"
    proc = _run([str(archive), "-o", str(restored)], env=env)
    assert proc.returncode == EXIT_OK
    assert restored.read_bytes() == _source_path(receipt["run_relpath"]).read_bytes()

    # Without the secret: must fail closed, never fabricate a pass.
    env_no_secret = dict(os.environ)
    env_no_secret.pop("LIQUEFY_SECRET", None)
    proc = _run([str(archive), "--verify-only"], env=env_no_secret)
    assert proc.returncode != EXIT_OK
    assert "[VERIFIED]" not in proc.stdout
