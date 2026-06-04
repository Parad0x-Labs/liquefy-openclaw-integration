#!/usr/bin/env python3
"""
Liquefy / Trace Vault Local Decompressor (Public Reference Path)
================================================================
A real, deterministic, self-contained reference decoder for ``.null`` archives
produced by the Trace Vault pack pipeline (``tools/tracevault_pack.py``).

Why this exists
---------------
Any "forensically-faithful compressed evidence" claim is only as good as a third
party's ability to *independently* reconstruct the original bytes and confirm
they match the recorded ``sha256_original``. This script is that independent
decoder. It does no network calls, ships no sealed binary, and reuses the exact
in-repo engine implementations that the pack pipeline used to compress.

What it does
------------
1. Reads a ``.null`` archive (the per-file blob written by the pack pipeline).
2. Looks the archive up in ``tracevault_index.json`` to learn which engine
   produced it (``engine_used``), whether it is encrypted, the tenant id, and the
   SHA-256 of the *original* plaintext (``sha256_original``).
3. Reconstructs the original bytes by, in order:
     - unsealing the per-tenant AES-256-GCM envelope (LSEC v2) when ``encrypted``,
     - stripping the optional MRTV safety header (``SAFE`` + 4-byte tag),
     - decompressing with the recorded engine, loaded through
       ``orchestrator.engine_map.get_engine_instance`` exactly as the pipeline
       loads it -- or zstd for the ``zstd-fallback`` safety path.
4. With ``--verify-only``, recomputes SHA-256 over the reconstructed bytes and
   compares it to the receipt's ``sha256_original``, exiting NON-ZERO on mismatch.

Determinism
-----------
The *decode* direction is deterministic / byte-stable: it reconstructs the exact
original bytes (proven by the SHA-256 check), regardless of the zstd build that
produced the archive. The *compress* direction is intentionally NOT bit-stable
across zstd versions/levels (see tests/test_roundtrip_byteperfect.py), which is
why faithfulness is anchored on the decoded plaintext hash, never on the
compressed-byte layout.

Encrypted archives require the tenant master secret in the ``LIQUEFY_SECRET``
environment variable.

Usage
-----
    # Verify a single archive against its recorded original hash (no output written)
    python decompress_local.py vault/run_001/events.jsonl.null --verify-only

    # Restore a single archive to a file (also integrity-checked when a hash exists)
    python decompress_local.py vault/run_001/events.jsonl.null -o restored/events.jsonl

    # Subcommand form used by tools/tracevault_restore.py find_decoder():
    python decompress_local.py decompress <archive> <output>

Exit codes
----------
    0  success (restored, or verification matched)
    1  usage / I/O error (bad args, archive or index not found)
    2  VERIFICATION MISMATCH (reconstructed bytes != recorded sha256_original)
    3  decode failure (could not reconstruct the original bytes at all)
    4  cannot verify (no recorded sha256 available, or missing decryption secret)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

# ── Make the in-repo engine implementations importable ───────────────────────
# Engines live under api/ and are loaded through orchestrator.engine_map, exactly
# as the production pack/restore pipeline loads them. We reuse those codecs
# verbatim rather than reimplementing any decompressor here.
REPO_ROOT = Path(__file__).resolve().parent
API_DIR = REPO_ROOT / "api"
if API_DIR.is_dir() and str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
SAFE_MAGIC = b"SAFE"            # MRTV safety-valve wrapper prefix
SAFE_ZSTD_TAG = b"ZST\x00"     # tag used by the safety valve's zstd fail-safe
LSEC_MAGIC = b"LSEC"           # per-tenant AES-256-GCM envelope magic (liquefy_security)

# Exit codes (documented in the module docstring).
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_MISMATCH = 2
EXIT_DECODE_FAIL = 3
EXIT_CANNOT_VERIFY = 4

INDEX_NAME = "tracevault_index.json"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Index / receipt lookup ───────────────────────────────────────────────────
def find_index(archive: Path, explicit: Optional[Path]) -> Optional[Path]:
    """Locate the tracevault_index.json that describes ``archive``.

    The pack pipeline writes the index alongside the ``.null`` blobs, so we look
    in the archive's directory first, then walk up a few parents (a vault may sit
    inside a larger run directory).
    """
    if explicit is not None:
        return explicit if explicit.is_file() else None

    seen = set()
    d = archive.resolve().parent
    for _ in range(8):
        if d in seen:
            break
        seen.add(d)
        candidate = d / INDEX_NAME
        if candidate.is_file():
            return candidate
        if d.parent == d:
            break
        d = d.parent
    return None


def _iter_receipts(index: Dict) -> Iterator[Dict]:
    """Yield every per-file receipt: top-level ones and chunked big-file parts."""
    for receipt in index.get("receipts", []) or []:
        yield receipt
    for group in index.get("bigfile_groups", []) or []:
        for part in group.get("parts", []) or []:
            yield part


def find_receipt(index: Dict, archive: Path) -> Optional[Dict]:
    """Find the receipt whose output blob is ``archive``.

    Matched on the output file's basename rather than its full ``output_path``:
    the path recorded at pack time is absolute and goes stale the moment a vault
    is copied or moved, but the blob's name is stable.
    """
    target = archive.name
    for receipt in _iter_receipts(index):
        output_path = receipt.get("output_path")
        if output_path and Path(str(output_path)).name == target:
            return receipt
    return None


# ── Decode primitives (reuse the real engines) ───────────────────────────────
def decode_zstd(payload: bytes) -> Optional[bytes]:
    try:
        import zstandard as zstd

        return zstd.ZstdDecompressor().decompress(payload)
    except Exception:
        return None


def decode_with_engine(engine_id: Optional[str], payload: bytes) -> Optional[bytes]:
    """Decompress ``payload`` with the recorded engine, via the real registry."""
    if not engine_id or engine_id == "zstd-fallback":
        return None
    try:
        from orchestrator.engine_map import get_engine_instance
    except Exception as exc:  # pragma: no cover - environment/setup error
        _err(f"[ERROR] cannot import engine registry from api/: {exc}")
        return None

    instance = get_engine_instance(engine_id)
    if instance is None or not hasattr(instance, "decompress"):
        _err(f"[WARN] engine '{engine_id}' is not available in this build")
        return None
    try:
        out = instance.decompress(payload)
    except Exception as exc:
        _err(f"[WARN] engine '{engine_id}' failed to decompress: {exc}")
        return None
    if isinstance(out, bytearray):
        out = bytes(out)
    return out if isinstance(out, bytes) else None


def brute_force_decode(payload: bytes, expected_sha256: Optional[str]) -> Optional[bytes]:
    """Last resort: try every registered engine, accept only an exact hash match.

    Gated on ``expected_sha256`` so it can never return wrong bytes as a
    "success". Only reached when the recorded engine is unavailable or failed;
    its use is logged so coverage is never silently narrowed.
    """
    if not expected_sha256:
        return None
    try:
        from orchestrator.engine_map import ENGINE_MAP, get_engine_instance
    except Exception:
        return None

    _err("[INFO] recorded engine did not decode; brute-forcing the engine "
         "registry (gated on sha256_original)")
    for engine_id in ENGINE_MAP.keys():
        try:
            instance = get_engine_instance(engine_id)
            if instance is None or not hasattr(instance, "decompress"):
                continue
            out = instance.decompress(payload)
            if isinstance(out, bytearray):
                out = bytes(out)
            if isinstance(out, bytes) and out and sha256_bytes(out) == expected_sha256:
                _err(f"[INFO] brute-force reconstruction matched via engine '{engine_id}'")
                return out
        except Exception:
            continue
    return None


def unseal_if_encrypted(blob: bytes, encrypted: bool, tenant_id: Optional[str]) -> Tuple[Optional[bytes], Optional[str]]:
    """Return (plaintext, error_message). ``error_message`` is None on success."""
    if not encrypted:
        return blob, None
    if not tenant_id:
        return None, "encrypted archive but no tenant_id available (receipt or --tenant-id)"
    secret = os.environ.get("LIQUEFY_SECRET")
    if not secret:
        return None, "MISSING_SECRET: set LIQUEFY_SECRET to restore encrypted archives"
    try:
        from liquefy_security import LiquefySecurity

        plain, _meta = LiquefySecurity(master_secret=secret).unseal(blob, tenant_id)
        return plain, None
    except Exception as exc:
        return None, f"unseal failed for tenant '{tenant_id}': {exc}"


def reconstruct_original(
    blob: bytes,
    *,
    engine_used: Optional[str],
    encrypted: bool,
    tenant_id: Optional[str],
    expected_sha256: Optional[str],
) -> Tuple[Optional[bytes], Optional[str]]:
    """Reconstruct the original plaintext bytes from a ``.null`` archive blob.

    Mirrors the canonical decode path used by tools/tracevault_restore.py
    (``local_decode_receipt``):
      unseal -> strip optional SAFE header -> engine decode (-> zstd -> brute).

    Returns (original_bytes, error_message). On success error_message is None.
    """
    plain, err = unseal_if_encrypted(blob, encrypted, tenant_id)
    if plain is None:
        return None, err

    # The MRTV safety valve only prepends a header in its zstd fail-safe path
    # (b"SAFE" + b"ZST\x00"); successful engine seals carry no prefix. Strip it
    # defensively when present.
    payload = plain
    safe_tag = None
    if payload.startswith(SAFE_MAGIC) and len(payload) >= 8:
        safe_tag = payload[4:8]
        payload = payload[8:]

    decoded = decode_with_engine(engine_used, payload)
    if decoded is None and (engine_used == "zstd-fallback" or safe_tag == SAFE_ZSTD_TAG):
        decoded = decode_zstd(payload)
    if decoded is None:
        # The recorded engine may itself have stored a raw zstd frame; try it.
        decoded = decode_zstd(payload)
    if decoded is None:
        decoded = brute_force_decode(payload, expected_sha256)

    if decoded is None:
        return None, "could not reconstruct original bytes with any known decoder"
    return decoded, None


# ── CLI ──────────────────────────────────────────────────────────────────────
_VERBS = {"decompress", "restore", "verify"}


def _split_leading_verb(argv) -> Tuple[Optional[str], list]:
    """Accept an optional leading verb for compatibility with the decoder-wrapper
    contract in tools/tracevault_restore.py (``decompress <archive> <output>``).
    Returns (verb_or_None, remaining_argv).
    """
    if argv and argv[0] in _VERBS:
        return argv[0], list(argv[1:])
    return None, list(argv)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decompress_local.py",
        description="Deterministic public reference decoder for Trace Vault .null archives.",
    )
    parser.add_argument("archive", help="Path to the .null archive to decode")
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Output path for restored data (positional form; or use -o/--output)",
    )
    parser.add_argument("-o", "--output", dest="output_flag", default=None,
                        help="Output path for restored data")
    parser.add_argument("--verify-only", action="store_true",
                        help="Reconstruct and check SHA-256 against the receipt; write nothing")
    parser.add_argument("--index", default=None,
                        help=f"Explicit path to {INDEX_NAME} (default: auto-discover near the archive)")
    parser.add_argument("--engine", default=None,
                        help="Override/supply engine_used (when no index/receipt is available)")
    parser.add_argument("--expected-sha256", default=None,
                        help="Override/supply the expected original SHA-256 to verify against")
    parser.add_argument("--tenant-id", default=None,
                        help="Override/supply the tenant id for encrypted archives")
    return parser


def _resolve_receipt_fields(args, blob: bytes, archive: Path) -> Tuple[Dict, Optional[Path]]:
    """Resolve engine_used / sha256_original / encrypted / tenant_id.

    The tracevault index is the source of truth (engine_used + sha256_original are
    recorded per-receipt). Explicit CLI flags win when provided, and encryption is
    cross-checked against the LSEC envelope magic so a moved/edited index can't
    cause us to skip a decrypt.
    """
    receipt: Dict = {}
    index_path = find_index(archive, Path(args.index).resolve() if args.index else None)
    if index_path is not None:
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except Exception as exc:
            _err(f"[WARN] could not read index {index_path}: {exc}")
            index = {}
        found = find_receipt(index, archive)
        if found is not None:
            receipt = found
        else:
            _err(f"[WARN] no receipt for '{archive.name}' in {index_path}")

    engine_used = args.engine or receipt.get("engine_used")
    expected_sha256 = args.expected_sha256 or receipt.get("sha256_original")

    encrypted = receipt.get("encrypted")
    if encrypted is None:
        # No receipt flag — detect from the blob itself.
        encrypted = blob.startswith(LSEC_MAGIC)
    tenant_id = args.tenant_id or receipt.get("tenant_id")

    resolved = {
        "engine_used": engine_used,
        "expected_sha256": expected_sha256,
        "encrypted": bool(encrypted),
        "tenant_id": tenant_id,
    }
    return resolved, index_path


def _write_output(output: Path, data: bytes) -> None:
    """Write restored bytes atomically (temp file + replace)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.parent / f"{output.name}.tmp.decode"
    try:
        tmp.write_bytes(data)
        os.replace(tmp, output)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    verb, rest = _split_leading_verb(sys.argv[1:] if argv is None else argv)
    args = _build_parser().parse_args(rest)

    verify_only = args.verify_only or verb == "verify"
    output_arg = args.output_flag or args.output

    archive = Path(args.archive)
    if not archive.is_file():
        _err(f"[ERROR] archive not found: {archive}")
        return EXIT_USAGE

    try:
        blob = archive.read_bytes()
    except Exception as exc:
        _err(f"[ERROR] could not read archive {archive}: {exc}")
        return EXIT_USAGE

    fields, index_path = _resolve_receipt_fields(args, blob, archive)
    engine_used = fields["engine_used"]
    expected_sha256 = fields["expected_sha256"]

    decoded, err = reconstruct_original(
        blob,
        engine_used=engine_used,
        encrypted=fields["encrypted"],
        tenant_id=fields["tenant_id"],
        expected_sha256=expected_sha256,
    )

    print("--- Liquefy Trace Vault -- Local Reference Decoder ---")
    print(f"Archive:   {archive}")
    if index_path is not None:
        print(f"Index:     {index_path}")
    print(f"Engine:    {engine_used or '(unknown)'}")
    print(f"Encrypted: {'yes' if fields['encrypted'] else 'no'}")

    if decoded is None:
        _err(f"[ERROR] {err}")
        print("Result: [DECODE FAILED]")
        return EXIT_DECODE_FAIL

    restored_sha256 = sha256_bytes(decoded)

    # ── Verification ─────────────────────────────────────────────────────────
    if expected_sha256:
        matched = restored_sha256 == expected_sha256
        print(f"Restored bytes:    {len(decoded)}")
        print(f"Expected sha256:   {expected_sha256}")
        print(f"Restored sha256:   {restored_sha256}")
        if not matched:
            print("Result: [MISMATCH]")
            _err("[FAIL] reconstructed bytes do NOT match recorded sha256_original")
            return EXIT_MISMATCH
        print("Result: [VERIFIED]")
    else:
        # No recorded hash to check against — be explicit, never fabricate a pass.
        print(f"Restored bytes:    {len(decoded)}")
        print(f"Restored sha256:   {restored_sha256}")
        print("Result: [UNVERIFIED -- no recorded sha256_original available]")
        if verify_only:
            _err("[ERROR] --verify-only requires a recorded sha256 "
                 "(provide an index/receipt or --expected-sha256)")
            return EXIT_CANNOT_VERIFY

    # ── Verify-only stops here (nothing is written) ──────────────────────────
    if verify_only:
        return EXIT_OK

    # ── Restore path: an output target is required ───────────────────────────
    if not output_arg:
        _err("[ERROR] output path required for restore. Use -o <path> "
             "(or --verify-only to only check integrity).")
        return EXIT_USAGE

    output = Path(output_arg)
    try:
        _write_output(output, decoded)
    except Exception as exc:
        _err(f"[ERROR] could not write output {output}: {exc}")
        return EXIT_USAGE

    print(f"Restored to: {output}")
    print("Result: [SUCCESS]")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
