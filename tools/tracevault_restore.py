#!/usr/bin/env python3
"""
tracevault_restore.py
=====================
Restore files from a Trace Vault pack using the decoder wrapper.

Usage:
    python tools/tracevault_restore.py ./vault/run_001 --out ./restored/run_001
"""

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from cli_runtime import (
    doctor_checks_common,
    resolve_repo_root,
    self_test_core,
    version_result,
)

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = str(REPO_ROOT / "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)


DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
CLI_SCHEMA_VERSION = "liquefy.tracevault.restore.cli.v1"


class RestoreLimitExceeded(RuntimeError):
    def __init__(self, written_bytes: int, max_output_bytes: int):
        self.written_bytes = int(written_bytes)
        self.max_output_bytes = int(max_output_bytes)
        super().__init__(
            "RESTORE_ABORTED_OUTPUT_LIMIT: "
            f"wrote {self.written_bytes} bytes, cap {self.max_output_bytes} bytes. "
            "Re-run with --max-output-bytes 0 to disable."
        )


class RestoreWriteLimiter:
    def __init__(self, max_output_bytes: int):
        self.max_output_bytes = int(max_output_bytes)
        self.total_written = 0
        self._lock = threading.Lock()

    def enabled(self) -> bool:
        return self.max_output_bytes > 0

    def reserve(self, nbytes: int) -> int:
        n = int(nbytes)
        if n <= 0:
            return self.total_written
        if self.max_output_bytes <= 0:
            with self._lock:
                self.total_written += n
                return self.total_written
        with self._lock:
            attempted = self.total_written + n
            if attempted > self.max_output_bytes:
                raise RestoreLimitExceeded(attempted, self.max_output_bytes)
            self.total_written = attempted
            return self.total_written


def _tmp_restore_path(target_path: Path) -> Path:
    return target_path.parent / f"{target_path.name}.tmp.liquefy"


def _cleanup_tmp(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _harden_file_mode(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _emit_cli_json(payload: Dict, enabled: bool, json_file: Optional[Path]) -> None:
    if json_file:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _harden_file_mode(json_file)
    if enabled:
        print(json.dumps(payload, indent=2))


def _error_code_from_exception(exc: BaseException) -> str:
    msg = str(exc)
    if isinstance(exc, RestoreLimitExceeded):
        return "restore_output_limit"
    if isinstance(exc, SystemExit):
        if "MISSING_INDEX" in msg or "tracevault_index.json" in msg:
            return "missing_index"
        if "MISSING_SECRET" in msg:
            return "missing_secret"
        return "restore_failed"
    return "restore_failed"


def atomic_write_bytes_counted(
    target_path: Path,
    data: bytes,
    limiter: RestoreWriteLimiter,
    chunk_size: int = 1 << 20,
) -> None:
    tmp_path = _tmp_restore_path(target_path)
    _cleanup_tmp(tmp_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tmp_path.open("wb") as out_f:
            for i in range(0, len(data), max(1, chunk_size)):
                chunk = data[i:i + max(1, chunk_size)]
                limiter.reserve(len(chunk))
                out_f.write(chunk)
        os.replace(tmp_path, target_path)
    except Exception:
        _cleanup_tmp(tmp_path)
        raise


def atomic_copy_file_counted(
    src_path: Path,
    target_path: Path,
    limiter: RestoreWriteLimiter,
    chunk_size: int = 1 << 20,
) -> None:
    tmp_path = _tmp_restore_path(target_path)
    _cleanup_tmp(tmp_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with src_path.open("rb") as in_f, tmp_path.open("wb") as out_f:
            while True:
                chunk = in_f.read(max(1, chunk_size))
                if not chunk:
                    break
                limiter.reserve(len(chunk))
                out_f.write(chunk)
        os.replace(tmp_path, target_path)
    except Exception:
        _cleanup_tmp(tmp_path)
        raise


def find_decoder() -> List[str]:
    """Locate the decoder wrapper. Prefer ./liquefy, fall back to python."""
    if sys.platform != "win32":
        wrapper = REPO_ROOT / "liquefy"
        if wrapper.exists() and os.access(str(wrapper), os.X_OK):
            return [str(wrapper)]

    for ext in (".exe", ".bat", ".cmd"):
        candidate = REPO_ROOT / f"liquefy{ext}"
        if candidate.exists():
            return [str(candidate)]

    for name in ("decompress_local.py", "tools/decompress.py", "appliance/decoder.py"):
        candidate = REPO_ROOT / name
        if candidate.exists():
            return [sys.executable, str(candidate)]

    return []


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def run_decompress(
    decoder: List[str],
    archive_path: Path,
    restored_path: Path,
    limiter: Optional[RestoreWriteLimiter] = None,
) -> bool:
    restored_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = _tmp_restore_path(restored_path)
    _cleanup_tmp(tmp_path)
    try:
        cmd = decoder + ["decompress", str(archive_path), str(tmp_path)]
        if limiter is None or not limiter.enabled():
            subprocess.run(cmd, check=True, capture_output=True)
            os.replace(tmp_path, restored_path)
            return True

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        counted = 0
        try:
            while True:
                rc = proc.poll()
                cur_size = tmp_path.stat().st_size if tmp_path.exists() else 0
                if cur_size > counted:
                    limiter.reserve(cur_size - counted)
                    counted = cur_size
                if rc is not None:
                    if rc != 0:
                        _cleanup_tmp(tmp_path)
                        return False
                    break
                time.sleep(0.02)
            os.replace(tmp_path, restored_path)
            return True
        except RestoreLimitExceeded:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            _cleanup_tmp(tmp_path)
            raise
    except (subprocess.CalledProcessError, FileNotFoundError):
        _cleanup_tmp(tmp_path)
        return False


def safe_restore_target_path(out_dir: Path, rel_path: str) -> Path:
    rel_text = str(rel_path).replace("\\", "/")
    rel = Path(rel_text)
    # is_absolute() misses Unix-style leading "/" on Windows (no drive letter)
    if rel.is_absolute() or rel_text.startswith("/"):
        raise ValueError("invalid_restore_path:absolute")
    if any(part == ".." for part in rel.parts):
        raise ValueError("invalid_restore_path:traversal")
    target = (out_dir / rel).resolve(strict=False)
    base = out_dir.resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError("invalid_restore_path:outside_output_dir")
    return target


def verify_hash(restored_path: Path, expected_sha256: Optional[str], label: str) -> bool:
    if not expected_sha256:
        return True
    got = sha256_file(restored_path)
    if got == expected_sha256:
        return True
    print(f"  [FAIL] {label} -- sha256 mismatch")
    print(f"         expected={expected_sha256}")
    print(f"         got     ={got}")
    return False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_zstd(payload: bytes) -> Optional[bytes]:
    try:
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(payload)
    except Exception:
        return None


def decode_with_engine(engine_id: Optional[str], payload: bytes) -> Optional[bytes]:
    if not engine_id or engine_id == "zstd-fallback":
        return None
    try:
        from orchestrator.engine_map import get_engine_instance
        instance = get_engine_instance(engine_id)
        if instance is None or not hasattr(instance, "decompress"):
            return None
        out = instance.decompress(payload)
        if isinstance(out, bytes):
            return out
        if isinstance(out, bytearray):
            return bytes(out)
    except Exception:
        return None
    return None


def maybe_unseal(blob: bytes, receipt: Dict) -> Optional[bytes]:
    if not receipt.get("encrypted"):
        return blob

    tenant_id = receipt.get("tenant_id")
    if not tenant_id:
        print("  [FAIL] encrypted blob missing tenant_id in receipt")
        return None

    secret = os.environ.get("LIQUEFY_SECRET")
    if not secret:
        print("  [FAIL] MISSING_SECRET: set LIQUEFY_SECRET to restore encrypted blobs")
        return None

    try:
        from liquefy_security import LiquefySecurity
        security = LiquefySecurity(
            master_secret=secret,
        )
        plain, _meta = security.unseal(blob, tenant_id)
        return plain
    except Exception as exc:
        print(f"  [FAIL] unseal failed for tenant '{tenant_id}': {exc}")
        return None


def brute_force_decode(payload: bytes, expected_sha256: Optional[str]) -> Optional[bytes]:
    try:
        from orchestrator.engine_map import ENGINE_MAP, get_engine_instance
    except Exception:
        return None

    skip_ids = {"liquefy-nginx-rep-v1"}
    for engine_id in ENGINE_MAP.keys():
        if engine_id in skip_ids:
            continue
        try:
            instance = get_engine_instance(engine_id)
            if instance is None or not hasattr(instance, "decompress"):
                continue
            out = instance.decompress(payload)
            if isinstance(out, bytearray):
                out = bytes(out)
            if not isinstance(out, bytes) or not out:
                continue
            if expected_sha256 and sha256_bytes(out) != expected_sha256:
                continue
            return out
        except Exception:
            continue
    return None


def local_decode_receipt(archive_path: Path, receipt: Dict) -> Optional[bytes]:
    try:
        blob = archive_path.read_bytes()
    except Exception:
        return None

    expected_sha256 = receipt.get("sha256_original")
    engine_used = receipt.get("engine_used")

    plain = maybe_unseal(blob, receipt)
    if plain is None:
        return None

    payload = plain
    safe_tag = None
    if payload.startswith(b"SAFE") and len(payload) >= 8:
        safe_tag = payload[4:8]
        payload = payload[8:]

    # First-choice: decode using the engine recorded at pack time.
    decoded = decode_with_engine(engine_used, payload)
    if decoded is None and (engine_used == "zstd-fallback" or safe_tag == b"ZST\x00"):
        decoded = decode_zstd(payload)

    # If no declared engine worked, try zstd and then brute-force engines.
    if decoded is None:
        decoded = decode_zstd(payload)
    if decoded is None:
        decoded = brute_force_decode(payload, expected_sha256)

    if decoded is None:
        return None
    if expected_sha256 and sha256_bytes(decoded) != expected_sha256:
        return None
    return decoded


def write_local_decoded(
    archive_path: Path,
    receipt: Dict,
    restored_path: Path,
    limiter: Optional[RestoreWriteLimiter] = None,
) -> bool:
    decoded = local_decode_receipt(archive_path, receipt)
    if decoded is None:
        return False
    if limiter is None:
        limiter = RestoreWriteLimiter(0)
    atomic_write_bytes_counted(restored_path, decoded, limiter)
    return True


def restore(vault_dir: Path, out_dir: Path, max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES):
    index_path = vault_dir / "tracevault_index.json"
    if not index_path.exists():
        raise SystemExit(f"MISSING_INDEX: {index_path}")

    index = json.loads(index_path.read_text(encoding="utf-8"))
    receipts = index.get("receipts", [])
    bigfile_groups = index.get("bigfile_groups", [])
    decoder = find_decoder()

    restored_count = 0
    failed_count = 0
    limiter = RestoreWriteLimiter(max_output_bytes)

    if not decoder:
        print("  [WARN] Decoder not found; using local restore fallback.")

    worker_count = max(1, min((os.cpu_count() or 4), 8))
    if limiter.enabled():
        # Default safety mode favors deterministic cap enforcement over parallel restore throughput.
        worker_count = 1

    def restore_normal_receipt(receipt: Dict) -> Tuple[bool, str]:
        archive_path = Path(receipt.get("output_path", ""))
        rel = receipt.get("run_relpath") or archive_path.stem

        if not archive_path.exists():
            print(f"  [MISS] {archive_path} not found")
            return False, rel

        try:
            restored_path = safe_restore_target_path(out_dir, str(rel))
        except ValueError as exc:
            print(f"  [FAIL] {rel} -- {exc}")
            return False, str(rel)
        restored_ok = False
        if decoder:
            restored_ok = run_decompress(decoder, archive_path, restored_path, limiter=limiter)
        if not restored_ok:
            restored_ok = write_local_decoded(archive_path, receipt, restored_path, limiter=limiter)
        if not restored_ok:
            # Last resort: preserve artifact, but hash check will likely fail.
            atomic_copy_file_counted(archive_path, restored_path, limiter)

        if not verify_hash(restored_path, receipt.get("sha256_original"), rel):
            return False, rel

        return True, rel

    # Restore normal files (parallel per-file restore).
    if worker_count == 1:
        for receipt in receipts:
            ok, _rel = restore_normal_receipt(receipt)
            if ok:
                restored_count += 1
            else:
                failed_count += 1
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [pool.submit(restore_normal_receipt, receipt) for receipt in receipts]
            for fut in as_completed(futures):
                ok, _rel = fut.result()
                if ok:
                    restored_count += 1
                else:
                    failed_count += 1

    # Restore chunked big files by concatenating decompressed parts.
    with tempfile.TemporaryDirectory(prefix="tracevault_restore_chunks_") as temp_dir:
        temp_root = Path(temp_dir)

        for group in bigfile_groups:
            rel = group.get("run_relpath")
            parts = group.get("parts", [])
            expected_sha = group.get("sha256_original")

            if not rel or not parts:
                print("  [FAIL] Invalid chunk group entry in index")
                failed_count += 1
                continue

            try:
                target_path = safe_restore_target_path(out_dir, str(rel))
            except ValueError as exc:
                print(f"  [FAIL] {rel} -- {exc}")
                failed_count += 1
                continue
            target_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_target = _tmp_restore_path(target_path)
            _cleanup_tmp(tmp_target)

            chunk_ok = True
            try:
                with tmp_target.open("wb") as out_f:
                    ordered_parts = sorted(parts, key=lambda p: int(p.get("chunk_index", 0)))
                    for part in ordered_parts:
                        archive_path = Path(part.get("output_path", ""))
                        chunk_index = int(part.get("chunk_index", 0))
                        chunk_out = temp_root / f"{sanitize_for_tmp(rel)}_{chunk_index:06d}.bin"

                        if not archive_path.exists():
                            print(f"  [MISS] {archive_path} not found")
                            chunk_ok = False
                            break
                        chunk_ok_local = False
                        if decoder:
                            chunk_ok_local = run_decompress(decoder, archive_path, chunk_out)
                        if not chunk_ok_local:
                            part_receipt = dict(part)
                            chunk_ok_local = write_local_decoded(archive_path, part_receipt, chunk_out)
                        if not chunk_ok_local:
                            print(f"  [FAIL] {rel} chunk {chunk_index} -- decode failed")
                            chunk_ok = False
                            break

                        with chunk_out.open("rb") as in_f:
                            while True:
                                chunk = in_f.read(1 << 20)
                                if not chunk:
                                    break
                                limiter.reserve(len(chunk))
                                out_f.write(chunk)
            except RestoreLimitExceeded:
                _cleanup_tmp(tmp_target)
                raise
            except Exception:
                _cleanup_tmp(tmp_target)
                raise

            if not chunk_ok:
                _cleanup_tmp(tmp_target)
                failed_count += 1
                continue
            if not verify_hash(tmp_target, expected_sha, rel):
                _cleanup_tmp(tmp_target)
                failed_count += 1
                continue

            os.replace(tmp_target, target_path)

            restored_count += 1

    print(f"\n  restored: {restored_count} files")
    if failed_count:
        print(f"  failed:   {failed_count}")
    print(f"  output:   {out_dir}")
    return {
        "vault_dir": str(vault_dir),
        "out_dir": str(out_dir),
        "restored_files": restored_count,
        "failed_files": failed_count,
        "decoder_found": bool(decoder),
        "max_output_bytes": int(max_output_bytes),
        "output_limit_enabled": bool(max_output_bytes > 0),
        "written_bytes": int(limiter.total_written),
    }


def sanitize_for_tmp(value: str) -> str:
    return value.replace("\\", "_").replace("/", "_")


def _emit_runtime_payload(
    *,
    command: str,
    result: Dict,
    ok: bool,
    vault_dir: Optional[Path],
    out_dir: Optional[Path],
    enabled_json: bool,
    json_file: Optional[Path],
) -> None:
    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "tracevault_restore",
        "command": command,
        "ok": bool(ok),
        "exit_code": 0 if ok else 1,
        "vault_dir": str(vault_dir) if vault_dir is not None else None,
        "vault_name": vault_dir.name if vault_dir is not None else None,
        "out_dir": str(out_dir) if out_dir is not None else None,
        "out_dir_name": out_dir.name if out_dir is not None else None,
        "result": result,
    }
    _emit_cli_json(payload, enabled=enabled_json, json_file=json_file)
    if not enabled_json:
        if command == "version":
            build = result.get("build", {})
            print(
                f"liquefy tracevault-restore {build.get('liquefy_version','dev')} "
                f"({build.get('system','?')}/{build.get('machine','?')})"
            )
        elif command in {"self_test", "doctor"}:
            summary = result.get("summary", {})
            print(
                f"[{command}] ok={summary.get('ok')} "
                f"passed={summary.get('checks_passed')}/{summary.get('checks_total')} "
                f"errors={summary.get('errors')} warnings={summary.get('warnings')}"
            )


def _try_runtime_command() -> bool:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("vault_dir", nargs="?")
    pre.add_argument("--out", default=None)
    pre.add_argument("--json", action="store_true")
    pre.add_argument("--json-file", default=None)
    pre.add_argument("--version", action="store_true")
    pre.add_argument("--self-test", action="store_true")
    pre.add_argument("--doctor", action="store_true")
    pre.add_argument("--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    args, _unknown = pre.parse_known_args()

    if not (args.version or args.self_test or args.doctor):
        return False

    vault_dir = Path(args.vault_dir).resolve() if args.vault_dir else None
    out_dir = Path(args.out).resolve() if args.out else None
    json_file = Path(args.json_file).resolve() if args.json_file else None

    if args.version:
        result = version_result(tool="tracevault_restore", repo_root=REPO_ROOT)
        _emit_runtime_payload(
            command="version",
            result=result,
            ok=True,
            vault_dir=vault_dir,
            out_dir=out_dir,
            enabled_json=args.json,
            json_file=json_file,
        )
        return True

    if args.self_test:
        result = self_test_core(tool="tracevault_restore", repo_root=REPO_ROOT)
        ok = bool(result.get("summary", {}).get("ok"))
        _emit_runtime_payload(
            command="self_test",
            result=result,
            ok=ok,
            vault_dir=vault_dir,
            out_dir=out_dir,
            enabled_json=args.json,
            json_file=json_file,
        )
        if not ok:
            raise SystemExit(1)
        return True

    extra_checks: List[Dict] = []
    try:
        cap = int(args.max_output_bytes)
        extra_checks.append({"name": "max_output_bytes_arg", "ok": cap >= 0, "severity": "error", "value": cap})
    except Exception:
        extra_checks.append({"name": "max_output_bytes_arg", "ok": False, "severity": "error", "value": args.max_output_bytes})
    result = doctor_checks_common(
        tool="tracevault_restore",
        repo_root=REPO_ROOT,
        api_dir=REPO_ROOT / "api",
        vault_dir=vault_dir,
        out_dir=out_dir,
        require_secret=False,
        extra_checks=extra_checks,
    )
    ok = bool(result.get("summary", {}).get("ok"))
    _emit_runtime_payload(
        command="doctor",
        result=result,
        ok=ok,
        vault_dir=vault_dir,
        out_dir=out_dir,
        enabled_json=args.json,
        json_file=json_file,
    )
    if not ok:
        raise SystemExit(1)
    return True


def main():
    if _try_runtime_command():
        return
    ap = argparse.ArgumentParser(description="Restore files from a Trace Vault pack.")
    ap.add_argument("--version", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--doctor", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("vault_dir", help="Path to vault directory containing tracevault_index.json")
    ap.add_argument("--out", required=True, help="Output directory for restored files")
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout (human restore logs go to stderr).",
    )
    ap.add_argument(
        "--json-file",
        default=None,
        help="Optional path to write the same machine-readable JSON result.",
    )
    ap.add_argument(
        "--max-output-bytes",
        type=int,
        default=DEFAULT_MAX_OUTPUT_BYTES,
        help="Abort restore if total bytes written exceed this limit. Use 0 for unlimited.",
    )
    args = ap.parse_args()
    vault_dir = Path(args.vault_dir).resolve()
    out_dir = Path(args.out).resolve()
    json_file = Path(args.json_file).resolve() if args.json_file else None
    max_output_bytes = max(0, int(args.max_output_bytes))

    try:
        if args.json:
            with contextlib.redirect_stdout(sys.stderr):
                result = restore(
                    vault_dir=vault_dir,
                    out_dir=out_dir,
                    max_output_bytes=max_output_bytes,
                )
        else:
            result = restore(
                vault_dir=vault_dir,
                out_dir=out_dir,
                max_output_bytes=max_output_bytes,
            )
        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "tool": "tracevault_restore",
            "command": "restore",
            "ok": True,
            "exit_code": 0,
            "vault_dir": str(vault_dir),
            "vault_name": vault_dir.name,
            "out_dir": str(out_dir),
            "out_dir_name": out_dir.name,
            "result": result,
        }
        _emit_cli_json(payload, enabled=args.json, json_file=json_file)
    except RestoreLimitExceeded as exc:
        if args.json or json_file:
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_restore",
                "command": "restore",
                "ok": False,
                "exit_code": 1,
                "vault_dir": str(vault_dir),
                "vault_name": vault_dir.name,
                "out_dir": str(out_dir),
                "out_dir_name": out_dir.name,
                "error": {
                    "code": "restore_output_limit",
                    "message": str(exc),
                    "written_bytes": exc.written_bytes,
                    "max_output_bytes": exc.max_output_bytes,
                    "hint": "Re-run with --max-output-bytes 0 to disable.",
                },
            }
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        print(str(exc))
        raise SystemExit(1)
    except SystemExit as exc:
        if args.json or json_file:
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_restore",
                "command": "restore",
                "ok": False,
                "exit_code": 1,
                "vault_dir": str(vault_dir),
                "vault_name": vault_dir.name,
                "out_dir": str(out_dir),
                "out_dir_name": out_dir.name,
                "error": {
                    "code": _error_code_from_exception(exc),
                    "message": str(exc),
                    "error_type": exc.__class__.__name__,
                },
            }
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise
    except Exception as exc:
        if args.json or json_file:
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_restore",
                "command": "restore",
                "ok": False,
                "exit_code": 1,
                "vault_dir": str(vault_dir),
                "vault_name": vault_dir.name,
                "out_dir": str(out_dir),
                "out_dir_name": out_dir.name,
                "error": {
                    "code": _error_code_from_exception(exc),
                    "message": str(exc),
                    "error_type": exc.__class__.__name__,
                },
            }
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise


if __name__ == "__main__":
    main()
