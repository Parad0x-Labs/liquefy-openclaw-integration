#!/usr/bin/env python3
"""
tracevault_pack.py
==================
Pack a run folder into verified .null archives using the Liquefy pipeline.

Usage:
    python tools/tracevault_pack.py ./runs/run_001 --org dev --out ./vault/run_001
"""

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple
from cli_runtime import (
    doctor_checks_common,
    resolve_repo_root,
    self_test_core,
    version_result,
)
from path_policy import (
    default_policy,
    add_policy_cli_args,
    build_policy_from_args,
    classify_risky_path,
    effective_rules_payload,
    explain_policy_path,
    evaluate_risky_policy,
    redact_risky_rows,
    summarize_risky_inclusions,
)

SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", ".pytest_cache"}
CLI_SCHEMA_VERSION = "liquefy.tracevault.cli.v1"

# Resolve api/ import path
REPO_ROOT = resolve_repo_root(__file__)
API_DIR = str(REPO_ROOT / "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

if TYPE_CHECKING:
    from orchestrator.orchestrator import Orchestrator


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def sanitize_relpath(path_like: str) -> str:
    return path_like.replace("\\", "__").replace("/", "__")


def split_file(src: Path, chunk_bytes: int, tmp_dir: Path) -> List[Path]:
    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be greater than 0")

    parts: List[Path] = []
    index = 0
    with src.open("rb") as f:
        while True:
            payload = f.read(chunk_bytes)
            if not payload:
                break
            part_path = tmp_dir / f"chunk_{index:06d}.bin"
            part_path.write_bytes(payload)
            parts.append(part_path)
            index += 1
    return parts


def _group_or_world_writable(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def ensure_secure_output_dir(path: Path, unsafe_perms_ok: bool = False) -> None:
    if path.exists():
        if not path.is_dir():
            raise SystemExit(f"out is not a directory: {path}")
        if _group_or_world_writable(path) and not unsafe_perms_ok:
            raise SystemExit(
                f"UNSAFE_OUTPUT_DIR_PERMS: {path} is group/world-writable "
                f"(use --unsafe-perms-ok to override)"
            )
    else:
        path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            path.chmod(0o700)
        except OSError:
            pass


def _harden_file_mode(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def write_bytes_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _harden_file_mode(path)


def write_text_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _harden_file_mode(path)


def estimate_ratio_for_path(path: Path) -> float:
    """Conservative estimate used for scan/dry-run planning only."""
    ext = path.suffix.lower()
    name = path.name.lower()
    if ext in {".jsonl", ".json"}:
        return 4.0
    if ext in {".log", ".txt"}:
        if "apache" in name or "nginx" in name or "syslog" in name:
            return 5.0
        return 3.0
    if ext in {".sql"}:
        return 4.0
    if ext in {".html", ".htm", ".md"}:
        return 2.5
    return 1.5


def scan_run_dir(
    run_dir: Path,
    max_file_mb: int,
    chunk_mb: int,
    bigfile_threshold_mb: int,
    policy=None,
) -> Dict:
    if policy is None:
        policy = default_policy(mode="strict", source="tracevault-default")
    if not run_dir.exists() or not run_dir.is_dir():
        raise SystemExit(f"run_dir not found: {run_dir}")

    files = sorted(f for f in run_dir.rglob("*") if f.is_file())
    max_file_bytes = max_file_mb * 1024 * 1024 if max_file_mb > 0 else 0
    bigfile_threshold_bytes = (
        bigfile_threshold_mb * 1024 * 1024 if bigfile_threshold_mb > 0 else 0
    )
    chunk_bytes = max(1, chunk_mb) * 1024 * 1024

    included: List[Dict] = []
    skipped: List[Dict] = []
    scan_skipped: List[Dict] = []
    risky_included_rows: List[Dict] = []
    denied_risky_rows: List[Dict] = []

    total_bytes = 0
    est_output_bytes = 0
    chunked_files = 0

    for fp in files:
        rel = fp.relative_to(run_dir).as_posix()
        size = fp.stat().st_size
        if fp.is_symlink():
            scan_skipped.append({
                "run_relpath": rel,
                "reason": "symlink_file",
                "original_bytes": size,
            })
            continue
        if should_skip(fp):
            scan_skipped.append({
                "run_relpath": rel,
                "reason": "skip_dir",
                "original_bytes": size,
            })
            continue

        if policy is not None:
            risk = classify_risky_path(fp, run_dir)
            category = risk[0] if risk else None
            category_reason = risk[1] if risk else None
            decision = evaluate_risky_policy(
                policy,
                rel_path=rel,
                category=category,
                category_reason=category_reason,
            )
            if not bool(decision.get("allow", False)):
                denied_risky_rows.append({
                    "run_relpath": rel,
                    "original_bytes": size,
                    "reason": decision.get("reason"),
                    "category": decision.get("category"),
                })
                continue
            if bool(decision.get("risky")):
                risky_included_rows.append({
                    "run_relpath": rel,
                    "original_bytes": size,
                    "category": decision.get("category"),
                    "reason": decision.get("reason"),
                    "overridden": bool(decision.get("overridden", False)),
                })

        if max_file_bytes and size > max_file_bytes:
            skipped.append({
                "run_relpath": rel,
                "reason": f"file_too_large>{max_file_mb}MB",
                "original_bytes": size,
            })
            continue

        chunked = bool(bigfile_threshold_bytes and size >= bigfile_threshold_bytes)
        est_ratio = estimate_ratio_for_path(fp)
        est_out = int(max(1, round(size / max(1.0, est_ratio))))
        if chunked:
            chunked_files += 1

        included.append({
            "run_relpath": rel,
            "original_bytes": size,
            "chunked": chunked,
            "estimated_ratio": round(est_ratio, 2),
            "estimated_output_bytes": est_out,
            "chunk_size_bytes": chunk_bytes if chunked else 0,
        })
        total_bytes += size
        est_output_bytes += est_out

    risk_summary = summarize_risky_inclusions(risky_included_rows)
    risky_rows_out = redact_risky_rows(risky_included_rows) if (policy and getattr(policy, "redact_output", False)) else risky_included_rows
    return {
        "version": "tracevault-scan-v1",
        "run_dir": str(run_dir),
        "policy": policy.public_summary() if policy is not None else None,
        "risk_summary": risk_summary,
        "files_seen": len(files),
        "files_skipped_by_path_policy": len(scan_skipped),
        "files_denied_by_risk_policy": len(denied_risky_rows),
        "files_skipped": len(skipped),
        "files_eligible": len(included),
        "chunked_files": chunked_files,
        "input_bytes": total_bytes,
        "estimated_output_bytes": est_output_bytes,
        "estimated_ratio": round(total_bytes / max(1, est_output_bytes), 2),
        "included": included,
        "skipped": skipped,
        "path_policy_skipped": scan_skipped,
        "risk_policy_denied": denied_risky_rows,
        "risky_files": risky_rows_out,
    }


def _emit_cli_json(payload: Dict, enabled: bool, json_file: Optional[Path]) -> None:
    if json_file:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        write_text_private(json_file, json.dumps(payload, indent=2))
    if enabled:
        print(json.dumps(payload, indent=2))


def _rel_for_explain(path_text: str, root: Path) -> str:
    p = Path(path_text).expanduser()
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except Exception:
            return p.as_posix()
    return p.as_posix()


def _print_effective_policy_human(policy, effective: Dict, *, root_label: str, root_path: Path) -> None:
    deny_preview = effective.get("deny_preview", [])
    allow_preview = effective.get("allow_preview", [])
    print("[POLICY] Effective path policy")
    print(f"        root: {root_label}={root_path}")
    print(f"        mode: {policy.mode}")
    print(f"        source: {policy.source}")
    print(f"        include_secrets: {bool(policy.include_secrets)} (phrase_ok={bool(policy.include_secrets_phrase_ok)})")
    print(f"        allow_categories: {', '.join(sorted(policy.allow_categories)) or '(none)'}")
    print(f"        deny_rules: {len(effective.get('deny', []))} total")
    for row in deny_preview:
        if row.get('type') == 'mode_category':
            print(f"          - mode:{row.get('category')}")
        else:
            print(f"          - {row.get('pattern')} [{row.get('reason')}]")
    if len(effective.get("deny", [])) > len(deny_preview):
        print(f"          ... +{len(effective.get('deny', [])) - len(deny_preview)} more")
    print(f"        allow_rules: {len(effective.get('allow', []))} total")
    for row in allow_preview:
        print(f"          - {row.get('pattern')}")
    if len(effective.get("allow", [])) > len(allow_preview):
        print(f"          ... +{len(effective.get('allow', [])) - len(allow_preview)} more")
    print("        precedence:")
    for line in effective.get("precedence", []):
        print(f"          - {line}")


def _print_explain_human(explain: Dict, *, root_label: str, root_path: Path) -> None:
    print("[POLICY] Explain")
    print(f"        root: {root_label}={root_path}")
    print(f"        path: {explain.get('path')}")
    print(f"        normalized: {explain.get('normalized_path')}")
    print(f"        decision: {explain.get('decision')}")
    print(f"        reason_code: {explain.get('reason_code')}")
    print(f"        category: {explain.get('category')}")
    print(f"        requires_override: {bool(explain.get('requires_override'))}")
    matched = explain.get("matched_rule")
    if matched:
        print(f"        matched_rule: {json.dumps(matched, sort_keys=True)}")


def _emit_runtime_payload(
    *,
    command: str,
    result: Dict,
    ok: bool,
    profile: str,
    run_dir: Optional[Path],
    out_dir: Optional[Path],
    enabled_json: bool,
    json_file: Optional[Path],
) -> None:
    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "tracevault_pack",
        "command": command,
        "ok": bool(ok),
        "profile": profile,
        "run_dir": str(run_dir) if run_dir is not None else None,
        "out_dir": str(out_dir) if out_dir is not None else None,
        "result": result,
    }
    _emit_cli_json(payload, enabled=enabled_json, json_file=json_file)
    if not enabled_json:
        if command == "version":
            build = result.get("build", {})
            print(
                f"liquefy tracevault-pack {build.get('liquefy_version','dev')} "
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
    pre.add_argument("run_dir", nargs="?")
    pre.add_argument("--out", default=None)
    pre.add_argument("--json", action="store_true")
    pre.add_argument("--json-file", default=None)
    pre.add_argument("--version", action="store_true")
    pre.add_argument("--self-test", action="store_true")
    pre.add_argument("--doctor", action="store_true")
    pre.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")
    pre.add_argument("--scan-only", action="store_true")
    pre.add_argument("--no-encrypt", action="store_true")
    pre.add_argument("--unsafe-perms-ok", action="store_true")
    add_policy_cli_args(pre)
    args, _unknown = pre.parse_known_args()

    if not (args.version or args.self_test or args.doctor):
        return False

    run_dir = Path(args.run_dir).resolve() if args.run_dir else None
    out_dir = Path(args.out).resolve() if args.out else None
    json_file = Path(args.json_file).resolve() if args.json_file else None

    if args.version:
        result = version_result(tool="tracevault_pack", repo_root=REPO_ROOT)
        _emit_runtime_payload(
            command="version",
            result=result,
            ok=True,
            profile=args.profile,
            run_dir=run_dir,
            out_dir=out_dir,
            enabled_json=args.json,
            json_file=json_file,
        )
        return True

    if args.self_test:
        result = self_test_core(tool="tracevault_pack", repo_root=REPO_ROOT)
        ok = bool(result.get("summary", {}).get("ok"))
        _emit_runtime_payload(
            command="self_test",
            result=result,
            ok=ok,
            profile=args.profile,
            run_dir=run_dir,
            out_dir=out_dir,
            enabled_json=args.json,
            json_file=json_file,
        )
        if not ok:
            raise SystemExit(1)
        return True

    extra_checks = []
    try:
        _ = build_policy_from_args(args, source_label="tracevault_pack_doctor")
        extra_checks.append({"name": "policy_parse", "ok": True, "severity": "info"})
    except SystemExit as exc:
        extra_checks.append({"name": "policy_parse", "ok": False, "severity": "error", "detail": str(exc)})

    result = doctor_checks_common(
        tool="tracevault_pack",
        repo_root=REPO_ROOT,
        api_dir=REPO_ROOT / "api",
        run_dir=run_dir,
        out_dir=out_dir,
        policy_path=Path(args.policy).expanduser().resolve() if args.policy else None,
        require_secret=not args.scan_only and not args.no_encrypt,
        unsafe_perms_ok=bool(args.unsafe_perms_ok),
        extra_checks=extra_checks,
    )
    ok = bool(result.get("summary", {}).get("ok"))
    _emit_runtime_payload(
        command="doctor",
        result=result,
        ok=ok,
        profile=args.profile,
        run_dir=run_dir,
        out_dir=out_dir,
        enabled_json=args.json,
        json_file=json_file,
    )
    if not ok:
        raise SystemExit(1)
    return True


async def process_single_file(
    orch: "Orchestrator",
    src_path: Path,
    run_relpath: str,
    out_name: str,
    org_id: str,
    out_dir: Path,
    encrypt: bool,
    verify: bool,
    verify_mode: str,
) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        result = await orch.process_file(
            filepath=str(src_path),
            tenant_id=org_id,
            api_key=org_id,
            encrypt=encrypt,
            verify=verify,
            verify_mode=verify_mode,
        )
    except Exception as exc:
        return None, str(exc)

    if not result.get("ok"):
        return None, result.get("error", "unknown")

    output_data = result.get("output_data")
    if output_data is None:
        return None, "missing_output_data"

    out_path = out_dir / out_name
    write_bytes_private(out_path, output_data)

    receipt = {
        "run_relpath": run_relpath,
        "output_path": str(out_path),
        "engine_used": result.get("engine_used"),
        "tenant_id": result.get("tenant_id", org_id),
        "original_bytes": int(result.get("original_bytes", src_path.stat().st_size)),
        "compressed_bytes": int(result.get("compressed_bytes", 0)),
        "output_bytes": len(output_data),
        "ratio": result.get("ratio", 1.0),
        "sha256_original": sha256_file(src_path),
        "encrypted": bool(result.get("encrypted", False)),
        "verified": bool(result.get("verified", False)),
    }
    return receipt, None


async def pack(
    run_dir: Path,
    org_id: str,
    out_dir: Path,
    encrypt: bool,
    verify: bool,
    verify_mode: str,
    max_file_mb: int,
    chunk_mb: int,
    bigfile_threshold_mb: int,
    workers: int,
    unsafe_perms_ok: bool = False,
    policy=None,
    verbose: bool = True,
):
    if policy is None:
        policy = default_policy(mode="strict", source="tracevault-default")
    if not run_dir.exists() or not run_dir.is_dir():
        raise SystemExit(f"run_dir not found: {run_dir}")

    ensure_secure_output_dir(out_dir, unsafe_perms_ok=unsafe_perms_ok)

    from orchestrator.orchestrator import Orchestrator

    master_secret = os.environ.get("LIQUEFY_SECRET")
    if encrypt and not master_secret:
        raise SystemExit("MISSING_SECRET: set LIQUEFY_SECRET")

    orch = Orchestrator(
        engines_dir=str(REPO_ROOT / "api" / "engines"),
        master_secret=master_secret,
    )

    files = sorted(f for f in run_dir.rglob("*") if f.is_file())
    receipts: List[Dict] = []
    bigfile_groups: List[Dict] = []
    skipped: List[Dict] = []
    risk_denied: List[Dict] = []
    risky_included: List[Dict] = []
    total_in = 0
    total_out = 0

    max_file_bytes = max_file_mb * 1024 * 1024 if max_file_mb > 0 else 0
    chunk_bytes = max(1, chunk_mb) * 1024 * 1024
    bigfile_threshold_bytes = 0
    if bigfile_threshold_mb > 0:
        bigfile_threshold_bytes = bigfile_threshold_mb * 1024 * 1024

    with tempfile.TemporaryDirectory(prefix="tracevault_chunks_") as temp_dir:
        temp_root = Path(temp_dir)

        normal_jobs: List[Tuple[Path, str, int]] = []
        bigfile_jobs: List[Tuple[Path, str, int]] = []

        for fp in files:
            rel = fp.relative_to(run_dir).as_posix()
            file_size = fp.stat().st_size

            if fp.is_symlink():
                skipped.append({
                    "run_relpath": rel,
                    "reason": "symlink_file",
                    "original_bytes": file_size,
                })
                if verbose:
                    print(f"  [SKIP] {rel} -- symlink_file")
                continue

            if should_skip(fp):
                skipped.append({
                    "run_relpath": rel,
                    "reason": "skip_dir",
                    "original_bytes": file_size,
                })
                continue

            if policy is not None:
                risk = classify_risky_path(fp, run_dir)
                category = risk[0] if risk else None
                category_reason = risk[1] if risk else None
                decision = evaluate_risky_policy(
                    policy,
                    rel_path=rel,
                    category=category,
                    category_reason=category_reason,
                )
                if not bool(decision.get("allow", False)):
                    risk_denied.append({
                        "run_relpath": rel,
                        "reason": decision.get("reason"),
                        "category": decision.get("category"),
                        "original_bytes": file_size,
                    })
                    if verbose:
                        print(f"  [DENY] {rel} -- {decision.get('reason')}")
                    continue
                if bool(decision.get("risky")):
                    risky_included.append({
                        "run_relpath": rel,
                        "original_bytes": file_size,
                        "category": decision.get("category"),
                        "reason": decision.get("reason"),
                        "overridden": bool(decision.get("overridden", False)),
                    })

            if max_file_bytes and file_size > max_file_bytes:
                skipped.append({
                    "run_relpath": rel,
                    "reason": f"file_too_large>{max_file_mb}MB",
                    "original_bytes": file_size,
                })
                print(f"  [SKIP] {rel} -- file_too_large>{max_file_mb}MB")
                continue

            if bigfile_threshold_bytes and file_size >= bigfile_threshold_bytes:
                bigfile_jobs.append((fp, rel, file_size))
                continue

            normal_jobs.append((fp, rel, file_size))

        worker_count = max(1, workers if workers > 0 else min(8, (os.cpu_count() or 4)))
        sem = asyncio.Semaphore(worker_count)

        async def process_normal_job(fp: Path, rel: str, file_size: int):
            async with sem:
                out_name = f"{sanitize_relpath(rel)}.null"
                receipt, error = await process_single_file(
                    orch=orch,
                    src_path=fp,
                    run_relpath=rel,
                    out_name=out_name,
                    org_id=org_id,
                    out_dir=out_dir,
                    encrypt=encrypt,
                    verify=verify,
                    verify_mode=verify_mode,
                )
                return rel, file_size, receipt, error

        if normal_jobs:
            tasks = [
                asyncio.create_task(process_normal_job(fp, rel, file_size))
                for fp, rel, file_size in normal_jobs
            ]
            for fut in asyncio.as_completed(tasks):
                rel, file_size, receipt, error = await fut
                if error:
                    if verbose:
                        print(f"  [SKIP] {rel} -- {error}")
                    skipped.append({
                        "run_relpath": rel,
                        "reason": error,
                        "original_bytes": file_size,
                    })
                    continue

                receipts.append(receipt)
                total_in += receipt["original_bytes"]
                total_out += receipt["output_bytes"]

        # Big files are kept sequential to preserve simple ordered chunk receipts.
        for fp, rel, file_size in bigfile_jobs:
            parts_dir = temp_root / sanitize_relpath(rel)
            parts_dir.mkdir(parents=True, exist_ok=True)
            parts = split_file(fp, chunk_bytes=chunk_bytes, tmp_dir=parts_dir)

            group = {
                "run_relpath": rel,
                "original_bytes": file_size,
                "sha256_original": sha256_file(fp),
                "chunk_bytes": chunk_bytes,
                "chunk_count": len(parts),
                "parts": [],
            }
            chunk_failed = False
            chunk_errors: List[str] = []

            for idx, part_path in enumerate(parts):
                out_name = (
                    f"{sanitize_relpath(rel)}.__chunk_{idx:06d}_of_{len(parts):06d}.null"
                )
                part_rel = f"{rel}::chunk{idx:06d}"
                receipt, error = await process_single_file(
                    orch=orch,
                    src_path=part_path,
                    run_relpath=part_rel,
                    out_name=out_name,
                    org_id=org_id,
                    out_dir=out_dir,
                    encrypt=encrypt,
                    verify=verify,
                    verify_mode=verify_mode,
                )
                if error:
                    chunk_failed = True
                    chunk_errors.append(f"chunk {idx}: {error}")
                    print(f"  [SKIP] {rel} -- chunk {idx} failed: {error}")
                    break

                receipt["chunk_index"] = idx
                receipt["chunk_count"] = len(parts)
                group["parts"].append(receipt)
                total_in += receipt["original_bytes"]
                total_out += receipt["output_bytes"]

            if chunk_failed:
                for part_receipt in group["parts"]:
                    out_path = Path(part_receipt["output_path"])
                    if out_path.exists():
                        out_path.unlink()
                skipped.append({
                    "run_relpath": rel,
                    "reason": "chunking_failed",
                    "details": chunk_errors,
                    "original_bytes": file_size,
                })
                continue

            bigfile_groups.append(group)
            if verbose:
                print(f"  [OK] {rel} -- chunked into {len(parts)} parts")

    receipts.sort(key=lambda r: r.get("run_relpath", ""))
    bigfile_groups.sort(key=lambda g: g.get("run_relpath", ""))
    logical_processed = len(receipts) + len(bigfile_groups)
    risk_summary = summarize_risky_inclusions(risky_included)
    risky_out = redact_risky_rows(risky_included) if (policy and getattr(policy, "redact_output", False)) else risky_included
    index = {
        "version": "tracevault-index-v2",
        "run_dir": str(run_dir),
        "org_id": org_id,
        "policy": policy.public_summary() if policy is not None else None,
        "risk_summary": risk_summary,
        "risky_files": risky_out,
        "risk_denied": risk_denied,
        "input_bytes": total_in,
        "output_bytes": total_out,
        "ratio": round(total_in / max(1, total_out), 2),
        "files_processed": logical_processed,
        "files_skipped": len(skipped),
        "chunked_files": len(bigfile_groups),
        "receipts": receipts,
        "bigfile_groups": bigfile_groups,
        "skipped": skipped,
    }

    index_path = out_dir / "tracevault_index.json"
    write_text_private(index_path, json.dumps(index, indent=2))
    index["_index_path"] = str(index_path)

    if verbose:
        print(f"\n  input:         {total_in:,} bytes")
        print(f"  output:        {total_out:,} bytes ({index['ratio']}x)")
        print(f"  files packed:  {logical_processed}")
        print(f"  files skipped: {len(skipped)}")
        print(f"  chunked files: {len(bigfile_groups)}")
        print(f"  index:         {index_path}")

    return index


def main():
    if _try_runtime_command():
        return
    ap = argparse.ArgumentParser(description="Pack a run folder into .null archives.")
    ap.add_argument("--version", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--doctor", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("run_dir", help="Path to run folder")
    ap.add_argument("--org", default="default", help="Organization / tenant ID")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--no-encrypt", action="store_true", help="Skip per-org encryption")
    ap.add_argument("--no-verify", action="store_true", help="Skip MRTV verification")
    ap.add_argument(
        "--max-file-mb",
        type=int,
        default=0,
        help="Skip files above this size in MB (0 disables max size guard).",
    )
    ap.add_argument(
        "--chunk-mb",
        type=int,
        default=64,
        help="Chunk size in MB for large-file chunking.",
    )
    ap.add_argument(
        "--bigfile-threshold-mb",
        type=int,
        default=64,
        help="Chunk files at or above this size in MB (0 disables chunking).",
    )
    ap.add_argument(
        "--verify-mode",
        choices=["full", "fast", "off"],
        default="full",
        help="Verification strategy for in-process engines.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Parallel workers for normal file packing (0 = auto).",
    )
    ap.add_argument(
        "--profile",
        choices=["default", "ratio", "speed"],
        default="default",
        help="Optional Liquefy engine profile to apply during packing.",
    )
    ap.add_argument(
        "--scan-only",
        action="store_true",
        help="Do not compress; output a file plan and estimated savings.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout (suppress human text output).",
    )
    ap.add_argument(
        "--json-file",
        default=None,
        help="Optional path to write the same machine-readable JSON result.",
    )
    ap.add_argument(
        "--unsafe-perms-ok",
        action="store_true",
        help="Allow group/world-writable output directory (disabled by default).",
    )
    add_policy_cli_args(ap)
    args = ap.parse_args()
    run_dir = Path(args.run_dir).resolve()
    out_dir = Path(args.out).resolve()
    json_file = Path(args.json_file).resolve() if args.json_file else None

    if args.profile == "default":
        os.environ.pop("LIQUEFY_PROFILE", None)
    else:
        os.environ["LIQUEFY_PROFILE"] = args.profile

    try:
        policy = build_policy_from_args(args, source_label="tracevault_pack")
        if args.print_effective_policy or args.explain:
            effective = effective_rules_payload(policy)
            explain_obj = None
            if args.explain:
                explain_obj = explain_policy_path(policy, rel_path=_rel_for_explain(args.explain, run_dir))
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_pack",
                "command": "policy",
                "ok": True,
                "profile": args.profile,
                "run_dir": str(run_dir),
                "out_dir": str(out_dir),
                "result": {
                    "policy": policy.public_summary(),
                    **({"effective_rules": effective} if args.print_effective_policy else {}),
                    **({"explain": explain_obj} if explain_obj is not None else {}),
                },
            }
            if not args.json:
                if args.print_effective_policy:
                    _print_effective_policy_human(policy, effective, root_label="run_dir", root_path=run_dir)
                if explain_obj is not None:
                    if args.print_effective_policy:
                        print()
                    _print_explain_human(explain_obj, root_label="run_dir", root_path=run_dir)
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            return
        if args.scan_only:
            scan = scan_run_dir(
                run_dir=run_dir,
                max_file_mb=args.max_file_mb,
                chunk_mb=args.chunk_mb,
                bigfile_threshold_mb=args.bigfile_threshold_mb,
                policy=policy,
            )
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_pack",
                "command": "scan",
                "ok": True,
                "profile": args.profile,
                "run_dir": str(run_dir),
                "out_dir": str(out_dir),
                "result": {
                    **scan,
                    "touched_paths": [],
                },
            }
            if not args.json:
                print(f"[SCAN] {scan['files_eligible']} eligible, {scan['files_skipped']} skipped")
                print(
                    f"       est ratio: {scan['estimated_ratio']:.2f}x "
                    f"({scan['input_bytes']:,} -> {scan['estimated_output_bytes']:,} bytes)"
                )
                if scan.get("risk_summary", {}).get("risky_files_included"):
                    print("       warning: risky files included by explicit override", file=sys.stderr)
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            return

        if args.json:
            with contextlib.redirect_stdout(sys.stderr):
                index = asyncio.run(pack(
                    run_dir=run_dir,
                    org_id=args.org,
                    out_dir=out_dir,
                    encrypt=not args.no_encrypt,
                    verify=not args.no_verify,
                    verify_mode=args.verify_mode,
                    max_file_mb=args.max_file_mb,
                    chunk_mb=args.chunk_mb,
                    bigfile_threshold_mb=args.bigfile_threshold_mb,
                    workers=args.workers,
                    unsafe_perms_ok=args.unsafe_perms_ok,
                    policy=policy,
                    verbose=False,
                ))
        else:
            index = asyncio.run(pack(
                run_dir=run_dir,
                org_id=args.org,
                out_dir=out_dir,
                encrypt=not args.no_encrypt,
                verify=not args.no_verify,
                verify_mode=args.verify_mode,
                max_file_mb=args.max_file_mb,
                chunk_mb=args.chunk_mb,
                bigfile_threshold_mb=args.bigfile_threshold_mb,
                workers=args.workers,
                unsafe_perms_ok=args.unsafe_perms_ok,
                policy=policy,
                verbose=True,
            ))

        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "tool": "tracevault_pack",
            "command": "pack",
            "ok": True,
            "profile": args.profile,
            "run_dir": str(run_dir),
            "out_dir": str(out_dir),
            "result": {
                "index_path": index.get("_index_path"),
                "version": index.get("version"),
                "files_processed": index.get("files_processed"),
                "files_skipped": index.get("files_skipped"),
                "chunked_files": index.get("chunked_files"),
                "input_bytes": index.get("input_bytes"),
                "output_bytes": index.get("output_bytes"),
                "ratio": index.get("ratio"),
                "policy": index.get("policy"),
                "risk_summary": index.get("risk_summary"),
                "risky_files": index.get("risky_files"),
            },
        }
        if not args.json and (index.get("risk_summary") or {}).get("risky_files_included"):
            print("[WARN] Risky file inclusion override enabled; review index risk_summary/risky_files", file=sys.stderr)
        _emit_cli_json(payload, enabled=args.json, json_file=json_file)
    except SystemExit as exc:
        if args.json or json_file:
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_pack",
                "command": "scan" if args.scan_only else "pack",
                "ok": False,
                "profile": args.profile,
                "run_dir": str(run_dir),
                "out_dir": str(out_dir),
                "error": str(exc),
            }
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise
    except Exception as exc:
        if args.json or json_file:
            payload = {
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "tracevault_pack",
                "command": "scan" if args.scan_only else "pack",
                "ok": False,
                "profile": args.profile,
                "run_dir": str(run_dir),
                "out_dir": str(out_dir),
                "error": str(exc),
                "error_type": exc.__class__.__name__,
            }
            _emit_cli_json(payload, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise


if __name__ == "__main__":
    main()
