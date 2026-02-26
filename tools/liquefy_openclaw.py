#!/usr/bin/env python3
"""
liquefy_openclaw.py
===================
One-command OpenClaw workspace packer.

Usage:
    python tools/liquefy_openclaw.py --workspace ~/.openclaw --out ./openclaw-vault
"""

import argparse
import json
import os
import stat
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
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
)

REPO_ROOT = resolve_repo_root(__file__)

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
}

CLI_SCHEMA_VERSION = "liquefy.openclaw.cli.v1"


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


def write_text_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _harden_file_mode(path)


def should_skip(path: Path, workspace: Path) -> bool:
    return classify_skip(path, workspace) is not None


def classify_skip(path: Path, workspace: Path) -> Optional[str]:
    rel = path.relative_to(workspace)
    for part in rel.parts:
        if part in SKIP_DIRS:
            return f"skip_dir:{part}"
    return None


def collect_files(workspace: Path) -> List[Tuple[Path, Path]]:
    out: List[Tuple[Path, Path]] = []
    for f in sorted(workspace.rglob("*")):
        if not f.is_file():
            continue
        if f.is_symlink():
            continue
        if should_skip(f, workspace):
            continue
        out.append((f, f.relative_to(workspace)))
    return out


def estimate_ratio_for_openclaw_file(path: Path) -> float:
    ext = path.suffix.lower()
    rel = path.as_posix().lower()
    if ext in {".jsonl"}:
        if "sessions/" in rel or "tool_trace/" in rel:
            return 5.5
        return 4.0
    if ext in {".json"}:
        return 3.5
    if ext in {".log"}:
        if "errors" in rel:
            return 4.0
        return 3.0
    if ext in {".html", ".htm"}:
        return 2.2
    if ext in {".md"}:
        return 2.0
    return 1.5


def scan_workspace(
    workspace: Path,
    max_bytes_per_run: int = 0,
    list_limit: int = 200,
    policy=None,
) -> Dict:
    if policy is None:
        policy = default_policy(mode="strict", source="openclaw-default")
    eligible: List[Tuple[Path, Path]] = []
    eligible_rows: List[Dict] = []
    denied_rows: List[Dict] = []
    skipped_rows: List[Dict] = []
    risky_included_rows: List[Dict] = []
    risky_included_count = 0
    risky_category_counts: Dict[str, int] = {}
    total_seen = 0
    denied_count = 0
    skipped_count = 0
    eligible_bytes = 0
    denied_bytes = 0
    skipped_bytes = 0
    est_output = 0
    cap_reached = False

    for f in sorted(workspace.rglob("*")):
        if not f.is_file():
            continue
        total_seen += 1
        size = f.stat().st_size
        rel = f.relative_to(workspace)

        if f.is_symlink():
            denied_count += 1
            denied_bytes += size
            if len(denied_rows) < list_limit:
                denied_rows.append({
                    "path": rel.as_posix(),
                    "bytes": size,
                    "reason": "symlink_file",
                })
            continue

        skip_reason = classify_skip(f, workspace)
        if skip_reason:
            denied_count += 1
            denied_bytes += size
            if len(denied_rows) < list_limit:
                denied_rows.append({
                    "path": rel.as_posix(),
                    "bytes": size,
                    "reason": skip_reason,
                })
            continue

        if policy is not None:
            risk = classify_risky_path(f, workspace)
            category = risk[0] if risk else None
            category_reason = risk[1] if risk else None
            decision = evaluate_risky_policy(
                policy,
                rel_path=rel.as_posix(),
                category=category,
                category_reason=category_reason,
            )
            if not bool(decision.get("allow", False)):
                denied_count += 1
                denied_bytes += size
                if len(denied_rows) < list_limit:
                    denied_rows.append({
                        "path": rel.as_posix(),
                        "bytes": size,
                        "reason": decision.get("reason"),
                        "category": decision.get("category"),
                    })
                continue
            if bool(decision.get("risky")):
                risky_included_count += 1
                cat = str(decision.get("category") or "UNKNOWN")
                risky_category_counts[cat] = risky_category_counts.get(cat, 0) + 1
                row = {
                    "path": rel.as_posix(),
                    "bytes": size,
                    "category": decision.get("category"),
                    "reason": decision.get("reason"),
                    "overridden": bool(decision.get("overridden", False)),
                }
                if len(risky_included_rows) < list_limit:
                    risky_included_rows.append(row)

        if max_bytes_per_run > 0 and (eligible_bytes + size) > max_bytes_per_run:
            cap_reached = True
            skipped_count += 1
            skipped_bytes += size
            if len(skipped_rows) < list_limit:
                skipped_rows.append({
                    "path": rel.as_posix(),
                    "bytes": size,
                    "reason": "max_bytes_per_run",
                })
            continue

        eligible.append((f, rel))
        ratio_est = estimate_ratio_for_openclaw_file(rel)
        out_est = int(max(1, round(size / max(1.0, ratio_est))))
        eligible_bytes += size
        est_output += out_est
        if len(eligible_rows) < list_limit:
            eligible_rows.append({
                "path": rel.as_posix(),
                "bytes": size,
                "estimated_ratio": round(ratio_est, 2),
                "estimated_output_bytes": out_est,
            })

    est_ratio = round(eligible_bytes / max(1, est_output), 2) if eligible_bytes else 0.0
    est_savings_pct = round((1.0 - (est_output / max(1, eligible_bytes))) * 100.0, 2) if eligible_bytes else 0.0
    risk_summary = {
        "risky_files_included": risky_included_count,
        "risky_categories_included": risky_category_counts,
    }
    risky_rows_out = redact_risky_rows(risky_included_rows) if (policy and getattr(policy, "redact_output", False)) else risky_included_rows
    return {
        "version": "openclaw-scan-v1",
        "workspace": str(workspace),
        "policy": policy.public_summary() if policy is not None else None,
        "risk_summary": risk_summary,
        "summary": {
            "files_seen": total_seen,
            "eligible_files": len(eligible),
            "eligible_bytes": eligible_bytes,
            "denied_files_count": denied_count,
            "denied_bytes": denied_bytes,
            "skipped_files_count": skipped_count,
            "skipped_bytes": skipped_bytes,
            "list_limit": list_limit,
            "eligible_list_truncated": len(eligible) > len(eligible_rows),
            "denied_list_truncated": denied_count > len(denied_rows),
            "skipped_list_truncated": skipped_count > len(skipped_rows),
            "max_bytes_per_run": max_bytes_per_run,
            "max_bytes_cap_reached": cap_reached,
            "estimated_output_bytes": est_output,
            "estimated_ratio": est_ratio,
            "estimated_savings_percent": est_savings_pct,
        },
        "eligible_files": eligible_rows,
        "denied_files": denied_rows,
        "skipped_files": skipped_rows,
        "risky_files": risky_rows_out,
        "_eligible_pairs": eligible,
    }


def stage_workspace(files: Iterable[Tuple[Path, Path]], staging: Path) -> int:
    count = 0
    for src, rel in files:
        dst = staging / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        count += 1
    return count


def load_index(index_path: Path) -> dict:
    if not index_path.exists():
        return {}
    try:
        obj = json.loads(index_path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _emit_json(payload: Dict, enabled: bool, json_file: Optional[Path]) -> None:
    if json_file:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        write_text_private(json_file, json.dumps(payload, indent=2))
    if enabled:
        print(json.dumps(payload, indent=2))


def _emit_runtime_payload(
    *,
    command: str,
    result: Dict,
    ok: bool,
    profile: str,
    workspace: Optional[Path],
    out_dir: Optional[Path],
    verify_mode: str,
    secure: bool,
    dry_run: bool,
    enabled_json: bool,
    json_file: Optional[Path],
) -> None:
    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "liquefy_openclaw",
        "command": command,
        "ok": bool(ok),
        "profile": profile,
        "workspace": str(workspace) if workspace is not None else None,
        "out_dir": str(out_dir) if out_dir is not None else None,
        "verify_mode": verify_mode,
        "secure": bool(secure),
        "dry_run": bool(dry_run),
        "result": result,
    }
    _emit_json(payload, enabled=enabled_json, json_file=json_file)
    if not enabled_json:
        if command == "version":
            build = result.get("build", {})
            print(
                f"liquefy-openclaw {build.get('liquefy_version','dev')} "
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
    pre.set_defaults(dry_run=True)
    pre.add_argument("--workspace", default="~/.openclaw")
    pre.add_argument("--out", default=None)
    pre.add_argument("--json", action="store_true")
    pre.add_argument("--json-file", default=None)
    pre.add_argument("--version", action="store_true")
    pre.add_argument("--self-test", action="store_true")
    pre.add_argument("--doctor", action="store_true")
    pre.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")
    pre.add_argument("--verify-mode", choices=["full", "fast", "off"], default="full")
    pre.add_argument("--secure", action="store_true")
    pre.add_argument("--dry-run", "--scan-only", dest="dry_run", action="store_true")
    pre.add_argument("--apply", dest="dry_run", action="store_false")
    pre.add_argument("--unsafe-perms-ok", action="store_true")
    pre.add_argument("--max-bytes-per-run", type=int, default=0)
    add_policy_cli_args(pre)
    args, _unknown = pre.parse_known_args()

    if not (args.version or args.self_test or args.doctor):
        return False

    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    out_dir = Path(args.out).resolve() if args.out else None
    json_file = Path(args.json_file).resolve() if args.json_file else None

    if args.version:
        result = version_result(tool="liquefy_openclaw", repo_root=REPO_ROOT)
        _emit_runtime_payload(
            command="version",
            result=result,
            ok=True,
            profile=args.profile,
            workspace=workspace,
            out_dir=out_dir,
            verify_mode=args.verify_mode,
            secure=bool(args.secure),
            dry_run=bool(args.dry_run),
            enabled_json=args.json,
            json_file=json_file,
        )
        return True

    if args.self_test:
        result = self_test_core(tool="liquefy_openclaw", repo_root=REPO_ROOT)
        ok = bool(result.get("summary", {}).get("ok"))
        _emit_runtime_payload(
            command="self_test",
            result=result,
            ok=ok,
            profile=args.profile,
            workspace=workspace,
            out_dir=out_dir,
            verify_mode=args.verify_mode,
            secure=bool(args.secure),
            dry_run=bool(args.dry_run),
            enabled_json=args.json,
            json_file=json_file,
        )
        if not ok:
            raise SystemExit(1)
        return True

    extra_checks: List[Dict] = []
    try:
        build_policy_from_args(args, source_label="liquefy_openclaw_doctor")
        extra_checks.append({"name": "policy_parse", "ok": True, "severity": "info"})
    except SystemExit as exc:
        extra_checks.append({"name": "policy_parse", "ok": False, "severity": "error", "detail": str(exc)})
    extra_checks.append({
        "name": "max_bytes_per_run_arg",
        "ok": int(args.max_bytes_per_run) >= 0,
        "severity": "error",
        "value": int(args.max_bytes_per_run),
    })
    result = doctor_checks_common(
        tool="liquefy_openclaw",
        repo_root=REPO_ROOT,
        workspace=workspace,
        out_dir=out_dir,
        policy_path=Path(args.policy).expanduser().resolve() if args.policy else None,
        require_secret=bool(args.secure) and not bool(args.dry_run),
        unsafe_perms_ok=bool(args.unsafe_perms_ok),
        extra_checks=extra_checks,
    )
    ok = bool(result.get("summary", {}).get("ok"))
    _emit_runtime_payload(
        command="doctor",
        result=result,
        ok=ok,
        profile=args.profile,
        workspace=workspace,
        out_dir=out_dir,
        verify_mode=args.verify_mode,
        secure=bool(args.secure),
        dry_run=bool(args.dry_run),
        enabled_json=args.json,
        json_file=json_file,
    )
    if not ok:
        raise SystemExit(1)
    return True


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
        if row.get("type") == "mode_category":
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


def write_report(
    report_path: Path,
    workspace: Path,
    out_dir: Path,
    index: dict,
    copied_files: int,
    elapsed_s: float,
    profile: str = "default",
    risk_summary: Optional[dict] = None,
):
    input_bytes = int(index.get("input_bytes", 0))
    output_bytes = int(index.get("output_bytes", 0))
    ratio = float(index.get("ratio", 0.0))
    savings = 0.0
    if input_bytes > 0:
        savings = (1.0 - (output_bytes / input_bytes)) * 100.0

    lines = [
        "# OpenClaw Liquefy Report",
        "",
        f"- Workspace: `{workspace}`",
        f"- Vault: `{out_dir}`",
        f"- Files Packed: {copied_files}",
        f"- Input Bytes: {input_bytes:,}",
        f"- Output Bytes: {output_bytes:,}",
        f"- Compression Ratio: {ratio:.2f}x",
        f"- Storage Saved: {savings:.2f}%",
        f"- Elapsed: {elapsed_s:.2f}s",
        f"- Profile: `{profile}`",
        "",
    ]
    risky_count = int((risk_summary or {}).get("risky_files_included", 0))
    if risky_count > 0:
        lines.extend([
            "## WARNING",
            "",
            f"- Risky file inclusion override was enabled: {risky_count} risky files were packed.",
            "- Review JSON `risk_summary` / `risky_files` before sharing this vault.",
            "",
        ])
    lines.extend([
        "## Notes",
        "",
        "- Search while compressed is available via `liquefy search <vault_dir> --query <text>`.",
        "- Hash-verified restore is available via `python tools/tracevault_restore.py <vault_dir> --out <dir>`.",
        "- Sensitive credential-like files are excluded by denylist defaults unless explicit risky override is enabled.",
    ])
    write_text_private(report_path, "\n".join(lines) + "\n")


def main():
    if _try_runtime_command():
        return
    ap = argparse.ArgumentParser(description="One-command OpenClaw workspace packer.")
    ap.set_defaults(dry_run=True)
    ap.add_argument("--version", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--doctor", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--workspace", default="~/.openclaw", help="OpenClaw workspace path")
    ap.add_argument("--out", required=True, help="Output vault directory")
    ap.add_argument("--org", default="openclaw_user", help="Org/tenant label")
    ap.add_argument("--verify-mode", choices=["full", "fast", "off"], default="full")
    ap.add_argument("--workers", type=int, default=0, help="Parallel workers (0=auto)")
    ap.add_argument("--hash-cache", action="store_true", help="Enable persistent hash cache during pack.")
    ap.add_argument("--hash-cache-clear", action="store_true", help="Clear hash cache before pack (requires --hash-cache).")
    ap.add_argument("--sign", action="store_true", help="Sign vault proof artifacts after pack.")
    ap.add_argument("--secure", action="store_true", help="Enable per-tenant encryption")
    ap.add_argument("--no-chunking", action="store_true", help="Disable large-file chunking")
    ap.add_argument(
        "--profile",
        choices=["default", "ratio", "speed"],
        default="default",
        help="Liquefy engine profile for tracevault packing.",
    )
    ap.add_argument(
        "--dry-run",
        "--scan-only",
        dest="dry_run",
        action="store_true",
        help="Scan workspace and return an estimated plan without writing a vault (default).",
    )
    ap.add_argument(
        "--apply",
        dest="dry_run",
        action="store_false",
        help="Actually pack files into a vault (requires explicit opt-in).",
    )
    ap.add_argument(
        "--max-bytes-per-run",
        type=int,
        default=0,
        help="Optional cap on total bytes packed from eligible files (0 = no cap).",
    )
    ap.add_argument(
        "--trace-id",
        default=None,
        help="Correlation ID for multi-agent chain-of-custody (passed between agent handoffs).",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout (suppress normal text output).",
    )
    ap.add_argument(
        "--json-file",
        default=None,
        help="Optional path to write the same machine-readable JSON result.",
    )
    ap.add_argument(
        "--list-limit",
        type=int,
        default=200,
        help="Max files per list section (eligible/denied/skipped) in scan JSON output.",
    )
    ap.add_argument(
        "--unsafe-perms-ok",
        action="store_true",
        help="Allow group/world-writable output directory (disabled by default).",
    )
    add_policy_cli_args(ap)
    args = ap.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    out_dir = Path(args.out).resolve()

    if not workspace.exists() or not workspace.is_dir():
        raise SystemExit(f"Workspace not found: {workspace}")
    json_file = Path(args.json_file).resolve() if args.json_file else None

    try:
        policy = build_policy_from_args(args, source_label="liquefy_openclaw")
    except SystemExit as exc:
        if args.json or json_file:
            _emit_json({
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "liquefy_openclaw",
                "command": "scan" if args.dry_run else "pack",
                "ok": False,
                "profile": args.profile,
                "workspace": str(workspace),
                "out_dir": str(out_dir),
                "verify_mode": args.verify_mode,
                "secure": bool(args.secure),
                "dry_run": bool(args.dry_run),
                "error": str(exc),
            }, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise

    if args.print_effective_policy or args.explain:
        effective = effective_rules_payload(policy)
        explain_obj = None
        if args.explain:
            explain_obj = explain_policy_path(policy, rel_path=_rel_for_explain(args.explain, workspace))
        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "tool": "liquefy_openclaw",
            "command": "policy",
            "ok": True,
            "profile": args.profile,
            "workspace": str(workspace),
            "out_dir": str(out_dir),
            "verify_mode": args.verify_mode,
            "secure": bool(args.secure),
            "dry_run": bool(args.dry_run),
            "result": {
                "policy": policy.public_summary(),
                **({"effective_rules": effective} if args.print_effective_policy else {}),
                **({"explain": explain_obj} if explain_obj is not None else {}),
            },
        }
        if not args.json:
            if args.print_effective_policy:
                _print_effective_policy_human(policy, effective, root_label="workspace", root_path=workspace)
            if explain_obj is not None:
                if args.print_effective_policy:
                    print()
                _print_explain_human(explain_obj, root_label="workspace", root_path=workspace)
        _emit_json(payload, enabled=args.json, json_file=json_file)
        return

    scan = scan_workspace(
        workspace=workspace,
        max_bytes_per_run=max(0, args.max_bytes_per_run),
        list_limit=max(1, args.list_limit),
        policy=policy,
    )
    files = scan.pop("_eligible_pairs")
    risk_summary = scan.get("risk_summary", {}) if isinstance(scan, dict) else {}

    trace_id = getattr(args, "trace_id", None) or os.environ.get("LIQUEFY_TRACE_ID")

    if args.dry_run:
        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "tool": "liquefy_openclaw",
            "command": "scan",
            "ok": True,
            "profile": args.profile,
            "workspace": str(workspace),
            "out_dir": str(out_dir),
            "verify_mode": args.verify_mode,
            "secure": bool(args.secure),
            "dry_run": True,
            **({"trace_id": trace_id} if trace_id else {}),
            "result": {
                **scan,
                "touched_paths": [],
            },
        }
        if not args.json:
            summary = scan["summary"]
            print("[SCAN] OpenClaw workspace")
            print(f"       eligible: {summary['eligible_files']} files ({summary['eligible_bytes']:,} bytes)")
            print(f"       denied:   {summary['denied_files_count']} listed ({summary['denied_bytes']:,} bytes blocked)")
            print(
                f"       est:      {summary['estimated_ratio']:.2f}x "
                f"({summary['eligible_bytes']:,} -> {summary['estimated_output_bytes']:,} bytes)"
            )
            if summary["max_bytes_cap_reached"]:
                print("       cap:      max_bytes_per_run reached")
            if risk_summary.get("risky_files_included"):
                print("       warning:  risky files included by explicit override", file=sys.stderr)
        _emit_json(payload, enabled=args.json, json_file=json_file)
        return

    if not files:
        raise SystemExit(f"No eligible files found in {workspace}")

    if args.secure and not os.environ.get("LIQUEFY_SECRET"):
        error_msg = "MISSING_SECRET: set LIQUEFY_SECRET"
        if args.json or json_file:
            _emit_json({
                "schema_version": CLI_SCHEMA_VERSION,
                "tool": "liquefy_openclaw",
                "command": "pack",
                "ok": False,
                "profile": args.profile,
                "workspace": str(workspace),
                "out_dir": str(out_dir),
                "verify_mode": args.verify_mode,
                "secure": bool(args.secure),
                "dry_run": False,
                "error": error_msg,
            }, enabled=args.json, json_file=json_file)
            raise SystemExit(1)
        raise SystemExit(error_msg)

    ensure_secure_output_dir(out_dir, unsafe_perms_ok=args.unsafe_perms_ok)
    start = time.time()
    pack_payload = None

    with tempfile.TemporaryDirectory(prefix="liquefy_openclaw_") as td:
        staging = Path(td)
        copied = stage_workspace(files, staging)

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "tracevault_pack.py"),
            str(staging),
            "--org",
            args.org,
            "--out",
            str(out_dir),
            "--verify-mode",
            args.verify_mode,
            "--profile",
            args.profile,
        ]
        if args.workers > 0:
            cmd.extend(["--workers", str(args.workers)])
        if args.hash_cache:
            cmd.append("--hash-cache")
            if args.hash_cache_clear:
                cmd.append("--hash-cache-clear")
        if args.sign:
            cmd.append("--sign")
        if not args.secure:
            cmd.append("--no-encrypt")
        if args.no_chunking:
            cmd.extend(["--bigfile-threshold-mb", "0"])
        if args.unsafe_perms_ok:
            cmd.append("--unsafe-perms-ok")
        if args.policy:
            cmd.extend(["--policy", str(args.policy)])
        if args.mode:
            cmd.extend(["--mode", str(args.mode)])
        for pat in (args.deny or []):
            cmd.extend(["--deny", pat])
        for pat in (args.allow or []):
            cmd.extend(["--allow", pat])
        for cat in (args.allow_category or []):
            cmd.extend(["--allow-category", cat])
        if args.include_secrets is not None:
            cmd.extend(["--include-secrets", args.include_secrets])
        if args.json:
            cmd.append("--json")
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if proc.returncode != 0:
                try:
                    pack_error = json.loads(proc.stdout) if proc.stdout.strip() else {}
                except Exception:
                    pack_error = {}
                error_msg = pack_error.get("error") or proc.stderr.strip() or f"tracevault_pack failed ({proc.returncode})"
                _emit_json({
                    "schema_version": CLI_SCHEMA_VERSION,
                    "tool": "liquefy_openclaw",
                    "command": "pack",
                    "ok": False,
                    "profile": args.profile,
                    "workspace": str(workspace),
                    "out_dir": str(out_dir),
                    "verify_mode": args.verify_mode,
                    "secure": bool(args.secure),
                    "dry_run": False,
                    "error": error_msg,
                    "upstream": pack_error if isinstance(pack_error, dict) and pack_error else None,
                }, enabled=args.json, json_file=json_file)
                raise SystemExit(1)
            try:
                pack_payload = json.loads(proc.stdout)
            except Exception as exc:
                raise SystemExit(f"Failed to parse tracevault_pack JSON output: {exc}")
        else:
            subprocess.run(cmd, check=True)

    elapsed = time.time() - start
    index = load_index(out_dir / "tracevault_index.json")
    report = out_dir / "OPENCLAW_LIQUEFY_REPORT.md"
    write_report(report, workspace, out_dir, index, copied, elapsed, profile=args.profile, risk_summary=risk_summary)

    input_bytes = int(index.get("input_bytes", 0))
    output_bytes = int(index.get("output_bytes", 0))
    ratio = float(index.get("ratio", 0.0))
    savings = (1.0 - (output_bytes / max(1, input_bytes))) * 100.0

    if trace_id:
        try:
            from liquefy_audit_chain import audit_log
            audit_log("openclaw.pack", trace_id=trace_id, workspace=str(workspace),
                      files=copied, input_bytes=input_bytes, output_bytes=output_bytes)
        except Exception:
            pass
        trace_file = out_dir / ".liquefy-trace-id"
        trace_file.write_text(trace_id, encoding="utf-8")

    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "liquefy_openclaw",
        "command": "pack",
        "ok": True,
        "profile": args.profile,
        "workspace": str(workspace),
        "out_dir": str(out_dir),
        "verify_mode": args.verify_mode,
        "secure": bool(args.secure),
        "sign": bool(args.sign),
        "dry_run": False,
        **({"trace_id": trace_id} if trace_id else {}),
        "result": {
            "scan": scan,
            "files_staged": copied,
            "duration_seconds": round(elapsed, 3),
            "index_path": str(out_dir / "tracevault_index.json"),
            "report_path": str(report),
            "input_bytes": input_bytes,
            "output_bytes": output_bytes,
            "ratio": round(ratio, 2),
            "savings_percent": round(savings, 2),
            "policy": scan.get("policy"),
            "risk_summary": scan.get("risk_summary"),
            "risky_files": scan.get("risky_files", []),
            "tracevault_pack": pack_payload,
        },
    }

    if not args.json:
        print(f"[OK] OpenClaw workspace packed")
        print(f"     files:   {copied}")
        print(f"     ratio:   {ratio:.2f}x")
        print(f"     saved:   {savings:.2f}%")
        print(f"     report:  {report}")
        if risk_summary.get("risky_files_included"):
            print("     warning: risky files were included by explicit override", file=sys.stderr)
    _emit_json(payload, enabled=args.json, json_file=json_file)


if __name__ == "__main__":
    main()
