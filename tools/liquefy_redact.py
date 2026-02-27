#!/usr/bin/env python3
"""
liquefy_redact.py
=================
PII and secret redaction layer for AI agent data.

Strips sensitive data (emails, IPs, API keys, phone numbers, credentials)
from files BEFORE they enter LLM context windows or leave your network.
Unlike LeakHunter (which blocks/quarantines), Redact produces a clean copy
with sensitive values replaced by typed placeholders.

Commands:
    scan      <path>     Dry-run: report what would be redacted (no changes)
    apply     <path>     Redact in-place or to --out directory
    profile   <path>     Estimate PII density and redaction impact
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
CLI_SCHEMA = "liquefy.redact.v1"

# ── PII Patterns ──

PII_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # Emails
    ("email", re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), "[REDACTED_EMAIL]"),

    # IPv4
    ("ipv4", re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), "[REDACTED_IP]"),

    # IPv6 (simplified — catches most common forms)
    ("ipv6", re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), "[REDACTED_IPV6]"),

    # Phone numbers (international formats)
    ("phone", re.compile(r'\b\+?[1-9]\d{0,2}[\s\-\.]?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}\b'), "[REDACTED_PHONE]"),

    # Credit card numbers (basic Luhn-plausible patterns)
    ("credit_card", re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}\b'), "[REDACTED_CC]"),

    # SSN (US)
    ("ssn", re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[REDACTED_SSN]"),

    # AWS Access Keys
    ("aws_key", re.compile(r'AKIA[0-9A-Z]{16}'), "[REDACTED_AWS_KEY]"),

    # AWS Secret Keys
    ("aws_secret", re.compile(r'(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}'), "[REDACTED_AWS_SECRET]"),

    # GitHub tokens
    ("github_token", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "[REDACTED_GITHUB_TOKEN]"),
    ("github_pat", re.compile(r'github_pat_[A-Za-z0-9_]{82,}'), "[REDACTED_GITHUB_PAT]"),

    # OpenAI keys
    ("openai_key", re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'), "[REDACTED_OPENAI_KEY]"),

    # Anthropic keys
    ("anthropic_key", re.compile(r'sk-ant-[A-Za-z0-9\-]{80,}'), "[REDACTED_ANTHROPIC_KEY]"),

    # Stripe keys
    ("stripe_key", re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}'), "[REDACTED_STRIPE_KEY]"),

    # Slack tokens
    ("slack_token", re.compile(r'xox[bpras]-[A-Za-z0-9\-]{10,}'), "[REDACTED_SLACK_TOKEN]"),

    # Google API keys
    ("google_key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "[REDACTED_GOOGLE_KEY]"),

    # Generic secrets in key-value pairs
    ("generic_secret", re.compile(
        r'(?i)(?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?token|private[_\-]?key)'
        r'\s*[=:]\s*["\']?([A-Za-z0-9/+=\-_.]{8,})["\']?'
    ), "[REDACTED_SECRET]"),

    # Bearer tokens
    ("bearer_token", re.compile(r'(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*'), "[REDACTED_BEARER]"),

    # Private keys (PEM blocks)
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY_BLOCK]"),

    # Wallet addresses — Solana (base58, 32-44 chars)
    ("solana_address", re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'), None),

    # Wallet addresses — Ethereum (0x + 40 hex)
    ("eth_address", re.compile(r'\b0x[0-9a-fA-F]{40}\b'), "[REDACTED_ETH_ADDR]"),
]

# Solana addresses overlap with normal base58 text; only redact if user explicitly opts in
SOLANA_PLACEHOLDER = "[REDACTED_SOL_ADDR]"

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache"}
MAX_FILE_BYTES = 50 * 1024 * 1024
TEXT_EXTENSIONS = {
    ".txt", ".log", ".json", ".jsonl", ".csv", ".tsv", ".md", ".yml", ".yaml",
    ".xml", ".html", ".env", ".cfg", ".conf", ".ini", ".toml", ".py", ".js",
    ".ts", ".sh", ".bash", ".sql", ".ndjson",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    payload = {
        "schema_version": CLI_SCHEMA,
        "tool": "liquefy_redact",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    print(json.dumps(payload, indent=2))


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        chunk = path.read_bytes()[:8192]
        chunk.decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


def _collect_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.stat().st_size <= MAX_FILE_BYTES and _is_text_file(fpath):
                files.append(fpath)
    return sorted(files)


def _build_active_patterns(
    categories: Optional[List[str]] = None,
    include_wallets: bool = False,
) -> List[Tuple[str, re.Pattern, str]]:
    active = []
    for name, pattern, placeholder in PII_PATTERNS:
        if name == "solana_address":
            if include_wallets:
                active.append((name, pattern, SOLANA_PLACEHOLDER))
            continue
        if categories and name not in categories:
            continue
        if placeholder is not None:
            active.append((name, pattern, placeholder))
    return active


def _redact_line(
    line: str,
    patterns: List[Tuple[str, re.Pattern, str]],
) -> Tuple[str, List[Dict[str, Any]]]:
    hits: List[Dict[str, Any]] = []
    result = line
    for name, regex, placeholder in patterns:
        matches = list(regex.finditer(result))
        if not matches:
            continue
        for m in reversed(matches):
            original = m.group(0)
            if name == "generic_secret" and m.lastindex and m.lastindex >= 1:
                secret_val = m.group(1)
                result = result[:m.start(1)] + placeholder + result[m.end(1):]
            else:
                result = result[:m.start()] + placeholder + result[m.end():]
            hits.append({
                "type": name,
                "placeholder": placeholder,
                "original_length": len(original),
            })
    return result, hits


def _redact_content(
    content: str,
    patterns: List[Tuple[str, re.Pattern, str]],
) -> Tuple[str, List[Dict[str, Any]]]:
    lines = content.split("\n")
    all_hits: List[Dict[str, Any]] = []
    out_lines = []
    for i, line in enumerate(lines):
        redacted, hits = _redact_line(line, patterns)
        out_lines.append(redacted)
        for h in hits:
            h["line"] = i + 1
            all_hits.append(h)
    return "\n".join(out_lines), all_hits


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("scan", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    patterns = _build_active_patterns(
        categories=args.categories,
        include_wallets=args.include_wallets,
    )
    files = _collect_files(target)

    file_results = []
    total_hits = 0
    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        _, hits = _redact_content(content, patterns)
        if hits:
            rel = str(fpath.relative_to(target)) if target.is_dir() else fpath.name
            file_results.append({
                "file": rel,
                "hits": len(hits),
                "types": sorted(set(h["type"] for h in hits)),
                "details": hits[:50],
            })
            total_hits += len(hits)

    result = {
        "target": str(target),
        "files_scanned": len(files),
        "files_with_pii": len(file_results),
        "total_hits": total_hits,
        "files": file_results,
    }

    if args.json:
        _emit("scan", True, result)
    else:
        print(f"Redact scan: {len(files)} files, {total_hits} PII hits in {len(file_results)} files")
        for fr in file_results:
            print(f"  {fr['file']}: {fr['hits']} hits ({', '.join(fr['types'])})")

    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("apply", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).expanduser().resolve() if args.out else None
    patterns = _build_active_patterns(
        categories=args.categories,
        include_wallets=args.include_wallets,
    )
    files = _collect_files(target)

    file_results = []
    total_hits = 0
    total_redacted = 0

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        redacted, hits = _redact_content(content, patterns)

        if not hits:
            if out_dir and target.is_dir():
                rel = fpath.relative_to(target)
                dest = out_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
            continue

        total_hits += len(hits)
        total_redacted += 1
        rel = str(fpath.relative_to(target)) if target.is_dir() else fpath.name

        if out_dir:
            if target.is_dir():
                dest = out_dir / fpath.relative_to(target)
            else:
                dest = out_dir / fpath.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(redacted, encoding="utf-8")
        else:
            fpath.write_text(redacted, encoding="utf-8")

        file_results.append({
            "file": rel,
            "hits": len(hits),
            "types": sorted(set(h["type"] for h in hits)),
        })

    result = {
        "target": str(target),
        "out_dir": str(out_dir) if out_dir else "(in-place)",
        "files_scanned": len(files),
        "files_redacted": total_redacted,
        "total_hits": total_hits,
        "files": file_results,
    }

    if args.json:
        _emit("apply", True, result)
    else:
        dest_label = str(out_dir) if out_dir else "in-place"
        print(f"Redacted {total_redacted} files ({total_hits} PII hits) -> {dest_label}")
        for fr in file_results:
            print(f"  {fr['file']}: {fr['hits']} hits ({', '.join(fr['types'])})")

    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        if args.json:
            _emit("profile", False, {"error": f"Path not found: {target}"})
        else:
            print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    patterns = _build_active_patterns(include_wallets=args.include_wallets)
    files = _collect_files(target)

    type_counts: Dict[str, int] = {}
    total_bytes = 0
    pii_bytes_removed = 0
    files_with_pii = 0

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_bytes += len(content.encode("utf-8"))
        redacted, hits = _redact_content(content, patterns)
        if hits:
            files_with_pii += 1
            pii_bytes_removed += len(content.encode("utf-8")) - len(redacted.encode("utf-8"))
            for h in hits:
                type_counts[h["type"]] = type_counts.get(h["type"], 0) + 1

    density = (sum(type_counts.values()) / max(len(files), 1))
    result = {
        "target": str(target),
        "files_scanned": len(files),
        "files_with_pii": files_with_pii,
        "total_bytes": total_bytes,
        "pii_bytes_delta": pii_bytes_removed,
        "density_hits_per_file": round(density, 2),
        "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
    }

    if args.json:
        _emit("profile", True, result)
    else:
        print(f"PII Profile: {len(files)} files, {total_bytes:,} bytes")
        print(f"  Files with PII: {files_with_pii}")
        print(f"  Density: {density:.2f} hits/file")
        print(f"  Byte delta after redaction: {pii_bytes_removed:+,}")
        for ptype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  - {ptype}: {count}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-redact",
        description="PII and secret redaction for AI agent data",
    )
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_scan = sub.add_parser("scan", help="Dry-run: report PII without changes")
    p_scan.add_argument("path", help="File or directory to scan")
    p_scan.add_argument("--categories", nargs="*", help="Limit to specific PII types")
    p_scan.add_argument("--include-wallets", action="store_true", help="Include Solana address detection")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(fn=cmd_scan)

    p_apply = sub.add_parser("apply", help="Redact PII (in-place or to --out)")
    p_apply.add_argument("path", help="File or directory to redact")
    p_apply.add_argument("--out", help="Output directory (omit for in-place)")
    p_apply.add_argument("--categories", nargs="*", help="Limit to specific PII types")
    p_apply.add_argument("--include-wallets", action="store_true")
    p_apply.add_argument("--json", action="store_true")
    p_apply.set_defaults(fn=cmd_apply)

    p_profile = sub.add_parser("profile", help="Estimate PII density and redaction impact")
    p_profile.add_argument("path", help="File or directory to profile")
    p_profile.add_argument("--include-wallets", action="store_true")
    p_profile.add_argument("--json", action="store_true")
    p_profile.set_defaults(fn=cmd_profile)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
