#!/usr/bin/env python3
"""
liquefy_leakhunter.py
=====================
Deep-scan live sessions, existing vaults, and raw files for secrets, keys,
env vars, skillsSnapshot dumps, and recursive JSONL credential patterns.

Uses the Liquefy policy engine + OpenClaw-specific patterns.
Supports standalone CLI mode and daemon-integrated mode.

Directly addresses: credential leakage in agent workspaces.

Modes:
    scan      — scan a directory or file, report findings
    watch     — daemon mode: continuous monitoring with auto-quarantine
    report    — generate LEAKS.md from previous scan results

Usage:
    python tools/liquefy_leakhunter.py scan  ~/.openclaw --json
    python tools/liquefy_leakhunter.py scan  ./vault/run_001 --deep --quarantine
    python tools/liquefy_leakhunter.py watch ~/.openclaw --poll 60
    python tools/liquefy_leakhunter.py report --input leakhunter_results.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

from path_policy import (
    PathPolicy,
    default_policy,
    classify_risky_path,
    classify_risky_rel_path,
)

CLI_SCHEMA_VERSION = "liquefy.leakhunter.cli.v1"

SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", ".pytest_cache"}
MAX_FILE_SCAN_BYTES = 50 * 1024 * 1024  # 50 MB per file

# ── Secret Patterns ──

@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern
    severity: str  # "critical" | "high" | "medium" | "low"
    description: str

SECRET_PATTERNS: List[SecretPattern] = [
    # API Keys & Tokens
    SecretPattern("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), "critical", "AWS IAM access key ID"),
    SecretPattern("AWS Secret Key", re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}'), "critical", "AWS secret access key"),
    SecretPattern("GitHub Token", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "critical", "GitHub personal/OAuth/app token"),
    SecretPattern("GitHub Classic PAT", re.compile(r'github_pat_[A-Za-z0-9_]{82,}'), "critical", "GitHub fine-grained PAT"),
    SecretPattern("OpenAI API Key", re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'), "critical", "OpenAI API key"),
    SecretPattern("Anthropic Key", re.compile(r'sk-ant-[A-Za-z0-9\-]{80,}'), "critical", "Anthropic API key"),
    SecretPattern("Slack Token", re.compile(r'xox[bpras]-[A-Za-z0-9\-]{10,}'), "high", "Slack bot/app/user token"),
    SecretPattern("Stripe Key", re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}'), "critical", "Stripe API key"),
    SecretPattern("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "high", "Google Cloud API key"),
    SecretPattern("Discord Token", re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'), "critical", "Discord bot token"),
    SecretPattern("Telegram Bot Token", re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'), "high", "Telegram bot API token"),

    # Private Keys
    SecretPattern("RSA Private Key", re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "critical", "PEM-encoded private key"),
    SecretPattern("EC Private Key", re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "critical", "EC private key"),
    SecretPattern("OpenSSH Private Key", re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "critical", "OpenSSH private key"),

    # Connection Strings & Passwords
    SecretPattern("Generic Password", re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}'), "high", "Password in config/env"),
    SecretPattern("Connection String", re.compile(r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\']+@[^\s"\']+'), "critical", "Database/service connection string with credentials"),
    SecretPattern("Bearer Token", re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'), "high", "HTTP Bearer token"),

    # Environment & Config Leaks
    SecretPattern("Env File Content", re.compile(r'^[A-Z_]{3,50}=[^\s]{8,}$', re.MULTILINE), "medium", "Environment variable assignment"),
    SecretPattern("JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "high", "JSON Web Token"),

    # OpenClaw-Specific
    SecretPattern("OpenClaw Config Secrets", re.compile(r'(?i)(?:api_key|secret_key|master_secret)\s*[=:]\s*["\']?[^\s"\']{12,}'), "critical", "OpenClaw config secret"),
    SecretPattern("SkillsSnapshot Dump", re.compile(r'"skillsSnapshot"\s*:\s*\{'), "medium", "Agent skills snapshot in JSONL (may contain injected creds)"),
    SecretPattern("Session Auth Blob", re.compile(r'"auth(?:_token|orization)?"\s*:\s*"[A-Za-z0-9+/=]{20,}"'), "high", "Auth token embedded in session data"),

    # Crypto & Wallet
    SecretPattern("Mnemonic Seed", re.compile(r'(?i)(?:mnemonic|seed\s*phrase)\s*[=:]\s*"[a-z\s]{20,}"'), "critical", "Cryptocurrency mnemonic seed phrase"),
    SecretPattern("Hex Private Key", re.compile(r'(?i)private[_\-]?key\s*[=:]\s*["\']?(?:0x)?[0-9a-fA-F]{64}'), "critical", "Hex-encoded private key"),
]


@dataclass
class Finding:
    file: str
    line_number: int
    pattern_name: str
    severity: str
    matched_text: str  # redacted snippet
    description: str


@dataclass
class ScanResult:
    target: str
    ts: str
    files_scanned: int
    findings: List[Finding] = field(default_factory=list)
    policy_denials: List[Dict[str, str]] = field(default_factory=list)
    quarantined: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_match(text: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    if len(text) <= keep_prefix + keep_suffix + 4:
        return "*" * len(text)
    return text[:keep_prefix] + "***REDACTED***" + text[-keep_suffix:]


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _is_text_file(path: Path) -> bool:
    """Heuristic: check first 8KB for binary content."""
    try:
        with path.open("rb") as f:
            chunk = f.read(8192)
        if b"\x00" in chunk:
            return False
        return True
    except OSError:
        return False


def _scan_file_content(
    file_path: Path,
    patterns: List[SecretPattern],
    deep: bool,
) -> List[Finding]:
    findings: List[Finding] = []

    if not _is_text_file(file_path):
        return findings

    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_SCAN_BYTES:
            return findings

        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = content.split("\n")
    for line_num, line in enumerate(lines, start=1):
        for pattern in patterns:
            for match in pattern.regex.finditer(line):
                matched = match.group(0)
                findings.append(Finding(
                    file=str(file_path),
                    line_number=line_num,
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    matched_text=_redact_match(matched),
                    description=pattern.description,
                ))

    if deep:
        findings.extend(_deep_scan_jsonl(file_path, content))

    return findings


def _deep_scan_jsonl(file_path: Path, content: str) -> List[Finding]:
    """Deep scan JSONL files for nested/recursive credential patterns."""
    findings: List[Finding] = []
    if file_path.suffix.lower() not in {".jsonl", ".json", ".log"}:
        return findings

    for line_num, line in enumerate(content.split("\n"), start=1):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            _walk_json_for_secrets(obj, str(file_path), line_num, findings, depth=0)
        except (json.JSONDecodeError, RecursionError):
            pass

    return findings


SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|'
    r'password|passwd|credential|private[_\-]?key|master[_\-]?secret|'
    r'bearer|authorization|session[_\-]?token|refresh[_\-]?token)',
)


def _walk_json_for_secrets(
    obj: Any,
    file_path: str,
    line_number: int,
    findings: List[Finding],
    depth: int,
    path: str = "$",
) -> None:
    if depth > 15:
        return

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}"
            if isinstance(value, str) and len(value) >= 8 and SENSITIVE_KEY_PATTERNS.search(key):
                findings.append(Finding(
                    file=file_path,
                    line_number=line_number,
                    pattern_name="JSON Nested Secret",
                    severity="high",
                    matched_text=f"{key}={_redact_match(value)}",
                    description=f"Sensitive key '{key}' found at {current_path}",
                ))
            if isinstance(value, str) and len(value) > 100:
                try:
                    nested = json.loads(value)
                    _walk_json_for_secrets(nested, file_path, line_number, findings, depth + 1, current_path)
                except (json.JSONDecodeError, RecursionError):
                    pass
            elif isinstance(value, (dict, list)):
                _walk_json_for_secrets(value, file_path, line_number, findings, depth + 1, current_path)

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _walk_json_for_secrets(item, file_path, line_number, findings, depth + 1, f"{path}[{idx}]")


def _quarantine(file_path: Path, quarantine_dir: Path) -> Optional[str]:
    """Move file to quarantine directory."""
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    dest = quarantine_dir / f"{file_path.name}.quarantined.{int(time.time())}"
    try:
        shutil.move(str(file_path), str(dest))
        return str(dest)
    except OSError:
        return None


def scan(
    target: Path,
    *,
    deep: bool = False,
    quarantine: bool = False,
    quarantine_dir: Optional[Path] = None,
    policy: PathPolicy,
    patterns: Optional[List[SecretPattern]] = None,
) -> ScanResult:
    """Scan a directory or file for secrets and policy violations."""
    result = ScanResult(target=str(target), ts=_utc_now(), files_scanned=0)
    used_patterns = patterns or SECRET_PATTERNS

    if quarantine_dir is None:
        quarantine_dir = target.parent / ".liquefy_quarantine" if target.is_dir() else target.parent / ".liquefy_quarantine"

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [f for f in target.rglob("*") if f.is_file() and not _should_skip(f)]
    else:
        result.errors.append(f"Target not found: {target}")
        return result

    root = target if target.is_dir() else target.parent

    for file_path in files:
        result.files_scanned += 1

        risky = classify_risky_path(file_path, root)
        if risky:
            category, reason = risky
            result.policy_denials.append({
                "file": str(file_path),
                "category": category,
                "reason": reason,
            })

        file_findings = _scan_file_content(file_path, used_patterns, deep)
        result.findings.extend(file_findings)

        if quarantine and (file_findings or risky):
            critical = any(f.severity == "critical" for f in file_findings)
            if critical or risky:
                dest = _quarantine(file_path, quarantine_dir)
                if dest:
                    result.quarantined.append(dest)

    return result


def _generate_leaks_md(result: ScanResult) -> str:
    """Generate a LEAKS.md report from scan results."""
    lines = [
        "# Liquefy LeakHunter Report",
        "",
        f"**Scan Target**: `{result.target}`",
        f"**Timestamp**: {result.ts}",
        f"**Files Scanned**: {result.files_scanned}",
        f"**Total Findings**: {result.total_findings}",
        f"**Critical**: {result.critical_count} | **High**: {result.high_count}",
        "",
    ]

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Pattern | File | Line | Match (Redacted) |")
        lines.append("|---|----------|---------|------|------|-----------------|")
        for i, f in enumerate(result.findings, 1):
            rel_file = Path(f.file).name
            lines.append(f"| {i} | **{f.severity.upper()}** | {f.pattern_name} | `{rel_file}` | {f.line_number} | `{f.matched_text}` |")
        lines.append("")

    if result.policy_denials:
        lines.append("## Policy Denials (Risky Files)")
        lines.append("")
        for d in result.policy_denials:
            lines.append(f"- `{Path(d['file']).name}` — {d['category']}: {d['reason']}")
        lines.append("")

    if result.quarantined:
        lines.append("## Quarantined Files")
        lines.append("")
        for q in result.quarantined:
            lines.append(f"- `{q}`")
        lines.append("")

    if result.errors:
        lines.append("## Errors")
        lines.append("")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")

    if not result.findings and not result.policy_denials:
        lines.append("## Status: CLEAN")
        lines.append("")
        lines.append("No secrets or policy violations detected.")
        lines.append("")

    return "\n".join(lines)


def _emit_json(payload: Dict, enabled: bool, json_file: Optional[str]) -> None:
    if json_file:
        p = Path(json_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if enabled:
        print(json.dumps(payload, indent=2))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-leakhunter", description="Liquefy Redact + Leak Hunter")
    sub = ap.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan for secrets and leaks")
    p_scan.add_argument("target", help="Directory or file to scan")
    p_scan.add_argument("--deep", action="store_true", help="Enable deep JSONL recursive scanning")
    p_scan.add_argument("--quarantine", action="store_true", help="Auto-quarantine critical findings")
    p_scan.add_argument("--quarantine-dir", default=None, help="Custom quarantine directory")
    p_scan.add_argument("--mode", choices=["strict", "balanced", "off"], default="strict")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--json-file", default=None)
    p_scan.add_argument("--output-leaks-md", default=None, help="Write LEAKS.md report to path")

    p_watch = sub.add_parser("watch", help="Daemon mode: continuous leak monitoring")
    p_watch.add_argument("target", help="Directory to watch")
    p_watch.add_argument("--deep", action="store_true")
    p_watch.add_argument("--quarantine", action="store_true")
    p_watch.add_argument("--poll", type=int, default=60, help="Seconds between scans")
    p_watch.add_argument("--mode", choices=["strict", "balanced", "off"], default="strict")

    p_report = sub.add_parser("report", help="Generate LEAKS.md from scan results JSON")
    p_report.add_argument("--input", required=True, help="Path to leakhunter results JSON")
    p_report.add_argument("--output", default="LEAKS.md", help="Output path for report")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    if args.command == "scan":
        target = Path(args.target).expanduser().resolve()
        policy = default_policy(mode=args.mode)
        quarantine_dir = Path(args.quarantine_dir).resolve() if args.quarantine_dir else None

        result = scan(
            target,
            deep=args.deep,
            quarantine=args.quarantine,
            quarantine_dir=quarantine_dir,
            policy=policy,
        )

        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "command": "scan",
            "ok": result.critical_count == 0,
            "result": {
                "target": result.target,
                "ts": result.ts,
                "files_scanned": result.files_scanned,
                "total_findings": result.total_findings,
                "critical": result.critical_count,
                "high": result.high_count,
                "findings": [
                    {
                        "file": f.file,
                        "line": f.line_number,
                        "pattern": f.pattern_name,
                        "severity": f.severity,
                        "match": f.matched_text,
                        "description": f.description,
                    }
                    for f in result.findings
                ],
                "policy_denials": result.policy_denials,
                "quarantined": result.quarantined,
                "errors": result.errors,
            },
        }

        enabled = getattr(args, "json", False)
        _emit_json(payload, enabled, getattr(args, "json_file", None))

        if args.output_leaks_md:
            md = _generate_leaks_md(result)
            Path(args.output_leaks_md).write_text(md, encoding="utf-8")
            print(f"LEAKS.md written to {args.output_leaks_md}", file=sys.stderr)

        if not enabled:
            print(f"\nLeakHunter Scan: {target}")
            print(f"  Files scanned: {result.files_scanned}")
            print(f"  Findings: {result.total_findings} (critical={result.critical_count}, high={result.high_count})")
            print(f"  Policy denials: {len(result.policy_denials)}")
            if result.quarantined:
                print(f"  Quarantined: {len(result.quarantined)}")
            if result.critical_count > 0:
                print("\n  *** CRITICAL SECRETS DETECTED — review findings immediately ***")

        return 0 if result.critical_count == 0 else 2

    if args.command == "watch":
        import signal as sig
        target = Path(args.target).expanduser().resolve()
        policy = default_policy(mode=args.mode)
        running = True

        def _stop(s, f):
            nonlocal running
            running = False

        sig.signal(sig.SIGTERM, _stop)
        sig.signal(sig.SIGINT, _stop)

        print(f"[leakhunter] watch mode started on {target}, poll={args.poll}s", file=sys.stderr)
        while running:
            result = scan(target, deep=args.deep, quarantine=args.quarantine, policy=policy)
            if result.total_findings > 0:
                print(f"[leakhunter] {_utc_now()} — {result.total_findings} findings ({result.critical_count} critical)", file=sys.stderr)
            for _ in range(args.poll):
                if not running:
                    break
                time.sleep(1)
        print("[leakhunter] watch stopped", file=sys.stderr)
        return 0

    if args.command == "report":
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Input not found: {input_path}", file=sys.stderr)
            return 1

        data = json.loads(input_path.read_text(encoding="utf-8"))
        res = data.get("result", data)

        result = ScanResult(
            target=res.get("target", "unknown"),
            ts=res.get("ts", _utc_now()),
            files_scanned=res.get("files_scanned", 0),
            findings=[
                Finding(
                    file=f.get("file", ""),
                    line_number=f.get("line", 0),
                    pattern_name=f.get("pattern", ""),
                    severity=f.get("severity", "medium"),
                    matched_text=f.get("match", ""),
                    description=f.get("description", ""),
                )
                for f in res.get("findings", [])
            ],
            policy_denials=res.get("policy_denials", []),
            quarantined=res.get("quarantined", []),
            errors=res.get("errors", []),
        )

        md = _generate_leaks_md(result)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"Report written to {args.output}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
