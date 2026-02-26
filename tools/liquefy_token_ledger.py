#!/usr/bin/env python3
"""
liquefy_token_ledger.py  [EXPERIMENTAL]
=======================================
Token usage tracking, budgeting, and waste detection for AI agent runs.

Parses agent traces/logs for LLM token usage metadata and provides:
    1. scan    — extract token usage from agent output directories
    2. budget  — set soft/hard token limits per org (daily/monthly)
    3. report  — usage breakdown by model, agent, time window, cost
    4. audit   — detect waste: duplicate prompts, oversized context, model misuse

EXPERIMENTAL: Token counts are extracted from agent logs on a best-effort
basis. Actual billing may differ from estimates. Supported log formats:
OpenAI, Anthropic, LangChain, and generic JSONL with usage fields.

Usage:
    python tools/liquefy_token_ledger.py scan   --dir ./agent-output --json
    python tools/liquefy_token_ledger.py budget --org acme --daily 500000 --monthly 10000000
    python tools/liquefy_token_ledger.py report --org acme --json
    python tools/liquefy_token_ledger.py audit  --dir ./agent-output --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

LEDGER_DIR_NAME = ".liquefy-tokens"
LEDGER_FILE = "ledger.jsonl"
BUDGET_FILE = "budgets.json"
SCHEMA = "liquefy.token-ledger.v1"

MODEL_COSTS_PER_1K = {
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-4-sonnet": {"input": 0.003, "output": 0.015},
    "claude-4-opus": {"input": 0.015, "output": 0.075},
}

DEFAULT_COST = {"input": 0.002, "output": 0.006}


def _ledger_dir(base: Optional[Path] = None) -> Path:
    if base:
        return base / LEDGER_DIR_NAME
    return Path.home() / ".liquefy" / "tokens"


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    model_lower = model.lower()
    costs = DEFAULT_COST
    best_match = ""
    for key, val in MODEL_COSTS_PER_1K.items():
        if key in model_lower and len(key) > len(best_match):
            best_match = key
            costs = val
    return (input_tokens / 1000 * costs["input"]) + (output_tokens / 1000 * costs["output"])


def _normalize_model(raw: str) -> str:
    if not raw:
        return "unknown"
    return raw.strip().lower().replace("_", "-")


def _extract_usage_from_line(data: Dict) -> Optional[Dict]:
    """Extract token usage from a single JSON object (best-effort, multi-format)."""

    usage = data.get("usage") or data.get("token_usage") or data.get("llm_output", {}).get("usage", {})

    if not usage and "response" in data:
        resp = data["response"]
        if isinstance(resp, dict):
            usage = resp.get("usage", {})

    if not usage:
        return None

    input_t = (
        usage.get("prompt_tokens")
        or usage.get("input_tokens")
        or usage.get("prompt_token_count")
        or 0
    )
    output_t = (
        usage.get("completion_tokens")
        or usage.get("output_tokens")
        or usage.get("completion_token_count")
        or 0
    )
    total_t = usage.get("total_tokens") or (input_t + output_t)

    if total_t == 0:
        return None

    model = (
        data.get("model")
        or data.get("model_name")
        or data.get("response", {}).get("model", "")
        if isinstance(data.get("response"), dict)
        else data.get("model", "")
    )
    if isinstance(model, dict):
        model = model.get("id", "unknown")

    ts = data.get("timestamp") or data.get("ts") or data.get("created_at") or data.get("time")

    prompt_hash = None
    messages = data.get("messages") or data.get("prompt") or data.get("input")
    if messages:
        try:
            canonical = json.dumps(messages, sort_keys=True, separators=(",", ":"))
            prompt_hash = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        except (TypeError, ValueError):
            pass

    return {
        "input_tokens": int(input_t),
        "output_tokens": int(output_t),
        "total_tokens": int(total_t),
        "model": _normalize_model(str(model)) if model else "unknown",
        "timestamp": str(ts) if ts else None,
        "prompt_hash": prompt_hash,
    }


def _scan_file(fpath: Path) -> List[Dict]:
    """Scan a single file for token usage entries."""
    entries = []
    try:
        with fpath.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        usage = _extract_usage_from_line(data)
                        if usage:
                            usage["source_file"] = str(fpath.name)
                            entries.append(usage)
                except json.JSONDecodeError:
                    continue
    except (OSError, UnicodeDecodeError):
        pass

    if not entries and fpath.suffix == ".json":
        try:
            raw = json.loads(fpath.read_text("utf-8", errors="replace"))
            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                if isinstance(item, dict):
                    usage = _extract_usage_from_line(item)
                    if usage:
                        usage["source_file"] = str(fpath.name)
                        entries.append(usage)
        except (json.JSONDecodeError, OSError):
            pass

    return entries


def _scan_directory(target_dir: Path) -> List[Dict]:
    """Scan a directory tree for token usage in log/trace files."""
    all_entries = []
    scan_extensions = {".jsonl", ".json", ".log", ".ndjson"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".liquefy-guard", ".liquefy-tokens"}

    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in fnames:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in scan_extensions:
                entries = _scan_file(fpath)
                all_entries.extend(entries)

    return all_entries


def _audit_log(event: str, **details):
    try:
        from liquefy_audit_chain import audit_log
        audit_log(event, **details)
    except Exception:
        pass


def cmd_scan(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    entries = _scan_directory(target_dir)

    if not entries:
        result = {"ok": True, "entries": 0, "message": "No token usage found in logs."}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("  No token usage data found in agent logs.")
            print("  Supported: OpenAI, Anthropic, LangChain JSONL/JSON traces.")
        return 0

    total_input = sum(e["input_tokens"] for e in entries)
    total_output = sum(e["output_tokens"] for e in entries)
    total_tokens = sum(e["total_tokens"] for e in entries)

    by_model = defaultdict(lambda: {"input": 0, "output": 0, "total": 0, "calls": 0, "cost": 0.0})
    for e in entries:
        m = e["model"]
        by_model[m]["input"] += e["input_tokens"]
        by_model[m]["output"] += e["output_tokens"]
        by_model[m]["total"] += e["total_tokens"]
        by_model[m]["calls"] += 1
        by_model[m]["cost"] += _estimate_cost(e["model"], e["input_tokens"], e["output_tokens"])

    total_cost = sum(v["cost"] for v in by_model.values())

    ld = _ledger_dir(target_dir)
    ld.mkdir(parents=True, exist_ok=True)
    ledger_path = ld / LEDGER_FILE
    with ledger_path.open("a", encoding="utf-8") as f:
        for e in entries:
            e["scanned_at"] = datetime.now(timezone.utc).isoformat()
            f.write(json.dumps(e, separators=(",", ":")) + "\n")

    _audit_log("token_ledger.scan", entries=len(entries), total_tokens=total_tokens,
               estimated_cost=round(total_cost, 4))

    result = {
        "ok": True,
        "experimental": True,
        "entries": len(entries),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_tokens,
        "estimated_cost_usd": round(total_cost, 4),
        "by_model": {k: {**v, "cost": round(v["cost"], 4)} for k, v in by_model.items()},
        "ledger_file": str(ledger_path),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Token Ledger — Scan [EXPERIMENTAL]")
        print(f"    Directory:       {target_dir}")
        print(f"    API calls found: {len(entries)}")
        print(f"    Input tokens:    {total_input:,}")
        print(f"    Output tokens:   {total_output:,}")
        print(f"    Total tokens:    {total_tokens:,}")
        print(f"    Est. cost:       ${total_cost:.4f}")
        print()
        print(f"    By model:")
        for model, stats in sorted(by_model.items(), key=lambda x: -x[1]["total"]):
            print(f"      {model}: {stats['total']:,} tokens, {stats['calls']} calls, ~${stats['cost']:.4f}")
        print()
        print(f"    Note: Cost estimates are approximate. Check provider billing for exact amounts.")

    return 0


def cmd_budget(args: argparse.Namespace) -> int:
    org = args.org or "default"
    ld = _ledger_dir()
    ld.mkdir(parents=True, exist_ok=True)
    budget_path = ld / BUDGET_FILE

    budgets = {}
    if budget_path.exists():
        budgets = json.loads(budget_path.read_text("utf-8"))

    budgets[org] = {
        "daily_tokens": args.daily,
        "monthly_tokens": args.monthly,
        "daily_cost_usd": args.daily_cost,
        "monthly_cost_usd": args.monthly_cost,
        "warn_at_percent": args.warn or 80,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    budget_path.write_text(json.dumps(budgets, indent=2), encoding="utf-8")
    _audit_log("token_ledger.budget_set", org=org)

    if args.json:
        print(json.dumps({"ok": True, "org": org, **budgets[org]}, indent=2))
    else:
        print(f"  Token Budget — {org}")
        if args.daily:
            print(f"    Daily limit:   {args.daily:,} tokens")
        if args.monthly:
            print(f"    Monthly limit: {args.monthly:,} tokens")
        if args.daily_cost:
            print(f"    Daily cost:    ${args.daily_cost}")
        if args.monthly_cost:
            print(f"    Monthly cost:  ${args.monthly_cost}")
        print(f"    Warn at:       {budgets[org]['warn_at_percent']}%")
        print(f"    Saved:         {budget_path}")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    org = args.org or "default"

    search_paths = [_ledger_dir()]
    if args.dir:
        search_paths.insert(0, _ledger_dir(Path(args.dir).resolve()))

    all_entries = []
    for ld in search_paths:
        ledger_path = ld / LEDGER_FILE
        if ledger_path.exists():
            with ledger_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            all_entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

    if not all_entries:
        msg = "No token data found. Run 'scan' first."
        if args.json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"  {msg}")
        return 1

    now = datetime.now(timezone.utc)
    today_str = now.strftime("%Y-%m-%d")

    period = args.period or "all"
    if period == "today":
        entries = [e for e in all_entries if e.get("scanned_at", "").startswith(today_str)]
    elif period == "week":
        week_ago = (now - timedelta(days=7)).isoformat()
        entries = [e for e in all_entries if e.get("scanned_at", "") >= week_ago]
    elif period == "month":
        month_str = now.strftime("%Y-%m")
        entries = [e for e in all_entries if e.get("scanned_at", "").startswith(month_str)]
    else:
        entries = all_entries

    total_input = sum(e.get("input_tokens", 0) for e in entries)
    total_output = sum(e.get("output_tokens", 0) for e in entries)
    total_tokens = sum(e.get("total_tokens", 0) for e in entries)

    by_model = defaultdict(lambda: {"input": 0, "output": 0, "total": 0, "calls": 0, "cost": 0.0})
    for e in entries:
        m = e.get("model", "unknown")
        by_model[m]["input"] += e.get("input_tokens", 0)
        by_model[m]["output"] += e.get("output_tokens", 0)
        by_model[m]["total"] += e.get("total_tokens", 0)
        by_model[m]["calls"] += 1
        by_model[m]["cost"] += _estimate_cost(m, e.get("input_tokens", 0), e.get("output_tokens", 0))

    total_cost = sum(v["cost"] for v in by_model.values())

    budget_path = _ledger_dir() / BUDGET_FILE
    budget_status = None
    if budget_path.exists():
        budgets = json.loads(budget_path.read_text("utf-8"))
        if org in budgets:
            b = budgets[org]
            budget_status = {"org": org}
            if b.get("daily_tokens"):
                budget_status["daily_tokens_limit"] = b["daily_tokens"]
                day_entries = [e for e in all_entries if e.get("scanned_at", "").startswith(today_str)]
                day_total = sum(e.get("total_tokens", 0) for e in day_entries)
                budget_status["daily_tokens_used"] = day_total
                budget_status["daily_tokens_pct"] = round(day_total / b["daily_tokens"] * 100, 1) if b["daily_tokens"] else 0
            if b.get("monthly_tokens"):
                month_str = now.strftime("%Y-%m")
                month_entries = [e for e in all_entries if e.get("scanned_at", "").startswith(month_str)]
                month_total = sum(e.get("total_tokens", 0) for e in month_entries)
                budget_status["monthly_tokens_limit"] = b["monthly_tokens"]
                budget_status["monthly_tokens_used"] = month_total
                budget_status["monthly_tokens_pct"] = round(month_total / b["monthly_tokens"] * 100, 1) if b["monthly_tokens"] else 0

    result = {
        "ok": True,
        "experimental": True,
        "period": period,
        "entries": len(entries),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_tokens,
        "estimated_cost_usd": round(total_cost, 4),
        "by_model": {k: {**v, "cost": round(v["cost"], 4)} for k, v in by_model.items()},
        "budget": budget_status,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Token Ledger — Report [EXPERIMENTAL]")
        print(f"    Period:          {period}")
        print(f"    API calls:       {len(entries)}")
        print(f"    Input tokens:    {total_input:,}")
        print(f"    Output tokens:   {total_output:,}")
        print(f"    Total tokens:    {total_tokens:,}")
        print(f"    Est. cost:       ${total_cost:.4f}")
        if by_model:
            print()
            for model, stats in sorted(by_model.items(), key=lambda x: -x[1]["total"]):
                print(f"      {model}: {stats['total']:,} tokens, {stats['calls']} calls, ~${stats['cost']:.4f}")
        if budget_status:
            print()
            print(f"    Budget ({org}):")
            if "daily_tokens_pct" in budget_status:
                pct = budget_status["daily_tokens_pct"]
                flag = " ⚠ OVER LIMIT" if pct >= 100 else " ⚠ WARNING" if pct >= 80 else ""
                print(f"      Daily:   {budget_status['daily_tokens_used']:,} / {budget_status['daily_tokens_limit']:,} ({pct}%){flag}")
            if "monthly_tokens_pct" in budget_status:
                pct = budget_status["monthly_tokens_pct"]
                flag = " ⚠ OVER LIMIT" if pct >= 100 else " ⚠ WARNING" if pct >= 80 else ""
                print(f"      Monthly: {budget_status['monthly_tokens_used']:,} / {budget_status['monthly_tokens_limit']:,} ({pct}%){flag}")
        print()
        print(f"    Note: Cost estimates are approximate. Check provider billing for exact amounts.")

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve()
    if not target_dir.exists():
        print(json.dumps({"ok": False, "error": f"Directory not found: {target_dir}"}))
        return 1

    entries = _scan_directory(target_dir)

    if not entries:
        if args.json:
            print(json.dumps({"ok": True, "issues": [], "message": "No token data to audit."}))
        else:
            print("  No token usage data found to audit.")
        return 0

    issues = []

    prompt_hashes = defaultdict(list)
    for e in entries:
        if e.get("prompt_hash"):
            prompt_hashes[e["prompt_hash"]].append(e)

    for ph, dupes in prompt_hashes.items():
        if len(dupes) > 1:
            wasted = sum(d["total_tokens"] for d in dupes[1:])
            issues.append({
                "type": "duplicate_prompt",
                "severity": "warning",
                "count": len(dupes),
                "wasted_tokens": wasted,
                "prompt_hash": ph,
                "message": f"Identical prompt sent {len(dupes)} times — {wasted:,} tokens wasted",
            })

    for e in entries:
        if e["input_tokens"] > 100000:
            issues.append({
                "type": "oversized_context",
                "severity": "warning",
                "tokens": e["input_tokens"],
                "model": e["model"],
                "source": e.get("source_file", "unknown"),
                "message": f"Oversized input: {e['input_tokens']:,} tokens to {e['model']}",
            })

    expensive_models = {"gpt-4", "claude-3-opus", "claude-4-opus"}
    for e in entries:
        if any(m in e["model"] for m in expensive_models):
            if e["output_tokens"] < 50 and e["input_tokens"] < 500:
                issues.append({
                    "type": "model_overkill",
                    "severity": "info",
                    "model": e["model"],
                    "input_tokens": e["input_tokens"],
                    "output_tokens": e["output_tokens"],
                    "source": e.get("source_file", "unknown"),
                    "message": f"Small task ({e['total_tokens']} tokens) on expensive model {e['model']} — consider a cheaper model",
                })

    input_output_ratios = [e["input_tokens"] / max(e["output_tokens"], 1) for e in entries if e["output_tokens"] > 0]
    if input_output_ratios:
        avg_ratio = sum(input_output_ratios) / len(input_output_ratios)
        if avg_ratio > 20:
            issues.append({
                "type": "high_input_ratio",
                "severity": "info",
                "avg_ratio": round(avg_ratio, 1),
                "message": f"Average input/output ratio is {avg_ratio:.1f}x — agents may be sending too much context for small outputs",
            })

    total_tokens = sum(e["total_tokens"] for e in entries)
    total_wasted = sum(i.get("wasted_tokens", 0) for i in issues)
    waste_pct = round(total_wasted / total_tokens * 100, 1) if total_tokens > 0 else 0

    result = {
        "ok": True,
        "experimental": True,
        "total_calls": len(entries),
        "total_tokens": total_tokens,
        "issues_found": len(issues),
        "wasted_tokens": total_wasted,
        "waste_percent": waste_pct,
        "issues": issues,
    }

    _audit_log("token_ledger.audit", issues=len(issues), wasted_tokens=total_wasted)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Token Ledger — Audit [EXPERIMENTAL]")
        print(f"    Calls analyzed: {len(entries)}")
        print(f"    Total tokens:   {total_tokens:,}")
        print(f"    Issues found:   {len(issues)}")
        if total_wasted > 0:
            print(f"    Wasted tokens:  {total_wasted:,} ({waste_pct}%)")
        print()
        if issues:
            for i in issues:
                sev = i["severity"].upper()
                print(f"    [{sev}] {i['message']}")
        else:
            print(f"    No waste detected. Token usage looks clean.")
        print()
        print(f"    Note: Estimates are approximate. Check provider billing for exact amounts.")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-token-ledger",
        description="[EXPERIMENTAL] Token usage tracking, budgeting, and waste detection.",
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan agent logs for token usage")
    p_scan.add_argument("--dir", required=True, help="Agent output directory")
    p_scan.add_argument("--json", action="store_true")

    p_budget = sub.add_parser("budget", help="Set token budgets per org")
    p_budget.add_argument("--org", default="default", help="Organization name")
    p_budget.add_argument("--daily", type=int, help="Daily token limit")
    p_budget.add_argument("--monthly", type=int, help="Monthly token limit")
    p_budget.add_argument("--daily-cost", type=float, help="Daily cost limit (USD)")
    p_budget.add_argument("--monthly-cost", type=float, help="Monthly cost limit (USD)")
    p_budget.add_argument("--warn", type=int, help="Warn at percent (default 80)")
    p_budget.add_argument("--json", action="store_true")

    p_report = sub.add_parser("report", help="Usage report")
    p_report.add_argument("--org", default="default", help="Organization name")
    p_report.add_argument("--dir", help="Agent output directory (optional)")
    p_report.add_argument("--period", choices=["today", "week", "month", "all"], default="all")
    p_report.add_argument("--json", action="store_true")

    p_audit = sub.add_parser("audit", help="Detect token waste")
    p_audit.add_argument("--dir", required=True, help="Agent output directory")
    p_audit.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"scan": cmd_scan, "budget": cmd_budget, "report": cmd_report, "audit": cmd_audit}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
