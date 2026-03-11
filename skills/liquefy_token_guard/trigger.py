#!/usr/bin/env python3
"""
ClawHub Skill Trigger: Liquefy Token Guard
==========================================
Entry point for token scan, waste audit, budget guard, and operator recommendations.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


SKILL_DIR = Path(__file__).resolve().parent
REPO_ROOT = SKILL_DIR.parent.parent
LEDGER_SCRIPT = REPO_ROOT / "tools" / "liquefy_token_ledger.py"
CAPSULE_SCRIPT = REPO_ROOT / "tools" / "liquefy_context_capsule.py"


def _load_config() -> Dict[str, Any]:
    config_path = Path(os.environ.get("OPENCLAW_SKILL_CONFIG", str(SKILL_DIR / "config.json")))
    defaults: Dict[str, Any] = {
        "trace_dir": "~/.openclaw",
        "org": "default",
        "period": "today",
        "capsule_out_dir": None,
        "daily_tokens": 500000,
        "monthly_tokens": 10000000,
        "daily_cost_usd": None,
        "monthly_cost_usd": None,
        "warn_at_percent": 80,
        "auto_scan_on_status": True,
        "apply_budget_on_status": False,
    }
    if config_path.exists():
        try:
            user_cfg = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(user_cfg, dict):
                defaults.update(user_cfg)
        except Exception:
            pass
    return defaults


def _expanded_trace_dir(cfg: Dict[str, Any]) -> Path:
    return Path(str(cfg["trace_dir"])).expanduser().resolve()


def _run_ledger(*args: str) -> Dict[str, Any]:
    cmd = [sys.executable, str(LEDGER_SCRIPT), *args, "--json"]
    env = os.environ.copy()
    env["HOME"] = str(Path.home())
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
    if proc.returncode != 0:
        try:
            payload = json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError:
            payload = {"ok": False, "error": proc.stderr.strip() or proc.stdout.strip() or "command failed"}
        if "ok" not in payload:
            payload["ok"] = False
        return payload
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": proc.stderr.strip() or "invalid json from token ledger"}


def _run_capsule(*args: str) -> Dict[str, Any]:
    cmd = [sys.executable, str(CAPSULE_SCRIPT), *args, "--json"]
    env = os.environ.copy()
    env["HOME"] = str(Path.home())
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
    if proc.returncode != 0:
        try:
            payload = json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError:
            payload = {"ok": False, "error": proc.stderr.strip() or proc.stdout.strip() or "command failed"}
        if "ok" not in payload:
            payload["ok"] = False
        return payload
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": proc.stderr.strip() or "invalid json from context capsule"}


def _budget_args(cfg: Dict[str, Any]) -> List[str]:
    args = ["budget", "--org", str(cfg["org"])]
    if cfg.get("daily_tokens") is not None:
        args.extend(["--daily", str(cfg["daily_tokens"])])
    if cfg.get("monthly_tokens") is not None:
        args.extend(["--monthly", str(cfg["monthly_tokens"])])
    if cfg.get("daily_cost_usd") is not None:
        args.extend(["--daily-cost", str(cfg["daily_cost_usd"])])
    if cfg.get("monthly_cost_usd") is not None:
        args.extend(["--monthly-cost", str(cfg["monthly_cost_usd"])])
    if cfg.get("warn_at_percent") is not None:
        args.extend(["--warn", str(cfg["warn_at_percent"])])
    return args


def _scan_if_needed(cfg: Dict[str, Any]) -> Dict[str, Any]:
    trace_dir = _expanded_trace_dir(cfg)
    if not trace_dir.exists():
        return {"ok": False, "error": f"Trace directory not found: {trace_dir}"}
    return _run_ledger("scan", "--dir", str(trace_dir))


def _recommendations(audit: Dict[str, Any], report: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    recommendations: List[Dict[str, Any]] = []
    seen_types = {issue.get("type") for issue in audit.get("issues", [])}

    if "duplicate_prompt" in seen_types:
        recommendations.append({
            "priority": "high",
            "title": "Dedupe repeated prompts",
            "action": "Cache exact prompt/context pairs or collapse retry loops before they hit the model.",
            "why": "The same prompt is being sent multiple times and burning tokens for no new value.",
        })
    if "oversized_context" in seen_types:
        recommendations.append({
            "priority": "high",
            "title": "Split context into bootstrap / relevant / cold",
            "action": "Keep cold history out of the live prompt. Archive old traces with Liquefy and load summaries first.",
            "why": "Oversized input is the clearest sign the stack is dumping raw history instead of ranking context.",
        })
    if "model_overkill" in seen_types:
        recommendations.append({
            "priority": "medium",
            "title": "Route small tasks to cheaper models",
            "action": "Use expensive models only for hard tasks. Let small extraction/summarization calls hit cheaper providers.",
            "why": "Tiny tasks on premium models waste money without improving output quality.",
        })
    if "high_input_ratio" in seen_types:
        recommendations.append({
            "priority": "medium",
            "title": "Send summaries, not transcript dumps",
            "action": "Persist session summaries and resolution patterns instead of replaying every previous turn.",
            "why": "A very high input/output ratio usually means the agent is overfeeding context for very small answers.",
        })
    if "unknown_model" in seen_types:
        recommendations.append({
            "priority": "low",
            "title": "Fix model cost metadata",
            "action": "Add custom model prices so cost estimates stop lying.",
            "why": "Unknown-model defaults make budget reporting noisy and undermine operator trust.",
        })

    budget = (report or {}).get("budget") or {}
    if budget.get("daily_tokens_pct", 0) >= 80 or budget.get("monthly_tokens_pct", 0) >= 80:
        recommendations.append({
            "priority": "high",
            "title": "Budget pressure is real",
            "action": "Cut duplicate prompts now and move stale artifacts into Liquefy Archive before the hot path grows further.",
            "why": "You are already near the configured budget threshold.",
        })

    if not recommendations:
        recommendations.append({
            "priority": "info",
            "title": "Usage looks clean",
            "action": "Keep scanning daily. If token totals still rise, focus on provider choice and archival of cold artifacts.",
            "why": "No major waste pattern was detected in the current trace set.",
        })

    return recommendations


def cmd_scan_now(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return _scan_if_needed(cfg)


def cmd_audit_now(cfg: Dict[str, Any]) -> Dict[str, Any]:
    trace_dir = _expanded_trace_dir(cfg)
    if not trace_dir.exists():
        return {"ok": False, "error": f"Trace directory not found: {trace_dir}"}
    return _run_ledger("audit", "--dir", str(trace_dir))


def cmd_set_budget(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return _run_ledger(*_budget_args(cfg))


def cmd_build_capsule(cfg: Dict[str, Any]) -> Dict[str, Any]:
    trace_dir = _expanded_trace_dir(cfg)
    if not trace_dir.exists():
        return {"ok": False, "error": f"Trace directory not found: {trace_dir}"}

    args = ["build", "--dir", str(trace_dir)]
    if cfg.get("capsule_out_dir"):
        args.extend(["--out", str(Path(str(cfg["capsule_out_dir"])).expanduser().resolve())])
    return _run_capsule(*args)


def cmd_prime_next_run(cfg: Dict[str, Any]) -> Dict[str, Any]:
    trace_dir = _expanded_trace_dir(cfg)
    if not trace_dir.exists():
        return {"ok": False, "error": f"Trace directory not found: {trace_dir}"}

    workspace_dir = Path(str(cfg.get("workspace_dir") or cfg["trace_dir"])).expanduser().resolve()
    args = ["prime", "--workspace", str(workspace_dir), "--trace-dir", str(trace_dir)]
    return _run_capsule(*args)


def cmd_verify_capsule(cfg: Dict[str, Any]) -> Dict[str, Any]:
    workspace_dir = Path(str(cfg.get("workspace_dir") or cfg["trace_dir"])).expanduser().resolve()
    trace_dir = _expanded_trace_dir(cfg)
    return _run_capsule("verify", "--workspace", str(workspace_dir), "--trace-dir", str(trace_dir))


def cmd_scoreboard(cfg: Dict[str, Any]) -> Dict[str, Any]:
    workspace_dir = Path(str(cfg.get("workspace_dir") or cfg["trace_dir"])).expanduser().resolve()
    return _run_capsule("scoreboard", "--workspace", str(workspace_dir))


def cmd_status(cfg: Dict[str, Any]) -> Dict[str, Any]:
    scan_result = None
    if cfg.get("auto_scan_on_status", True):
        scan_result = _scan_if_needed(cfg)
        if not scan_result.get("ok"):
            return scan_result

    if cfg.get("apply_budget_on_status", False) and any(
        cfg.get(key) is not None for key in ("daily_tokens", "monthly_tokens", "daily_cost_usd", "monthly_cost_usd")
    ):
        budget_result = cmd_set_budget(cfg)
        if not budget_result.get("ok"):
            return budget_result

    report = _run_ledger(
        "report",
        "--org", str(cfg["org"]),
        "--dir", str(_expanded_trace_dir(cfg)),
        "--period", str(cfg.get("period", "today")),
    )
    audit = cmd_audit_now(cfg)
    if not report.get("ok"):
        return report
    if not audit.get("ok"):
        return audit

    recommendations = _recommendations(audit, report)
    capsule_state_payload = cmd_verify_capsule(cfg)
    scoreboard_payload = cmd_scoreboard(cfg)
    capsule_state = capsule_state_payload.get("result", capsule_state_payload)
    scoreboard = scoreboard_payload.get("result", scoreboard_payload)
    return {
        "ok": True,
        "trace_dir": str(_expanded_trace_dir(cfg)),
        "scan": scan_result,
        "report": report,
        "audit": audit,
        "capsule_state": capsule_state,
        "scoreboard": scoreboard,
        "recommendations": recommendations,
    }


def cmd_recommend(cfg: Dict[str, Any]) -> Dict[str, Any]:
    status = cmd_status(cfg)
    if not status.get("ok"):
        return status
    report = status["report"]
    audit = status["audit"]
    recommendations = status["recommendations"]
    return {
        "ok": True,
        "trace_dir": status["trace_dir"],
        "total_tokens": report.get("total_tokens", 0),
        "cost_usd": report.get("cost_usd", report.get("estimated_cost_usd", 0)),
        "estimated_cost_usd": report.get("estimated_cost_usd", 0),
        "truth": report.get("truth"),
        "issues_found": audit.get("issues_found", 0),
        "waste_percent": audit.get("waste_percent", 0),
        "capsule_state": status.get("capsule_state"),
        "scoreboard": status.get("scoreboard"),
        "recommendations": recommendations,
    }


def cmd_daily_guard(cfg: Dict[str, Any]) -> Dict[str, Any]:
    status = cmd_status(cfg)
    if not status.get("ok"):
        return status
    report = status["report"]
    audit = status["audit"]
    top_model = "unknown"
    by_model = report.get("by_model") or {}
    if by_model:
        top_model = max(by_model.items(), key=lambda item: item[1].get("total", 0))[0]
    truth = report.get("truth") or {}
    cost_truth = ((truth.get("cost") or {}).get("mode")) or "unavailable"
    cost_prefix = "$" if cost_truth == "exact" else "~$"
    message = (
        f"Token Guard: {report.get('total_tokens', 0):,} tokens, "
        f"{cost_prefix}{report.get('cost_usd', report.get('estimated_cost_usd', 0)):.4f}, "
        f"{audit.get('issues_found', 0)} issues, "
        f"{audit.get('waste_percent', 0)}% estimated waste, "
        f"top model {top_model}, "
        f"cost truth {cost_truth}."
    )
    return {
        "ok": True,
        "message": message,
        "status": status,
    }


COMMANDS = {
    "scan_now": cmd_scan_now,
    "audit_now": cmd_audit_now,
    "set_budget": cmd_set_budget,
    "build_capsule": cmd_build_capsule,
    "prime_next_run": cmd_prime_next_run,
    "verify_capsule": cmd_verify_capsule,
    "scoreboard": cmd_scoreboard,
    "status": cmd_status,
    "recommend": cmd_recommend,
    "daily_guard": cmd_daily_guard,
}


def main() -> int:
    command = os.environ.get("OPENCLAW_SKILL_COMMAND") or (sys.argv[1] if len(sys.argv) > 1 else "status")
    cfg = _load_config()
    handler = COMMANDS.get(command)
    if not handler:
        print(json.dumps({"ok": False, "error": f"Unknown command: {command}"}))
        return 1
    result = handler(cfg)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
