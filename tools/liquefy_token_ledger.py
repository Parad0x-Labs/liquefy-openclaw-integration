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
SKIP_SCAN_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".liquefy", ".liquefy-guard", ".liquefy-tokens"}

BUILTIN_MODEL_COSTS_PER_1K = {
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-5": {"input": 0.005, "output": 0.02},
    "gpt-5-mini": {"input": 0.001, "output": 0.004},
    "o1": {"input": 0.015, "output": 0.06},
    "o1-mini": {"input": 0.003, "output": 0.012},
    "o1-pro": {"input": 0.15, "output": 0.60},
    "o3-mini": {"input": 0.0011, "output": 0.0044},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3.5-haiku": {"input": 0.0008, "output": 0.004},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-4-sonnet": {"input": 0.003, "output": 0.015},
    "claude-4-opus": {"input": 0.015, "output": 0.075},
    "claude-4.5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-4.6-opus": {"input": 0.015, "output": 0.075},
    "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
    "gemini-2.0-pro": {"input": 0.00125, "output": 0.005},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
    "gemini-1.5-flash": {"input": 0.000075, "output": 0.0003},
    "deepseek-v3": {"input": 0.00027, "output": 0.0011},
    "deepseek-r1": {"input": 0.00055, "output": 0.00219},
    "llama-3.3-70b": {"input": 0.0006, "output": 0.0006},
    "mistral-large": {"input": 0.002, "output": 0.006},
}

DEFAULT_COST = {"input": 0.002, "output": 0.006}
EXACT_COST_KEYS = ("cost_usd", "billed_cost_usd", "provider_cost_usd", "usage_cost_usd")
PROVIDER_HINTS = (
    ("openai", ("gpt-", "o1", "o3", "o4", "gpt5", "gpt-5")),
    ("anthropic", ("claude-",)),
    ("google", ("gemini-",)),
    ("deepseek", ("deepseek-",)),
    ("mistral", ("mistral-",)),
    ("meta", ("llama-",)),
)
PROVIDER_ADAPTERS = {
    "openai": {
        "env_vars": ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY"),
        "profile_tokens": ("openai", "chatgpt", "codex"),
    },
    "anthropic": {
        "env_vars": ("ANTHROPIC_API_KEY",),
        "profile_tokens": ("anthropic", "claude"),
    },
    "google": {
        "env_vars": ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"),
        "profile_tokens": ("google", "gemini"),
    },
    "openrouter": {
        "env_vars": ("OPENROUTER_API_KEY",),
        "profile_tokens": ("openrouter",),
    },
    "deepseek": {
        "env_vars": ("DEEPSEEK_API_KEY",),
        "profile_tokens": ("deepseek",),
    },
    "xai": {
        "env_vars": ("XAI_API_KEY",),
        "profile_tokens": ("xai", "grok"),
    },
}

CUSTOM_COSTS_FILE = "model_costs.json"


def _load_model_costs() -> Dict[str, Dict[str, float]]:
    """Load model costs: custom overrides file > env var > built-in table.

    Users can override by placing a model_costs.json in:
    - ~/.liquefy/tokens/model_costs.json
    - LIQUEFY_MODEL_COSTS env var pointing to a JSON file

    Format: {"model-name": {"input": 0.003, "output": 0.015}, ...}
    """
    costs = dict(BUILTIN_MODEL_COSTS_PER_1K)

    custom_paths = [
        Path.home() / ".liquefy" / "tokens" / CUSTOM_COSTS_FILE,
    ]
    env_path = os.environ.get("LIQUEFY_MODEL_COSTS")
    if env_path:
        custom_paths.insert(0, Path(env_path))

    for cp in custom_paths:
        try:
            if cp.exists():
                custom = json.loads(cp.read_text("utf-8"))
                if isinstance(custom, dict):
                    costs.update(custom)
        except (json.JSONDecodeError, OSError):
            pass

    return costs


MODEL_COSTS_PER_1K = _load_model_costs()


def _ledger_dir(base: Optional[Path] = None) -> Path:
    if base:
        return base / LEDGER_DIR_NAME
    return Path.home() / ".liquefy" / "tokens"


_unknown_models_seen: set = set()


def _is_known_model(model: str) -> bool:
    model_lower = model.lower()
    for key in MODEL_COSTS_PER_1K:
        if key in model_lower:
            return True
    return False


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    model_lower = model.lower()
    costs = DEFAULT_COST
    best_match = ""
    for key, val in MODEL_COSTS_PER_1K.items():
        if key in model_lower and len(key) > len(best_match):
            best_match = key
            costs = val
    if not best_match and model_lower != "unknown":
        _unknown_models_seen.add(model_lower)
    return (input_tokens / 1000 * costs["input"]) + (output_tokens / 1000 * costs["output"])


def _normalize_model(raw: str) -> str:
    if not raw:
        return "unknown"
    return raw.strip().lower().replace("_", "-")


def _coerce_int(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return 0
        try:
            return int(float(text))
        except ValueError:
            return 0
    return 0


def _coerce_float(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _first_token_value(payload: Dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = _coerce_int(payload.get(key))
        if value > 0:
            return value
    return 0


def _first_float_value(payload: Dict[str, Any], *keys: str) -> Optional[float]:
    for key in keys:
        value = _coerce_float(payload.get(key))
        if value is not None and value >= 0:
            return value
    return None


def _usage_candidates(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    def _append(candidate: Any) -> None:
        if isinstance(candidate, dict) and candidate not in candidates:
            candidates.append(candidate)

    for key in ("usage", "token_usage", "usage_metadata", "last_token_usage", "metrics"):
        _append(data.get(key))

    for key in ("response", "llm_output", "output", "result"):
        container = data.get(key)
        if isinstance(container, dict):
            _append(container)
            for subkey in ("usage", "token_usage", "usage_metadata", "last_token_usage", "metrics"):
                _append(container.get(subkey))

    top_level = {
        key: data.get(key)
        for key in (
            "prompt_tokens",
            "completion_tokens",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "prompt_token_count",
            "completion_token_count",
            "input_token_count",
            "output_token_count",
            "prompt_eval_count",
            "eval_count",
            "token_count",
        )
        if key in data
    }
    if top_level:
        candidates.append(top_level)

    return candidates


def _extract_model_name(data: Dict[str, Any]) -> str:
    model = data.get("model") or data.get("model_name") or data.get("provider_model")
    if isinstance(model, dict):
        model = model.get("id") or model.get("name")
    if not model:
        for key in ("response", "llm_output", "output", "result"):
            container = data.get(key)
            if isinstance(container, dict):
                model = container.get("model") or container.get("model_name")
                if isinstance(model, dict):
                    model = model.get("id") or model.get("name")
                if model:
                    break
    return _normalize_model(str(model)) if model else "unknown"


def _extract_provider_name(data: Dict[str, Any], model: str) -> str:
    provider = data.get("provider") or data.get("provider_name") or data.get("vendor")
    if isinstance(provider, dict):
        provider = provider.get("id") or provider.get("name")
    if not provider:
        for key in ("response", "llm_output", "output", "result"):
            container = data.get(key)
            if isinstance(container, dict):
                provider = container.get("provider") or container.get("provider_name") or container.get("vendor")
                if isinstance(provider, dict):
                    provider = provider.get("id") or provider.get("name")
                if provider:
                    break
    if provider:
        return str(provider).strip().lower()

    model_lower = model.lower()
    for provider_name, prefixes in PROVIDER_HINTS:
        if any(model_lower.startswith(prefix) for prefix in prefixes):
            return provider_name
    return "unknown"


def _extract_billed_cost_usd(data: Dict[str, Any]) -> Optional[float]:
    for candidate in [data, *(item for item in _usage_candidates(data) if isinstance(item, dict))]:
        exact = _first_float_value(candidate, *EXACT_COST_KEYS)
        if exact is not None:
            return exact
    for key in ("response", "llm_output", "output", "result"):
        container = data.get(key)
        if isinstance(container, dict):
            exact = _first_float_value(container, *EXACT_COST_KEYS)
            if exact is not None:
                return exact
    return None


def _extract_provider_markers(value: Any, known_tokens: Dict[str, Tuple[str, ...]], found: set) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _extract_provider_markers(item, known_tokens, found)
        return
    if isinstance(value, list):
        for item in value:
            _extract_provider_markers(item, known_tokens, found)
        return
    if isinstance(value, str):
        lower = value.strip().lower()
        for provider, tokens in known_tokens.items():
            if any(token in lower for token in tokens):
                found.add(provider)


def _workspace_profile_providers(base_dir: Optional[Path]) -> set:
    if not base_dir:
        return set()
    base_dir = Path(base_dir).resolve()
    known_tokens = {name: config["profile_tokens"] for name, config in PROVIDER_ADAPTERS.items()}
    parent_chain = [base_dir]
    for parent in base_dir.parents:
        parent_chain.append(parent)
        if len(parent_chain) >= 5:
            break
    for candidate_dir in parent_chain:
        profile_path = candidate_dir / "auth-profiles.json"
        if not profile_path.exists():
            continue
        try:
            payload = json.loads(profile_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found: set = set()
        _extract_provider_markers(payload, known_tokens, found)
        if found:
            return found
    return set()


def _provider_adapter_report(
    entries: List[Dict[str, Any]],
    budget_status: Optional[Dict[str, Any]] = None,
    base_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    providers_in_trace = Counter(e.get("provider", "unknown") or "unknown" for e in entries if e.get("provider"))
    profile_providers = _workspace_profile_providers(base_dir)
    env_providers = {
        provider
        for provider, config in PROVIDER_ADAPTERS.items()
        if any(os.environ.get(env_name) for env_name in config["env_vars"])
    }
    relevant = sorted((set(providers_in_trace) | profile_providers | env_providers) - {"unknown"})
    adapters: List[Dict[str, Any]] = []
    for provider in relevant:
        config = PROVIDER_ADAPTERS.get(provider, {"env_vars": (), "profile_tokens": ()})
        env_present = [name for name in config["env_vars"] if os.environ.get(name)]
        trace_entries = [e for e in entries if (e.get("provider") or "unknown") == provider]
        exact_entries = sum(1 for e in trace_entries if e.get("billed_cost_usd") is not None)
        estimated_entries = max(0, len(trace_entries) - exact_entries)
        if env_present and provider in profile_providers:
            auth_mode = "api_key_present+workspace_profile"
            detail = "Local API credentials and a workspace provider profile were both detected."
        elif env_present:
            auth_mode = "api_key_present"
            detail = "Local API credentials are present, but Liquefy is not querying provider billing APIs here."
        elif provider in profile_providers:
            auth_mode = "workspace_profile_present"
            detail = "The workspace declares this provider, but no local API key evidence was detected."
        else:
            auth_mode = "trace_only"
            detail = "This provider was inferred only from trace payloads."
        adapters.append({
            "provider": provider,
            "auth_mode": auth_mode,
            "env_evidence": env_present,
            "workspace_profile_present": provider in profile_providers,
            "trace_entries": len(trace_entries),
            "cost_mode": (
                "exact" if trace_entries and exact_entries == len(trace_entries)
                else "estimated" if trace_entries
                else "unavailable"
            ),
            "quota_mode": "manual" if budget_status else "unavailable",
            "detail": detail,
            "exact_cost_entries": exact_entries,
            "estimated_cost_entries": estimated_entries,
        })
    return adapters


def _extract_timestamp(data: Dict[str, Any]) -> Optional[str]:
    for key in ("timestamp", "ts", "created_at", "time", "eventTime", "createdAt"):
        value = data.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _extract_prompt_source(data: Dict[str, Any]) -> Any:
    for key in ("messages", "prompt", "input", "query", "contents"):
        value = data.get(key)
        if value not in (None, ""):
            return value
    for key in ("request", "response", "llm_output"):
        container = data.get(key)
        if isinstance(container, dict):
            for subkey in ("messages", "prompt", "input", "query", "contents"):
                value = container.get(subkey)
                if value not in (None, ""):
                    return value
    return None


def _extract_usage_from_line(data: Dict) -> Optional[Dict]:
    """Extract token usage from a single JSON object (best-effort, multi-format)."""
    input_t = 0
    output_t = 0
    total_t = 0
    for usage in _usage_candidates(data):
        input_t = _first_token_value(
            usage,
            "prompt_tokens",
            "input_tokens",
            "prompt_token_count",
            "input_token_count",
            "prompt_eval_count",
        )
        output_t = _first_token_value(
            usage,
            "completion_tokens",
            "output_tokens",
            "completion_token_count",
            "output_token_count",
            "eval_count",
        )
        total_t = _first_token_value(
            usage,
            "total_tokens",
            "total_token_count",
            "token_count",
        )
        if total_t == 0 and (input_t > 0 or output_t > 0):
            total_t = input_t + output_t
        if total_t > 0:
            break

    if total_t == 0:
        return None

    model = _extract_model_name(data)
    provider = _extract_provider_name(data, model)
    ts = _extract_timestamp(data)
    billed_cost_usd = _extract_billed_cost_usd(data)

    prompt_hash = None
    messages = _extract_prompt_source(data)
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
        "model": model,
        "provider": provider,
        "timestamp": str(ts) if ts else None,
        "prompt_hash": prompt_hash,
        "billed_cost_usd": round(float(billed_cost_usd), 6) if billed_cost_usd is not None else None,
    }


def _summarize_truth(
    entries: List[Dict[str, Any]],
    budget_status: Optional[Dict[str, Any]] = None,
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    providers = Counter(e.get("provider", "unknown") or "unknown" for e in entries)
    provider_list = sorted(name for name in providers if name)
    dominant_provider = "unknown"
    if len(provider_list) == 1:
        dominant_provider = provider_list[0]
    elif len(provider_list) > 1:
        dominant_provider = "mixed"

    exact_cost_entries = [e for e in entries if e.get("billed_cost_usd") is not None]
    exact_cost_total = sum(float(e.get("billed_cost_usd") or 0.0) for e in exact_cost_entries)
    estimated_only_total = sum(
        _estimate_cost(e.get("model", "unknown"), e.get("input_tokens", 0), e.get("output_tokens", 0))
        for e in entries
        if e.get("billed_cost_usd") is None
    )
    unknown_models = sorted({e.get("model", "unknown") for e in entries if not _is_known_model(e.get("model", "unknown")) and e.get("model", "unknown") != "unknown"})

    if not entries:
        cost_truth = {
            "mode": "unavailable",
            "source": "no_entries",
            "detail": "No token entries were available, so billing truth cannot be established.",
            "usd": 0.0,
            "exact_usd": 0.0,
            "estimated_usd": 0.0,
        }
    elif len(exact_cost_entries) == len(entries):
        cost_truth = {
            "mode": "exact",
            "source": "trace_billed_cost",
            "detail": "Every entry carried an explicit billed cost in the trace payload.",
            "usd": round(exact_cost_total, 4),
            "exact_usd": round(exact_cost_total, 4),
            "estimated_usd": round(estimated_only_total, 4),
            "exact_entries": len(exact_cost_entries),
            "estimated_entries": 0,
        }
    else:
        detail = "Cost is derived from the static model rate table."
        source = "model_rate_table"
        if exact_cost_entries:
            detail = "Some entries carried billed cost; missing entries were filled with model-table estimates."
            source = "mixed_trace_and_model_rate_table"
        if unknown_models:
            detail += " Unknown models are using default fallback rates."
        cost_truth = {
            "mode": "estimated",
            "source": source,
            "detail": detail,
            "usd": round(exact_cost_total + estimated_only_total, 4),
            "exact_usd": round(exact_cost_total, 4),
            "estimated_usd": round(estimated_only_total, 4),
            "exact_entries": len(exact_cost_entries),
            "estimated_entries": len(entries) - len(exact_cost_entries),
            "unknown_model_count": len(unknown_models),
        }

    quota_truth = {
        "mode": "manual" if budget_status else "unavailable",
        "source": "local_budget_file" if budget_status else "none",
        "detail": (
            "Budget/quota numbers come from the local Liquefy budget file, not from provider APIs."
            if budget_status
            else "Provider subscription or quota state is not inferred from token math."
        ),
    }

    token_truth = {
        "mode": "exact" if entries else "unavailable",
        "source": "trace_usage_fields" if entries else "none",
        "detail": (
            "Token counts come directly from usage fields found in local traces."
            if entries
            else "No usage fields were found in local traces."
        ),
    }

    return {
        "provider_family": dominant_provider,
        "providers_seen": provider_list,
        "provider_adapters": _provider_adapter_report(entries, budget_status=budget_status, base_dir=base_dir),
        "token_usage": token_truth,
        "cost": cost_truth,
        "quota": quota_truth,
    }


def _build_entry_fingerprint(usage: Dict[str, Any], source_path: str, source_index: int) -> str:
    payload = {
        "source_path": source_path,
        "source_index": int(source_index),
        "timestamp": usage.get("timestamp"),
        "model": usage.get("model", "unknown"),
        "provider": usage.get("provider", "unknown"),
        "input_tokens": int(usage.get("input_tokens", 0)),
        "output_tokens": int(usage.get("output_tokens", 0)),
        "total_tokens": int(usage.get("total_tokens", 0)),
        "prompt_hash": usage.get("prompt_hash"),
        "billed_cost_usd": usage.get("billed_cost_usd"),
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _existing_ledger_fingerprints(ledger_path: Path) -> set:
    fingerprints = set()
    if not ledger_path.exists():
        return fingerprints
    try:
        with ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fingerprint = payload.get("entry_fingerprint")
                if isinstance(fingerprint, str) and fingerprint:
                    fingerprints.add(fingerprint)
    except OSError:
        pass
    return fingerprints


def _dedupe_ledger_entries(entries: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    ignored = 0
    for entry in entries:
        fingerprint = entry.get("entry_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            if fingerprint in seen:
                ignored += 1
                continue
            seen.add(fingerprint)
        deduped.append(entry)
    return deduped, ignored


def _scan_file(fpath: Path, base_dir: Optional[Path] = None) -> List[Dict]:
    """Scan a single file for token usage entries."""
    entries = []
    source_path = str(fpath)
    if base_dir is not None:
        try:
            source_path = str(fpath.resolve().relative_to(base_dir.resolve()))
        except Exception:
            source_path = str(fpath.name)
    try:
        with fpath.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        usage = _extract_usage_from_line(data)
                        if usage:
                            usage["source_file"] = str(fpath.name)
                            usage["source_path"] = source_path
                            usage["source_index"] = line_no
                            usage["entry_fingerprint"] = _build_entry_fingerprint(usage, source_path, line_no)
                            entries.append(usage)
                except json.JSONDecodeError:
                    continue
    except (OSError, UnicodeDecodeError):
        pass

    if not entries and fpath.suffix == ".json":
        try:
            raw = json.loads(fpath.read_text("utf-8", errors="replace"))
            items = raw if isinstance(raw, list) else [raw]
            for item_index, item in enumerate(items, start=1):
                if isinstance(item, dict):
                    usage = _extract_usage_from_line(item)
                    if usage:
                        usage["source_file"] = str(fpath.name)
                        usage["source_path"] = source_path
                        usage["source_index"] = item_index
                        usage["entry_fingerprint"] = _build_entry_fingerprint(usage, source_path, item_index)
                        entries.append(usage)
        except (json.JSONDecodeError, OSError):
            pass

    return entries


def _scan_directory(target_dir: Path) -> List[Dict]:
    """Scan a directory tree for token usage in log/trace files."""
    all_entries = []
    scan_extensions = {".jsonl", ".json", ".log", ".ndjson"}

    for root, dirs, fnames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
        for fname in fnames:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in scan_extensions:
                entries = _scan_file(fpath, base_dir=target_dir)
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
    existing_fingerprints = _existing_ledger_fingerprints(ledger_path)
    written_entries = 0
    skipped_duplicates = 0
    scanned_at = datetime.now(timezone.utc).isoformat()
    with ledger_path.open("a", encoding="utf-8") as f:
        for e in entries:
            fingerprint = e.get("entry_fingerprint")
            if isinstance(fingerprint, str) and fingerprint:
                if fingerprint in existing_fingerprints:
                    skipped_duplicates += 1
                    continue
                existing_fingerprints.add(fingerprint)
            record = dict(e)
            record["scanned_at"] = scanned_at
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
            written_entries += 1

    _audit_log("token_ledger.scan", entries=len(entries), total_tokens=total_tokens,
               estimated_cost=round(total_cost, 4))

    unknown = sorted(_unknown_models_seen)
    _unknown_models_seen.clear()
    truth = _summarize_truth(entries, base_dir=target_dir)

    result = {
        "ok": True,
        "experimental": True,
        "entries": len(entries),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_tokens,
        "estimated_cost_usd": round(total_cost, 4),
        "cost_usd": truth["cost"]["usd"],
        "by_model": {k: {**v, "cost": round(v["cost"], 4)} for k, v in by_model.items()},
        "ledger_file": str(ledger_path),
        "new_ledger_entries": written_entries,
        "duplicate_entries_skipped": skipped_duplicates,
        "unknown_models": unknown,
        "truth": truth,
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
        print(f"    Cost shown:      ${result['cost_usd']:.4f}")
        print(f"    Est. cost only:  ${total_cost:.4f}")
        print(f"    Cost truth:      {truth['cost']['mode']} ({truth['cost']['source']})")
        print(f"    Quota truth:     {truth['quota']['mode']} ({truth['quota']['source']})")
        print(f"    Ledger writes:   {written_entries} new, {skipped_duplicates} duplicate")
        print()
        print(f"    By model:")
        for model, stats in sorted(by_model.items(), key=lambda x: -x[1]["total"]):
            print(f"      {model}: {stats['total']:,} tokens, {stats['calls']} calls, ~${stats['cost']:.4f}")
        if unknown:
            print()
            print(f"    WARNING: {len(unknown)} unknown model(s) using default cost estimates:")
            for m in unknown:
                print(f"      → {m}")
            print(f"    Update costs: python tools/liquefy_token_ledger.py models --add '{unknown[0]}:0.003:0.015'")
        print()
        print(f"    Note: {truth['cost']['detail']}")

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
    all_entries, duplicate_ledger_entries = _dedupe_ledger_entries(all_entries)

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

    truth = _summarize_truth(entries, budget_status=budget_status, base_dir=Path(args.dir).resolve() if args.dir else None)
    result = {
        "ok": True,
        "experimental": True,
        "period": period,
        "entries": len(entries),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_tokens,
        "estimated_cost_usd": round(total_cost, 4),
        "cost_usd": truth["cost"]["usd"],
        "by_model": {k: {**v, "cost": round(v["cost"], 4)} for k, v in by_model.items()},
        "budget": budget_status,
        "duplicate_ledger_entries_ignored": duplicate_ledger_entries,
        "truth": truth,
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
        print(f"    Cost shown:      ${result['cost_usd']:.4f}")
        print(f"    Est. cost only:  ${total_cost:.4f}")
        print(f"    Cost truth:      {result['truth']['cost']['mode']} ({result['truth']['cost']['source']})")
        print(f"    Quota truth:     {result['truth']['quota']['mode']} ({result['truth']['quota']['source']})")
        if duplicate_ledger_entries:
            print(f"    Ledger dedupe:   ignored {duplicate_ledger_entries} duplicate entry records")
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
        print(f"    Note: {result['truth']['cost']['detail']}")

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

    models_used = sorted({e["model"] for e in entries if e["model"] != "unknown"})
    if len(models_used) > 1:
        by_source = defaultdict(set)
        for e in entries:
            if e.get("source_file"):
                by_source[e["source_file"]].add(e["model"])
        switches = {src: sorted(models) for src, models in by_source.items() if len(models) > 1}
        if switches:
            for src, models in switches.items():
                issues.append({
                    "type": "model_switch",
                    "severity": "info",
                    "source": src,
                    "models": models,
                    "message": f"Model switch in {src}: {' → '.join(models)} — verify intentional",
                })

    for e in entries:
        if not _is_known_model(e["model"]) and e["model"] != "unknown":
            _unknown_models_seen.add(e["model"])
    unknown_in_audit = sorted(_unknown_models_seen)
    _unknown_models_seen.clear()
    for m in unknown_in_audit:
        issues.append({
            "type": "unknown_model",
            "severity": "warning",
            "model": m,
            "message": f"Unknown model '{m}' — cost estimate uses default rates. Run: token-models --add '{m}:INPUT:OUTPUT'",
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
        "models_used": models_used,
        "unknown_models": unknown_in_audit,
        "issues": issues,
        "truth": _summarize_truth(entries, base_dir=target_dir),
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
        print(f"    Cost truth: {result['truth']['cost']['mode']} ({result['truth']['cost']['source']})")
        print(f"    Quota truth: {result['truth']['quota']['mode']} ({result['truth']['quota']['source']})")
        print(f"    Note: {result['truth']['cost']['detail']}")

    return 0


def cmd_models(args: argparse.Namespace) -> int:
    """List known models and their costs, or update the custom cost table."""
    costs = _load_model_costs()
    custom_path = Path.home() / ".liquefy" / "tokens" / CUSTOM_COSTS_FILE
    has_custom = custom_path.exists()

    if args.add:
        parts = args.add.split(":")
        if len(parts) != 3:
            print("ERROR: Format is MODEL:INPUT_PER_1K:OUTPUT_PER_1K  (e.g. gpt-5:0.005:0.02)")
            return 1
        model_name, inp, out = parts[0].strip().lower(), float(parts[1]), float(parts[2])
        custom = {}
        if custom_path.exists():
            custom = json.loads(custom_path.read_text("utf-8"))
        custom[model_name] = {"input": inp, "output": out}
        custom_path.parent.mkdir(parents=True, exist_ok=True)
        custom_path.write_text(json.dumps(custom, indent=2), encoding="utf-8")

        global MODEL_COSTS_PER_1K
        MODEL_COSTS_PER_1K = _load_model_costs()

        if args.json:
            print(json.dumps({"ok": True, "added": model_name, "input": inp, "output": out}))
        else:
            print(f"  Added/updated: {model_name} (${inp}/1K in, ${out}/1K out)")
            print(f"  Saved to: {custom_path}")
        return 0

    result = {
        "ok": True,
        "builtin_models": len(BUILTIN_MODEL_COSTS_PER_1K),
        "total_models": len(costs),
        "has_custom_overrides": has_custom,
        "custom_path": str(custom_path),
        "models": {k: v for k, v in sorted(costs.items())},
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Token Ledger — Model Costs")
        print(f"    Built-in:  {len(BUILTIN_MODEL_COSTS_PER_1K)} models")
        print(f"    Custom:    {custom_path}")
        if has_custom:
            custom = json.loads(custom_path.read_text("utf-8"))
            print(f"    Overrides: {len(custom)} models")
        print()
        for model, c in sorted(costs.items()):
            print(f"    {model:<28s} ${c['input']:.6f}/1K in   ${c['output']:.6f}/1K out")
        print()
        print(f"  To add/update a model:")
        print(f"    python tools/liquefy_token_ledger.py models --add 'gpt-6:0.01:0.03'")
        print(f"  Or edit: {custom_path}")

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

    p_models = sub.add_parser("models", help="List/update model cost table")
    p_models.add_argument("--add", help="Add model: MODEL:INPUT_PER_1K:OUTPUT_PER_1K")
    p_models.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {
        "scan": cmd_scan, "budget": cmd_budget,
        "report": cmd_report, "audit": cmd_audit,
        "models": cmd_models,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
