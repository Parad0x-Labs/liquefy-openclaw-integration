#!/usr/bin/env python3
"""Shared path safety policy for TraceVault and OpenClaw wrappers."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

DEFAULT_INCLUDE_SECRETS_PHRASE = "I UNDERSTAND THIS MAY LEAK SECRETS"

CATEGORY_ENV_FILE = "ENV_FILE"
CATEGORY_PRIVATE_KEY = "PRIVATE_KEY_FILE"
CATEGORY_WALLET = "WALLET_OR_SEED"
CATEGORY_OPENCLAW_CONFIG = "OPENCLAW_CONFIG"
CATEGORY_CREDENTIAL_DIR = "CREDENTIAL_DIR"
CATEGORY_SENSITIVE_CONFIG = "SENSITIVE_CONFIG"

RISK_CATEGORIES_ALL = {
    CATEGORY_ENV_FILE,
    CATEGORY_PRIVATE_KEY,
    CATEGORY_WALLET,
    CATEGORY_OPENCLAW_CONFIG,
    CATEGORY_CREDENTIAL_DIR,
    CATEGORY_SENSITIVE_CONFIG,
}

HIGH_RISK_CATEGORIES_BALANCED = {
    CATEGORY_PRIVATE_KEY,
    CATEGORY_WALLET,
    CATEGORY_OPENCLAW_CONFIG,
    CATEGORY_CREDENTIAL_DIR,
    CATEGORY_SENSITIVE_CONFIG,
}


@dataclass
class DenyRule:
    pattern: str
    reason: str = "CUSTOM_DENY_RULE"


@dataclass
class PathPolicy:
    mode: str = "strict"
    deny_rules: List[DenyRule] = field(default_factory=list)
    allow_rules: List[str] = field(default_factory=list)
    allow_categories: Set[str] = field(default_factory=set)
    include_secrets: bool = False
    include_secrets_phrase_ok: bool = False
    include_secrets_phrase_required: str = DEFAULT_INCLUDE_SECRETS_PHRASE
    redact_output: bool = False
    source: Optional[str] = None

    def denied_categories(self) -> Set[str]:
        mode = (self.mode or "strict").strip().lower()
        if mode == "off":
            return set()
        if mode == "balanced":
            return set(HIGH_RISK_CATEGORIES_BALANCED)
        return set(RISK_CATEGORIES_ALL)

    def allows_category(self, category: Optional[str]) -> bool:
        if not category:
            return False
        if category in self.allow_categories:
            return True
        if "ALL" in self.allow_categories:
            return self.include_secrets_phrase_ok
        return False

    def risky_override_enabled_for(self, category: Optional[str]) -> bool:
        if not category:
            return False
        return self.include_secrets_phrase_ok or self.allows_category(category)

    def public_summary(self) -> Dict[str, object]:
        return {
            "mode": self.mode,
            "source": self.source,
            "include_secrets": bool(self.include_secrets),
            "include_secrets_phrase_ok": bool(self.include_secrets_phrase_ok),
            "allow_categories": sorted(self.allow_categories),
            "deny_rules_count": len(self.deny_rules),
            "allow_rules_count": len(self.allow_rules),
            "redact_output": bool(self.redact_output),
        }


def default_policy(mode: str = "strict", source: str = "default") -> PathPolicy:
    return PathPolicy(mode=mode, source=source)


def _parse_policy_file(path: Path) -> Dict:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dep
            raise SystemExit(f"POLICY_PARSE_ERROR: YAML requires PyYAML ({exc})")
        obj = yaml.safe_load(raw)
        return obj if isinstance(obj, dict) else {}
    obj = json.loads(raw)
    return obj if isinstance(obj, dict) else {}


def _normalize_deny_rules(items: Iterable[object]) -> List[DenyRule]:
    out: List[DenyRule] = []
    for item in items or []:
        if isinstance(item, str):
            out.append(DenyRule(pattern=item, reason="CUSTOM_DENY_RULE"))
            continue
        if isinstance(item, dict):
            pat = str(item.get("pattern", "")).strip()
            if not pat:
                continue
            out.append(DenyRule(pattern=pat, reason=str(item.get("reason", "CUSTOM_DENY_RULE"))))
    return out


def _normalize_allow_rules(items: Iterable[object]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        if isinstance(item, str):
            pat = item.strip()
            if pat:
                out.append(pat)
            continue
        if isinstance(item, dict):
            pat = str(item.get("pattern", "")).strip()
            if pat:
                out.append(pat)
    return out


def build_policy_from_args(args, *, source_label: str = "cli") -> PathPolicy:
    file_cfg: Dict = {}
    policy_path = getattr(args, "policy", None)
    if policy_path:
        p = Path(policy_path).expanduser().resolve()
        if not p.exists():
            raise SystemExit(f"POLICY_NOT_FOUND: {p}")
        file_cfg = _parse_policy_file(p)
        source_label = str(p)

    include_cfg = file_cfg.get("include_risky", {}) if isinstance(file_cfg.get("include_risky"), dict) else {}
    required_phrase = str(include_cfg.get("require_phrase") or DEFAULT_INCLUDE_SECRETS_PHRASE)

    file_phrase = include_cfg.get("phrase")
    cli_phrase = getattr(args, "include_secrets", None)
    phrase_value = cli_phrase if cli_phrase is not None else file_phrase
    include_enabled = bool(getattr(args, "include_secrets", None) is not None) or bool(include_cfg.get("enabled"))
    phrase_ok = bool(phrase_value and str(phrase_value) == required_phrase)

    allow_categories: Set[str] = set()
    for c in file_cfg.get("allow_categories", []) or []:
        allow_categories.add(str(c))
    for c in getattr(args, "allow_category", []) or []:
        allow_categories.add(str(c))

    if include_enabled and not phrase_ok:
        raise SystemExit(
            "OVERRIDE_PHRASE_REQUIRED: use --include-secrets "
            f"\"{required_phrase}\""
        )
    if "ALL" in allow_categories and not phrase_ok:
        raise SystemExit(
            "OVERRIDE_PHRASE_REQUIRED: --allow-category ALL requires "
            f"\"{required_phrase}\""
        )

    mode = getattr(args, "mode", None) or file_cfg.get("mode") or "strict"
    deny_rules = _normalize_deny_rules(file_cfg.get("deny", []))
    deny_rules.extend(DenyRule(pattern=pat, reason="CLI_DENY_RULE") for pat in (getattr(args, "deny", []) or []))

    allow_rules = _normalize_allow_rules(file_cfg.get("allow", []))
    allow_rules.extend([pat for pat in (getattr(args, "allow", []) or []) if pat])

    redact_output = bool(file_cfg.get("redact_output", False))

    return PathPolicy(
        mode=str(mode),
        deny_rules=deny_rules,
        allow_rules=allow_rules,
        allow_categories=allow_categories,
        include_secrets=include_enabled,
        include_secrets_phrase_ok=phrase_ok,
        include_secrets_phrase_required=required_phrase,
        redact_output=redact_output,
        source=source_label,
    )


def add_policy_cli_args(parser) -> None:
    parser.add_argument("--policy", default=None, help="Optional policy file (.json/.yaml) for path safety rules.")
    parser.add_argument(
        "--mode",
        choices=["strict", "balanced", "off"],
        default=None,
        help="Path safety mode (strict by default if not set).",
    )
    parser.add_argument("--deny", action="append", default=[], help="Add deny glob pattern (can repeat).")
    parser.add_argument("--allow", action="append", default=[], help="Add allow glob pattern (can repeat).")
    parser.add_argument(
        "--allow-category",
        action="append",
        default=[],
        choices=sorted(RISK_CATEGORIES_ALL | {"ALL"}),
        help="Allow a risky category (can repeat). 'ALL' requires include-secrets phrase.",
    )
    parser.add_argument(
        "--include-secrets",
        default=None,
        help=f"Explicit risky override phrase (exact): {DEFAULT_INCLUDE_SECRETS_PHRASE}",
    )
    parser.add_argument(
        "--print-effective-policy",
        action="store_true",
        help="Print the resolved path policy and effective rules, then exit.",
    )
    parser.add_argument(
        "--explain",
        default=None,
        metavar="PATH",
        help="Explain allow/deny decision for a path under the active policy, then exit.",
    )


def classify_risky_path(path: Path, root: Path) -> Optional[Tuple[str, str]]:
    rel = path.relative_to(root).as_posix()
    rel_lower = rel.lower()
    parts_lower = [p.lower() for p in Path(rel).parts]
    name_lower = path.name.lower()
    suffix_lower = path.suffix.lower()

    if any(p in {"credentials", "auth", "secrets"} for p in parts_lower):
        return CATEGORY_CREDENTIAL_DIR, "path_contains_credentials_or_auth_dir"

    if name_lower == "openclaw.json":
        return CATEGORY_OPENCLAW_CONFIG, "openclaw_config_file"

    if name_lower in {"auth-profiles.json", "oauth.json", "tokens"}:
        return CATEGORY_SENSITIVE_CONFIG, "sensitive_auth_config"

    if name_lower.startswith(".env") or "/.env" in rel_lower:
        return CATEGORY_ENV_FILE, "env_file"

    if any(k in name_lower for k in ("id_rsa", "id_ed25519")):
        return CATEGORY_PRIVATE_KEY, "ssh_private_key_name"

    if suffix_lower in {".key", ".pem", ".p12", ".pfx"}:
        return CATEGORY_PRIVATE_KEY, f"private_key_extension:{suffix_lower}"

    if "wallet" in name_lower or "seed" in name_lower:
        return CATEGORY_WALLET, "wallet_or_seed_name"

    return None


def _matches_any(patterns: Iterable[str], rel_path: str) -> bool:
    return any(fnmatch.fnmatch(rel_path, pat) for pat in patterns)


def _matching_allow_rule(patterns: Iterable[str], rel_path: str) -> Optional[str]:
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return pattern
    return None


def _matching_deny_rule(rules: Iterable[DenyRule], rel_path: str) -> Optional[DenyRule]:
    for rule in rules:
        if fnmatch.fnmatch(rel_path, rule.pattern):
            return rule
    return None


def evaluate_risky_policy(policy: PathPolicy, *, rel_path: str, category: Optional[str], category_reason: Optional[str]) -> Dict[str, object]:
    """Return decision metadata for risky/default deny policy evaluation."""
    allow_rule = _matching_allow_rule(policy.allow_rules, rel_path)
    allow_hit = bool(allow_rule)
    deny_hit = _matching_deny_rule(policy.deny_rules, rel_path)

    risky = bool(category)
    denied_by_mode = risky and category in policy.denied_categories()
    category_allowed = policy.allows_category(category)
    risky_override = policy.risky_override_enabled_for(category)

    if not risky:
        if allow_hit:
            return {
                "allow": True,
                "risky": False,
                "overridden": bool(deny_hit),
                "reason": "allow_rule",
                "matched_rule": {"type": "allow", "pattern": str(allow_rule)},
                "requires_override": False,
            }
        if deny_hit:
            return {
                "allow": False,
                "risky": False,
                "category": None,
                "reason": deny_hit.reason,
                "matched_rule": {"type": "deny", "pattern": deny_hit.pattern, "reason": deny_hit.reason},
                "requires_override": False,
            }
        return {"allow": True, "risky": False, "matched_rule": None, "requires_override": False}

    # Risky path
    # allow-category provides explicit per-category override; include-secrets phrase allows all risky.
    if category_allowed:
        return {
            "allow": True,
            "risky": True,
            "category": category,
            "overridden": denied_by_mode or bool(deny_hit),
            "reason": "allow_category",
            "category_reason": category_reason,
            "matched_rule": {"type": "allow_category", "category": category},
            "requires_override": False,
        }
    if allow_hit and risky_override:
        return {
            "allow": True,
            "risky": True,
            "category": category,
            "overridden": denied_by_mode or bool(deny_hit),
            "reason": "allow_rule_with_risky_override",
            "category_reason": category_reason,
            "matched_rule": {"type": "allow", "pattern": str(allow_rule)},
            "requires_override": False,
        }
    if policy.include_secrets_phrase_ok:
        return {
            "allow": True,
            "risky": True,
            "category": category,
            "overridden": denied_by_mode or bool(deny_hit),
            "reason": "include_secrets_override",
            "category_reason": category_reason,
            "matched_rule": {"type": "include_secrets"},
            "requires_override": False,
        }

    if deny_hit:
        return {
            "allow": False,
            "risky": True,
            "category": category,
            "reason": deny_hit.reason,
            "category_reason": category_reason,
            "matched_rule": {"type": "deny", "pattern": deny_hit.pattern, "reason": deny_hit.reason},
            "requires_override": True,
        }
    if denied_by_mode:
        return {
            "allow": False,
            "risky": True,
            "category": category,
            "reason": category or "RISKY_FILE",
            "category_reason": category_reason,
            "matched_rule": {"type": "mode_category", "category": category},
            "requires_override": True,
        }
    if allow_hit:
        return {
            "allow": True,
            "risky": True,
            "category": category,
            "overridden": False,
            "reason": "allow_rule",
            "category_reason": category_reason,
            "matched_rule": {"type": "allow", "pattern": str(allow_rule)},
            "requires_override": False,
        }
    return {
        "allow": True,
        "risky": True,
        "category": category,
        "overridden": False,
        "reason": "not_denied_by_mode",
        "category_reason": category_reason,
        "matched_rule": None,
        "requires_override": False,
    }


def summarize_risky_inclusions(included_risky: List[Dict]) -> Dict[str, object]:
    counts: Dict[str, int] = {}
    for row in included_risky:
        cat = str(row.get("category") or "UNKNOWN")
        counts[cat] = counts.get(cat, 0) + 1
    return {
        "risky_files_included": len(included_risky),
        "risky_categories_included": counts,
    }


def redact_risky_rows(rows: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for row in rows:
        out.append({
            "path": "<redacted>",
            "category": row.get("category"),
            "reason": row.get("reason"),
            "bytes": row.get("bytes"),
        })
    return out


def classify_risky_rel_path(rel_path: str) -> Optional[Tuple[str, str]]:
    rel_posix = rel_path.replace("\\", "/")
    if rel_posix.startswith("./"):
        rel_posix = rel_posix[2:]
    p = Path(rel_posix or ".")
    rel_lower = rel_posix.lower()
    parts_lower = [part.lower() for part in p.parts]
    name_lower = p.name.lower()
    suffix_lower = p.suffix.lower()

    if any(part in {"credentials", "auth", "secrets"} for part in parts_lower):
        return CATEGORY_CREDENTIAL_DIR, "path_contains_credentials_or_auth_dir"

    if name_lower == "openclaw.json":
        return CATEGORY_OPENCLAW_CONFIG, "openclaw_config_file"

    if name_lower in {"auth-profiles.json", "oauth.json", "tokens"}:
        return CATEGORY_SENSITIVE_CONFIG, "sensitive_auth_config"

    if name_lower.startswith(".env") or "/.env" in rel_lower:
        return CATEGORY_ENV_FILE, "env_file"

    if any(k in name_lower for k in ("id_rsa", "id_ed25519")):
        return CATEGORY_PRIVATE_KEY, "ssh_private_key_name"

    if suffix_lower in {".key", ".pem", ".p12", ".pfx"}:
        return CATEGORY_PRIVATE_KEY, f"private_key_extension:{suffix_lower}"

    if "wallet" in name_lower or "seed" in name_lower:
        return CATEGORY_WALLET, "wallet_or_seed_name"

    return None


def effective_rules_payload(policy: PathPolicy, *, preview_limit: int = 20) -> Dict[str, object]:
    deny_rows: List[Dict[str, object]] = []
    for cat in sorted(policy.denied_categories()):
        deny_rows.append({
            "type": "mode_category",
            "category": cat,
            "reason": f"mode:{policy.mode}",
        })
    for rule in policy.deny_rules:
        deny_rows.append({
            "type": "deny",
            "pattern": rule.pattern,
            "reason": rule.reason,
        })

    allow_rows: List[Dict[str, object]] = [
        {"type": "allow", "pattern": pat} for pat in policy.allow_rules
    ]
    allow_categories = sorted(policy.allow_categories)

    return {
        "deny": deny_rows,
        "allow": allow_rows,
        "allow_categories": allow_categories,
        "deny_preview": deny_rows[: max(0, preview_limit)],
        "allow_preview": allow_rows[: max(0, preview_limit)],
        "preview_limit": int(preview_limit),
        "precedence": [
            "Risky files are denied by mode/category unless include-secrets phrase or allow-category overrides apply.",
            "Custom deny rules apply to both risky and non-risky paths.",
            "Allow rules permit risky paths only when a risky override is enabled.",
            "Allow-category is more specific than allow-rule for risky paths.",
        ],
    }


def explain_policy_path(policy: PathPolicy, *, rel_path: str) -> Dict[str, object]:
    rel = rel_path.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    risky = classify_risky_rel_path(rel)
    category = risky[0] if risky else None
    category_reason = risky[1] if risky else None
    decision = evaluate_risky_policy(
        policy,
        rel_path=rel,
        category=category,
        category_reason=category_reason,
    )
    return {
        "path": rel_path,
        "normalized_path": rel,
        "decision": "ALLOW" if bool(decision.get("allow")) else "DENY",
        "reason_code": decision.get("reason"),
        "matched_rule": decision.get("matched_rule"),
        "requires_override": bool(decision.get("requires_override")),
        "risky": bool(decision.get("risky")),
        "category": decision.get("category"),
        "category_reason": decision.get("category_reason"),
    }
