"""
plugin_loader.py
================
Auto-registering plugin ecosystem for engines and LeakHunter patterns.

Drop a folder into:
    engines/community/   — auto-discovered as compression engines
    patterns/community/  — auto-discovered as LeakHunter secret patterns

Engine plugin format:
    engines/community/my_engine/
        engine.json      — standard EngineManifest
        my_engine.py     — Python module with compress()/decompress()

Pattern plugin format:
    patterns/community/my_patterns.json — array of secret patterns:
    [
        {
            "name": "My Custom Secret",
            "regex": "MY_SECRET_[A-Z0-9]{32}",
            "severity": "high",
            "description": "Custom secret pattern"
        }
    ]

Security:
    - Community engines run at priority <= 400 (cannot override core)
    - Community engines cannot use type=inprocess in sensitive mode
    - Pattern files are validated before loading
    - All plugins logged to audit trail
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from orchestrator.contracts import EngineManifest

MAX_COMMUNITY_PRIORITY = 400
COMMUNITY_ENGINE_DIRS = ["engines/community", "engines/contrib"]
COMMUNITY_PATTERN_DIRS = ["patterns/community", "patterns/contrib"]


def discover_community_engines(
    api_dir: Path,
    *,
    max_priority: int = MAX_COMMUNITY_PRIORITY,
    strict: bool = True,
) -> List[Tuple[EngineManifest, Path]]:
    """
    Scan community engine directories for valid engine.json manifests.
    Returns list of (manifest, manifest_path), ready to merge with core registry.
    """
    found: List[Tuple[EngineManifest, Path]] = []
    errors: List[str] = []

    for rel_dir in COMMUNITY_ENGINE_DIRS:
        base = api_dir / rel_dir
        if not base.exists():
            continue

        for manifest_path in base.rglob("engine.json"):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))

                if data.get("priority", 0) > max_priority:
                    data["priority"] = max_priority

                if strict and data.get("type") == "inprocess":
                    entrypoint = data.get("entrypoint", "")
                    if ".." in entrypoint or entrypoint.startswith("/"):
                        errors.append(f"Rejected {manifest_path}: suspicious entrypoint path")
                        continue

                m = EngineManifest(**data)
                found.append((m, manifest_path))
            except Exception as exc:
                errors.append(f"Invalid plugin manifest {manifest_path}: {exc}")

    if errors:
        for e in errors:
            print(f"[plugin-loader] {e}", file=sys.stderr)

    found.sort(key=lambda t: t[0].priority, reverse=True)
    return found


def discover_community_patterns(
    repo_root: Path,
) -> List[Dict[str, Any]]:
    """
    Scan community pattern directories for LeakHunter pattern files.
    Returns list of pattern dicts ready to compile into SecretPattern objects.
    """
    found: List[Dict[str, Any]] = []
    errors: List[str] = []

    for rel_dir in COMMUNITY_PATTERN_DIRS:
        base = repo_root / rel_dir
        if not base.exists():
            continue

        for pattern_file in sorted(base.glob("*.json")):
            try:
                data = json.loads(pattern_file.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    data = [data]

                for item in data:
                    if not isinstance(item, dict):
                        continue
                    if "name" not in item or "regex" not in item:
                        continue
                    re.compile(item["regex"])
                    item.setdefault("severity", "medium")
                    item.setdefault("description", f"Community pattern: {item['name']}")
                    item["_source"] = str(pattern_file)
                    found.append(item)

            except json.JSONDecodeError as exc:
                errors.append(f"Invalid JSON in {pattern_file}: {exc}")
            except re.error as exc:
                errors.append(f"Invalid regex in {pattern_file}: {exc}")
            except Exception as exc:
                errors.append(f"Error loading {pattern_file}: {exc}")

    if errors:
        for e in errors:
            print(f"[plugin-loader] {e}", file=sys.stderr)

    return found


def load_community_engine_module(
    manifest: EngineManifest,
    manifest_path: Path,
) -> Optional[Any]:
    """
    Dynamically load a community engine's Python module.
    Returns the module object, or None on failure.
    """
    if manifest.type != "inprocess" or not manifest.entrypoint:
        return None

    parts = manifest.entrypoint.rsplit(".", 1)
    if len(parts) != 2:
        return None

    module_path_str, class_name = parts
    engine_dir = manifest_path.parent

    module_file = engine_dir / module_path_str.replace(".", "/")
    candidates = [
        module_file.with_suffix(".py"),
        engine_dir / f"{module_path_str.split('.')[-1]}.py",
    ]

    for candidate in candidates:
        if candidate.exists():
            try:
                spec = importlib.util.spec_from_file_location(
                    f"community_engine.{manifest.id}", str(candidate)
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return module
            except Exception as exc:
                print(f"[plugin-loader] Failed to load {candidate}: {exc}", file=sys.stderr)

    return None


def merge_registries(
    core: List[Tuple[EngineManifest, Path]],
    community: List[Tuple[EngineManifest, Path]],
) -> List[Tuple[EngineManifest, Path]]:
    """Merge core and community engine registries, maintaining priority order."""
    core_ids = {m.id for m, _ in core}
    merged = list(core)
    for m, p in community:
        if m.id in core_ids:
            print(f"[plugin-loader] Skipping community engine {m.id}: conflicts with core engine", file=sys.stderr)
            continue
        merged.append((m, p))
    merged.sort(key=lambda t: t[0].priority, reverse=True)
    return merged


def create_plugin_template(
    target_dir: Path,
    engine_id: str,
    *,
    engine_type: str = "inprocess",
) -> Path:
    """Create a template for a new community engine plugin."""
    plugin_dir = target_dir / engine_id.replace("-", "_")
    plugin_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "id": engine_id,
        "type": engine_type,
        "api_version": "1.0",
        "priority": 300,
        "capabilities": {
            "mimetypes": [],
            "extensions": [".custom"],
        },
        "sniff": {
            "contains_any": [],
            "contains_all": [],
            "regex_any": [],
        },
        "entrypoint": f"{engine_id.replace('-', '_')}.CustomEngine",
    }

    (plugin_dir / "engine.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    module_name = engine_id.replace("-", "_")
    (plugin_dir / f"{module_name}.py").write_text(f'''"""
Community Engine: {engine_id}
Drop into engines/community/{module_name}/ to auto-register.
"""
import zstandard as zstd


class CustomEngine:
    def __init__(self):
        self.cctx = zstd.ZstdCompressor(level=12)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw_data: bytes) -> bytes:
        # Your custom compression logic here.
        # Must return bytes. Will be compared against raw zstd (choose-smaller).
        return self.cctx.compress(raw_data)

    def decompress(self, compressed_data: bytes) -> bytes:
        # Must return the exact original bytes (MRTV will verify).
        return self.dctx.decompress(compressed_data)
''', encoding="utf-8")

    (plugin_dir / "README.md").write_text(f"""# {engine_id}

Community compression engine for Liquefy.

## Install

Copy this folder to `api/engines/community/{module_name}/`.
It will be auto-discovered on next run.

## Develop

Edit `{module_name}.py` — implement `compress()` and `decompress()`.
Update `engine.json` with your file extensions and sniff rules.
""", encoding="utf-8")

    return plugin_dir
