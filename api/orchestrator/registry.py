import json
from pathlib import Path
from typing import List, Tuple
from orchestrator.contracts import EngineManifest

def load_registry(base_dir: str = "engines") -> List[Tuple[EngineManifest, Path]]:
    """
    Returns a list of (manifest, manifest_path), sorted by priority desc.
    Security rule: enterprise folder cannot register inprocess engines.
    Automatically discovers community/contrib plugins via plugin_loader.
    """
    base = Path(base_dir)
    scan_roots = [
        ("core", base / "core"),
        ("enterprise", base / "enterprise"),
    ]

    found: List[Tuple[EngineManifest, Path]] = []

    for bucket, folder in scan_roots:
        if not folder.exists():
            continue

        for manifest_path in folder.rglob("engine.json"):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                m = EngineManifest(**data)

                if bucket == "enterprise" and m.type == "inprocess":
                    raise ValueError("enterprise engines cannot be type=inprocess (Security Policy)")

                found.append((m, manifest_path))
            except Exception as e:
                print(f"[WARN] Invalid manifest at {manifest_path}: {e}")

    try:
        from orchestrator.plugin_loader import discover_community_engines, merge_registries
        api_dir = base.parent if (base.parent / "orchestrator").exists() else base.parent.parent
        community = discover_community_engines(api_dir)
        if community:
            found = merge_registries(found, community)
    except ImportError:
        pass

    found.sort(key=lambda t: t[0].priority, reverse=True)
    return found
