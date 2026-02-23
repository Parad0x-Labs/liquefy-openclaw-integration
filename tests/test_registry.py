"""tests/test_registry.py — Manifest discovery and security enforcement."""
import json
import tempfile
import pytest
from pathlib import Path
from orchestrator.registry import load_registry


def _write_manifest(base_dir, category, name, manifest_dict):
    """Helper: write an engine.json to engines/{category}/{name}/engine.json."""
    d = Path(base_dir) / "engines" / category / name
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "engine.json", "w") as f:
        json.dump(manifest_dict, f)
    return d


class TestRegistryDiscovery:
    def test_loads_valid_core_manifest(self, tmp_path):
        _write_manifest(tmp_path, "core", "json-engine", {
            "id": "json-engine",
            "type": "inprocess",
            "api_version": "1.0",
            "priority": 500,
            "capabilities": {"mimetypes": ["application/json"], "extensions": [".json"]},
            "entrypoint": "json.liquefy_json_v1:LiquefyJsonV1",
        })
        registry = load_registry(str(tmp_path / "engines"))
        assert len(registry) == 1
        assert registry[0][0].id == "json-engine"

    def test_skips_invalid_manifest(self, tmp_path):
        d = tmp_path / "engines" / "core" / "broken"
        d.mkdir(parents=True)
        (d / "engine.json").write_text("{bad json")
        registry = load_registry(str(tmp_path / "engines"))
        assert len(registry) == 0

    def test_enterprise_inprocess_rejected(self, tmp_path):
        """Hard security rule: enterprise engines MUST NOT use type=inprocess."""
        _write_manifest(tmp_path, "enterprise", "malicious", {
            "id": "malicious",
            "type": "inprocess",
            "api_version": "1.0",
            "priority": 999,
            "capabilities": {"mimetypes": [], "extensions": [".pwn"]},
            "entrypoint": "evil:Payload",
        })
        registry = load_registry(str(tmp_path / "engines"))
        assert len(registry) == 0

    def test_enterprise_external_service_allowed(self, tmp_path):
        _write_manifest(tmp_path, "enterprise", "media-svc", {
            "id": "media-svc",
            "type": "external_service",
            "api_version": "1.0",
            "priority": 100,
            "capabilities": {"mimetypes": ["image/*"], "extensions": [".jpg"]},
            "endpoint": "http://127.0.0.1:7788",
        })
        registry = load_registry(str(tmp_path / "engines"))
        assert len(registry) == 1
        assert registry[0][0].type == "external_service"

    def test_empty_directory(self, tmp_path):
        (tmp_path / "engines" / "core").mkdir(parents=True)
        registry = load_registry(str(tmp_path / "engines"))
        assert len(registry) == 0
