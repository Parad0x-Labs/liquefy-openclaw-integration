"""tests/test_contracts.py — Manifest schema validation."""
import pytest
from orchestrator.contracts import EngineManifest, EngineCapabilities


class TestManifestValidation:
    """Verify EngineManifest Pydantic schema rejects invalid configs."""

    def test_valid_inprocess(self):
        m = EngineManifest(
            id="liquefy-json-v1",
            type="inprocess",
            api_version="1.0",
            priority=500,
            capabilities=EngineCapabilities(
                mimetypes=["application/json"],
                extensions=[".json", ".jsonl"],
            ),
            entrypoint="json.liquefy_json_v1:LiquefyJsonV1",
        )
        assert m.id == "liquefy-json-v1"
        assert m.endpoint is None
        assert m.cmd is None

    def test_valid_external_service(self):
        m = EngineManifest(
            id="media-engine",
            type="external_service",
            api_version="1.0",
            priority=100,
            capabilities=EngineCapabilities(
                mimetypes=["image/*", "video/*"],
                extensions=[".jpg", ".mp4"],
            ),
            endpoint="http://127.0.0.1:7788",
        )
        assert m.endpoint == "http://127.0.0.1:7788"
        assert m.entrypoint is None

    def test_valid_external_binary(self):
        m = EngineManifest(
            id="binary-engine",
            type="external_binary",
            api_version="1.0",
            priority=200,
            capabilities=EngineCapabilities(
                mimetypes=[],
                extensions=[".pcap"],
            ),
            cmd=["/opt/bin/compress", "--mode=fast"],
        )
        assert m.cmd == ["/opt/bin/compress", "--mode=fast"]

    def test_priority_bounds(self):
        """Priority must be 0-1000."""
        with pytest.raises(Exception):
            EngineManifest(
                id="bad",
                type="inprocess",
                api_version="1.0",
                priority=1001,
                capabilities=EngineCapabilities(mimetypes=[], extensions=[]),
                entrypoint="mod:Cls",
            )

    def test_missing_required_fields(self):
        with pytest.raises(Exception):
            EngineManifest(id="x", type="inprocess")

    def test_wildcard_mimetype_format(self):
        caps = EngineCapabilities(
            mimetypes=["image/*", "application/pdf"],
            extensions=[".pdf"],
        )
        assert "image/*" in caps.mimetypes

    def test_extension_case_preserved(self):
        caps = EngineCapabilities(mimetypes=[], extensions=[".JSON", ".Log"])
        assert ".JSON" in caps.extensions
