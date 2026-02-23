"""tests/test_router.py — Engine selection, priority, and tie-breaking."""
import pytest
from pathlib import Path
from orchestrator.contracts import EngineManifest, EngineCapabilities, SniffRule
from orchestrator.router import select_engine, _mime_matches


def _make_manifest(
    engine_id,
    priority,
    mimetypes=None,
    extensions=None,
    sniff=None,
    etype="inprocess",
):
    return EngineManifest(
        id=engine_id,
        type=etype,
        api_version="1.0",
        priority=priority,
        capabilities=EngineCapabilities(
            mimetypes=mimetypes or [],
            extensions=extensions or [],
        ),
        sniff=SniffRule(**sniff) if sniff else None,
        entrypoint="mod:Cls" if etype == "inprocess" else None,
        endpoint="http://localhost:9999" if etype == "external_service" else None,
    )


class TestMimeMatching:
    def test_exact_match(self):
        assert _mime_matches("application/json", "application/json")

    def test_wildcard_match(self):
        assert _mime_matches("image/*", "image/png")
        assert _mime_matches("image/*", "image/jpeg")

    def test_wildcard_no_match(self):
        assert not _mime_matches("image/*", "application/pdf")

    def test_empty_actual(self):
        assert not _mime_matches("image/*", "")
        assert not _mime_matches("image/*", None)


class TestSelectEngine:
    def test_extension_match(self):
        registry = [
            (_make_manifest("json-engine", 500, extensions=[".json"]), Path(".")),
            (_make_manifest("sql-engine", 500, extensions=[".sql"]), Path(".")),
        ]
        result = select_engine(registry, "data.json")
        assert result.id == "json-engine"

    def test_priority_wins(self):
        registry = [
            (_make_manifest("low", 100, extensions=[".log"]), Path(".")),
            (_make_manifest("high", 900, extensions=[".log"]), Path(".")),
        ]
        result = select_engine(registry, "server.log")
        assert result.id == "high"

    def test_tie_break_alphabetical(self):
        registry = [
            (_make_manifest("b-engine", 500, extensions=[".log"]), Path(".")),
            (_make_manifest("a-engine", 500, extensions=[".log"]), Path(".")),
        ]
        result = select_engine(registry, "server.log")
        assert result.id == "a-engine"

    def test_no_match_returns_none(self):
        registry = [
            (_make_manifest("json-only", 500, extensions=[".json"]), Path(".")),
        ]
        result = select_engine(registry, "image.bmp")
        assert result is None

    def test_mime_wildcard_match(self):
        registry = [
            (_make_manifest("media", 500, mimetypes=["image/*"]), Path(".")),
        ]
        result = select_engine(registry, "photo.png")
        assert result.id == "media"

    def test_case_insensitive_extension(self):
        registry = [
            (_make_manifest("json", 500, extensions=[".json"]), Path(".")),
        ]
        result = select_engine(registry, "DATA.JSON")
        assert result.id == "json"

    def test_extension_preferred_over_mime(self):
        registry = [
            (_make_manifest("mime-high", 900, mimetypes=["text/plain"], extensions=[".log"]), Path(".")),
            (_make_manifest("ext-low", 100, extensions=[".txt"]), Path(".")),
        ]
        result = select_engine(registry, "notes.txt")
        assert result.id == "ext-low"

    def test_sniff_needs_positive_score_to_beat_generic(self, tmp_path):
        sample = tmp_path / "notes.log"
        sample.write_text("just plain text with no http signatures\n", encoding="utf-8")
        registry = [
            (_make_manifest(
                "sniff-high",
                900,
                extensions=[".log"],
                sniff={"contains_any": ["GET /", "HTTP/1.1"]},
            ), Path(".")),
            (_make_manifest("generic", 100, extensions=[".log"]), Path(".")),
        ]
        result = select_engine(registry, str(sample))
        assert result.id == "generic"

    def test_positive_sniff_signal_wins(self, tmp_path):
        sample = tmp_path / "access.log"
        sample.write_text(
            '127.0.0.1 - - [22/Feb/2026:23:59:59 +0000] "GET /health HTTP/1.1" 200 123\n',
            encoding="utf-8",
        )
        registry = [
            (_make_manifest(
                "apache-sniff",
                500,
                extensions=[".log"],
                sniff={"contains_any": ["GET /"], "regex_any": ['"(GET|POST) /']},
            ), Path(".")),
            (_make_manifest("generic", 900, extensions=[".log"]), Path(".")),
        ]
        result = select_engine(registry, str(sample))
        assert result.id == "apache-sniff"
