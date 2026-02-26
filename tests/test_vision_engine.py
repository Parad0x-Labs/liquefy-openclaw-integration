"""Tests for LiquefyVisionV1 — perceptual dedup engine."""
from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "api"))

from vision.liquefy_vision_v1 import LiquefyVisionV1, PROTOCOL_ID, VERSION


@pytest.fixture
def engine():
    return LiquefyVisionV1(level=3)


def _make_png_like(width: int = 8, height: int = 8, fill: int = 128) -> bytes:
    """Create a minimal valid-ish raw payload (not a real PNG, just test bytes)."""
    return bytes([fill] * (width * height * 3))


class TestSingleCompress:
    def test_roundtrip(self, engine):
        raw = _make_png_like(fill=200)
        compressed = engine.compress(raw)
        assert compressed[:4] == PROTOCOL_ID
        restored = engine.decompress(compressed)
        assert restored == raw

    def test_container_header(self, engine):
        raw = _make_png_like()
        compressed = engine.compress(raw)
        assert compressed[4] == VERSION
        manifest_len = struct.unpack(">I", compressed[5:9])[0]
        manifest = json.loads(compressed[9 : 9 + manifest_len])
        assert manifest["version"] == VERSION
        assert len(manifest["files"]) == 1
        assert manifest["stats"]["total_files"] == 1


class TestBatchCompress:
    def test_exact_dedup(self, engine):
        img = _make_png_like(fill=100)
        images = [
            ("shot_001.png", img),
            ("shot_002.png", img),
            ("shot_003.png", img),
        ]
        packed = engine.compress_batch(images)
        assert packed[:4] == PROTOCOL_ID

        offset = 5
        manifest_len = struct.unpack(">I", packed[offset : offset + 4])[0]
        offset += 4
        manifest = json.loads(packed[offset : offset + manifest_len])

        assert manifest["stats"]["total_files"] == 3
        assert manifest["stats"]["unique_files"] == 1
        assert manifest["stats"]["dedup_files"] == 2

    def test_different_images_stored(self, engine):
        images = [
            ("a.png", _make_png_like(fill=10)),
            ("b.png", _make_png_like(fill=200)),
            ("c.png", _make_png_like(fill=50)),
        ]
        packed = engine.compress_batch(images)
        offset = 5
        manifest_len = struct.unpack(">I", packed[offset : offset + 4])[0]
        offset += 4
        manifest = json.loads(packed[offset : offset + manifest_len])
        assert manifest["stats"]["unique_files"] == 3
        assert manifest["stats"]["dedup_files"] == 0

    def test_batch_roundtrip(self, engine):
        images = [
            ("a.png", _make_png_like(fill=10)),
            ("b.png", _make_png_like(fill=10)),
            ("c.png", _make_png_like(fill=200)),
        ]
        packed = engine.compress_batch(images)
        restored = engine.decompress_batch(packed)
        restored_dict = {name: data for name, data in restored}
        assert restored_dict["a.png"] == _make_png_like(fill=10)
        assert restored_dict["b.png"] == _make_png_like(fill=10)
        assert restored_dict["c.png"] == _make_png_like(fill=200)


class TestStats:
    def test_stats_from_batch(self, engine):
        img = _make_png_like(fill=42)
        packed = engine.compress_batch([("x.png", img), ("y.png", img)])
        stats = engine.stats(packed)
        assert stats["total_files"] == 2
        assert stats["unique_files"] == 1
        assert "ratio" in stats

    def test_invalid_container(self, engine):
        stats = engine.stats(b"not a vsnx container")
        assert "error" in stats
