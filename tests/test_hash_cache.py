#!/usr/bin/env python3
from pathlib import Path
import time

import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from common_hash_cache import HashCache  # type: ignore


def test_hash_cache_record_lookup_and_persist(tmp_path):
    cache_path = tmp_path / ".liquefy" / "hash_cache.json"
    cache = HashCache(cache_path, max_entries=10)
    f = tmp_path / "a.txt"
    f.write_text("hello\n", encoding="utf-8")

    assert cache.lookup(f) is None
    cache.record(f, "abc123")
    assert cache.lookup(f) == "abc123"
    cache.save()
    assert cache_path.exists()

    cache2 = HashCache(cache_path, max_entries=10)
    assert cache2.lookup(f) == "abc123"


def test_hash_cache_invalidates_on_file_change(tmp_path):
    cache = HashCache(tmp_path / "cache.json", max_entries=10)
    f = tmp_path / "b.txt"
    f.write_text("one\n", encoding="utf-8")
    cache.record(f, "sha-one")
    assert cache.lookup(f) == "sha-one"

    time.sleep(0.001)
    f.write_text("two\n", encoding="utf-8")
    assert cache.lookup(f) is None
