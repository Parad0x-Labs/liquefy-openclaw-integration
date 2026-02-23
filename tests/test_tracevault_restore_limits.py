#!/usr/bin/env python3
"""Restore output-cap safety tests."""
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from tracevault_restore import (  # type: ignore
    RestoreLimitExceeded,
    RestoreWriteLimiter,
    _tmp_restore_path,
    atomic_write_bytes_counted,
)


def test_restore_limit_default_style_trigger_cleans_tmp(tmp_path):
    target = tmp_path / "restored.bin"
    limiter = RestoreWriteLimiter(8)

    with pytest.raises(RestoreLimitExceeded, match="RESTORE_ABORTED_OUTPUT_LIMIT"):
        atomic_write_bytes_counted(target, b"0123456789", limiter, chunk_size=4)

    assert not target.exists()
    assert not _tmp_restore_path(target).exists()


def test_restore_limit_power_user_override_zero_is_unlimited(tmp_path):
    target = tmp_path / "restored.bin"
    limiter = RestoreWriteLimiter(0)
    payload = b"x" * 32

    atomic_write_bytes_counted(target, payload, limiter, chunk_size=7)

    assert target.exists()
    assert target.read_bytes() == payload
    assert limiter.total_written == len(payload)


def test_restore_limit_exact_boundary_then_next_byte_fails(tmp_path):
    target_a = tmp_path / "a.bin"
    target_b = tmp_path / "b.bin"
    limiter = RestoreWriteLimiter(10)

    atomic_write_bytes_counted(target_a, b"0123456789", limiter, chunk_size=3)
    assert target_a.read_bytes() == b"0123456789"
    assert limiter.total_written == 10

    with pytest.raises(RestoreLimitExceeded):
        atomic_write_bytes_counted(target_b, b"Z", limiter, chunk_size=1)

    assert not target_b.exists()
    assert not _tmp_restore_path(target_b).exists()
