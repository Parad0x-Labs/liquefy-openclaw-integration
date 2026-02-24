#!/usr/bin/env python3
"""
Shared zstd compressor factory for Liquefy runtime engines.

Centralizes threading/content-size defaults so engine-vs-benchmark comparisons
aren't skewed by inconsistent compressor settings.
"""

from __future__ import annotations

import math
import os
from typing import Optional

import zstandard as zstd


def _adaptive_window_log(source_size: Optional[int]) -> int:
    """Choose a conservative adaptive window log (20..28)."""
    if not source_size or source_size <= 0:
        return 25
    # Use next power-of-two-ish bound for source size, clamped.
    wl = int(math.ceil(math.log2(max(1, int(source_size)))))
    return max(20, min(28, wl))


def make_cctx(
    *,
    level: int = 19,
    threads: Optional[int] = -1,
    write_content_size: bool = True,
    write_checksum: bool = False,
    write_dict_id: bool = False,
    text_like: bool = False,
    enable_ldm: Optional[bool] = None,
    window_log: Optional[int] = None,
    source_size: Optional[int] = None,
):
    """
    Build a zstd compressor with consistent defaults.

    - `threads=-1` means "all cores" and is the baseline parity default.
    - Text-like streams at higher levels use a conservative LDM/window_log setup.
    """
    eff_threads = -1 if threads in (None, 0) else int(threads)
    disable_ldm = os.getenv("LIQUEFY_DISABLE_LDM", "").strip() == "1"

    want_ldm = False
    if enable_ldm is not None:
        want_ldm = bool(enable_ldm)
    elif text_like and int(level) >= 9:
        want_ldm = True
    if disable_ldm:
        want_ldm = False

    wl = int(window_log) if window_log is not None else _adaptive_window_log(source_size)

    try:
        if want_ldm or window_log is not None:
            params = zstd.ZstdCompressionParameters.from_level(
                int(level),
                window_log=wl,
                enable_ldm=want_ldm,
            )
            return zstd.ZstdCompressor(
                level=int(level),
                compression_params=params,
                threads=eff_threads,
                write_content_size=write_content_size,
                write_checksum=write_checksum,
                write_dict_id=write_dict_id,
            )
    except Exception:
        # Best-effort tuning only; fall through to a plain compressor.
        pass

    return zstd.ZstdCompressor(
        level=int(level),
        threads=eff_threads,
        write_content_size=write_content_size,
        write_checksum=write_checksum,
        write_dict_id=write_dict_id,
    )
