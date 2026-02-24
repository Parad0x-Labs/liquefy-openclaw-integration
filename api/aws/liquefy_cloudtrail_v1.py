#!/usr/bin/env python3
"""
NULL_Aws_CloudTrail_Entropy_Focused - [NULL ENTROPY v1 - LOSSLESS]
==================================================================
TARGET: AWS CloudTrail Logs (.json or .json.gz).
TECH:   Zstd LDM + Adaptive Search Index.
STATUS: 100% Lossless, Searchable.
"""

import time
import re
import io
import zstandard as zstd
import sys
import struct
import json
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex, ZSTD_MAGIC

PROTOCOL_ID = b'CTL\x01'

class LiquefyCloudTrailV1:
    def __init__(self, level=19):
        self.level = level
        self.raw_cctx = make_cctx(
            level=level,
            text_like=True,
            write_content_size=False,
            write_checksum=False,
            write_dict_id=False,
        )
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        if not raw: return b""

        # Fast path for highly repetitive streams.
        raw_candidate = self.raw_cctx.compress(raw)
        if len(raw_candidate) * 4 < len(raw):
            return raw_candidate

        # 1. Search Index (Extract common fields)
        tokens = set()
        # Find "eventTime":"...", "eventName":"...", etc.
        for m in re.finditer(rb'"(eventTime|eventName|eventSource|sourceIPAddress|userAgent)":"(.*?)"', raw[:200000]):
            tokens.add(m.group(2))

        idx = AdaptiveSearchIndex(len(tokens))
        for t in tokens: idx.add(t)
        idx_bytes = bytes(idx)

        # 2. Lossless Zstd with LDM.
        # Use from_level(...) so configured level is preserved.
        try:
            cctx = make_cctx(
                level=self.level,
                text_like=True,
                enable_ldm=True,
                window_log=22,
                write_content_size=False,
                write_checksum=False,
                write_dict_id=False,
            )
        except:
            cctx = self.raw_cctx

        c_raw = cctx.compress(raw)
        indexed_candidate = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + c_raw
        return raw_candidate if len(raw_candidate) <= len(indexed_candidate) else indexed_candidate

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        p = 4
        idx_len, p = unpack_varint_buf(blob, p); p += idx_len
        return self._zstd_decompress(blob[p:])

    def grep(self, blob: bytes, query: str):
        if blob.startswith(ZSTD_MAGIC):
            data = self._zstd_decompress(blob)
            q_bytes = query.encode("utf-8")
            print(f"Found {data.count(q_bytes)} matches for '{query}'")
            return
        if not blob.startswith(PROTOCOL_ID): return
        p = 4
        idx_len, p = unpack_varint_buf(blob, p)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, p)
        q_bytes = query.encode('utf-8')
        if not idx.check(q_bytes):
            print(f"Index: '{query}' NOT FOUND"); return
        data = self.decompress(blob)
        print(f"Found {data.count(q_bytes)} matches for '{query}'")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: [compress|decompress] <in> <out>"); sys.exit(1)
    codec = LiquefyCloudTrailV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(d))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
