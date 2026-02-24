#!/usr/bin/env python3
"""
LiquefySqlRepetitionV1 - [NULL REPETITION v1]
==================================================
TARGET: High-volume repetitive SQL (heartbeats, bulk inserts).
TECH:   Line-Level RLE + Zstd + Adaptive Search Index.
SPEED:  200-500 MB/s on repetitive data.
"""

import time
import zstandard as zstd
import sys
import os
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

PROTOCOL_ID = b'SQR\x01'

class LiquefySqlRepetitionV1:
    def __init__(self, level=3): # Default to level 3 for SPEED
        self.cctx = make_cctx(level=level, text_like=True)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        lines = raw.splitlines(keepends=True)
        if not lines: return b""

        unique_tokens = set()
        rle_lines = []
        last_line = lines[0]; count = 0
        for line in lines:
            if line == last_line: count += 1
            else:
                rle_lines.append((last_line, count))
                if len(last_line) < 512: unique_tokens.add(last_line.strip())
                last_line = line; count = 1
        rle_lines.append((last_line, count))

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        stream = bytearray()
        stream.extend(pack_varint(len(rle_lines)))
        for line, c in rle_lines:
            stream.extend(pack_varint(len(line))); stream.extend(line)
            stream.extend(pack_varint(c))

        custom = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + self.cctx.compress(stream)
        raw_zstd = self.cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return self.dctx.decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4; l_idx, pos = unpack_varint_buf(blob, pos); pos += l_idx
        stream = self.dctx.decompress(blob[pos:])
        p = 0; out = bytearray()
        num_blocks, p = unpack_varint_buf(stream, p)
        for _ in range(num_blocks):
            llen, p = unpack_varint_buf(stream, p); line = stream[p:p+llen]; p += llen
            count, p = unpack_varint_buf(stream, p)
            for _ in range(count): out.extend(line)
        return bytes(out)

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(1)
    codec = LiquefySqlRepetitionV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        res = codec.compress(d); print(f"Speed Ratio: {len(d)/len(res):.2f}x")
        with open(sys.argv[3], "wb") as f: f.write(res)
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
