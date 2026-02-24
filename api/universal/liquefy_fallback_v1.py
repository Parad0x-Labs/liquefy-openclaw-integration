#!/usr/bin/env python3
"""
NULL_Universal_Repetition_Focused - [NULL REPETITION v1 - GLOBAL DEDUP]
======================================================================
TARGET: Any text file with repeating lines (Global or Local).
TECH:   Global Line Deduplication + RLE + Zstd LDM.
STATUS: 100% Lossless, High Ratio on repetitive logs.
"""

import time
import zstandard as zstd
import sys
import struct
import json
from collections import defaultdict
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

PROTOCOL_ID = b'URLE'
VERSION = 1

class LiquefyFallbackV1:
    def __init__(self, level=9):
        self.level = level

    def compress(self, raw: bytes) -> bytes:
        if not raw: return PROTOCOL_ID + pack_varint(0)

        lines = raw.split(b"\n")
        unique_lines = []
        line_to_id = {}
        line_stream = []
        unique_tokens = set()

        # 1. Global Line Deduplication
        for line in lines:
            if line not in line_to_id:
                line_to_id[line] = len(unique_lines)
                unique_lines.append(line)
                # Sample tokens for search
                for tok in line.split()[:5]:
                    if 4 < len(tok) < 64: unique_tokens.add(tok.strip(b'"[]{},'))
            line_stream.append(line_to_id[line])

        # 2. Search Index
        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        # 3. Pack Payload
        # We use RLE on the line IDs
        rle_stream = []
        if line_stream:
            last = line_stream[0]; count = 0
            for lid in line_stream:
                if lid == last: count += 1
                else:
                    rle_stream.append((last, count))
                    last = lid; count = 1
            rle_stream.append((last, count))

        cctx = make_cctx(level=self.level, text_like=True)

        # Dictionary of unique lines
        dict_blob = bytearray()
        dict_blob.extend(pack_varint(len(unique_lines)))
        for l in unique_lines:
            dict_blob.extend(pack_varint(len(l)) + l)

        # RLE stream
        rle_blob = bytearray()
        rle_blob.extend(pack_varint(len(rle_stream)))
        for lid, count in rle_stream:
            rle_blob.extend(pack_varint(lid) + pack_varint(count))

        c_payload = cctx.compress(dict_blob + rle_blob)

        custom = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + c_payload
        raw_zstd = cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return zstd.ZstdDecompressor().decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = len(PROTOCOL_ID)
        idx_len, pos = unpack_varint_buf(blob, pos); pos += idx_len

        dctx = zstd.ZstdDecompressor()
        payload = dctx.decompress(blob[pos:])
        pp = 0

        # Unpack unique lines
        num_uniq, pp = unpack_varint_buf(payload, pp)
        unique_lines = []
        for _ in range(num_uniq):
            l_len, pp = unpack_varint_buf(payload, pp)
            unique_lines.append(payload[pp:pp+l_len]); pp += l_len

        # Unpack RLE
        num_runs, pp = unpack_varint_buf(payload, pp)
        out = []
        for _ in range(num_runs):
            lid, pp = unpack_varint_buf(payload, pp)
            count, pp = unpack_varint_buf(payload, pp)
            line = unique_lines[lid]
            for _ in range(count): out.append(line)

        return b"\n".join(out)

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: [compress|decompress] <in> <out>"); sys.exit(1)
    codec = NULL_Universal_Repetition_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(d))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
