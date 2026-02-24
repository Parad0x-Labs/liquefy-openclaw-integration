#!/usr/bin/env python3
"""
LiquefyJsonRepetitionV1 - [NULL REPETITION v1]
===================================================
TARGET: 7000x+ Compression on highly repetitive JSON telemetry.
TECH: Line-Level RLE + Pattern Deduplication + Binary Columnar Packing.
"""

import time
import socket
import zstandard as zstd
import sys
import struct
import json
from collections import defaultdict
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

class LiquefyJsonRepetitionV1:
    def __init__(self, level=22):
        self.cctx = make_cctx(level=level, text_like=True)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        lines = raw.splitlines(keepends=True)
        if not lines: return b""

        unique_tokens = set()
        rle_lines = [] # (line, count)
        if lines:
            last_line = lines[0]; count = 0
            for line in lines:
                if line == last_line: count += 1
                else:
                    rle_lines.append((last_line, count))
                    # Tokenize sample
                    if len(last_line) < 1024: unique_tokens.add(last_line.strip())
                    last_line = line; count = 1
            rle_lines.append((last_line, count))
            if len(last_line) < 1024: unique_tokens.add(last_line.strip())

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        stream = bytearray()
        stream.extend(pack_varint(len(rle_lines)))
        for line, count in rle_lines:
            stream.extend(pack_varint(len(line))); stream.extend(line)
            stream.extend(pack_varint(count))

        custom = b'JSUR' + pack_varint(len(idx_bytes)) + idx_bytes + self.cctx.compress(stream)
        raw_zstd = self.cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return self.dctx.decompress(blob)
        if not blob.startswith(b'JSUR'): return b""
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos); pos += l_idx
        stream = self.dctx.decompress(blob[pos:])

        p = 0; out = bytearray()
        num_blocks, p = unpack_varint_buf(stream, p)
        for _ in range(num_blocks):
            llen, p = unpack_varint_buf(stream, p); line = stream[p:p+llen]; p += llen
            count, p = unpack_varint_buf(stream, p)
            for _ in range(count): out.extend(line)
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        q_bytes = query.encode('latin-1')
        if not idx.maybe_has(q_bytes):
            print(f"Index: '{query}' NOT FOUND (FAST SKIP)"); return
        print(f"Index: '{query}' MIGHT EXIST. Decompressing..."); data = self.decompress(blob)
        for line in data.splitlines():
            if q_bytes.lower() in line.lower(): print(line.decode('latin-1', errors='ignore'))

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python LiquefyJsonRepetitionV1.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = LiquefyJsonRepetitionV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
