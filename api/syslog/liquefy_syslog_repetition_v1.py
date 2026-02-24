#!/usr/bin/env python3
"""
LiquefySyslogRepetitionV1 - [NULL REPETITION v1]
=====================================================
TARGET: 100% Lossless, Highly Repetitive Syslog.
TECH: Line-Level RLE + Pattern Deduplication + Binary RLE.
"""

import time
import io
import zstandard as zstd
import sys
import os
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex, ZSTD_MAGIC

PROTOCOL_ID = b'SLU\x01'

class LiquefySyslogRepetitionV1:
    def __init__(self, level=19):
        self.cctx = make_cctx(
            level=level,
            text_like=True,
            write_content_size=False,
            write_checksum=False,
            write_dict_id=False,
        )
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        lines = raw.splitlines(keepends=True)
        if not lines: return b""

        raw_candidate = self.cctx.compress(raw)
        # For very repetitive syslog streams raw zstd is usually optimal and far faster.
        if len(raw_candidate) * 4 < len(raw):
            return raw_candidate

        unique_tokens = set()
        rle_lines = []
        if lines:
            last_line = lines[0]; count = 0
            for line in lines:
                if line == last_line: count += 1
                else:
                    rle_lines.append((last_line, count))
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

        custom_candidate = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + self.cctx.compress(stream)
        return raw_candidate if len(raw_candidate) <= len(custom_candidate) else custom_candidate

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos); pos += l_idx
        stream = self._zstd_decompress(blob[pos:])

        p = 0; out = bytearray()
        num_blocks, p = unpack_varint_buf(stream, p)
        for _ in range(num_blocks):
            llen, p = unpack_varint_buf(stream, p); line = stream[p:p+llen]; p += llen
            count, p = unpack_varint_buf(stream, p)
            for _ in range(count): out.extend(line)
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        if blob.startswith(ZSTD_MAGIC):
            q_bytes = query.encode('latin-1')
            data = self._zstd_decompress(blob)
            for line in data.splitlines():
                if q_bytes.lower() in line.lower():
                    print(line.decode('latin-1', errors='ignore'))
            return
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
    if len(sys.argv) < 3: print("Usage: python LiquefySyslogRepetitionV1.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = LiquefySyslogRepetitionV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
