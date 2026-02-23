#!/usr/bin/env python3
"""
NULL_Syslog_Entropy_Focused - [NULL ENTROPY v1]
===============================================
TARGET: Extreme compression on repetitive data + Beating Zstd on real logs.
TECH:   Global Columnar Buffers + Adaptive Transforms (RLE/Dict/Delta) + Zstd.
"""

import time
import re
import zstandard as zstd
import math
import xxhash
import sys
import os
from collections import defaultdict

PROTOCOL_ID = b'SLG\x01'

# =========================================================
# 1. CORE UTILITIES
# =========================================================

def pack_varint(val: int) -> bytes:
    if val < 0: val = 0
    if val < 0x80: return bytes([val])
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple[int, int]:
    res = 0; shift = 0
    while True:
        b = data[pos]; pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return res, pos

def zigzag_enc(n: int) -> int: return (n << 1) ^ (n >> 63)
def zigzag_dec(n: int) -> int: return (n >> 1) ^ -(n & 1)

class AdaptiveSearchIndex:
    def __init__(self, num_items: int, fpr=0.01):
        num_items = max(10, num_items)
        m = -(num_items * math.log(fpr)) / (math.log(2)**2)
        self.num_bits = max(64, int(m))
        self.num_bytes = (self.num_bits + 7) // 8
        self.ba = bytearray(self.num_bytes)
        self.k = max(1, int((self.num_bits / num_items) * math.log(2)))

    def add(self, token: bytes):
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            self.ba[pos >> 3] |= (1 << (pos & 7))

    def maybe_has(self, token: bytes) -> bool:
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            if not (self.ba[pos >> 3] & (1 << (pos & 7))):
                return False
        return True

    def __bytes__(self):
        return pack_varint(self.k) + pack_varint(self.num_bits) + bytes(self.ba)

    @staticmethod
    def from_bytes(data: bytes, pos: int) -> tuple["AdaptiveSearchIndex", int]:
        k, pos = unpack_varint_buf(data, pos)
        num_bits, pos = unpack_varint_buf(data, pos)
        num_bytes = (num_bits + 7) // 8
        idx = AdaptiveSearchIndex(10)
        idx.k = k; idx.num_bits = num_bits; idx.num_bytes = num_bytes
        idx.ba = bytearray(data[pos:pos+num_bytes])
        return idx, pos + num_bytes

# =========================================================
# 2. SMART COLUMN ENCODER
# =========================================================

MODE_RAW = 0
MODE_DICT = 1
MODE_DELTA = 2
MODE_RLE = 3

class SmartColumn:
    @staticmethod
    def encode(raw_values: list[bytes]) -> bytes:
        count = len(raw_values)
        if count == 0: return pack_varint(MODE_RAW) + pack_varint(0)

        # 1. RLE
        if count > 1 and all(x == raw_values[0] for x in raw_values):
             return pack_varint(MODE_RLE) + pack_varint(count) + pack_varint(len(raw_values[0])) + raw_values[0]

        # 2. Dictionary
        unique_vals = sorted(list(set(raw_values)))
        if len(unique_vals) < 256 and len(unique_vals) < count * 0.3:
            val_map = {v: i for i, v in enumerate(unique_vals)}
            dict_blob = pack_varint(len(unique_vals))
            for v in unique_vals: dict_blob += pack_varint(len(v)) + v
            idx_blob = bytearray(val_map[v] for v in raw_values)
            return pack_varint(MODE_DICT) + pack_varint(count) + dict_blob + idx_blob

        # 3. Delta
        try:
            is_numeric = all(x.isdigit() or (x.startswith(b'-') and x[1:].isdigit()) for x in raw_values)
            if is_numeric and count > 1:
                nums = [int(x) for x in raw_values]
                delta_blob = pack_varint(count)
                last = 0
                for n in nums:
                    diff = n - last
                    delta_blob += pack_varint(zigzag_enc(diff))
                    last = n
                return pack_varint(MODE_DELTA) + delta_blob
        except: pass

        # 4. Raw
        raw_blob = pack_varint(count)
        for v in raw_values: raw_blob += pack_varint(len(v)) + v
        return pack_varint(MODE_RAW) + raw_blob

    @staticmethod
    def decode(chunk: bytes) -> list[bytes]:
        mode, p = unpack_varint_buf(chunk, 0)
        vals = []
        if mode == MODE_RAW:
            cnt, p = unpack_varint_buf(chunk, p)
            for _ in range(cnt):
                vl, p = unpack_varint_buf(chunk, p)
                vals.append(chunk[p:p+vl]); p += vl
        elif mode == MODE_RLE:
            cnt, p = unpack_varint_buf(chunk, p)
            vl, p = unpack_varint_buf(chunk, p)
            val = chunk[p:p+vl]
            vals = [val] * cnt
        elif mode == MODE_DICT:
            cnt, p = unpack_varint_buf(chunk, p)
            dsz, p = unpack_varint_buf(chunk, p)
            dct = []
            for _ in range(dsz):
                vl, p = unpack_varint_buf(chunk, p)
                dct.append(chunk[p:p+vl]); p += vl
            for _ in range(cnt):
                vals.append(dct[chunk[p]]); p += 1
        elif mode == MODE_DELTA:
            cnt, p = unpack_varint_buf(chunk, p)
            last = 0
            for _ in range(cnt):
                zd, p = unpack_varint_buf(chunk, p)
                dt = zigzag_dec(zd); curr = last + dt
                vals.append(str(curr).encode('ascii')); last = curr
        return vals

# =========================================================
# 3. MAIN COMPRESSOR
# =========================================================

class LiquefySyslogV1:
    def __init__(self, level=22):
        self.cctx = zstd.ZstdCompressor(level=level)
        self.dctx = zstd.ZstdDecompressor()
        self.re_vars = re.compile(rb'(\[.*?\])|(".*?")|(\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*\b)|(\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\b)|(\b\d+\.\d+\.\d+\.\d+\b)|(\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b)|(\b\d+\b)')

    def _extract(self, line: bytes) -> tuple[bytes, list[bytes]]:
        vars = []; last_pos = 0; template = bytearray()
        for m in self.re_vars.finditer(line):
            template.extend(line[last_pos:m.start()]); template.extend(b"\x00")
            vars.append(m.group(0)); last_pos = m.end()
        template.extend(line[last_pos:])
        return bytes(template), vars

    def compress(self, raw: bytes) -> bytes:
        lines = raw.splitlines(keepends=True)
        templates = []; template_map = {}
        line_tids = []
        global_cols = defaultdict(list)
        unique_tokens = set()

        for line in lines:
            tpl, vars = self._extract(line)
            if tpl not in template_map:
                template_map[tpl] = len(templates); templates.append(tpl)
            tid = template_map[tpl]
            line_tids.append(tid)
            for i, v in enumerate(vars):
                global_cols[i].append(v)
                if len(v) < 64: unique_tokens.add(v.strip(b'"[]'))

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        # 1. Templates
        t_stream = pack_varint(len(templates))
        for t in templates: t_stream += pack_varint(len(t)) + t

        # 2. Structure (RLE)
        l_stream = pack_varint(len(line_tids))
        if line_tids:
            rle_runs = []
            curr_tid = line_tids[0]; run = 0
            for tid in line_tids:
                if tid == curr_tid: run += 1
                else: rle_runs.append((curr_tid, run)); curr_tid = tid; run = 1
            rle_runs.append((curr_tid, run))
            l_stream += pack_varint(len(rle_runs))
            for tid, r in rle_runs: l_stream += pack_varint(tid) + pack_varint(r)
        else: l_stream += pack_varint(0)

        # 3. Global Smart Columns
        c_stream = pack_varint(len(global_cols))
        for i in sorted(global_cols.keys()):
            smart_blob = SmartColumn.encode(global_cols[i])
            c_stream += pack_varint(len(smart_blob)) + smart_blob

        payload = self.cctx.compress(t_stream + l_stream + c_stream)
        return PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + payload

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(PROTOCOL_ID): return b""
        p = 4
        l_idx, p = unpack_varint_buf(blob, p); p += l_idx
        stream = self.dctx.decompress(blob[p:])

        sp = 0
        num_t, sp = unpack_varint_buf(stream, sp)
        templates = []
        for _ in range(num_t):
            tl, sp = unpack_varint_buf(stream, sp)
            templates.append(stream[sp:sp+tl]); sp += tl

        total_lines, sp = unpack_varint_buf(stream, sp)
        num_runs, sp = unpack_varint_buf(stream, sp)
        line_tids = []
        for _ in range(num_runs):
            tid, sp = unpack_varint_buf(stream, sp)
            run, sp = unpack_varint_buf(stream, sp)
            line_tids.extend([tid]*run)

        num_cols, sp = unpack_varint_buf(stream, sp)
        col_iters = []
        for _ in range(num_cols):
            blen, sp = unpack_varint_buf(stream, sp)
            col_iters.append(iter(SmartColumn.decode(stream[sp:sp+blen])))
            sp += blen

        out = bytearray()
        for tid in line_tids:
            tpl = templates[tid]; parts = tpl.split(b"\x00")
            for i in range(len(parts)-1):
                out.extend(parts[i])
                try: out.extend(next(col_iters[i]))
                except: out.extend(b"ERR")
            out.extend(parts[-1])
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        p = 4
        l_idx, p = unpack_varint_buf(blob, p); idx, _ = AdaptiveSearchIndex.from_bytes(blob, p)
        if not idx.maybe_has(query.encode('latin-1')):
            print(f"Index: '{query}' NOT FOUND (FAST SKIP)"); return
        print(f"Index: Match. Decompressing..."); data = self.decompress(blob)
        for line in data.splitlines():
            if query.encode('latin-1').lower() in line.lower(): print(line.decode('latin-1', errors='ignore'))

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Syslog_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = NULL_Syslog_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        res = codec.compress(d); print(f"Compressed {len(d)} -> {len(res)} bytes ({len(d)/len(res):.2f}x)")
        with open(sys.argv[3], "wb") as f: f.write(res)
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: d=f.read()
        codec.grep(d, sys.argv[3])
