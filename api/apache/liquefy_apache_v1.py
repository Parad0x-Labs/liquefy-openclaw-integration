#!/usr/bin/env python3
"""
NULL_Apache_Entropy_Focused - [NULL ENTROPY v1 - OPTIMIZED]
==========================================================
TARGET: 100% Lossless, Complex Enterprise Logs.
TECH:   Fast Template-based Columnar Extraction.
GOAL:   5+ MB/s Compression.
"""

import struct
import zstandard as zstd
import json
import re
import sys
import math
from collections import defaultdict

PROTOCOL_ID = b'LPRM'
VERSION = 1

def pack_varint(val: int) -> bytes:
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

class LiquefyApacheV1:
    def __init__(self, level=1):
        self.level = level
        # Optimized regex for Apache/Common log parts
        self.re_parts = re.compile(rb'(\S+)|(\[.*?\])|(".*?")|(\b\d+\b)')

    def compress(self, raw: bytes) -> bytes:
        if not raw: return b""

        templates = []
        template_map = {}
        col_data = defaultdict(list)
        line_struct = []

        # Optimized line splitting and parsing
        for line in raw.split(b"\n"):
            if not line:
                line_struct.append(-1); continue

            # FAST PARSE: Use split by space if no quotes/brackets, otherwise regex
            if b'"' not in line and b'[' not in line:
                parts = line.split()
                tpl = b" ".join([b"\x00"] * len(parts))
            else:
                last_pos = 0; tpl = bytearray(); parts = []
                for m in self.re_parts.finditer(line):
                    tpl.extend(line[last_pos:m.start()]); tpl.extend(b"\x00")
                    parts.append(m.group(0)); last_pos = m.end()
                tpl.extend(line[last_pos:]); tpl = bytes(tpl)

            if tpl not in template_map:
                tid = len(templates); template_map[tpl] = tid; templates.append(tpl)
            else: tid = template_map[tpl]

            line_struct.append(tid)
            for i, v in enumerate(parts): col_data[(tid, i)].append(v)

        cctx = zstd.ZstdCompressor(level=self.level)

        # Pack Templates
        t_blob = bytearray()
        t_blob.extend(pack_varint(len(templates)))
        for t in templates:
            t_blob.extend(pack_varint(len(t)) + t)
        c_t_blob = cctx.compress(t_blob)

        # Pack Structure (RLE)
        s_blob = bytearray()
        if line_struct:
            last = line_struct[0]; run = 0
            for tid in line_struct:
                if tid == last: run += 1
                else:
                    s_blob.extend(pack_varint(last + 1)); s_blob.extend(pack_varint(run))
                    last = tid; run = 1
            s_blob.extend(pack_varint(last + 1)); s_blob.extend(pack_varint(run))
        c_s_blob = cctx.compress(s_blob)

        # Pack Columns
        meta = bytearray()
        data = bytearray()
        meta.extend(pack_varint(len(col_data)))
        for (tid, f_idx), vals in sorted(col_data.items()):
            meta.extend(pack_varint(tid)); meta.extend(pack_varint(f_idx))
            meta.extend(pack_varint(len(vals)))

            buf = bytearray()
            for v in vals:
                buf.extend(pack_varint(len(v)) + v)
            c_buf = cctx.compress(buf)
            meta.extend(pack_varint(len(c_buf)))
            data.extend(c_buf)

        c_meta = cctx.compress(meta)

        header = struct.pack(">4sBIIII", PROTOCOL_ID, VERSION, len(c_t_blob), len(c_s_blob), len(c_meta), 0)
        return header + c_t_blob + c_s_blob + c_meta + data

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4
        ver, l_tpl, l_str, l_meta, l_unused = struct.unpack(">BIIII", blob[pos:pos+17]); pos += 17

        dctx = zstd.ZstdDecompressor()

        templates = []
        t_blob = dctx.decompress(blob[pos:pos+l_tpl]); pos += l_tpl
        tp = 0; num_t, tp = unpack_varint_buf(t_blob, tp)
        for _ in range(num_t):
            tl, tp = unpack_varint_buf(t_blob, tp); templates.append(t_blob[tp:tp+tl]); tp += tl

        line_struct = []
        s_blob = dctx.decompress(blob[pos:pos+l_str]); pos += l_str
        sp = 0
        while sp < len(s_blob):
            tid_m1, sp = unpack_varint_buf(s_blob, sp)
            run, sp = unpack_varint_buf(s_blob, sp)
            line_struct.extend([tid_m1 - 1] * run)

        meta_raw = dctx.decompress(blob[pos:pos+l_meta]); pos += l_meta
        mp = 0; num_cols, mp = unpack_varint_buf(meta_raw, mp)
        col_iters = {}
        for _ in range(num_cols):
            tid, mp = unpack_varint_buf(meta_raw, mp); f_idx, mp = unpack_varint_buf(meta_raw, mp)
            count, mp = unpack_varint_buf(meta_raw, mp); clen, mp = unpack_varint_buf(meta_raw, mp)

            c_data = blob[pos:pos+clen]; pos += clen
            buf = dctx.decompress(c_data)
            bp = 0; vals = []
            for _ in range(count):
                vlen, bp = unpack_varint_buf(buf, bp); vals.append(buf[bp:bp+vlen]); bp += vlen
            col_iters[(tid, f_idx)] = iter(vals)

        out_lines = []
        for tid in line_struct:
            if tid == -1:
                out_lines.append(b"")
                continue
            tpl = templates[tid]
            res = bytearray()
            tp = 0; f_idx = 0
            parts = tpl.split(b"\x00")
            for i in range(len(parts)-1):
                res.extend(parts[i])
                res.extend(next(col_iters[(tid, f_idx)]))
                f_idx += 1
            res.extend(parts[-1])
            out_lines.append(res)

        return b"\n".join(out_lines)

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: [compress|decompress] <in> <out>"); sys.exit(1)
    codec = NULL_Apache_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(d))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
