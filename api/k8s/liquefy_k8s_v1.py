#!/usr/bin/env python3
"""
NULL_K8s_Entropy_Focused - [NULL ENTROPY v1 - MAX RATIO]
=========================================================
TARGET: Kubernetes/Docker Logs (Mixed JSON/Text).
TECH:   Wrapper Stripping + Multi-Stage Columnar Zstd.
STATUS: 100% Lossless, Searchable, High Ratio (Target 20x+).
"""

import time
import re
import zstandard as zstd
import sys
import struct
from collections import defaultdict
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

PROTOCOL_ID = b'K8U\x01'

class LiquefyK8sV1:
    def __init__(self, level=19):
        self.level = level
        self.re_json = re.compile(rb'("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?)|(true|false|null)')

    def compress(self, raw: bytes) -> bytes:
        if not raw: return PROTOCOL_ID + pack_varint(0)

        lines = raw.split(b"\n")
        templates = []; template_map = {}
        # Columns grouped by field index globally (e.g. all "timestamps" together)
        global_cols = defaultdict(list)
        line_struct = []; unique_tokens = set()

        for line in lines:
            if not line:
                line_struct.append(-1); continue

            if not line.startswith(b'{'):
                t_bytes = b"\xFF"; vars = [line]
            else:
                vars = []; last_pos = 0; template = bytearray()
                for m in self.re_json.finditer(line):
                    template.extend(line[last_pos:m.start()]); template.extend(b"\x00")
                    val = m.group(0); vars.append(val); last_pos = m.end()
                    if val.startswith(b'"') and 8 < len(val) < 128:
                        unique_tokens.add(val[1:-1])
                template.extend(line[last_pos:]); t_bytes = bytes(template)

            if t_bytes not in template_map:
                tid = len(templates); template_map[t_bytes] = tid; templates.append(t_bytes)
            else: tid = template_map[t_bytes]

            line_struct.append(tid)
            for i, v in enumerate(vars): global_cols[i].append((tid, v))

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        cctx = make_cctx(level=self.level, text_like=True)

        # 1. Pack Templates
        t_blob = bytearray()
        t_blob.extend(pack_varint(len(templates)))
        for t in templates: t_blob.extend(pack_varint(len(t)) + t)

        # 2. Pack Line Structure
        l_blob = bytearray()
        l_blob.extend(pack_varint(len(line_struct)))
        if line_struct:
            last = line_struct[0]; run = 0
            for tid in line_struct:
                if tid == last: run += 1
                else:
                    l_blob.extend(pack_varint(last + 1)); l_blob.extend(pack_varint(run))
                    last = tid; run = 1
            l_blob.extend(pack_varint(last + 1)); l_blob.extend(pack_varint(run))

        # 3. Pack Columns (The ratio driver)
        # We group all values for the same field index across ALL templates
        c_blob = bytearray()
        c_blob.extend(pack_varint(len(global_cols)))
        for f_idx in sorted(global_cols.keys()):
            col_vals = global_cols[f_idx]
            c_blob.extend(pack_varint(f_idx))
            c_blob.extend(pack_varint(len(col_vals)))

            # Sub-group by TID to help Zstd find local patterns
            buf = bytearray()
            for tid, v in col_vals:
                buf.extend(pack_varint(tid)) # TID helps reconstruction
                buf.extend(pack_varint(len(v)) + v)

            # We compress each global column with LDM
            try:
                col_cctx = make_cctx(level=self.level, text_like=True, enable_ldm=True, window_log=22)
            except:
                col_cctx = cctx

            c_data = col_cctx.compress(buf)
            c_blob.extend(pack_varint(len(c_data)) + c_data)

        final_payload = cctx.compress(t_blob + l_blob + c_blob)
        custom = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + final_payload
        raw_zstd = cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return zstd.ZstdDecompressor().decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4; idx_len, pos = unpack_varint_buf(blob, pos); pos += idx_len
        dctx = zstd.ZstdDecompressor()
        stream = dctx.decompress(blob[pos:]); p = 0

        num_tpl, p = unpack_varint_buf(stream, p); templates = []
        for _ in range(num_tpl):
            tl, p = unpack_varint_buf(stream, p); templates.append(stream[p:p+tl]); p += tl

        total_lines, p = unpack_varint_buf(stream, p); line_struct = []
        while len(line_struct) < total_lines:
            tid_m1, p = unpack_varint_buf(stream, p); run, p = unpack_varint_buf(stream, p)
            line_struct.extend([tid_m1 - 1] * run)

        num_fields, p = unpack_varint_buf(stream, p)
        col_iters = defaultdict(dict)
        for _ in range(num_fields):
            f_idx, p = unpack_varint_buf(stream, p)
            num_vals, p = unpack_varint_buf(stream, p)
            clen, p = unpack_varint_buf(stream, p)
            c_buf = dctx.decompress(stream[p:p+clen]); p += clen
            bp = 0
            # Populate iterators for each (tid, f_idx)
            # We need to preserve the order per tid
            temp_map = defaultdict(list)
            for _ in range(num_vals):
                tid, bp = unpack_varint_buf(c_buf, bp)
                vlen, bp = unpack_varint_buf(c_buf, bp)
                temp_map[tid].append(c_buf[bp:bp+vlen]); bp += vlen
            for tid in temp_map: col_iters[tid][f_idx] = iter(temp_map[tid])

        out = []
        for tid in line_struct:
            if tid == -1: out.append(b""); continue
            tpl = templates[tid]
            if tpl == b"\xFF":
                out.append(next(col_iters[tid][0])); continue
            parts = tpl.split(b"\x00"); res = bytearray()
            for i in range(len(parts)-1):
                res.extend(parts[i]); res.extend(next(col_iters[tid][i]))
            res.extend(parts[-1]); out.append(res)
        return b"\n".join(out)
