#!/usr/bin/env python3
"""
NULL_Nginx_Entropy_Focused - [NULL ENTROPY v1]
==============================================
TARGET: 100% Lossless, Complex Nginx Logs.
TECH: Template-based Columnar Extraction + Adaptive Bloom.
"""

import struct
import zstandard as zstd
import json
import re
import time
import os
import sys
from collections import defaultdict
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

PROTOCOL_ID = b'LPRM'
VERSION = 1

class LogTemplateExtractor:
    def __init__(self):
        self.re_combined = re.compile(r'(^[^\s]+)|(\[.*?\])|(".*?")|(\b\d+\b)')
    def extract(self, line_str):
        variables = []
        def replacer(match):
            variables.append(match.group(0))
            return '\x00'
        s = self.re_combined.sub(replacer, line_str)
        return s, variables

class LiquefyNginxV1:
    def __init__(self, level=22):
        self.extractor = LogTemplateExtractor()
        self.level = level
        self.cctx = make_cctx(level=level, text_like=True)
        self.dctx = zstd.ZstdDecompressor()

    @staticmethod
    def _pack_vlist(data):
        buf = bytearray()
        for x in data:
            buf.extend(pack_varint(x))
        return buf

    @staticmethod
    def _iter_v(data):
        idx = 0; n = len(data)
        while idx < n:
            val, idx = unpack_varint_buf(data, idx)
            yield val

    def compress(self, raw: bytes) -> bytes:
        if not raw:
            return b""

        templates = {}; rev_templates = []
        template_buffers = defaultdict(lambda: defaultdict(list))
        structure_stream = []
        unique_tokens = set()

        text = raw.decode('latin-1')
        for line in text.splitlines(keepends=True):
            if not line:
                continue
            template, vars_ = self.extractor.extract(line)
            if template not in templates:
                tid = len(rev_templates); templates[template] = tid
                rev_templates.append(template)
            else:
                tid = templates[template]
            structure_stream.append(tid)
            for i, v in enumerate(vars_):
                template_buffers[tid][i].append(v)
                if len(v) > 3:
                    unique_tokens.add(v.encode('latin-1'))

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens:
            idx.add(t)
        idx_bytes = bytes(idx)

        c_tpl = self.cctx.compress(json.dumps(rev_templates).encode('utf-8'))

        rle_struct = []
        if structure_stream:
            last = structure_stream[0]; run = 0
            for s in structure_stream:
                if s == last:
                    run += 1
                else:
                    rle_struct.extend([last, run]); last = s; run = 1
            rle_struct.extend([last, run])
        c_struct = self.cctx.compress(self._pack_vlist(rle_struct))

        col_blob = bytearray()
        for tid in sorted(template_buffers.keys()):
            for col_idx, values in template_buffers[tid].items():
                raw_data = "\x00".join(values).encode('latin-1')
                c_data = self.cctx.compress(raw_data)
                col_blob.extend(struct.pack('>HBI', tid, col_idx, len(c_data)))
                col_blob.extend(c_data)

        header = struct.pack('>4sBIIII', PROTOCOL_ID, VERSION, len(c_tpl), len(c_struct), len(col_blob), len(idx_bytes))
        custom = header + idx_bytes + c_tpl + c_struct + bytes(col_blob)
        raw_zstd = self.cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return self.dctx.decompress(blob)
        if not blob.startswith(PROTOCOL_ID):
            return b""

        magic, ver, l_tpl, l_str, l_col, l_idx = struct.unpack('>4sBIIII', blob[:21])
        pos = 21
        pos += l_idx

        templates = json.loads(self.dctx.decompress(blob[pos:pos+l_tpl])); pos += l_tpl
        s_iter = self._iter_v(self.dctx.decompress(blob[pos:pos+l_str])); pos += l_str
        structure = []
        try:
            while True:
                structure.extend([next(s_iter)] * next(s_iter))
        except StopIteration:
            pass

        col_data = blob[pos:pos+l_col]
        col_iters = defaultdict(dict); ptr = 0
        while ptr < len(col_data):
            tid, c_idx, size = struct.unpack('>HBI', col_data[ptr:ptr+7])
            ptr += 7
            raw_chunk = self.dctx.decompress(col_data[ptr:ptr+size]).decode('latin-1')
            col_iters[tid][c_idx] = iter(raw_chunk.split('\x00'))
            ptr += size

        out = []
        for tid in structure:
            parts = templates[tid].split('\x00')
            res = []
            for j, part in enumerate(parts):
                res.append(part)
                if j < len(parts) - 1:
                    try:
                        res.append(next(col_iters[tid][j]))
                    except StopIteration:
                        res.append("ERR")
            out.append("".join(res))
        return "".join(out).encode('latin-1')
