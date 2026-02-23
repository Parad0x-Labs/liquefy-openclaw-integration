#!/usr/bin/env python3
"""
NULL_Aws_VpcFlow_Entropy_Focused - [NULL ENTROPY v1]
====================================================
TARGET: AWS VPC Flow Logs (Standard & Custom).
TECH:   Binary IP Packing + Columnar RLE + Delta + Zstd.
STATUS: 100% Lossless, Searchable, Speed Optimized.
"""

import time
import re
import io
import os
import zstandard as zstd
import math
import xxhash
import sys
import struct
import socket
from collections import defaultdict
from typing import Optional

PROTOCOL_ID = b'VPC\x01'
RAW_MODE_MARKER = b"RZ"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# =========================================================
# 1. CORE UTILITIES
# =========================================================

def pack_varint(val: int) -> bytes:
    if val < 0x80: return struct.pack("B", val)
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple[int, int]:
    val = data[pos]; pos += 1
    if val < 0x80: return val, pos
    res = val & 0x7F; shift = 7
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

    def check(self, token: bytes) -> bool:
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            if not (self.ba[pos >> 3] & (1 << (pos & 7))): return False
        return True

    def __bytes__(self):
        return pack_varint(self.k) + pack_varint(self.num_bits) + bytes(self.ba)

    @staticmethod
    def from_bytes(data: bytes, pos: int):
        k, pos = unpack_varint_buf(data, pos)
        num_bits, pos = unpack_varint_buf(data, pos)
        num_bytes = (num_bits + 7) // 8
        idx = AdaptiveSearchIndex(10)
        idx.k = k; idx.num_bits = num_bits; idx.num_bytes = num_bytes
        idx.ba = bytearray(data[pos:pos+num_bytes])
        return idx, pos + num_bytes

# =========================================================
# 2. VPC SMART COLUMNS
# =========================================================

MODE_RAW = 0
MODE_DICT = 1
MODE_DELTA = 2
MODE_RLE = 3
MODE_IPV4 = 4

class VpcSmartColumn:
    @staticmethod
    def encode(raw_values: list[bytes]) -> bytes:
        if not raw_values: return pack_varint(MODE_RAW) + pack_varint(0)
        count = len(raw_values)

        # 1. RLE (Account ID, ENI, Action, Protocol)
        if raw_values.count(raw_values[0]) == count:
             return pack_varint(MODE_RLE) + pack_varint(count) + pack_varint(len(raw_values[0])) + raw_values[0]

        # 2. IP Packing Check (IPv4)
        is_ipv4 = True
        try:
            for x in raw_values[:10]:
                if b'.' not in x: # Stricter check: must have dots
                    is_ipv4 = False; break
                socket.inet_aton(x.decode())
        except: is_ipv4 = False

        if is_ipv4:
            try:
                ip_blob = bytearray()
                for x in raw_values:
                    ip_blob.extend(socket.inet_aton(x.decode()))
                return pack_varint(MODE_IPV4) + pack_varint(count) + ip_blob
            except: pass

        # 3. Dictionary (Ports, ENIs)
        unique_vals = set(raw_values)
        if len(unique_vals) < 256 and len(unique_vals) < count * 0.2:
            sorted_uniq = sorted(list(unique_vals))
            val_map = {v: i for i, v in enumerate(sorted_uniq)}
            dict_blob = bytearray()
            dict_blob.extend(pack_varint(len(sorted_uniq)))
            for v in sorted_uniq:
                dict_blob.extend(pack_varint(len(v)) + v)
            idx_blob = bytearray([val_map[v] for v in raw_values])
            return pack_varint(MODE_DICT) + dict_blob + pack_varint(count) + idx_blob

        # 4. Delta (Timestamps, Packets, Bytes)
        is_numeric = True
        nums = []
        try:
            for x in raw_values:
                if not x.isdigit():
                    is_numeric = False; break
                nums.append(int(x))
        except: is_numeric = False

        if is_numeric:
            deltas = []
            last = 0
            for n in nums:
                diff = n - last
                deltas.append(zigzag_enc(diff))
                last = n
            delta_blob = bytearray()
            for d in deltas: delta_blob.extend(pack_varint(d))
            return pack_varint(MODE_DELTA) + pack_varint(count) + delta_blob

        # 5. Fallback RAW
        raw_blob = bytearray()
        for v in raw_values:
            raw_blob.extend(pack_varint(len(v)))
            raw_blob.extend(v)
        return pack_varint(MODE_RAW) + pack_varint(count) + raw_blob

    @staticmethod
    def decode(data: bytes, pos: int) -> tuple[list[bytes], int]:
        mode, pos = unpack_varint_buf(data, pos)
        values = []

        if mode == MODE_RAW:
            count, pos = unpack_varint_buf(data, pos)
            for _ in range(count):
                vlen, pos = unpack_varint_buf(data, pos)
                values.append(data[pos:pos+vlen]); pos += vlen
        elif mode == MODE_RLE:
            count, pos = unpack_varint_buf(data, pos)
            vlen, pos = unpack_varint_buf(data, pos)
            val = data[pos:pos+vlen]; pos += vlen
            values = [val] * count
        elif mode == MODE_DICT:
            d_size, pos = unpack_varint_buf(data, pos)
            dictionary = []
            for _ in range(d_size):
                vlen, pos = unpack_varint_buf(data, pos)
                dictionary.append(data[pos:pos+vlen]); pos += vlen
            count, pos = unpack_varint_buf(data, pos)
            for _ in range(count):
                idx = data[pos]; pos += 1
                values.append(dictionary[idx])
        elif mode == MODE_DELTA:
            count, pos = unpack_varint_buf(data, pos)
            last = 0
            for _ in range(count):
                z_delta, pos = unpack_varint_buf(data, pos)
                delta = zigzag_dec(z_delta)
                last += delta
                values.append(str(last).encode('ascii'))
        elif mode == MODE_IPV4:
            count, pos = unpack_varint_buf(data, pos)
            for _ in range(count):
                ip_bytes = data[pos:pos+4]; pos += 4
                values.append(socket.inet_ntoa(ip_bytes).encode('ascii'))

        return values, pos

# =========================================================
# 3. VPC CHAMPION ENGINE
# =========================================================

class LiquefyVpcFlowV1:
    def __init__(self, level=19):
        self.cctx = zstd.ZstdCompressor(
            level=level,
            write_content_size=False,
            write_checksum=False,
            write_dict_id=False,
        )
        # Legacy decoder uses one-shot dctx.decompress(), so content size must be present.
        self.legacy_cctx = zstd.ZstdCompressor(
            level=level,
            write_content_size=True,
            write_checksum=False,
            write_dict_id=False,
        )
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        raw = raw or b""
        raw_comp = self.cctx.compress(raw)
        if len(raw) < 128:
            return raw_comp

        if os.getenv("LIQUEFY_PROFILE", "").strip().lower() != "ratio":
            return raw_comp

        if not self._sample_prefers_columnar(raw):
            return raw_comp

        try:
            columnar = self._compress_legacy_columnar(raw)
            if columnar is not None and len(columnar) < len(raw_comp):
                return columnar
        except Exception:
            # Safety valve will still verify at orchestrator level; fall back locally.
            pass

        return raw_comp

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def _sample_prefers_columnar(
        self,
        raw: bytes,
        sample_target: int = 256 * 1024,
        min_lines: int = 64,
        min_gain_ratio: float = 0.98,
    ) -> bool:
        """
        Cheap gate for ratio profile.
        Compare raw-zstd vs legacy-columnar on a bounded newline-aligned sample and
        only pay full columnar CPU if the sample suggests a real size win.
        """
        if len(raw) < 4096 or b"\n" not in raw:
            return False

        sample_end = min(len(raw), sample_target)
        if sample_end < len(raw):
            nl = raw.rfind(b"\n", 0, sample_end)
            if nl <= 0:
                return False
            sample_end = nl + 1
        sample = raw[:sample_end]
        if not sample.endswith(b"\n"):
            return False
        if sample.count(b"\n") < min_lines:
            return False

        try:
            raw_sample = self.cctx.compress(sample)
            col_sample = self._compress_legacy_columnar(sample)
            if col_sample is None:
                return False
            return len(col_sample) <= int(len(raw_sample) * min_gain_ratio)
        except Exception:
            return False

    def _compress_legacy_columnar(self, raw: bytes) -> Optional[bytes]:
        """
        Emit the legacy VPC columnar format that `_decompress_legacy()` expects.
        Guardrails ensure byte-perfect reconstruction (single-space, LF-terminated lines).
        """
        if not raw or b"\r" in raw or b"\t" in raw:
            return None
        if not raw.endswith(b"\n"):
            return None

        body = raw[:-1]
        if not body:
            return None

        lines = body.split(b"\n")
        if not lines or any(not line for line in lines):
            return None

        columns: list[list[bytes]] = []
        expected_cols = None
        unique_tokens: set[bytes] = set()
        bloom = AdaptiveSearchIndex(len(lines) * 8)

        for line in lines:
            # Decoder reconstructs with b" ".join(parts) + b"\\n", so spacing must be canonical.
            if line.startswith(b" ") or line.endswith(b" ") or b"  " in line:
                return None

            parts = line.split(b" ")
            if not parts or any(p == b"" for p in parts):
                return None

            if expected_cols is None:
                expected_cols = len(parts)
                if expected_cols < 8:
                    return None
                columns = [[] for _ in range(expected_cols)]
            elif len(parts) != expected_cols:
                return None

            bloom.add(line)
            for i, token in enumerate(parts):
                columns[i].append(token)
                if token not in unique_tokens:
                    unique_tokens.add(token)
                    bloom.add(token)

        stream = bytearray()
        total_lines = len(lines)
        tid = 0
        stream.extend(pack_varint(total_lines))
        stream.extend(pack_varint(1))           # one run
        stream.extend(pack_varint(tid))
        stream.extend(pack_varint(total_lines))

        for col_idx, values in enumerate(columns):
            encoded = VpcSmartColumn.encode(values)
            stream.extend(pack_varint(tid))
            stream.extend(pack_varint(col_idx))
            stream.extend(pack_varint(len(encoded)))
            stream.extend(encoded)

        idx_bytes = bytes(bloom)
        out = bytearray(PROTOCOL_ID)
        out.extend(pack_varint(len(idx_bytes)))
        out.extend(idx_bytes)
        out.extend(self.legacy_cctx.compress(bytes(stream)))
        return bytes(out)

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)

        if not blob.startswith(PROTOCOL_ID):
            raise ValueError("Invalid Magic")

        if (
            blob.startswith(PROTOCOL_ID + RAW_MODE_MARKER)
            and len(blob) > len(PROTOCOL_ID) + len(RAW_MODE_MARKER)
            and blob[len(PROTOCOL_ID) + len(RAW_MODE_MARKER):].startswith(ZSTD_MAGIC)
        ):
            return self._zstd_decompress(blob[len(PROTOCOL_ID) + len(RAW_MODE_MARKER):])

        return self._decompress_legacy(blob)

    def _decompress_legacy(self, blob: bytes) -> bytes:
        pos = 4
        idx_len, pos = unpack_varint_buf(blob, pos)
        pos += idx_len
        stream = self.dctx.decompress(blob[pos:])
        p = 0

        _total_lines, p = unpack_varint_buf(stream, p)
        num_runs, p = unpack_varint_buf(stream, p)
        struct_tids = []
        for _ in range(num_runs):
            tid, p = unpack_varint_buf(stream, p)
            run, p = unpack_varint_buf(stream, p)
            struct_tids.extend([tid] * run)

        col_map = defaultdict(dict)
        while p < len(stream):
            tid, p = unpack_varint_buf(stream, p)
            col_idx, p = unpack_varint_buf(stream, p)
            dlen, p = unpack_varint_buf(stream, p)
            vals, _ = VpcSmartColumn.decode(stream[p:p + dlen], 0)
            col_map[tid][col_idx] = iter(vals)
            p += dlen

        out = []
        for tid in struct_tids:
            line_parts = []
            col_idx = 0
            while col_idx in col_map[tid]:
                line_parts.append(next(col_map[tid][col_idx], b"ERR"))
                col_idx += 1
            out.append(b" ".join(line_parts) + b"\n")

        return b"".join(out)

    def grep(self, blob: bytes, query: str):
        q_bytes = query.encode("utf-8")
        if blob.startswith(ZSTD_MAGIC) or blob.startswith(PROTOCOL_ID + RAW_MODE_MARKER):
            data = self.decompress(blob)
            print(f"Found {data.count(q_bytes)} matches for '{query}'")
            return

        pos = 4
        idx_len, pos = unpack_varint_buf(blob, pos)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        if not idx.check(q_bytes):
            return
        data = self.decompress(blob)
        print(f"Found {data.count(q_bytes)} matches for '{query}'")
