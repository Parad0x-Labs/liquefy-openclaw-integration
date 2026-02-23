#!/usr/bin/env python3
"""
LiquefyK8sVelocityV1 - [NULL VELOCITY v1]
==============================================
TARGET: High-Velocity K8s/Docker JSON Logs.
GOAL:   Maximum Speed + Structural Compression.
TECH:   Vectorized Regex + Block Columnar + Searchable Content Stream.
STATUS: 100% Lossless, Searchable.
"""

import time
import re
import zstandard as zstd
import struct
import xxhash
import sys
import io

PROTOCOL_ID = b'NIT\x01'
V2_INDEX_FLAG = 1 << 31
COL_MODE_RAW = 0
COL_MODE_DICT = 1
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

def pack_varint(val: int) -> bytes:
    if val < 0x80: return struct.pack("B", val)
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80); val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple:
    val = data[pos]; pos += 1
    if val < 0x80: return val, pos
    res = val & 0x7F; shift = 7
    while True:
        b = data[pos]; pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return res, pos

class BloomIndex:
    def __init__(self):
        self.ba = bytearray(4096)
    def add(self, token: bytes):
        h = xxhash.xxh64(token).intdigest()
        self.ba[(h & 0x7FFF) >> 3] |= (1 << (h & 7))
        self.ba[((h >> 16) & 0x7FFF) >> 3] |= (1 << ((h >> 16) & 7))
    def check(self, token: bytes) -> bool:
        h = xxhash.xxh64(token).intdigest()
        if not (self.ba[(h & 0x7FFF) >> 3] & (1 << (h & 7))): return False
        if not (self.ba[((h >> 16) & 0x7FFF) >> 3] & (1 << ((h >> 16) & 7))): return False
        return True

RE_K8S_FAST = re.compile(rb'^{"log":"((?:[^"\\]|\\.)*)","stream":"(stdout|stderr)","time":"([^"]+)"}\n$')

class LiquefyK8sVelocityV1:
    def __init__(self, level=19): # Favor ratio parity/wins against zstd-19 by default
        self.cctx = zstd.ZstdCompressor(
            level=level,
            write_content_size=False,
            write_checksum=False,
            write_dict_id=False,
        )
        self.dctx = zstd.ZstdDecompressor()

    @staticmethod
    def _pack_column_raw(items):
        b = bytearray()
        for x in items:
            b.extend(pack_varint(len(x)))
            b.extend(x)
        return bytes(b)

    @staticmethod
    def _pack_column(items):
        # v2 column codec:
        #   [mode=0][legacy-raw]
        #   [mode=1][count][dict_len][dict_blob][idx_varints]
        raw_blob = LiquefyK8sVelocityV1._pack_column_raw(items)
        if not items:
            return bytes([COL_MODE_RAW]) + raw_blob

        uniq = list(dict.fromkeys(items))
        if len(uniq) >= len(items) or len(uniq) > 65535:
            return bytes([COL_MODE_RAW]) + raw_blob

        value_to_id = {v: i for i, v in enumerate(uniq)}
        dict_blob = bytearray()
        dict_blob.extend(pack_varint(len(uniq)))
        for val in uniq:
            dict_blob.extend(pack_varint(len(val)))
            dict_blob.extend(val)

        idx_blob = bytearray()
        for val in items:
            idx_blob.extend(pack_varint(value_to_id[val]))

        dict_mode = bytearray()
        dict_mode.append(COL_MODE_DICT)
        dict_mode.extend(pack_varint(len(items)))
        dict_mode.extend(pack_varint(len(dict_blob)))
        dict_mode.extend(dict_blob)
        dict_mode.extend(idx_blob)

        # Keep RAW when dictionary mode has no practical size benefit.
        if len(dict_mode) + 4 >= len(raw_blob):
            return bytes([COL_MODE_RAW]) + raw_blob
        return bytes(dict_mode)

    @staticmethod
    def _unpack_column_v2(blob: bytes):
        if not blob:
            return iter(())

        mode = blob[0]
        if mode == COL_MODE_RAW:
            data = blob[1:]
            res, ptr = [], 0
            while ptr < len(data):
                l, ptr = unpack_varint_buf(data, ptr)
                res.append(data[ptr:ptr + l])
                ptr += l
            return iter(res)

        if mode == COL_MODE_DICT:
            ptr = 1
            count, ptr = unpack_varint_buf(blob, ptr)
            dict_len, ptr = unpack_varint_buf(blob, ptr)
            dict_end = min(len(blob), ptr + dict_len)

            dictionary = []
            dptr = ptr
            dict_size = 0
            if dptr < dict_end:
                dict_size, dptr = unpack_varint_buf(blob, dptr)
            for _ in range(dict_size):
                if dptr >= dict_end:
                    break
                l, dptr = unpack_varint_buf(blob, dptr)
                dictionary.append(blob[dptr:dptr + l])
                dptr += l

            ptr = dict_end
            values = []
            for _ in range(count):
                if ptr >= len(blob):
                    values.append(b"")
                    continue
                idx, ptr = unpack_varint_buf(blob, ptr)
                values.append(dictionary[idx] if idx < len(dictionary) else b"")
            return iter(values)

        # Fallback for safety.
        data = blob
        res, ptr = [], 0
        while ptr < len(data):
            l, ptr = unpack_varint_buf(data, ptr)
            res.append(data[ptr:ptr + l])
            ptr += l
        return iter(res)

    @staticmethod
    def _unpack_column_legacy(blob: bytes):
        res, ptr = [], 0
        while ptr < len(blob):
            l, ptr = unpack_varint_buf(blob, ptr)
            res.append(blob[ptr:ptr + l])
            ptr += l
        return iter(res)

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def compress(self, raw: bytes) -> bytes:
        raw = raw or b""
        raw_candidate = self.cctx.compress(raw)
        # For highly repetitive K8s logs, direct zstd is usually both smaller and far faster.
        if len(raw_candidate) * 4 < len(raw):
            return raw_candidate

        col_content, col_time, col_stream, col_raw = [], [], bytearray(), []
        bitmap = bytearray(); curr_byte = 0; bit_idx = 0; bloom = BloomIndex()
        total_lines = 0

        lines = raw.splitlines(keepends=True)
        for line in lines:
            total_lines += 1
            m = RE_K8S_FAST.match(line)
            if m:
                col_stream.append(0 if m.group(2) == b'stdout' else 1)
                content = m.group(1); col_content.append(content)
                if len(content) > 4:
                    for tok in content.split(b' '):
                        if len(tok) > 3: bloom.add(tok)
                col_time.append(m.group(3))
            else:
                curr_byte |= (1 << bit_idx); col_raw.append(line)
            bit_idx += 1
            if bit_idx == 8:
                bitmap.append(curr_byte); curr_byte = 0; bit_idx = 0
        if bit_idx > 0: bitmap.append(curr_byte)

        rle_stream = bytearray()
        if col_stream:
            last = col_stream[0]; count = 0
            for s in col_stream:
                if s == last: count += 1
                else:
                    rle_stream.extend(pack_varint(count)); rle_stream.append(last)
                    last = s; count = 1
            rle_stream.extend(pack_varint(count)); rle_stream.append(last)

        payload = bytearray()
        payload.extend(pack_varint(total_lines))
        for chunk in [
            bitmap,
            rle_stream,
            self._pack_column(col_time),
            self._pack_column(col_raw),
            self._pack_column(col_content),
        ]:
            payload.extend(pack_varint(len(chunk))); payload.extend(chunk)

        idx_bytes = bytes(bloom.ba)
        idx_len = len(idx_bytes) | V2_INDEX_FLAG
        custom_candidate = PROTOCOL_ID + struct.pack('<I', idx_len) + idx_bytes + self.cctx.compress(payload)
        return raw_candidate if len(raw_candidate) <= len(custom_candidate) else custom_candidate

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID): raise ValueError("Invalid Magic")
        idx_meta = struct.unpack('<I', blob[4:8])[0]
        v2_mode = bool(idx_meta & V2_INDEX_FLAG)
        idx_len = idx_meta & (~V2_INDEX_FLAG)
        data = self._zstd_decompress(blob[8+idx_len:]); p = 0

        total_lines, p = unpack_varint_buf(data, p)

        def read_chunk():
            nonlocal p; l, p = unpack_varint_buf(data, p); c = data[p:p+l]; p += l; return c

        bitmap, rle_stream, blob_time, blob_raw, blob_content = [read_chunk() for _ in range(5)]

        if v2_mode:
            iter_time = self._unpack_column_v2(blob_time)
            iter_raw = self._unpack_column_v2(blob_raw)
            iter_content = self._unpack_column_v2(blob_content)
        else:
            iter_time = self._unpack_column_legacy(blob_time)
            iter_raw = self._unpack_column_legacy(blob_raw)
            iter_content = self._unpack_column_legacy(blob_content)
        stream_vals = []; sr_ptr = 0
        while sr_ptr < len(rle_stream):
            count, sr_ptr = unpack_varint_buf(rle_stream, sr_ptr); val = rle_stream[sr_ptr]; sr_ptr += 1
            stream_vals.extend([val] * count)
        iter_stream = iter(stream_vals)

        out = io.BytesIO()
        P, M, MS, ME, S, E = b'{"log":"', b'","stream":"', b'stdout', b'stderr', b'","time":"', b'"}\n'

        for bm_idx in range(total_lines):
            byte_idx, bit_offset = bm_idx // 8, bm_idx % 8
            if (bitmap[byte_idx] >> bit_offset) & 1:
                out.write(next(iter_raw))
            else:
                out.write(P); out.write(next(iter_content)); out.write(M)
                out.write(MS if next(iter_stream) == 0 else ME)
                out.write(S); out.write(next(iter_time)); out.write(E)

        return out.getvalue()

    def grep(self, blob: bytes, query: str):
        if blob.startswith(ZSTD_MAGIC):
            data = self._zstd_decompress(blob)
            q = query.encode()
            print(f"Found {data.count(q)} matches for '{query}'")
            return
        idx_meta = struct.unpack('<I', blob[4:8])[0]
        v2_mode = bool(idx_meta & V2_INDEX_FLAG)
        idx_len = idx_meta & (~V2_INDEX_FLAG)
        idx = BloomIndex(); idx.ba = bytearray(blob[8:8+idx_len])
        q = query.encode()
        if not idx.check(q): return
        if v2_mode:
            data = self.decompress(blob)
            print(f"Found {data.count(q)} matches for '{query}'")
            return
        data = self._zstd_decompress(blob[8+idx_len:]); p = 0
        _, p = unpack_varint_buf(data, p) # total_lines
        def skip(): nonlocal p; l, p = unpack_varint_buf(data, p); p += l
        for _ in range(4): skip()
        l, p = unpack_varint_buf(data, p); content_blob = data[p:p+l]
        print(f"Found {content_blob.count(q)} matches for '{query}'")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python LiquefyK8sVelocityV1.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = LiquefyK8sVelocityV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
