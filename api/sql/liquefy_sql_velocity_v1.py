#!/usr/bin/env python3
"""
LiquefySqlVelocityV1 - [NULL VELOCITY v1]
==============================================
TARGET: Enterprise SQL Dumps @ Native Speeds.
TECH:   Direct C-Transform + Smart Column Buffers + Zstd.
"""

import time
import ctypes
import os
import io
import zstandard as zstd
import xxhash
from common_zstd import make_cctx

PROTOCOL_ID = b'SQC\x01'
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

try:
    # Try local path first
    base_path = os.path.dirname(os.path.abspath(__file__))
    lib = ctypes.CDLL(os.path.join(base_path, "sql_scanner.so"))
except:
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        lib = ctypes.CDLL(os.path.join(base_path, "sql_scanner.dll"))
    except:
        lib = None

if lib is not None:
    lib.transform_sql.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, # In
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32), # Tpl Out
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32), # Var Out
        ctypes.POINTER(ctypes.c_uint32) # Var Count
    ]
    lib.transform_sql.restype = ctypes.c_int32

class LiquefySqlVelocityV1:
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
        if lib is None:
            # Native scanner unavailable: return smallest direct zstd frame.
            return self.cctx.compress(raw)

        # Buffers
        raw_ptr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
        tpl_out = (ctypes.c_uint8 * (len(raw) * 2))()
        var_out = (ctypes.c_uint8 * (len(raw) * 2))()

        tpl_len = ctypes.c_uint32(0)
        var_len = ctypes.c_uint32(0)
        var_count = ctypes.c_uint32(0)

        # ONE NATIVE CALL
        lib.transform_sql(raw_ptr, len(raw),
                          tpl_out, ctypes.byref(tpl_len),
                          var_out, ctypes.byref(var_len),
                          ctypes.byref(var_count))

        # 3. Final Compression (Combined bytes)
        # Layout: [TplLen][Tpl][VCount][VarStream]
        # We use a simple separator for Zstd to find
        combined = bytes(tpl_out[:tpl_len.value]) + b'TITAN' + bytes(var_out[:var_len.value])

        payload = self.cctx.compress(combined)
        candidate_custom = PROTOCOL_ID + payload
        candidate_raw = self.cctx.compress(raw)
        return candidate_raw if len(candidate_raw) <= len(candidate_custom) else candidate_custom

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        stream = self._zstd_decompress(blob[4:])

        if lib is None:
            raise ValueError("sql_scanner native library unavailable; cannot decompress SQC container")

        tpl_part, var_part = stream.split(b'TITAN', 1)

        # Reconstruct (Still in Python, but very fast)
        out = bytearray()
        parts = tpl_part.split(b"\x00")

        v_ptr = 0
        def unpack_varint():
            nonlocal v_ptr
            res = 0; shift = 0
            while True:
                b = var_part[v_ptr]; v_ptr += 1
                res |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            return res

        for i in range(len(parts)-1):
            out.extend(parts[i])
            v_l = unpack_varint()
            out.extend(var_part[v_ptr:v_ptr+v_l])
            v_ptr += v_l
        out.extend(parts[-1])
        return bytes(out)

if __name__ == "__main__":
    codec = LiquefySqlVelocityV1()
    if len(os.sys.argv) > 2:
        with open(os.sys.argv[2], "rb") as f: d = f.read()
        if os.sys.argv[1] == "compress":
            with open(os.sys.argv[3], "wb") as f: f.write(codec.compress(d))
        else:
            with open(os.sys.argv[3], "wb") as f: f.write(codec.decompress(d))
