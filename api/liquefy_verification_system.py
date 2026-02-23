#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import struct
import tempfile
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

@dataclass
class VerificationResult:
    test_name: str
    passed: bool
    details: Dict[str, Any]
    error: Optional[str] = None
    duration: float = 0.0

@dataclass
class FileStats:
    path: Path
    size: int
    sha256: str
    blake3: Optional[str]
    sha512: str
    line_count: Optional[int]
    newline_mode: Optional[str]
    encoding: Optional[str]
    magic_bytes: Optional[str]

class LiquefyVerificationSystem:
    def __init__(self):
        self.results: List[VerificationResult] = []
        self.start_time = time.time()

    def calculate_hashes(self, data: bytes) -> Dict[str, str]:
        hashes = {
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest(),
        }
        if HAS_BLAKE3:
            hashes['blake3'] = blake3.blake3(data).hexdigest()
        else:
            hashes['blake3'] = None
        return hashes

    def analyze_file(self, file_path: Path) -> FileStats:
        with open(file_path, 'rb') as f:
            data = f.read()

        hashes = self.calculate_hashes(data)

        try:
            text = data.decode('utf-8', errors='ignore')
            line_count = len(text.splitlines())
            if b'\r\n' in data: newline_mode = 'CRLF'
            elif b'\n' in data: newline_mode = 'LF'
            else: newline_mode = 'NONE'
            encoding = 'UTF-8'
        except:
            line_count = None
            newline_mode = None
            encoding = 'BINARY'

        magic = data[:16].hex() if len(data) >= 16 else data.hex()

        return FileStats(
            path=file_path, size=len(data), sha256=hashes['sha256'],
            blake3=hashes['blake3'], sha512=hashes['sha512'],
            line_count=line_count, newline_mode=newline_mode,
            encoding=encoding, magic_bytes=magic
        )

    def generate_public_proof_report(self, input_file, compressed_file, restored_file, engine_name, ratio, savings):
        return {
            "engine": engine_name,
            "input": str(input_file),
            "ratio": ratio,
            "savings": savings,
            "verification_results": [
                {"test": r.test_name, "passed": r.passed, "details": r.details} for r in self.results
            ]
        }
