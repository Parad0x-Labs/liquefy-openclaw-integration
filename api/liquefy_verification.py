#!/usr/bin/env python3

# ==============================================================================
# LIQUEFY ENTERPRISE - COMPREHENSIVE VERIFICATION SYSTEM
# Public-Proof Lossless Compression Validation
# ==============================================================================

import os
import sys
import time
import hashlib
import hmac
import struct
import tempfile
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import concurrent.futures
import random
import json

try:
    import blake3  # pip install blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

# Add parent directory to path to find orchestrator
sys.path.append(str(Path(__file__).parent))

try:
    from services.orchestrator import LiquefyOrchestrator
    ENGINES_AVAILABLE = True
except ImportError:
    ENGINES_AVAILABLE = False

@dataclass
class VerificationResult:
    """Comprehensive verification result"""
    test_name: str
    passed: bool
    details: Dict[str, Any]
    error: Optional[str] = None
    duration: float = 0.0

@dataclass
class FileStats:
    """File statistics for verification"""
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
    """Complete verification system for public-proof compression"""

    def __init__(self):
        self.results: List[VerificationResult] = []
        self.start_time = time.time()

    def calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate multiple hash algorithms"""
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
        """Comprehensive file analysis"""
        with open(file_path, 'rb') as f:
            data = f.read()

        hashes = self.calculate_hashes(data)

        try:
            text = data.decode('utf-8', errors='ignore')
            line_count = len(text.splitlines())
            if b'\r\n' in data:
                newline_mode = 'CRLF'
            elif b'\n' in data:
                newline_mode = 'LF'
            else:
                newline_mode = 'NONE'
            encoding = 'UTF-8'
        except:
            line_count = None
            newline_mode = None
            encoding = 'BINARY'

        magic = data[:16].hex() if len(data) >= 16 else data.hex()

        return FileStats(
            path=file_path,
            size=len(data),
            sha256=hashes['sha256'],
            blake3=hashes['blake3'],
            sha512=hashes['sha512'],
            line_count=line_count,
            newline_mode=newline_mode,
            encoding=encoding,
            magic_bytes=magic
        )

    def verify_bit_perfect_identity(self, original: Path, restored: Path) -> VerificationResult:
        """A. Bit-perfect identity verification"""
        start_time = time.time()

        try:
            orig_stats = self.analyze_file(original)
            rest_stats = self.analyze_file(restored)

            size_equal = orig_stats.size == rest_stats.size
            sha256_equal = orig_stats.sha256 == rest_stats.sha256
            sha512_equal = orig_stats.sha512 == rest_stats.sha512
            blake3_equal = (orig_stats.blake3 == rest_stats.blake3) if orig_stats.blake3 else True

            with open(original, 'rb') as f1, open(restored, 'rb') as f2:
                byte_equal = f1.read() == f2.read()

            with open(original, 'rb') as f:
                orig_data = f.read()
            with open(restored, 'rb') as f:
                rest_data = f.read()

            n_check = min(1024, len(orig_data))
            first_equal = orig_data[:n_check] == rest_data[:n_check]
            last_equal = orig_data[-n_check:] == rest_data[-n_check:]

            passed = all([size_equal, sha256_equal, sha512_equal, blake3_equal,
                         byte_equal, first_equal, last_equal])

            details = {
                'size_equal': size_equal,
                'sha256_equal': sha256_equal,
                'sha512_equal': sha512_equal,
                'blake3_equal': blake3_equal,
                'byte_equal': byte_equal,
                'first_bytes_equal': first_equal,
                'last_bytes_equal': last_equal,
                'original_size': orig_stats.size,
                'restored_size': rest_stats.size
            }

        except Exception as e:
            passed = False
            details = {}
            error = str(e)

        return VerificationResult(
            test_name="Bit-Perfect Identity",
            passed=passed,
            details=details,
            error=error if 'error' in locals() else None,
            duration=time.time() - start_time
        )

    def verify_deterministic_decode(self, archive_path: Path, decompress_func) -> VerificationResult:
        """B. Deterministic decode verification"""
        start_time = time.time()

        try:
            results = []
            for i in range(3):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.restored') as tmp:
                    tmp_path = Path(tmp.name)

                with open(archive_path, 'rb') as f:
                    secure_blob = f.read()

                restored_data = decompress_func(secure_blob)
                with open(tmp_path, 'wb') as f:
                    f.write(restored_data)

                stats = self.analyze_file(tmp_path)
                results.append(stats.sha256)
                tmp_path.unlink(missing_ok=True)

            all_identical = all(h == results[0] for h in results)
            passed = all_identical
            details = {
                'decode_attempts': len(results),
                'all_hashes_identical': all_identical,
                'hash_values': results,
                'deterministic': all_identical
            }

        except Exception as e:
            passed = False
            details = {}
            error = str(e)

        return VerificationResult(
            test_name="Deterministic Decode",
            passed=passed,
            details=details,
            error=error if 'error' in locals() else None,
            duration=time.time() - start_time
        )

    def verify_format_integrity(self, original: Path, restored: Path) -> VerificationResult:
        """2. Format-level integrity checks"""
        start_time = time.time()

        try:
            orig_stats = self.analyze_file(original)
            rest_stats = self.analyze_file(restored)

            checks = {}
            if orig_stats.encoding != 'BINARY':
                checks['line_count_equal'] = orig_stats.line_count == rest_stats.line_count
                checks['newline_mode_preserved'] = orig_stats.newline_mode == rest_stats.newline_mode
                checks['encoding_preserved'] = orig_stats.encoding == rest_stats.encoding

                with open(original, 'rb') as f:
                    orig_sample = f.read(min(8192, orig_stats.size))
                with open(restored, 'rb') as f:
                    rest_sample = f.read(min(8192, rest_stats.size))
                checks['whitespace_preserved'] = orig_sample == rest_sample

            checks['magic_bytes_preserved'] = orig_stats.magic_bytes == rest_stats.magic_bytes

            passed = all(checks.values())
            details = checks

        except Exception as e:
            passed = False
            details = {}
            error = str(e)

        return VerificationResult(
            test_name="Format Integrity",
            passed=passed,
            details=details,
            error=error if 'error' in locals() else None,
            duration=time.time() - start_time
        )

    def verify_archive_integrity(self, archive_path: Path) -> VerificationResult:
        """3. Archive-level checks"""
        start_time = time.time()

        try:
            with open(archive_path, 'rb') as f:
                sig = f.read(32)
                magic = f.read(4)
                # Updated magic to LSEC for Liquefy Security
                magic_valid = magic == b"LSEC"

            passed = magic_valid
            details = {
                'magic_valid': magic_valid,
                'sha256_present': len(sig) == 32
            }

        except Exception as e:
            passed = False
            details = {}
            error = str(e)

        return VerificationResult(
            test_name="Archive Integrity",
            passed=passed,
            details=details,
            error=error if 'error' in locals() else None,
            duration=time.time() - start_time
        )

    def run_negative_tests(self, archive_path: Path, decompress_func) -> VerificationResult:
        """C. Negative tests - corruption should fail"""
        start_time = time.time()

        try:
            with open(archive_path, 'rb') as f:
                original_data = f.read()

            bitflip_failed = False
            truncate_failed = False
            garbage_failed = False

            corrupted1 = bytearray(original_data)
            if len(corrupted1) > 40:
                corrupted1[40] ^= 0x01

            try:
                decompress_func(bytes(corrupted1))
                bitflip_failed = False
            except:
                bitflip_failed = True

            corrupted2 = original_data[:-1] if len(original_data) > 1 else original_data
            try:
                decompress_func(corrupted2)
                truncate_failed = False
            except:
                truncate_failed = True

            corrupted3 = original_data + os.urandom(100)
            try:
                decompress_func(corrupted3)
                garbage_failed = False
            except:
                garbage_failed = True

            passed = all([bitflip_failed, truncate_failed, garbage_failed])
            details = {
                'bitflip_detection': bitflip_failed,
                'truncate_detection': truncate_failed,
                'garbage_detection': garbage_failed,
                'negative_tests_passed': sum([bitflip_failed, truncate_failed, garbage_failed]),
                'negative_tests_total': 3
            }

        except Exception as e:
            passed = False
            details = {}
            error = str(e)

        return VerificationResult(
            test_name="Negative Tests",
            passed=passed,
            details=details,
            error=error if 'error' in locals() else None,
            duration=time.time() - start_time
        )

    def run_compression_verification(self, input_file: Path, engine_name: str = "LIQUEFY_V1_MIXED") -> Dict[str, Any]:
        """Run complete verification suite on a compression test"""
        if not ENGINES_AVAILABLE:
            return {'success': False, 'error': 'Engines not available'}

        orch = LiquefyOrchestrator(security_secret="VERIFIER_SECRET")

        try:
            with open(input_file, 'rb') as f:
                raw_data = f.read()

            secure_blob, actual_engine = orch.compress(raw_data, engine_name, tenant_id="verifier")
            archive_path = input_file.with_suffix('.null')
            with open(archive_path, 'wb') as f:
                f.write(secure_blob)

            restored_data, audit_meta = orch.decompress(secure_blob, tenant_id="verifier")
            engine_used = audit_meta.get("meta", {}).get("engine", "unknown")
            restored_path = input_file.with_suffix('.restored')
            with open(restored_path, 'wb') as f:
                f.write(restored_data)

            # Verification functions might need a wrapper for the updated decompress call
            def simple_decompress(blob):
                data, _ = orch.decompress(blob, tenant_id="verifier")
                return data

            tests = [
                self.verify_bit_perfect_identity(input_file, restored_path),
                self.verify_deterministic_decode(archive_path, simple_decompress),
                self.verify_format_integrity(input_file, restored_path),
                self.verify_archive_integrity(archive_path),
                self.run_negative_tests(archive_path, simple_decompress)
            ]

            self.results.extend(tests)

            orig_size = len(raw_data)
            comp_size = len(secure_blob)
            compression_ratio = orig_size / comp_size if comp_size > 0 else 0
            space_savings = (1 - comp_size / orig_size) * 100 if orig_size > 0 else 0

            report = self.generate_public_proof_report(
                input_file, archive_path, restored_path,
                engine_name, compression_ratio, space_savings
            )

            archive_path.unlink(missing_ok=True)
            restored_path.unlink(missing_ok=True)

            return {
                'success': all(t.passed for t in tests),
                'compression_ratio': compression_ratio,
                'space_savings': space_savings,
                'tests_passed': sum(t.passed for t in tests),
                'tests_total': len(tests),
                'report': report
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'compression_ratio': 0,
                'space_savings': 0,
                'tests_passed': 0,
                'tests_total': 0,
                'report': None
            }

    def generate_public_proof_report(self, orig: Path, comp: Path, rest: Path,
                                   engine: str, ratio: float, savings: float) -> str:
        orig_stats = self.analyze_file(orig)
        rest_stats = self.analyze_file(rest)

        env_info = {
            'os': platform.system(),
            'platform': platform.platform(),
            'python_version': sys.version.split()[0],
            'cpu_count': os.cpu_count(),
            'architecture': platform.machine()
        }

        tests_summary = {}
        for result in self.results[-5:]:
            tests_summary[result.test_name] = {
                'passed': result.passed,
                'duration': f"{result.duration:.3f}s",
                'details': result.details
            }

        report = f"""
================================================================================
LIQUEFY ENTERPRISE - PUBLIC PROOF REPORT (Liquefy v1)
Compression Lossless Verification
================================================================================

FILE INFO:
  Original:     {orig.name}
  Type:         {orig_stats.encoding}
  Size:         {orig_stats.size:,} bytes
  Lines:        {orig_stats.line_count or 'N/A'}
  Encoding:     {orig_stats.encoding}

COMPRESSION RESULTS:
  Engine:       {engine.upper()}
  Ratio:        {ratio:.2f}x
  Savings:      {savings:.1f}%

HASH VERIFICATION:
  Original SHA256:  {orig_stats.sha256}
  Restored SHA256:  {rest_stats.sha256}
  SHA256 Match:     {'YES' if orig_stats.sha256 == rest_stats.sha256 else 'NO'}

VERIFICATION TESTS:
"""
        for test_name, test_info in tests_summary.items():
            status = 'PASS' if test_info['passed'] else 'FAIL'
            report += f"  {test_name}: {status} ({test_info['duration']})\n"

        report += f"""
SYSTEM INFO:
  OS:           {env_info['os']} {env_info['platform']}
  Python:       {env_info['python_version']}
  Timestamp:    {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

================================================================================
VERIFICATION {'COMPLETE' if all(t['passed'] for t in tests_summary.values()) else 'FAILED'}
================================================================================
"""
        return report
