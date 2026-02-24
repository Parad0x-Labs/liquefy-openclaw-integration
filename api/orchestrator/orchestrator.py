#!/usr/bin/env python3
"""
Liquefy Orchestrator
====================
Central dispatch pipeline for the Liquefy compression system.

Pipeline stages:
  1. Engine routing       (orchestrator/router)
  2. MRTV verification    (liquefy_safety)
  3. Compression          (engine.compress)
  4. Per-tenant encryption (liquefy_security)
  5. Telemetry            (liquefy_observability)
"""

import sys
import os
import time
import asyncio
from typing import Any, Dict, Optional
from pathlib import Path

# Add the api/ directory to sys.path so all engine imports work
API_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

from orchestrator.registry import load_registry
from orchestrator.router import select_engine
from orchestrator.contracts import EngineManifest
from orchestrator.drivers.inprocess_driver import execute_inprocess, InProcessDriverError
from orchestrator.drivers.http_driver import execute_http_driver, DriverError
from orchestrator.drivers.binary_driver import execute_binary, BinaryDriverError
from orchestrator.engine_map import get_engine_instance
from common_zstd import make_cctx

# ── Enterprise Modules ──────────────────────────────────────────────
from liquefy_security import LiquefySecurity, secure_audit_log
from liquefy_safety import LiquefySafety, Valve
from liquefy_observability import LiquefyObservability, Vision

try:
    from liquefy_audit_chain import audit_log as _chain_audit_log
except ImportError:
    def _chain_audit_log(event, **details):
        return None

try:
    from liquefy_resilience import ResilientEngine, adaptive_zstd_level, recover_malformed_jsonl
except ImportError:
    ResilientEngine = None
    def adaptive_zstd_level(base_level=12):
        return base_level
    def recover_malformed_jsonl(data):
        return data, 0, 0

try:
    from observability.liquefy_otel import track_compression as otel_track_compression
except Exception:
    def otel_track_compression(**kwargs):
        return None


class Orchestrator:
    """Central processing unit. Chains all pipeline layers for a single file."""

    def __init__(self, engines_dir: str = "engines", master_secret: str = None):
        # ── Engine Registry ──────────────────────────────────────────
        self.registry = load_registry(engines_dir)
        print(f"[ORCHESTRATOR] Loaded {len(self.registry)} engines from '{engines_dir}'")
        for manifest, path in self.registry:
            print(f"  [{manifest.priority:>4}] {manifest.id} ({manifest.type})")

        self.security = LiquefySecurity(master_secret=master_secret) if master_secret is not None else None
        self.safety = Valve
        self.vision = Vision
        self._engine_cache: Dict[str, Any] = {}

    async def _probe_json_family_candidates(
        self,
        filepath: str,
        raw_data: bytes,
        engine_id: str,
        instance: Any,
    ):
        """
        Try sibling JSON engines and keep the smallest verified result.
        This only runs for JSON/JSONL and is disabled in speed profile.
        """
        if os.getenv("LIQUEFY_DISABLE_JSON_CASCADE", "").strip() == "1":
            return engine_id, instance, None
        if os.getenv("LIQUEFY_PROFILE", "").strip().lower() == "speed":
            return engine_id, instance, None
        if Path(filepath).suffix.lower() not in {".json", ".jsonl"}:
            return engine_id, instance, None
        if engine_id != "liquefy-json-hypernebula-v1":
            return engine_id, instance, None

        ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

        candidate_ids = [
            "liquefy-json-hypernebula-v1",
            "liquefy-json-rep-v1",
            "liquefy-json-columnar-v1",
            "liquefy-json-v1",
        ]

        best_id = engine_id
        best_instance = instance
        best_comp = await asyncio.to_thread(instance.compress, raw_data)

        # If the top engine already fell back to raw zstd (choose-smaller),
        # no other Python engine will beat it — skip the cascade entirely.
        if best_comp.startswith(ZSTD_MAGIC):
            return engine_id, instance, best_comp

        # Verify the baseline candidate too before using it as comparator.
        if not await asyncio.to_thread(self.safety.quick_verify, raw_data, best_comp, instance.decompress):
            return engine_id, instance, None

        for cid in candidate_ids[1:]:
            try:
                cand_instance = get_engine_instance(cid)
                if cand_instance is None:
                    continue
                cand_comp = await asyncio.to_thread(cand_instance.compress, raw_data)
                if cand_comp.startswith(ZSTD_MAGIC):
                    continue
                cand_ok = await asyncio.to_thread(
                    self.safety.quick_verify,
                    raw_data,
                    cand_comp,
                    cand_instance.decompress,
                )
                if not cand_ok:
                    continue
                if len(cand_comp) < len(best_comp):
                    best_id = cid
                    best_instance = cand_instance
                    best_comp = cand_comp
            except Exception:
                continue

        if best_id != engine_id:
            print(f"[ROUTER] JSON cascade selected '{best_id}' over '{engine_id}' for '{filepath}'")
        return best_id, best_instance, best_comp

    async def process_file(
        self,
        filepath: str,
        tenant_id: str = "default",
        api_key: str = None,
        ip_address: str = None,
        encrypt: bool = True,
        verify: bool = True,
        verify_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process a file through the full pipeline. Returns a result dict."""
        t_start = time.time()

        # ═══════════════════════════════════════════════════════════
        # STEP 1: READ FILE
        # ═══════════════════════════════════════════════════════════
        with open(filepath, "rb") as f:
            raw_data = f.read()

        original_bytes = len(raw_data)

        # ═══════════════════════════════════════════════════════════
        # STEP 2: ROUTE TO BEST ENGINE
        # ═══════════════════════════════════════════════════════════
        engine = select_engine(self.registry, filepath)
        engine_id_str = engine.id if engine else "zstd-fallback"

        if engine is None:
            print(f"[ROUTER] No engine matched '{filepath}'. Using Zstd fallback.")
        else:
            print(f"[ROUTER] Matched '{filepath}' -> '{engine.id}' (priority={engine.priority})")

        # ═══════════════════════════════════════════════════════════
        # STEP 3: COMPRESS WITH MRTV SAFETY VALVE
        # ═══════════════════════════════════════════════════════════
        requested_verify_mode = (
            verify_mode
            or os.environ.get("LIQUEFY_VERIFY", "full")
        ).strip().lower()
        if requested_verify_mode not in {"full", "fast", "off"}:
            requested_verify_mode = "full"
        if not verify:
            requested_verify_mode = "off"

        try:
            if engine and engine.type == "inprocess":
                # Load the engine instance for MRTV wrapping
                cache_key = engine.id
                if cache_key not in self._engine_cache:
                    self._engine_cache[cache_key] = get_engine_instance(engine.id)
                instance = self._engine_cache[cache_key]
                if instance is None:
                    raise InProcessDriverError(f"Could not load engine '{engine.id}'")

                precompressed = None
                engine_id_str, instance, precompressed = await self._probe_json_family_candidates(
                    filepath,
                    raw_data,
                    engine.id,
                    instance,
                )

                # Derive a 4-byte engine tag for the SAFE header
                engine_tag = engine.id[:4].encode().ljust(4, b'\x00')[:4]
                if engine_id_str != engine.id:
                    engine_tag = engine_id_str[:4].encode().ljust(4, b'\x00')[:4]

                if requested_verify_mode == "full":
                    if precompressed is not None:
                        import xxhash
                        original_hash = xxhash.xxh64(raw_data).digest()
                        restored = await asyncio.to_thread(instance.decompress, precompressed)
                        ok = xxhash.xxh64(restored).digest() == original_hash
                        if ok:
                            compressed = precompressed
                            print(f"[SAFETY] MRTV verified (precompressed) for engine '{engine_id_str}'")
                        else:
                            compressed = await asyncio.to_thread(
                                self.safety.seal,
                                raw_data,
                                instance.compress,
                                instance.decompress,
                                engine_tag,
                            )
                            if compressed.startswith(b"SAFEZST\x00"):
                                engine_id_str = "zstd-fallback"
                                print(f"[SAFETY] MRTV fallback triggered for engine '{engine.id}'")
                            else:
                                print(f"[SAFETY] MRTV verified for engine '{engine.id}'")
                    else:
                        compressed = await asyncio.to_thread(
                            self.safety.seal,
                            raw_data,
                            instance.compress,
                            instance.decompress,
                            engine_tag,
                        )
                        if compressed.startswith(b"SAFEZST\x00"):
                            engine_id_str = "zstd-fallback"
                            print(f"[SAFETY] MRTV fallback triggered for engine '{engine.id}'")
                        else:
                            print(f"[SAFETY] MRTV verified for engine '{engine.id}'")
                elif requested_verify_mode == "fast":
                    # Fast verify: direct compress + sampled post-check.
                    compressed = precompressed if precompressed is not None else await asyncio.to_thread(instance.compress, raw_data)
                    fast_ok = await asyncio.to_thread(
                        self.safety.quick_verify,
                        raw_data,
                        compressed,
                        instance.decompress,
                    )
                    if fast_ok:
                        print(f"[SAFETY] Fast verify passed for engine '{engine.id}'")
                    else:
                        print(f"[SAFETY] Fast verify failed for engine '{engine.id}'. Escalating to full MRTV.")
                        compressed = await asyncio.to_thread(
                            self.safety.seal,
                            raw_data,
                            instance.compress,
                            instance.decompress,
                            engine_tag,
                        )
                        if compressed.startswith(b"SAFEZST\x00"):
                            engine_id_str = "zstd-fallback"
                            print(f"[SAFETY] MRTV fallback triggered for engine '{engine.id}'")
                        else:
                            print(f"[SAFETY] MRTV verified for engine '{engine.id}'")
                else:
                    # Verification disabled.
                    compressed = precompressed if precompressed is not None else await asyncio.to_thread(instance.compress, raw_data)

            elif engine and engine.type == "external_service":
                # External service — bypass MRTV (trust the service)
                result = await execute_http_driver(engine, filepath)
                compressed = result.get("compressed_data", b"")
                if not compressed:
                    # Service returned receipt mode (output_path), not raw bytes
                    duration_ms = (time.time() - t_start) * 1000
                    self.vision.track_op(engine_id_str, tenant_id, original_bytes,
                                         result.get("compressed_bytes", 0), duration_ms)
                    return {**result, "pipeline": "external_service_receipt"}

            elif engine and engine.type == "external_binary":
                result = await execute_binary(engine, filepath)
                duration_ms = (time.time() - t_start) * 1000
                self.vision.track_op(engine_id_str, tenant_id, original_bytes, 0, duration_ms)
                return {**result, "pipeline": "external_binary"}

            else:
                # No engine matched -> Zstd fallback
                cctx = make_cctx(level=9, text_like=True)
                compressed = await asyncio.to_thread(cctx.compress, raw_data)

        except Exception as e:
            print(f"[ERROR] Engine '{engine_id_str}' failed: {e}. Falling back to Zstd.")
            secure_audit_log("ENGINE_FAILURE", {"engine": engine_id_str, "error": str(e)})
            cctx = make_cctx(level=9, text_like=True)
            compressed = await asyncio.to_thread(cctx.compress, raw_data)
            engine_id_str = "zstd-fallback"

        compressed_bytes = len(compressed)

        # ═══════════════════════════════════════════════════════════
        # STEP 4: ENCRYPT (Per-Tenant AES-256-GCM Seal)
        # ═══════════════════════════════════════════════════════════
        if encrypt:
            if self.security is None:
                raise ValueError("MISSING_SECRET: pass master_secret when encrypt=True")
            sealed_blob = await asyncio.to_thread(
                self.security.seal,
                compressed,
                tenant_id,
                {"engine": engine_id_str, "original_bytes": original_bytes},
            )
            output_bytes = len(sealed_blob)
            output_data = sealed_blob
            print(f"[SECURITY] Sealed for tenant '{tenant_id}'")

        else:
            output_data = compressed
            output_bytes = compressed_bytes

        # ═══════════════════════════════════════════════════════════
        # STEP 5: OBSERVE
        # ═══════════════════════════════════════════════════════════
        duration_ms = (time.time() - t_start) * 1000

        # Telemetry
        self.vision.track_op(
            engine_id=engine_id_str,
            tenant_id=tenant_id,
            bytes_in=original_bytes,
            bytes_out=compressed_bytes,
            duration_ms=duration_ms,
            success=True,
        )
        otel_track_compression(
            engine_id=engine_id_str,
            tenant_id=tenant_id,
            bytes_in=original_bytes,
            bytes_out=compressed_bytes,
            duration_ms=duration_ms,
        )

        # Audit trail (legacy + tamper-proof chain)
        audit_payload = {
            "engine": engine_id_str,
            "tenant": tenant_id,
            "bytes_in": original_bytes,
            "bytes_out": compressed_bytes,
            "ratio": round(original_bytes / max(1, compressed_bytes), 2),
            "duration_ms": round(duration_ms, 2),
            "encrypted": encrypt,
            "verified": (requested_verify_mode != "off"),
            "verify_mode": requested_verify_mode,
        }
        secure_audit_log("COMPRESS_SUCCESS", audit_payload)
        _chain_audit_log("compress", **audit_payload)

        print(f"[ORCHESTRATOR] Done. {original_bytes:,} -> {compressed_bytes:,} bytes "
              f"({original_bytes / max(1, compressed_bytes):.1f}x) in {duration_ms:.0f}ms")

        return {
            "ok": True,
            "engine_used": engine_id_str,
            "original_bytes": original_bytes,
            "compressed_bytes": compressed_bytes,
            "output_bytes": output_bytes,
            "ratio": round(original_bytes / max(1, compressed_bytes), 2),
            "duration_ms": round(duration_ms, 2),
            "encrypted": encrypt,
            "verified": (requested_verify_mode != "off"),
            "verify_mode": requested_verify_mode,
            "tenant_id": tenant_id,
            "pipeline": "full_enterprise",
            "output_data": output_data,
        }

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns real-time KPI dashboard data."""
        return self.vision.get_stats()
