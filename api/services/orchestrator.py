#!/usr/bin/env python3
"""
Liquefy Orchestrator - [LIQUEFY V1 CORE]
========================================
MISSION: Unified entry point for all Liquefy Engines.
FEAT:    Automatic Type Detection + Safety Valve Integration + Media Mounts.
"""

import sys
import os
import time
import subprocess
import re
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

# Add all subdirectories to sys.path
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

# Ensure all engine directories are in path
for d in BASE_DIR.iterdir():
    if d.is_dir():
        sys.path.insert(0, str(d))

from liquefy_safety import Valve
from liquefy_security import LiquefySecurity, secure_audit_log
from liquefy_ai import LiquefyAI
from liquefy_observability import Vision

class LiquefyOrchestrator:
    def __init__(self, safety_enabled=None, security_secret=None):
        if safety_enabled is None:
            safety_enabled = os.environ.get("LIQUEFY_SAFETY_OFF", "0") != "1"

        self.safety_enabled = safety_enabled
        Valve.enabled = safety_enabled

        # Security Layer
        self.security = LiquefySecurity(master_secret=security_secret) if security_secret is not None else None

        # AI Persona (Internal Helper)
        self.ai = LiquefyAI()

        # Stable Engine IDs for Archive Compatibility
        # Format: 'Internal_ID' : (Module, ClassName, ProtocolID)
        self.engines = {
            'LIQUEFY_V1_JSON': ('liquefy_json_v1', 'LiquefyJsonV1', b'JSON'),
            'LIQUEFY_V1_JSON_REP': ('liquefy_json_repetition_v1', 'LiquefyJsonRepetitionV1', b'JSON'),
            'LIQUEFY_V1_JSON_COLUMNAR': ('liquefy_columnar_gun_v1', 'LiquefyColumnarGunV1', b'COL1'),
            'LIQUEFY_V1_HYPER_NEBULA': ('liquefy_hyper_nebula_v1', 'LiquefyHyperNebulaV1', b'HYP1'),
            'LIQUEFY_V1_APACHE': ('liquefy_apache_v1', 'LiquefyApacheV1', b'LPRM'),
            'LIQUEFY_V1_APACHE_REP': ('liquefy_apache_repetition_v1', 'LiquefyApacheRepetitionV1', b'UNI\x01'),
            'LIQUEFY_V1_NGINX': ('liquefy_nginx_v1', 'LiquefyNginxV1', b'NGX\x01'),
            'LIQUEFY_V1_NGINX_REP': ('liquefy_nginx_repetition_v1', 'LiquefyNginxRepetitionV1', b'UNI\x01'),
            'LIQUEFY_V1_SYSLOG_3164': ('liquefy_syslog_v1', 'LiquefySyslogV1', b'SYSL'),
            'LIQUEFY_V1_SYSLOG_5424': ('liquefy_syslog_v1', 'LiquefySyslogV1', b'SYSL'),
            'LIQUEFY_V1_SYSLOG_REP': ('liquefy_syslog_repetition_v1', 'LiquefySyslogRepetitionV1', b'SYSL'),
            'LIQUEFY_V1_K8S': ('liquefy_k8s_v1', 'LiquefyK8sV1', b'K8S\x01'),
            'LIQUEFY_V1_K8S_VELOCITY': ('liquefy_k8s_velocity_v1', 'LiquefyK8sVelocityV1', b'K8S\x01'),
            'LIQUEFY_V1_SQL': ('liquefy_sql_v1', 'LiquefySqlV1', b'SQL\x01'),
            'LIQUEFY_V1_SQL_VELOCITY': ('liquefy_sql_velocity_v1', 'LiquefySqlVelocityV1', b'SQL\x01'),
            'LIQUEFY_V1_SQL_REP': ('liquefy_sql_repetition_v1', 'LiquefySqlRepetitionV1', b'SQL\x01'),
            'LIQUEFY_V1_CLOUDTRAIL': ('liquefy_cloudtrail_v1', 'LiquefyCloudTrailV1', b'CTL\x01'),
            'LIQUEFY_V1_VPCFLOW': ('liquefy_vpcflow_v1', 'LiquefyVpcFlowV1', b'VPC\x01'),
            'LIQUEFY_V1_WINDOWS_EVTX': ('liquefy_windows_v1', 'LiquefyWindowsV1', b'EVTX'),
            'LIQUEFY_V1_NETFLOW': ('liquefy_netflow_v1', 'LiquefyNetflowV1', b'NET\x01'),
            'LIQUEFY_V1_GITHUB': ('liquefy_github_v1', 'LiquefyGithubV1', b'SCM\x01'),
            'LIQUEFY_V1_VMWARE': ('liquefy_vmware_v1', 'LiquefyVmwareV1', b'VMW\x01'),
            'LIQUEFY_V1_MIXED': ('liquefy_universal_v1', 'LiquefyUniversalV1', b'NMX5'),
            'LIQUEFY_V1_RAW_FALLBACK': ('liquefy_fallback_v1', 'LiquefyFallbackV1', b'UNI\x01'),
        }
        self.registry = {} # ProtocolID -> Decompress Func
        self.MEDIA_MOUNT_PATH = Path("/opt/nulla_dreamwave")

    def _get_engine(self, engine_key):
        if engine_key not in self.engines:
            raise ValueError(f"Unknown engine ID: {engine_key}")

        mod_name, class_name, proto_id = self.engines[engine_key]
        mod = __import__(mod_name)
        engine_class = getattr(mod, class_name)
        engine = engine_class()
        self.registry[proto_id] = engine.decompress
        return engine, proto_id

    def detect_format(self, data: bytes) -> str:
        """Detects the best engine for a given data sample out of 21 specialized options."""
        sample = data[:8192] # Use larger sample for better detection
        if not sample: return "LIQUEFY_V1_RAW_FALLBACK"

        # --- 0. PRE-ANALYSIS: Check for Repetition ---
        lines = sample.splitlines()
        is_repetitive = False
        if len(lines) > 5:
            unique_ratio = len(set(lines)) / len(lines)
            if unique_ratio < 0.7:
                is_repetitive = True

        # --- 1. Windows Event Logs (EVTX) ---
        if sample.startswith(b'ElfFile\x00'):
            return "LIQUEFY_V1_WINDOWS_EVTX"

        # --- 2. JSON-based Detection (JSON, K8s, CloudTrail) ---
        if sample.strip().startswith((b'{', b'[')):
            # Distinguish between CloudTrail and generic JSON
            aws_cloudtrail_markers = (
                b'"eventSource"',
                b'"awsRegion"',
                b'"recipientAccountId"',
                b'"eventID"',
                b'"requestParameters"',
                b'"responseElements"',
            )
            aws_hits = sum(1 for marker in aws_cloudtrail_markers if marker in sample)
            if b'CloudTrail' in sample or (
                aws_hits >= 2 and b'"eventVersion"' in sample and b'"eventTime"' in sample
            ):
                return "LIQUEFY_V1_CLOUDTRAIL"
            if b'kind": "AuditSink' in sample or b'apiVersion": "audit.k8s.io' in sample:
                # K8s is often deep nested -> HyperNebula is ideal
                return "LIQUEFY_V1_HYPER_NEBULA"

            # For standard JSON, prefer HyperNebula for non-repetitive structured streams
            if not is_repetitive and b'":' in sample:
                return "LIQUEFY_V1_HYPER_NEBULA"

            return "LIQUEFY_V1_JSON_REP" if is_repetitive else "LIQUEFY_V1_JSON"

        # --- 3. SQL Detection ---
        if re.search(rb'(?i)INSERT\s+INTO|UPDATE\s+|SELECT\s+.*FROM|CREATE\s+TABLE', sample):
            if is_repetitive: return "LIQUEFY_V1_SQL_REP"
            if b'velocity' in sample.lower(): return "LIQUEFY_V1_SQL_VELOCITY"
            return "LIQUEFY_V1_SQL"

        # --- 4. Web Logs Detection (Apache, Nginx) ---
        # Common Log Format / Combined Log Format
        if re.search(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}', sample):
            if b'nginx' in sample.lower():
                return "LIQUEFY_V1_NGINX_REP" if is_repetitive else "LIQUEFY_V1_NGINX"
            return "LIQUEFY_V1_APACHE_REP" if is_repetitive else "LIQUEFY_V1_APACHE"

        # --- 5. Syslog Detection ---
        if re.search(rb'<\d+>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}', sample) or re.search(rb'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', sample):
            if is_repetitive: return "LIQUEFY_V1_SYSLOG_REP"
            # Distinguish between 3164 and 5424
            if b' 1 ' in sample[:100]: # Version 1 often in 5424
                return "LIQUEFY_V1_SYSLOG_5424"
            return "LIQUEFY_V1_SYSLOG_3164"

        # --- 6. VPC Flow Logs ---
        if re.match(rb'\d+ \d+ eni-\w+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sample):
            return "LIQUEFY_V1_VPCFLOW"

        # --- 7. Netflow ---
        if sample.startswith((b'\x00\x05', b'\x00\x09', b'\x00\x0a')): # Netflow v5, v9, IPFIX
            return "LIQUEFY_V1_NETFLOW"

        # --- 8. VMware / SCM / Others ---
        if b'vmware' in sample.lower() or b'vpxd' in sample.lower():
            return "LIQUEFY_V1_VMWARE"
        if b'github.com' in sample or b'git-receive-pack' in sample:
            return "LIQUEFY_V1_GITHUB"

        return "LIQUEFY_V1_MIXED"

    def compress(self, data: bytes, engine_key: str, tenant_id: str = "default", orig_filename: str = None) -> Tuple[bytes, str]:
        start_t = time.time()

        actual_engine_key = engine_key
        if engine_key == "LIQUEFY_V1_MIXED":
            actual_engine_key = self.detect_format(data)

        engine, proto_id = self._get_engine(actual_engine_key)

        # 1. Compress + Verify (Safety Valve)
        compressed_blob = Valve.seal(data, engine.compress, engine.decompress, proto_id[:4].ljust(4, b'\x00'))

        # 2. Encrypt + Isolate (Security Layer)
        if self.security is None:
            raise ValueError("MISSING_SECRET: pass security_secret for encrypted compress")
        secure_blob = self.security.seal(compressed_blob, tenant_id, {
            "engine": actual_engine_key,
            "orig_filename": orig_filename,
            "version": "1.0",
            "safety": self.safety_enabled
        })

        duration_ms = (time.time() - start_t) * 1000
        Vision.track_op(actual_engine_key, tenant_id, len(data), len(secure_blob), duration_ms)
        Vision.add_trace("COMPRESS", {"engine": actual_engine_key, "tenant": tenant_id, "size": len(data)})

        return secure_blob, actual_engine_key

    def decompress(self, secure_blob: bytes, tenant_id: str = "default") -> Tuple[bytes, Dict[str, Any]]:
        start_t = time.time()
        # 1. Auth & Decrypt
        if self.security is None:
            raise ValueError("MISSING_SECRET: pass security_secret for decrypt")
        compressed_blob, audit_meta = self.security.unseal(secure_blob, tenant_id)

        # 2. Decompress
        if not self.registry:
            for k in self.engines: self._get_engine(k)

        data = Valve.unseal(compressed_blob, self.registry)

        duration_ms = (time.time() - start_t) * 1000
        meta = audit_meta.get("meta", {})
        engine_key = meta.get("engine", "unknown")
        Vision.track_op(f"dec_{engine_key}", tenant_id, len(secure_blob), len(data), duration_ms)

        return data, audit_meta

    def compress_media(self, input_path: str, profile: str = "balanced") -> bytes:
        if not self.MEDIA_MOUNT_PATH.exists():
            raise RuntimeError("MEDIA_ENGINE_UNAVAILABLE: /opt/nulla_dreamwave not mounted.")

        input_file = Path(input_path)
        ext = input_file.suffix.lower()

        if ext == '.pdf':
            engine_script = self.MEDIA_MOUNT_PATH / "lazarus" / "cli.py"
        elif ext in {'.jpg', '.jpeg', '.png', '.webp', '.mp4', '.mov', '.avi'}:
            engine_script = self.MEDIA_MOUNT_PATH / "nebula" / "cli.py"
        else:
            raise ValueError(f"Unsupported media format for black-box engine: {ext}")

        if not engine_script.exists():
            raise RuntimeError(f"MEDIA_ENGINE_MISSING: {engine_script} not found on mount.")

        tmp_out = input_file.with_suffix('.pdx.tmp')
        cmd = [
            "python3",
            str(engine_script),
            "--profile", profile,
            "--input", str(input_file),
            "--output", str(tmp_out)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, check=True)
            if tmp_out.exists():
                with open(tmp_out, 'rb') as f:
                    payload = f.read()
                os.remove(tmp_out)
                return payload
            return result.stdout
        except Exception as e:
            raise RuntimeError(f"MEDIA_ENGINE_FAILURE: {str(e)}")

    def get_stats(self) -> dict:
        return Vision.get_stats()
