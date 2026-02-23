#!/usr/bin/env python3
"""
External Binary Driver
=====================
Runs compression via external CLI executables.
Args are always passed as a list — never uses shell=True.
"""

import asyncio
import subprocess
from typing import Any, Dict
from orchestrator.contracts import EngineManifest


class BinaryDriverError(RuntimeError):
    ...


async def execute_binary(engine: EngineManifest, filepath: str) -> Dict[str, Any]:
    """
    Runs the external binary with --input <filepath>.
    Expects the binary to write output and return 0 on success.
    """
    if not engine.cmd:
        raise BinaryDriverError(f"Engine '{engine.id}' has no cmd defined.")

    args = list(engine.cmd) + ["--input", filepath]

    proc = await asyncio.to_thread(
        subprocess.run,
        args,
        capture_output=True,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        raise BinaryDriverError(
            f"Binary '{engine.id}' failed (exit {proc.returncode}): {proc.stderr[:300]}"
        )

    out = proc.stdout.strip()
    return {
        "ok": True,
        "engine_used": engine.id,
        "stdout": out[:500],
    }
