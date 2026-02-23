#!/usr/bin/env python3
"""
In-Process Driver
=================
Loads core Python engine classes and runs compress() in a thread pool.
Only used for engines under engines/core/.
"""

import asyncio
from typing import Any, Dict
from orchestrator.contracts import EngineManifest
from orchestrator.engine_map import get_engine_instance


class InProcessDriverError(RuntimeError):
    ...


async def execute_inprocess(engine: EngineManifest, filepath: str) -> Dict[str, Any]:
    """
    Loads the engine class, reads the file, and runs compress().
    Returns a result dict with compression stats.
    """
    instance = get_engine_instance(engine.id)
    if instance is None:
        raise InProcessDriverError(f"Engine '{engine.id}' could not be loaded.")

    if not hasattr(instance, "compress"):
        raise InProcessDriverError(f"Engine '{engine.id}' has no compress() method.")

    # Read file bytes
    with open(filepath, "rb") as f:
        raw_data = f.read()

    original_bytes = len(raw_data)

    # Run compression in thread pool (engines are CPU-bound sync code)
    compressed = await asyncio.to_thread(instance.compress, raw_data)

    compressed_bytes = len(compressed) if compressed else 0

    return {
        "ok": True,
        "engine_used": engine.id,
        "original_bytes": original_bytes,
        "compressed_bytes": compressed_bytes,
        "ratio": round(original_bytes / compressed_bytes, 2) if compressed_bytes > 0 else 0,
        "compressed_data": compressed,
    }
