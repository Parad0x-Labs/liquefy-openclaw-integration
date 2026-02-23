#!/usr/bin/env python3
"""
HTTP Driver
===========
Async client for enterprise engines running as external REST services.
Enforces connect and read timeouts.
"""
import httpx
import asyncio
from typing import Any, Dict
from orchestrator.contracts import EngineManifest


class DriverError(RuntimeError): ...

async def execute_http_driver(engine: EngineManifest, filepath: str) -> Dict[str, Any]:
    """Execute compression via an external HTTP service."""

    timeout = httpx.Timeout(connect=2.0, read=60.0, write=60.0, pool=2.0)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            with open(filepath, "rb") as f:
                resp = await client.post(
                    f"{engine.endpoint.rstrip('/')}/compress",
                    files={"file": f}
                )

        if resp.status_code != 200:
            raise DriverError(f"HTTP Service failed: {resp.status_code} {resp.text[:200]}")

        # Expecting Receipt Mode JSON response
        if "application/json" in resp.headers.get("content-type", ""):
            return resp.json()
        else:
            return {"ok": True, "note": "Binary stream received"}

    except httpx.RequestError as e:
        raise DriverError(f"HTTP Request failed for {engine.id}: {str(e)}")
