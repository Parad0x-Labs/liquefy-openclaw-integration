#!/usr/bin/env python3
"""
Liquefy Main - [LIQUEFY V1 MASTER SERVER]
==========================================
MISSION: Unified Enterprise API for the Liquefy v1 Stack.
FEAT:    FastAPI, Orchestrator v1, Vision Observability, Fortress Security.
STATUS:  Production Grade - Verified Baseline.
"""

import os
import sys
import uuid
import time
import shutil
import hashlib
import urllib.parse
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Form, Request, Depends, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add current directory to path for engine imports
BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR))

try:
    from services.orchestrator import LiquefyOrchestrator
    from liquefy_observability import Vision
    from liquefy_verification import LiquefyVerificationSystem
except ImportError as e:
    print(f"CRITICAL ERROR: Missing Liquefy v1 components. Error: {e}")
    sys.exit(1)

# Initialize Core Stack (fail-closed: no implicit production default secret)
_master_key = os.environ.get("LIQUEFY_MASTER_KEY")
if not _master_key:
    raise SystemExit("MISSING_SECRET: set LIQUEFY_MASTER_KEY")
orch = LiquefyOrchestrator(safety_enabled=True, security_secret=_master_key)
verifier = LiquefyVerificationSystem()

app = FastAPI(title="Liquefy v1 Enterprise API")

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Directories
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Mount archive directory for downloads (most reliable way)
app.mount("/api/archive", StaticFiles(directory=str(UPLOAD_DIR)), name="archive")

# --- ROUTES ---

def get_auth_key(authorization: Optional[str] = Header(None)) -> Optional[str]:
    if authorization and authorization.startswith("Bearer "):
        return authorization.split(" ")[1]
    return None

@app.get("/")
def home():
    return FileResponse(str(BASE_DIR / "index.html"))

@app.get("/liquefy")
def liquefy_page():
    return FileResponse(str(BASE_DIR / "liquefy.html"))

@app.get("/media")
def media_page():
    return FileResponse(str(BASE_DIR / "media.html"))

@app.get("/api-docs")
def docs_page():
    return FileResponse(str(BASE_DIR / "docs.html"))

@app.get("/roadmap")
def roadmap_page():
    return FileResponse(str(BASE_DIR / "roadmap.html"))

@app.get("/token")
def token_page():
    return FileResponse(str(BASE_DIR / "token.html"))

@app.get("/null")
def null_page():
    return FileResponse(str(BASE_DIR / "null.html"))

@app.get("/health")
def health():
    return {
        "status": "OK",
        "version": "1.0",
        "stack": "Liquefy v1 (Black-Box)",
        "identity": orch.ai.get_identity(),
        "uploads_ready": UPLOAD_DIR.exists()
    }

@app.post("/api/compress/log")
async def compress_log(
    request: Request,
    file: UploadFile = File(...),
    engine: str = Form("LIQUEFY_V1_MIXED"),
    tenant: str = Form("default"),
    api_key: Optional[str] = Depends(get_auth_key)
):
    job_id = str(uuid.uuid4())
    # Sanitize filename for disk
    safe_filename = "".join([c for c in file.filename if c.isalnum() or c in "._- "]).strip()
    input_path = UPLOAD_DIR / f"{job_id}_{safe_filename}"

    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        with open(input_path, "rb") as f:
            data = f.read()

        secure_blob, actual_engine = orch.compress(data, engine, tenant_id=tenant, orig_filename=file.filename)
        output_path = input_path.with_suffix(".null")
        with open(output_path, "wb") as f:
            f.write(secure_blob)

        ratio = len(data) / len(secure_blob)

        # Point to the static mount
        return {
            "status": "success",
            "job_id": job_id,
            "engine": actual_engine,
            "original_size": len(data),
            "compressed_size": len(secure_blob),
            "ratio": f"{ratio:.2f}x",
            "download_url": f"/api/archive/{output_path.name}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/decompress")
async def decompress_log(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form("default"),
    api_key: Optional[str] = Depends(get_auth_key)
):
    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_{file.filename}"

    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        with open(input_path, "rb") as f:
            secure_blob = f.read()

        restored_data, audit_meta = orch.decompress(secure_blob, tenant_id=tenant)
        meta = audit_meta.get("meta", {})
        engine_used = meta.get("engine", "unknown")
        orig_filename = meta.get("orig_filename")

        if orig_filename:
            # Restore to original name but keep job_id prefix to prevent collisions
            safe_orig = "".join([c for c in orig_filename if c.isalnum() or c in "._- "]).strip()
            output_path = UPLOAD_DIR / f"{job_id}_RESTORED_{safe_orig}"
        else:
            # Fallback if no filename in metadata
            output_path = input_path.with_suffix(".restored")

        with open(output_path, "wb") as f:
            f.write(restored_data)

        return {
            "status": "success",
            "job_id": job_id,
            "engine": engine_used,
            "download_url": f"/api/archive/{output_path.name}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/compress/media")
async def compress_media(
    request: Request,
    file: UploadFile = File(...),
    profile: str = Form("balanced"),
    api_key: Optional[str] = Depends(get_auth_key)
):
    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        payload = orch.compress_media(str(input_path), profile=profile)
        output_path = input_path.with_suffix(".pdx")
        with open(output_path, 'wb') as f:
            f.write(payload)

        return {
            "status": "success",
            "job_id": job_id,
            "download_url": f"/api/archive/{output_path.name}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats():
    return Vision.get_stats()

# Placeholder routes for Next.js requirements
@app.get("/api/docs")
def get_docs():
    return {"docs": "Liquefy v1 Technical Documentation - Access Restricted."}

@app.get("/api/roadmap")
def get_roadmap():
    return {"roadmap": ["Liquefy v1 Deployed", "NULLA AI Integration", ".null Domain Support"]}

@app.get("/api/token")
def get_token_info():
    return {
        "symbol": "$NULL",
        "ca": os.environ.get("NEXT_PUBLIC_TOKEN_CA", "PENDING"),
        "utility": "Governance and specialized compute access."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
