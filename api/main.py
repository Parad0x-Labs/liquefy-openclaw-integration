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
import hashlib
import hmac
import urllib.parse
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Form, Request, Depends, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
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

# CORS restricted to explicit origins (comma-separated env override; no wildcards)
_cors_origins = [o.strip() for o in os.environ.get(
    "LIQUEFY_CORS_ORIGINS", "http://localhost:3000"
).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Setup Directories
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Upload size cap (default 512 MB, env-overridable)
MAX_UPLOAD_BYTES = int(os.environ.get("LIQUEFY_MAX_UPLOAD_MB", "512")) * 1024 * 1024

# --- ROUTES ---

def get_auth_key(authorization: Optional[str] = Header(None)) -> str:
    """Require a Bearer key matching LIQUEFY_API_KEY. Fail-closed: the data
    endpoints stay disabled until LIQUEFY_API_KEY is configured."""
    expected = os.environ.get("LIQUEFY_API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="API disabled: LIQUEFY_API_KEY not configured")
    provided = None
    if authorization and authorization.startswith("Bearer "):
        provided = authorization.split(" ", 1)[1]
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return provided

def sanitize_filename(name: Optional[str]) -> str:
    """Reduce a client-supplied filename to a safe basename."""
    if not name:
        return "upload.bin"
    base = name.replace("\\", "/").split("/")[-1]
    safe = "".join(c for c in base if c.isalnum() or c in "._- ").strip()
    return safe or "upload.bin"

def save_upload(file: UploadFile, dest: Path) -> None:
    """Stream an upload to disk, enforcing MAX_UPLOAD_BYTES."""
    written = 0
    try:
        with open(dest, "wb") as buffer:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Upload exceeds size limit")
                buffer.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise

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
    input_path = UPLOAD_DIR / f"{job_id}_{sanitize_filename(file.filename)}"
    save_upload(file, input_path)

    try:
        with open(input_path, "rb") as f:
            data = f.read()

        secure_blob, actual_engine = orch.compress(data, engine, tenant_id=tenant, orig_filename=sanitize_filename(file.filename))
        output_path = input_path.with_suffix(".null")
        with open(output_path, "wb") as f:
            f.write(secure_blob)

        ratio = len(data) / len(secure_blob)

        return {
            "status": "success",
            "job_id": job_id,
            "engine": actual_engine,
            "original_size": len(data),
            "compressed_size": len(secure_blob),
            "ratio": f"{ratio:.2f}x",
            "download_url": f"/api/archive/{output_path.name}"
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        # Do not retain plaintext input after processing
        input_path.unlink(missing_ok=True)

@app.post("/api/decompress")
async def decompress_log(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form("default"),
    api_key: Optional[str] = Depends(get_auth_key)
):
    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_{sanitize_filename(file.filename)}"
    save_upload(file, input_path)

    try:
        with open(input_path, "rb") as f:
            secure_blob = f.read()

        restored_data, audit_meta = orch.decompress(secure_blob, tenant_id=tenant)
        meta = audit_meta.get("meta", {})
        engine_used = meta.get("engine", "unknown")
        orig_filename = meta.get("orig_filename")

        if orig_filename:
            # Restore to original name but keep job_id prefix to prevent collisions
            output_path = UPLOAD_DIR / f"{job_id}_RESTORED_{sanitize_filename(orig_filename)}"
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
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        input_path.unlink(missing_ok=True)

@app.post("/api/compress/media")
async def compress_media(
    request: Request,
    file: UploadFile = File(...),
    profile: str = Form("balanced"),
    api_key: Optional[str] = Depends(get_auth_key)
):
    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_{sanitize_filename(file.filename)}"
    save_upload(file, input_path)

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
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        input_path.unlink(missing_ok=True)

@app.get("/api/archive/{name}")
def download_archive(name: str, api_key: str = Depends(get_auth_key)):
    """Authenticated download of processed artifacts (replaces the open static mount)."""
    safe_name = sanitize_filename(name)
    target = (UPLOAD_DIR / safe_name).resolve()
    if not str(target).startswith(str(UPLOAD_DIR.resolve()) + os.sep) or not target.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(str(target))

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
