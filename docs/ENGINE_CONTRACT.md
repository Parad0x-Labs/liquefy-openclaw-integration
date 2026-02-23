# Liquefy Engine Manifest & External Service Contract

This document outlines the strict API contract and manifest specification for building plugins or external enterprise engines for the Liquefy Orchestrator.

By adhering to this contract, you ensure that external engines (e.g., hardware-accelerated media compressors) can operate safely via a separate-process boundary, reducing coupling and keeping proprietary components completely independent of the core orchestrator.

## 1. `engine.json` Manifest Specification

Every external engine must provide an `engine.json` file inside the `engines/enterprise/{engine-name}/` folder.

```json
{
  "id": "parad0x-media-engine",
  "type": "external_service",
  "api_version": "1.0",
  "priority": 100,
  "capabilities": {
    "mimetypes": ["image/*", "video/*", "application/pdf"],
    "extensions": [".jpg", ".png", ".mp4", ".mov", ".pdf"]
  },
  "endpoint": "http://127.0.0.1:7788",
  "entrypoint": null,
  "cmd": null
}
```

### Security Rules:
*   Files in the `engines/enterprise` folder **MUST NOT** use the `inprocess` type. Doing so will cause the orchestrator to reject the manifest.
*   Wildcards are fully supported in `mimetypes` (e.g., `image/*`).

---

## 2. External Service REST API Contract (v1.0)

If your manifest declares `"type": "external_service"`, your engine must expose the following HTTP endpoints.

### A. Health Check
*   **Method:** `GET /health`
*   **Response:** `200 OK`
*   **Body:** `{"status": "ready", "version": "1.0"}`

### B. Compression Endpoint (Receipt Mode)
*   **Method:** `POST /compress`
*   **Content-Type:** `multipart/form-data`
*   **Fields:**
    *   `file` (bytes): The raw file stream.
    *   `metadata` (string, optional): JSON metadata passed by Orchestrator.

**Success Response (200 OK):**
```json
{
  "ok": true,
  "engine_used": "parad0x-media-engine-v1.4",
  "original_bytes": 104857600,
  "compressed_bytes": 1048576,
  "output_path": "/mnt/shared_volume/archive_01.null"
}
```

*(Note: Ensure `output_path` points to an allowed directory mounted between the orchestrator and the engine container, e.g., `/mnt/shared_volume/`)*

---

### Reference Implementation (FastAPI Starter)
If you are building an enterprise engine in Python, use this stub:

```python
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
import hashlib, os

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ready", "version": "1.0"}

@app.post("/compress")
async def compress(file: UploadFile = File(...), metadata: str | None = Form(None)):
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()

    # Apply proprietary compression here
    out_path = f"/mnt/shared_volume/{file.filename}.null"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)

    return JSONResponse({
        "ok": True,
        "engine_used": "example-engine-v1.0",
        "original_bytes": len(data),
        "compressed_bytes": os.path.getsize(out_path),
        "sha256_original": sha,
        "output_path": out_path
    })
```
