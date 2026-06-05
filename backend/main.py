"""MCP Scanner GUI — Python FastAPI backend.

Serves as the bridge between the Tauri webview frontend and the mcp-scanner
library. Runs as a sidecar process spawned by Tauri, listening on localhost.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# mcp-scanner imports
from scanner.checks import run_checks
from scanner.models import MCPServer, ScanResult, Severity
from scanner.reporter import generate_json, generate_markdown
from scanner.siem_export import generate_export

app = FastAPI(title="MCP Scanner GUI Backend", version="0.1.0")

# CORS: allow requests from Tauri webview (localhost origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*", "tauri://localhost", "https://tauri.localhost"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store (sufficient for single-user desktop app)
_scan_store: dict[str, ScanResult] = {}


def _parse_config(path: str) -> list[MCPServer]:
    """Parse MCP config file into MCPServer objects."""
    import yaml

    p = Path(path)
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    servers_block = data.get("mcpServers", data)
    servers = []
    for name, config in servers_block.items():
        if isinstance(config, dict):
            servers.append(MCPServer.from_dict(name, config))
    return servers


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/scan")
async def scan_config(file: UploadFile = File(...)):
    """Upload an MCP config file and run a security scan."""
    scan_id = str(uuid.uuid4())

    # Save uploaded file to temp
    suffix = Path(file.filename or "config.json").suffix
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        servers = _parse_config(tmp_path)
        findings = run_checks(servers)
        result = ScanResult(
            target=file.filename or tmp_path,
            servers=servers,
            findings=findings,
        )
        _scan_store[scan_id] = result

        return {
            "scan_id": scan_id,
            "status": "complete",
            "summary": result.summary,
            "findings": [f.to_dict() for f in result.findings],
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@app.get("/api/results/{scan_id}")
async def get_results(scan_id: str):
    """Retrieve scan results by ID."""
    result = _scan_store.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "summary": result.summary,
        "findings": [f.to_dict() for f in result.findings],
    }


@app.get("/api/export/{scan_id}/{fmt}")
async def export_results(scan_id: str, fmt: str):
    """Export scan results in the specified format."""
    result = _scan_store.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    if fmt == "json":
        content = generate_json(result)
        media_type = "application/json"
        filename = "scan-results.json"
    elif fmt == "markdown":
        content = generate_markdown(result)
        media_type = "text/markdown"
        filename = "scan-results.md"
    elif fmt in ("cef", "leef", "syslog", "ndjson", "csv", "w3c"):
        content = generate_export(result, fmt)
        media_type = "text/plain"
        filename = f"scan-results.{fmt}"
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown format: {fmt}. Supported: json, markdown, cef, leef, syslog, ndjson, csv, w3c",
        )

    from fastapi.responses import Response
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=3030)
