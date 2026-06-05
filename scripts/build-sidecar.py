#!/usr/bin/env python3
"""Build the Python backend as a standalone executable via PyInstaller."""

import subprocess
import sys
from pathlib import Path

root = Path(__file__).parent

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--name", "mcp-scanner-backend",
    "--hidden-import", "scanner",
    "--hidden-import", "scanner.checks",
    "--hidden-import", "scanner.models",
    "--hidden-import", "scanner.reporter",
    "--hidden-import", "scanner.siem_export",
    "--hidden-import", "uvicorn",
    "--hidden-import", "uvicorn.logging",
    "--hidden-import", "uvicorn.loops",
    "--hidden-import", "uvicorn.loops.auto",
    "--hidden-import", "uvicorn.protocols",
    "--hidden-import", "uvicorn.protocols.http",
    "--hidden-import", "uvicorn.protocols.http.auto",
    "--hidden-import", "uvicorn.protocols.websockets",
    "--hidden-import", "uvicorn.protocols.websockets.auto",
    "--hidden-import", "fastapi",
    "--hidden-import", "starlette",
    "--hidden-import", "pydantic",
    "--hidden-import", "yaml",
    "--hidden-import", "click",
    "--hidden-import", "rich",
    str(root / "backend" / "main.py"),
]

print(f"[build] Running: {' '.join(cmd)}")
result = subprocess.run(cmd, cwd=str(root))
sys.exit(result.returncode)
