# Build the Python sidecar for Windows via PyInstaller
# Run on Windows (e.g., Hedwig) with Python 3.11+

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=== Installing dependencies ===" -ForegroundColor Cyan
& pip install -r "$ProjectRoot\backend\requirements.txt"
& pip install pyinstaller

Write-Host "=== Building sidecar ===" -ForegroundColor Cyan
& pyinstaller --onefile `
  --name mcp-scanner-backend `
  --hidden-import=scanner `
  --hidden-import=scanner.checks `
  --hidden-import=scanner.models `
  --hidden-import=scanner.reporter `
  --hidden-import=scanner.siem_export `
  --hidden-import=uvicorn `
  --hidden-import=uvicorn.logging `
  --hidden-import=uvicorn.loops `
  --hidden-import=uvicorn.loops.auto `
  --hidden-import=fastapi `
  --hidden-import=starlette `
  --hidden-import=pydantic `
  --hidden-import=yaml `
  --hidden-import=click `
  --hidden-import=rich `
  "$ProjectRoot\backend\main.py"

Write-Host "=== Copying to Tauri resources ===" -ForegroundColor Cyan
$sidecarDir = "$ProjectRoot\src-tauri\sidecar"
New-Item -ItemType Directory -Force -Path $sidecarDir | Out-Null
Copy-Item -Force "$ProjectRoot\dist\mcp-scanner-backend.exe" "$sidecarDir\mcp-scanner-backend.exe"

Write-Host "=== Sidecar built OK ===" -ForegroundColor Green
Write-Host "Next: cd src-tauri; cargo tauri build"
