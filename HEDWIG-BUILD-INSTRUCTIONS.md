# Hedwig Build Instructions — MCP Scanner GUI

## Prerequisites Check

Open PowerShell on Hedwig and verify:

```powershell
# Should show: MyHedwig
whoami

# Should show: Python 3.11.15
python --version

# Should show: v24.15.0 (or similar)
node --version

# Should show: 1.96.0+ (or similar)
rustc --version

# Should show: @tauri-apps/cli@2.x.x
npm list -g @tauri-apps/cli
```

If any of these are missing, see "Setup" below.

## Setup (one-time, only if something above is missing)

```powershell
# 1. Install Rust (if not present)
winget install Rustlang.Rustup --accept-package-agreements --accept-source-agreements
rustup default stable

# 2. Install Tauri CLI (if not present)
npm install -g @tauri-apps/cli

# 3. Install Visual Studio Build Tools (needed for Rust compilation)
winget install Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements
# In the installer, check "Desktop development with C++" workload
```

## Clone the Project

```powershell
cd C:\Users\MyHedwig\projects

# If you already have an old clone, update it instead:
# cd mcp-scanner-gui
# git pull

git clone https://github.com/memyselfandaiandai/mcp-scanner-gui.git
cd mcp-scanner-gui
```

## Sync the Scanner Engine

```powershell
# Clone the latest scanner engine
git clone --depth 1 https://github.com/memyselfandaiandai/mcp-scanner.git C:\Users\MyHedwig\projects\tmp-mcp-scanner

# Copy scanner modules into backend
Remove-Item -Recurse -Force .\backend\scanner -ErrorAction SilentlyContinue
Copy-Item -Recurse -Force C:\Users\MyHedwig\projects\tmp-mcp-scanner\scanner .\backend\scanner

# Copy additional modules that are in the repo root (not in scanner/ subfolder)
# v2_checks.py, sarif_export.py, discovery.py are inside scanner/ and get copied above

# Cleanup
Remove-Item -Recurse -Force C:\Users\MyHedwig\projects\tmp-mcp-scanner
```

## Build the Python Sidecar

```powershell
# Install Python dependencies
pip install click pyyaml rich fastapi uvicorn python-multipart pyinstaller pydantic

# Build the sidecar executable (includes all checks + SIEM + SARIF)
pyinstaller --onefile `
  --name mcp-scanner-backend `
  --hidden-import=scanner `
  --hidden-import=scanner.checks `
  --hidden-import=scanner.models `
  --hidden-import=scanner.reporter `
  --hidden-import=scanner.siem_export `
  --hidden-import=scanner.sarif_export `
  --hidden-import=scanner.v2_checks `
  --hidden-import=scanner.discovery `
  --hidden-import=uvicorn `
  --hidden-import=fastapi `
  --hidden-import=starlette `
  --hidden-import=pydantic `
  --hidden-import=yaml `
  backend\main.py

# Copy sidecar to Tauri resources
New-Item -ItemType Directory -Force -Path src-tauri\sidecar
Copy-Item -Force dist\mcp-scanner-backend.exe src-tauri\sidecar\
```

## Test the Sidecar Alone

```powershell
# Should start the backend on http://127.0.0.1:3030
.\src-tauri\sidecar\mcp-scanner-backend.exe

# In another PowerShell window, test it:
Invoke-RestMethod -Uri "http://127.0.0.1:3030/api/health"
# Should return: {"status":"ok","version":"0.2.0"}
```

## Build the Full Tauri App (.msi installer)

```powershell
cd src-tauri

# First time: install Rust dependencies (takes a few minutes)
cargo build

# Build the release .msi installer
cargo tauri build
```

The installer will be at:
```
src-tauri\target\release\bundle\msi\MCP Scanner_0.2.0_x64_en-US.msi
```

## Development Loop (for ongoing work)

Terminal 1 — Python backend:
```powershell
cd C:\Users\MyHedwig\projects\mcp-scanner-gui\backend
pip install -r requirements.txt
python main.py
# Runs on http://127.0.0.1:3030
```

Terminal 2 — Tauri dev server:
```powershell
cd C:\Users\MyHedwig\projects\mcp-scanner-gui
npx tauri dev
# Opens dev window with hot reload
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `cargo build` fails with linker error | Install VS Build Tools with C++ workload (see Setup step 3) |
| `pyinstaller` command not found | `pip install pyinstaller` |
| Port 3030 already in use | `netstat -ano \| findstr 3030` then `taskkill /PID <pid> /F` |
| `npx tauri dev` can't find sidecar | Ensure `src-tauri/sidecar/mcp-scanner-backend.exe` exists |
| WebView2 errors | `winget install Microsoft.Edge.WebView2Runtime` |
| `git clone` is very slow | Normal on Hedwig — use shallow clone `--depth 1` |
| ModuleNotFoundError for scanner.* | Re-run the "Sync the Scanner Engine" step above |

## What Gets Produced

- **Sidecar**: `dist/mcp-scanner-backend.exe` (~85 MB, standalone Python+FastAPI with all check engines)
- **Installer**: `src-tauri/target/release/bundle/msi/MCP Scanner_0.2.0_x64_en-US.msi` (~90 MB)
- The installer bundles both the Tauri shell and the Python sidecar into one `.msi`
