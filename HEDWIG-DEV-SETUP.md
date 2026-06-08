# Hedwig Dev Environment Setup for MCP Scanner GUI

## What This Sets Up

A complete Windows dev environment on Hedwig for building Tauri + Python desktop apps:

- **Rust** (cargo, rustc) — Tauri's native layer
- **Tauri CLI** — scaffolding and builds
- **Python 3.12** — backend sidecar
- **PyInstaller** — Python → .exe packaging
- **VS Code** (optional) — with Rust + Python extensions
- **WebView2** — Tauri's web renderer (usually pre-installed on Win 10/11)

## Automated Setup Script

Save the following as `C:\Users\Hedwig\setup-dev-env.ps1` and run in PowerShell as admin.

```powershell
# setup-dev-env.ps1 — Hedwig Dev Environment for Tauri + Python
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "=== Hedwig Dev Environment Setup ===" -ForegroundColor Cyan

# 1. Chocolatey (package manager)
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# 2. Git (if not present)
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Git..." -ForegroundColor Yellow
    choco install git -y
}

# 3. Python 3.12
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Python 3.12..." -ForegroundColor Yellow
    choco install python -y
}
python -m pip install --upgrade pip
pip install pyinstaller fastapi uvicorn python-multipart click pyyaml rich

# 4. Rust
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Rust..." -ForegroundColor Yellow
    choco install rustup -y
    rustup default stable
}

# 5. Node.js (for Tauri CLI)
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Node.js LTS..." -ForegroundColor Yellow
    choco install nodejs-lts -y
}

# 6. Tauri CLI
Write-Host "Installing Tauri CLI..." -ForegroundColor Yellow
npm install -g @tauri-apps/cli

# 7. WebView2 Runtime (usually present on Win 10 20H2+ / Win 11)
$wv2 = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -ErrorAction SilentlyContinue
if (-not $wv2) {
    Write-Host "Installing WebView2 Runtime..." -ForegroundColor Yellow
    choco install microsoft-edge-webview2-runtime -y
}

# 8. VS Code (optional)
$installVsCode = Read-Host "Install VS Code? (y/n)"
if ($installVsCode -eq 'y') {
    choco install vscode -y
    code --install-extension rust-lang.rust-analyzer
    code --install-extension ms-python.python
    code --install-extension tauri-apps.tauri-vscode
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host "rustc:  $(rustc --version)"
Write-Host "cargo:  $(cargo --version)"
Write-Host "python: $(python --version)"
Write-Host "node:   $(node --version)"
Write-Host "npm:    $(npm --version)"
```

## Verifying the Environment

After setup, verify everything works:

```powershell
# Check all tools
rustc --version    # rustc 1.x.x
cargo --version    # cargo 1.x.x
python --version   # Python 3.12.x
node --version     # v20.x.x or v22.x.x
npm list -g @tauri-apps/cli  # @tauri-apps/cli@2.x.x
pip show pyinstaller  # Version: 6.x.x
```

## Developer Workflow

### Initial Project Setup (once)
```powershell
cd C:\Users\Hedwig\projects
git clone https://github.com/memyselfandaiandai/mcp-scanner-gui.git
cd mcp-scanner-gui

# Install Python deps
pip install -r backend/requirements.txt
pip install pyinstaller click pyyaml rich

# Build sidecar once
python scripts/build-sidecar.py  # or .ps1
```

### Daily Development Loop

**Terminal 1 — Python backend:**
```powershell
cd backend\
pip install -r requirements.txt
python main.py
# Runs on http://127.0.0.1:3030
```

**Terminal 2 — Tauri frontend:**
```powershell
cd src-tauri
npx tauri dev
# Opens dev window with hot reload
```

### Building a Release
```powershell
# On Hedwig, after both terminals are working:
.\scripts\build-sidecar.ps1   # Build Python → .exe
cd src-tauri
cargo tauri build             # Build .msi installer

# Output: src-tauri/target/release/bundle/msi/
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `cargo tauri build` fails with linker error | Install Visual Studio Build Tools: `choco install visualstudio2022-buildtools -y --add Microsoft.VisualStudio.Workload.VCTools` |
| WebView2 not found | Install: `choco install microsoft-edge-webview2-runtime -y` |
| PyInstaller can't find hidden imports | Add `--hidden-import=<module>` to build script |
| Port 1420 already in use | Kill old Tauri dev server: `netstat -ano \| findstr 1420` then `taskkill /PID <pid> /F` |
| Port 3030 already in use | Kill old Python backend: `netstat -ano \| findstr 3030` then `taskkill /PID <pid> /F` |
| Tauri can't find sidecar | Ensure `src-tauri/sidecar/mcp-scanner-backend.exe` exists after build |

## File System Layout on Hedwig

```
C:\Users\Hedwig\
├── projects\
│   └── mcp-scanner-gui\       # Main project
│       ├── backend\             # Python FastAPI
│       ├── src-tauri\           # Rust + Tauri
│       │   ├── sidecar\         # Compiled Python .exe goes here
│       │   ├── src\main.rs
│       │   └── Cargo.toml
│       ├── src\                 # Frontend HTML/CSS/JS
│       └── scripts\             # Build scripts
└── setup-dev-env.ps1           # This setup script
```
