# MCP Security Scanner GUI

A desktop application wrapping [mcp-scanner](https://github.com/coryabarham/mcp-scanner)
with a modern web-based GUI, built with **Tauri** (Rust) + **Python** backend.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Tauri Desktop Shell (Rust)                     │
│  ┌───────────────────────────────────────────┐  │
│  │  Webview (HTML/CSS/JS)                    │  │
│  │  - File picker for MCP config files       │  │
│  │  - Scan progress & results dashboard      │  │
│  │  - Severity filter / search               │  │
│  │  - Export buttons (JSON, MD, SIEM)        │  │
│  └──────────────────┬────────────────────────┘  │
│                     │  HTTP (localhost)          │
│  ┌──────────────────▼────────────────────────┐  │
│  │  Python Backend (FastAPI)                 │  │
│  │  - Compiled to .exe via PyInstaller       │  │
│  │  - Runs as Tauri sidecar process          │  │
│  │  - Wraps mcp-scanner CLI logic            │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
mcp-scanner-gui/
├── src-tauri/              # Rust + Tauri application
│   ├── src/
│   │   └── main.rs         # Spawns Python sidecar, handles IPC
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── icons/
├── src/                    # Frontend (HTML/CSS/JS)
│   ├── index.html
│   ├── style.css
│   └── app.js
├── backend/                # Python FastAPI server
│   ├── main.py             # API endpoints
│   ├── scanner_wrapper.py  # Wraps mcp-scanner library
│   └── requirements.txt
├── scripts/
│   ├── build-sidecar.sh    # PyInstaller build for Linux
│   ├── build-sidecar.ps1   # PyInstaller build for Windows
│   └── build-all.sh        # Full Tauri build
├── .github/workflows/
│   └── build-release.yml   # CI: build sidecar + Tauri installer
└── README.md
```

## API Contract (Python ↔ Frontend)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Upload config file, run scan |
| `GET` | `/api/results/{id}` | Get scan results by ID |
| `GET` | `/api/export/{id}/{fmt}` | Export results (json/md/cef/...) |
| `GET` | `/api/health` | Backend health check |

### POST /api/scan

Request: `multipart/form-data` with `config` file
```json
Response: {
  "scan_id": "uuid",
  "status": "complete",
  "summary": {
    "servers_scanned": 3,
    "total_findings": 7,
    "severity_counts": { "CRITICAL": 1, "HIGH": 2, ... }
  },
  "findings": [...]
}
```

## Development

### Prerequisites (Windows dev machine)
- Rust + Cargo: `rustup-init.exe`
- Tauri CLI: `npm install -g @tauri-apps/cli`
- Python 3.11+: with `pip install fastapi uvicorn mcp-scanner`
- WebView2: included with Windows 10/11

### Local dev workflow
```bash
# Terminal 1: Python backend
cd backend/
pip install -r requirements.txt
uvicorn main:app --reload --port 3030

# Terminal 2: Tauri frontend
npm install
npm run tauri dev
```

### Building for release
```bash
# Build Python sidecar
./scripts/build-sidecar.ps1

# Build Tauri app (produces .msi installer)
npm run tauri build
```

## License

MIT
