#!/usr/bin/env bash
# Build the full Tauri application (macOS/Linux)
# Prerequisites: Rust, Tauri CLI (npm i -g @tauri-apps/cli), Python + PyInstaller

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Building Python sidecar ==="
cd "$PROJECT_ROOT/backend"
pip install -r requirements.txt
pip install pyinstaller
python "$PROJECT_ROOT/scripts/build-sidecar.py"

echo "=== Copying sidecar to Tauri resources ==="
mkdir -p "$PROJECT_ROOT/src-tauri/sidecar"
if [[ "$(uname)" == "Darwin" ]]; then
  cp "$PROJECT_ROOT/dist/mcp-scanner-backend" "$PROJECT_ROOT/src-tauri/sidecar/"
elif [[ "$(uname)" == "Linux" ]]; then
  cp "$PROJECT_ROOT/dist/mcp-scanner-backend" "$PROJECT_ROOT/src-tauri/sidecar/"
fi

echo "=== Building Tauri app ==="
cd "$PROJECT_ROOT/src-tauri"
cargo tauri build

echo "=== Done ==="
echo "Bundle location: src-tauri/target/release/bundle/"
