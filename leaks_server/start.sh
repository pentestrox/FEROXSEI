#!/usr/bin/env bash
# Start the FEROXSEI Leaks Server
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure Flask is available
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[!] Flask not found — installing..."
    pip install flask --break-system-packages -q
fi

echo "[*] Starting FEROXSEI Leaks Server..."
python3 feroxsei_leaks_server.py
