#!/bin/bash
# ── FEROXSEI OSINT — Docker entrypoint ───────────────────────────────
set -e

# ── Symlink data dirs so DB + screenshots persist across restarts ──
ln -sf /data/osint.db    /app/osint.db    2>/dev/null || true
ln -sf /data/screenshots /app/screenshots 2>/dev/null || true
ln -sf /data/reports     /app/reports     2>/dev/null || true

# ── Start TOR (background) if not using external service ──────────
if [ "${TOR_EXTERNAL:-0}" != "1" ]; then
  echo "[FEROXSEI] Starting built-in TOR daemon..."
  service tor start 2>/dev/null || tor --quiet --RunAsDaemon 1 2>/dev/null || true
  # Wait for SOCKS port
  for i in $(seq 1 15); do
    if curl -s --socks5 127.0.0.1:9050 --max-time 2 https://check.torproject.org >/dev/null 2>&1; then
      echo "[FEROXSEI] TOR ready ✓"
      break
    fi
    echo "[FEROXSEI] Waiting for TOR... ($i/15)"
    sleep 2
  done
else
  echo "[FEROXSEI] Using external TOR at ${TOR_SOCKS_HOST:-tor}:${TOR_SOCKS_PORT:-9050}"
fi

echo "[FEROXSEI] Starting FEROXSEI OSINT on port 5001..."
exec "$@"
