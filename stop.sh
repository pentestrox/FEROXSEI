#!/bin/bash
# ── FEROXSEI OSINT — Stop script ───────────────────────────────────────────
cd "$(dirname "$0")"

GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   FEROXSEI OSINT — Stopping                                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  echo -e "${RED}[✗]${NC} Docker not found."
  exit 1
fi

echo "Stopping all services..."
$COMPOSE down --remove-orphans 2>/dev/null || true
docker rm -f feroxsei-osint feroxsei-tor feroxsei-mailhog 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅ All services stopped.                               ║"
echo "║   Data in Docker volumes is preserved.                  ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║   bash start.sh           — restart                      ║"
echo "║   bash start.sh --no-build — restart without rebuilding  ║"
echo "║   bash clear.sh           — remove containers + images   ║"
echo "║   bash clear.sh --volumes — full wipe including data     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
