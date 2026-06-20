#!/bin/bash
# ── FEROXSEI OSINT — Full cleanup script ───────────────────────────────────
# Usage:
#   bash clear.sh              # remove containers + images (keeps data volumes)
#   bash clear.sh --volumes    # ALSO delete all data (osint.db, screenshots, etc.)
#   bash clear.sh --volumes --force   # same but skip confirmation prompt
cd "$(dirname "$0")"

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'

DELETE_VOLUMES=0; FORCE=0
for arg in "$@"; do
  case $arg in
    --volumes|-v) DELETE_VOLUMES=1 ;;
    --force|-f)   FORCE=1 ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   FEROXSEI OSINT — Docker Cleanup                           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Detect compose
if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  echo -e "${RED}[✗]${NC} Docker not found."
  exit 1
fi

# Warn about data deletion
if [ "$DELETE_VOLUMES" -eq 1 ]; then
  echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║  ⚠  DATA DELETION WARNING                                ║${NC}"
  echo -e "${RED}║                                                          ║${NC}"
  echo -e "${RED}║  --volumes will permanently delete:                      ║${NC}"
  echo -e "${RED}║    • osint.db  (all scans, findings, investigations)     ║${NC}"
  echo -e "${RED}║    • screenshots/, reports/, uploads/                    ║${NC}"
  echo -e "${RED}║    • All phishing campaign results                       ║${NC}"
  echo -e "${RED}║                                                          ║${NC}"
  echo -e "${RED}║  This CANNOT be undone.                                  ║${NC}"
  echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
  if [ "$FORCE" -eq 0 ]; then
    read -rp "   Type 'DELETE' to confirm permanent data deletion: " confirm
    if [ "$confirm" != "DELETE" ]; then
      echo ""
      echo "Aborted. No data was deleted."
      exit 0
    fi
    echo ""
  fi
fi

echo "[1/4] Stopping and removing containers..."
$COMPOSE down --remove-orphans 2>/dev/null || true
docker rm -f feroxsei-osint feroxsei-tor feroxsei-mailhog 2>/dev/null || true

echo "[2/4] Removing project images..."
# Remove images built by this compose project
COMPOSE_IMAGES=$($COMPOSE images -q 2>/dev/null || true)
if [ -n "$COMPOSE_IMAGES" ]; then
  echo "$COMPOSE_IMAGES" | xargs docker rmi -f 2>/dev/null || true
fi
# Also remove by maintainer label
docker images --filter "label=maintainer=FEROXSEI OSINT" -q | xargs docker rmi -f 2>/dev/null || true

echo "[3/4] Removing project networks..."
docker network rm "$(basename "$(pwd)")_feroxsei_net" 2>/dev/null || true
docker network prune -f 2>/dev/null || true

if [ "$DELETE_VOLUMES" -eq 1 ]; then
  echo -e "[4/4] ${RED}Deleting data volumes (all scan data will be lost)...${NC}"
  COMPOSE_PREFIX=$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_-')
  docker volume rm "${COMPOSE_PREFIX}_feroxsei_data" "${COMPOSE_PREFIX}_tor_data" 2>/dev/null || true
  docker volume prune -f 2>/dev/null || true
else
  echo "[4/4] Skipping volumes — data preserved."
  echo "      Use bash clear.sh --volumes to also delete scan data."
fi

# Optional: remove dangling images
docker image prune -f 2>/dev/null || true

echo ""
if [ "$DELETE_VOLUMES" -eq 1 ]; then
  echo -e "╔══════════════════════════════════════════════════════════╗"
  echo -e "║   ✅ Full wipe complete.                                 ║"
  echo -e "║   Containers, images, networks and data volumes removed. ║"
else
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║   ✅ Cleanup complete.                                   ║"
  echo "║   Containers + images removed. Data volumes preserved.  ║"
fi
echo "╠══════════════════════════════════════════════════════════╣"
echo "║   Run: bash start.sh   to rebuild and start fresh        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
