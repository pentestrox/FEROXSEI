#!/bin/bash
# ── FEROXSEI OSINT — Start script ──────────────────────────────────────────
# Usage:
#   bash start.sh              # build images and start all services
#   bash start.sh --no-build   # start without rebuilding images (fast restart)
#   bash start.sh --logs       # tail logs after start
set -e
cd "$(dirname "$0")"

GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; CYN='\033[0;36m'
BLU='\033[0;34m'; MAG='\033[0;35m'; WHT='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'

NO_BUILD=0; TAIL_LOGS=0
for arg in "$@"; do
  case $arg in
    --no-build) NO_BUILD=1 ;;
    --logs)     TAIL_LOGS=1 ;;
  esac
done

# ── logo ──────────────────────────────────────────────────────
echo ""
echo -e "${CYN}${BOLD}"
printf '\033[1;32m'   # bright green
cat <<'EOF'
 _____  _____  ____    ___  __  __ ____   _____  ___ 
|  ___||  ___||  _ \  / _ \ \ \/ // ___| |  ___||_ _|
| |_   |  _|  | |_) || | | | \  / \___ \ |  _|   | | 
|  _|  | |___ |  _ < | |_| | /  \  ___) || |___  | | 
|_|    |_____||_| \_\ \___/ /_/\_\|____/ |_____||___|
EOF
printf '\033[0m'      # reset
echo -e "${NC}${MAG}${BOLD}"
echo "  ___  ____  ___ _   _ _____"
echo " / _ \/ ___|_ _| \ | |_   _|"
echo "| | | \___ \| ||  \| | | |"
echo "| |_| |___) | || |\  | | |"
echo " \___/|____/___|_| \_| |_|"
echo -e "${NC}"
echo -e "${WHT}  Autonomous OSINT Intelligence Platform  |  by PentestRox${NC}"
echo    "  ─────────────────────────────────────────────────────────"
echo ""

# ── Detect compose command ──────────────────────────────────────────────
if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
  echo -e "${GRN}[+]${NC} Docker Compose v2 detected"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
  echo -e "${YLW}[!]${NC} docker-compose v1 (legacy) — upgrade: sudo apt install docker-compose-plugin -y"
else
  echo -e "${RED}[-]${NC} Docker not found. Install: https://docs.docker.com/engine/install/"
  exit 1
fi

# ── Stop and remove stale containers ───────────────────────────────────
echo ""
echo -e "${CYN}[1/3]${NC} Cleaning up stale containers..."
$COMPOSE down --remove-orphans 2>/dev/null || true
docker rm -f feroxsei-osint feroxsei-tor feroxsei-mailhog 2>/dev/null || true

# ── Build and start ─────────────────────────────────────────────────────
echo ""
if [ "$NO_BUILD" -eq 1 ]; then
  echo -e "${CYN}[2/3]${NC} Starting services (skipping rebuild)..."
  $COMPOSE up -d
else
  echo -e "${CYN}[2/3]${NC} Building images and starting services..."
  echo    "       First build: ~3-5 min (downloads Chromium + dependencies)"
  $COMPOSE up --build -d
fi

# ── Wait for app readiness ──────────────────────────────────────────────
echo ""
echo -e "${CYN}[3/3]${NC} Waiting for FEROXSEI OSINT to be ready..."
for i in $(seq 1 40); do
  if curl -s http://localhost:5001 >/dev/null 2>&1; then
    echo ""
    echo -e "${GRN}${BOLD}"
    echo    "╔══════════════════════════════════════════════════════════════╗"
    echo    "║                                                              ║"
    echo    "║   [OK]  FEROXSEI OSINT is running!                           ║"
    echo    "║                                                              ║"
    echo    "╠══════════════════════════════════════════════════════════════╣"
    echo    "║                                                              ║"
    printf  "║   App      >>  %-46s║\n" "http://localhost:5001"
    printf  "║   MailHog  >>  %-46s║\n" "http://localhost:8025"
    echo    "║                                                              ║"
    echo    "╠══════════════════════════════════════════════════════════════╣"
    echo    "║                                                              ║"
    echo    "║   First run:  http://localhost:5001/register                 ║"
    echo    "║   License:    http://localhost:5001/license                  ║"
    echo    "║                                                              ║"
    echo    "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Container status:"
    $COMPOSE ps
    echo ""
    echo -e "${CYN}Useful commands:${NC}"
    echo "  $COMPOSE logs -f feroxsei      # live app logs"
    echo "  $COMPOSE logs -f mailhog    # captured email logs"
    echo "  bash stop.sh                # stop all services"
    echo "  bash clear.sh               # remove containers + images"
    echo "  bash clear.sh --volumes     # full wipe including database"
    echo ""
    if [ "$TAIL_LOGS" -eq 1 ]; then
      echo "Tailing logs (Ctrl+C to exit)..."
      $COMPOSE logs -f
    fi
    exit 0
  fi
  printf "  Waiting... (%d/40)\r" "$i"
  sleep 3
done

echo ""
echo -e "${YLW}[!]${NC} App did not respond after 120s. Check logs:"
echo "    $COMPOSE logs feroxsei"
exit 1
