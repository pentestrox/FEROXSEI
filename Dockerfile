# ╔══════════════════════════════════════════════════════════════════╗
# ║   FEROXSEI OSINT — Dockerfile                                       ║
# ║   Base: Microsoft Playwright Python image (Chromium pre-baked)   ║
# ╚══════════════════════════════════════════════════════════════════╝
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

LABEL maintainer="FEROXSEI OSINT" \
      description="Autonomous OSINT Scanner with headless browser & TOR support" \
      version="2.0"

# ── System dependencies ────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      tor \
      curl \
      nmap \
      dnsutils \
      whois \
      proxychains4 \
      libpq-dev \
      tesseract-ocr \
      tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Playwright browsers already in base image; install deps ────────
RUN playwright install-deps chromium 2>/dev/null || true

# ── App source ────────────────────────────────────────────────────
COPY . .

# ── Persistent data directories ────────────────────────────────────
RUN mkdir -p /data/screenshots /data/reports /data/uploads

# ── TOR config for standalone mode (no separate tor container) ─────
RUN mkdir -p /var/lib/tor /run/tor && \
    echo "SocksPort 0.0.0.0:9050\nControlPort 0.0.0.0:9051\nDataDirectory /var/lib/tor\nLog notice stdout" \
    > /etc/tor/torrc && \
    chown -R debian-tor:debian-tor /var/lib/tor /run/tor 2>/dev/null || true

# ── Entrypoint script ──────────────────────────────────────────────
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5001

VOLUME ["/data"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python3", "feroxsei_osint.py"]
