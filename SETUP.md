# FEROXSEI OSINT - Setup Guide

> **Authorized Use Only.** Only scan systems you own or have written permission to test.

---

## Option A - Kali Linux (Direct, No Docker)

Fastest setup. Runs natively on Kali with your system Python.

### 1. Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-pip git tor nmap dnsutils whois \
  tesseract-ocr tesseract-ocr-eng proxychains4
```

### 2. Clone / Copy the project

```bash
cd ~/Desktop
# If you have the folder already, skip this
git clone <your-repo-url> FEROXSEI
cd FEROXSEI
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 4. Install Playwright + Chromium (headless browser)

```bash
playwright install chromium
playwright install-deps chromium
```

> **Headless browser guide:** Playwright drives a real Chromium instance invisibly in the background.
> The `webCrawl` and `imageOsint` modules use it for screenshots, JS rendering, and reverse image search.
> No display required - it runs fully headless.
>
> Verify it works:
> ```bash
> python3 -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); print('Chromium OK'); b.close(); p.stop()"
> ```

### 5. Start TOR (optional - for Anonymous Mode)

```bash
sudo systemctl start tor
sudo systemctl enable tor   # auto-start on boot
```

Verify: `curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip`
You should see `"IsTor": true`.

### 6. Run the app

```bash
python3 feroxsei_osint.py
```

Open **http://127.0.0.1:5001** - first run shows the Register page.

### 7. Optional API keys

Create a `.env` file or set environment variables before running:

```bash
export ANTHROPIC_KEY="sk-ant-..."        # AI OSINT synthesis (aiOsint module)
export OPENAI_KEY="sk-..."               # Alternative AI synthesis
export GITHUB_TOKEN="ghp_..."            # Git leak scanning, social media
export SHODAN_KEY="..."                  # Infrastructure + favicon fingerprint
export VIRUSTOTAL_KEY="..."              # Threat intelligence
export HUNTER_KEY="..."                  # Email harvest identity
export HIBP_KEY="..."                    # Have I Been Pwned breach checks
export OTX_KEY="..."                     # AlienVault OTX threat intel
export ABUSEIPDB_KEY="..."              # AbuseIPDB reputation

python3 feroxsei_osint.py
```

All keys are optional - modules degrade gracefully without them.

---

## Option B - Windows (via WSL2 + Docker)

Docker on Windows requires WSL2. The app runs inside Docker exactly as on Linux.

### 1. Enable WSL2

Open PowerShell as Administrator:

```powershell
wsl --install
```

Restart your PC when prompted. This installs Ubuntu by default.

If WSL is already installed but not WSL2:
```powershell
wsl --set-default-version 2
```

Verify: `wsl --list --verbose` - should show `VERSION 2`.

### 2. Install Docker Desktop

Download from: **https://www.docker.com/products/docker-desktop/**

During install, make sure **"Use WSL 2 based engine"** is checked.

After install, open Docker Desktop → Settings → Resources → WSL Integration → enable your distro.

Verify in PowerShell: `docker run hello-world`

### 3. Copy the project into WSL

Option A - copy from Windows into WSL:
```bash
# Inside WSL terminal (Ubuntu)
cp -r /mnt/c/Users/YourName/Downloads/OSINT-Prod ~/feroxsei-osint
cd ~/feroxsei-osint
```

Option B - clone directly in WSL:
```bash
git clone <your-repo-url> ~/feroxsei-osint
cd ~/feroxsei-osint
```

> **Performance tip:** Always keep the project files inside WSL (`~/...`), not on the Windows filesystem (`/mnt/c/...`). Docker volume mounts to `/mnt/c/` are 10–20× slower.

### 4. Start the app

```bash
cd ~/feroxsei-osint
bash start.sh
```

First build downloads ~2 GB (Playwright + Chromium + dependencies) - takes 3–5 minutes once.

Open **http://localhost:5001** in your Windows browser.

### 5. Useful commands

```bash
bash start.sh              # build + start (first time)
bash start.sh --no-build   # restart without rebuilding (after code changes)
bash start.sh --logs       # start and tail live logs
bash stop.sh               # stop all containers (data is preserved)
bash clear.sh              # remove containers + images
bash clear.sh --volumes    # full wipe including database
```

### 6. MailHog (test emails)

Phishing campaign emails are captured locally - nothing reaches real inboxes during testing.

- **Web UI:** http://localhost:8025
- **SMTP:** localhost:1025

---

## Docker Reference (Kali + Windows)

| Container | Purpose | Port |
|-----------|---------|------|
| `feroxsei-osint` | Main app | 5001 |
| `feroxsei-tor` | TOR proxy | internal only |
| `feroxsei-mailhog` | Email capture | 8025 web, 1025 SMTP |

```bash
# Live logs
docker compose logs -f feroxsei

# Restart app only (picks up code changes)
docker compose restart feroxsei

# Open shell inside container
docker compose exec feroxsei bash

# Check TOR status
docker compose exec feroxsei curl --socks5 tor:9050 https://check.torproject.org/api/ip
```

---

## First Run

1. Go to **http://localhost:5001** (or **http://127.0.0.1:5001** on Kali direct)
2. Click **Register** → create your admin account
3. Log in → you're in

---

## Headless Browser Notes

The `webCrawl` module uses Playwright Chromium to take real screenshots of targets.

| Mode | How screenshots work |
|------|---------------------|
| Kali direct | Chromium runs headless, screenshots saved to `screenshots/` |
| Docker | Chromium is pre-installed in the container image (mcr.microsoft.com/playwright/python) |
| WSL2 | Docker handles Chromium - no extra setup needed |

To verify screenshots are working after a scan: check the **Web Crawl** findings tab for embedded screenshots.

---

## TOR Anonymous Mode

| Mode | How to enable |
|------|--------------|
| Kali direct | `sudo systemctl start tor` then toggle in app header |
| Docker | TOR container starts automatically - toggle in app header |

The app header shows a **🔴 Direct** / **🟢 TOR** badge. Click it to toggle.
Exit IP is shown when TOR is active.

---

## License

MIT License - see `LICENSE` file or visit `/license` in the app.
This software is provided **as-is** for authorized security testing only.
The author accepts no liability for misuse. **Use at your own risk.**
