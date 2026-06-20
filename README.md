# FEROXSEI OSINT

**Autonomous white-box OSINT & phishing simulation platform for security professionals.**

FEROXSEI is a self-hosted intelligence platform that accepts a target - domain, URL, IP address, email, username, phone number, keyword, or image - fires 22 parallel analysis modules, stores every finding in SQLite with full chain-of-custody, and displays results in a live investigation workspace.

---
##Screenshots:
<img width="1377" height="792" alt="image" src="https://github.com/user-attachments/assets/b4ea168a-a99d-4d28-a843-40e3107614d4" />
<img width="1385" height="804" alt="image" src="https://github.com/user-attachments/assets/b5e90f5f-9084-43b0-89f3-2888e958e605" />


---

## Features

### OSINT Engine
- 22 parallel modules: DNS, SSL certs, web crawl, Git secrets, JS recon, cloud buckets, subdomain takeover, typosquatting, dark web, AI synthesis, and more
- Playwright headless Chromium - screenshot every page during crawl
- TOR anonymisation - all traffic routed via SOCKS5, DNS via Cloudflare DoH over TOR (no leaks)
- 110+ regex detection patterns - API keys, tokens, PII, CVEs, credentials
- Image OSINT - EXIF/GPS, OCR, AI vision (Claude), perceptual hash, Yandex reverse search
- Entity graph - D3.js force-directed relationship map built from every scan
- Investigation workspace - case management, multiple scans per case, analyst notes, timeline
- One-click HTML reports with all findings, screenshots, and evidence

### Phishing Simulation
- Authorised phishing campaigns with full ethical safeguards
- Campaign approval gate (admin must approve before launch)
- Open/click/submit tracking pixels + credential capture (passwords redacted server-side)
- Education redirect after click - targets see an awareness page, not credentials stored
- MailHog integration for safe local email testing without hitting real inboxes
- Scheduled campaign end date / auto-stop

### Platform
- Multi-user with role-based access control (admin / analyst)
- Per-user permission toggles for OSINT, phishing, audit log, TOR, leaks
- Immutable audit log with IP geolocation, entity graph, action stats
- Team chat with DMs, channels, emoji picker
- Notifications - scan and campaign completion alerts
- Credential leak search - search locally stored breach data files
- Remote leaks server - separate microservice for large datasets

---

## Modules

| # | Icon | Module | Target Types | Key Sources |
|---|------|--------|-------------|-------------|
| 1 | 🕰️ | Wayback Machine | domain, URL | archive.org CDX API |
| 2 | 📜 | Cert Transparency | domain | crt.sh, CertSpotter |
| 3 | 🌐 | DNS Recon | domain | A/MX/NS/TXT/SOA/CAA/DMARC/SPF, zone transfer, 60+ subdomain brute-force |
| 4 | 🛡️ | Security Headers | domain, URL | CSP, HSTS, X-Frame-Options scoring |
| 5 | 🔮 | Favicon Hash | domain, URL | MMH3 → Shodan fingerprint |
| 6 | 🕷️ | Web Crawler | domain, URL | Playwright - screenshots, forms, JS endpoints |
| 7 | 🖼️ | Image OSINT | image | EXIF/GPS, OCR, AI vision, pHash, Yandex reverse search |
| 8 | 📑 | Metadata Harvest | domain, URL | PDF/DOCX/XLSX author, GPS, creation tool |
| 9 | 🔓 | Git Leaks | domain, email | GitHub secret search, .env exposure, .git/ check |
| 10 | 🔬 | JS Recon | domain, URL | API keys, tokens, endpoints, S3 URLs (110+ patterns) |
| 11 | ☁️ | Cloud Exposure | domain | S3/GCS/Azure/DO bucket brute-force |
| 12 | 🔍 | Google Dork | domain, keyword | 20+ dork queries via DuckDuckGo |
| 13 | 📧 | Email Harvest | domain | web/WHOIS/crt.sh/GitHub + naming pattern inference |
| 14 | 👤 | Username Hunt | username | 40+ platforms (GitHub, Reddit, X, HackerNews…) |
| 15 | 🧬 | Identity Intel | email, username | WHOIS, HIBP breach checks, Gravatar, GitHub |
| 16 | 🗺️ | Infrastructure | domain, IP | ASN, BGP, geolocation, Shodan, cloud provider |
| 17 | 🎯 | Subdomain Takeover | domain | Dangling CNAMEs → GitHub Pages, Heroku, Fastly, S3 |
| 18 | ⚡ | Threat Intel | domain, IP, URL | URLhaus, VirusTotal, AbuseIPDB, AlienVault OTX |
| 19 | 🕳️ | Dark Web | domain, keyword | Ahmia.fi .onion search (TOR required) |
| 20 | 📱 | Social Media | domain, username | GitHub org crawl, LinkedIn, X, job postings tech stack |
| 21 | 🔍 | Typosquatting | domain | 100s of permutations → registered check → phishing detection |
| 22 | 🤖 | AI Analysis | all | Claude/GPT synthesis - threat narrative, attack surface map |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+ · Flask 3.x |
| Database | SQLite (auto-created, no setup) |
| Crawler | Playwright Chromium (headless) |
| Anonymisation | TOR SOCKS5 · Cloudflare DoH |
| Frontend | Vanilla JS · D3.js v7 · CSS variables |
| Container | Docker Compose · Playwright Python base image |
| Email test | MailHog (local SMTP capture) |

---

## Quick Start
<img width="925" height="639" alt="image" src="https://github.com/user-attachments/assets/331f09a0-4e59-4d6e-82e8-af42957f1429" />
<img width="1007" height="613" alt="image" src="https://github.com/user-attachments/assets/c9f35902-bb76-42b2-a993-428655dde931" />

```bash
# Clone / copy to your machine
cd FEROXSEI-OSINT

# (Optional) add API keys
cp .env.example .env
nano .env

# Launch
./start.sh

# Open
http://localhost:5001
username:password = admin:admin
```

First visit: register your admin account. Full setup guide → [SETUP.md](SETUP.md)

---

## API Keys

All keys are optional - modules degrade gracefully without them.

| Key | Used By | Free Tier |
|-----|---------|-----------|
| Anthropic | AI Analysis, Image OSINT vision | Yes (limited) |
| OpenAI | AI Analysis (fallback) | Yes (limited) |
| GitHub Token | Git Leaks, Social Media | Yes (public repos) |
| Shodan | Infrastructure, Favicon Hash | Yes (limited) |
| VirusTotal | Threat Intel | Yes (4 req/min) |
| Hunter.io | Identity Intel | Yes (25 req/month) |
| HaveIBeenPwned | Identity Intel | Paid |
| AbuseIPDB | Threat Intel | Yes (1000 req/day) |
| AlienVault OTX | Threat Intel | Yes |

Configure at `http://localhost:5001/settings`

---

## Legal & Ethics

- Only investigate targets you have explicit written authorisation to scan
- Phishing campaigns require admin approval and redirect targets to an awareness page after click - no credentials are stored
- TOR exit nodes are logged per-request - not a substitute for operational security
- All actions are audit-logged with timestamp, user, and IP address
- GDPR-aware: no PII stored beyond what is required for the investigation

---

## ☕ Buy Me a Coffee

If you find my work useful, consider supporting me!

| | Network | Address |
|---|---|---|
| [![BTC](https://img.shields.io/badge/BTC-orange?logo=bitcoin&logoColor=white)](https://mempool.space/address/bc1p2pwjyk64e6sm89pn9ksy3w4u8tmsxyfvfr4lpl9hjtememjzwv0qm55sq4) | Bitcoin Taproot | `bc1p2pwjyk64e6sm89pn9ksy3w4u8tmsxyfvfr4lpl9hjtememjzwv0qm55sq4` |
| [![ETH](https://img.shields.io/badge/ETH-blue?logo=ethereum&logoColor=white)](https://etherscan.io/address/0x6b36e02F7557D19C7D443fd7b5F7f4a45056e8A6) | Ethereum | `0x6b36e02F7557D19C7D443fd7b5F7f4a45056e8A6` |
| [![DOGE](https://img.shields.io/badge/DOGE-yellow?logo=dogecoin&logoColor=white)](https://dogechain.info/address/DDRqpMn3KfAQAkxUaSxWWAV4uNn5HCX5Qh) | Dogecoin | `DDRqpMn3KfAQAkxUaSxWWAV4uNn5HCX5Qh` |
