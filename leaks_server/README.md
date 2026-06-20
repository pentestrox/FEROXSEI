# FEROXSEI Leaks Server - Setup & Connection Guide

Standalone credential search microservice. Runs **on the Kali host** (not in Docker).
FEROXSEI app (in Docker) connects to it via the Docker bridge network.

---

## Quick Start

```bash
cd /home/kali/Desktop/FEROXSEI/leaks_server
./start.sh
```

The server starts on port **5002** and prints your API key on startup.

---

## Data Directory Layout

Place credential files in the `data/` subdirectory of the leaks server, or add any external directory via Settings → Leaks.

Supported file formats:
- Files with `.txt` extension: `data/a.txt`, `data/b.txt`
- Files with **no extension**: `data/a/a`, `data/b/c`
- Subdirectories are walked recursively

```
leaks_server/
├── data/
│   ├── a.txt          ← email:password lines starting with 'a'
│   ├── b.txt
│   ├── rockyou/
│   │   └── part1      ← no extension - also searched
│   └── combo/
│       ├── 01.txt
│       └── 02.txt
├── config.json        ← auto-generated; holds API key + configured dirs
├── feroxsei_leaks_server.py
├── start.sh
└── README.md          ← this file
```

File format - one credential per line:
```
user@example.com:Password123
admin@corp.io:hunter2
```

---

## Connect to FEROXSEI (Docker)

FEROXSEI runs inside Docker. The leaks server runs on the Kali host.
Docker containers cannot reach host services by default - two things are needed:

### Step 1 - Open the firewall for Docker → host port 5002

The Docker bridge interface name changes every time the `feroxsei_net` network is recreated.
Use this command to derive it dynamically:

```bash
# Get the bridge interface name dynamically from the Docker network
BRIDGE=$(docker network inspect feroxsei_osint_feroxsei_net 2>/dev/null \
         || docker network inspect feroxsei_net 2>/dev/null \
         | python3 -c "import sys,json; nets=json.load(sys.stdin); print(nets[0]['Id'][:12])" 2>/dev/null)
IFACE="br-${BRIDGE}"

echo "Bridge interface: $IFACE"
sudo iptables -I INPUT -i "$IFACE" -p tcp --dport 5002 -j ACCEPT
echo "Rule added."
```

Or as a one-liner (finds any br-* interface carrying the FEROXSEI network):

```bash
IFACE=$(ip link show | grep -oP 'br-[a-f0-9]{12}' | head -1)
sudo iptables -I INPUT -i "$IFACE" -p tcp --dport 5002 -j ACCEPT
```

Or without specifying an interface (simpler, slightly broader):

```bash
sudo iptables -I INPUT -s 172.18.0.0/16 -p tcp --dport 5002 -j ACCEPT
```

Make the rule survive reboots:

```bash
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### Step 2 - Recreate the FEROXSEI container

The `extra_hosts` entry in `docker-compose.yml` adds `host.docker.internal` to the container's `/etc/hosts`.
This only takes effect when the container is **recreated** (not just restarted):

```bash
cd /home/kali/Desktop/FEROXSEI
docker compose up -d --force-recreate FEROXSEI
```

### Step 3 - Set the URL in FEROXSEI Settings

In FEROXSEI → Settings → Leaks → Remote Leaks Server, enter:

```
URL: http://host.docker.internal:5002
Key: <paste from leaks server startup output or config.json>
```

**Never use `127.0.0.1` or `localhost`** - from inside Docker, those refer to the container itself.
**`host.docker.internal`** resolves to the Docker bridge gateway (`172.18.0.1`), which routes to the Kali host.

---

## Verify It's Working

From Kali terminal - confirm leaks server is up:

```bash
curl http://127.0.0.1:5002/health
# Expected: {"dirs": 1, "ok": true, "service": "feroxsei-leaks-server"}
```

From Kali terminal - simulate what Docker sees (bridge gateway IP):

```bash
curl http://172.18.0.1:5002/health
# Expected: same response
```

From FEROXSEI settings page - Status should show **● Online**.

---

## Check the API Key

The key is generated once and stored in `config.json`:

```bash
cat /home/kali/Desktop/FEROXSEI/leaks_server/config.json
```

To rotate the key (while server is running):

```bash
KEY=$(cat leaks_server/config.json | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
curl -s -X POST http://127.0.0.1:5002/api/rotate-key -H "X-Leaks-Key: $KEY" | python3 -m json.tool
# New key is printed - update FEROXSEI Settings → Leaks
```

---

## Add Leaks Data Directories

Via FEROXSEI Settings → Leaks → Remote Directories (GUI), or directly via API:

```bash
KEY=$(python3 -c "import json; print(json.load(open('leaks_server/config.json'))['api_key'])")

# Add a directory
curl -s -X POST http://127.0.0.1:5002/api/dirs \
  -H "X-Leaks-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"path": "/home/kali/Desktop/FEROXSEI/leaks/data"}'

# List configured directories + stats
curl -s http://127.0.0.1:5002/api/dirs -H "X-Leaks-Key: $KEY" | python3 -m json.tool
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Status: ● Offline <urlopen error timed out>` | Docker container can't reach port 5002 on host | Add iptables rule (Step 1) AND recreate container (Step 2) |
| `Status: ● Offline <[Errno 111] Connection refused>` | Leaks server not running | `cd leaks_server && ./start.sh` |
| `Status: ● Offline <urlopen error [Errno -2]>` | `host.docker.internal` not in container `/etc/hosts` | Container not recreated after `extra_hosts` was added - run Step 2 |
| `Status: ● Key not set` | URL saved but no key entered | Paste key from `config.json` into Settings → Leaks |
| Search returns 0 results | No data directories configured or files are wrong format | Add dir in Settings → Leaks; files must be `email:password` per line |
| `127.0.0.1` URL shows Offline | Wrong URL for Docker | Change to `http://host.docker.internal:5002` |
| Bridge interface not found | Docker not running or network not created | Start Docker first: `cd OSINT-dev && docker compose up -d` |

---

## Architecture

```
┌─────────────────────────────┐
│   Kali Host                 │
│                             │
│  feroxsei_leaks_server.py      │
│  listening 0.0.0.0:5002     │◄──── iptables ACCEPT rule needed
│                             │      for Docker bridge traffic
│  ┌──────────────────────┐   │
│  │  Docker (feroxsei_net)  │   │
│  │                      │   │
│  │  feroxsei-osint app     │   │
│  │  → host.docker.      │   │
│  │    internal:5002     │───┼──► 172.18.0.1:5002 → leaks server
│  │  (extra_hosts maps   │   │
│  │   to 172.18.0.1)     │   │
│  └──────────────────────┘   │
└─────────────────────────────┘
```

---

## config.json Reference

```json
{
  "api_key": "your-key-here",
  "port": 5002,
  "host": "0.0.0.0",
  "dirs": [
    "/home/kali/Desktop/FEROXSEI/leaks/data"
  ]
}
```

Edit this file directly or use the FEROXSEI UI / API endpoints to manage directories.
The server reads `config.json` on every request - no restart needed after changes.
