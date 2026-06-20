#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   FEROXSEI OSINT ENGINE - Ultimate Intelligence Platform                        ║
║   Plugin Modules | TOR Proxy | AI Analysis | Pattern Match                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Core classes:  OSINTDatabase, FeroxseiHTTP, PatternEngine, OSINTEngine
Modules:       Auto-discovered from modules/ folder at startup
"""
from __future__ import annotations
import os, sys, json, time, uuid, sqlite3, re, threading, socket, hashlib
import ipaddress, base64, random, string, traceback, subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, urljoin, quote, urlencode, parse_qs

# ── Optional imports (graceful degradation) ───────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver, dns.zone, dns.query, dns.name, dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import shodan as shodan_lib
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════
class OSINTDatabase:
    """Lightweight SQLite DB layer for FEROXSEI OSINT."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user', api_keys TEXT DEFAULT '{}',
        created_at TEXT);
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        created_at TEXT, expires_at TEXT);
    CREATE TABLE IF NOT EXISTS osint_scans (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        scan_name TEXT, target TEXT NOT NULL,
        scan_type TEXT DEFAULT 'osint',
        modules TEXT DEFAULT '{}',
        status TEXT DEFAULT 'pending',
        progress INTEGER DEFAULT 0,
        current_module TEXT DEFAULT '',
        crawl_depth INTEGER DEFAULT 3,
        file_types TEXT DEFAULT '*',
        use_tor INTEGER DEFAULT 0,
        wordlist TEXT DEFAULT 'default',
        notes TEXT DEFAULT '',
        source_path TEXT DEFAULT '',
        created_at TEXT, started_at TEXT, completed_at TEXT,
        error TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS osint_findings (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
        module TEXT NOT NULL, severity TEXT DEFAULT 'info',
        title TEXT, description TEXT,
        url TEXT DEFAULT '', evidence TEXT DEFAULT '',
        pattern_id TEXT DEFAULT '', tags TEXT DEFAULT '[]',
        raw_data TEXT DEFAULT '{}', screenshot_id TEXT DEFAULT '',
        created_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES osint_scans(id));
    CREATE TABLE IF NOT EXISTS osint_traffic (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
        ts TEXT, source_ip TEXT, dest_host TEXT,
        dest_port INTEGER DEFAULT 443,
        via_tor INTEGER DEFAULT 0, tor_exit_ip TEXT DEFAULT '',
        method TEXT DEFAULT 'GET', url TEXT,
        status_code INTEGER DEFAULT 0,
        bytes_sent INTEGER DEFAULT 0, bytes_recv INTEGER DEFAULT 0,
        module TEXT DEFAULT '', duration_ms INTEGER DEFAULT 0,
        error TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS osint_patterns (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        category TEXT DEFAULT 'custom',
        pattern TEXT NOT NULL, description TEXT DEFAULT '',
        severity TEXT DEFAULT 'medium',
        tags TEXT DEFAULT '[]',
        source TEXT DEFAULT 'user',
        enabled INTEGER DEFAULT 1,
        hit_count INTEGER DEFAULT 0,
        created_at TEXT);
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY, user_id TEXT,
        type TEXT DEFAULT 'info', title TEXT,
        body TEXT, is_read INTEGER DEFAULT 0,
        created_at TEXT);
    CREATE TABLE IF NOT EXISTS osint_screenshots (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
        url TEXT, file_path TEXT, thumbnail TEXT,
        module TEXT DEFAULT '', created_at TEXT);
    CREATE TABLE IF NOT EXISTS osint_task_logs (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
        module TEXT NOT NULL,
        module_label TEXT DEFAULT '',
        module_icon  TEXT DEFAULT '',
        task TEXT NOT NULL,
        detail TEXT DEFAULT '',
        status TEXT DEFAULT 'running',
        parent_id TEXT DEFAULT '',
        started_at TEXT, completed_at TEXT);
    CREATE TABLE IF NOT EXISTS userhunt_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        url TEXT NOT NULL,
        check_type TEXT DEFAULT 'status_code',
        found_status INTEGER DEFAULT 200,
        miss_status INTEGER DEFAULT 404,
        found_str TEXT DEFAULT '',
        error_str TEXT DEFAULT '',
        expect_url TEXT DEFAULT '',
        json_path TEXT DEFAULT '',
        tags TEXT DEFAULT '[]',
        enabled INTEGER DEFAULT 1,
        is_custom INTEGER DEFAULT 0,
        created_at TEXT DEFAULT '');

    CREATE TABLE IF NOT EXISTS username_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        example TEXT DEFAULT '',
        enabled INTEGER DEFAULT 1,
        is_custom INTEGER DEFAULT 0,
        created_at TEXT DEFAULT '');
    """

    def __init__(self, path: str = "osint.db"):
        self.path = os.path.abspath(path)
        self._lock = threading.Lock()
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init(self):
        with self._conn() as c:
            c.executescript(self.SCHEMA)
            # Migrations - add columns that didn't exist in older DBs
            for sql in [
                "ALTER TABLE osint_task_logs ADD COLUMN parent_id TEXT DEFAULT ''",
                "ALTER TABLE osint_scans ADD COLUMN investigation_id TEXT DEFAULT ''",
                "ALTER TABLE osint_findings ADD COLUMN screenshot_id TEXT DEFAULT ''",
                "ALTER TABLE osint_scans ADD COLUMN deleted_by_user INTEGER DEFAULT 0",
                "ALTER TABLE osint_scans ADD COLUMN api_cfg TEXT DEFAULT '{}'",
                # userhunt sequential search
                "ALTER TABLE userhunt_sites ADD COLUMN secondary_url TEXT DEFAULT ''",
                "ALTER TABLE userhunt_sites ADD COLUMN id_pattern TEXT DEFAULT ''",
                # phishing result error tracking
                "ALTER TABLE phishing_results ADD COLUMN last_error TEXT DEFAULT ''",
                # phishing OAuth2
                "ALTER TABLE phishing_sending_profiles ADD COLUMN auth_type TEXT DEFAULT 'basic'",
                "ALTER TABLE phishing_sending_profiles ADD COLUMN oauth_client_id TEXT DEFAULT ''",
                "ALTER TABLE phishing_sending_profiles ADD COLUMN oauth_client_secret TEXT DEFAULT ''",
                "ALTER TABLE phishing_sending_profiles ADD COLUMN oauth_tenant_id TEXT DEFAULT ''",
                "ALTER TABLE phishing_sending_profiles ADD COLUMN oauth_refresh_token TEXT DEFAULT ''",
                # entity per-scan tracking
                "ALTER TABLE entities ADD COLUMN scan_ids TEXT DEFAULT '[]'",
                # server-side session tracking
                """CREATE TABLE IF NOT EXISTS user_sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    username TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    geo_location TEXT DEFAULT '',
                    user_agent TEXT DEFAULT '',
                    browser TEXT DEFAULT '',
                    os_name TEXT DEFAULT '',
                    created_at TEXT,
                    last_active TEXT
                )""",
            ]:
                try:
                    c.execute(sql)
                except Exception:
                    pass  # column already exists

    def exec(self, sql: str, params=()):
        with self._lock:
            with self._conn() as c:
                c.execute(sql, params)

    def rows(self, sql: str, params=()):
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()):
        with self._conn() as c:
            r = c.execute(sql, params).fetchone()
            return dict(r) if r else None

    def ins(self, table: str, data: dict):
        cols  = ", ".join(data.keys())
        marks = ", ".join("?" for _ in data)
        with self._lock:
            with self._conn() as c:
                c.execute(f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({marks})",
                          list(data.values()))

    def upd(self, table: str, data: dict, where: str, params=()):
        sets = ", ".join(f"{k}=?" for k in data.keys())
        with self._lock:
            with self._conn() as c:
                c.execute(f"UPDATE {table} SET {sets} WHERE {where}",
                          list(data.values()) + list(params))

    def get_userhunt_sites(self, enabled_only: bool = False) -> list:
        if enabled_only:
            return self.rows("SELECT * FROM userhunt_sites WHERE enabled=1 ORDER BY name")
        return self.rows("SELECT * FROM userhunt_sites ORDER BY name")

    def seed_userhunt_sites(self, sites_dict: dict) -> int:
        seeded = 0
        now = _now()
        for name, cfg in sites_dict.items():
            try:
                self.exec(
                    "INSERT OR IGNORE INTO userhunt_sites "
                    "(name,url,check_type,found_status,miss_status,found_str,"
                    "error_str,expect_url,json_path,tags,secondary_url,id_pattern,"
                    "enabled,is_custom,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,0,?)",
                    (name, cfg["url"],
                     cfg.get("check", "status_code"),
                     cfg.get("found_status", 200),
                     cfg.get("miss_status", 404),
                     cfg.get("found_str", "") or "",
                     cfg.get("error_str", "") or "",
                     cfg.get("expect_url", "") or "",
                     cfg.get("json_path", "") or "",
                     json.dumps(cfg.get("tags", [])),
                     cfg.get("secondary_url", "") or "",
                     cfg.get("id_pattern", "") or "",
                     now)
                )
                seeded += 1
                # Backfill secondary_url / id_pattern for existing rows seeded without them
                _sec = cfg.get("secondary_url", "") or ""
                _pat = cfg.get("id_pattern", "") or ""
                if _sec or _pat:
                    self.exec(
                        "UPDATE userhunt_sites SET secondary_url=?, id_pattern=? "
                        "WHERE name=? AND is_custom=0 "
                        "AND (secondary_url IS NULL OR secondary_url='' "
                        "OR id_pattern IS NULL OR id_pattern='')",
                        (_sec, _pat, name)
                    )
            except Exception:
                pass
        return seeded

    def get_username_patterns(self, enabled_only: bool = False) -> list:
        if enabled_only:
            return self.rows("SELECT * FROM username_patterns WHERE enabled=1 ORDER BY id")
        return self.rows("SELECT * FROM username_patterns ORDER BY id")

    def seed_username_patterns(self, patterns: list) -> int:
        seeded = 0
        now = _now()
        for pattern, description, example in patterns:
            try:
                self.exec(
                    "INSERT OR IGNORE INTO username_patterns "
                    "(pattern,description,example,enabled,is_custom,created_at) "
                    "VALUES (?,?,?,1,0,?)",
                    (pattern, description, example, now)
                )
                seeded += 1
            except Exception:
                pass
        return seeded

    # ── Convenience methods ────────────────────────────────────────────────────
    def save_finding(self, scan_id, module, severity, title, description,
                     url="", evidence="", tags=None, raw_data=None, pattern_id="",
                     screenshot_id=""):
        fid = str(uuid.uuid4())
        try:
            self.ins("osint_findings", {
                "id": fid, "scan_id": scan_id, "module": module,
                "severity": severity, "title": title, "description": description,
                "url": url[:2000], "evidence": (evidence or "")[:4000],
                "pattern_id": pattern_id,
                "tags": json.dumps(tags or []),
                "raw_data": json.dumps(raw_data or {}),
                "screenshot_id": screenshot_id,
                "created_at": _now()
            })
        except Exception:
            pass
        return fid

    # ── Screenshot helpers ────────────────────────────────────────────────────
    def save_screenshot(self, scan_id: str, module: str, url: str,
                        png_bytes: bytes = b"", thumbnail_b64: str = "") -> str:
        """Save a screenshot record; returns screenshot id."""
        sid = str(uuid.uuid4())
        # Store file on disk next to the DB
        ss_dir = Path(self.path).parent / "screenshots"
        ss_dir.mkdir(exist_ok=True)
        file_path = ""
        if png_bytes:
            file_path = str(ss_dir / f"{sid}.png")
            with open(file_path, "wb") as f:
                f.write(png_bytes)
            # Build thumbnail (base64, max 400px wide) if not provided
            if not thumbnail_b64:
                try:
                    from PIL import Image
                    import io
                    img = Image.open(io.BytesIO(png_bytes))
                    img.thumbnail((400, 800))
                    buf = io.BytesIO()
                    img.save(buf, format="PNG", optimize=True)
                    import base64
                    thumbnail_b64 = base64.b64encode(buf.getvalue()).decode()
                except Exception:
                    # Fallback: store raw bytes as b64 thumbnail (may be large)
                    import base64
                    thumbnail_b64 = base64.b64encode(png_bytes[:200_000]).decode()
        self.ins("osint_screenshots", {
            "id": sid, "scan_id": scan_id, "url": url[:2000],
            "file_path": file_path, "thumbnail": thumbnail_b64,
            "module": module, "created_at": _now()
        })
        return sid

    def get_screenshot(self, screenshot_id: str):
        """Return screenshot row by id."""
        return self.one("SELECT * FROM osint_screenshots WHERE id=?", (screenshot_id,))

    def get_screenshots_for_scan(self, scan_id: str):
        """All screenshots for a scan."""
        return self.rows(
            "SELECT * FROM osint_screenshots WHERE scan_id=? ORDER BY created_at DESC",
            (scan_id,))

    def get_screenshot_for_url(self, scan_id: str, url: str):
        """Best-match screenshot for a URL within a scan."""
        return self.one(
            "SELECT * FROM osint_screenshots WHERE scan_id=? AND url=? LIMIT 1",
            (scan_id, url))

    def log_traffic(self, scan_id, module, method, url, status_code,
                    source_ip, dest_host, dest_port, duration_ms,
                    via_tor=False, tor_exit_ip="", error="",
                    bytes_sent=0, bytes_recv=0):
        self.ins("osint_traffic", {
            "id": str(uuid.uuid4()), "scan_id": scan_id, "ts": _now(),
            "source_ip": source_ip, "dest_host": dest_host,
            "dest_port": dest_port, "via_tor": 1 if via_tor else 0,
            "tor_exit_ip": tor_exit_ip, "method": method, "url": url[:2000],
            "status_code": status_code, "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv, "module": module,
            "duration_ms": duration_ms, "error": error[:500]
        })

    # ── Task log helpers ───────────────────────────────────────────────────────
    def log_task(self, scan_id: str, module: str, task: str,
                 detail: str = "", module_label: str = "", module_icon: str = "",
                 parent_id: str = "") -> str:
        """Start a new task entry; returns task_id."""
        tid = str(uuid.uuid4())
        self.ins("osint_task_logs", {
            "id": tid, "scan_id": scan_id, "module": module,
            "module_label": module_label, "module_icon": module_icon,
            "task": task[:300], "detail": detail[:1000],
            "status": "running", "parent_id": parent_id,
            "started_at": _now(), "completed_at": ""
        })
        return tid

    def finish_task(self, task_id: str, status: str = "done", detail_append: str = ""):
        """Mark an existing task as done/skipped/error."""
        data: dict = {"status": status, "completed_at": _now()}
        if detail_append:
            # Append to existing detail
            row = self.one("SELECT detail FROM osint_task_logs WHERE id=?", (task_id,))
            if row:
                data["detail"] = ((row["detail"] or "") + "\n" + detail_append).strip()[:1000]
        self.upd("osint_task_logs", data, "id=?", (task_id,))

    def update_task(self, task_id: str, task: str = "", detail: str = ""):
        """Update the running task text (for sub-steps within a module)."""
        data: dict = {}
        if task:   data["task"]   = task[:300]
        if detail: data["detail"] = detail[:1000]
        if data:   self.upd("osint_task_logs", data, "id=?", (task_id,))

    def get_tasks(self, scan_id: str, limit: int = 500):
        """Return tasks ordered so parent rows come first, children follow grouped under parent."""
        all_rows = self.rows(
            "SELECT * FROM osint_task_logs WHERE scan_id=? ORDER BY started_at ASC LIMIT ?",
            (scan_id, limit))
        # Separate parents and children
        parents  = [r for r in all_rows if not r.get("parent_id")]
        children = [r for r in all_rows if r.get("parent_id")]
        # Build ordered list: parent → its children → next parent → ...
        child_map: dict = {}
        for c in children:
            child_map.setdefault(c["parent_id"], []).append(c)
        ordered = []
        for p in parents:
            ordered.append(p)
            ordered.extend(child_map.get(p["id"], []))
        return ordered

    def set_scan_status(self, scan_id, status, progress=None,
                        current_module=None, error=None):
        data = {"status": status}
        if progress is not None:  data["progress"] = progress
        if current_module is not None: data["current_module"] = current_module
        if error is not None:     data["error"] = error
        if status == "running":   data.setdefault("started_at", _now())
        if status in ("completed","failed"): data["completed_at"] = _now()
        self.upd("osint_scans", data, "id=?", (scan_id,))

    def get_scan(self, scan_id):
        return self.one("SELECT * FROM osint_scans WHERE id=?", (scan_id,))

    def get_findings(self, scan_id, limit=1000):
        return self.rows(
            "SELECT * FROM osint_findings WHERE scan_id=? ORDER BY created_at DESC LIMIT ?",
            (scan_id, limit))

    def get_traffic(self, scan_id, limit=500):
        return self.rows(
            "SELECT * FROM osint_traffic WHERE scan_id=? ORDER BY ts DESC LIMIT ?",
            (scan_id, limit))

    def findings_summary(self, scan_id):
        rows = self.rows(
            "SELECT severity, count(*) as cnt FROM osint_findings "
            "WHERE scan_id=? GROUP BY severity", (scan_id,))
        return {r["severity"]: r["cnt"] for r in rows}

    # ── Entity Graph helpers ───────────────────────────────────────────────────

    def ensure_entity(self, investigation_id: str, entity_type: str, value: str,
                      label: str = "", confidence: int = 70,
                      source_module: str = "", metadata: dict | None = None,
                      scan_id: str = "") -> str:
        """Upsert an entity by (investigation_id, entity_type, value).
        Returns the entity id (existing or new).
        scan_id is recorded in a JSON array so per-scan graph filtering works."""
        value = value.strip()[:500]
        if not value:
            return ""
        row = self.one(
            "SELECT id, source_modules, evidence_count, scan_ids FROM entities "
            "WHERE investigation_id=? AND entity_type=? AND value=?",
            (investigation_id, entity_type, value))
        if row:
            eid  = row["id"]
            mods = json.loads(row["source_modules"] or "[]")
            if source_module and source_module not in mods:
                mods.append(source_module)
            sids = json.loads(row.get("scan_ids") or "[]")
            if scan_id and scan_id not in sids:
                sids.append(scan_id)
            self.upd("entities",
                     {"source_modules": json.dumps(mods),
                      "scan_ids":       json.dumps(sids),
                      "evidence_count":  row["evidence_count"] + 1,
                      "last_seen": _now()},
                     "id=?", (eid,))
            return eid
        eid = str(uuid.uuid4())
        self.ins("entities", {
            "id": eid,
            "investigation_id": investigation_id,
            "entity_type": entity_type,
            "value": value,
            "label": (label or value)[:200],
            "confidence": confidence,
            "confidence_explanation": f"Detected by {source_module}" if source_module else "",
            "source_modules": json.dumps([source_module] if source_module else []),
            "scan_ids": json.dumps([scan_id] if scan_id else []),
            "evidence_count": 1,
            "contradiction_count": 0,
            "first_seen": _now(),
            "last_seen": _now(),
            "metadata": json.dumps(metadata or {})
        })
        return eid

    def ensure_relationship(self, investigation_id: str,
                            source_id: str, target_id: str,
                            relationship_type: str,
                            confidence: int = 60) -> str:
        """Upsert a relationship; returns relationship id."""
        if not source_id or not target_id or source_id == target_id:
            return ""
        row = self.one(
            "SELECT id FROM entity_relationships "
            "WHERE investigation_id=? AND source_id=? AND target_id=? AND relationship_type=?",
            (investigation_id, source_id, target_id, relationship_type))
        if row:
            return row["id"]
        rid = str(uuid.uuid4())
        self.ins("entity_relationships", {
            "id": rid,
            "investigation_id": investigation_id,
            "source_id": source_id,
            "target_id": target_id,
            "relationship_type": relationship_type,
            "confidence": confidence,
            "confidence_explanation": "",
            "evidence_ids": "[]",
            "contradiction_ids": "[]",
            "created_at": _now()
        })
        return rid


def _looks_like_ip(s: str) -> bool:
    """Validate that a string looks like an IPv4 or IPv6 address."""
    import re as _re
    s = s.strip()
    if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):
        return all(0 <= int(p) <= 255 for p in s.split('.'))
    if ':' in s and len(s) > 4:   # IPv6 rough check
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# TOR-AWARE HTTP SESSION
# ══════════════════════════════════════════════════════════════════════════════
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

class FeroxseiHTTP:
    """
    TOR-aware HTTP client. Logs every request to DB with full traffic details.
    Shows: SOURCE_IP ──TOR──► EXIT_IP ──► DEST_HOST:PORT

    Source IP is refreshed automatically:
      - At init (LAN IP + async public IP fetch)
      - On TOR enable/disable
      - Every 5 minutes in background
      - On explicit refresh_source_ip() call
    """
    _IP_REFRESH_INTERVAL = 300   # seconds

    def __init__(self, db: OSINTDatabase, use_tor: bool = False,
                 socks_host: str = "127.0.0.1", socks_port: int = 9050,
                 timeout: int = 10):
        self.db           = db
        self.use_tor      = use_tor
        self.timeout      = timeout
        self._force_timeout = None
        self._socks_host  = socks_host
        self._socks_port  = socks_port
        self._tor_exit_ip = ""
        self._local_ip    = self._get_lan_ip()    # fast LAN detection
        self._public_ip   = ""                    # real public IP (fetched async)
        self._ip_refresh_ts = 0.0
        self._session     = self._build_session(socks_host, socks_port)
        # Event is SET when identity is ready; cleared during rotation so
        # concurrent scan requests block until the new circuit is established.
        self._identity_ready = threading.Event()
        self._identity_ready.set()
        # Fetch public IP asynchronously so __init__ doesn't block
        threading.Thread(target=self._refresh_public_ip_bg, daemon=True,
                         name="feroxsei-ip-refresh").start()

    # ── IP detection ──────────────────────────────────────────────────────────

    def _get_lan_ip(self) -> str:
        """Get the machine's outgoing LAN/interface IP (fast, no internet needed)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _fetch_public_ip_direct(self) -> str:
        """
        Fetch real public IP without proxy using ifconfig.me (plain-text response).
        Falls back to api.ipify.org JSON, then icanhazip.com.
        curl is tried first (always on Kali/Linux, no extra libs needed).
        """
        _sources = [
            # (url, is_json, json_key)
            ("https://ifconfig.me/ip",          False, ""),
            ("https://api.ipify.org?format=json", True, "ip"),
            ("https://icanhazip.com",             False, ""),
            ("https://ipecho.net/plain",          False, ""),
        ]
        # curl path - most reliable on Kali
        import subprocess as _sp
        for url, is_json, key in _sources:
            try:
                r = _sp.run(
                    ["curl", "-s", "--max-time", "6", "-A", "curl/7.88.1", url],
                    capture_output=True, text=True, timeout=8
                )
                if r.returncode == 0 and r.stdout.strip():
                    raw = r.stdout.strip()
                    if is_json:
                        import json as _j
                        ip = _j.loads(raw).get(key, "")
                    else:
                        ip = raw.split()[0]   # ifconfig.me returns bare IP
                    if ip and _looks_like_ip(ip):
                        return ip
            except Exception:
                pass
        # requests fallback (direct, no proxy)
        if HAS_REQUESTS:
            for url, is_json, key in _sources:
                try:
                    sess = requests.Session()
                    sess.proxies = {}   # force no proxy
                    resp = sess.get(url, timeout=6,
                                    headers={"User-Agent": "curl/7.88.1"})
                    raw = resp.text.strip()
                    if is_json:
                        ip = resp.json().get(key, "")
                    else:
                        ip = raw.split()[0]
                    if ip and _looks_like_ip(ip):
                        return ip
                except Exception:
                    pass
        return ""

    def _refresh_public_ip_bg(self) -> None:
        """Background thread: fetch public IP and update _local_ip + _public_ip."""
        ip = self._fetch_public_ip_direct()
        if ip:
            self._public_ip = ip
            # Only override _local_ip if the current value looks like a LAN address
            if self._local_ip.startswith(("10.", "172.", "192.168.", "127.")):
                self._local_ip = ip
        self._ip_refresh_ts = time.time()
        _log(f"[HTTP] Source IP resolved: {self._local_ip}")

    def refresh_source_ip(self) -> str:
        """Force refresh source IP (call this when network changes or on TOR toggle)."""
        self._ip_refresh_ts = 0   # reset so background will always run
        lan = self._get_lan_ip()
        pub = self._fetch_public_ip_direct()
        self._local_ip  = pub or lan
        self._public_ip = pub
        _log(f"[HTTP] Source IP refreshed: {self._local_ip}")
        return self._local_ip

    def _maybe_refresh_ip(self) -> None:
        """Auto-refresh IP if > 5 minutes since last check."""
        if time.time() - self._ip_refresh_ts > self._IP_REFRESH_INTERVAL:
            self._ip_refresh_ts = time.time()   # prevent storm
            threading.Thread(target=self._refresh_public_ip_bg, daemon=True,
                             name="feroxsei-ip-refresh").start()

    def _build_session(self, socks_host=None, socks_port=None):
        h = socks_host or self._socks_host
        p = socks_port or self._socks_port
        if not HAS_REQUESTS:
            return None
        s = requests.Session()
        if self.use_tor:
            # Verify PySocks is available before setting SOCKS5 proxy
            try:
                import socks as _socks_test  # noqa: F401 - PySocks check
                s.proxies = {
                    "http":  f"socks5h://{h}:{p}",
                    "https": f"socks5h://{h}:{p}",
                }
            except ImportError:
                _log("[HTTP] ⚠ PySocks not installed - TOR proxy cannot be set. "
                     "Run: pip install PySocks --break-system-packages")
                # Return session without proxy so we don't crash, but log warning
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500,502,503,504])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://",  HTTPAdapter(max_retries=retry))
        s.headers["User-Agent"] = random.choice(_USER_AGENTS)
        return s

    def tor_deps_ok(self) -> tuple[bool, str]:
        """Check if all TOR dependencies are installed. Returns (ok, missing_msg)."""
        missing = []
        try:
            import socks  # noqa
        except ImportError:
            missing.append("PySocks (pip install PySocks --break-system-packages)")
        try:
            import stem  # noqa
        except ImportError:
            missing.append("stem (pip install stem --break-system-packages)")
        import shutil
        if not shutil.which("tor"):
            missing.append("tor binary (sudo apt install tor)")
        if missing:
            return False, "Missing TOR dependencies:\n  • " + "\n  • ".join(missing)
        return True, "ok"

    def enable_tor(self, socks_host: str = "", socks_port: int = 0) -> bool:
        """Enable TOR proxy on the existing session. Fetches exit IP. Returns True if ready."""
        if socks_host:
            self._socks_host = socks_host
        if socks_port:
            self._socks_port = socks_port
        self.use_tor = True
        self._session = self._build_session(self._socks_host, self._socks_port)
        self.refresh_tor_exit_ip()
        ok = bool(self._tor_exit_ip and self._tor_exit_ip not in ("", "?"))
        _log(f"[TOR] Enabled - exit IP: {self._tor_exit_ip or 'unknown'}")
        return ok

    def disable_tor(self):
        """Disable TOR proxy, rebuild session without proxy."""
        self.use_tor = False
        self._tor_exit_ip = ""
        self._session = self._build_session()
        _log("[TOR] Disabled - using direct connection")

    def probe_socks(self) -> bool:
        """Check if TOR SOCKS5 port is listening."""
        try:
            with socket.create_connection((self._socks_host, self._socks_port), timeout=2):
                return True
        except OSError:
            return False

    def rotate_identity(self):
        """Rebuild HTTP session so next request uses a fresh TOR circuit.
        Clears _identity_ready so any concurrent scan requests block until
        the new circuit is confirmed, preventing requests from leaking through
        with the old (or no) identity mid-rotation.
        """
        old_ip = self._tor_exit_ip
        # Signal all waiting request() calls to hold
        self._identity_ready.clear()
        try:
            self._session = self._build_session()
            self._tor_exit_ip = "rotating…"
            # TOR needs a few seconds to build a new circuit after NEWNYM
            time.sleep(4)
            self.refresh_tor_exit_ip()
            new_ip = self._tor_exit_ip
        finally:
            # Always unblock requests, even if rotation fails
            self._identity_ready.set()
        _log(f"[TOR] Identity rotated: {old_ip} → {new_ip}")
        # Log the rotation as a meta-traffic event so it shows in the traffic log
        try:
            self.db.log_traffic(
                scan_id="system", module="tor",
                method="NEWNYM", url="tor://newnym",
                status_code=200,
                source_ip=self._local_ip,
                dest_host="127.0.0.1", dest_port=9050,
                duration_ms=4000,
                via_tor=True,
                tor_exit_ip=f"{old_ip}→{new_ip}",
                error="", bytes_sent=0, bytes_recv=0
            )
        except Exception:
            pass
        return new_ip

    def refresh_tor_exit_ip(self):
        """Fetch current TOR exit IP via the proxied SOCKS5 session."""
        sources = [
            ("https://ifconfig.me/ip",            False, ""),
            ("https://api.ipify.org?format=json",  True,  "ip"),
            ("https://icanhazip.com",              False, ""),
            ("https://checkip.amazonaws.com",      False, ""),
            ("https://ipecho.net/plain",            False, ""),
        ]
        for url, is_json, key in sources:
            try:
                r = self._session.get(url, timeout=20,
                                      headers={"User-Agent": "curl/7.88.1"},
                                      allow_redirects=True)
                if r and r.status_code == 200:
                    raw = r.text.strip()
                    ip  = (r.json().get(key, "") if is_json else raw.split()[0])
                    if ip and _looks_like_ip(ip):
                        self._tor_exit_ip = ip
                        _log(f"[HTTP] TOR exit IP confirmed: {ip}")
                        return
            except Exception:
                pass
        _log("[HTTP] ⚠ Could not fetch TOR exit IP - real IP will NOT be logged (using 🧅 TOR placeholder)")
        self._tor_exit_ip = ""

    def request(self, method: str, url: str, scan_id: str, module: str,
                add_delay: bool = True, **kwargs) -> Optional[requests.Response]:
        if not HAS_REQUESTS or not self._session:
            return None
        # Auto-refresh source IP every 5 min so traffic logs always show current IP
        self._maybe_refresh_ip()
        # If a TOR identity rotation is in progress, wait for the new circuit
        # before sending (max 30s to avoid hanging indefinitely on TOR failures)
        if self.use_tor and not self._identity_ready.is_set():
            _log(f"[HTTP] Waiting for TOR identity rotation… ({url[:60]})")
            self._identity_ready.wait(timeout=30)
        if add_delay:
            time.sleep(random.uniform(0.1, 0.4) if not self.use_tor else random.uniform(0.2, 0.6))

        parsed    = urlparse(url)
        dest_host = parsed.hostname or url
        dest_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        t0        = time.time()
        error     = ""
        resp      = None
        status    = 0
        bsent     = len(json.dumps(kwargs).encode()) if kwargs else 0
        brecv     = 0

        try:
            eff_timeout = self._force_timeout if self._force_timeout is not None else self.timeout
            kwargs.setdefault("timeout", eff_timeout)
            kwargs.setdefault("allow_redirects", True)
            resp   = self._session.request(method, url, **kwargs)
            status = resp.status_code
            brecv  = len(resp.content) if resp.content else 0
        except Exception as e:
            error = str(e)[:200]

        dur_ms = int((time.time() - t0) * 1000)

        if self.use_tor:
            effective_src = self._tor_exit_ip if self._tor_exit_ip and self._tor_exit_ip not in ("", "?", "rotating…") else "🧅 TOR"
        else:
            effective_src = self._local_ip
        self.db.log_traffic(
            scan_id=scan_id, module=module,
            method=method.upper(), url=url,
            status_code=status,
            source_ip=effective_src,
            dest_host=dest_host, dest_port=dest_port,
            duration_ms=dur_ms,
            via_tor=self.use_tor,
            tor_exit_ip=self._tor_exit_ip if self.use_tor else "",
            error=error, bytes_sent=bsent, bytes_recv=brecv
        )
        return resp

    def get(self, url, scan_id, module, **kw):
        return self.request("GET",  url, scan_id, module, **kw)

    def post(self, url, scan_id, module, **kw):
        return self.request("POST", url, scan_id, module, **kw)

    # ── Screenshot capture ────────────────────────────────────────────────────
    def take_screenshot(self, url: str, via_tor: bool = False,
                        width: int = 1920, height: int = 1080,
                        timeout_ms: int = 30000,
                        scale: int = 3) -> bytes:
        """
        Capture a full-page HD screenshot using Playwright (headless Chromium).
        - Viewport: 1920×1080 by default (HD baseline)
        - device_scale_factor=3  →  effective 5760×3240 px rendering (crisp on any display)
        - Waits for networkidle after DOMContentLoaded for fully-rendered pages
        - Auto-routes .onion URLs through TOR SOCKS5 proxy
        - Returns raw PNG bytes; raises RuntimeError on failure
        """
        is_onion = ".onion" in url.lower()
        if is_onion:
            via_tor = True
            if timeout_ms < 45000:
                timeout_ms = 45000
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright not installed. Run: pip install playwright --break-system-packages && playwright install chromium")
        if via_tor and not self.probe_socks():
            raise RuntimeError("TOR SOCKS5 proxy not reachable. Enable TOR in the header badge first.")
        try:
            from playwright.sync_api import sync_playwright, Error as PWError
            with sync_playwright() as pw:
                launch_args = [
                    "--no-sandbox", "--disable-dev-shm-usage",
                    "--disable-gpu", "--disable-web-security",
                    "--ignore-certificate-errors",
                    # Force high-DPI rendering pipeline
                    "--force-device-scale-factor=3",
                    "--high-dpi-support=1",
                ]
                proxy_cfg = None
                if via_tor:
                    socks_url = f"socks5://{self._socks_host}:{self._socks_port}"
                    proxy_cfg = {"server": socks_url}
                    launch_args += ["--proxy-bypass-list=<-loopback>"]
                browser = pw.chromium.launch(
                    headless=True,
                    args=launch_args,
                    proxy=proxy_cfg,
                )
                ctx = browser.new_context(
                    viewport={"width": width, "height": height},
                    device_scale_factor=scale,          # 3× = true HD/Retina output
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    ignore_https_errors=True,
                    color_scheme="light",               # consistent rendering
                )
                page = ctx.new_page()
                page.set_default_timeout(timeout_ms)

                # ── Navigate ──────────────────────────────────────────────────
                wait_until = "commit" if is_onion else "domcontentloaded"
                try:
                    page.goto(url, wait_until=wait_until, timeout=timeout_ms)
                except PWError as e:
                    raise RuntimeError(f"Page load failed: {str(e)[:200]}")

                # ── Wait for full render ───────────────────────────────────────
                # networkidle catches lazy-loaded images, web fonts, and JS-rendered content
                try:
                    page.wait_for_load_state(
                        "networkidle",
                        timeout=8000 if not is_onion else 20000
                    )
                except Exception:
                    # networkidle timeout is acceptable - page still rendered
                    pass
                # Extra settle time: JS animations, deferred paints
                page.wait_for_timeout(2000 if is_onion else 1000)

                # ── Scroll to top so full_page capture starts clean ───────────
                try:
                    page.evaluate("window.scrollTo(0, 0)")
                except Exception:
                    pass

                # ── Capture ───────────────────────────────────────────────────
                try:
                    png_bytes = page.screenshot(
                        full_page=True,
                        type="png",
                        animations="disabled",          # freeze CSS animations for sharp text
                    )
                except PWError as e:
                    raise RuntimeError(f"Screenshot capture failed: {str(e)[:200]}")
                finally:
                    ctx.close()
                    browser.close()

                if not png_bytes:
                    raise RuntimeError("Playwright returned empty screenshot")

                # ── Lossless PNG optimisation (pillow) ────────────────────────
                # Keeps full quality but strips unnecessary metadata chunks,
                # reducing file size ~20-40% without any pixel degradation.
                try:
                    import io
                    from PIL import Image
                    img = Image.open(io.BytesIO(png_bytes))
                    buf = io.BytesIO()
                    img.save(buf, format="PNG", optimize=True, compress_level=6)
                    optimised = buf.getvalue()
                    if optimised:
                        png_bytes = optimised
                except Exception:
                    pass  # pillow not installed → return raw bytes unchanged

                return png_bytes
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Screenshot error: {str(e)[:200]}")


# ══════════════════════════════════════════════════════════════════════════════
# PATTERN ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class PatternEngine:
    """Loads patterns from DB + JSON file, applies them to text/URLs."""

    def __init__(self, db: OSINTDatabase, pattern_file: str = None):
        self.db = db
        self._compiled: List[dict] = []
        self._load(pattern_file)

    def _load(self, pattern_file):
        # Load from file - skip any pattern disabled in the DB
        if pattern_file and os.path.exists(pattern_file):
            try:
                raw = json.loads(open(pattern_file).read())
                for p in raw:
                    try:
                        existing = self.db.one(
                            "SELECT id, enabled FROM osint_patterns WHERE name=?", (p["name"],))
                        if existing and not existing["enabled"]:
                            continue  # Disabled via DB toggle - honour it
                        compiled = re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)
                        self._compiled.append({**p, "_re": compiled})
                        if not existing:
                            self.db.ins("osint_patterns", {
                                "id": p.get("id", str(uuid.uuid4())),
                                "name": p["name"],
                                "category": p.get("category","custom"),
                                "pattern": p["pattern"],
                                "description": p.get("description",""),
                                "severity": p.get("severity","info"),
                                "tags": json.dumps(p.get("tags",[])),
                                "source": p.get("source","builtin"),
                                "enabled": 1, "hit_count": 0,
                                "created_at": _now()
                            })
                    except Exception:
                        pass
            except Exception:
                pass

        # Also load from DB (user/AI-added patterns)
        db_pats = self.db.rows("SELECT * FROM osint_patterns WHERE enabled=1")
        names_in_compiled = {p["name"] for p in self._compiled}
        for p in db_pats:
            if p["name"] not in names_in_compiled:
                try:
                    compiled = re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)
                    self._compiled.append({**p, "_re": compiled})
                except Exception:
                    pass

    def reload(self):
        self._compiled.clear()
        self._load(None)

    def scan_text(self, text: str, url: str = "") -> List[dict]:
        """Apply all patterns to text, return list of matches."""
        matches = []
        seen = set()
        for p in self._compiled:
            try:
                for m in p["_re"].finditer(text):
                    hit = m.group(0)[:300]
                    key = f"{p['id']}:{hit[:50]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append({
                        "pattern_id": p["id"],
                        "pattern_name": p["name"],
                        "category": p["category"],
                        "severity": p["severity"],
                        "evidence": hit,
                        "context": text[max(0,m.start()-60):m.end()+60],
                        "url": url,
                    })
                    self.db.exec(
                        "UPDATE osint_patterns SET hit_count=hit_count+1 WHERE id=?",
                        (p["id"],))
            except Exception:
                pass
        return matches

    def add_pattern(self, name, pattern, category, severity, description,
                    tags=None, source="user") -> bool:
        """Add a new pattern. Reject if an ENABLED pattern with same name exists."""
        existing = self.db.one("SELECT id, enabled FROM osint_patterns WHERE name=?", (name,))
        if existing and existing["enabled"]:
            return False  # Active duplicate - reject
        try:
            re.compile(pattern)
        except Exception:
            return False
        pid = str(uuid.uuid4())
        self.db.ins("osint_patterns", {
            "id": pid, "name": name, "category": category,
            "pattern": pattern, "description": description,
            "severity": severity, "tags": json.dumps(tags or []),
            "source": source, "enabled": 1,
            "hit_count": 0, "created_at": _now()
        })
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            self._compiled.append({
                "id": pid, "name": name, "category": category,
                "pattern": pattern, "severity": severity,
                "_re": compiled
            })
        except Exception:
            pass
        return True


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS (re-exported from investigations.osint.modules.base for backward compat)
# ══════════════════════════════════════════════════════════════════════════════
def _now(): return datetime.now().isoformat()
def _log(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def _extract_domain(target: str) -> str:
    """Extract hostname/domain from URL or bare domain."""
    if "://" not in target:
        target = "https://" + target
    return urlparse(target).hostname or target

def _extract_username(target: str) -> str:
    """Try to extract a username from @handle or /user/handle patterns."""
    if target.startswith("@"):
        return target[1:]
    m = re.search(r'/(?:user|u|profile|in)/([a-zA-Z0-9._\-]+)', target)
    if m:
        return m.group(1)
    return ""

def _thread_pool(max_workers=8):
    from concurrent.futures import ThreadPoolExecutor
    return ThreadPoolExecutor(max_workers=max_workers)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENGINE ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════
class OSINTEngine:
    """Orchestrate all OSINT modules for a scan."""

    def __init__(self, db: OSINTDatabase, db_path: str = "osint.db"):
        self.db       = db
        self.http     = FeroxseiHTTP(db)  # reconfigured per scan
        self.patterns = PatternEngine(
            db,
            pattern_file=str(Path(__file__).parent / "osint_patterns.json")
        )
        self._running: Dict[str, threading.Thread] = {}
        self._running_scans = self._running  # alias for external stale-scan detection
        # Per-scan skip signal: when scan_id is in this set, the engine will
        # stop the current module after its current atomic step and advance to next
        self._skip_signals: set = set()
        # Auto-discover all module classes from the modules/ folder
        self.MODULE_CLASSES = self._discover_modules()
        _log(f"[ENGINE] Loaded {len(self.MODULE_CLASSES)} modules: "
             f"{', '.join(c.NAME for c in self.MODULE_CLASSES)}")

    # ── Module auto-discovery ─────────────────────────────────────────────────
    def _discover_modules(self) -> list:
        """Auto-discover all BaseOSINTModule subclasses in investigations/osint/modules/."""
        import importlib
        import pkgutil
        from investigations.osint.modules.base import BaseOSINTModule

        modules_dir = Path(__file__).parent / "investigations" / "osint" / "modules"
        discovered  = []

        for finder, name, ispkg in pkgutil.iter_modules([str(modules_dir)]):
            # Skip infrastructure files that aren't real modules
            if name in ("base", "TEMPLATE"):
                continue
            try:
                mod = importlib.import_module(f"investigations.osint.modules.{name}")
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (isinstance(attr, type)
                            and issubclass(attr, BaseOSINTModule)
                            and attr is not BaseOSINTModule
                            and hasattr(attr, "NAME")):
                        discovered.append(attr)
            except Exception as e:
                print(f"[FEROXSEI] Failed to load module {name}: {e}")

        # Sort by ORDER attribute so the pipeline runs in a defined sequence
        discovered.sort(key=lambda c: getattr(c, "ORDER", 50))
        return discovered

    # ── Scan lifecycle ────────────────────────────────────────────────────────
    def start_scan(self, scan_id: str):
        """Launch scan in background thread."""
        t = threading.Thread(target=self._run, args=(scan_id,), daemon=True)
        self._running[scan_id] = t
        t.start()
        return t

    def stop_scan(self, scan_id: str):
        """Request scan stop (best-effort)."""
        self._running.pop(scan_id, None)
        self._skip_signals.discard(scan_id)

    def skip_module(self, scan_id: str):
        """Immediately abort the running module and advance to the next one.

        Three-layer interrupt:
        1. Skip signal - module loops check this and exit
        2. _force_timeout = 0.1s - next request call returns instantly
        3. socket.setdefaulttimeout(0.1) - breaks the OS-level blocking recv()
           on any new sockets; restored automatically after 2 seconds
        """
        self._skip_signals.add(scan_id)
        try:
            self.http._force_timeout = 0.1
            self.http._session.close()
            self.http._session = self.http._build_session(
                self.http._socks_host, self.http._socks_port)
        except Exception:
            pass
        try:
            socket.setdefaulttimeout(0.1)
            def _restore():
                time.sleep(2)
                socket.setdefaulttimeout(None)
                try:
                    self.http._force_timeout = None
                except Exception:
                    pass
            threading.Thread(target=_restore, daemon=True, name="skip-restore").start()
        except Exception:
            pass

    def should_skip(self, scan_id: str) -> bool:
        """Modules call this to check if they should abort early."""
        return scan_id in self._skip_signals

    def _run(self, scan_id: str):
        scan = self.db.get_scan(scan_id)
        if not scan:
            return

        target  = scan["target"]
        # TOR: badge toggle (engine.http.use_tor) overrides per-scan setting.
        # We NEVER recreate engine.http - we just update use_tor on it so the
        # same session (with its already-fetched exit IP) is reused.
        tor_from_scan   = bool(scan.get("use_tor", 0))
        tor_from_badge  = bool(self.http.use_tor)
        use_tor         = tor_from_scan or tor_from_badge

        if use_tor and not self.http.use_tor:
            # Badge was off but this scan needs TOR - enable it now
            self.http.enable_tor()
        elif use_tor and not self.http._tor_exit_ip:
            # TOR already on but exit IP not fetched yet (e.g. first scan after restart)
            self.http.refresh_tor_exit_ip()

        _log(f"[ENGINE] TOR={use_tor}  exit={self.http._tor_exit_ip or 'n/a'}  local={self.http._local_ip}")

        try:
            modules_cfg = json.loads(scan.get("modules") or "{}")
        except Exception:
            modules_cfg = {}

        # Build config dict from scan
        config = {
            "crawl_depth": scan.get("crawl_depth", 2),
            "file_types":  (scan.get("file_types") or "").split(","),
            "use_tor":     use_tor,
        }
        # Add API keys / extra config from scan notes JSON
        try:
            extra = json.loads(scan.get("notes") or "{}")
            config.update(extra)
        except Exception:
            pass

        self.db.set_scan_status(scan_id, "running", progress=0,
                                current_module="Initializing")
        # Log engine start task
        init_tid = self.db.log_task(scan_id, "engine", "Scan initializing",
                                    detail=f"Target: {target} | TOR: {use_tor}",
                                    module_label="Engine", module_icon="⬡")
        self.db.finish_task(init_tid, "done",
                            detail_append=f"{len(self.MODULE_CLASSES)} modules discovered")

        # ── Target-type filtering ─────────────────────────────────────────────
        # config["target_types"] is a list like ["domain"] or ["username","email"].
        # If not set (old scans / API callers), default to ["domain"] so nothing breaks.
        target_types = config.get("target_types") or ["domain"]
        if isinstance(target_types, str):
            target_types = [t.strip() for t in target_types.split(",") if t.strip()]
        # Always include "domain" in context when the primary target looks like a domain
        if "domain" not in target_types and not config.get("target_types"):
            target_types = ["domain"]

        enabled_modules = [
            cls for cls in self.MODULE_CLASSES
            if modules_cfg.get(cls.NAME, True)
            and any(tt in target_types
                    for tt in getattr(cls, "TARGET_TYPES", ["domain"]))
        ]
        total = len(enabled_modules)
        _log(f"[ENGINE] target_types={target_types} → {total} modules active")

        def _run_one_module(mod_cls, idx):
            """Run a single module; returns (mod, error_or_None)."""
            if scan_id not in self._running:
                return None, None
            if getattr(mod_cls, "REQUIRES_TOR", False) and not self.http.use_tor:
                _log(f"[ENGINE] Skipping {mod_cls.LABEL} - TOR disabled mid-scan")
                tid = self.db.log_task(scan_id, mod_cls.NAME,
                    "⏭ Skipped - TOR disabled mid-scan",
                    module_label=mod_cls.LABEL, module_icon=mod_cls.ICON)
                self.db.finish_task(tid, "skipped")
                self.db.save_finding(scan_id, mod_cls.NAME, "info",
                    f"⏭ Skipped: {mod_cls.LABEL} (TOR Disabled)",
                    "Module requires TOR which was disabled mid-scan.",
                    tags=["skipped","tor","safety"])
                return None, None
            _log(f"[ENGINE] [{idx+1}/{total}] Running: {mod_cls.LABEL}")
            mod = mod_cls(self)
            # Tell the module which target type is primary - used by _pattern_scan()
            # to scope pattern matching to web targets only.
            mod._target_type = target_types[0] if target_types else "domain"
            tid = self.db.log_task(scan_id, mod.NAME,
                f"Running {mod.LABEL}",
                detail=f"Module {idx+1}/{total}",
                module_label=mod.LABEL, module_icon=mod.ICON)
            mod._task_id = tid
            mod._last_subtask_id = ""
            try:
                mod.run(scan_id, target, config)
            except Exception as e:
                _log(f"[ENGINE] Module {mod.NAME} error: {e}\n{traceback.format_exc()}")
                if mod._last_subtask_id:
                    self.db.finish_task(mod._last_subtask_id, "error")
                self.db.finish_task(tid, "error", detail_append=str(e)[:200])
                self.db.save_finding(scan_id, mod.NAME, "info",
                    f"Module Error: {mod.LABEL}", f"Module error: {e}",
                    tags=["error","module"])
                return mod, e
            if mod._last_subtask_id:
                self.db.finish_task(mod._last_subtask_id, "done")
            skipped = scan_id in self._skip_signals
            fin_status = "skipped" if skipped else "done"
            self.db.finish_task(tid, fin_status)
            self._skip_signals.discard(scan_id)
            self.http._force_timeout = None
            return mod, None

        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

        MAX_PARALLEL = 4
        completed = 0
        batch_start = 0

        while batch_start < total and scan_id in self._running:
            batch = enabled_modules[batch_start: batch_start + MAX_PARALLEL]
            batch_start += MAX_PARALLEL

            running_names = ", ".join(f"{c.ICON}{c.LABEL}" for c in batch)
            self.db.set_scan_status(scan_id, "running",
                progress=int((completed / total) * 90),
                current_module=running_names[:80])

            with ThreadPoolExecutor(max_workers=MAX_PARALLEL,
                                    thread_name_prefix="feroxsei-mod") as pool:
                futs = {pool.submit(_run_one_module, cls, batch_start - MAX_PARALLEL + i): cls
                        for i, cls in enumerate(batch)}
                for fut in _as_completed(futs):
                    completed += 1
                    # Re-raise any unexpected exceptions from the future
                    try:
                        fut.result()
                    except Exception as _fe:
                        _log(f"[ENGINE] Future error: {_fe}")

            # Clear any lingering skip signal after batch completes
            self._skip_signals.discard(scan_id)
            self.http._force_timeout = None

        # Done
        self.db.set_scan_status(scan_id, "completed", progress=100,
                                current_module="")
        self._running.pop(scan_id, None)
        self._skip_signals.discard(scan_id)
        summary = self.db.findings_summary(scan_id)
        done_tid = self.db.log_task(scan_id, "engine", "✅ Scan completed",
                                    detail=str(summary), module_label="Engine", module_icon="⬡")
        self.db.finish_task(done_tid, "done")
        _log(f"[ENGINE] Scan {scan_id[:8]} complete - {summary}")

        # ── Notify scan owner ─────────────────────────────────────────────────
        try:
            scan_user = scan.get("user_id", "")
            if scan_user:
                import uuid as _uuid_n
                _nid = str(_uuid_n.uuid4())
                _nbody = f"Target: {target} | Findings: {summary}"
                self.db.exec(
                    "INSERT OR IGNORE INTO notifications"
                    "(id,user_id,type,title,body,is_read,link,created_at)"
                    " VALUES(?,?,?,?,?,0,?,?)",
                    (_nid, scan_user, "scan",
                     f"Scan complete: {target[:60]}",
                     _nbody[:300],
                     f"/scan/{scan_id}",
                     _now())
                )
        except Exception as _ne:
            _log(f"[ENGINE] Notification insert failed: {_ne}")

        # ── Auto-extract entities into the investigation graph ────────────────
        inv_id = scan.get("investigation_id", "")
        if inv_id:
            try:
                n_ent, n_rel = self._extract_entities_from_scan(
                    scan_id, inv_id, target, target_types[0] if target_types else "domain")
                _log(f"[ENGINE] Entity graph: +{n_ent} entities, +{n_rel} relationships")
            except Exception as _eg:
                _log(f"[ENGINE] Entity extraction error: {_eg}")

    # ── Entity extraction post-processor ──────────────────────────────────────
    def _extract_entities_from_scan(self, scan_id: str, inv_id: str,
                                    target: str, target_type: str) -> tuple[int, int]:
        """Parse all findings for scan_id and populate the entity graph.
        Returns (new_entities, new_relationships)."""
        import re as _re

        _IP_RE    = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        _EMAIL_RE = _re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')
        _DOM_RE   = _re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|onion|[a-z]{2,6})\b',
            _re.I)
        _PHONE_RE = _re.compile(r'\+?[\d][\d\s\-\(\)]{7,15}[\d]')
        _USER_RE  = _re.compile(r'(?:username|user|handle|account|profile)[\s:=]+([A-Za-z0-9_\-\.]{3,30})', _re.I)
        _ORG_RE   = _re.compile(r'(?:organization|org|company|corp|inc|ltd|llc)[\s:=]+([A-Za-z0-9 &,\.\-]{3,60})', _re.I)
        _PERSON_RE= _re.compile(r'(?:registrant|owner|admin|contact|name)[\s:=]+([A-Za-z]{2,30}(?:\s[A-Za-z]{2,30}){1,3})', _re.I)

        # Skip-lists - extremely generic values that pollute the graph
        _SKIP_DOMAINS = {
            "com","net","org","io","gov","edu","co","uk","de","fr","ru","cn","info",
            "cloudflare.com","google.com","amazonaws.com","github.com",
            "googleapis.com","gstatic.com","jquery.com","cdnjs.cloudflare.com",
        }
        _SKIP_IPS = {"127.0.0.1","0.0.0.0","255.255.255.255","8.8.8.8","8.8.4.4","1.1.1.1"}

        findings = self.db.get_findings(scan_id, limit=2000)
        n_ent = n_rel = 0

        # ── Seed target node ─────────────────────────────────────────────────
        target_id = self.db.ensure_entity(inv_id, target_type, target,
                                          label=target, confidence=100,
                                          source_module="engine",
                                          metadata={"target": True},
                                          scan_id=scan_id)
        if target_id:
            n_ent += 1

        def _add(etype, value, module, conf=70, meta=None):
            nonlocal n_ent
            eid = self.db.ensure_entity(inv_id, etype, value,
                                        confidence=conf, source_module=module,
                                        metadata=meta or {},
                                        scan_id=scan_id)
            if eid:
                n_ent += 1
            return eid

        def _rel(src, tgt, rtype, conf=65):
            nonlocal n_rel
            if src and tgt:
                rid = self.db.ensure_relationship(inv_id, src, tgt, rtype, conf)
                if rid:
                    n_rel += 1
            return rid if src and tgt else ""

        for f in findings:
            mod  = f.get("module", "")
            text = " ".join(filter(None, [
                f.get("title",""), f.get("description",""),
                f.get("evidence",""), f.get("url","")
            ]))
            sev  = f.get("severity","info")
            conf = {"critical":95,"high":85,"medium":70,"low":55,"info":45}.get(sev, 60)

            # ── Cert Transparency / DNS → subdomains ─────────────────────────
            if mod in ("certTransparency", "dns"):
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom in _SKIP_DOMAINS or dom == target:
                        continue
                    if target_type == "domain" and not dom.endswith(target):
                        continue
                    eid = _add("domain", dom, mod, conf)
                    _rel(eid, target_id, "subdomain_of", conf)

            # ── DNS → IPs ─────────────────────────────────────────────────────
            if mod == "dns":
                for ip in set(_IP_RE.findall(text)):
                    if ip in _SKIP_IPS:
                        continue
                    eid = _add("ip", ip, mod, conf)
                    _rel(eid, target_id, "resolves_to", conf)

            # ── Email Harvester → emails ──────────────────────────────────────
            if mod in ("emailHarvest", "identity"):
                for email in set(_EMAIL_RE.findall(text)):
                    eid = _add("email", email.lower(), mod, conf)
                    _rel(eid, target_id, "associated_with", conf)
                    # link email → domain part
                    dom_part = email.lower().split("@")[-1] if "@" in email else ""
                    if dom_part and dom_part not in _SKIP_DOMAINS:
                        did = _add("domain", dom_part, mod, 65)
                        _rel(eid, did, "belongs_to", 80)

            # ── Infrastructure → IPs ──────────────────────────────────────────
            if mod in ("infrastructure", "threatIntel", "subTakeover"):
                for ip in set(_IP_RE.findall(text)):
                    if ip in _SKIP_IPS:
                        continue
                    eid = _add("ip", ip, mod, conf)
                    _rel(eid, target_id, "hosts", conf)

            # ── Username Hunt → usernames + Flickr IDs ───────────────────────
            if mod in ("username", "socialMedia"):
                for m in _USER_RE.finditer(text):
                    uname = m.group(1).strip()
                    if len(uname) >= 3:
                        eid = _add("username", uname, mod, conf)
                        _rel(eid, target_id, "associated_with", conf)
                # Flickr numeric ID extraction (e.g. 90535065@N03)
                _FLICKR_ID_RE = _re.compile(r'\b(\d{5,15}@N\d{2,3})\b')
                for fm in _FLICKR_ID_RE.finditer(text):
                    fid = fm.group(1)
                    eid = _add("flickr_id", fid, mod, conf)
                    _rel(eid, target_id, "flickr_id_of", conf)
                if target_type == "username":
                    _rel(target_id, target_id, "found_on", 0)

            # ── Phone OSINT → phone ───────────────────────────────────────────
            if mod == "phoneOsint" and target_type == "phone":
                for pm in _PHONE_RE.findall(text):
                    pm = pm.strip()
                    if len(pm) >= 8 and pm != target:
                        _add("phone", pm, mod, conf - 10)

            # ── Identity → org / person ───────────────────────────────────────
            if mod == "identity":
                for m in _ORG_RE.finditer(text):
                    org = m.group(1).strip()
                    if len(org) >= 3:
                        eid = _add("organization", org, mod, conf)
                        _rel(eid, target_id, "operates", conf)
                for m in _PERSON_RE.finditer(text):
                    person = m.group(1).strip()
                    if len(person) >= 5 and person.lower() not in ("domain name", "not applicable"):
                        eid = _add("person", person, mod, conf - 10)
                        _rel(eid, target_id, "associated_with", conf - 10)

            # ── Dark Web → onion domains ──────────────────────────────────────
            if mod == "darkWeb":
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom.endswith(".onion"):
                        eid = _add("domain", dom, mod, conf)
                        _rel(eid, target_id, "mentions", conf)

            # ── Typosquat → registered variants ──────────────────────────────
            if mod == "typosquat":
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom in _SKIP_DOMAINS or dom == target:
                        continue
                    eid = _add("domain", dom, mod, conf)
                    _rel(eid, target_id, "typosquat_of", conf)

            # ── Git Leaks → urls/domains ──────────────────────────────────────
            if mod == "gitLeaks":
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom in _SKIP_DOMAINS:
                        continue
                    eid = _add("domain", dom, mod, conf)
                    _rel(eid, target_id, "leaked_from", conf)
                for email in set(_EMAIL_RE.findall(text)):
                    eid = _add("email", email.lower(), mod, conf)
                    _rel(eid, target_id, "leaked_from", conf)

            # ── Cloud Exposure → domains ──────────────────────────────────────
            if mod == "cloudExposure":
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom in _SKIP_DOMAINS:
                        continue
                    eid = _add("domain", dom, mod, conf)
                    _rel(eid, target_id, "cloud_asset_of", conf)

            # ── Image OSINT → GPS location, URLs, matched domains, persons ──────
            if mod == "imageOsint":
                # GPS coordinates → location entity
                _GPS_RE = _re.compile(
                    r'(?:GPS|Coordinates?|Lat(?:itude)?|Lon(?:gitude)?)[^\d\-]*'
                    r'([\-]?\d{1,3}\.\d{4,})[^\d\-]+([\-]?\d{1,3}\.\d{4,})',
                    _re.I)
                for gm in _GPS_RE.finditer(text):
                    loc_val = f"{gm.group(1)},{gm.group(2)}"
                    eid = _add("location", loc_val, mod, conf)
                    _rel(eid, target_id, "gps_from", conf)
                # Reverse-search matched domains (flickr.com, yandex.com, etc.)
                _IMG_SKIP = {"flickr.com","yandex.com","bing.com","tineye.com",
                             "lens.google.com","picsum.photos"}
                for dom in set(_DOM_RE.findall(text)):
                    dom = dom.lower()
                    if dom in _SKIP_DOMAINS or dom in _IMG_SKIP:
                        continue
                    eid = _add("domain", dom, mod, conf - 10)
                    _rel(eid, target_id, "found_in_image", conf - 10)
                # Person names from context (subject_name in title/description)
                _IMG_PERSON_RE = _re.compile(
                    r"(?:subject|person|name|Context Username)[:\s]+([A-Z][a-z]{1,19}\s[A-Z][a-z]{1,19})"
                )
                for pm in _IMG_PERSON_RE.finditer(text):
                    person = pm.group(1).strip()
                    if len(person) >= 4:
                        eid = _add("person", person, mod, conf)
                        _rel(eid, target_id, "depicted_in", conf)
                # Usernames confirmed via userhunt
                _IMG_USER_RE = _re.compile(
                    r"username\s+'([A-Za-z0-9_.]{3,30})'", _re.I)
                for um in _IMG_USER_RE.finditer(text):
                    uname = um.group(1).strip()
                    eid = _add("username", uname, mod, conf)
                    _rel(eid, target_id, "identity_linked_to", conf)
                # Emails in OCR or DDG hits
                for email in set(_EMAIL_RE.findall(text)):
                    eid = _add("email", email.lower(), mod, conf - 15)
                    _rel(eid, target_id, "found_in_image", conf - 15)

        return n_ent, n_rel
