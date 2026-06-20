"""
FEROXSEI OSINT - Base module class + shared helpers.
All module files in modules/ must import and subclass BaseOSINTModule.
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse


# ── Shared helpers (used by modules and engine) ───────────────────────────────

def _now() -> str:
    return datetime.now().isoformat()

def _log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def _is_keyword_target(target: str) -> bool:
    """
    Returns True if the target is a free-text keyword/phrase rather than
    a domain, URL, IP, email, or @handle.
    Keyword indicators: contains spaces, or has no dot outside of @handle/email.
    """
    t = target.strip()
    if t.startswith("@"):
        return False
    if "://" in t:
        return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', t):
        return False   # IPv4
    if "@" in t and "." in t.split("@")[-1]:
        return False   # email
    if " " in t:
        return True    # sentence / multi-word phrase
    # No dots at all → likely a single-word keyword
    if "." not in t:
        return True
    return False

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

def _thread_pool(max_workers: int = 8):
    from concurrent.futures import ThreadPoolExecutor
    return ThreadPoolExecutor(max_workers=max_workers)


# ── Base class ────────────────────────────────────────────────────────────────

class BaseOSINTModule:
    """
    Base class for all FEROXSEI OSINT modules.

    To create a new module, make a .py file in modules/ and define a class that:
    - inherits BaseOSINTModule
    - sets NAME (str), LABEL (str), ICON (str) as class attributes
    - implements run(self, scan_id: str, target: str, config: dict)

    The engine auto-discovers any BaseOSINTModule subclass in modules/*.py at
    startup - no manual registration needed.
    """
    NAME:  str = "baseModule"
    LABEL: str = "Base Module"
    ICON:  str = "🔌"
    # Set to True if this module requires TOR to be useful
    REQUIRES_TOR: bool = False
    # Execution order (lower = earlier in the pipeline)
    ORDER: int = 50
    # Mark as experimental / beta
    EXPERIMENTAL: bool = False
    # Target types this module is relevant for.
    # Valid values: "domain", "ip", "email", "username", "phone", "string"
    # The engine uses this to skip modules that don't apply to the selected target types.
    TARGET_TYPES: list = ["domain"]

    def __init__(self, engine: Any):
        self.engine   = engine
        self.db       = engine.db
        self.http     = engine.http
        self.patterns = engine.patterns
        self._task_id: str = ""
        self._last_subtask_id: str = ""
        # Set by engine before run() - used by _pattern_scan() to scope pattern matching
        self._target_type: str = "domain"

    @property
    def use_tor(self) -> bool:
        return bool(getattr(self.http, "use_tor", False))

    def safe_resolve(self, hostname: str, record_type: str = "A") -> list:
        """
        Resolve hostname to IPs without leaking source IP.
        When TOR is enabled: resolves via Cloudflare DoH through the TOR SOCKS5 session.
        When TOR is off: uses local socket.getaddrinfo().
        Returns list of IP strings (empty list on failure).
        """
        hostname = hostname.strip().rstrip(".")
        if not hostname:
            return []
        if not self.use_tor:
            import socket as _sock
            try:
                return list({r[4][0] for r in _sock.getaddrinfo(hostname, None)})
            except Exception:
                return []
        try:
            r = self.http._session.get(
                f"https://cloudflare-dns.com/dns-query?name={hostname}&type={record_type}",
                headers={"Accept": "application/dns-json"},
                timeout=10,
                allow_redirects=True,
            )
            if r and r.status_code == 200:
                data = r.json()
                answers = data.get("Answer") or []
                type_num = {"A": 1, "AAAA": 28, "PTR": 12, "MX": 15}.get(record_type, 1)
                return [a["data"] for a in answers if a.get("type") == type_num]
        except Exception:
            pass
        return []

    def safe_reverse_dns(self, ip: str) -> str:
        """Reverse-resolve an IP to hostname without leaking source IP."""
        if not self.use_tor:
            import socket as _sock
            try:
                return _sock.gethostbyaddr(ip)[0]
            except Exception:
                return ""
        parts = ip.split(".")
        if len(parts) == 4:
            arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
            results = self.safe_resolve(arpa, record_type="PTR")
            return results[0].rstrip(".") if results else ""
        return ""

    def run(self, scan_id: str, target: str, config: Dict[str, Any]) -> None:
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    def emit_task(self, scan_id: str, task: str, detail: str = "") -> None:
        """
        Create a new child task log entry for real-time sub-step tracking.
        Each call produces a separate row in the Task Activity Log so the full
        history of what the module did is visible.

        Example:
            self.emit_task(scan_id, "Resolving DNS A records", detail="querying 8 record types")
            self.emit_task(scan_id, "Attempting zone transfer")
        """
        if self._task_id:
            # Mark the previous sub-task as done before creating the next one
            if self._last_subtask_id:
                self.db.finish_task(self._last_subtask_id, "done")
            # Create a new child row under the parent module task
            self._last_subtask_id = self.db.log_task(
                scan_id, self.NAME, task, detail=detail,
                module_label=self.LABEL, module_icon=self.ICON,
                parent_id=self._task_id
            )
        else:
            # No task_id yet (direct module use without engine), create a standalone row
            self._task_id = self.db.log_task(
                scan_id, self.NAME, task, detail=detail,
                module_label=self.LABEL, module_icon=self.ICON
            )
            self._last_subtask_id = self._task_id

    def should_skip(self, scan_id: str) -> bool:
        """
        Check if the engine has been asked to skip this module.
        Call this inside long-running loops to bail out early.

        Example:
            for url in urls:
                if self.should_skip(scan_id):
                    break
                ...process url...
        """
        return scan_id in getattr(self.engine, "_skip_signals", set())

    def _get_config(self, config: dict, key: str, default=None):
        """Safely retrieve a value from the scan config."""
        return config.get(key, default)

    def _pattern_scan(self, scan_id: str, text: str, url: str = "",
                      max_hits: int = 20, strip_scripts: bool = True) -> int:
        """
        Run all enabled patterns against `text` and save any hits as findings.
        Returns the number of new findings saved.

        Patterns are web/domain-oriented (HTTP headers, secrets in pages, etc.).
        This method automatically skips for non-web target types (username, phone,
        string, etc.) to prevent irrelevant noise in OSINT-only scans.

        strip_scripts=True (default): removes <script>, <style>, <noscript> and
        HTML comments before scanning so inline JS/CSS doesn't generate false positives.

        Example:
            r = self.http.get(url, scan_id, self.NAME)
            if r and r.status_code == 200:
                self._pattern_scan(scan_id, r.text, url)
        """
        if not text:
            return 0
        # Only run pattern matching for web targets (domain / ip / url).
        # For username, email, phone, string targets, patterns are domain-specific
        # regex (paths, headers, HTTP responses) and would only produce false positives.
        if self._target_type not in ("domain", "ip", "url"):
            return 0

        scan_text = text
        if strip_scripts:
            try:
                from bs4 import BeautifulSoup as _BS
                soup = _BS(text, "html.parser")
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                # Remove HTML comments
                for comment in soup.find_all(string=lambda s: isinstance(s, str) and s.strip().startswith("<!--")):
                    comment.extract()
                scan_text = soup.get_text(separator=" ")
            except Exception:
                # BS4 not available - regex strip of script blocks
                scan_text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.S | re.I)
                scan_text = re.sub(r'<style[^>]*>.*?</style>',   ' ', scan_text, flags=re.S | re.I)
                scan_text = re.sub(r'<!--.*?-->',                 ' ', scan_text, flags=re.S)

        hits = self.patterns.scan_text(scan_text, url)
        count = 0
        for hit in hits[:max_hits]:
            self.db.save_finding(
                scan_id, self.NAME, hit["severity"],
                f"Pattern Match [{self.LABEL}]: {hit['pattern_name']}",
                f"Found in response from {url or 'unknown'}: {hit['context'][:200]}",
                url=url, evidence=hit["evidence"],
                pattern_id=hit.get("pattern_id", ""),
                tags=["pattern", hit.get("category", ""), self.NAME.lower()]
            )
            count += 1
        return count
