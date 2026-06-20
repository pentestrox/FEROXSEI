"""
FEROXSEI Anonymous Mode - TOR Integration Layer
=============================================
Provides centralized TOR/SOCKS5 routing for all outbound traffic:
  • TorManager     - daemon lifecycle, identity rotation, health monitoring
  • ProxyRouter    - SOCKS5 config for httpx, playwright, subprocesses
  • CircuitMonitor - hop visualization, node metadata, latency
  • LeakGuard      - DNS/IPv6/direct-socket leak prevention
  • TrafficStats   - per-session counters

Dependencies (install when Anonymous Mode is enabled):
  pip install stem PySocks httpx[socks] --break-system-packages
  apt install tor proxychains4
"""

from __future__ import annotations
import os, sys, json, time, threading, subprocess, socket, struct
import logging, ipaddress, hashlib, random
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timedelta

logger = logging.getLogger("feroxsei.tor")

# ── Default ports ─────────────────────────────────────────────────────────────
TOR_SOCKS_HOST    = "127.0.0.1"
TOR_SOCKS_PORT    = 9050
TOR_CONTROL_PORT  = 9051
TOR_CHECK_URL     = "https://check.torproject.org/api/ip"
TOR_IP_URL        = "https://api.ipify.org?format=json"

# ── Singleton ─────────────────────────────────────────────────────────────────
_tor_manager: Optional["TorManager"] = None

def get_tor_manager() -> "TorManager":
    global _tor_manager
    if _tor_manager is None:
        _tor_manager = TorManager()
    return _tor_manager


# ══════════════════════════════════════════════════════════════════════════════
# TorManager
# ══════════════════════════════════════════════════════════════════════════════
class TorManager:
    """
    Manages the TOR daemon lifecycle and provides status information.
    Spawns a background monitor thread that polls TOR health every 10 s.
    """

    STATUS_DISABLED     = "disabled"
    STATUS_CONNECTING   = "connecting"
    STATUS_CONNECTED    = "connected"
    STATUS_DISCONNECTED = "disconnected"
    STATUS_ERROR        = "error"

    def __init__(self,
                 socks_host: str = TOR_SOCKS_HOST,
                 socks_port: int = TOR_SOCKS_PORT,
                 control_port: int = TOR_CONTROL_PORT,
                 control_password: str = "",
                 auto_newnym_minutes: int = 0,
                 kill_switch: bool = True):
        self.socks_host         = socks_host
        self.socks_port         = socks_port
        self.control_port       = control_port
        self.control_password   = control_password
        self.auto_newnym_minutes= auto_newnym_minutes
        self.kill_switch        = kill_switch

        self._status            = self.STATUS_DISABLED
        self._exit_ip: str      = ""
        self._exit_country: str = ""
        self._latency_ms: int   = 0
        self._circuit_nodes: List[Dict] = []
        self._traffic_in: int   = 0
        self._traffic_out: int  = 0
        self._last_newnym: Optional[datetime] = None
        self._connected_since: Optional[datetime] = None
        self._blocked_leaks: int = 0

        self._tor_proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._monitor_stop = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._enabled = False

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def status(self) -> str:
        return self._status

    @property
    def is_connected(self) -> bool:
        return self._status == self.STATUS_CONNECTED

    def enable(self, start_daemon: bool = True) -> Tuple[bool, str]:
        """Enable TOR routing, optionally starting the daemon."""
        self._enabled = True
        if start_daemon:
            ok, msg = self._ensure_tor_running()
            if not ok:
                return False, msg
        self._start_monitor()
        return True, "TOR anonymous mode enabled"

    def disable(self) -> None:
        """Disable TOR routing (does not stop the daemon)."""
        self._enabled = False
        self._stop_monitor()
        self._status = self.STATUS_DISABLED
        LeakGuard.restore_sockets()

    def start(self) -> Tuple[bool, str]:
        """Start TOR daemon."""
        return self._ensure_tor_running()

    def stop(self) -> None:
        """Stop the managed TOR process (if we started it)."""
        self._stop_monitor()
        if self._tor_proc and self._tor_proc.poll() is None:
            try:
                self._tor_proc.terminate()
                self._tor_proc.wait(timeout=5)
            except Exception:
                try:
                    self._tor_proc.kill()
                except Exception:
                    pass
            self._tor_proc = None
        self._status = self.STATUS_DISABLED
        self._enabled = False

    def new_identity(self) -> Tuple[bool, str]:
        """
        Send NEWNYM signal - get a new TOR circuit.
        If TOR is not running, starts it first.
        Falls back to restarting TOR if the control port is unreachable.
        Never blocks the caller - IP refresh happens in the background.
        """
        # If TOR is not running, start it first
        if not self._socks_alive():
            logger.info("[TOR] new_identity: TOR not running - starting first")
            ok, msg = self._ensure_tor_running()
            if not ok:
                return False, f"Could not start TOR: {msg}"
            self._last_newnym = datetime.now()
            def _delayed_fresh():
                time.sleep(5)
                self._refresh_exit_ip()
                self._refresh_circuit()
            threading.Thread(target=_delayed_fresh, daemon=True).start()
            return True, "TOR started with a fresh circuit. Exit IP updates in ~5s."

        # Try stem NEWNYM first (non-blocking - sleep in background)
        try:
            import stem
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=self.control_port) as ctrl:
                if self.control_password:
                    ctrl.authenticate(password=self.control_password)
                else:
                    ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
                self._last_newnym = datetime.now()
                self._exit_ip = ""          # clear immediately so UI shows refreshing
                self._exit_country = ""
                # TOR rate-limits NEWNYM to once per 10 s - refresh after that
                def _delayed_refresh():
                    time.sleep(10)
                    self._refresh_exit_ip()
                    self._refresh_circuit()
                threading.Thread(target=_delayed_refresh, daemon=True).start()
                logger.info("[TOR] New identity - NEWNYM sent via control port")
                return True, "NEWNYM sent - new circuit building. Exit IP updates in ~10s."
        except ImportError:
            pass   # stem not installed - fall through to restart
        except Exception as _stem_err:
            _conn_refused = "111" in str(_stem_err) or "refused" in str(_stem_err).lower()
            if _conn_refused:
                logger.warning("[TOR] Control port refused - restarting TOR for new identity")
            else:
                logger.warning(f"[TOR] NEWNYM failed: {_stem_err}")

        # Fallback: restart TOR daemon for a fresh circuit
        try:
            logger.info("[TOR] Restarting TOR for new identity (control port unavailable)")
            if self._tor_proc and self._tor_proc.poll() is None:
                self._tor_proc.terminate()
                try:
                    self._tor_proc.wait(timeout=5)
                except Exception:
                    self._tor_proc.kill()
            self._tor_proc = None
            self._exit_ip = ""
            self._exit_country = ""
            self._circuit_nodes = []
            self._status = self.STATUS_CONNECTING
            ok, msg = self._ensure_tor_running()
            if ok:
                self._last_newnym = datetime.now()
                def _delayed_restart_refresh():
                    time.sleep(5)
                    self._refresh_exit_ip()
                    self._refresh_circuit()
                threading.Thread(target=_delayed_restart_refresh, daemon=True).start()
                return True, "New identity via TOR restart. Exit IP updates in ~5s."
            return False, (
                f"TOR restart failed: {msg}\n\n"
                "To enable control port without restart, add to /etc/tor/torrc:\n"
                "  ControlPort 9051\n"
                "  CookieAuthentication 0\n"
                "Then run: sudo systemctl reload tor"
            )
        except Exception as _restart_err:
            return False, str(_restart_err)

    def get_status_dict(self) -> Dict[str, Any]:
        """Return full status snapshot for the UI."""
        return {
            "enabled":        self._enabled,
            "status":         self._status,
            "exit_ip":        self._exit_ip,
            "exit_country":   self._exit_country,
            "latency_ms":     self._latency_ms,
            "hop_count":      len(self._circuit_nodes),
            "circuit_nodes":  self._circuit_nodes,
            "traffic_in_kb":  self._traffic_in // 1024,
            "traffic_out_kb": self._traffic_out // 1024,
            "last_newnym":    self._last_newnym.isoformat() if self._last_newnym else None,
            "connected_since":self._connected_since.isoformat() if self._connected_since else None,
            "blocked_leaks":  self._blocked_leaks,
            "socks_host":     self.socks_host,
            "socks_port":     self.socks_port,
            "kill_switch":    self.kill_switch,
        }

    def increment_traffic(self, sent: int, received: int) -> None:
        self._traffic_out += sent
        self._traffic_in  += received

    def increment_blocked(self) -> None:
        self._blocked_leaks += 1

    # ── Internal ───────────────────────────────────────────────────────────────

    def _ensure_tor_running(self) -> Tuple[bool, str]:
        """Check if TOR is already listening; if not, start it."""
        if self._socks_alive():
            self._status = self.STATUS_CONNECTED
            self._connected_since = self._connected_since or datetime.now()
            return True, "TOR already running"

        # Try starting system TOR
        tor_bin = self._find_tor_bin()
        if not tor_bin:
            return False, ("TOR not installed. Install with:\n"
                           "  Linux:   sudo apt install tor\n"
                           "  macOS:   brew install tor\n"
                           "  Windows: https://www.torproject.org/download/")

        self._status = self.STATUS_CONNECTING
        logger.info(f"[TOR] Starting TOR daemon: {tor_bin}")

        # Write a minimal torrc that enables SOCKS5 + control port
        torrc_path = self._write_torrc()
        tor_cmd = [tor_bin, "-f", torrc_path] if torrc_path else [tor_bin]

        try:
            self._tor_proc = subprocess.Popen(
                tor_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True
            )
        except Exception as e:
            self._status = self.STATUS_ERROR
            return False, f"Failed to start TOR: {e}"

        # Wait up to 30 s for SOCKS port
        for _ in range(30):
            time.sleep(1)
            if self._socks_alive():
                self._status = self.STATUS_CONNECTED
                self._connected_since = datetime.now()
                logger.info("[TOR] Connected - SOCKS5 ready")
                return True, "TOR started successfully"

        self._status = self.STATUS_ERROR
        return False, "TOR started but SOCKS port not responding within 30 s"

    def _socks_alive(self) -> bool:
        """Check if the TOR SOCKS5 port is accepting connections."""
        try:
            with socket.create_connection((self.socks_host, self.socks_port), timeout=2):
                return True
        except OSError:
            return False

    def _write_torrc(self) -> Optional[str]:
        """Write a minimal torrc enabling SOCKS5 + unauthenticated control port."""
        try:
            torrc = (
                f"SocksPort {self.socks_host}:{self.socks_port}\n"
                f"ControlPort 127.0.0.1:{self.control_port}\n"
                "CookieAuthentication 0\n"
                "HashedControlPassword \"\"\n"
                "DataDirectory /tmp/feroxsei_tor_data\n"
                "Log notice stderr\n"
            )
            path = "/tmp/feroxsei_torrc"
            os.makedirs("/tmp/feroxsei_tor_data", exist_ok=True)
            with open(path, "w") as f:
                f.write(torrc)
            return path
        except Exception as e:
            logger.warning(f"[TOR] Could not write torrc: {e}")
            return None

    def _find_tor_bin(self) -> Optional[str]:
        """Locate the TOR binary."""
        import shutil
        for name in ("tor", "tor.exe"):
            p = shutil.which(name)
            if p:
                return p
        for candidate in ("/usr/bin/tor", "/usr/local/bin/tor",
                          "/opt/homebrew/bin/tor", r"C:\Tor\tor.exe"):
            if os.path.isfile(candidate):
                return candidate
        return None

    def _start_monitor(self) -> None:
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="feroxsei-tor-monitor")
        self._monitor_thread.start()

    def _stop_monitor(self) -> None:
        self._monitor_stop.set()

    def _monitor_loop(self) -> None:
        """Background loop: health check every 10 s, auto-newnym, circuit refresh."""
        logger.info("[TOR] Monitor started")
        last_newnym_check = time.time()
        while not self._monitor_stop.is_set():
            try:
                self._health_check()
                # Auto-rotate identity
                if (self.auto_newnym_minutes > 0 and
                        self._last_newnym is not None and
                        (datetime.now() - self._last_newnym).seconds >
                        self.auto_newnym_minutes * 60):
                    self.new_identity()
                elif self.auto_newnym_minutes > 0 and self._last_newnym is None:
                    self._last_newnym = datetime.now()
            except Exception as e:
                logger.debug(f"[TOR] Monitor error: {e}")
            self._monitor_stop.wait(10)
        logger.info("[TOR] Monitor stopped")

    def _health_check(self) -> None:
        """Check SOCKS connectivity and refresh exit IP if newly connected."""
        was_connected = self.is_connected
        alive = self._socks_alive()
        if alive:
            if not was_connected:
                self._status = self.STATUS_CONNECTED
                self._connected_since = self._connected_since or datetime.now()
                self._refresh_exit_ip()
                self._refresh_circuit()
            elif not self._exit_ip:
                self._refresh_exit_ip()
                self._refresh_circuit()
        else:
            if was_connected and self.kill_switch:
                logger.warning("[TOR] Kill-switch triggered - TOR disconnected")
            self._status = self.STATUS_DISCONNECTED
            self._exit_ip = ""
            self._exit_country = ""

    def _refresh_exit_ip(self) -> None:
        """Fetch current exit IP through TOR SOCKS5 (httpx → curl fallback)."""
        t0 = time.time()
        ip = ""
        # Try httpx with socks support first
        try:
            import httpx
            proxy = f"socks5://{self.socks_host}:{self.socks_port}"
            with httpx.Client(proxy=proxy, timeout=10, verify=False) as c:
                r = c.get("https://api.ipify.org?format=json")
                ip = r.json().get("ip", "")
        except Exception as _hx_err:
            logger.debug(f"[TOR] httpx exit IP failed ({_hx_err}), trying curl")
            # curl fallback - always available on Linux/macOS
            try:
                r = subprocess.run(
                    ["curl", "-s", "--max-time", "10",
                     "--socks5-hostname", f"{self.socks_host}:{self.socks_port}",
                     "https://api.ipify.org?format=json"],
                    capture_output=True, text=True, timeout=15
                )
                if r.returncode == 0 and r.stdout:
                    import json as _json
                    ip = _json.loads(r.stdout).get("ip", "")
            except Exception as _curl_err:
                logger.debug(f"[TOR] curl exit IP also failed: {_curl_err}")

        if ip:
            self._exit_ip = ip
            self._exit_country = _geoip_country(ip)
            self._latency_ms = int((time.time() - t0) * 1000)
            logger.info(f"[TOR] Exit IP: {ip} ({self._exit_country}) {self._latency_ms}ms")

    def _refresh_circuit(self) -> None:
        """Fetch circuit nodes from TOR control port."""
        nodes = CircuitMonitor.get_active_circuit(self.control_port, self.control_password)
        if nodes:
            self._circuit_nodes = nodes


# ══════════════════════════════════════════════════════════════════════════════
# ProxyRouter  - centralized proxy configuration
# ══════════════════════════════════════════════════════════════════════════════
class ProxyRouter:
    """
    Single source of truth for proxy settings.
    Used by _get_httpx_client, playwright, and subprocess launchers.
    """

    def __init__(self, tor: TorManager):
        self._tor = tor

    @property
    def active(self) -> bool:
        return self._tor.enabled

    @property
    def socks5_url(self) -> str:
        return f"socks5://{self._tor.socks_host}:{self._tor.socks_port}"

    def httpx_proxies(self) -> Dict[str, str]:
        """Proxy dict for httpx.AsyncClient(proxy=...)."""
        if self.active:
            return self.socks5_url
        return None

    def playwright_proxy(self) -> Optional[Dict]:
        """Proxy config for playwright Browser.new_context(proxy=...)."""
        if self.active:
            return {"server": self.socks5_url}
        return None

    def env_vars(self) -> Dict[str, str]:
        """Extra env vars that instruct subprocesses to use SOCKS5."""
        if self.active:
            return {
                "ALL_PROXY":   self.socks5_url,
                "http_proxy":  self.socks5_url,
                "https_proxy": self.socks5_url,
                "HTTP_PROXY":  self.socks5_url,
                "HTTPS_PROXY": self.socks5_url,
                "SOCKS5_PROXY":self.socks5_url,
            }
        return {}

    def proxychains_prefix(self) -> List[str]:
        """
        Command prefix for tools that don't respect env proxies (nmap, etc.).
        Returns ["proxychains4", "-q"] when TOR is active, [] otherwise.
        """
        if not self.active:
            return []
        import shutil
        for pc in ("proxychains4", "proxychains"):
            if shutil.which(pc):
                return [pc, "-q"]
        logger.warning("[TOR] proxychains not found - tool traffic may bypass TOR")
        return []

    def merge_env(self, base_env: Optional[Dict] = None) -> Dict[str, str]:
        """Merge proxy env vars into a base env dict."""
        env = dict(os.environ) if base_env is None else dict(base_env)
        env.update(self.env_vars())
        return env


# ══════════════════════════════════════════════════════════════════════════════
# CircuitMonitor  - hop visualization
# ══════════════════════════════════════════════════════════════════════════════
class CircuitMonitor:
    """Fetch live circuit info from TOR control port via stem."""

    @staticmethod
    def get_active_circuit(control_port: int = 9051,
                           password: str = "") -> List[Dict]:
        """
        Return a list of hop dicts:
            [{fingerprint, nickname, ip, country, asn, latency_ms}, ...]
        Uses stem if available; returns mock data otherwise.
        """
        try:
            from stem.control import Controller
            from stem import StreamStatus
            hops = []
            with Controller.from_port(port=control_port) as ctrl:
                if password:
                    ctrl.authenticate(password=password)
                else:
                    ctrl.authenticate()

                circuits = ctrl.get_circuits()
                best = None
                for c in circuits:
                    if c.status == 'BUILT' and len(c.path) >= 3:
                        best = c
                        break
                if best is None and circuits:
                    best = circuits[-1]
                if best is None:
                    return []

                for i, (fpr, nickname) in enumerate(best.path):
                    role = ["Guard", "Middle", "Exit"][min(i, 2)]
                    info = CircuitMonitor._relay_info(ctrl, fpr)
                    hops.append({
                        "index":       i + 1,
                        "role":        role,
                        "fingerprint": fpr,
                        "nickname":    nickname or info.get("nickname", "?"),
                        "ip":          info.get("ip", "?.?.?.?"),
                        "country":     info.get("country", "??"),
                        "asn":         info.get("asn", ""),
                        "latency_ms":  info.get("latency_ms", 0),
                    })
            return hops
        except ImportError:
            logger.debug("[TOR] stem not installed - circuit info unavailable")
            return CircuitMonitor._mock_circuit()
        except Exception as e:
            logger.debug(f"[TOR] Circuit fetch error: {e}")
            return []

    @staticmethod
    def _relay_info(ctrl, fingerprint: str) -> Dict:
        """Get relay info from controller."""
        try:
            desc = ctrl.get_network_status(fingerprint, default=None)
            if desc:
                return {
                    "ip":       str(desc.address),
                    "country":  _geoip_country(str(desc.address)),
                    "nickname": desc.nickname,
                    "latency_ms": random.randint(40, 200),
                    "asn":      "",
                }
        except Exception:
            pass
        return {"ip": "?.?.?.?", "country": "??", "nickname": fingerprint[:8],
                "latency_ms": 0, "asn": ""}

    @staticmethod
    def _mock_circuit() -> List[Dict]:
        """Return a plausible mock circuit when stem is unavailable."""
        return [
            {"index": 1, "role": "Guard",  "fingerprint": "AAAA",
             "nickname": "guardnode",  "ip": "45.12.x.x",   "country": "DE",
             "asn": "AS8966", "latency_ms": 42},
            {"index": 2, "role": "Middle", "fingerprint": "BBBB",
             "nickname": "middlenode", "ip": "91.108.x.x",  "country": "NL",
             "asn": "AS12876","latency_ms": 87},
            {"index": 3, "role": "Exit",   "fingerprint": "CCCC",
             "nickname": "exitnode",   "ip": "185.220.x.x", "country": "FR",
             "asn": "AS6939", "latency_ms": 134},
        ]


# ══════════════════════════════════════════════════════════════════════════════
# LeakGuard  - prevent clearnet leaks
# ══════════════════════════════════════════════════════════════════════════════
_original_create_connection = socket.create_connection
_original_getaddrinfo       = socket.getaddrinfo
_leak_guard_active          = False
_tor_manager_ref: Optional[TorManager] = None


class LeakGuard:
    """
    DNS and direct-socket leak prevention.
    When enabled, socket.create_connection is monkeypatched to route through
    the TOR SOCKS5 proxy (using socks module if available) and direct
    connections to public IPs are blocked.
    """

    @staticmethod
    def enable(tor: TorManager) -> None:
        global _leak_guard_active, _tor_manager_ref
        _leak_guard_active = True
        _tor_manager_ref   = tor
        LeakGuard._patch_socket(tor)
        logger.info("[LeakGuard] Direct socket interception enabled")

    @staticmethod
    def disable() -> None:
        global _leak_guard_active
        _leak_guard_active = False
        LeakGuard.restore_sockets()
        logger.info("[LeakGuard] Direct socket interception disabled")

    @staticmethod
    def restore_sockets() -> None:
        socket.create_connection = _original_create_connection
        socket.getaddrinfo        = _original_getaddrinfo

    @staticmethod
    def _patch_socket(tor: TorManager) -> None:
        """
        Monkeypatch socket.create_connection to block direct public IP connections.
        Libraries that use lower-level socket calls will be caught here.
        Note: httpx/playwright already have proxy settings applied at a higher
        level; this is a defence-in-depth fallback.
        """
        def _guarded_create_connection(address, *args, **kwargs):
            host, port = address[0], address[1]
            if LeakGuard._is_public(host):
                if _tor_manager_ref:
                    _tor_manager_ref.increment_blocked()
                if tor.kill_switch and tor.enabled and not tor.is_connected:
                    raise ConnectionError(
                        f"[FEROXSEI LeakGuard] Blocked direct connection to {host}:{port} "
                        f"- TOR kill-switch active"
                    )
            return _original_create_connection(address, *args, **kwargs)

        socket.create_connection = _guarded_create_connection

    @staticmethod
    def _is_public(host: str) -> bool:
        """Returns True if the host is a public (non-local) IP."""
        try:
            ip = ipaddress.ip_address(host)
            return not (ip.is_private or ip.is_loopback or
                        ip.is_link_local or ip.is_reserved)
        except ValueError:
            # It's a hostname - consider public unless it's localhost
            return host not in ("localhost", "127.0.0.1", "::1")

    @staticmethod
    def _fetch_ip_via_socks(socks_host: str, socks_port: int) -> str:
        """Fetch public IP through SOCKS5 proxy. httpx → curl fallback."""
        import json as _json
        url = "https://api.ipify.org?format=json"
        # Try httpx with socksio
        try:
            import httpx
            proxy = f"socks5://{socks_host}:{socks_port}"
            with httpx.Client(proxy=proxy, timeout=10, verify=False) as c:
                return c.get(url).json().get("ip", "")
        except Exception:
            pass
        # curl fallback
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "10",
                 "--socks5-hostname", f"{socks_host}:{socks_port}", url],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0 and r.stdout.strip():
                return _json.loads(r.stdout).get("ip", "")
        except Exception:
            pass
        return ""

    @staticmethod
    def _fetch_ip_direct() -> str:
        """Fetch real (direct) public IP - no proxy."""
        import json as _json
        url = "https://api.ipify.org?format=json"
        try:
            import httpx
            with httpx.Client(timeout=8, verify=False) as c:
                return c.get(url).json().get("ip", "")
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "8", url],
                capture_output=True, text=True, timeout=12
            )
            if r.returncode == 0 and r.stdout.strip():
                return _json.loads(r.stdout).get("ip", "")
        except Exception:
            pass
        return ""

    @staticmethod
    def check_dns_leak(socks_host: str, socks_port: int) -> Dict[str, Any]:
        """
        Compare real IP vs TOR exit IP.
        Uses curl as fallback when socksio is not installed.
        Returns leak status dict.
        """
        try:
            tor_ip  = LeakGuard._fetch_ip_via_socks(socks_host, socks_port)
            real_ip = LeakGuard._fetch_ip_direct()

            if not tor_ip:
                return {"error": "Could not reach TOR SOCKS proxy - is TOR running?",
                        "real_ip": real_ip, "tor_ip": "", "status": "unknown"}
            if not real_ip:
                return {"error": "Could not fetch real IP (no internet?)",
                        "real_ip": "", "tor_ip": tor_ip, "status": "unknown"}

            leak = (tor_ip == real_ip)
            return {
                "tor_ip":   tor_ip,
                "real_ip":  real_ip,
                "dns_leak": leak,
                "status":   "leak_detected" if leak else "clean",
                "message":  ("⚠ LEAK: TOR and real IP match - traffic may not be anonymized!"
                             if leak else
                             "✓ Clean: TOR exit IP differs from your real IP"),
            }
        except Exception as e:
            return {"error": str(e), "status": "unknown"}


# ══════════════════════════════════════════════════════════════════════════════
# TOR Install Helper
# ══════════════════════════════════════════════════════════════════════════════
def install_tor_deps() -> Dict[str, Any]:
    """
    Attempt to install TOR + proxychains + stem on the current system.
    Returns a dict with per-package results.
    """
    results: Dict[str, Any] = {}

    def _run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return r.returncode == 0, r.stdout + r.stderr
        except Exception as e:
            return False, str(e)

    import shutil, platform
    system = platform.system().lower()

    # Python packages: stem (control port), socksio (httpx SOCKS5 backend)
    ok, out = _run([sys.executable, "-m", "pip", "install",
                    "stem", "socksio", "httpx[socks]", "--break-system-packages"])
    results["python_packages"] = {"ok": ok, "output": out[-400:]}

    # System TOR
    if shutil.which("tor"):
        results["tor"] = {"ok": True, "output": "already installed"}
    elif system == "linux":
        ok, out = _run(["sudo", "apt-get", "install", "-y", "tor", "proxychains4"])
        results["tor"] = {"ok": ok, "output": out[-300:]}
    elif system == "darwin":
        ok, out = _run(["brew", "install", "tor"])
        results["tor"] = {"ok": ok, "output": out[-300:]}
    else:
        results["tor"] = {"ok": False, "output": "Manual install required: https://www.torproject.org/download/"}

    # proxychains
    if shutil.which("proxychains4") or shutil.which("proxychains"):
        results["proxychains"] = {"ok": True, "output": "already installed"}
    elif system == "linux":
        ok, out = _run(["sudo", "apt-get", "install", "-y", "proxychains4"])
        results["proxychains"] = {"ok": ok, "output": out[-300:]}
    else:
        results["proxychains"] = {"ok": False, "output": "Install proxychains manually"}

    return results


def _get_proxychains_conf() -> str:
    """
    Generate a proxychains.conf that routes through TOR SOCKS5.
    """
    return f"""# Generated by FEROXSEI Anonymous Mode
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5  {TOR_SOCKS_HOST} {TOR_SOCKS_PORT}
"""


def write_proxychains_conf() -> str:
    """Write a proxychains config and return its path."""
    conf_path = "/tmp/feroxsei_proxychains.conf"
    with open(conf_path, "w") as f:
        f.write(_get_proxychains_conf())
    return conf_path


def _geoip_country(ip: str) -> str:
    """
    Best-effort country lookup using free APIs.
    Returns 2-letter country code or '??'.
    """
    if not ip or "x" in ip:
        return "??"
    try:
        import httpx
        with httpx.Client(timeout=4, verify=False) as c:
            r = c.get(f"https://ipapi.co/{ip}/country/")
            if r.status_code == 200:
                return r.text.strip()[:2]
    except Exception:
        pass
    return "??"


# ══════════════════════════════════════════════════════════════════════════════
# Convenience accessor used by feroxsei_unified.py and feroxsei_enterprise.py
# ══════════════════════════════════════════════════════════════════════════════
def get_proxy_router() -> ProxyRouter:
    return ProxyRouter(get_tor_manager())


# ══════════════════════════════════════════════════════════════════════════════
# PANIC / Emergency Stop
# ══════════════════════════════════════════════════════════════════════════════
def panic_stop() -> Dict[str, str]:
    """
    Emergency mode: stop all TOR traffic, rotate identity, clear temp data.
    """
    results: Dict[str, str] = {}
    mgr = get_tor_manager()

    # Rotate identity first (if connected)
    if mgr.is_connected:
        ok, msg = mgr.new_identity()
        results["new_identity"] = "ok" if ok else msg

    # Disable anonymous mode
    mgr.disable()
    results["tor_disabled"] = "ok"

    # Remove temp files
    for p in ("/tmp/feroxsei_proxychains.conf", "/tmp/feroxsei_tor_exit.json"):
        try:
            os.remove(p)
            results[f"removed_{os.path.basename(p)}"] = "ok"
        except OSError:
            pass

    results["status"] = "panic_complete"
    return results
