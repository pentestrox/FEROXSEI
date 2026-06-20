#!/usr/bin/env python3
"""FEROXSEI Manual Crawl Helper - Playwright-based traffic capture with DB persistence.

Launched as a subprocess by Flask when the user clicks "Manual Crawl" on the
scan view page.  Captures all HTTP traffic from the user's manual browsing,
filters to the target host, saves every request/response to the crawl_requests
DB table, detects login-page redirects, and notifies the user via the
notifications table.

Usage (called internally by feroxsei_enterprise.py):
    python feroxsei_crawl.py <scan_id> <target_url> [--headless] [--db-path PATH]

DB tables written:
    crawl_requests  - one row per captured HTTP exchange
    notifications   - one row if a login redirect is detected
"""
from __future__ import annotations
import sys, json, time, os, uuid, sqlite3, signal
from pathlib import Path
from urllib.parse import urlparse, parse_qs

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


# ── Login-page heuristics ──────────────────────────────────────────────────────
_LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "authenticate",
                   "session", "token", "oauth", "sso", "saml")

def _is_login_url(url: str) -> bool:
    """Return True if the URL looks like a login/auth page."""
    try:
        p = urlparse(url.lower())
        path_qs = p.path + "?" + p.query
        return any(kw in path_qs for kw in _LOGIN_KEYWORDS)
    except Exception:
        return False

def _is_login_redirect(resp_status: int, resp_headers: dict,
                        resp_url: str, req_url: str) -> bool:
    """Return True if this response is a redirect to a login page."""
    if resp_status in (301, 302, 303, 307, 308):
        location = resp_headers.get("location", "")
        if location and _is_login_url(location):
            return True
    # Also flag non-redirect responses whose URL itself is a login page
    # (e.g. the server rewrote the URL internally)
    if _is_login_url(resp_url) and resp_status < 400:
        return True
    return False


# ── Tiny sqlite3 helper ────────────────────────────────────────────────────────
class _DB:
    def __init__(self, path: str):
        self.path = path

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def exec(self, sql: str, params=()):
        with self._conn() as c:
            c.execute(sql, params)

    def one(self, sql: str, params=()):
        with self._conn() as c:
            row = c.execute(sql, params).fetchone()
            return dict(row) if row else None

    def ins(self, table: str, data: dict):
        cols  = ", ".join(data.keys())
        marks = ", ".join("?" for _ in data)
        with self._conn() as c:
            c.execute(f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({marks})",
                      list(data.values()))

    def has_crawl_request(self, scan_id: str, method: str, url: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM crawl_requests WHERE scan_id=? AND method=? AND url=? LIMIT 1",
                (scan_id, method, url)).fetchone()
            return row is not None


# ── Main crawl logic ───────────────────────────────────────────────────────────
def run_crawl(scan_id: str, target_url: str, headless: bool = False,
              timeout_seconds: int = 600, db_path: str = "feroxsei.db") -> dict:
    """
    Open a browser window, capture traffic scoped to target_url's host.
    Saves every request/response pair to the DB. Returns captured data dict.
    """
    if not HAS_PLAYWRIGHT:
        msg = "playwright not installed - run: pip install playwright --break-system-packages && playwright install chromium"
        print(f"[crawl] ERROR: {msg}")
        return {"error": msg}

    # Resolve DB path relative to this script's directory if not absolute
    if not os.path.isabs(db_path):
        db_path = str(Path(__file__).parent / db_path)

    db = _DB(db_path)

    # Load scan record for auth headers / cookies
    scan = db.one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if not scan:
        print(f"[crawl] WARNING: scan {scan_id} not found in DB - proceeding without auth")
        scan = {}

    scan_user_id = scan.get("user_id")

    # Parse auth info from scan record
    _extra_headers: dict = {}
    try:
        raw_hdrs = scan.get("headers") or ""
        if raw_hdrs.strip():
            for line in raw_hdrs.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    _extra_headers[k.strip()] = v.strip()
    except Exception as e:
        print(f"[crawl] Header parse warning: {e}")

    auth_token = (scan.get("auth_token") or "").strip()
    if auth_token and "Authorization" not in _extra_headers:
        _extra_headers["Authorization"] = f"Bearer {auth_token}"

    _extra_cookies: list = []
    try:
        raw_cookies = scan.get("cookies") or ""
        if raw_cookies.strip():
            for part in raw_cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    _extra_cookies.append({"name": name.strip(), "value": value.strip()})
    except Exception as e:
        print(f"[crawl] Cookie parse warning: {e}")

    parsed  = urlparse(target_url)
    t_host  = parsed.hostname or ""
    t_scheme = parsed.scheme or "https"

    # Track pairs: we capture request then match with response
    _pending: dict = {}   # request_id (playwright) -> request dict
    _login_notified = False

    def _safe_headers(hdrs) -> dict:
        try:
            return dict(hdrs)
        except Exception:
            return {}

    def _content_type(headers: dict) -> str:
        return headers.get("content-type", "").split(";")[0].strip()

    print(f"[crawl] ═══════════════════════════════════════════════════")
    print(f"[crawl]  FEROXSEI Manual Crawl  -  scan {scan_id[:8]}")
    print(f"[crawl]  Target : {target_url}")
    print(f"[crawl]  DB     : {db_path}")
    print(f"[crawl]  Auth   : {len(_extra_headers)} header(s), {len(_extra_cookies)} cookie(s)")
    print(f"[crawl]  Timeout: {timeout_seconds}s   headless={headless}")
    print(f"[crawl] ═══════════════════════════════════════════════════")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        ctx     = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=_extra_headers,
        )

        # Inject cookies into the browser context
        if _extra_cookies and t_host:
            try:
                ctx.add_cookies([
                    {**ck, "domain": t_host, "path": "/", "url": target_url}
                    for ck in _extra_cookies
                ])
            except Exception as e:
                print(f"[crawl] Cookie inject warning: {e}")

        # ── Request hook ──────────────────────────────────────────────────────
        def on_request(req):
            nonlocal _login_notified
            try:
                parsed_r = urlparse(req.url)
                if parsed_r.hostname != t_host:
                    return   # out-of-scope
                path  = parsed_r.path or "/"
                query = parsed_r.query or ""
                method = req.method.upper()

                # Store for later pairing with the response
                _pending[req] = {
                    "method":          method,
                    "url":             req.url,
                    "path":            path,
                    "query":           query,
                    "request_headers": _safe_headers(req.headers),
                    "request_body":    req.post_data or "",
                }
                print(f"[>>] {method:6s} {req.url[:110]}")

                # Flag login URL even on the request side
                if not _login_notified and _is_login_url(req.url):
                    _notify_login_redirect(db, scan_id, scan_user_id, req.url, False)
                    _login_notified = True

            except Exception as e:
                print(f"[crawl] req hook error: {e}")

        # ── Response hook ─────────────────────────────────────────────────────
        def on_response(resp):
            nonlocal _login_notified
            try:
                parsed_r = urlparse(resp.url)
                if parsed_r.hostname != t_host:
                    return

                req      = resp.request
                req_data = _pending.pop(req, None)
                if req_data is None:
                    # Synthesise minimal request data from the response
                    req_data = {
                        "method":          req.method.upper() if req else "GET",
                        "url":             resp.url,
                        "path":            parsed_r.path or "/",
                        "query":           parsed_r.query or "",
                        "request_headers": {},
                        "request_body":    "",
                    }

                resp_hdrs = _safe_headers(resp.headers)
                ct        = _content_type(resp_hdrs)

                login_redirect = _is_login_redirect(
                    resp.status, resp_hdrs, resp.url, req_data["url"])

                # Persist to DB (skip exact duplicates already stored)
                if not db.has_crawl_request(scan_id, req_data["method"], req_data["url"]):
                    db.ins("crawl_requests", {
                        "id":               str(uuid.uuid4()),
                        "scan_id":          scan_id,
                        "method":           req_data["method"],
                        "url":              req_data["url"],
                        "path":             req_data["path"],
                        "query":            req_data["query"],
                        "request_headers":  json.dumps(req_data["request_headers"]),
                        "request_body":     req_data["request_body"] or "",
                        "response_status":  resp.status,
                        "response_headers": json.dumps(resp_hdrs),
                        "content_type":     ct,
                        "is_login_redirect": 1 if login_redirect else 0,
                        "recorded_at":      _now_iso(),
                    })

                status_icon = "🔴" if login_redirect else ("🟡" if resp.status >= 400 else "🟢")
                print(f"[<<] {status_icon} {resp.status} {resp.url[:100]}")

                if login_redirect and not _login_notified:
                    _notify_login_redirect(db, scan_id, scan_user_id, resp.url, True)
                    _login_notified = True

            except Exception as e:
                print(f"[crawl] resp hook error: {e}")

        ctx.on("request",  on_request)
        ctx.on("response", on_response)

        page = ctx.new_page()
        try:
            page.goto(target_url, timeout=15_000)
        except Exception:
            pass

        print(f"\n[crawl] Browser open - browse the application manually.")
        print(f"[crawl] All traffic to {t_host} is being captured into the DB.")
        print(f"[crawl] Close the browser or wait {timeout_seconds}s to finish.\n")

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                if not browser.contexts:
                    break
                if not ctx.pages:
                    break
                time.sleep(2)
            except Exception:
                break

        try:
            page.wait_for_timeout(1000)
        except Exception:
            pass
        browser.close()

    # Final summary from DB
    try:
        with sqlite3.connect(db_path, timeout=10) as c:
            rows = c.execute(
                "SELECT method, path FROM crawl_requests WHERE scan_id=?", (scan_id,)
            ).fetchall()
        total_reqs  = len(rows)
        unique_paths = len(set(r[1] for r in rows))
        print(f"\n[crawl] ✓ Done - {total_reqs} requests saved, {unique_paths} unique paths")
    except Exception as e:
        print(f"[crawl] Summary query error: {e}")
        total_reqs = unique_paths = 0

    return {
        "scan_id":      scan_id,
        "target_host":  t_host,
        "total":        total_reqs,
        "unique_paths": unique_paths,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat()


def _notify_login_redirect(db: _DB, scan_id: str, user_id,
                            redirect_url: str, is_redirect: bool):
    """Write a notification to the DB so the UI can alert the user."""
    verb  = "Redirected to" if is_redirect else "Navigated to"
    title = "⚠️ Session Expired - Login Redirect Detected"
    body  = (
        f"Manual crawl for scan {scan_id[:8]} detected a login page redirect.\n"
        f"{verb}: {redirect_url[:120]}\n\n"
        "Your session may have expired. Please:\n"
        "1. Log in again inside the crawl browser window, or\n"
        "2. Update your auth token in Scan Settings and restart the crawl."
    )
    try:
        db.ins("notifications", {
            "id":           str(uuid.uuid4()),
            "user_id":      user_id,
            "from_user_id": None,
            "type":         "warning",
            "title":        title,
            "body":         body,
            "is_read":      0,
            "created_at":   _now_iso(),
        })
        print(f"[crawl] ⚠️  LOGIN REDIRECT detected → notification saved for user {user_id}")
    except Exception as e:
        print(f"[crawl] Could not save login-redirect notification: {e}")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: feroxsei_crawl.py <scan_id> <target_url> [--headless] [--db-path PATH]")
        sys.exit(1)

    _scan_id    = sys.argv[1]
    _target_url = sys.argv[2]
    _headless   = "--headless" in sys.argv

    _db_path = "feroxsei.db"
    if "--db-path" in sys.argv:
        idx = sys.argv.index("--db-path")
        if idx + 1 < len(sys.argv):
            _db_path = sys.argv[idx + 1]

    if not HAS_PLAYWRIGHT:
        print("ERROR: playwright not installed.")
        print("Install: pip install playwright --break-system-packages && playwright install chromium")
        sys.exit(1)

    run_crawl(_scan_id, _target_url, headless=_headless, db_path=_db_path)
