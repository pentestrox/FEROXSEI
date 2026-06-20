"""FEROXSEI OSINT - Web Crawler module (Playwright-based, deep recursive)."""
from __future__ import annotations
import hashlib
import random
import re
import time
import uuid
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

from .base import BaseOSINTModule, _log, _now, _is_keyword_target

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

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

# Extensions to skip - static assets with no interesting content
_SKIP_EXTS = {
    ".png",".jpg",".jpeg",".gif",".svg",".ico",".webp",".bmp",".tiff",
    ".woff",".woff2",".ttf",".eot",".otf",
    ".mp4",".mp3",".webm",".ogg",".wav",".avi",".mov",
    ".zip",".tar",".gz",".rar",".7z",
    ".css",          # CSS files rarely contain secrets worth crawling
}

# Max URLs to enqueue to prevent infinite crawls
_MAX_QUEUE   = 2000
# Max pages actually visited per run
_MAX_VISITED = 500


def _normalize_url(url: str, base_host: str) -> str | None:
    """
    Normalize a URL for deduplication and same-host check.
    Returns None if the URL should be skipped.
    """
    try:
        p = urlparse(url)
        # Must be http/https
        if p.scheme not in ("http", "https"):
            return None
        # Must be same host (or www. variant)
        host = (p.hostname or "").lstrip("www.")
        bhost = base_host.lstrip("www.")
        if host != bhost:
            return None
        # Skip static asset extensions
        path = p.path.rstrip("/") or "/"
        ext  = "." + path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
        if ext in _SKIP_EXTS:
            return None
        # Normalize: scheme + netloc + path (keep query for unique pages, drop fragment)
        # Sort query params for stable dedup
        qs = p.query
        if qs:
            params = parse_qs(qs, keep_blank_values=True)
            qs = urlencode(sorted(params.items()))
        normalized = urlunparse((p.scheme, p.netloc, path, "", qs, ""))
        return normalized
    except Exception:
        return None


def _extract_links_from_html(html: str, page_url: str) -> list[str]:
    """Extract all href/src links from raw HTML using regex (fast fallback)."""
    import html as _html_mod
    links = []
    for m in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.I):
        raw = _html_mod.unescape(m.group(1).strip())
        if raw and not raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            links.append(urljoin(page_url, raw))
    return links


class WebCrawlerModule(BaseOSINTModule):
    """Playwright-based deep recursive web crawler with pattern matching + screenshots."""
    NAME  = "webCrawl"
    LABEL = "Web Crawler"
    ICON  = "🕷️"
    ORDER = 25
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id, target, config):
        if _is_keyword_target(target):
            self.db.save_finding(scan_id, self.NAME, "info",
                f"Web Crawler: Skipped - keyword target '{target}'",
                "Web Crawler requires a URL or domain to crawl. "
                "For keyword/phrase targets, use Dark Web Monitor or Google Dork.",
                tags=["crawler","skip","keyword"])
            return
        if not HAS_PLAYWRIGHT:
            self.db.save_finding(scan_id, self.NAME, "info",
                "Web Crawler: Playwright not installed",
                "Install: pip install playwright --break-system-packages && playwright install chromium",
                tags=["setup"])
            return

        depth      = int(config.get("crawl_depth", 2))
        max_depth  = min(depth, 5)   # safety cap
        use_tor    = self.use_tor or bool(config.get("use_tor", False))
        if target.startswith("http"):
            target_url = target
        else:
            _probe = self.http.get(f"https://{target}", scan_id, self.NAME, add_delay=False)
            target_url = f"https://{target}" if (_probe and _probe.status_code in (200,301,302,403)) else f"http://{target}"
        parsed     = urlparse(target_url)
        base_host  = parsed.hostname or target
        base_origin= f"{parsed.scheme}://{parsed.netloc}"

        _log(f"[{self.LABEL}] Crawling {target_url} depth={max_depth} tor={use_tor}")
        self.emit_task(scan_id, f"Initialising crawler for {base_host}",
                       detail=f"depth={max_depth}, tor={use_tor}")

        visited: set[str] = set()
        # BFS queue: (normalized_url, original_url, depth)
        queue: deque = deque()

        # ── Seed from robots.txt and sitemap.xml ──────────────────────────────
        self._seed_from_robots(scan_id, base_origin, base_host, queue, visited)
        self._seed_from_sitemap(scan_id, base_origin, base_host, queue, visited)

        # Always start from the root
        root_norm = _normalize_url(target_url, base_host)
        if root_norm and root_norm not in visited:
            queue.appendleft((root_norm, target_url, 0))

        scr_dir = Path(__file__).parent.parent / "screenshots" / scan_id
        scr_dir.mkdir(parents=True, exist_ok=True)

        socks_host = getattr(self.http, "_socks_host", "127.0.0.1")
        socks_port = getattr(self.http, "_socks_port", 9050)
        proxy_settings = {"server": f"socks5://{socks_host}:{socks_port}"} if use_tor else None
        all_paths: list[str] = []
        form_count = 0
        seen_forms: set[str] = set()
        pattern_hits = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                proxy=proxy_settings,
                args=["--no-sandbox","--disable-setuid-sandbox",
                      "--disable-dev-shm-usage","--disable-gpu"]
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080},  # HD baseline
                device_scale_factor=2,                      # 2× → 3840×2160 effective
                user_agent=random.choice(_USER_AGENTS),
                java_script_enabled=True,
                color_scheme="light",
            )

            # Log outgoing requests
            def on_request(req):
                try:
                    rp = urlparse(req.url)
                    if (rp.hostname or "").lstrip("www.") == base_host.lstrip("www."):
                        _exit = self.http._tor_exit_ip if use_tor else ""
                        if use_tor:
                            _src = _exit if _exit and _exit not in ("", "?", "rotating…") else "🧅 TOR"
                        else:
                            _src = self.http._local_ip
                        self.db.log_traffic(
                            scan_id=scan_id, module=self.NAME,
                            method=req.method, url=req.url[:2000],
                            status_code=0, source_ip=_src,
                            dest_host=rp.hostname, dest_port=rp.port or (443 if rp.scheme=="https" else 80),
                            duration_ms=0, via_tor=use_tor,
                            tor_exit_ip=_exit
                        )
                except Exception:
                    pass

            ctx.on("request", on_request)
            page = ctx.new_page()

            while queue and len(visited) < _MAX_VISITED:
                if self.should_skip(scan_id):
                    break

                norm_url, orig_url, cur_depth = queue.popleft()

                if norm_url in visited:
                    continue
                visited.add(norm_url)
                all_paths.append(urlparse(norm_url).path)

                self.emit_task(scan_id,
                               f"Crawling [{cur_depth}/{max_depth}] {norm_url[:80]}",
                               detail=f"{len(visited)} visited · {len(queue)} queued")

                try:
                    t0   = time.time()
                    resp = page.goto(orig_url, timeout=20000, wait_until="domcontentloaded")
                    # Wait a bit for JS-rendered content to appear
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                    dur_ms = int((time.time() - t0) * 1000)

                    status = resp.status if resp else 0
                    final_url = page.url  # handle redirects

                    content = page.content()
                    title   = page.title() or norm_url

                    _log(f"[{self.LABEL}] {status} {norm_url[:60]} ({dur_ms}ms, {len(content)}b)")

                    # ── Pattern scan ──────────────────────────────────────────
                    hits = self.patterns.scan_text(content, norm_url)
                    for hit in hits:
                        pattern_hits += 1
                        self.db.save_finding(
                            scan_id, self.NAME, hit["severity"],
                            f"Crawler: {hit['pattern_name']}",
                            f"Found on {norm_url}: {hit['context'][:200]}",
                            url=norm_url, evidence=hit["evidence"],
                            pattern_id=hit["pattern_id"],
                            tags=["crawler","pattern",hit["category"]]
                        )

                    # ── Interesting page detection ────────────────────────────
                    self._check_interesting(scan_id, norm_url, title, content, status)

                    # ── Screenshot (depth 0 and 1 only) ──────────────────────
                    if cur_depth <= 1:
                        try:
                            # Let JS-rendered content and web fonts fully settle
                            try:
                                page.wait_for_load_state("networkidle", timeout=5000)
                            except Exception:
                                pass
                            page.wait_for_timeout(800)
                            # Scroll to top so full-page capture starts cleanly
                            try:
                                page.evaluate("window.scrollTo(0, 0)")
                            except Exception:
                                pass
                            scr_path = scr_dir / f"{hashlib.md5(norm_url.encode()).hexdigest()}.png"
                            raw_bytes = page.screenshot(
                                full_page=True,
                                type="png",
                                animations="disabled",  # freeze CSS animations → sharp text
                            )
                            # Lossless PNG optimisation via Pillow (if available)
                            try:
                                import io as _io
                                from PIL import Image as _Img
                                _buf = _io.BytesIO()
                                _Img.open(_io.BytesIO(raw_bytes)).save(
                                    _buf, format="PNG", optimize=True, compress_level=6
                                )
                                raw_bytes = _buf.getvalue() or raw_bytes
                            except Exception:
                                pass
                            scr_path.write_bytes(raw_bytes)
                            self.db.ins("osint_screenshots", {
                                "id": str(uuid.uuid4()), "scan_id": scan_id,
                                "url": norm_url, "file_path": str(scr_path),
                                "module": self.NAME, "created_at": _now()
                            })
                        except Exception:
                            pass

                    # ── Form detection ────────────────────────────────────────
                    form_count += self._scan_forms(scan_id, page, norm_url, seen_forms)

                    # ── Link discovery (enqueue next level) ───────────────────
                    if cur_depth < max_depth and len(queue) < _MAX_QUEUE:
                        new_links = self._extract_links(page, content, norm_url, base_host)
                        enqueued = 0
                        for lnorm, lorig in new_links:
                            if lnorm not in visited and len(queue) < _MAX_QUEUE:
                                queue.append((lnorm, lorig, cur_depth + 1))
                                enqueued += 1
                        if enqueued:
                            _log(f"[{self.LABEL}] Enqueued {enqueued} links from {norm_url[:50]}")

                except Exception as ex:
                    _log(f"[{self.LABEL}] Error on {norm_url[:60]}: {ex}")

            browser.close()

        # ── Summary finding ───────────────────────────────────────────────────
        self.emit_task(scan_id, "Crawl complete - saving summary", detail=f"{len(visited)} pages")
        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"🕷️ Web Crawl Complete: {len(visited)} pages found",
            f"Crawled {len(visited)} unique pages at depth {max_depth}\n"
            f"Pattern hits: {pattern_hits} · Forms found: {form_count}",
            url=target_url,
            evidence="\n".join(sorted(set(all_paths))[:200]),
            tags=["crawler","summary"],
            raw_data={"visited": len(visited), "depth": max_depth,
                      "pattern_hits": pattern_hits, "forms": form_count,
                      "paths": sorted(set(all_paths))[:300]}
        )
        _log(f"[{self.LABEL}] Done - {len(visited)} pages, {pattern_hits} hits, {form_count} forms")

    # ─────────────────────────────────────────────────────────────────────────

    def _extract_links(self, page, html: str, page_url: str, base_host: str) -> list[tuple[str,str]]:
        """Return list of (normalized_url, original_url) for same-host links."""
        raw_links: list[str] = []

        # Playwright: get all anchor hrefs (includes JS-rendered links)
        try:
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            raw_links.extend(hrefs)
        except Exception:
            pass

        # Also extract from <form action="...">, <script src="...">, data-href etc.
        try:
            extras = page.eval_on_selector_all(
                "[data-href],[data-url],[data-src]",
                "els => els.flatMap(e => [e.dataset.href,e.dataset.url,e.dataset.src].filter(Boolean))"
            )
            raw_links.extend(extras)
        except Exception:
            pass

        # Regex fallback on raw HTML (catches links in JS strings, JSON, etc.)
        raw_links.extend(_extract_links_from_html(html, page_url))

        seen_norm: set[str] = set()
        result: list[tuple[str,str]] = []
        for raw in raw_links:
            try:
                abs_url  = urljoin(page_url, raw) if raw else None
                if not abs_url:
                    continue
                norm = _normalize_url(abs_url, base_host)
                if norm and norm not in seen_norm:
                    seen_norm.add(norm)
                    result.append((norm, abs_url))
            except Exception:
                pass
        return result

    def _scan_forms(self, scan_id: str, page, url: str, seen_forms: set | None = None) -> int:
        """Detect forms and save findings. Returns count of forms found."""
        if seen_forms is None:
            seen_forms = set()
        count = 0
        try:
            forms = page.query_selector_all("form")
            for form in forms:
                try:
                    action  = form.get_attribute("action") or url
                    method  = (form.get_attribute("method") or "GET").upper()
                    inputs  = form.query_selector_all("input,textarea,select")
                    fields  = []
                    for inp in inputs:
                        itype = inp.get_attribute("type") or "text"
                        iname = inp.get_attribute("name") or inp.get_attribute("id") or ""
                        fields.append(f"{itype}:{iname}")
                    fields_str = ", ".join(fields) if fields else "no fields"

                    action_full = urljoin(url, action) if action and not action.startswith("http") else action
                    # Dedup key: action path (strip query) + sorted field names
                    from urllib.parse import urlparse as _up
                    _ap = _up(action_full)
                    dedup_key = f"{_ap.scheme}://{_ap.netloc}{_ap.path}|{','.join(sorted(fields))}"
                    if dedup_key in seen_forms:
                        continue
                    seen_forms.add(dedup_key)

                    # Classify by content
                    fl = fields_str.lower()
                    if any(k in fl for k in ["password","pass","pwd"]):
                        sev, tag, label = "medium", "login", "Login Form"
                    elif any(k in fl for k in ["search","q","query","keyword"]):
                        sev, tag, label = "info", "search", "Search Form"
                    elif any(k in fl for k in ["email","user","username","login"]):
                        sev, tag, label = "low", "auth", "Auth/Register Form"
                    elif any(k in fl for k in ["file","upload"]):
                        sev, tag, label = "medium", "upload", "File Upload Form"
                    else:
                        sev, tag, label = "info", "form", "Form"

                    self.db.save_finding(
                        scan_id, self.NAME, sev,
                        f"{label} Detected: {method} {action_full[:80]}",
                        f"{method} form on {url}",
                        url=url, evidence=f"Action: {action_full}\nFields: {fields_str}",
                        tags=["crawler","form",tag]
                    )
                    count += 1
                except Exception:
                    pass
        except Exception:
            pass
        return count

    def _check_interesting(self, scan_id: str, url: str, title: str, content: str, status: int):
        """Detect admin panels, login pages, error pages, exposed config etc."""
        path  = urlparse(url).path.lower()
        cl    = content.lower()

        checks = [
            # (condition, severity, title, description, tags)
            (any(p in path for p in ["/admin","/administrator","/wp-admin","/dashboard",
                                      "/manage","/management","/panel","/control"]),
             "high", "Admin Panel Detected", f"Admin panel at {url}", ["admin","panel"]),

            (status in (401, 403),
             "medium", f"Access Restricted ({status})", f"Protected path: {url}", ["auth","restricted"]),

            (status == 500 or "internal server error" in cl or "stack trace" in cl or "exception" in cl,
             "medium", "Server Error / Stack Trace Exposed", f"Error response at {url}", ["error","exposure"]),

            (any(p in path for p in ["/backup","/bak","/old","/temp","/tmp",".bak",".old",".backup"]),
             "high", "Backup File / Directory Found", f"Potential backup at {url}", ["backup","exposure"]),

            (any(p in path for p in ["/api/","/v1/","/v2/","/v3/","/rest/","/graphql","/swagger","/openapi"]),
             "info", "API Endpoint Discovered", f"API path: {url}", ["api","endpoint"]),

            (any(p in path for p in ["/config","/configuration","/settings","/env",".env","/setup"]),
             "high", "Configuration Page Found", f"Config exposure risk at {url}", ["config","exposure"]),

            ("/login" in path or "/signin" in path or "/auth" in path or
             ('type="password"' in content and "login" in cl),
             "info", "Login Page Detected", f"Authentication page: {url}", ["auth","login"]),

            (any(c in cl for c in ["phpinfo(", "php version", "php information"]),
             "critical", "phpinfo() Page Exposed", f"PHP info disclosure at {url}", ["phpinfo","critical"]),

            ("/phpmyadmin" in path or "/pma" in path or "/mysqladmin" in path,
             "critical", "phpMyAdmin Detected", f"Database admin at {url}", ["phpmyadmin","db","critical"]),

            (any(k in cl for k in ['"AccessKeyId"','"aws_access_key"',"aws_secret","s3.amazonaws.com"]),
             "critical", "AWS Credentials / S3 Reference", f"AWS data in page: {url}", ["aws","credential","critical"]),

            ("/.git/" in url or "/.svn/" in url or "/.env" in url,
             "critical", "Version Control / .env Exposure", f"Sensitive path accessible: {url}", ["git","env","critical"]),
        ]

        for condition, sev, ttl, desc, tags in checks:
            if condition:
                self.db.save_finding(
                    scan_id, self.NAME, sev, ttl, desc,
                    url=url, evidence=f"Title: {title}\nStatus: {status}",
                    tags=["crawler"] + tags
                )

    def _seed_from_robots(self, scan_id, base_origin, base_host, queue, visited):
        """Parse robots.txt for Disallow/Allow paths to seed the crawl."""
        robots_url = f"{base_origin}/robots.txt"
        try:
            r = self.http.get(robots_url, scan_id, self.NAME, timeout=8)
            if r and r.status_code == 200 and "text" in r.headers.get("content-type",""):
                paths_found = []
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:","allow:","sitemap:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            val = parts[1].strip()
                            if parts[0].lower() == "sitemap":
                                # Sitemap URL in robots.txt
                                norm = _normalize_url(val, base_host)
                                if norm and norm not in visited:
                                    queue.append((norm, val, 0))
                            elif val and val != "/":
                                path_url = urljoin(base_origin, val)
                                norm = _normalize_url(path_url, base_host)
                                if norm and norm not in visited:
                                    queue.append((norm, path_url, 0))
                                    paths_found.append(val)
                if paths_found:
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        "robots.txt: Paths Discovered",
                        f"{len(paths_found)} paths found in robots.txt",
                        url=robots_url, evidence="\n".join(paths_found[:100]),
                        tags=["crawler","robots","recon"]
                    )
        except Exception:
            pass

    def _seed_from_sitemap(self, scan_id, base_origin, base_host, queue, visited):
        """Parse sitemap.xml (and sitemap index) for URLs to seed the crawl."""
        for sitemap_url in [f"{base_origin}/sitemap.xml", f"{base_origin}/sitemap_index.xml"]:
            try:
                r = self.http.get(sitemap_url, scan_id, self.NAME, timeout=8)
                if not r or r.status_code != 200:
                    continue
                if "xml" not in r.headers.get("content-type","") and "<url" not in r.text:
                    continue
                # Find all <loc> tags
                locs = re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", r.text)
                added = 0
                for loc in locs[:500]:
                    norm = _normalize_url(loc.strip(), base_host)
                    if norm and norm not in visited and len(queue) < _MAX_QUEUE:
                        queue.append((norm, loc.strip(), 1))  # treat as depth 1
                        added += 1
                # Also look for nested sitemaps
                nested = re.findall(r"<sitemap>\s*<loc>\s*(https?://[^<]+)\s*</loc>", r.text)
                for ns_url in nested[:10]:
                    try:
                        nr = self.http.get(ns_url.strip(), scan_id, self.NAME, timeout=8)
                        if nr and nr.status_code == 200:
                            sub_locs = re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", nr.text)
                            for loc in sub_locs[:200]:
                                norm = _normalize_url(loc.strip(), base_host)
                                if norm and norm not in visited and len(queue) < _MAX_QUEUE:
                                    queue.append((norm, loc.strip(), 1))
                                    added += 1
                    except Exception:
                        pass
                if added:
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"sitemap.xml: {added} URLs Discovered",
                        f"Seeded {added} URLs from {sitemap_url}",
                        url=sitemap_url, evidence="\n".join([l.strip() for l in locs[:50]]),
                        tags=["crawler","sitemap","recon"]
                    )
                    break  # one sitemap is enough
            except Exception:
                pass
