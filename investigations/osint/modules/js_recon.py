"""
FEROXSEI OSINT - JavaScript File Intelligence
Crawls the target website, discovers all .js files, downloads and
deeply analyses them for:

  • Hardcoded secrets / API keys / tokens
  • Hidden API endpoints (REST paths, GraphQL, WebSocket, gRPC)
  • Internal hostnames and IP addresses
  • S3 / GCP / Azure storage references
  • AWS credentials and region references
  • JWT secret patterns
  • Debug flags, feature flags, staging/dev endpoints
  • Dependency fingerprinting (library versions for CVE lookup)
  • Source map URLs (reveal original TypeScript/JSX source paths)
  • Comments with TODO / FIXME / HACK / BUG / TEMP / password

Needs beautifulsoup4 for HTML link extraction; falls back to regex.
No API keys required.

Config keys:
  js_max_files     int   Max .js files to analyse (default 40)
  js_max_size_kb   int   Max individual file size in KB (default 500)
"""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse, quote

from .base import BaseOSINTModule, _log, _extract_domain

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ── Secret / credential patterns ──────────────────────────────────────────────
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (name, regex, severity)
    ("AWS Access Key",          r'(?i)AKIA[0-9A-Z]{16}',                              "critical"),
    ("AWS Secret Key",          r'(?i)(aws_secret|aws_key|secretaccesskey)\s*[:=]\s*["\']?[A-Za-z0-9/+]{40}', "critical"),
    ("GCP API Key",             r'AIza[0-9A-Za-z\-_]{35}',                            "critical"),
    ("GitHub Token",            r'gh[pousr]_[A-Za-z0-9]{36,}',                        "critical"),
    ("Slack Token",             r'xox[baprs]-[A-Za-z0-9\-]+',                         "critical"),
    ("Stripe Secret Key",       r'sk_live_[0-9a-zA-Z]{24,}',                          "critical"),
    ("Stripe Publishable Key",  r'pk_live_[0-9a-zA-Z]{24,}',                          "medium"),
    ("Stripe Test Key",         r'sk_test_[0-9a-zA-Z]{24,}',                          "low"),
    ("SendGrid API Key",        r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',        "critical"),
    ("Twilio Account SID",      r'AC[a-f0-9]{32}',                                    "high"),
    ("Twilio Auth Token",       r'(?i)twilio.*auth.*token.*[0-9a-f]{32}',              "critical"),
    ("JWT Token",               r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "high"),
    ("Private Key Header",      r'-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY',        "critical"),
    ("Google OAuth Token",      r'ya29\.[0-9A-Za-z\-_]+',                             "critical"),
    ("Firebase URL",            r'https://[a-z0-9-]+\.firebaseio\.com',               "high"),
    ("Mailgun API Key",         r'key-[0-9a-zA-Z]{32}',                               "critical"),
    ("Password in code",        r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "high"),
    ("Generic Secret",          r'(?i)(api_key|api_secret|client_secret|auth_token|access_token)\s*[:=]\s*["\'][^"\']{8,}["\']', "high"),
    ("Bearer Token hardcoded",  r'(?i)(Authorization|Bearer)\s*[:=]\s*["\']Bearer\s+[A-Za-z0-9\-_\.]{20,}', "high"),
    ("Basic Auth hardcoded",    r'(?i)Authorization\s*[:=]\s*["\']Basic\s+[A-Za-z0-9+/=]{10,}', "high"),
    ("Internal IP",             r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "medium"),
    ("Localhost reference",     r'(?i)(https?://)?(localhost|127\.0\.0\.1)(:\d+)?(/[^\s"\']{0,80})?', "medium"),
    ("S3 bucket URL",           r'https?://[a-z0-9\-]+\.s3[.\-][a-z0-9\-]*amazonaws\.com', "high"),
    ("Source Map",              r'//# sourceMappingURL=(.+\.map)',                     "medium"),
    ("Debug mode on",           r'(?i)(debug|verbose|devMode|isDev)\s*[:=]\s*(true|1|"true")', "medium"),
    ("Staging endpoint",        r'(?i)https?://[a-z0-9\-]*\.(staging|stage|dev|test|uat|qa)\.[a-z.]{3,}', "medium"),
    ("TODO/FIXME password",     r'(?i)(TODO|FIXME|HACK|BUG|XXX|TEMP)[^\n]{0,80}(password|secret|token|key|auth)', "low"),
    ("GraphQL endpoint",        r'(?i)(endpoint|url|apiUrl|graphqlUrl)\s*[:=]\s*["\'][^"\']*graphql[^"\']*["\']', "info"),
    ("WebSocket URL",           r'(?i)wss?://[a-z0-9.\-]+(:\d+)?(/[^\s"\']{0,80})?', "info"),
]

# ── API endpoint extraction patterns ─────────────────────────────────────────
_ENDPOINT_RE = re.compile(
    r'''(?x)
    (?:
      ["'`]                          # opening quote
      (/(?:api|v\d+|rest|graphql|   # path starts with /api or /v1 etc.
           ws|socket|webhook|admin|
           auth|oauth|login|user|
           upload|download|stream|
           internal|private|rpc)[^\s"'`<>]{0,120})
      ["'`]                          # closing quote
    )
    ''',
    re.IGNORECASE
)

# ── Library version fingerprinting ────────────────────────────────────────────
_LIB_RE = re.compile(
    r'(?i)(?:jquery|react|angular|vue|lodash|moment|axios|bootstrap)[^\w]'
    r'v?(\d+\.\d+(?:\.\d+)?)',
    re.IGNORECASE
)


class JsReconModule(BaseOSINTModule):
    """JavaScript file intelligence - secrets, hidden endpoints, library versions."""
    NAME  = "jsRecon"
    LABEL = "JS Intelligence"
    ICON  = "🔬"
    ORDER = 30
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain       = _extract_domain(target)
        max_files    = int(config.get("js_max_files",   40))
        max_size_kb  = int(config.get("js_max_size_kb", 500))

        _log(f"[{self.LABEL}] Starting JS recon for {domain}")

        base_url = target if target.startswith("http") else f"https://{domain}"

        # ── Discover JS files ─────────────────────────────────────────────────
        js_urls = self._discover_js(scan_id, base_url, domain, max_files)
        _log(f"[{self.LABEL}] Found {len(js_urls)} JS files to analyse")

        if not js_urls:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"JS Intelligence: No JS Files Discovered",
                "No .js files found on the target. The site may use server-side rendering "
                "or block automated crawling.",
                tags=["js", "recon", "clean"]
            )
            return

        # ── Analyse each file ─────────────────────────────────────────────────
        all_secrets:   list[dict] = []
        all_endpoints: set[str]   = set()
        all_libs:      dict[str, str] = {}
        source_maps:   list[str]  = []

        for js_url in js_urls[:max_files]:
            _log(f"[{self.LABEL}] Analysing: {js_url[-80:]}")
            r = self.http.get(js_url, scan_id, self.NAME, add_delay=False)
            if not r or r.status_code != 200:
                continue
            content_kb = len(r.content) / 1024
            if content_kb > max_size_kb:
                _log(f"[{self.LABEL}] Skipping {js_url[-50:]} ({content_kb:.0f}KB > {max_size_kb}KB)")
                continue

            text = r.text

            # Run DB patterns against JS content
            self._pattern_scan(scan_id, text, js_url)

            # Secrets
            for name, pattern, sev in _SECRET_PATTERNS:
                for m in re.finditer(pattern, text):
                    matched = m.group(0)[:200]
                    start   = max(0, m.start() - 80)
                    context = text[start:m.start() + 200].strip()[:300]
                    all_secrets.append({
                        "name": name, "severity": sev,
                        "match": matched, "context": context,
                        "url": js_url
                    })

            # Endpoints
            for m in _ENDPOINT_RE.finditer(text):
                ep = m.group(1)
                if len(ep) > 2 and not any(c in ep for c in ['\n', '\t']):
                    all_endpoints.add(ep)

            # Library versions
            for m in _LIB_RE.finditer(text[:5000]):
                lib = m.group(0).split(m.group(1))[0].rstrip().lower()
                ver = m.group(1)
                lib_key = lib[:20].strip()
                if lib_key:
                    all_libs[lib_key] = ver

            # Source maps
            sm_match = re.search(r'//# sourceMappingURL=(.+\.map)', text)
            if sm_match:
                sm_path = sm_match.group(1).strip()
                sm_url  = sm_path if sm_path.startswith("http") else urljoin(js_url, sm_path)
                source_maps.append(sm_url)

        # ── Save findings ─────────────────────────────────────────────────────

        # Secrets - group by severity, deduplicate
        seen_matches: set[str] = set()
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped = []
        for s in sorted(all_secrets, key=lambda x: sev_order.get(x["severity"], 5)):
            key = s["name"] + s["match"][:30]
            if key not in seen_matches:
                seen_matches.add(key)
                deduped.append(s)

        for s in deduped[:30]:
            self.db.save_finding(
                scan_id, self.NAME, s["severity"],
                f"🔬 JS Secret: {s['name']}",
                f"Hardcoded secret found in JavaScript file:\n{s['url']}",
                url=s["url"], evidence=s["context"],
                tags=["js", "secret", "hardcoded", s["severity"]]
            )

        # Endpoints
        if all_endpoints:
            sorted_eps = sorted(all_endpoints)
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"🔬 JS Hidden Endpoints: {len(all_endpoints)} API Path(s) Discovered",
                f"JavaScript analysis revealed {len(all_endpoints)} API/route paths "
                "not visible in standard crawling.",
                evidence="\n".join(sorted_eps[:80]),
                tags=["js", "endpoints", "discovery"],
                raw_data={"endpoints": sorted_eps}
            )

        # Libraries
        if all_libs:
            lib_evidence = "\n".join(f"  {lib}: v{ver}" for lib, ver in sorted(all_libs.items()))
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"JS Libraries: {len(all_libs)} Detected (version fingerprinting)",
                "Client-side library versions detected. Compare against CVE databases "
                "for known vulnerabilities in these versions.",
                evidence=lib_evidence,
                tags=["js", "libraries", "fingerprint"],
                raw_data={"libraries": all_libs}
            )

        # Source maps
        if source_maps:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"🗺 Source Maps Exposed: {len(source_maps)} .map File(s)",
                "JavaScript source maps are publicly accessible. These reveal original "
                "TypeScript/JSX source code, internal file paths, and unminified logic "
                "that may expose business logic and vulnerabilities.",
                evidence="\n".join(source_maps[:20]),
                tags=["js", "sourcemap", "source-exposure"]
            )
            # Try to fetch a source map to confirm it's accessible
            sm_r = self.http.get(source_maps[0], scan_id, self.NAME, add_delay=False)
            if sm_r and sm_r.status_code == 200 and len(sm_r.content) > 100:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"🚨 Source Map CONFIRMED Accessible: {source_maps[0][-80:]}",
                    "A JavaScript .map file is publicly downloadable, exposing original "
                    "source code. Attackers can reconstruct the full application source.",
                    url=source_maps[0],
                    evidence=sm_r.text[:500],
                    tags=["js", "sourcemap", "confirmed", "critical"]
                )

        # Summary
        if not deduped and not all_endpoints and not source_maps:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"JS Intelligence: {len(js_urls)} Files Analysed - No Critical Findings",
                f"Analysed {len(js_urls)} JavaScript files. No hardcoded secrets, "
                "hidden endpoints, or source maps found.",
                tags=["js", "recon", "clean"]
            )

        _log(f"[{self.LABEL}] ✅ {len(deduped)} secrets, {len(all_endpoints)} endpoints, "
             f"{len(source_maps)} source maps")

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_js(self, scan_id: str, base_url: str,
                     domain: str, max_files: int) -> list[str]:
        """Crawl base URL for <script src=...> tags and webpack chunk manifests."""
        found: set[str] = set()

        def _add(url: str) -> None:
            if url and url.endswith(".js") and domain in urlparse(url).netloc:
                found.add(url.split("?")[0])

        r = self.http.get(base_url, scan_id, self.NAME, add_delay=False)
        if not r or r.status_code != 200:
            return []

        if HAS_BS4:
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all("script", src=True):
                _add(urljoin(base_url, tag["src"]))
        else:
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I):
                _add(urljoin(base_url, m.group(1)))

        # Probe common webpack/vite chunk manifests
        manifest_paths = [
            "/asset-manifest.json", "/static/js/main.chunk.js",
            "/_next/static/chunks/main.js", "/js/app.js", "/js/main.js",
            "/js/bundle.js", "/dist/main.js", "/build/static/js/main.js",
            "/static/js/bundle.js", "/app.js", "/main.js",
        ]
        for path in manifest_paths:
            url = urljoin(base_url, path)
            if url not in found:
                r2 = self.http.get(url, scan_id, self.NAME, add_delay=False)
                if r2 and r2.status_code == 200 and len(r2.content) > 500:
                    if url.endswith(".js"):
                        found.add(url)
                    elif url.endswith(".json"):
                        # Parse manifest for JS paths
                        try:
                            import json
                            mfst = r2.json()
                            for v in _flatten_values(mfst):
                                if isinstance(v, str) and v.endswith(".js"):
                                    _add(urljoin(base_url, v))
                        except Exception:
                            pass

        return list(found)[:max_files]


def _flatten_values(obj, depth=0):
    """Yield all string leaf values from a nested dict/list."""
    if depth > 5:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten_values(v, depth+1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten_values(v, depth+1)
    else:
        yield obj
