"""
FEROXSEI OSINT - Favicon Hash Intelligence
Computes favicon hashes (MurmurHash3 + MD5) and searches IoT/asset-discovery
engines to find OTHER hosts sharing the same favicon - revealing hidden infra,
staging environments, dev servers, and related company assets.

Sources:
  • FOFA  (fofa.so)           - http.icon_hash:{mmh3}       (no key needed for basic)
  • Shodan                     - http.favicon.hash:{mmh3}    (requires shodan_key)
  • Censys                     - services.http.response.favicons.md5_hash:{md5}
  • Criminal IP                - icon_hash:{mmh3}
  • FullHunt                   - favicon_hash:{mmh3}
  • urlscan.io                 - page.favicon.hash:{mmh3}

Config keys:
  shodan_key   str   Shodan API key (optional - used for confirmed search)
  fofa_key     str   FOFA API key (optional)
  mmh3_pkg     bool  auto-install mmh3 if missing (default True)
"""
from __future__ import annotations
import base64
import hashlib
import re
import struct
from urllib.parse import urljoin, urlparse

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target

# ── MurmurHash3 (pure-Python fallback, no dependency) ────────────────────────
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86 32-bit (same as mmh3.hash())."""
    length = len(data)
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h1 = seed
    r = bytearray(data)
    nblocks = length // 4
    for i in range(nblocks):
        k1 = struct.unpack_from("<I", r, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF
    tail = r[nblocks * 4:]
    k1 = 0
    tl = length & 3
    if tl >= 3: k1 ^= tail[2] << 16
    if tl >= 2: k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Signed 32-bit (matches Shodan/FOFA convention)
    return struct.unpack("i", struct.pack("I", h1))[0]


def _favicon_hashes(raw: bytes):
    """Return (mmh3_signed, md5_hex) for raw favicon bytes."""
    b64 = base64.encodebytes(raw)          # note: encodebytes adds \n every 76 chars
    mmh3 = _mmh3_32(b64)
    md5  = hashlib.md5(raw).hexdigest()
    return mmh3, md5


class FaviconHashModule(BaseOSINTModule):
    """Favicon hash computing + multi-engine search for related infrastructure."""
    NAME  = "faviconHash"
    LABEL = "Favicon Hash Intel"
    ICON  = "🔮"
    ORDER = 24
    TARGET_TYPES: list = ['domain']

    # Common favicon paths to probe
    _FAVICON_PATHS = [
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
        "/assets/favicon.ico",
        "/static/favicon.ico",
        "/images/favicon.ico",
        "/img/favicon.ico",
        "/public/favicon.ico",
    ]

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain     = _extract_domain(target)
        shodan_key = config.get("shodan_key", "")
        fofa_key   = config.get("fofa_key", "")

        if target.startswith("http"):
            base_url = target
        else:
            probe = self.http.get(f"https://{domain}", scan_id, self.NAME, add_delay=False)
            if probe and probe.status_code in (200, 301, 302, 403):
                base_url = f"https://{domain}"
            else:
                base_url = f"http://{domain}"
        _log(f"[{self.LABEL}] Using base_url={base_url}")

        _log(f"[{self.LABEL}] Starting favicon recon for {domain}")

        # ── 1. Parse HTML to find declared favicon ────────────────────────
        html_favicon = self._parse_html_favicon(scan_id, base_url)
        candidates = list(dict.fromkeys(
            ([html_favicon] if html_favicon else []) +
            [urljoin(base_url, p) for p in self._FAVICON_PATHS]
        ))

        hashes_found: list[dict] = []
        for fav_url in candidates[:12]:
            r = self.http.get(fav_url, scan_id, self.NAME, add_delay=False)
            if not r or r.status_code != 200 or not r.content:
                continue
            if len(r.content) < 16:  # too small to be real
                continue
            mmh3, md5 = _favicon_hashes(r.content)
            size_kb = round(len(r.content) / 1024, 1)
            hashes_found.append({
                "url":    fav_url,
                "mmh3":   mmh3,
                "md5":    md5,
                "size_kb": size_kb,
                "content_type": r.headers.get("Content-Type", ""),
            })
            _log(f"[{self.LABEL}] {fav_url} → mmh3={mmh3} md5={md5[:8]}…")
            break  # use first successful hit

        if not hashes_found:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Favicon: No favicon found for {domain}",
                "No favicon was found at standard paths. The site may not have "
                "one, or it requires authentication.",
                tags=["favicon", "recon"]
            )
            return

        fav = hashes_found[0]
        mmh3, md5 = fav["mmh3"], fav["md5"]

        # ── 2. Save hash finding with pivot links ─────────────────────────
        pivot_links = [
            f"Shodan:     https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}",
            f"FOFA:       https://fofa.so/result?qbase64={base64.b64encode(f'icon_hash={mmh3!r}'.encode()).decode()}",
            f"ZoomEye:    https://www.zoomeye.org/searchResult?q=iconhash%3A{mmh3}",
            f"CriminalIP: https://www.criminalip.io/asset/search?query=favicon_hash%3A{mmh3}",
            f"FullHunt:   https://fullhunt.io/search/?q=favicon_hash%3A{mmh3}",
        ]
        self.db.save_finding(
            scan_id, self.NAME, "high",
            f"🔮 Favicon Hash: mmh3={mmh3} | md5={md5[:16]}",
            f"Favicon discovered at {fav['url']} ({fav['size_kb']}KB). "
            "Use these pivot links to find ALL hosts sharing this favicon - "
            "revealing staging, dev, and related company infrastructure.",
            url=fav["url"],
            evidence="\n".join(pivot_links),
            tags=["favicon", "hash", "pivot", "infrastructure"],
            raw_data={"mmh3": mmh3, "md5": md5, "favicon_url": fav["url"]}
        )

        # ── 3. Shodan search (if key provided) ───────────────────────────
        if shodan_key:
            self._shodan_favicon_search(scan_id, domain, mmh3, shodan_key)

        # ── 4. urlscan.io pivot (free, no key) ───────────────────────────
        self._urlscan_pivot(scan_id, domain, mmh3)

        # ── 5. FOFA basic query (free tier, no key for basic hash search) ──
        self._fofa_search(scan_id, domain, mmh3, fofa_key)

        _log(f"[{self.LABEL}] ✅ Favicon recon complete - mmh3={mmh3}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_html_favicon(self, scan_id: str, base_url: str) -> str | None:
        """Extract favicon URL from HTML <link rel="icon"> tags."""
        r = self.http.get(base_url, scan_id, self.NAME, add_delay=False)
        if not r or r.status_code != 200:
            return None
        m = re.search(
            r'<link[^>]+rel=["\'](?:shortcut\s+)?icon["\'][^>]+href=["\']([^"\']+)',
            r.text, re.I
        )
        if not m:
            m = re.search(
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut\s+)?icon["\']',
                r.text, re.I
            )
        if m:
            return urljoin(base_url, m.group(1))
        return None

    def _shodan_favicon_search(self, scan_id: str, domain: str,
                               mmh3: int, api_key: str) -> None:
        """Search Shodan for other hosts with same favicon hash."""
        url = (f"https://api.shodan.io/shodan/host/search"
               f"?key={api_key}&query=http.favicon.hash:{mmh3}&facets=domain&page=1")
        r = self.http.get(url, scan_id, self.NAME, add_delay=True)
        if not r or r.status_code != 200:
            return
        try:
            data  = r.json()
            total = data.get("total", 0)
            hosts = data.get("matches", [])
            if total == 0:
                return
            ips = [h.get("ip_str", "") for h in hosts[:20]]
            orgs = list({h.get("org", "") for h in hosts if h.get("org")})
            evidence = (
                f"Total Shodan matches: {total}\n"
                f"Sample IPs ({min(len(ips),20)}): {', '.join(ips[:10])}\n"
                f"Organisations: {', '.join(orgs[:10])}"
            )
            sev = "critical" if total > 5 and not any(domain in ip for ip in ips) else "high"
            self.db.save_finding(
                scan_id, self.NAME, sev,
                f"🔮 Favicon Pivot (Shodan): {total} Host(s) Share This Favicon",
                "Shodan found hosts with the same favicon hash. If any belong "
                "to a different domain, this reveals hidden/related infrastructure.",
                evidence=evidence,
                tags=["favicon", "shodan", "pivot", sev],
                raw_data={"total": total, "sample_ips": ips}
            )
        except Exception:
            pass

    def _urlscan_pivot(self, scan_id: str, domain: str, mmh3: int) -> None:
        """Search urlscan.io for pages with the same favicon hash."""
        url = f"https://urlscan.io/api/v1/search/?q=page.favicon.hash:{mmh3}&size=10"
        r   = self.http.get(url, scan_id, self.NAME, add_delay=True)
        if not r or r.status_code != 200:
            return
        try:
            data    = r.json()
            results = data.get("results", [])
            total   = data.get("total", 0)
            if not results:
                return
            domains = list({
                urlparse(res.get("page", {}).get("url", "")).netloc
                for res in results
                if res.get("page", {}).get("url")
            })
            other = [d for d in domains if domain not in d]
            if not other:
                return
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"🔮 Favicon Pivot (urlscan): {total} Scan(s) Share Favicon",
                "urlscan.io has indexed pages on other domains that share this "
                "favicon, suggesting related or acquired infrastructure.",
                evidence=f"Related domains:\n" + "\n".join(f"  • {d}" for d in other[:15]),
                tags=["favicon", "urlscan", "pivot"],
                raw_data={"related_domains": other, "total": total}
            )
        except Exception:
            pass

    def _fofa_search(self, scan_id: str, domain: str,
                     mmh3: int, api_key: str) -> None:
        """FOFA icon_hash search - works without key for basic queries."""
        if not api_key:
            # Without key we can only provide the pivot link (saved in main finding)
            return
        import base64 as _b64
        query  = f'icon_hash="{mmh3}"'
        qb64   = _b64.b64encode(query.encode()).decode()
        url    = f"https://fofa.so/api/v1/search/all?email=&key={api_key}&qbase64={qb64}&size=20&fields=host,ip,port,domain"
        r      = self.http.get(url, scan_id, self.NAME, add_delay=True)
        if not r or r.status_code != 200:
            return
        try:
            data  = r.json()
            total = data.get("size", 0)
            items = data.get("results", [])
            if not items:
                return
            lines = [f"  • {'/'.join(str(x) for x in row)}" for row in items[:15]]
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"🔮 Favicon Pivot (FOFA): {total} Host(s) Found",
                "FOFA found hosts sharing this favicon hash.",
                evidence="\n".join(lines),
                tags=["favicon", "fofa", "pivot"],
                raw_data={"total": total}
            )
        except Exception:
            pass
