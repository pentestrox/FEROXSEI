"""
FEROXSEI OSINT - Google Dorking module
Type-aware dork templates + per-result confidence scoring.

Confidence scoring (0–100):
  +55  target string found anywhere in the result URL
  +15  bonus - target is an exact path segment in the URL
       (e.g. /john_smith_smith/ is stronger than ?q=john_smith_smith)
  +30  target found in the page title
  +25  target found in the search snippet

Only results ≥ threshold% (default 60) are saved as findings.
"""
from __future__ import annotations
import random
import re
import time
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain

try:
    from ddgs import DDGS
    HAS_DDGS = True
except ImportError:
    try:
        from duckduckgo_search import DDGS
        HAS_DDGS = True
    except ImportError:
        HAS_DDGS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

# Default confidence threshold - results below this are discarded
_DEFAULT_THRESHOLD = 60

# ── Dork templates per target type ────────────────────────────────────────────
# {t}  → primary target value
# All templates must work with DuckDuckGo HTML search
_DORKS: dict[str, list[str]] = {
    "domain": [
        'site:{t} filetype:pdf',
        'site:{t} filetype:xls OR filetype:xlsx',
        'site:{t} filetype:doc OR filetype:docx',
        'site:{t} ext:sql OR ext:db OR ext:backup',
        'site:{t} intitle:"index of"',
        'site:{t} inurl:admin OR inurl:login OR inurl:dashboard',
        'site:{t} "not for public" OR "internal only" OR "confidential"',
        'site:{t} inurl:api OR inurl:v1 OR inurl:v2',
        'site:{t} filetype:env OR filetype:config',
        '"@{t}" email',
        '"{t}" password OR passwd OR pwd site:pastebin.com',
        '"{t}" "api_key" OR "access_token" site:github.com',
        'site:{t} inurl:wp-admin OR inurl:phpmyadmin',
        '"{t}" site:linkedin.com/in',
        'site:{t} -www',
    ],
    "username": [
        '"{t}"',
        '"@{t}"',
        '"{t}" site:github.com',
        '"{t}" site:reddit.com',
        '"{t}" site:linkedin.com',
        '"{t}" site:twitter.com OR site:x.com',
        '"{t}" site:instagram.com',
        '"{t}" site:facebook.com',
        '"{t}" profile OR account',
        '"{t}" site:keybase.io OR site:keybase.pub',
        '"{t}" password OR email site:pastebin.com',
        '"{t}" email',
    ],
    "email": [
        '"{t}"',
        '"{t}" password OR passwd',
        '"{t}" site:pastebin.com',
        '"{t}" site:github.com',
        '"{t}" site:linkedin.com',
        '"{t}" credentials OR breach OR leak',
        '"{t}" site:haveibeenpwned.com',
    ],
    "string": [
        '"{t}"',
        '"{t}" site:pastebin.com',
        '"{t}" credentials OR password OR breach',
        '"{t}" site:github.com',
        '"{t}" filetype:pdf',
        '"{t}" site:reddit.com',
    ],
}


def _match_confidence(target: str, result: dict) -> int:
    """
    Return 0–100 confidence that this search result is actually about the target.

    Scoring breakdown:
      URL path contains target            → +55
      Target is an exact URL path segment → +15 bonus  (e.g. /username/ vs ?q=username)
      Title contains target               → +30
      Snippet contains target             → +25
    """
    t     = target.lower().strip()
    url   = result.get("url",     "").lower()
    title = result.get("title",   "").lower()
    snip  = result.get("snippet", "").lower()

    score = 0
    if t in url:
        score += 55
        # Split URL on common delimiters to check for exact segment match
        parts = re.split(r'[/.\-?&=#@+]', url)
        if t in parts:
            score += 15           # e.g. instagram.com/john_smith/ path segment
    if t in title:
        score += 30
    if t in snip:
        score += 25

    return min(100, score)


class GoogleDorkModule(BaseOSINTModule):
    """Multi-engine Google Dorking - type-aware, confidence-filtered."""
    NAME  = "googleDork"
    LABEL = "Google Dorking"
    ICON  = "🔍"
    ORDER = 35
    TARGET_TYPES: list = ['domain', 'username', 'email', 'string']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        target_type = self._target_type or config.get("target_type", "domain")
        threshold   = int(config.get("dork_confidence_threshold", _DEFAULT_THRESHOLD))
        if target_type == "string":
            threshold = 0

        # Resolve primary search term and dork list
        if target_type == "domain":
            primary   = _extract_domain(target)
            dork_list = _DORKS["domain"]
        elif target_type == "email":
            primary   = target.strip()
            dork_list = _DORKS["email"]
        elif target_type == "username":
            primary   = target.strip().lstrip("@")
            dork_list = _DORKS["username"]
        else:  # string / keyword
            primary   = target.strip()
            dork_list = _DORKS["string"]

        _log(f"[{self.LABEL}] type={target_type} | '{primary}' | "
             f"{len(dork_list)} dorks | threshold={threshold}%")

        total_hits  = 0
        total_tried = 0

        for dork_tmpl in dork_list:
            if self.should_skip(scan_id):
                break

            dork          = dork_tmpl.replace("{t}", primary)
            total_tried  += 1

            self.emit_task(scan_id, f"Dork: {dork[:60]}", detail=f"engine=DuckDuckGo")
            raw_results = self._ddg_search(scan_id, dork)

            if not raw_results:
                time.sleep(random.uniform(1.5, 2.5))
                continue

            # Score every result against the target
            scored:   list[dict] = []
            rejected: int        = 0
            for r in raw_results:
                conf = _match_confidence(primary, r)
                if conf >= threshold:
                    r["confidence"] = conf
                    scored.append(r)
                else:
                    rejected += 1

            _log(f"[{self.LABEL}] '{dork[:50]}': "
                 f"{len(scored)}/{len(raw_results)} results ≥{threshold}%")

            if not scored:
                time.sleep(random.uniform(2, 4))
                continue

            total_hits += len(scored)

            # Severity: upgrade to medium when very high-confidence hits
            sev = "medium" if any(r["confidence"] >= 85 for r in scored) else "info"

            # Build evidence lines with confidence bar
            evidence_lines: list[str] = []
            for r in scored[:10]:
                conf = r["confidence"]
                bar  = "█" * (conf // 10) + "░" * (10 - conf // 10)
                evidence_lines.append(
                    f"[{conf:3d}%] {bar}\n"
                    f"  URL:     {r.get('url','')[:100]}\n"
                    f"  Title:   {r.get('title','')[:90]}\n"
                    f"  Snippet: {r.get('snippet','')[:120]}"
                )

            reject_note = f" ({rejected} low-confidence result(s) filtered)" if rejected else ""
            self.db.save_finding(
                scan_id, self.NAME, sev,
                f"🔍 Dork Hit ({len(scored)} result{'s' if len(scored)>1 else ''}): {dork[:65]}",
                f"{len(scored)} result(s) at ≥{threshold}% confidence for: {dork}{reject_note}",
                evidence="\n\n".join(evidence_lines),
                tags=["dork", "recon", target_type],
                raw_data={
                    "dork":      dork,
                    "threshold": threshold,
                    "results":   scored[:20],     # kept for UI card rendering
                    "rejected":  rejected,
                }
            )

            time.sleep(random.uniform(2, 4))

        _log(f"[{self.LABEL}] Done - {total_hits} hits from {total_tried} dorks")
        if total_hits == 0 and total_tried > 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"🔍 Google Dorking: No Results for '{primary[:60]}'",
                f"All {total_tried} dork queries returned no usable results. "
                "Possible causes: DuckDuckGo rate-limiting, SSL/TLS connectivity issue "
                "from this host, or no indexed content matching the dork templates.",
                tags=["dork", "recon", target_type],
            )

    # ── Search backend ────────────────────────────────────────────────────────

    def _ddg_search(self, scan_id: str, query: str) -> list[dict]:
        """Search DuckDuckGo for a dork query.
        Primary: ddgs library (API-based, no HTML scraping, no bot blocks).
        Fallback: html.duckduckgo.com HTML scraping.
        """
        if HAS_DDGS:
            try:
                ddg     = DDGS()
                hits    = ddg.text(query, max_results=12)
                results = []
                for h in (hits or []):
                    url = h.get("href", "") or h.get("url", "")
                    if not url:
                        continue
                    results.append({
                        "url":     url[:300],
                        "title":   h.get("title", "")[:200],
                        "snippet": h.get("body", "")[:300],
                    })
                _log(f"[{self.LABEL}] ddgs returned {len(results)} results for: {query[:50]}")
                return results
            except Exception as exc:
                _log(f"[{self.LABEL}] ddgs error: {exc} - falling back to HTML scrape")

        if not HAS_BS4:
            return []
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        r   = self.http.get(url, scan_id, self.NAME,
                            headers={"User-Agent": random.choice(_USER_AGENTS)},
                            add_delay=False, timeout=15)
        if not r or r.status_code != 200:
            return []

        results: list[dict] = []
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            for res in soup.select(".result__body")[:12]:
                title_el = res.select_one(".result__title")
                url_el   = res.select_one(".result__url")
                snip_el  = res.select_one(".result__snippet")
                url_text = url_el.get_text(strip=True) if url_el else ""
                url_text = re.sub(r'\s+', '', url_text)
                if not url_text:
                    continue
                if not url_text.startswith(("http://", "https://")):
                    url_text = "https://" + url_text
                results.append({
                    "title":   title_el.get_text(strip=True)[:200] if title_el else "",
                    "url":     url_text[:300],
                    "snippet": snip_el.get_text(strip=True)[:300]  if snip_el else "",
                })
        except Exception as exc:
            _log(f"[{self.LABEL}] DDG HTML parse error: {exc}")

        return results
