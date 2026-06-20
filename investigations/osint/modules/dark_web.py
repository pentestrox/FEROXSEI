"""
FEROXSEI OSINT - Dark Web Monitor (Advanced)
Inspired by: TorBot, OnionSearch, darkdump, onionscan, ahmia, SpiderFoot, LeakLooker

Architecture:
  ┌──────────────────────────────────────────────────────────────┐
  │  PHASE 1 - Multi-engine search (OnionSearch / darkdump)      │
  │    15+ clearnet dark web indexes + 8 .onion engines via TOR  │
  │    Parallel search, deduplicated .onion URL harvesting       │
  ├──────────────────────────────────────────────────────────────┤
  │  PHASE 2 - .onion crawl + analysis (TorBot + onionscan)      │
  │    Fetch each .onion page; extract title, links, emails      │
  │    Follow links 1 level deep (TorBot crawler style)          │
  │    Onionscan-style: check headers, open directories,         │
  │    OPSEC leaks (real IPs in headers, Apache status pages)    │
  │    Detect forum posts, marketplace listings, paste content   │
  ├──────────────────────────────────────────────────────────────┤
  │  PHASE 3 - Breach / credential intelligence (LeakLooker)     │
  │    psbdmp · Pastebin dork · GhostBin · Rentry               │
  │    RansomWatch · DDoSecrets · Distributed Denial of Secrets  │
  │    URLhaus · AbuseIPDB · IntelX.io (clearnet) · Cybergordon  │
  │    HIBP domain (key optional) · LeakCheck                    │
  ├──────────────────────────────────────────────────────────────┤
  │  PHASE 4 - Telegram & forum intelligence (SpiderFoot style)  │
  │    telegramchannels.me · tgstat.com · lolarchiver            │
  │    Bing / DDG dork for t.me links                            │
  │    Dark web forum keyword detection                          │
  ├──────────────────────────────────────────────────────────────┤
  │  PHASE 5 - Exposed database / service detection (LeakLooker) │
  │    Shodan dork via API: "X-Target" headers, open ES/Mongo    │
  │    GitHub code leak search: domain + credential keywords     │
  │    Public trello boards, Jira, Confluence mentions           │
  └──────────────────────────────────────────────────────────────┘

Config keys:
  hibp_api_key      HaveIBeenPwned API key (optional)
  github_token      GitHub PAT (optional, higher rate limits)
  shodan_key        Shodan API key (optional, for exposed DB search)
  darkweb_limit     Max .onion URLs to deeply fetch (default 20)
  crawl_depth       Follow links N levels deep on .onion pages (default 1)

Target:
  • domain/URL:  "example.com" → searches + checks domain mentions
  • keyword:     "Acme Corp leak" → uses full string as search term
"""
from __future__ import annotations
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin, urlparse

from .base import BaseOSINTModule, _log, _extract_domain, _thread_pool

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# ── Regex helpers ─────────────────────────────────────────────────────────────
_ONION_RE   = re.compile(r'https?://[a-z2-7]{10,56}\.onion(?:/[^\s"\'<>]*)?', re.I)
_EMAIL_RE   = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')
_IP_RE      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_TITLE_RE   = re.compile(r'<title[^>]*>([^<]{1,200})</title>', re.I | re.S)
_META_RE    = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,300})["\']', re.I)


def _extract_onion_urls(html: str) -> list[str]:
    seen: set[str] = set()
    out:  list[str] = []
    for m in _ONION_RE.finditer(html):
        url = m.group(0).rstrip(".,;)")
        if url not in seen:
            seen.add(url); out.append(url)
    return out


def _page_title(html: str) -> str:
    if HAS_BS4:
        try:
            t = BeautifulSoup(html, "html.parser").title
            return t.string.strip()[:200] if t and t.string else ""
        except Exception:
            pass
    m = _TITLE_RE.search(html)
    return m.group(1).strip() if m else ""


def _page_meta(html: str) -> str:
    if HAS_BS4:
        try:
            tag = BeautifulSoup(html, "html.parser").find(
                "meta", attrs={"name": re.compile("description", re.I)})
            if tag and tag.get("content"):
                return tag["content"][:300]
        except Exception:
            pass
    m = _META_RE.search(html)
    return m.group(1).strip() if m else ""


def _visible_text(html: str, max_chars: int = 1500) -> str:
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for t in soup(["script","style","nav","footer","head"]):
                t.decompose()
            return " ".join(soup.get_text(separator=" ").split())[:max_chars]
        except Exception:
            pass
    clean = re.sub(r'<[^>]+>', ' ', html)
    return " ".join(clean.split())[:max_chars]


def _context(text: str, term: str, window: int = 300) -> str:
    idx = text.lower().find(term.lower())
    if idx == -1:
        return text[:window]
    s = max(0, idx - 100); e = min(len(text), idx + 200)
    return ("…" if s > 0 else "") + text[s:e] + ("…" if e < len(text) else "")


# ── Search engine registry ────────────────────────────────────────────────────
# (name, url_template, needs_tor, parser_hint)
# parser_hint: "json" | "html" | "darksearch"
_ENGINES = [
    # Clearnet indexes
    ("Ahmia.fi",
     "https://ahmia.fi/search/?q={q}",                              False, "html"),
    ("OnionLand",
     "https://onionlandsearchengine.com/search?q={q}",              False, "html"),
    ("DarkSearch.io",
     "https://darksearch.io/api/search?query={q}&page=1",           False, "darksearch"),
    ("Haystak-Clearnet",
     "https://haystak.com/?q={q}",                                   False, "html"),
    ("Phobos-Clearnet",
     "https://phobos.to/search?query={q}",                           False, "html"),
    ("TorLinks",
     "https://www.torlinks.net/search.php?q={q}",                    False, "html"),
    ("Abused.to",
     "https://www.abused.to/search?q={q}",                           False, "html"),
    ("Kirstens.i2p (clearnet)",
     "https://www.kirstens.co/search/?q={q}",                        False, "html"),
    # .onion search engines (TOR required)
    ("Ahmia.onion",
     "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}",
     True, "html"),
    ("Haystack.onion",
     "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}",
     True, "html"),
    ("TorDex.onion",
     "http://tordex7iie7z2wcg.onion/search?query={q}&type=text",
     True, "html"),
    ("Excavator.onion",
     "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search/?q={q}",
     True, "html"),
    ("DeepSearch.onion",
     "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={q}",
     True, "html"),
    ("Phobos.onion",
     "http://phobosxilamwcg75xt22id7aywkzol6q6rfl2flipcqoc4e4ahima5id.onion/search?query={q}",
     True, "html"),
    ("Torch.onion",
     "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/?q={q}&action=search",
     True, "html"),
    ("NotEvil.onion",
     "http://hss3uro2hsxfogfq.onion/?q={q}&lang=en&host=&type=text",
     True, "html"),
    ("Kirstens.onion",
     "http://kirstenshhhhhhhhhhhhh.onion/search/?q={q}",
     True, "html"),
]

# Build a set of known search-engine .onion host names so we can exclude
# their own pages from the Phase-2 deep-fetch. When Excavator (or any other
# engine) returns its own navigation links (/add-url, /css/…) those match the
# search engine's hostname and would otherwise generate noise findings.
_ENGINE_ONION_HOSTS: set[str] = set()
for _eng_name, _eng_url, _eng_tor, _eng_hint in _ENGINES:
    try:
        from urllib.parse import urlparse as _up
        _h = _up(_eng_url).hostname or ""
        if _h.endswith(".onion"):
            _ENGINE_ONION_HOSTS.add(_h.lower())
    except Exception:
        pass

# ── Breach / threat intel sources ────────────────────────────────────────────
_RANSOMWATCH = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
_URLHAUS     = "https://urlhaus-api.abuse.ch/v1/host/"
_PSBDMP      = "https://psbdmp.ws/api/v3/search/{domain}"
_LEAKCHECK   = "https://leakcheck.io/api/public?check={domain}"
_HIBP_DOMAIN = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
_GH_CODE     = "https://api.github.com/search/code?q={q}+in:file&per_page=10"

# ── Onionscan-style security checks ──────────────────────────────────────────
_OPSEC_PATHS = [
    "/server-status", "/.git/", "/.env", "/phpinfo.php",
    "/wp-admin/", "/admin/", "/backup/", "/config/",
    "/.htaccess", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
]
_CRED_KW = [
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "credential", "private_key", "access_key", "database", "dump",
    "breach", "leak", "hacked", "ransom", "ssn", "social security",
    "credit card", "cvv", "dox", "doxx",
]
_FORUM_KW = [
    "forum", "thread", "post", "reply", "topic", "marketplace",
    "vendor", "escrow", "pgp", "tor market",
]
_PASTE_SITES = [
    ("Pastebin",     "https://www.google.com/search?q=site:pastebin.com+\"{term}\""),
    ("GhostBin",     "https://ghostbin.co/search?q={term_q}"),
    ("Rentry",       "https://rentry.co/search?q={term_q}"),
    ("Hastebin",     "https://hastebin.com/search?q={term_q}"),
    ("Paste.ee",     "https://paste.ee/list/tag/{term_q}"),
]

# Phrases that indicate a fetched .onion page is empty / a search box / an
# error page with no real content about the target. Used in Phase 2 to avoid
# saving findings for trivial pages.
_TRIVIAL_PAGE_PATTERNS: tuple[str, ...] = (
    "no results found",
    "no results for",
    "enter your search",
    "enter a search query",
    "search the dark web",
    "search query",
    "nothing was found",
    "no pages found",
    "403 forbidden",
    "access denied",
    "under construction",
    "coming soon",
    "we'll be back",
    "service unavailable",
    "this site can't be reached",
    "connection refused",
)


class DarkWebModule(BaseOSINTModule):
    """Dark web intelligence - OnionSearch + TorBot + onionscan + LeakLooker style."""
    NAME         = "darkWeb"
    LABEL        = "Dark Web Monitor"
    ICON         = "🕳️"
    ORDER        = 60
    TARGET_TYPES: list = ['domain', 'username', 'email', 'string', 'phone', 'ip']
    REQUIRES_TOR = False

    # ── Target-type context builder ───────────────────────────────────────────

    def _build_search_context(self, raw: str, target_type: str):
        """Return (primary, secondary, label, search_terms) tailored to target type.

        primary      - main value to search (domain, username, email, phone, ip, string)
        secondary    - fallback / org name / local-part (for display + paste site alt searches)
        label        - human-readable label used in finding titles
        search_terms - ordered list of query variations sent to each search engine
        """
        import re as _re

        if target_type == "domain":
            domain   = _extract_domain(raw)
            org_name = domain.split(".")[0]
            terms    = [domain, f'"{domain}"']
            if org_name != domain:
                terms += [org_name, f'"{domain}" credentials']
            return domain, org_name, domain, terms

        elif target_type == "username":
            uname = raw.lstrip("@")
            terms = [
                uname,
                f'"{uname}"',
                f'"{uname}" password',
                f'"{uname}" credentials',
                f'"{uname}" leaked',
                f'"{uname}" hacked',
            ]
            return uname, uname, f"@{uname}", terms

        elif target_type == "email":
            local_part = raw.split("@")[0]
            terms = [
                raw,
                f'"{raw}"',
                f'"{raw}" breach',
                f'"{raw}" password',
                local_part,
            ]
            return raw, local_part, raw, terms

        elif target_type == "phone":
            clean       = _re.sub(r'[\s\-\(\)]', '', raw)
            digits_only = _re.sub(r'\D', '', raw)
            terms = [raw, clean, f'"{raw}"', f'"{clean}" leaked', digits_only]
            return raw, clean, raw, terms

        elif target_type == "ip":
            terms = [raw, f'"{raw}"', f'"{raw}" attack', f'"{raw}" botnet', f'"{raw}" scan']
            return raw, raw, raw, terms

        else:  # string / keyword
            terms = [raw, f'"{raw}"', f'{raw} credentials', f'{raw} leaked', f'{raw} database']
            return raw, raw, raw, terms

    # ── Main run ─────────────────────────────────────────────────────────────

    def run(self, scan_id: str, target: str, config: dict) -> None:
        raw         = target.strip()
        target_type = self._target_type or config.get("target_type", "domain")
        tor_on      = self.http.use_tor

        limit       = int(config.get("darkweb_limit", 20))
        crawl_depth = int(config.get("crawl_depth", 1))
        hibp_key    = (config.get("hibp_api_key") or "").strip()
        gh_token    = (config.get("github_token") or "").strip()

        primary, secondary, label, search_terms = self._build_search_context(raw, target_type)
        _log(f"[{self.LABEL}] type={target_type} | '{label}' | TOR={'ON' if tor_on else 'OFF'}")
        total_hits = 0

        # ── PHASE 1: Multi-engine dark web search ─────────────────────────────
        # Clearnet indexes (ahmia.fi, darksearch.io, onionlandsearch, etc.) always run.
        # .onion search engines (Torch, TorDex, Haystack, NotEvil…) only when TOR is ON.
        self.emit_task(scan_id, "Phase 1: Multi-engine dark web search",
                       detail=f"type={target_type} · terms={search_terms[:2]}")
        discovered: dict[str, dict] = {}

        enabled_engines = [(n, u, t, p) for n, u, t, p in _ENGINES if not t or tor_on]

        with _thread_pool(max_workers=6) as pool:
            futs = {
                pool.submit(self._search_one, scan_id, name, url_tpl, hint, term): (name, term)
                for name, url_tpl, _, hint in enabled_engines
                for term in search_terms[:4]          # cap per-engine queries
            }
            for fut in as_completed(futs):
                eng_name, term = futs[fut]
                try:
                    results = fut.result(timeout=30)
                    for onion_url, meta in results.items():
                        if onion_url not in discovered:
                            discovered[onion_url] = {**meta, "engines": [eng_name], "term": term}
                        else:
                            discovered[onion_url]["engines"] = list(
                                set(discovered[onion_url].get("engines", []) + [eng_name])
                            )
                except Exception as ex:
                    _log(f"[{self.LABEL}] {eng_name} error: {ex}")

        _log(f"[{self.LABEL}] Phase 1: {len(discovered)} .onion URLs for '{label}'")

        # ── Phase 1 finding: only save URLs whose search snippet/title actually
        # mentions the target. Bare links harvested from engine pages (snippet=
        # "via Engine") without target confirmation are kept for Phase 2 deep-
        # fetch but not counted as findings - they could easily be false positives.
        _snip_confirmed: dict[str, dict] = {}
        _unverified:     dict[str, dict] = {}
        for _url, _meta in discovered.items():
            _combined = (_meta.get("title","") + " " + _meta.get("snippet","")).lower()
            if primary.lower() in _combined or secondary.lower() in _combined:
                _snip_confirmed[_url] = _meta
            else:
                _unverified[_url] = _meta

        if _snip_confirmed:
            _n = len(_snip_confirmed)
            _extra = (
                f"\n({len(_unverified)} additional unverified URL(s) will be checked in Phase 2)"
                if tor_on and _unverified else ""
            )
            self.db.save_finding(
                scan_id, self.NAME, "high" if _n > 5 else "medium",
                f"🕳️ Dark Web Discovery: {_n} .onion Page(s) Mention '{label}'",
                f"Multi-engine search across {len(enabled_engines)} dark web indexes "
                f"found {_n} .onion page(s) with snippets referencing '{label}'.{_extra}",
                evidence="\n".join(
                    f"  [{','.join(m.get('engines',['?'])[:2])}] "
                    f"{url[:80]} - {m.get('title','')[:60]}"
                    for url, m in list(_snip_confirmed.items())[:30]
                ),
                tags=["darkweb", "onion", "discovery", target_type],
                raw_data={"urls": list(_snip_confirmed.keys())[:50]}
            )
            total_hits += _n
        elif _unverified and not tor_on:
            # Search engines returned links but snippets don't confirm target,
            # and TOR is OFF so we can't verify. Save as unverified info only.
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"🕳️ Dark Web: {len(_unverified)} .onion URL(s) Found (Unverified - TOR OFF)",
                f"Search engines found {len(_unverified)} .onion URL(s) but snippets don't "
                f"confirm '{label}' is mentioned on those pages. Enable TOR to fetch and "
                f"verify these pages.",
                evidence="\n".join(
                    f"  [{','.join(m.get('engines',['?'])[:2])}] {url[:80]}"
                    for url, m in list(_unverified.items())[:20]
                ),
                tags=["darkweb", "onion", "unverified", "info"],
            )
            # Don't increment total_hits - unverified ≠ confirmed finding
        elif _unverified and tor_on:
            # TOR is on - Phase 2 will fetch and verify; individual findings added there
            _log(f"[{self.LABEL}] Phase 1: {len(_unverified)} unverified URL(s) queued for Phase 2 deep-fetch")

        if self.should_skip(scan_id): return

        # ── PHASE 2: .onion fetch + OPSEC analysis (TOR required) ─────────────
        if tor_on and discovered:
            self.emit_task(scan_id, "Phase 2: .onion fetch + OPSEC analysis",
                           detail=f"TorBot+onionscan · depth={crawl_depth}")
            for onion_url, meta in list(discovered.items())[:limit]:
                if self.should_skip(scan_id): break
                # Skip the search engines themselves - they're our tools, not targets
                link_host = (urlparse(onion_url).hostname or "").lower()
                if link_host in _ENGINE_ONION_HOSTS:
                    _log(f"[{self.LABEL}] Phase 2: skipping search-engine host {link_host}")
                    continue
                self._analyse_onion(scan_id, primary, secondary, onion_url, meta,
                                    tor_on, crawl_depth, target_type)
        elif discovered:
            self.emit_task(scan_id, "Phase 2: Skipped - enable TOR to read .onion pages",
                           detail=f"{len(discovered)} URLs found but TOR is OFF")

        if self.should_skip(scan_id): return

        # ── PHASE 3: Breach + paste + credential intelligence (type-specific) ──
        self.emit_task(scan_id, "Phase 3: Breach + paste + credential intel",
                       detail=f"Routing by target_type={target_type}")

        if target_type == "domain":
            self.emit_task(scan_id, "Paste monitoring, ransomware, HIBP domain")
            for name, url_tmpl in _PASTE_SITES:
                if self.should_skip(scan_id): break
                total_hits += self._check_paste_site(scan_id, primary, secondary, name, url_tmpl)
            total_hits += self._check_psbdmp(scan_id, primary)
            total_hits += self._ransomwatch(scan_id, primary, secondary)
            total_hits += self._ddosecrets(scan_id, primary, secondary)
            self._urlhaus(scan_id, primary)
            self._leakcheck(scan_id, primary)
            self._abuseipdb_check(scan_id, primary)
            if hibp_key:
                total_hits += int(bool(self._hibp_domain(scan_id, primary, hibp_key)))

        elif target_type == "email":
            # Email: paste sites + psbdmp + leakcheck + HIBP per-email account
            self.emit_task(scan_id, "Email breach check: paste sites + LeakCheck + HIBP")
            for name, url_tmpl in _PASTE_SITES:
                if self.should_skip(scan_id): break
                total_hits += self._check_paste_site(
                    scan_id, primary, secondary or primary.split("@")[0], name, url_tmpl)
            total_hits += self._check_psbdmp(scan_id, primary)
            self._leakcheck(scan_id, primary)
            total_hits += self._ddosecrets(scan_id, primary, "")
            if hibp_key:
                total_hits += int(bool(self._hibp_email(scan_id, primary, hibp_key)))
            else:
                self.db.save_finding(scan_id, self.NAME, "info",
                    f"💡 HIBP Email Check Skipped - API Key Not Set",
                    f"Add a HaveIBeenPwned API key in Settings to check whether "
                    f"'{primary}' appears in known data breaches.",
                    tags=["hibp","email","info"])

        elif target_type == "username":
            # Username: paste sites + psbdmp + leakcheck + GitHub code search
            self.emit_task(scan_id, "Username: paste sites + LeakCheck + GitHub search")
            for name, url_tmpl in _PASTE_SITES:
                if self.should_skip(scan_id): break
                total_hits += self._check_paste_site(scan_id, primary, primary, name, url_tmpl)
            total_hits += self._check_psbdmp(scan_id, primary)
            self._leakcheck(scan_id, primary)

        elif target_type == "ip":
            # IP: direct reputation + URLhaus + DDoSecrets
            self.emit_task(scan_id, "IP reputation: Cybergordon + URLhaus + DDoSecrets")
            self._abuseipdb_ip(scan_id, primary)
            self._urlhaus(scan_id, primary)
            total_hits += self._ddosecrets(scan_id, primary, "")

        elif target_type == "phone":
            # Phone: paste sites + leakcheck
            self.emit_task(scan_id, "Phone: paste sites + LeakCheck")
            for name, url_tmpl in _PASTE_SITES:
                if self.should_skip(scan_id): break
                total_hits += self._check_paste_site(
                    scan_id, primary, secondary or primary, name, url_tmpl)
            self._leakcheck(scan_id, primary)

        else:  # string / keyword
            self.emit_task(scan_id, "Keyword: paste sites + psbdmp + DDoSecrets")
            for name, url_tmpl in _PASTE_SITES:
                if self.should_skip(scan_id): break
                total_hits += self._check_paste_site(scan_id, primary, primary, name, url_tmpl)
            total_hits += self._check_psbdmp(scan_id, primary)
            total_hits += self._ddosecrets(scan_id, primary, "")
            self._leakcheck(scan_id, primary)

        if self.should_skip(scan_id): return

        # ── PHASE 4: Telegram intelligence (all target types) ─────────────────
        self.emit_task(scan_id, "Phase 4: Telegram intelligence")
        total_hits += self._telegram_intel(scan_id, primary, secondary or primary, label)

        if self.should_skip(scan_id): return

        # ── PHASE 5: Code leaks + public exposure (domain/email/username/string) ─
        if target_type in ("domain", "email", "username", "string"):
            self.emit_task(scan_id, "Phase 5: GitHub code leaks + public exposure")
            total_hits += self._github_search(scan_id, primary, gh_token)
            if target_type == "domain":
                self._public_exposure_check(scan_id, primary, secondary or primary)

        # ── TOR advisory ───────────────────────────────────────────────────────
        if not tor_on:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                "🧅 Enable TOR for Full Dark Web Coverage",
                f"TOR is OFF. Clearnet dark web indexes were searched for '{label}'.\n\n"
                "Enable TOR to also:\n"
                "• Search 8+ .onion engines (Torch, TorDex, Haystack, NotEvil, Phobos…)\n"
                "• Fetch and read discovered .onion page content\n"
                "• Run onionscan OPSEC analysis on hidden servers\n"
                "• Follow links 1 level deep (TorBot crawler)",
                tags=["darkweb", "tor", "info"]
            )

        if total_hits == 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Dark Web: No Confirmed Mentions of '{label}'",
                f"No references found for '{label}' across dark web indexes, "
                "paste sites, breach databases, or intelligence feeds.",
                tags=["darkweb", "clean"]
            )

        _log(f"[{self.LABEL}] Done - {total_hits} hits, {len(discovered)} .onions")

    # ── Phase 1: search one engine ────────────────────────────────────────────

    def _search_one(self, scan_id: str, engine: str, url_tpl: str,
                    hint: str, term: str) -> dict[str, dict]:
        url = url_tpl.format(q=quote(term))
        r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=25)
        if not r or r.status_code != 200:
            return {}
        html = r.text or ""

        if hint == "darksearch":
            return self._parse_darksearch(html)

        results: dict[str, dict] = {}
        if HAS_BS4:
            results = self._parse_html_results(html, url)

        # Also harvest bare .onion URLs from raw HTML, but exclude the search
        # engine's own pages (e.g. Excavator /add-url, /css/ links).
        engine_host = urlparse(url).hostname or ""
        for onion_url in _extract_onion_urls(html):
            link_host = (urlparse(onion_url).hostname or "").lower()
            if link_host in _ENGINE_ONION_HOSTS:
                continue           # skip search-engine self-links
            if onion_url not in results:
                results[onion_url] = {"title": "", "snippet": f"via {engine}"}

        _log(f"[{self.LABEL}] {engine}: {len(results)} URLs for '{term}'")
        return results

    def _parse_html_results(self, html: str, page_url: str) -> dict[str, dict]:
        soup = BeautifulSoup(html, "html.parser")
        results: dict[str, dict] = {}
        containers = (
            soup.select("li.result") or soup.select("div.result") or
            soup.select(".search-result") or soup.select(".result-item") or
            soup.select("article") or soup.select("li")
        )
        for c in containers:
            link = c.find("a", href=_ONION_RE)
            if not link:
                continue
            href = link.get("href", "")
            if not href.startswith("http"):
                href = urljoin(page_url, href)
            title   = ""
            snippet = ""
            for sel in ("h4","h3","h2","strong","b"):
                el = c.find(sel)
                if el and el.get_text(strip=True):
                    title = el.get_text(strip=True)[:200]; break
            if not title and link:
                title = link.get_text(strip=True)[:200]
            for sel in ("p","span.description","div.description",".snippet",".excerpt"):
                el = c.find(sel)
                if el and el.get_text(strip=True):
                    snippet = el.get_text(separator=" ", strip=True)[:300]; break
            if not snippet:
                snippet = c.get_text(separator=" ", strip=True)[:300]
            if href and ".onion" in href:
                results[href] = {"title": title, "snippet": snippet}
        return results

    def _parse_darksearch(self, raw: str) -> dict[str, dict]:
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        out: dict[str, dict] = {}
        for item in (data.get("data") or data.get("results") or []):
            url = item.get("link","")
            if url:
                out[url] = {"title": item.get("title","")[:200],
                            "snippet": item.get("description","")[:300]}
        return out

    # ── Phase 2: analyse one .onion (TorBot + onionscan) ─────────────────────

    def _analyse_onion(self, scan_id: str, domain: str, org_name: str,
                       onion_url: str, meta: dict, tor_on: bool,
                       crawl_depth: int, target_type: str = "domain") -> None:
        engines = ", ".join(meta.get("engines", ["?"]))
        title   = meta.get("title", "")
        snippet = meta.get("snippet", "")

        self.emit_task(scan_id, f"Fetching: {onion_url[:55]}…", detail=f"via {engines}")

        fetched_title = title
        fetched_desc  = ""
        body_text     = ""
        http_status   = None
        mentions      = False
        cred_hit      = False
        forum_hit     = False
        found_emails: set[str] = set()
        found_links:  list[str] = []
        opsec_issues: list[str] = []

        if tor_on:
            r = self.http.get(onion_url, scan_id, self.NAME,
                              add_delay=True, timeout=35)
            if r:
                http_status = r.status_code
                if r.status_code == 200 and r.text:
                    html      = r.text[:30000]
                    body_text = _visible_text(html, 3000)
                    t = _page_title(html)
                    if t: fetched_title = t
                    fetched_desc = _page_meta(html)

                    body_lower = body_text.lower()
                    mentions   = domain.lower() in body_lower or org_name.lower() in body_lower
                    cred_hit   = any(kw in body_lower for kw in _CRED_KW)
                    forum_hit  = any(kw in body_lower for kw in _FORUM_KW)

                    # ── Early exit for empty / trivial pages ──────────────────
                    # If the page has almost no text, or is clearly a search box /
                    # access-denied page, and the target isn't mentioned → skip.
                    # This eliminates "search engine result page" false positives
                    # and pages that just show a search form with no real content.
                    _is_trivial = (
                        len(body_text.strip()) < 150
                        or any(p in body_lower for p in _TRIVIAL_PAGE_PATTERNS)
                    )
                    if _is_trivial and not mentions and not cred_hit:
                        _log(f"[{self.LABEL}] Skipping trivial/empty page: {onion_url[:55]}")
                        return
                    # ─────────────────────────────────────────────────────────

                    found_emails = set(_EMAIL_RE.findall(html))
                    # Exclude links that point back to search engine hosts
                    found_links = [
                        u for u in _extract_onion_urls(html)[:20]
                        if (urlparse(u).hostname or "").lower() not in _ENGINE_ONION_HOSTS
                    ]

                    # Pattern scan only meaningful for web targets
                    self._pattern_scan(scan_id, body_text, onion_url)

                    # ── onionscan-style OPSEC checks (domain/IP only, target mentioned) ──
                    # Only meaningful when this .onion page actually mentions the
                    # target; OPSEC issues on unrelated .onion servers are noise.
                    if target_type in ("domain", "ip") and mentions:
                        resp_hdrs = dict(r.headers)
                        opsec_issues = self._opsec_check(
                            scan_id, onion_url, html, body_text, resp_hdrs, domain
                        )

                    # ── TorBot-style link follow (domain/IP only) ────────────
                    if target_type in ("domain", "ip") and crawl_depth >= 1 and found_links:
                        self._follow_links(scan_id, domain, org_name, found_links[:5],
                                           onion_url)
        else:
            body_lower = (title + " " + snippet).lower()
            mentions   = domain.lower() in body_lower or org_name.lower() in body_lower
            cred_hit   = any(kw in body_lower for kw in _CRED_KW)
            forum_hit  = any(kw in body_lower for kw in _FORUM_KW)

        # Severity
        if tor_on and http_status and mentions and cred_hit:
            sev = "critical"
            hl  = f"🚨 .onion Directly References {domain} with Credentials/Sensitive Data"
        elif mentions and cred_hit:
            sev = "critical"
            hl  = f"🚨 Dark Web Reference: {domain} + Credential Content"
        elif tor_on and http_status and mentions:
            sev = "high"
            hl  = f"⚠️ .onion Site References {domain}"
        elif mentions:
            sev = "high"
            hl  = f"⚠️ Dark Web Mention: {domain}"
        elif cred_hit and tor_on and http_status and mentions:
            sev = "medium"
            hl  = f"🔑 .onion Site Contains Credential/Sensitive Content for {domain}"
        elif forum_hit and tor_on and http_status and mentions:
            sev = "medium"
            hl  = f"💬 .onion Forum/Marketplace References {domain}"
        else:
            sev = "info"
            hl  = f"🧅 .onion Site Discovered"

        ev = [
            f"URL:     {onion_url}",
            f"Source:  {engines}",
        ]
        if http_status:        ev.append(f"HTTP:    {http_status}")
        if fetched_title:      ev.append(f"Title:   {fetched_title}")
        if fetched_desc:       ev.append(f"Desc:    {fetched_desc[:200]}")
        if mentions and body_text:
            ev.append(f"\nTarget mention context:\n{_context(body_text, domain)}")
        if cred_hit:           ev.append(f"\nCredential keywords detected in content")
        if forum_hit:          ev.append(f"\nForum/marketplace patterns detected")
        if found_emails:
            ev.append(f"\nEmails found on page:\n" + "\n".join(list(found_emails)[:5]))
        if found_links:
            ev.append(f"\nLinked .onion pages:\n" + "\n".join(found_links[:5]))
        if opsec_issues:
            ev.append(f"\nOPSEC issues detected:\n" + "\n".join(opsec_issues))
        if not tor_on:
            ev.append("\n(TOR OFF - content not fetched; based on search snippet only)")

        _fetch_status = (f"HTTP: {http_status}" if http_status
                        else ("TOR OFF - not fetched" if not tor_on else "Unreachable"))
        desc = (
            f"Dark web .onion discovered via {engines}.\n"
            + (f"Page title: {fetched_title}\n" if fetched_title else "")
            + f"{_fetch_status}\n"
            + f"Mentions {domain}: {'YES ⚠️' if mentions else 'No'}\n"
            + f"Credential content: {'YES 🔑' if cred_hit else 'No'}\n"
            + f"Forum/marketplace: {'YES' if forum_hit else 'No'}"
        )

        tags = ["darkweb", "onion", sev]
        if mentions:  tags.append("target-mention")
        if cred_hit:  tags.append("credentials")
        if forum_hit: tags.append("forum")
        if opsec_issues: tags.append("opsec-leak")

        # Skip pure-noise findings: .onion page does not mention the target,
        # has no credential keywords, and has no forum/marketplace content.
        # Such pages surfaced in search results but have nothing relevant - skip.
        if not mentions and not cred_hit and not forum_hit:
            return

        self.db.save_finding(
            scan_id, self.NAME, sev, hl, desc,
            url=onion_url, evidence="\n".join(ev), tags=tags
        )

        if found_emails and domain.lower() in str(found_emails).lower():
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                f"📧 Target Emails Exposed on Dark Web: {len(found_emails)} Address(es)",
                f"Email addresses matching {domain} found on .onion page {onion_url}",
                url=onion_url,
                evidence="\n".join(
                    e for e in found_emails if domain.lower() in e.lower()
                ),
                tags=["darkweb", "email", "exposure", "critical"]
            )

    def _opsec_check(self, scan_id: str, onion_url: str,
                     html: str, body_text: str,
                     headers: dict, domain: str) -> list[str]:
        """onionscan-style: detect operational security failures on the .onion server."""
        issues: list[str] = []
        base = onion_url.split("/")[0] + "//" + onion_url.split("/")[2]

        server_hdr = headers.get("Server", headers.get("server", ""))
        if server_hdr:
            issues.append(f"Server header leaks software: {server_hdr}")

        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered:
            issues.append(f"X-Powered-By leaks tech stack: {powered}")

        real_ips = [ip for ip in _IP_RE.findall(html)
                    if not ip.startswith(("127.", "10.", "192.168.", "172."))]
        if real_ips:
            issues.append(f"Possible real IPs in page source: {', '.join(set(real_ips)[:5])}")

        for path in _OPSEC_PATHS[:6]:
            url = base.rstrip("/") + path
            r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=8)
            if r and r.status_code == 200:
                issues.append(f"Accessible sensitive path: {path}")

        if issues:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"🔍 Onionscan: {len(issues)} OPSEC Issue(s) on {onion_url[:50]}",
                f"Operational security problems detected on .onion server.",
                url=onion_url,
                evidence="\n".join(f"  • {i}" for i in issues),
                tags=["darkweb", "onionscan", "opsec", "misconfiguration"]
            )
        return issues

    def _follow_links(self, scan_id: str, domain: str, org_name: str,
                      links: list[str], parent: str) -> None:
        """TorBot-style: follow discovered .onion links one level deep."""
        for link in links:
            if self.should_skip(scan_id):
                return
            if link == parent:
                continue
            r = self.http.get(link, scan_id, self.NAME,
                              add_delay=True, timeout=25)
            if not r or r.status_code != 200 or not r.text:
                continue
            body = _visible_text(r.text, 2000)
            if domain.lower() in body.lower() or org_name.lower() in body.lower():
                title = _page_title(r.text)
                ctx   = _context(body, domain)
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"🔗 Linked .onion Also References {domain}: {title[:60]}",
                    f"TorBot-style link follow from {parent[:50]} discovered another "
                    f".onion page referencing the target.",
                    url=link,
                    evidence=(f"Parent:  {parent}\n"
                              f"Child:   {link}\n"
                              f"Title:   {title}\n"
                              f"Context: {ctx}"),
                    tags=["darkweb", "onion", "linked", "torbot", "high"]
                )
            self._pattern_scan(scan_id, body, link)

    # ── Phase 3: breach / paste intelligence ─────────────────────────────────

    def _check_paste_site(self, scan_id: str, domain: str, org: str,
                          name: str, url_tmpl: str) -> int:
        terms = [domain, f'"{domain}"', org]
        for term in terms[:2]:
            url = url_tmpl.format(
                term=quote(term), term_q=quote(term)
            ).replace("{term}", quote(term))
            r = self.http.get(url, scan_id, self.NAME, add_delay=True, timeout=12)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_lower = body.lower()
            if domain.lower() in body_lower or org.lower() in body_lower:
                self._pattern_scan(scan_id, body, url)
                snip = _visible_text(body, 600)
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"📋 Paste Site Hit: {name} mentions '{domain}'",
                    f"'{domain}' found in {name} paste platform search results.",
                    url=url,
                    evidence=f"Source: {name}\nURL: {url}\nSnippet:\n{snip[:400]}",
                    tags=["paste", "leak", "darkweb", name.lower()]
                )
                return 1
        return 0

    def _check_psbdmp(self, scan_id: str, domain: str) -> int:
        url = _PSBDMP.format(domain=quote(domain))
        r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=12)
        if not r: return 0
        if r.text: self._pattern_scan(scan_id, r.text, url)
        try:
            items = r.json().get("data", r.json().get("items", []))
            count = len(items)
            if count > 0:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"🔴 psbdmp: {count} Paste(s) Contain '{domain}'",
                    f"psbdmp paste database found {count} paste(s) referencing {domain}.",
                    url=url,
                    evidence="\n".join(
                        f"• [{i.get('id','?')}] {i.get('time','?')} - {str(i)[:120]}"
                        for i in items[:10]
                    ),
                    tags=["paste","leak","darkweb","psbdmp"]
                )
            return count
        except Exception:
            if r.text and domain.lower() in r.text.lower():
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"psbdmp Mention: {domain}", "",
                    url=url, tags=["paste","leak"]
                )
                return 1
        return 0

    def _ransomwatch(self, scan_id: str, domain: str, org: str) -> int:
        r = self.http.get(_RANSOMWATCH, scan_id, self.NAME, add_delay=False, timeout=15)
        if not r or r.status_code != 200: return 0
        try: posts = r.json()
        except Exception: return 0
        hits = [p for p in posts
                if domain.lower() in json.dumps(p).lower()
                or org.lower() in json.dumps(p).lower()]
        if hits:
            gangs  = list({p.get("group_name","?") for p in hits})
            sample = "\n".join(
                f"• {p.get('group_name','?')} | {p.get('post_title', p.get('description',''))[:100]}"
                for p in hits[:8]
            )
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                f"🚨 RANSOMWATCH: {domain} in {len(hits)} Ransomware Gang Post(s)!",
                f"RansomWatch found {domain} in ransomware leak site posts.\n"
                f"Gangs: {', '.join(gangs)}",
                url="https://ransomwatch.telemetry.ltd/",
                evidence=sample,
                tags=["ransomware","darkweb","critical"]
            )
        return len(hits)

    def _ddosecrets(self, scan_id: str, domain: str, org: str) -> int:
        url = f"https://ddosecrets.com/search/?q={quote(domain)}"
        r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=12)
        if not r or r.status_code != 200: return 0
        body = (r.text or "").lower()
        if domain.lower() in body and "no results" not in body:
            snip = _visible_text(r.text or "", 600)
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                f"🚨 DDoSecrets: '{domain}' Found in Distributed Secrets Archive",
                "Distributed Denial of Secrets (ddosecrets.com) may have published "
                f"leaked data related to '{domain}'.",
                url=url,
                evidence=f"Source: ddosecrets.com\nSnippet:\n{snip[:400]}",
                tags=["darkweb","leak","ddosecrets","critical"]
            )
            return 1
        return 0

    def _urlhaus(self, scan_id: str, domain: str) -> None:
        r = self.http.post(_URLHAUS, scan_id, self.NAME,
                           data={"host": domain}, add_delay=False, timeout=10)
        if not r or r.status_code != 200: return
        try: d = r.json()
        except Exception: return
        if d.get("query_status") == "is_host":
            urls   = d.get("urls", [])
            active = [u for u in urls if u.get("url_status") == "online"]
            self.db.save_finding(
                scan_id, self.NAME,
                "critical" if active else "high",
                f"⚠️ URLhaus: {len(urls)} Malware/Phishing URL(s) on {domain}",
                f"URLhaus reports {len(urls)} malicious URL(s) hosted on {domain}.",
                url=f"https://urlhaus.abuse.ch/host/{domain}/",
                evidence="\n".join(
                    f"• [{u.get('url_status','?')}] {u.get('url','?')[:120]}"
                    for u in urls[:10]
                ),
                tags=["malware","phishing","urlhaus"]
            )

    def _leakcheck(self, scan_id: str, domain: str) -> None:
        url = _LEAKCHECK.format(domain=quote(domain))
        r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200: return
        try: d = r.json()
        except Exception: return
        if d.get("found") or d.get("sources"):
            sources = d.get("sources", [])
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                f"🚨 LeakCheck: {domain} in {len(sources)} Breach Database(s)",
                f"LeakCheck.io found credentials from {domain} in breach databases.",
                url=f"https://leakcheck.io/?check={domain}",
                evidence=f"Sources: {', '.join(str(s) for s in sources[:10])}",
                tags=["breach","leak","darkweb","critical"]
            )

    def _abuseipdb_check(self, scan_id: str, domain: str) -> None:
        ips = self.safe_resolve(domain)
        if not ips: return
        for ip in ips[:3]:
            r = self.http.get(
                f"https://api.cybergordon.com/ip/{ip}",
                scan_id, self.NAME, add_delay=False, timeout=8
            )
            if r and r.status_code == 200:
                try:
                    d = r.json()
                    score = d.get("score", 0) or d.get("risk_score", 0)
                    if score and int(score) > 30:
                        self.db.save_finding(
                            scan_id, self.NAME, "high",
                            f"⚠️ Cybergordon: {ip} ({domain}) Risk Score {score}",
                            f"IP {ip} has an elevated risk score in Cybergordon reputation database.",
                            evidence=str(d)[:400],
                            tags=["reputation","darkweb","ip","risk"]
                        )
                except Exception:
                    pass

    def _hibp_domain(self, scan_id: str, domain: str, key: str) -> None:
        r = self.http.get(
            _HIBP_DOMAIN.format(domain=quote(domain)),
            scan_id, self.NAME, add_delay=False,
            headers={"hibp-api-key": key, "User-Agent": "FEROXSEI-OSINT"}
        )
        if not r: return
        if r.status_code == 200:
            try:
                emails = r.json()
                count  = len(emails) if isinstance(emails, list) else 0
                if count:
                    self.db.save_finding(
                        scan_id, self.NAME, "critical",
                        f"🚨 HIBP: {count} Breached Account(s) on {domain}",
                        f"{count} email account(s) from {domain} found in HIBP breach data.",
                        url=f"https://haveibeenpwned.com/DomainSearch/{domain}",
                        evidence="\n".join(str(e)[:120] for e in emails[:20]),
                        tags=["hibp","breach","email","critical"]
                    )
            except Exception:
                pass

    # ── Phase 4: Telegram + forum intelligence ────────────────────────────────

    def _hibp_email(self, scan_id: str, email: str, key: str) -> bool:
        """HIBP per-account breach lookup (requires API key)."""
        r = self.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            scan_id, self.NAME, add_delay=False,
            headers={"hibp-api-key": key, "User-Agent": "FEROXSEI-OSINT"}
        )
        if not r: return False
        if r.status_code == 200:
            try:
                breaches = r.json()
                if breaches:
                    names = [b.get("Name", "?") for b in breaches[:15]]
                    self.db.save_finding(
                        scan_id, self.NAME, "critical",
                        f"🚨 HIBP: '{email}' in {len(breaches)} Data Breach(es)!",
                        f"{email} appears in {len(breaches)} known breach dataset(s).",
                        url=f"https://haveibeenpwned.com/account/{quote(email)}",
                        evidence=f"Breaches: {', '.join(names)}",
                        tags=["hibp", "breach", "email", "critical"]
                    )
                    return True
            except Exception:
                pass
        elif r.status_code == 404:
            pass   # not found - clean
        return False

    def _abuseipdb_ip(self, scan_id: str, ip: str) -> None:
        """Direct IP reputation check via Cybergordon (no DNS resolution needed)."""
        r = self.http.get(
            f"https://api.cybergordon.com/ip/{ip}",
            scan_id, self.NAME, add_delay=False, timeout=8
        )
        if r and r.status_code == 200:
            try:
                d = r.json()
                score = d.get("score", 0) or d.get("risk_score", 0)
                if score and int(score) > 30:
                    self.db.save_finding(
                        scan_id, self.NAME, "high",
                        f"⚠️ Cybergordon: IP {ip} Risk Score {score}",
                        f"IP {ip} has an elevated risk score in Cybergordon reputation database.",
                        evidence=str(d)[:400],
                        tags=["reputation", "darkweb", "ip", "risk"]
                    )
            except Exception:
                pass

    def _telegram_intel(self, scan_id: str, primary: str, secondary: str, label: str) -> int:
        term = primary
        hits = 0
        tg_links: set[str] = set()

        for src_name, src_url_tpl in [
            ("telegramchannels.me", f"https://telegramchannels.me/search?query={quote(term)}"),
            ("tgstat.com",          f"https://tgstat.com/search?q={quote(term)}"),
            ("tgcat.com",           f"https://tgcat.com/search?q={quote(term)}"),
        ]:
            if self.should_skip(scan_id): break
            r = self.http.get(src_url_tpl, scan_id, self.NAME, add_delay=False, timeout=15)
            if not r or r.status_code != 200: continue
            body = r.text or ""
            for m in re.finditer(r'https?://t\.me/[a-zA-Z0-9_+/\-]{3,64}', body):
                tg_links.add(m.group(0))
            if term.lower() in body.lower():
                hits += 1

        dork_url = f"https://www.bing.com/search?q=site%3At.me+%22{quote(term)}%22"
        r = self.http.get(dork_url, scan_id, self.NAME, add_delay=False, timeout=12)
        if r and r.status_code == 200:
            for m in re.finditer(r'https?://t\.me/[a-zA-Z0-9_+/\-]{3,64}', r.text or ""):
                tg_links.add(m.group(0))

        lol_url = f"https://lolarchiver.com/search?q={quote(term)}"
        r = self.http.get(lol_url, scan_id, self.NAME, add_delay=False, timeout=12)
        if r and r.status_code == 200:
            body = (r.text or "").lower()
            if term.lower() in body and "no result" not in body:
                hits += 1
                self.db.save_finding(
                    scan_id, self.NAME, "critical",
                    f"🚨 Telegram Leak Archive: '{label}' on lolarchiver.com",
                    "lolarchiver.com (Telegram message archive) contains messages referencing the target.",
                    url=lol_url,
                    evidence=_visible_text(r.text or "", 600),
                    tags=["telegram","leak","archive","critical"]
                )

        if tg_links:
            hits += len(tg_links)
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"📱 Telegram: {len(tg_links)} Channel/Group Link(s) for '{label}'",
                f"Telegram channels/groups related to '{label}' discovered.",
                evidence="\n".join(f"  {u}" for u in sorted(tg_links)[:25]),
                tags=["telegram","darkweb","social"],
                raw_data={"tg_links": list(tg_links)[:50]}
            )

        return hits

    # ── Phase 5: code leaks + exposed services ────────────────────────────────

    def _github_search(self, scan_id: str, domain: str, token: str) -> int:
        hdrs = {"Accept": "application/vnd.github+json"}
        if token: hdrs["Authorization"] = f"Bearer {token}"
        queries = [
            f'"{domain}" password', f'"{domain}" api_key',
            f'"{domain}" secret',   f'"{domain}" token',
        ]
        all_items: list[dict] = []
        for q in queries[:3]:
            if self.should_skip(scan_id): break
            r = self.http.get(
                _GH_CODE.format(q=quote(q)),
                scan_id, self.NAME, add_delay=True, headers=hdrs
            )
            if r and r.status_code == 200:
                try: all_items.extend(r.json().get("items", []))
                except Exception: pass
        if all_items:
            unique = list({i.get("html_url",""): i for i in all_items}.values())
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                f"🚨 GitHub Code Leak: {len(unique)} File(s) Reference {domain} + Credentials",
                "Public GitHub code search found files mentioning domain alongside credential keywords.",
                url=f"https://github.com/search?q={quote(domain)}+password&type=code",
                evidence="\n".join(
                    f"• [{i.get('repository',{}).get('full_name','?')}] {i.get('name','?')}\n"
                    f"  {i.get('html_url','')}"
                    for i in unique[:10]
                ),
                tags=["github","credential","leak","critical"]
            )
        return len(all_items)

    def _public_exposure_check(self, scan_id: str, domain: str, org: str) -> None:
        queries = [
            (f'"{domain}" trello.com board', "Trello Board"),
            (f'"{domain}" jira site:atlassian.net', "Jira/Confluence"),
            (f'"{domain}" site:docs.google.com', "Google Docs"),
            (f'"{domain}" pastebin.com', "Pastebin"),
        ]
        for q, label in queries:
            if self.should_skip(scan_id): break
            r = self.http.get(
                f"https://www.bing.com/search?q={quote(q)}",
                scan_id, self.NAME, add_delay=True, timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (compatible; FEROXSEI-OSINT)"}
            )
            if not r or r.status_code != 200: continue
            body = (r.text or "").lower()
            if domain.lower() in body and "no results" not in body:
                snip = _visible_text(r.text or "", 400)
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"🌐 Public Exposure: {domain} Found in {label}",
                    f"Search engine found {domain} mentioned in public {label} content.",
                    evidence=f"Query: {q}\nSnippet:\n{snip[:350]}",
                    tags=["exposure","public","leak", label.lower().replace("/","-")]
                )
