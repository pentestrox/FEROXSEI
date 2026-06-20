"""
FEROXSEI OSINT - Wayback Machine Module
Uses the CDX API for historical URL + sensitive-file discovery.

Config keys (passed via scan config / api_cfg):
  wayback_limit      int   Max URLs per CDX query           (default 500)
  wayback_extensions str   Comma-sep extensions to search   (default: 50+ types below)
  wayback_all_urls   bool  Also fetch all archived URLs      (default True)
"""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlparse, quote, parse_qs

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target

_EXT_REDIR_RE = re.compile(
    r'[?&](?:r|url|redir|redirect|goto|link|out|dest|destination|return|next|ref)=https?://',
    re.I
)

def _url_for_pattern_scan(u: str, domain: str) -> str:
    """Return the part of the URL to run pattern matching against.
    If the URL is a redirect wrapper pointing to an external domain,
    return only the path up to the redirect parameter so patterns
    don't fire on third-party content embedded in the query string."""
    if not _EXT_REDIR_RE.search(u):
        return u
    try:
        parsed = urlparse(u)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for key in ("r", "url", "redir", "redirect", "goto", "link",
                    "out", "dest", "destination", "return", "next", "ref"):
            for val in qs.get(key, []):
                if val.startswith("http") and urlparse(val).netloc != domain:
                    return parsed.scheme + "://" + parsed.netloc + parsed.path
    except Exception:
        pass
    return u

# ── Default sensitive extensions ──────────────────────────────────────────────
_DEFAULT_EXTENSIONS = (
    "xls,xml,xlsx,json,pdf,sql,doc,docx,pptx,txt,git,zip,"
    "tar.gz,tgz,bak,7z,rar,log,cache,secret,db,backup,yaml,"
    "gz,config,csv,md,md5,exe,dll,bin,ini,bat,sh,tar,deb,rpm,"
    "iso,img,env,apk,msi,dmg,tmp,crt,pem,key,pub,asc,passwd,"
    "htpasswd,shadow,netrc,dockerenv,tfvars,tfstate"
)

_HIGH_SEV = {".sql",".db",".bak",".backup",".dump",".env",".key",".pem",
             ".asc",".passwd",".htpasswd",".shadow",".netrc",".dockerenv",
             ".tfvars",".tfstate",".secret",".pub"}
_MED_SEV  = {".git",".zip",".tar",".gz",".tgz",".7z",".rar",".deb",".rpm",
             ".iso",".img",".apk",".msi",".dmg",".exe",".dll",".bin",
             ".config",".conf",".yaml",".yml",".ini",".sh",".bat"}


class WaybackModule(BaseOSINTModule):
    """
    Wayback Machine CDX API - historical URL + sensitive-file discovery.

    Two passes:
      1. File-type CDX query with extension filter
         (CDX API: url=*.domain/&filter=original:.*.(ext|...)$)
      2. General all-URL query (limited) for pattern matching
    """
    NAME  = "wayback"
    LABEL = "Wayback Machine"
    ICON  = "🕰️"
    ORDER = 10
    TARGET_TYPES: list = ['domain']

    _CDX_BASE = "https://web.archive.org/cdx/search/cdx"

    def run(self, scan_id: str, target: str, config: dict) -> None:
        _log(f"[{self.LABEL}] Starting for {target}")
        domain = _extract_domain(target)

        # ── Config ──────────────────────────────────────────────────────────
        limit      = int(config.get("wayback_limit", 500))
        ext_raw    = config.get("wayback_extensions", _DEFAULT_EXTENSIONS)
        extensions = [e.strip().lstrip(".") for e in ext_raw.split(",") if e.strip()]
        do_all     = str(config.get("wayback_all_urls", "true")).lower() != "false"

        _log(f"[{self.LABEL}] limit={limit}, {len(extensions)} ext types, all_urls={do_all}")

        # ── Pass 1: Sensitive file-type CDX query ────────────────────────────
        file_hits = self._cdx_file_query(scan_id, domain, extensions, limit)
        _log(f"[{self.LABEL}] File CDX: {len(file_hits)} hits")

        # Group by extension
        by_ext: dict[str, list[str]] = {}
        for url in file_hits:
            path = urlparse(url).path.lower()
            ext = ""
            # Check compound extensions first (.tar.gz etc)
            for e in sorted(extensions, key=len, reverse=True):
                if path.endswith("." + e):
                    ext = "." + e
                    break
            if not ext:
                ext = Path(path).suffix or ".unknown"
            by_ext.setdefault(ext, []).append(url)

        if file_hits:
            summary = "\n".join(
                f"  {ext}: {len(urls)}"
                for ext, urls in sorted(by_ext.items(), key=lambda x: -len(x[1]))
            )
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"📁 Wayback Sensitive Files: {len(file_hits)} archived",
                f"CDX API found {len(file_hits)} sensitive files for {domain}.\n\nBreakdown:\n{summary}",
                url=f"https://web.archive.org/web/*/{domain}",
                tags=["wayback","file-exposure","recon"],
                raw_data={"total": len(file_hits),
                          "by_ext": {k: len(v) for k,v in by_ext.items()},
                          "limit_used": limit}
            )
            # Per-extension findings
            for ext, urls in sorted(by_ext.items(), key=lambda x: -len(x[1])):
                sev     = "critical" if ext in _HIGH_SEV else ("high" if ext in _MED_SEV else "medium")
                sample  = urls[:15]
                evidence= "\n".join(sample)
                if len(urls) > 15:
                    evidence += f"\n… and {len(urls)-15} more (limit={limit})"
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"Wayback {ext.upper()} Files: {len(urls)} found",
                    f"{len(urls)} archived {ext} file(s) indexed for {domain}.",
                    url=sample[0] if sample else "",
                    evidence=evidence,
                    tags=["wayback","file-exposure", ext.lstrip(".")]
                )
                # Pattern match URLs (strip external redirect targets first)
                for u in urls:
                    u_scan = _url_for_pattern_scan(u, domain)
                    for hit in self.patterns.scan_text(u_scan, url=u):
                        self.db.save_finding(
                            scan_id, self.NAME, hit["severity"],
                            f"Wayback Pattern: {hit['pattern_name']}",
                            f"Pattern matched in archived {ext} URL",
                            url=u, evidence=hit["evidence"],
                            pattern_id=hit["pattern_id"],
                            tags=["wayback","pattern"]
                        )
        else:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Wayback: No Sensitive Files Found for {domain}",
                f"CDX returned no archived files for {len(extensions)} extension types "
                f"(limit={limit}). This is a positive indicator.",
                tags=["wayback","clean"]
            )

        # ── Pass 2: General URL archive (pattern matching) ───────────────────
        if do_all:
            all_urls = self._cdx_all_query(scan_id, domain, min(limit, 500))
            _log(f"[{self.LABEL}] General CDX: {len(all_urls)} URLs")
            if all_urls:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"Wayback Machine: {len(all_urls)} Historical URLs (cap={min(limit,500)})",
                    f"Domain {domain} has {len(all_urls)} archived URLs in Wayback Machine.",
                    url=f"https://web.archive.org/web/*/{domain}",
                    tags=["wayback","archive","recon"],
                    raw_data={"sample": all_urls[:20]}
                )
                for u in all_urls:
                    u_scan = _url_for_pattern_scan(u, domain)
                    for hit in self.patterns.scan_text(u_scan, url=u):
                        self.db.save_finding(
                            scan_id, self.NAME, hit["severity"],
                            f"Wayback URL Pattern: {hit['pattern_name']}",
                            "Pattern matched in archived URL path",
                            url=u, evidence=hit["evidence"],
                            pattern_id=hit["pattern_id"],
                            tags=["wayback","pattern","url"]
                        )

        # ── Pass 3: robots.txt history ───────────────────────────────────────
        self._check_robots(scan_id, domain)
        _log(f"[{self.LABEL}] ✅ Done")

    # ── CDX helpers ──────────────────────────────────────────────────────────

    def _cdx_file_query(self, scan_id: str, domain: str,
                        extensions: list[str], limit: int) -> list[str]:
        """
        CDX API with extension filter:
        ?url=*.domain/&collapse=urlkey&output=text&fl=original
        &filter=original:.*.(ext1|ext2|...)$&limit=N
        """
        if not extensions:
            return []
        # Build regex alternation - escape dots for compound exts
        ext_alts = "|".join(re.escape(e) for e in extensions)
        filter_val = rf"original:.*\.({ext_alts})$"
        url = (
            f"{self._CDX_BASE}"
            f"?url=*.{domain}/&collapse=urlkey&output=text"
            f"&fl=original&filter={quote(filter_val, safe='')}"
            f"&limit={limit}"
        )
        _log(f"[{self.LABEL}] CDX file query → {url[:140]}")
        r = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=45)
        if not r or r.status_code != 200:
            return []
        raw = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
        valid_exts = tuple("." + e for e in extensions)
        return [u for u in raw
                if urlparse(u).path.lower().endswith(valid_exts)
                and "://" not in urlparse(u).path]

    def _cdx_all_query(self, scan_id: str, domain: str, limit: int) -> list[str]:
        """All archived URLs - JSON output, status 200 only."""
        url = (
            f"{self._CDX_BASE}"
            f"?url=*.{domain}/*&output=json&limit={limit}"
            f"&fl=original&collapse=urlkey&filter=statuscode:200"
        )
        r = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=45)
        if not r or r.status_code != 200:
            return []
        try:
            data = r.json()
            if len(data) > 1:
                return [row[0] for row in data[1:] if row]
        except Exception:
            pass
        return []

    def _check_robots(self, scan_id: str, domain: str) -> None:
        """Fetch and pattern-match the earliest archived robots.txt."""
        url = (
            f"{self._CDX_BASE}"
            f"?url={domain}/robots.txt&output=json&limit=1&fl=timestamp,original"
        )
        r = self.http.get(url, scan_id, self.NAME, add_delay=False)
        if not r or r.status_code != 200:
            return
        try:
            data = r.json()
            if len(data) < 2:
                return
            ts, orig_url = data[1][0], data[1][1]
            snapshot = f"https://web.archive.org/web/{ts}/{orig_url}"
            r2 = self.http.get(snapshot, scan_id, self.NAME)
            if not r2 or r2.status_code != 200:
                return
            # Pattern match content
            for hit in self.patterns.scan_text(r2.text, snapshot):
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    "Historical robots.txt: Path Disclosed",
                    f"Disallowed path in archived robots.txt: {hit['evidence']}",
                    url=snapshot, evidence=hit["evidence"],
                    tags=["wayback","robots","path-disclosure"]
                )
            # Extract Disallow lines
            disallows = [ln.strip() for ln in r2.text.splitlines()
                         if ln.strip().lower().startswith("disallow:") and len(ln.strip()) > 10]
            if disallows:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"robots.txt History: {len(disallows)} Disallowed Paths",
                    "Historical robots.txt reveals hidden path structure",
                    url=snapshot, evidence="\n".join(disallows[:30]),
                    tags=["wayback","robots","recon"]
                )
        except Exception:
            pass
