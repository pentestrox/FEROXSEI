"""
FEROXSEI OSINT - Document Metadata Harvester (Metagoofil-style)
Finds Google/Bing-indexed documents on the target domain, downloads them,
and extracts metadata - revealing employee names, software versions, internal
file paths, and company structure.

Supported document types:
  PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, ODT, ODS

Extraction backends (graceful degradation - uses what's available):
  • PyPDF2 / pypdf     - PDF metadata (Author, Creator, Producer, ModDate)
  • python-docx        - Word author, last-modified-by, title
  • openpyxl           - Excel creator, last-modified-by
  • python-pptx        - PowerPoint author, last-modified-by
  • ExifTool (CLI)     - fallback for all types
  • Basic regex        - last resort for any text-extractable metadata

Config keys:
  meta_filetypes    str   Comma-sep extensions (default: pdf,docx,xlsx,pptx,doc,xls,ppt)
  meta_max_files    int   Max docs to analyse (default 25)
  meta_max_kb       int   Max file size in KB (default 2048)
"""
from __future__ import annotations
import io
import re
import subprocess
import tempfile
import os
from urllib.parse import quote, urljoin, urlparse

from .base import BaseOSINTModule, _log, _extract_domain

# Optional metadata libraries
try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    try:
        import pypdf as PyPDF2  # newer name
        HAS_PYPDF2 = True
    except ImportError:
        HAS_PYPDF2 = False

try:
    import docx as _docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    import openpyxl as _xl
    HAS_XL = True
except ImportError:
    HAS_XL = False

try:
    import pptx as _pptx
    HAS_PPTX = True
except ImportError:
    HAS_PPTX = False

_DEFAULT_TYPES = ["pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt"]

# Fields considered high-value for OSINT
_INTERESTING_KEYS = {
    "author", "creator", "producer", "last_modified_by", "lastmodifiedby",
    "manager", "company", "title", "subject", "application", "appversion",
    "template", "content_status",
}


class MetadataHarvestModule(BaseOSINTModule):
    """Google/Bing document discovery + metadata extraction for employee/software intel."""
    NAME  = "metaHarvest"
    LABEL = "Metadata Harvester"
    ICON  = "📑"
    ORDER = 28
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain    = _extract_domain(target)
        base_url  = target if target.startswith("http") else f"https://{domain}"
        max_files = int(config.get("meta_max_files", 25))
        max_kb    = int(config.get("meta_max_kb", 2048))
        raw_types = config.get("meta_filetypes", ",".join(_DEFAULT_TYPES))
        ftypes    = [t.strip().lstrip(".").lower() for t in raw_types.split(",") if t.strip()]

        _log(f"[{self.LABEL}] Harvesting documents on {domain} ({','.join(ftypes)})")

        # ── 1. Discover documents via search engine dorking ──────────────
        doc_urls = self._discover_docs(scan_id, domain, ftypes, max_files)
        _log(f"[{self.LABEL}] Found {len(doc_urls)} document URL(s)")

        if not doc_urls:
            # Try direct crawl for linked documents
            doc_urls = self._crawl_links(scan_id, base_url, ftypes, max_files)
            _log(f"[{self.LABEL}] Crawl found {len(doc_urls)} doc(s)")

        if not doc_urls:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Metadata: No Documents Found on {domain}",
                "No publicly-indexed documents found via search engine dorking "
                "or direct crawl. The site may restrict indexing or have no "
                "downloadable documents.",
                tags=["metadata", "docs", "clean"]
            )
            return

        # ── 2. Download and extract metadata ─────────────────────────────
        all_authors:   set[str] = set()
        all_software:  set[str] = set()
        all_paths:     set[str] = set()
        all_companies: set[str] = set()
        processed = 0

        for url in doc_urls[:max_files]:
            _log(f"[{self.LABEL}] Downloading: {url[-80:]}")
            r = self.http.get(url, scan_id, self.NAME, add_delay=True)
            if not r or r.status_code != 200 or not r.content:
                continue
            size_kb = len(r.content) / 1024
            if size_kb > max_kb:
                _log(f"[{self.LABEL}] Skipping {url[-40:]} ({size_kb:.0f}KB > {max_kb}KB)")
                continue

            ext = url.rsplit(".", 1)[-1].lower().split("?")[0]
            # Pattern-scan the raw response (catches secrets in text-based docs)
            if r.text:
                self._pattern_scan(scan_id, r.text, url)
            meta = self._extract_meta(r.content, ext)
            if not meta:
                continue

            processed += 1
            # Aggregate interesting values
            for k, v in meta.items():
                vl = v.lower()
                kl = k.lower().replace("-", "_").replace(" ", "_")
                if not v or len(v) < 2:
                    continue
                if "author" in kl or "creator" in kl or "modified_by" in kl:
                    if not any(c.isdigit() for c in v[:3]):  # exclude version strings
                        all_authors.add(v[:80])
                if "application" in kl or "producer" in kl or "software" in kl:
                    all_software.add(v[:80])
                if "\\" in v or "/" in v and (":" in v or v.startswith("/")):
                    all_paths.add(v[:120])
                if "company" in kl or "organisation" in kl or "organization" in kl:
                    all_companies.add(v[:80])

            # Per-file finding if there are interesting metadata fields
            interesting = {k: v for k, v in meta.items()
                           if k.lower().replace("-", "_").replace(" ", "_")
                           in _INTERESTING_KEYS and v}
            if interesting:
                evidence = "\n".join(f"  {k}: {v}" for k, v in interesting.items())
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"📑 Document Metadata: {url.rsplit('/', 1)[-1][:60]}",
                    f"Metadata extracted from publicly-accessible document at {url[:80]}",
                    url=url,
                    evidence=evidence,
                    tags=["metadata", "document", ext],
                    raw_data={"url": url, "metadata": meta}
                )

        # ── 3. Aggregate findings ─────────────────────────────────────────
        if all_authors:
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"👤 Employee Names Discovered: {len(all_authors)} Author(s) in Documents",
                f"Document metadata revealed {len(all_authors)} employee/author names "
                "from documents hosted on or linked from the target domain. "
                "Useful for spearphishing, LinkedIn recon, and email construction.",
                evidence="\n".join(f"  • {a}" for a in sorted(all_authors)[:40]),
                tags=["metadata", "employees", "names", "spearphish"],
                raw_data={"authors": sorted(all_authors)}
            )

        if all_software:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"🖥️ Software Versions in Metadata: {len(all_software)} Application(s)",
                "Software/application names found in document metadata. Cross-reference "
                "with CVE databases to identify outdated software used internally.",
                evidence="\n".join(f"  • {s}" for s in sorted(all_software)[:20]),
                tags=["metadata", "software", "fingerprint"],
                raw_data={"software": sorted(all_software)}
            )

        if all_paths:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"📂 Internal File Paths in Metadata: {len(all_paths)} Path(s)",
                "Internal file system paths found in document metadata. These reveal "
                "OS type, directory structure, usernames, and server naming conventions.",
                evidence="\n".join(f"  • {p}" for p in sorted(all_paths)[:20]),
                tags=["metadata", "paths", "disclosure"],
                raw_data={"paths": sorted(all_paths)}
            )

        if all_companies:
            self.db.save_finding(
                scan_id, self.NAME, "low",
                f"🏢 Company Names in Metadata: {len(all_companies)}",
                "Company/organisation names embedded in document metadata.",
                evidence="\n".join(f"  • {c}" for c in sorted(all_companies)[:10]),
                tags=["metadata", "company", "recon"]
            )

        if processed == 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Metadata: {len(doc_urls)} Documents Found, None Extractable",
                "Documents were discovered but metadata could not be extracted "
                "(may require optional libraries: pip install PyPDF2 python-docx openpyxl python-pptx).",
                tags=["metadata", "docs"]
            )

        _log(f"[{self.LABEL}] ✅ {processed}/{len(doc_urls)} docs processed - "
             f"{len(all_authors)} authors, {len(all_software)} software, "
             f"{len(all_paths)} paths")

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_docs(self, scan_id: str, domain: str,
                       ftypes: list[str], limit: int) -> list[str]:
        """DuckDuckGo dork for indexed documents."""
        found: list[str] = []
        seen:  set[str]  = set()
        url_re = re.compile(
            r'href=["\']?(https?://[^\s"\'<>]+\.(?:' +
            '|'.join(re.escape(t) for t in ftypes) +
            r')(?:[?#][^\s"\'<>]*)?)["\']?',
            re.I
        )
        for ft in ftypes:
            if len(found) >= limit:
                break
            q   = f'site:{domain} filetype:{ft}'
            url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
            r   = self.http.get(url, scan_id, self.NAME, add_delay=True)
            if not r or r.status_code != 200:
                continue
            for m in url_re.finditer(r.text):
                u = m.group(1)
                if u not in seen and domain in urlparse(u).netloc:
                    seen.add(u)
                    found.append(u)
        return found[:limit]

    def _crawl_links(self, scan_id: str, base_url: str,
                     ftypes: list[str], limit: int) -> list[str]:
        """Simple HTML link crawler for document extensions."""
        r = self.http.get(base_url, scan_id, self.NAME, add_delay=False)
        if not r or r.status_code != 200:
            return []
        domain  = _extract_domain(base_url)
        ext_pat = re.compile(
            r'href=["\']([^"\'<>]+\.(?:' +
            '|'.join(re.escape(t) for t in ftypes) +
            r')(?:[?#][^"\']*)?)["\']', re.I
        )
        found = []
        seen: set[str] = set()
        for m in ext_pat.finditer(r.text):
            u = urljoin(base_url, m.group(1))
            if u not in seen and domain in urlparse(u).netloc:
                seen.add(u)
                found.append(u)
                if len(found) >= limit:
                    break
        return found

    # ── Extraction ────────────────────────────────────────────────────────────

    def _extract_meta(self, content: bytes, ext: str) -> dict[str, str]:
        """Route to appropriate extractor based on file extension."""
        try:
            if ext == "pdf":
                return self._pdf_meta(content)
            elif ext in ("docx", "doc"):
                return self._docx_meta(content)
            elif ext in ("xlsx", "xls"):
                return self._xlsx_meta(content)
            elif ext in ("pptx", "ppt"):
                return self._pptx_meta(content)
        except Exception:
            pass
        # Last resort: regex on raw bytes
        return self._regex_meta(content)

    def _pdf_meta(self, content: bytes) -> dict[str, str]:
        if not HAS_PYPDF2:
            return self._regex_meta(content)
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            info   = reader.metadata or {}
            return {k.lstrip("/"): str(v) for k, v in info.items() if v}
        except Exception:
            return self._regex_meta(content)

    def _docx_meta(self, content: bytes) -> dict[str, str]:
        if not HAS_DOCX:
            return self._regex_meta(content)
        try:
            doc  = _docx.Document(io.BytesIO(content))
            core = doc.core_properties
            meta: dict[str, str] = {}
            for attr in ("author", "last_modified_by", "title", "subject",
                         "company", "manager", "created", "modified", "revision"):
                val = getattr(core, attr, None)
                if val:
                    meta[attr] = str(val)[:200]
            return meta
        except Exception:
            return self._regex_meta(content)

    def _xlsx_meta(self, content: bytes) -> dict[str, str]:
        if not HAS_XL:
            return self._regex_meta(content)
        try:
            wb   = _xl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            prop = wb.properties
            meta: dict[str, str] = {}
            for attr in ("creator", "lastModifiedBy", "title", "subject",
                         "company", "created", "modified"):
                val = getattr(prop, attr, None)
                if val:
                    meta[attr] = str(val)[:200]
            return meta
        except Exception:
            return self._regex_meta(content)

    def _pptx_meta(self, content: bytes) -> dict[str, str]:
        if not HAS_PPTX:
            return self._regex_meta(content)
        try:
            from pptx import Presentation
            prs  = Presentation(io.BytesIO(content))
            core = prs.core_properties
            meta: dict[str, str] = {}
            for attr in ("author", "last_modified_by", "title", "subject",
                         "company", "created", "modified", "revision"):
                val = getattr(core, attr, None)
                if val:
                    meta[attr] = str(val)[:200]
            return meta
        except Exception:
            return self._regex_meta(content)

    def _regex_meta(self, content: bytes) -> dict[str, str]:
        """Regex-based fallback: extract XML metadata from Office/PDF bytes."""
        meta: dict[str, str] = {}
        text = content[:65536].decode("utf-8", errors="replace")
        patterns = [
            ("Author",           r'<dc:creator>([^<]{2,80})</dc:creator>'),
            ("LastModifiedBy",   r'<cp:lastModifiedBy>([^<]{2,80})</cp:lastModifiedBy>'),
            ("Company",          r'<cp:company>([^<]{2,80})</cp:company>'),
            ("Title",            r'<dc:title>([^<]{2,100})</dc:title>'),
            ("Application",      r'<cp:Application>([^<]{2,80})</cp:Application>'),
            ("Producer",         r'/Producer\s*\(([^)]{2,80})\)'),
            ("Author_PDF",       r'/Author\s*\(([^)]{2,80})\)'),
            ("Creator_PDF",      r'/Creator\s*\(([^)]{2,80})\)'),
            ("FilePath",         r'(?:C:\\|/home/|/Users/|/var/www)[^\s"\'<>]{4,100}'),
        ]
        for name, pat in patterns:
            m = re.search(pat, text, re.I)
            if m:
                val = m.group(1) if "(" in pat or ">" in pat else m.group(0)
                meta[name] = val.strip()[:200]
        return meta
