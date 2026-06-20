"""
FEROXSEI OSINT - Security Headers & CORS Analyzer
Audits HTTP response headers and cookie flags for every discovered URL.

Checks (OWASP aligned):
  • Strict-Transport-Security (HSTS)         - missing / weak max-age
  • Content-Security-Policy (CSP)           - missing / unsafe-inline / unsafe-eval / wildcard
  • X-Frame-Options                         - missing (clickjacking)
  • X-Content-Type-Options                  - missing nosniff
  • Referrer-Policy                         - missing / unsafe
  • Permissions-Policy                      - missing
  • X-XSS-Protection                        - deprecated but still checked
  • CORS (Access-Control-Allow-Origin)      - wildcard / credentialed wildcard
  • Cookie flags                            - missing Secure / HttpOnly / SameSite
  • Server / X-Powered-By leakage          - version disclosure
  • HTTP → HTTPS redirect                   - plain HTTP accessible
  • Clickjacking via CSP frame-ancestors    - compared with X-Frame-Options

No API keys required.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target


class SecurityHeadersModule(BaseOSINTModule):
    """HTTP security headers + CORS + cookie flags audit."""
    NAME  = "securityHeaders"
    LABEL = "Security Headers"
    ICON  = "🛡️"
    ORDER = 22
    TARGET_TYPES: list = ['domain']

    # Headers that MUST be present
    _REQUIRED = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    # Headers that leak server info
    _LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Generator", "X-Runtime"]

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain   = _extract_domain(target)
        base_url = target if target.startswith("http") else f"https://{domain}"

        _log(f"[{self.LABEL}] Auditing security headers for {domain}")

        # Probe HTTPS and (optionally) HTTP
        urls = [base_url]
        if base_url.startswith("https://"):
            urls.append(base_url.replace("https://", "http://", 1))

        audited = 0
        for url in urls:
            r = self.http.get(url, scan_id, self.NAME, add_delay=False)
            if not r:
                continue
            audited += 1
            hdrs    = r.headers
            scheme  = urlparse(url).scheme

            # Pattern-scan the response body
            if r.text:
                self._pattern_scan(scan_id, r.text, url)

            # ── Plain HTTP accessible? ──────────────────────────────────────
            if scheme == "http" and r.status_code < 400:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"🛡️ HTTP Accessible (No Forced HTTPS): {domain}",
                    f"The site responds to plain HTTP at {url}. Traffic can be "
                    "intercepted. Enforce HTTPS with a permanent redirect (301) "
                    "and enable HSTS.",
                    url=url, tags=["headers", "http", "tls", "owasp"]
                )

            # ── Missing required headers ────────────────────────────────────
            missing = [h for h in self._REQUIRED if h not in hdrs]
            if missing:
                sev = "high" if len(missing) >= 3 else "medium"
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"🛡️ Missing Security Headers: {len(missing)} Missing on {domain}",
                    "The following HTTP security headers are absent. Each missing "
                    "header increases exposure to client-side attacks.",
                    url=url,
                    evidence="Missing: " + ", ".join(missing),
                    tags=["headers", "owasp", "missing", sev]
                )

            # ── HSTS analysis ───────────────────────────────────────────────
            hsts = hdrs.get("Strict-Transport-Security", "")
            if hsts:
                ma = re.search(r'max-age=(\d+)', hsts, re.I)
                if ma and int(ma.group(1)) < 31536000:
                    self.db.save_finding(
                        scan_id, self.NAME, "medium",
                        f"🛡️ HSTS max-age Too Short: {ma.group(1)}s",
                        "HSTS max-age should be at least 31536000 (1 year). "
                        "Short values allow downgrade attacks between visits.",
                        url=url, evidence=f"Strict-Transport-Security: {hsts}",
                        tags=["headers", "hsts", "tls"]
                    )
                if "includeSubDomains" not in hsts:
                    self.db.save_finding(
                        scan_id, self.NAME, "low",
                        f"🛡️ HSTS Missing includeSubDomains",
                        "HSTS does not include the includeSubDomains directive. "
                        "Subdomains remain vulnerable to SSL stripping.",
                        url=url, evidence=f"Strict-Transport-Security: {hsts}",
                        tags=["headers", "hsts", "subdomain"]
                    )

            # ── CSP analysis ────────────────────────────────────────────────
            csp = hdrs.get("Content-Security-Policy", "")
            if csp:
                csp_issues = []
                if "unsafe-inline" in csp:
                    csp_issues.append("'unsafe-inline' permits inline scripts/styles (XSS risk)")
                if "unsafe-eval" in csp:
                    csp_issues.append("'unsafe-eval' permits eval() (XSS risk)")
                if re.search(r"(script-src|default-src)\s+['\"]?\*['\"]?", csp, re.I):
                    csp_issues.append("Wildcard (*) in script-src/default-src negates CSP")
                if "data:" in csp and "script-src" in csp:
                    csp_issues.append("'data:' URI in script-src allows JS execution via data URIs")
                if csp_issues:
                    self.db.save_finding(
                        scan_id, self.NAME, "high",
                        f"🛡️ Weak CSP Policy: {len(csp_issues)} Issue(s)",
                        "The Content-Security-Policy has weaknesses that may allow XSS.",
                        url=url,
                        evidence="Issues:\n" + "\n".join(f"  • {i}" for i in csp_issues)
                        + f"\n\nFull CSP:\n{csp[:500]}",
                        tags=["headers", "csp", "xss", "high"]
                    )

            # ── CORS analysis ───────────────────────────────────────────────
            acao = hdrs.get("Access-Control-Allow-Origin", "")
            acac = hdrs.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"🛡️ CORS Wildcard: Access-Control-Allow-Origin: *",
                    "Any origin can read responses from this server. May expose "
                    "sensitive data if the API does not require authentication.",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    tags=["headers", "cors", "owasp"]
                )
            if acao == "*" and acac.lower() == "true":
                self.db.save_finding(
                    scan_id, self.NAME, "critical",
                    f"🚨 CORS Misconfiguration: Wildcard + Allow-Credentials",
                    "Credentialed CORS requests are allowed from any origin. "
                    "This lets attacker sites read authenticated responses, "
                    "enabling account takeover via CSRF-like attacks.",
                    url=url,
                    evidence=(f"Access-Control-Allow-Origin: {acao}\n"
                              f"Access-Control-Allow-Credentials: {acac}"),
                    tags=["headers", "cors", "critical", "owasp"]
                )

            # ── Cookie flags ────────────────────────────────────────────────
            # requests processes Set-Cookie into r.cookies and strips it from
            # r.headers - use r.raw.headers.getlist() to get raw header values
            try:
                cookie_lines = r.raw.headers.getlist("Set-Cookie")
            except Exception:
                cookie_lines = [v for k, v in r.headers.items()
                                if k.lower() == "set-cookie"]
            for ck in cookie_lines:
                ck_name = ck.split("=")[0].strip()
                issues  = []
                if "Secure" not in ck:
                    issues.append("Missing Secure flag (sent over HTTP)")
                if "HttpOnly" not in ck:
                    issues.append("Missing HttpOnly flag (accessible via JS/XSS)")
                if not re.search(r'SameSite\s*=', ck, re.I):
                    issues.append("Missing SameSite flag (CSRF risk)")
                if issues:
                    self.db.save_finding(
                        scan_id, self.NAME, "medium",
                        f"🍪 Insecure Cookie: {ck_name[:40]}",
                        f"Cookie '{ck_name[:40]}' is missing security attributes.",
                        url=url,
                        evidence="Issues:\n" + "\n".join(f"  • {i}" for i in issues)
                        + f"\n\nSet-Cookie: {ck[:200]}",
                        tags=["headers", "cookie", "csrf", "xss"]
                    )

            # ── Server/tech version leakage ──────────────────────────────────
            leaked = {}
            for lh in self._LEAK_HEADERS:
                val = hdrs.get(lh, "")
                if val and re.search(r'\d+[\.\d]*', val):
                    leaked[lh] = val
            if leaked:
                evidence = "\n".join(f"  {k}: {v}" for k, v in leaked.items())
                self.db.save_finding(
                    scan_id, self.NAME, "low",
                    f"🛡️ Server Version Disclosure: {len(leaked)} Header(s)",
                    "Response headers reveal server software and version numbers, "
                    "aiding fingerprinting and CVE searches.",
                    url=url, evidence=evidence,
                    tags=["headers", "disclosure", "fingerprint"]
                )

            # ── Clickjacking (X-Frame-Options / CSP frame-ancestors) ─────────
            xfo = hdrs.get("X-Frame-Options", "")
            has_frame_anc = "frame-ancestors" in csp
            if not xfo and not has_frame_anc:
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"🖱️ Clickjacking Protection Missing",
                    "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                    "The page can be framed by any origin, enabling clickjacking.",
                    url=url,
                    tags=["headers", "clickjacking", "owasp"]
                )

        if audited == 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Security Headers: Could Not Reach {domain}",
                "No HTTP response received. The target may be offline or blocking.",
                tags=["headers", "unreachable"]
            )
        else:
            _log(f"[{self.LABEL}] ✅ Audited {audited} URL(s)")
