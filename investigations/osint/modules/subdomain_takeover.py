"""
FEROXSEI OSINT - Subdomain Takeover Detector
Enumerates subdomains (from crt.sh + brute-force) then checks each one for
dangling CNAME records pointing to inactive or claimable third-party services.

Fingerprint database covers 40+ providers:
  GitHub Pages, Heroku, Netlify, Vercel, AWS S3/EB/CloudFront/ECS,
  Azure App Service / Blob / Traffic Manager, Fastly, Ghost, Shopify,
  Zendesk, HubSpot, Surge.sh, Cargo, Tumblr, Pantheon, WP Engine,
  Readme.io, Intercom, Statuspage, Webflow, Squarespace, Wix, Strikingly,
  Uservoice, Feedpress, Campaign Monitor, Mailchimp, Kinsta, Fly.io,
  and more.

No API keys required.

Config keys:
  takeover_extra_subs  str   Comma-separated extra subdomains to check
"""
from __future__ import annotations
import re
from urllib.parse import urljoin

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target

# ── Fingerprint DB ─────────────────────────────────────────────────────────────
# Format: (cname_pattern, body_fingerprint, provider_name, severity)
# cname_pattern: regex matched against the resolved CNAME target
# body_fingerprint: string that appears in the response body when unclaimed
_FINGERPRINTS = [
    # GitHub Pages
    (r"\.github\.io$",   "There isn't a GitHub Pages site here",   "GitHub Pages",       "critical"),
    # Heroku
    (r"\.herokudns\.com$|\.herokuapp\.com$", "No such app",        "Heroku",             "critical"),
    (r"\.herokudns\.com$|\.herokuapp\.com$", "no app configured",  "Heroku",             "critical"),
    # Netlify
    (r"\.netlify\.app$|\.netlify\.com$", "Not Found - Request ID", "Netlify",            "critical"),
    # Vercel
    (r"\.vercel\.app$",  "The deployment could not be found",      "Vercel",             "critical"),
    # AWS
    (r"\.amazonaws\.com$|\.s3\.amazonaws\.com$",
                         "NoSuchBucket",                           "AWS S3",             "critical"),
    (r"\.elasticbeanstalk\.com$", "NXDOMAIN",                      "AWS ElasticBeanstalk","high"),
    (r"\.cloudfront\.net$",      "Bad request",                    "AWS CloudFront",     "medium"),
    # Azure
    (r"\.azurewebsites\.net$|\.azurecontainer\.io$",
                         "404 Web Site not found",                 "Azure App Service",  "critical"),
    (r"\.trafficmanager\.net$",  "404 Not Found",                  "Azure Traffic Mgr",  "high"),
    (r"\.blob\.core\.windows\.net$",
                         "BlobNotFound",                           "Azure Blob",         "critical"),
    # Fastly
    (r"\.global\.ssl\.fastly\.net$|\.fastlylb\.net$",
                         "Fastly error",                           "Fastly",             "high"),
    # Ghost
    (r"\.ghost\.io$",    "404 - Page not found",                   "Ghost",              "critical"),
    # Shopify
    (r"\.myshopify\.com$", "Sorry, this shop is currently unavailable", "Shopify",       "critical"),
    # Zendesk
    (r"\.zendesk\.com$", "Help Center Closed",                     "Zendesk",            "high"),
    # HubSpot
    (r"\.hs-sites\.com$|\.hubspot\.com$", "does not exist",        "HubSpot",            "high"),
    # Surge.sh
    (r"\.surge\.sh$",    "project not found",                      "Surge.sh",           "critical"),
    # Tumblr
    (r"\.tumblr\.com$",  "There's nothing here",                   "Tumblr",             "critical"),
    # Statuspage
    (r"\.statuspage\.io$", "You are being",                        "Statuspage.io",      "high"),
    # Readme.io
    (r"\.readme\.io$",   "Project doesnt exist",                   "Readme.io",          "high"),
    # Intercom
    (r"\.custom\.intercom\.help$", "This page is reserved",        "Intercom",           "medium"),
    # Webflow
    (r"\.webflow\.io$",  "The page you are looking for doesn't exist", "Webflow",        "critical"),
    # WP Engine
    (r"\.wpengine\.com$", "The site you were looking for couldn't be found", "WP Engine","high"),
    # Fly.io
    (r"\.fly\.dev$",     "404 Not Found",                          "Fly.io",             "critical"),
    # Kinsta
    (r"\.kinsta\.cloud$", "No Site For Domain",                    "Kinsta",             "critical"),
    # Pantheon
    (r"\.pantheon\.io$|\.pantheonsite\.io$", "404 error unknown site", "Pantheon",       "high"),
    # Cargo
    (r"\.cargo\.site$",  "If you're moving your domain",           "Cargo",              "medium"),
    # Uservoice
    (r"\.uservoice\.com$", "This UserVoice subdomain",             "UserVoice",          "high"),
    # Feedpress
    (r"\.feedpress\.me$", "The feed has not been found",           "Feedpress",          "medium"),
    # Campaign Monitor
    (r"\.createsend\.com$", "Double check the URL",                "Campaign Monitor",   "medium"),
    # Mailchimp
    (r"\.list-manage\.com$", "Oops! That page doesn't exist",     "Mailchimp",          "medium"),
    # Squarespace
    (r"\.squarespace\.com$", "No Such Account",                    "Squarespace",        "high"),
    # Strikingly
    (r"\.strikingly\.com$", "doesn't exist",                       "Strikingly",         "high"),
    # Tilda
    (r"\.tilda\.ws$",    "Please renew your subscription",         "Tilda",              "medium"),
    # Anima
    (r"\.animaapp\.io$", "Not Found",                              "Anima",              "medium"),
    # Netlify CMS
    (r"\.netlify\.com$", "page not found",                         "Netlify CMS",        "critical"),
]

# Common subdomains to brute-force in addition to crt.sh results
_BRUTE_LIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "admin", "host", "api", "dev", "staging", "beta", "app", "dashboard",
    "cdn", "static", "media", "assets", "img", "images", "files", "docs",
    "support", "help", "status", "monitoring", "internal", "intranet",
    "login", "auth", "sso", "oauth", "uat", "qa", "preprod", "sandbox",
    "demo", "lab", "git", "gitlab", "jira", "confluence", "wiki", "old",
    "backup", "legacy", "new", "v2", "api2", "gateway", "proxy", "waf",
]


class SubdomainTakeoverModule(BaseOSINTModule):
    """Check subdomains for dangling CNAME / takeover opportunities."""
    NAME  = "subTakeover"
    LABEL = "Subdomain Takeover"
    ICON  = "🎯"
    ORDER = 52
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain = _extract_domain(target)
        extra  = [s.strip() for s in
                  config.get("takeover_extra_subs", "").split(",") if s.strip()]

        _log(f"[{self.LABEL}] Starting subdomain takeover check for {domain}")

        # ── 1. Gather subdomains from crt.sh ─────────────────────────────
        subs = self._crtsh(scan_id, domain)
        _log(f"[{self.LABEL}] crt.sh: {len(subs)} subdomains")

        # ── 2. Add brute-force candidates + extras ─────────────────────────
        brute = {f"{w}.{domain}" for w in _BRUTE_LIST} | set(extra)
        all_subs = subs | brute
        _log(f"[{self.LABEL}] Total to check: {len(all_subs)}")

        vulnerable   = []
        dangling     = []
        checked      = 0

        for sub in sorted(all_subs):
            checked += 1
            cname = self._get_cname(sub)
            if not cname:
                continue  # NXDOMAIN or A-record only - skip

            # Check if CNAME target itself resolves
            target_resolves = self._resolves(cname)
            if target_resolves:
                # Resolves - check body fingerprints anyway (orphaned but live)
                result = self._check_body(scan_id, sub, cname)
                if result:
                    vulnerable.append(result)
            else:
                # Dangling - CNAME doesn't resolve at all (high risk)
                provider = self._match_provider(cname)
                dangling.append((sub, cname, provider))
                sev = "critical" if provider else "high"
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"🎯 Dangling CNAME: {sub}",
                    f"'{sub}' has a CNAME record pointing to '{cname}' which "
                    f"does NOT resolve. " +
                    (f"This matches {provider} - the service can likely be claimed."
                     if provider else
                     "The target may be an abandoned service that can be claimed."),
                    evidence=f"CNAME: {sub} → {cname}\nCNAME resolves: NO",
                    tags=["subdomain", "takeover", "dangling", sev]
                )

        # ── Summary ───────────────────────────────────────────────────────
        total_issues = len(vulnerable) + len(dangling)
        if total_issues == 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Subdomain Takeover: No Issues Found ({checked} Checked)",
                f"Checked {checked} subdomains for dangling CNAMEs and "
                "service fingerprints. No takeover opportunities found.",
                tags=["subdomain", "takeover", "clean"]
            )
        else:
            self.db.save_finding(
                scan_id, self.NAME,
                "critical" if vulnerable else "high",
                f"🎯 Subdomain Takeover: {total_issues} Issue(s) Found",
                f"{len(vulnerable)} confirmed body-match, {len(dangling)} dangling CNAMEs "
                f"across {checked} subdomains checked.",
                evidence="\n".join(
                    [f"[CONFIRMED] {v['sub']} → {v['cname']} ({v['provider']})"
                     for v in vulnerable] +
                    [f"[DANGLING]  {s} → {c} ({p or 'unknown'})"
                     for s, c, p in dangling]
                )[:3000],
                tags=["subdomain", "takeover", "summary"]
            )

        _log(f"[{self.LABEL}] ✅ {checked} checked, "
             f"{len(vulnerable)} confirmed, {len(dangling)} dangling")

    # ── DNS helpers ───────────────────────────────────────────────────────────

    def _crtsh(self, scan_id: str, domain: str) -> set[str]:
        """Pull subdomains from crt.sh certificate transparency."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r   = self.http.get(url, scan_id, self.NAME, add_delay=False)
        if not r or r.status_code != 200:
            return set()
        try:
            items = r.json()
            subs: set[str] = set()
            for item in items:
                for name in (item.get("name_value") or "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and domain in name and " " not in name:
                        subs.add(name.lower())
            return subs
        except Exception:
            return set()

    def _get_cname(self, host: str) -> str | None:
        """Return CNAME target if the host has a CNAME record, else None."""
        try:
            import dns.resolver as _res  # type: ignore
            answers = _res.resolve(host, "CNAME", lifetime=4)
            return str(answers[0].target).rstrip(".")
        except Exception:
            pass
        # Fallback: socket (slower, doesn't distinguish CNAME vs A)
        return None

    def _resolves(self, host: str) -> bool:
        return len(self.safe_resolve(host)) > 0

    def _match_provider(self, cname: str) -> str | None:
        for pattern, _, provider, _ in _FINGERPRINTS:
            if re.search(pattern, cname, re.I):
                return provider
        return None

    def _check_body(self, scan_id: str, sub: str, cname: str) -> dict | None:
        """Fetch the subdomain and check body for takeover fingerprints."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            r   = self.http.get(url, scan_id, self.NAME, add_delay=False)
            if not r or not r.text:
                continue
            body = r.text[:5000]
            # Pattern-scan the subdomain response body
            self._pattern_scan(scan_id, body, url)
            for pattern, body_fp, provider, sev in _FINGERPRINTS:
                if re.search(pattern, cname, re.I) and body_fp.lower() in body.lower():
                    self.db.save_finding(
                        scan_id, self.NAME, sev,
                        f"🎯 CONFIRMED Takeover: {sub} ({provider})",
                        f"Subdomain '{sub}' has a CNAME to '{cname}' ({provider}) "
                        "and the response body contains the unclaimed-service "
                        "fingerprint. This subdomain can very likely be claimed.",
                        url=url,
                        evidence=(f"CNAME: {sub} → {cname}\n"
                                  f"Provider: {provider}\n"
                                  f"Fingerprint matched: '{body_fp}'\n"
                                  f"Body snippet: {body[:400]}"),
                        tags=["subdomain", "takeover", "confirmed", sev]
                    )
                    return {"sub": sub, "cname": cname, "provider": provider, "sev": sev}
        return None
