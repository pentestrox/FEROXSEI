"""FEROXSEI OSINT - Identity Intelligence module."""
from __future__ import annotations
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


class IdentityIntelModule(BaseOSINTModule):
    """Email intelligence - breach check, domain info, email format."""
    NAME  = "identity"
    LABEL = "Identity Intel"
    ICON  = "🧬"
    ORDER = 45
    TARGET_TYPES: list = ['domain', 'email', 'username']

    def _pattern_format_guess(self, scan_id, domain, config):
        """Generate email candidates from name patterns if adv_email; else use static list."""
        first  = (config.get("email_first")  or "").strip()
        middle = (config.get("email_middle") or "").strip()
        last   = (config.get("email_last")   or "").strip()
        formats = []
        if config.get("adv_email") and first:
            try:
                patterns = self.db.get_username_patterns(enabled_only=True)
            except Exception:
                patterns = []
            seen = set()
            for p in patterns:
                pat = p.get("pattern","")
                f = first[0].lower()  if first  else ""
                m = middle[0].lower() if middle else ""
                l = last[0].lower()   if last   else ""
                needs_mid  = "{middle}" in pat or "{m}" in pat
                needs_last = "{last}"   in pat or "{l}" in pat
                if needs_mid  and not middle: continue
                if needs_last and not last:   continue
                result = (pat
                    .replace("{first}",  first.lower())
                    .replace("{last}",   last.lower())
                    .replace("{middle}", middle.lower())
                    .replace("{f}", f).replace("{m}", m).replace("{l}", l))
                if "{" not in result:
                    email = f"{result}@{domain}"
                    if email not in seen:
                        seen.add(email)
                        formats.append(email)
        if not formats:
            formats = [
                f"john.doe@{domain}", f"johndoe@{domain}",
                f"j.doe@{domain}",    f"jdoe@{domain}",
                f"john@{domain}",     f"doe@{domain}",
            ]
        label = f"Name Pattern Candidates - {first} {last} @{domain}".strip() \
                if (config.get("adv_email") and first) \
                else f"Likely Email Formats for @{domain}"
        self.db.save_finding(
            scan_id, self.NAME, "info",
            label,
            "Email address candidates based on name patterns and common formats",
            evidence="\n".join(formats),
            tags=["email","format","identity","recon"]
        )

    def run(self, scan_id, target, config):
        domain = _extract_domain(target)
        email  = config.get("email","")
        _log(f"[{self.LABEL}] Identity intel for {domain}")

        self._whois_lookup(scan_id, domain)

        hunter_key = config.get("hunter_key","")
        if hunter_key:
            self._hunter_io(scan_id, domain, hunter_key)
        else:
            self._pattern_format_guess(scan_id, domain, config)

        hibp_key = config.get("hibp_key","")
        if email and hibp_key:
            self._hibp_check(scan_id, email, hibp_key)

        self._mx_analysis(scan_id, domain)

    def _whois_lookup(self, scan_id, domain):
        if not HAS_WHOIS:
            return
        try:
            w = whois.whois(domain)
            def _fmt_date(d):
                if isinstance(d, list):
                    d = d[0] if d else None
                if d is None:
                    return "N/A"
                try:
                    return d.strftime("%Y-%m-%d")
                except Exception:
                    return str(d)
            def _fmt_list(v):
                if isinstance(v, list):
                    return ", ".join(str(x) for x in v if x)
                return str(v) if v else "N/A"
            evidence = (
                f"Registrar:    {w.registrar or 'N/A'}\n"
                f"Created:      {_fmt_date(w.creation_date)}\n"
                f"Expires:      {_fmt_date(w.expiration_date)}\n"
                f"Updated:      {_fmt_date(w.updated_date)}\n"
                f"Name Servers: {_fmt_list(w.name_servers)}\n"
                f"Emails:       {_fmt_list(w.emails)}\n"
                f"Org:          {w.org or 'N/A'}\n"
                f"Country:      {w.country or 'N/A'}"
            )
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"WHOIS Data for {domain}",
                "Domain registration information",
                evidence=evidence,
                tags=["whois","domain","identity","recon"],
                raw_data={"registrar": str(w.registrar),
                          "emails": str(w.emails),
                          "org": str(w.org)}
            )
            if w.emails:
                emails = [w.emails] if isinstance(w.emails, str) else w.emails
                for em in (emails or []):
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"WHOIS Contact Email: {em}",
                        "Email address found in WHOIS registration data",
                        evidence=em, tags=["email","whois","identity"]
                    )
        except Exception:
            pass

    def _email_format_guess(self, scan_id, domain):
        formats = [
            f"john.doe@{domain}",
            f"johndoe@{domain}",
            f"j.doe@{domain}",
            f"jdoe@{domain}",
            f"john@{domain}",
            f"doe@{domain}",
        ]
        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"Likely Email Formats for @{domain}",
            "Common email format patterns for this domain",
            evidence="\n".join(formats),
            tags=["email","format","identity","recon"]
        )

    def _mx_analysis(self, scan_id, domain):
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(domain, "MX")
            providers = []
            for r in answers:
                mx = str(r.exchange).lower().rstrip(".")
                if "google" in mx or "googlemail" in mx:
                    providers.append("Google Workspace (Gmail)")
                elif "outlook" in mx or "protection.outlook" in mx:
                    providers.append("Microsoft 365 (Exchange Online)")
                elif "protonmail" in mx:
                    providers.append("ProtonMail")
                elif "mimecast" in mx:
                    providers.append("Mimecast (email security gateway)")
                elif "mailgun" in mx:
                    providers.append("Mailgun")
                elif "sendgrid" in mx:
                    providers.append("SendGrid")
                elif "amazonses" in mx:
                    providers.append("Amazon SES")
                else:
                    providers.append(f"Custom MX: {mx}")
            if providers:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"Email Provider Identified",
                    "\n".join(set(providers)),
                    tags=["mx","email","infrastructure","recon"]
                )
        except Exception:
            pass

    def _hunter_io(self, scan_id, domain, key):
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=25"
        r   = self.http.get(url, scan_id, self.NAME)
        if not r or r.status_code != 200:
            return
        try:
            data   = r.json().get("data", {})
            emails = data.get("emails", [])
            if emails:
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"Hunter.io: {len(emails)} Email Addresses Found",
                    f"Email addresses associated with {domain}",
                    evidence="\n".join(
                        f"{e.get('value','')} ({e.get('first_name','')} {e.get('last_name','')} - {e.get('position','')})"
                        for e in emails),
                    tags=["email","hunter","identity"],
                    raw_data={"emails": emails}
                )
        except Exception:
            pass

    def _hibp_check(self, scan_id, email, key):
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        r   = self.http.get(url, scan_id, self.NAME,
                            headers={"hibp-api-key": key})
        if not r:
            return
        if r.status_code == 200:
            breaches = r.json()
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"⚠️ Email in {len(breaches)} Data Breach(es): {email}",
                f"Email {email} found in {len(breaches)} known data breaches",
                evidence="\n".join(b.get("Name","") + " (" + b.get("BreachDate","") + ")"
                                   for b in breaches),
                tags=["breach","hibp","email","identity"]
            )
        elif r.status_code == 404:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Email Not Found in HIBP: {email}",
                "No known data breaches for this email address.",
                tags=["breach","hibp","email"]
            )
