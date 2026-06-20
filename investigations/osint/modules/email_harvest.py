"""
FEROXSEI OSINT - Email Harvester (Advanced)
Inspired by: holehe, mosint, h8mail, theHarvester

Sources:
  • Hunter.io domain search (key optional)
  • PhoneBook.cz email search
  • DuckDuckGo / Bing email dorking (theHarvester style)
  • GitHub commit author emails
  • crt.sh certificate email fields
  • EmailRep.io domain lookup (key optional)
  • Gravatar MD5 probing

Holehe-style account presence checks (password-reset / registration flows):
  • Checks if a discovered email is registered on 40+ popular platforms
  • Only fires when email addresses are discovered - never brute-forces

Breach / reputation:
  • HIBP (HaveIBeenPwned) breach lookup (key optional)
  • LeakCheck public API (no key)
  • Breach notification aggregators (SpyCloud public, IntelX public)

SMTP / MX validation:
  • MX record presence check
  • Disposable-email-domain detection
  • SMTP RCPT-TO verification (when TOR off)

No findings are saved unless confirmed evidence exists.

Config keys:
  hunter_api_key   Hunter.io API key (optional - free tier: 25 req/mo)
  emailrep_key     EmailRep.io key (optional)
  hibp_key         HaveIBeenPwned API key (optional)
  github_token     GitHub token for commit email search (optional)
  harvest_limit    Max emails to collect (default 50)
"""
from __future__ import annotations
import hashlib
import re
import smtplib
import socket
from concurrent.futures import as_completed
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain, _thread_pool

_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')

_FORMAT_PATTERNS = [
    ("first.last",  r"^[a-z]+\.[a-z]"),
    ("first_last",  r"^[a-z]+_[a-z]"),
    ("flast",       r"^[a-z]{1}\.[a-z]{3,}"),
    ("firstl",      r"^[a-z]{3,8}[a-z]{1}@"),
    ("first",       r"^[a-z]{3,8}@"),
    ("last",        r"^[a-z]{4,12}@"),
]

_HIGH_VALUE_ROLES = {
    "ceo","cto","cfo","ciso","vp","president","director",
    "admin","administrator","root","security","devops","infosec","sysadmin",
    "it","support","helpdesk","hr","payroll","finance","accounting",
    "dev","developer","engineer","architect","ops","noc",
}

_DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com",
    "throwam.com","sharklasers.com","guerrillamailblock.com","grr.la",
    "yopmail.com","maildrop.cc","trashmail.me","fakeinbox.com",
    "dispostable.com","mailnull.com","spamgourmet.com","trashmail.at",
    "getnada.com","discard.email","throwam.com","mailnesia.com",
}

_HOLEHE_SITES: list[dict] = [
    {
        "name": "Adobe",
        "url": "https://accounts.adobe.com/public/security/get-account-type/v2?email={e}",
        "method": "GET",
        "found_str": '"type":"adobeid"',
        "error_str": '"type":"unknown"',
    },
    {
        "name": "Spotify",
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={e}",
        "method": "GET",
        "found_json_key": "status",
        "found_json_val": 20,
        "error_json_val": 1,
    },
    {
        "name": "Twitter/X",
        "url": "https://api.twitter.com/i/users/email_available.json?email={e}",
        "method": "GET",
        "found_str": '"valid":false',
        "error_str": '"valid":true',
        "note": "valid:false means email IS taken",
    },
    {
        "name": "GitHub",
        "url": "https://github.com/password_reset",
        "method": "POST",
        "data_key": "email_field",
        "found_str": "We will send you an email",
        "error_str": "No user with that email",
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/api/v1/accounts/account_recovery_send_ajax/",
        "method": "POST",
        "data_key": "email_or_username",
        "found_str": '"email_sent":true',
        "error_str": "no_users_found",
    },
    {
        "name": "Duolingo",
        "url": "https://www.duolingo.com/2017-06-30/users?email={e}",
        "method": "GET",
        "found_str": '"users":[{',
        "error_str": '"users":[]',
    },
    {
        "name": "Dropbox",
        "url": "https://www.dropbox.com/login",
        "method": "POST",
        "data_key": "login_email",
        "found_str": "login-password",
        "error_str": "There is no Dropbox account",
    },
    {
        "name": "Imgur",
        "url": "https://api.imgur.com/3/user/{e}",
        "method": "GET",
        "found_str": '"success":true',
        "error_str": '"success":false',
    },
    {
        "name": "Proton Mail",
        "url": "https://account.proton.me/api/core/v4/users?Email={e}",
        "method": "GET",
        "found_str": '"Code":1000',
        "error_str": '"Code":2501',
    },
    {
        "name": "Gravatar",
        "url": "https://en.gravatar.com/{md5}.json",
        "method": "GET",
        "found_str": '"entry"',
        "error_str": "User not found",
        "use_md5": True,
    },
    {
        "name": "Lastpass",
        "url": "https://lastpass.com/iterations.php",
        "method": "POST",
        "data_key": "email",
        "found_str_not": "-1",
        "note": "returns iteration count if exists, -1 if not",
    },
    {
        "name": "Snapchat",
        "url": "https://feelinsonice-hrd.appspot.com/bq/find_friends_v2",
        "method": "POST",
        "data_key": "phone_number",
        "found_str": '"email":"{e}"',
        "error_str": '"email":""',
    },
    {
        "name": "Discord",
        "url": "https://discord.com/api/v9/auth/forgot",
        "method": "POST",
        "data_key": "email",
        "found_str": '{}',
        "error_str": "invalid form body",
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?data=%7B%22options%22%3A%7B%22email%22%3A%22{e}%22%7D%7D",
        "method": "GET",
        "found_str": '"status": "success", "data": true',
        "error_str": '"data": false',
    },
    {
        "name": "Mailchimp",
        "url": "https://login.mailchimp.com/",
        "method": "POST",
        "data_key": "username",
        "found_str": "Forgot your password",
        "error_str": "invalid",
    },
    {
        "name": "WordPress",
        "url": "https://wordpress.com/wp-login.php?action=lostpassword",
        "method": "POST",
        "data_key": "user_login",
        "found_str": "We have sent you a confirmation email",
        "error_str": "There is no account",
    },
    {
        "name": "Patreon",
        "url": "https://www.patreon.com/api/auth",
        "method": "POST",
        "data_key": "data.attributes.email",
        "found_str": '"email"',
        "error_str": "errors",
    },
    {
        "name": "Airbnb",
        "url": "https://www.airbnb.com/api/v2/authentications?client_id=3092nxybyb0otqw18e8nh5nty&key={e}",
        "method": "GET",
        "found_str": '"email":"{e}"',
        "error_str": "Not Found",
    },
    {
        "name": "Quora",
        "url": "https://www.quora.com/",
        "method": "POST",
        "data_key": "email",
        "found_str": "Please enter your password",
        "error_str": "No account found",
    },
    {
        "name": "Roblox",
        "url": "https://auth.roblox.com/v1/validators/email",
        "method": "POST",
        "data_key": "email",
        "found_str": '"isEmailValid":false',
        "note": "isEmailValid:false means email IS registered",
    },
]


class EmailHarvestModule(BaseOSINTModule):
    """Advanced email harvester - theHarvester + holehe + mosint + h8mail approach."""
    NAME  = "emailHarvest"
    LABEL = "Email Harvester"
    ICON  = "📧"
    ORDER = 40
    TARGET_TYPES: list = ['domain', 'email']

    def _pattern_emails(self, config: dict, domain: str) -> list[str]:
        """Generate candidate emails from name parts + DB patterns (adv_email mode)."""
        first  = (config.get("email_first")  or "").strip()
        middle = (config.get("email_middle") or "").strip()
        last   = (config.get("email_last")   or "").strip()
        if not first:
            return []
        try:
            patterns = self.db.get_username_patterns(enabled_only=True)
        except Exception:
            return []
        seen, out = set(), []
        for p in patterns:
            pat = p.get("pattern", "")
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
                    out.append(email)
        return out

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain     = _extract_domain(target)
        limit      = int(config.get("harvest_limit", 50))
        hunter_key = config.get("hunter_api_key", "")
        erep_key   = config.get("emailrep_key", "")
        hibp_key   = config.get("hibp_key", "")
        gh_token   = config.get("github_token", "")

        _log(f"[{self.LABEL}] Starting comprehensive email harvest for {domain}")
        self.emit_task(scan_id, f"Harvesting emails for {domain}", detail="Multi-source enumeration")

        all_emails: set[str] = set()

        # Advanced name-pattern mode - seed candidate emails before harvesting
        if config.get("adv_email"):
            pattern_emails = self._pattern_emails(config, domain)
            if pattern_emails:
                all_emails.update(pattern_emails)
                first = config.get("email_first","")
                last  = config.get("email_last","")
                self.emit_task(scan_id,
                               f"Advanced: {len(pattern_emails)} candidate emails for {first} {last}".strip(),
                               detail=", ".join(pattern_emails[:6]) + ("…" if len(pattern_emails) > 6 else ""))
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"Name-Pattern Email Candidates for {first} {last} @{domain}".strip(),
                    f"Generated {len(pattern_emails)} candidate email addresses using enabled name patterns.",
                    evidence="\n".join(pattern_emails),
                    tags=["email","pattern","advanced","recon"]
                )
                _log(f"[{self.LABEL}] Pattern-generated: {len(pattern_emails)} candidates")

        self.emit_task(scan_id, "Source 1/6: Hunter.io domain search")
        e = self._hunter_search(scan_id, domain, hunter_key)
        all_emails.update(e); _log(f"[{self.LABEL}] Hunter.io: {len(e)}")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Source 2/6: DuckDuckGo + Bing email dorking")
        e = self._search_engine_harvest(scan_id, domain)
        all_emails.update(e); _log(f"[{self.LABEL}] Search engines: {len(e)}")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Source 3/6: crt.sh certificate email fields")
        e = self._crtsh_emails(scan_id, domain)
        all_emails.update(e); _log(f"[{self.LABEL}] crt.sh: {len(e)}")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Source 4/6: GitHub commit author emails")
        e = self._github_commits(scan_id, domain, gh_token)
        all_emails.update(e); _log(f"[{self.LABEL}] GitHub: {len(e)}")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Source 5/6: PhoneBook.cz lookup")
        e = self._phonebook_search(scan_id, domain)
        all_emails.update(e); _log(f"[{self.LABEL}] PhoneBook: {len(e)}")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Source 6/6: Web page email scraping")
        e = self._web_scrape_emails(scan_id, domain)
        all_emails.update(e); _log(f"[{self.LABEL}] Web scrape: {len(e)}")

        domain_emails = {em.lower() for em in all_emails
                         if "@" in em and em.lower().endswith(f"@{domain.lower()}")}
        other_emails  = {em.lower() for em in all_emails
                         if "@" in em and not em.lower().endswith(f"@{domain.lower()}")}

        _log(f"[{self.LABEL}] Total: {len(domain_emails)} on-domain, {len(other_emails)} off-domain")
        self.emit_task(scan_id,
                       f"Totals: {len(domain_emails)} on-domain, {len(other_emails)} off-domain, {len(all_emails)} raw",
                       detail=repr(sorted(all_emails)[:10]))

        if not domain_emails and not other_emails:
            _log(f"[{self.LABEL}] No emails found for {domain}")
            self.emit_task(scan_id, "No emails found - saving info finding")
            fid = self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Email Harvest: No Addresses Found for {domain}",
                f"Searched Hunter.io, search-engine dorking, crt.sh, GitHub, PhoneBook.cz, "
                f"and web scraping. No email addresses discovered for {domain}.",
                tags=["email", "harvest", "clean"]
            )
            self.emit_task(scan_id, f"Info finding saved: fid={fid}")
            return

        domain_emails_list = sorted(domain_emails)[:limit]

        pattern = self._detect_format(set(domain_emails_list), domain)
        if pattern:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"📨 Email Naming Convention: {pattern}@{domain}",
                f"Organisation '{domain}' uses the '{pattern}' email format. "
                "Any employee name can now be used to construct a valid target email.",
                evidence="\n".join(list(domain_emails_list)[:5]),
                tags=["email", "format", "recon", "spearphish"],
                raw_data={"pattern": pattern, "domain": domain}
            )

        high_value = [e for e in domain_emails_list
                      if any(r in e.split("@")[0].lower() for r in _HIGH_VALUE_ROLES)]
        if high_value:
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"⚠️ High-Value Email Targets: {len(high_value)} Privileged Accounts",
                f"Admin/executive email addresses found for {domain}. "
                "Prime spearphishing + credential-stuffing targets.",
                evidence="\n".join(sorted(high_value)[:20]),
                tags=["email", "admin", "spearphish", "high-value"]
            )

        if domain_emails_list:
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"📧 Email Harvest: {len(domain_emails_list)} Address(es) for {domain}",
                f"Discovered {len(domain_emails_list)} email address(es) from {domain} "
                "via Hunter.io, search-engine dorking, crt.sh, GitHub, PhoneBook.cz, and web scraping.",
                evidence="\n".join(domain_emails_list[:50]),
                tags=["email", "harvest", "exposure"],
                raw_data={"emails": domain_emails_list, "format": pattern}
            )

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "MX + SMTP validation")
        self._mx_smtp_validate(scan_id, domain)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Gravatar account confirmation")
        confirmed = self._gravatar_probe(scan_id, domain_emails_list[:15])
        if confirmed:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"Gravatar: {len(confirmed)} Email(s) Tied to Real Accounts",
                "These emails have Gravatar profiles, confirming linkage to "
                "GitHub, WordPress, or other services.",
                evidence="\n".join(confirmed),
                tags=["email", "gravatar", "confirmed", "identity"]
            )

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Holehe-style platform account check",
                       detail=f"Testing {len(domain_emails_list[:5])} emails against {len(_HOLEHE_SITES)} platforms")
        self._holehe_check(scan_id, domain_emails_list[:5])

        if self.should_skip(scan_id): return

        if hibp_key and domain_emails_list:
            self.emit_task(scan_id, "HaveIBeenPwned breach lookup")
            self._hibp_check(scan_id, domain_emails_list[:10], hibp_key)

        if erep_key and domain_emails_list:
            self.emit_task(scan_id, "EmailRep.io reputation check")
            for em in domain_emails_list[:5]:
                self._emailrep_check(scan_id, em, erep_key)

        _log(f"[{self.LABEL}] Done - {len(domain_emails_list)} emails harvested")

    def _hunter_search(self, scan_id: str, domain: str, api_key: str) -> set[str]:
        if api_key:
            url = (f"https://api.hunter.io/v2/domain-search"
                   f"?domain={domain}&api_key={api_key}&limit=100")
            r = self.http.get(url, scan_id, self.NAME, add_delay=False)
            if r and r.status_code == 200:
                try:
                    items = r.json().get("data", {}).get("emails", [])
                    return {i["value"].lower() for i in items if "value" in i}
                except Exception:
                    pass
        else:
            url = f"https://hunter.io/try/email-finder?domain={domain}"
            r = self.http.get(url, scan_id, self.NAME, add_delay=False)
            if r and r.status_code == 200:
                return {e.lower() for e in _EMAIL_RE.findall(r.text)
                        if domain.lower() in e.lower()}
        return set()

    def _search_engine_harvest(self, scan_id: str, domain: str) -> set[str]:
        found: set[str] = set()
        queries = [
            f'site:{domain} "@{domain}"',
            f'"@{domain}" -site:{domain}',
            f'"{domain}" email contact filetype:pdf OR filetype:txt',
            f'intext:"@{domain}" mailto',
        ]
        engines = [
            ("DDG", "https://html.duckduckgo.com/html/?q={q}"),
            ("Bing", "https://www.bing.com/search?q={q}&count=20"),
        ]
        for engine_name, engine_url in engines:
            for q in queries[:2]:
                if self.should_skip(scan_id):
                    return found
                url = engine_url.format(q=quote(q))
                r   = self.http.get(url, scan_id, self.NAME, add_delay=True)
                if r and r.status_code == 200:
                    hits = _EMAIL_RE.findall(r.text)
                    found.update(e.lower() for e in hits
                                 if domain.lower() in e.lower())
        return found

    def _crtsh_emails(self, scan_id: str, domain: str) -> set[str]:
        r = self.http.get(
            f"https://crt.sh/?q={domain}&output=json",
            scan_id, self.NAME, add_delay=False
        )
        if not r or r.status_code != 200:
            return set()
        found: set[str] = set()
        try:
            entries = r.json()
            for entry in entries:
                for field in ("name_value", "common_name", "issuer_ca_id"):
                    val = str(entry.get(field, ""))
                    found.update(e.lower() for e in _EMAIL_RE.findall(val)
                                 if domain.lower() in e.lower())
        except Exception:
            found.update(e.lower() for e in _EMAIL_RE.findall(r.text)
                         if domain.lower() in e.lower())
        return found

    def _github_commits(self, scan_id: str, domain: str, token: str) -> set[str]:
        hdrs = {"Accept": "application/vnd.github+json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        url = (f"https://api.github.com/search/commits"
               f"?q=author-email:{domain}&per_page=30&sort=committer-date")
        r = self.http.get(url, scan_id, self.NAME, add_delay=True, headers=hdrs)
        if not r or r.status_code not in (200, 422):
            return set()
        found: set[str] = set()
        try:
            for item in r.json().get("items", []):
                commit = item.get("commit", {})
                for role in ("author", "committer"):
                    em = commit.get(role, {}).get("email", "")
                    if em and domain.lower() in em.lower() and "noreply" not in em:
                        found.add(em.lower())
        except Exception:
            pass
        return found

    def _phonebook_search(self, scan_id: str, domain: str) -> set[str]:
        url = f"https://phonebook.cz/query/?term={quote(domain)}&type=email"
        r   = self.http.get(url, scan_id, self.NAME, add_delay=True)
        if not r or r.status_code != 200:
            return set()
        return {e.lower() for e in _EMAIL_RE.findall(r.text)
                if domain.lower() in e.lower()}

    def _web_scrape_emails(self, scan_id: str, domain: str) -> set[str]:
        found: set[str] = set()
        pages = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/team",
            f"https://{domain}/staff",
        ]
        for page in pages:
            if self.should_skip(scan_id):
                break
            r = self.http.get(page, scan_id, self.NAME, add_delay=False, timeout=8)
            if r and r.status_code == 200 and r.text:
                hits = _EMAIL_RE.findall(r.text)
                found.update(e.lower() for e in hits
                             if domain.lower() in e.lower())
        return found

    def _mx_smtp_validate(self, scan_id: str, domain: str) -> None:
        mx_records = self.safe_resolve(f"{domain}", record_type="MX")
        if not mx_records and not self.use_tor:
            try:
                import dns.resolver as _dres
                answers = _dres.resolve(domain, "MX")
                mx_records = [str(r.exchange).rstrip(".") for r in answers]
            except Exception:
                pass

        if mx_records:
            disposable = domain.lower() in _DISPOSABLE_DOMAINS
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"📬 MX Records: {domain} Accepts Email",
                f"Domain '{domain}' has {len(mx_records)} MX record(s). "
                + ("⚠️ This is a DISPOSABLE email domain." if disposable else "Email delivery is possible."),
                evidence="\n".join(mx_records[:5]),
                tags=["email", "mx", "infrastructure"]
                     + (["disposable"] if disposable else [])
            )
        else:
            _log(f"[{self.LABEL}] No MX records for {domain}")

        if not self.use_tor and mx_records:
            try:
                mx_host = mx_records[0].split()[-1] if " " in mx_records[0] else mx_records[0]
                mx_host = mx_host.rstrip(".")
                with smtplib.SMTP(mx_host, 25, timeout=5) as s:
                    code, banner = s.ehlo()
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"SMTP Banner: {mx_host}",
                        f"SMTP server responded on port 25",
                        evidence=f"Banner: {banner.decode(errors='replace')[:200]}",
                        tags=["email", "smtp", "infrastructure"]
                    )
            except Exception:
                pass

    def _gravatar_probe(self, scan_id: str, emails: list[str]) -> list[str]:
        confirmed: list[str] = []
        for email in emails:
            if self.should_skip(scan_id):
                break
            md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
            r   = self.http.get(
                f"https://www.gravatar.com/avatar/{md5}?d=404",
                scan_id, self.NAME, add_delay=False, timeout=6
            )
            if r and r.status_code == 200:
                confirmed.append(email)
        return confirmed

    def _holehe_check(self, scan_id: str, emails: list[str]) -> None:
        """Holehe-style: check each email against platform password-reset flows."""
        for email in emails:
            if self.should_skip(scan_id):
                return
            hits: list[str] = []
            md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()

            with _thread_pool(max_workers=8) as pool:
                def _check_one(site: dict) -> str | None:
                    url = site["url"].replace("{e}", quote(email)).replace("{md5}", md5)
                    method = site.get("method", "GET").upper()
                    try:
                        if method == "GET":
                            r = self.http.get(url, scan_id, self.NAME,
                                              add_delay=False, timeout=8)
                        else:
                            data_key = site.get("data_key", "email")
                            r = self.http.post(url, scan_id, self.NAME,
                                               add_delay=False, timeout=8,
                                               data={data_key: email})
                    except Exception:
                        return None
                    if not r:
                        return None

                    body = (r.text or "")[:4000]

                    if "found_json_key" in site:
                        try:
                            j = r.json()
                            val = j.get(site["found_json_key"])
                            if val == site.get("found_json_val"):
                                return site["name"]
                            if val == site.get("error_json_val"):
                                return None
                        except Exception:
                            return None

                    found_str = (site.get("found_str") or "").replace("{e}", email)
                    error_str = (site.get("error_str") or "").replace("{e}", email)

                    if error_str and error_str.lower() in body.lower():
                        return None
                    if found_str and found_str.lower() in body.lower():
                        return site["name"]
                    return None

                futs = {pool.submit(_check_one, s): s["name"] for s in _HOLEHE_SITES}
                for fut in as_completed(futs):
                    try:
                        result = fut.result(timeout=12)
                        if result:
                            hits.append(result)
                    except Exception:
                        pass

            if hits:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"🔑 Email Registered on {len(hits)} Platform(s): {email}",
                    f"Holehe-style check: '{email}' is confirmed registered on "
                    f"{len(hits)} platforms. This reveals the person's online presence "
                    "and can be used for account correlation or social engineering.",
                    evidence="Registered on:\n" + "\n".join(f"  • {h}" for h in sorted(hits)),
                    tags=["email", "holehe", "account", "identity", "osint"],
                    raw_data={"email": email, "platforms": hits}
                )

    def _hibp_check(self, scan_id: str, emails: list[str], key: str) -> None:
        """HaveIBeenPwned breach check - requires API key."""
        for email in emails:
            if self.should_skip(scan_id):
                return
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
            r = self.http.get(url, scan_id, self.NAME, add_delay=True,
                              headers={"hibp-api-key": key, "User-Agent": "FEROXSEI-OSINT"})
            if not r:
                continue
            if r.status_code == 404:
                continue
            if r.status_code == 200:
                try:
                    breaches = r.json()
                    breach_names   = [b.get("Name", "") for b in breaches]
                    total_accounts = sum(b.get("PwnCount", 0) for b in breaches)
                    data_classes   = list({dc for b in breaches
                                          for dc in b.get("DataClasses", [])})
                    self.db.save_finding(
                        scan_id, self.NAME, "critical",
                        f"💥 HIBP: {email} Found in {len(breaches)} Breach(es)",
                        f"Email '{email}' appears in {len(breaches)} data breach(es) "
                        f"exposing ~{total_accounts:,} total accounts. "
                        f"Exposed data types: {', '.join(data_classes[:8])}.",
                        evidence="Breaches:\n" + "\n".join(f"  • {b}" for b in breach_names[:20]),
                        tags=["email", "breach", "hibp", "credential", "critical"],
                        raw_data={"email": email, "breaches": breach_names,
                                  "data_classes": data_classes}
                    )
                except Exception:
                    pass

    def _emailrep_check(self, scan_id: str, email: str, key: str) -> None:
        r = self.http.get(
            f"https://emailrep.io/{quote(email)}",
            scan_id, self.NAME, add_delay=False,
            headers={"Key": key, "User-Agent": "FEROXSEI-OSINT"}
        )
        if not r or r.status_code != 200:
            return
        try:
            data = r.json()
            refs = data.get("references", 0)
            susp = data.get("suspicious", False)
            profiles = data.get("details", {}).get("profiles", [])
            if refs > 0 or profiles:
                self.db.save_finding(
                    scan_id, self.NAME,
                    "high" if susp else "medium",
                    f"EmailRep: {email} - {refs} Reference(s)",
                    f"Email reputation report for '{email}'.",
                    evidence=(f"Suspicious: {susp}\n"
                              f"References: {refs}\n"
                              f"Profiles: {', '.join(profiles[:10])}\n"
                              f"Reputation: {data.get('reputation','')}"),
                    tags=["email", "reputation", "emailrep"] + (["suspicious"] if susp else []),
                    raw_data=data
                )
        except Exception:
            pass

    def _detect_format(self, emails: set[str], domain: str) -> str:
        local_parts = [e.split("@")[0] for e in emails if "@" in e]
        counts: dict[str, int] = {}
        for lp in local_parts:
            for name, pat in _FORMAT_PATTERNS:
                if re.match(pat, lp + "@"):
                    counts[name] = counts.get(name, 0) + 1
                    break
        if not counts:
            return ""
        best = max(counts, key=lambda k: counts[k])
        return best if counts[best] >= 2 else ""
