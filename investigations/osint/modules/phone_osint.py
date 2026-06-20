"""
FEROXSEI OSINT - Phone Number Intelligence
Inspired by: phoneinfoga (sundowndev)

Passive OSINT only - all sources are public databases and search engines.

What it does:
  • Parse and validate phone number format (E.164, international, local)
  • Country / carrier / line-type identification
  • Number reputation: spam, fraud, scam databases
  • Search engine dorking (Google / DDG / Bing) for the number
  • Social media + public registry presence
  • CNAM (caller ID name) lookup via public aggregators
  • Leak / breach database mentions
  • Reverse phone lookup sites

How to trigger:
  • Target = phone number e.g. +12025550123, 0044…, (202) 555-0123
  • Or: config["phone"] = "<number>"

No findings saved unless confirmed public evidence exists.

Config keys:
  numverify_key    numverify.com API key (optional - carrier/line-type)
  phone            explicit phone number override
"""
from __future__ import annotations
import re
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _is_keyword_target, _extract_domain

_PHONE_RE  = re.compile(r'[\+\d][\d\s\-\(\)\.]{6,20}[\d]')
_E164_RE   = re.compile(r'^\+?[1-9]\d{6,14}$')

_COUNTRY_CODES: dict[str, tuple[str, str]] = {
    "1": ("US/Canada", "NANP"),
    "7": ("Russia / Kazakhstan", ""),
    "20": ("Egypt", ""),
    "27": ("South Africa", ""),
    "30": ("Greece", ""),
    "31": ("Netherlands", ""),
    "32": ("Belgium", ""),
    "33": ("France", ""),
    "34": ("Spain", ""),
    "36": ("Hungary", ""),
    "39": ("Italy", ""),
    "40": ("Romania", ""),
    "41": ("Switzerland", ""),
    "43": ("Austria", ""),
    "44": ("United Kingdom", ""),
    "45": ("Denmark", ""),
    "46": ("Sweden", ""),
    "47": ("Norway", ""),
    "48": ("Poland", ""),
    "49": ("Germany", ""),
    "51": ("Peru", ""),
    "52": ("Mexico", ""),
    "53": ("Cuba", ""),
    "54": ("Argentina", ""),
    "55": ("Brazil", ""),
    "56": ("Chile", ""),
    "57": ("Colombia", ""),
    "58": ("Venezuela", ""),
    "60": ("Malaysia", ""),
    "61": ("Australia", ""),
    "62": ("Indonesia", ""),
    "63": ("Philippines", ""),
    "64": ("New Zealand", ""),
    "65": ("Singapore", ""),
    "66": ("Thailand", ""),
    "81": ("Japan", ""),
    "82": ("South Korea", ""),
    "84": ("Vietnam", ""),
    "86": ("China", ""),
    "90": ("Turkey", ""),
    "91": ("India", ""),
    "92": ("Pakistan", ""),
    "93": ("Afghanistan", ""),
    "94": ("Sri Lanka", ""),
    "95": ("Myanmar", ""),
    "98": ("Iran", ""),
    "212": ("Morocco", ""),
    "213": ("Algeria", ""),
    "216": ("Tunisia", ""),
    "218": ("Libya", ""),
    "220": ("Gambia", ""),
    "221": ("Senegal", ""),
    "234": ("Nigeria", ""),
    "254": ("Kenya", ""),
    "971": ("UAE", ""),
    "972": ("Israel", ""),
    "973": ("Bahrain", ""),
    "974": ("Qatar", ""),
    "966": ("Saudi Arabia", ""),
    "880": ("Bangladesh", ""),
    "886": ("Taiwan", ""),
}

_SPAM_SOURCES = [
    ("ShouldIAnswer", "https://www.shouldianswer.com/phone-number/{local}"),
    ("SpamCalls",     "https://spamcalls.net/en/search/{local}"),
    ("800notes",      "https://800notes.com/Phone.aspx/{local}"),
    ("WhoCallsMe",    "https://www.whocalledme.com/PhoneNumber/{local}"),
]

_SPAM_INDICATORS = [
    "spam", "scam", "fraud", "telemarketer", "robocall", "phishing",
    "dangerous", "reported", "nuisance", "harassing",
]


def _normalise(raw: str) -> str | None:
    """Strip formatting and return digits-only string (with leading +)."""
    cleaned = re.sub(r'[^\d+]', '', raw.strip())
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    digits_only = cleaned.replace("+", "")
    if 7 <= len(digits_only) <= 15:
        return cleaned
    return None


def _detect_country(e164: str) -> tuple[str, str]:
    """Best-effort country detection from E.164 prefix."""
    digits = e164.lstrip("+")
    for prefix_len in (3, 2, 1):
        prefix = digits[:prefix_len]
        if prefix in _COUNTRY_CODES:
            return _COUNTRY_CODES[prefix]
    return ("Unknown", "")


def _local_formats(e164: str) -> list[str]:
    """Return several common string representations."""
    digits = e164.lstrip("+")
    variants = [
        e164,
        digits,
        "00" + digits,
        f"{digits[:3]}-{digits[3:6]}-{digits[6:]}",
        f"({digits[:3]}) {digits[3:6]}-{digits[6:]}",
        f"{digits[:3]} {digits[3:6]} {digits[6:]}",
    ]
    return [v for v in variants if v]


class PhoneOSINTModule(BaseOSINTModule):
    """Passive phone number OSINT - phoneinfoga-style multi-source intelligence."""
    NAME  = "phoneOsint"
    LABEL = "Phone OSINT"
    ICON  = "📞"
    ORDER = 43
    TARGET_TYPES: list = ['phone']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        raw_phone = config.get("phone", "") or target.strip()

        if not raw_phone:
            _log(f"[{self.LABEL}] No phone number in target - skipping")
            return

        if "@" in raw_phone or ("." in raw_phone and not re.search(r'[\d\+]', raw_phone[:3])):
            raw_phone = config.get("phone", "")
            if not raw_phone:
                _log(f"[{self.LABEL}] Target is domain/email, no phone override - skipping")
                return

        e164 = _normalise(raw_phone)
        if not e164:
            _log(f"[{self.LABEL}] Could not parse phone number: {raw_phone}")
            return

        country, region = _detect_country(e164)
        local = e164.lstrip("+")
        all_formats = _local_formats(e164)
        nv_key = config.get("numverify_key", "")

        _log(f"[{self.LABEL}] Phone OSINT for {e164} ({country})")
        self.emit_task(scan_id, f"Phone OSINT: {e164}", detail=f"Country: {country}")

        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"📞 Phone Number Identified: {e164}",
            f"Number parsed and identified for OSINT investigation.",
            evidence=(f"E.164:   {e164}\n"
                      f"Local:   {local}\n"
                      f"Country: {country}\n"
                      f"Region:  {region}"),
            tags=["phone", "identity", "recon"],
            raw_data={"e164": e164, "local": local, "country": country, "formats": all_formats}
        )

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Carrier / line-type lookup")
        self._carrier_lookup(scan_id, e164, local, nv_key)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Spam / reputation database checks",
                       detail=f"Checking {len(_SPAM_SOURCES)} databases")
        self._spam_check(scan_id, e164, local, all_formats)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Search engine dorking (phoneinfoga style)",
                       detail="DuckDuckGo + Bing multi-query")
        self._search_engine_dork(scan_id, e164, all_formats)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Social media + public registry presence")
        self._social_presence(scan_id, e164, local, all_formats)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Reverse phone lookup aggregators")
        self._reverse_lookup(scan_id, e164, local)

        _log(f"[{self.LABEL}] Phone OSINT complete for {e164}")

    def _carrier_lookup(self, scan_id: str, e164: str, local: str, nv_key: str) -> None:
        if nv_key:
            r = self.http.get(
                f"https://apilayer.net/api/validate?access_key={nv_key}&number={quote(e164)}&country_code=&format=1",
                scan_id, self.NAME, add_delay=False, timeout=8)
            if r and r.status_code == 200:
                try:
                    d = r.json()
                    if d.get("valid"):
                        self.db.save_finding(
                            scan_id, self.NAME, "info",
                            f"📡 Carrier: {d.get('carrier','?')} ({d.get('line_type','?')})",
                            f"Carrier and line type confirmed for {e164}.",
                            evidence=(f"Valid: {d.get('valid')}\n"
                                      f"Carrier: {d.get('carrier','?')}\n"
                                      f"Line type: {d.get('line_type','?')}\n"
                                      f"Country: {d.get('country_name','?')}\n"
                                      f"Location: {d.get('location','?')}\n"
                                      f"International: {d.get('international_format','')}\n"
                                      f"Local: {d.get('local_format','')}"),
                            tags=["phone", "carrier", "line-type"],
                            raw_data=d
                        )
                    return
                except Exception:
                    pass

        for api_url, label in [
            (f"https://phonevalidation.abstractapi.com/v1/?api_key=&phone={quote(e164)}", "AbstractAPI"),
            (f"https://www.hlrlookup.com/api/?number={quote(e164)}", "HLR Lookup"),
        ]:
            r = self.http.get(api_url, scan_id, self.NAME, add_delay=False, timeout=6)
            if r and r.status_code == 200:
                try:
                    d = r.json()
                    carrier = (d.get("carrier") or d.get("operator") or
                               d.get("original_carrier") or {})
                    if isinstance(carrier, dict):
                        carrier = carrier.get("name", "")
                    if carrier:
                        self.db.save_finding(
                            scan_id, self.NAME, "info",
                            f"📡 Carrier Identified: {carrier}",
                            f"Carrier information for {e164}.",
                            evidence=f"Carrier: {carrier}\nSource: {label}",
                            tags=["phone", "carrier"]
                        )
                        return
                except Exception:
                    pass

    def _spam_check(self, scan_id: str, e164: str, local: str, all_formats: list[str]) -> None:
        spam_reports: list[dict] = []

        for source_name, url_tmpl in _SPAM_SOURCES:
            if self.should_skip(scan_id):
                break
            url = url_tmpl.format(e164=quote(e164), local=local)
            r   = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=8)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")[:8000].lower()

            spam_count = sum(1 for ind in _SPAM_INDICATORS if ind in body)
            if spam_count >= 2:
                report_count_m = re.search(r'(\d+)\s+(?:report|complaint|comment)', body)
                report_count = report_count_m.group(1) if report_count_m else "multiple"
                spam_reports.append({
                    "source": source_name, "url": url,
                    "reports": report_count, "indicators": spam_count
                })

        if spam_reports:
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"⚠️ Spam/Scam Reports: {e164} Flagged on {len(spam_reports)} Source(s)",
                f"Phone number {e164} has been reported as spam/scam/fraud.",
                evidence="\n".join(
                    f"  {r['source']}: {r['reports']} report(s) [{r['url']}]"
                    for r in spam_reports
                ),
                tags=["phone", "spam", "scam", "fraud", "reputation"],
                raw_data={"e164": e164, "reports": spam_reports}
            )

    def _search_engine_dork(self, scan_id: str, e164: str, all_formats: list[str]) -> None:
        local = e164.lstrip("+")
        queries = [
            f'"{e164}"',
            f'"{local}"',
            f'"{all_formats[3]}"' if len(all_formats) > 3 else f'"{local}"',
            f'"{e164}" site:pastebin.com OR site:ghostbin.com OR site:hastebin.com',
            f'"{e164}" email OR linkedin OR facebook',
            f'"{e164}" password OR breach OR leaked',
        ]
        engines = [
            ("DDG",  "https://html.duckduckgo.com/html/?q={q}"),
            ("Bing", "https://www.bing.com/search?q={q}&count=20"),
        ]

        all_snippets: list[str] = []
        found_associations: set[str] = set()

        for engine_name, tmpl in engines:
            for q in queries[:3]:
                if self.should_skip(scan_id):
                    return
                r = self.http.get(tmpl.format(q=quote(q)),
                                  scan_id, self.NAME, add_delay=True, timeout=10)
                if not r or r.status_code != 200:
                    continue
                body = r.text or ""

                email_hits = re.findall(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b', body)
                found_associations.update(email_hits)

                name_hits = re.findall(r'(?:Name|Contact|Owner|Person)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)', body)
                found_associations.update(name_hits[:3])

                snippet_m = re.findall(r'<a[^>]+>([^<]{30,200})</a>', body)
                all_snippets.extend(snippet_m[:5])

        if found_associations:
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"🔍 Search Engine: {e164} Linked to {len(found_associations)} Identity Item(s)",
                f"Search engine results associate {e164} with identifiable information.",
                evidence="Associated identifiers:\n" + "\n".join(f"  • {a}" for a in list(found_associations)[:20]),
                tags=["phone", "dork", "identity", "association"],
                raw_data={"e164": e164, "associations": list(found_associations)[:30]}
            )
        elif all_snippets:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"🔍 Search Engine: {e164} Appears in {len(all_snippets)} Result(s)",
                f"Phone number appears in public search results.",
                evidence="\n".join(all_snippets[:10]),
                tags=["phone", "dork", "public-exposure"]
            )

    def _social_presence(self, scan_id: str, e164: str, local: str, all_formats: list[str]) -> None:
        checks = [
            ("Facebook",  f"https://www.facebook.com/search/top/?q={quote(e164)}",
             "timeline_list_unit"),
            ("Truecaller", f"https://www.truecaller.com/search/in/{local}",
             "result"),
            ("WhatsApp",  f"https://api.whatsapp.com/send?phone={quote(local.lstrip('+'))}",
             "open.whatsapp.com"),
            ("Telegram",  f"https://t.me/+{local.lstrip('+')}",
             "tgme_page_title"),
            ("Viber",     f"https://chats.viber.com/+{local.lstrip('+')}",
             "viber.com"),
        ]
        for platform, url, indicator in checks:
            if self.should_skip(scan_id):
                return
            r = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=8)
            if r and r.status_code == 200 and indicator in (r.text or "").lower():
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"📱 {platform}: {e164} Has Presence",
                    f"Phone number {e164} appears to be registered on {platform}.",
                    url=url,
                    evidence=f"Platform: {platform}\nIndicator matched: '{indicator}'",
                    tags=["phone", "social", platform.lower(), "presence"]
                )

    def _reverse_lookup(self, scan_id: str, e164: str, local: str) -> None:
        sources = [
            ("NumLookup", f"https://www.numlookup.com/{e164}",
             '"carrier"', '"carrier":""'),
            ("CallerIDTest", f"https://www.calleridtest.com/lookup/{local}",
             "name", "no record"),
            ("OpenCNAM",  f"https://api.opencnam.com/v3/phone/{quote(e164)}?format=json",
             "name", "unknown"),
        ]
        for source_name, url, found_str, miss_str in sources:
            if self.should_skip(scan_id):
                return
            r = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=8)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")[:3000]
            if miss_str.lower() in body.lower():
                continue
            if found_str.lower() in body.lower():
                name_m = re.search(r'"name"\s*:\s*"([^"]{2,60})"', body)
                cname  = name_m.group(1) if name_m else "Found"
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"☎️ Reverse Lookup: {e164} → {cname}",
                    f"Caller ID / CNAM data found for {e164}.",
                    url=url,
                    evidence=(f"Source: {source_name}\n"
                              f"CNAM / Name: {cname}\n"
                              f"Number: {e164}"),
                    tags=["phone", "reverse-lookup", "cnam", "identity"]
                )
                break
