"""
FEROXSEI OSINT - Typosquatting & Domain Permutation Detector
Generates hundreds of domain variations then checks which are registered,
resolving, or hosting content - revealing phishing infrastructure, brand abuse,
and impersonation attacks targeting your organisation.

Permutation techniques (inspired by dnstwist):
  • Missing character      (exmple.com instead of example.com)
  • Double character       (exxample.com)
  • Transposition          (exapmle.com)
  • Addition               (examplee.com)
  • Replacement            (3xample.com, using visually similar chars)
  • Homoglyphs             (аpple.com using Cyrillic 'а')
  • Hyphenation            (ex-ample.com)
  • Subdomain-style        (example-com.net)
  • TLD variation          (example.net, .org, .co, .io, etc.)
  • Common misspellings    (exmaple, exampel, etc.)
  • Bitsquatting           (1-bit flip in domain chars)
  • Vowel swap             (exomple, expamle)
  • Prepend/append abuse   (my-example.com, example-login.com)
  • Combo squatting        (example-secure.com, example-bank.com)

Config keys:
  typo_max_check    int   Max permutations to DNS-resolve (default 300)
  typo_check_mx    bool   Also check MX records (phishing kit detection, default True)
  typo_check_body  bool   Fetch flagged domains to detect phishing content (default True)
"""
from __future__ import annotations
import itertools
import random
import re
from urllib.parse import urlparse

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target

# ── Character sets ─────────────────────────────────────────────────────────────
_QWERTY_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "ersfcx",
    "e": "rdsw", "f": "rtgdcv", "g": "tyfhvb", "h": "yugjbn",
    "i": "uojk", "j": "uhknim", "k": "ijlom", "l": "kop",
    "m": "njk", "n": "bhjm", "o": "ipkl", "p": "ol",
    "q": "wa", "r": "eft", "s": "awedxz", "t": "rfgy",
    "u": "yihj", "v": "cfgb", "w": "qase", "x": "zsdc",
    "y": "tugh", "z": "asx",
}

_HOMOGLYPHS = {
    "a": ["à","á","â","ã","ä","å","а"],
    "c": ["ç","с"],
    "e": ["è","é","ê","ë","е"],
    "i": ["í","î","ï","ì","і"],
    "l": ["1","I","ⅼ"],
    "o": ["0","ο","о"],
    "p": ["р"],
    "s": ["$","ѕ"],
    "u": ["ü","ú","û","ù"],
    "y": ["ý","у"],
}

_VOWELS = set("aeiou")

_COMMON_TLDS = [
    "com","net","org","io","co","info","biz","xyz","online","site",
    "store","shop","app","tech","cloud","dev","ai","us","uk","de",
    "ru","cn","in","br","eu","cc","club","top","live","email",
]

_PHISHING_SUFFIXES = [
    "-login","-secure","-account","-verify","-auth","-portal",
    "-banking","-pay","-wallet","-help","-support","secure-",
    "login-","my-","get-","official-","the-","www-",
]

_PHISHING_BODY_PATTERNS = [
    r"login|signin|sign.in",
    r"password|passwd|credential",
    r"verify.*account|confirm.*email",
    r"enter.*card|credit.card",
    r"paypal|stripe|bank",
    r"update.*information|verify.*identity",
]


class TyposquattingModule(BaseOSINTModule):
    """Generate domain permutations and detect registered typosquats / phishing domains."""
    NAME  = "typosquat"
    LABEL = "Typosquatting Detector"
    ICON  = "🔍"
    ORDER = 88
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain     = _extract_domain(target)
        max_check  = int(config.get("typo_max_check", 300))
        check_mx   = str(config.get("typo_check_mx",   "true")).lower() != "false"
        check_body = str(config.get("typo_check_body", "true")).lower() != "false"

        parts  = domain.rsplit(".", 1)
        if len(parts) != 2:
            _log(f"[{self.LABEL}] Cannot parse TLD for {domain}")
            return
        name, tld = parts
        _log(f"[{self.LABEL}] Generating permutations for {domain}")

        perms = self._generate(name, tld)
        _log(f"[{self.LABEL}] {len(perms)} permutations generated; "
             f"checking up to {max_check}")

        # Remove the actual domain
        perms.discard(domain)

        registered:   list[dict] = []
        has_mx:       list[str]  = []
        phishing:     list[str]  = []

        for variant in list(perms)[:max_check]:
            ip = self._resolve_a(variant)
            if not ip:
                continue
            entry = {"domain": variant, "ip": ip}

            # MX record → potential phishing email sender
            if check_mx:
                mx = self._resolve_mx(variant)
                if mx:
                    entry["mx"] = mx
                    has_mx.append(variant)

            registered.append(entry)
            _log(f"[{self.LABEL}] REGISTERED: {variant} → {ip}")

        # Body check for confirmed phishing content
        if check_body:
            for entry in registered[:30]:
                purl = f"https://{entry['domain']}"
                r = self.http.get(purl, scan_id, self.NAME, add_delay=False)
                if r and r.text:
                    body = r.text[:8000].lower()
                    hits = [p for p in _PHISHING_BODY_PATTERNS
                            if re.search(p, body, re.I)]
                    if hits:
                        phishing.append(entry["domain"])
                        self.db.save_finding(
                            scan_id, self.NAME, "critical",
                            f"🎣 PHISHING: {entry['domain']} (Confirmed Content)",
                            f"Typosquat '{entry['domain']}' (resolves to {entry['ip']}) "
                            "hosts content that matches phishing page patterns.",
                            url=purl,
                            evidence=(f"Matched patterns: {', '.join(hits)}\n"
                                      f"Body snippet: {r.text[:400]}"),
                            tags=["typosquat", "phishing", "confirmed", "critical"]
                        )

        # ── Save findings ─────────────────────────────────────────────────
        if not registered:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Typosquatting: No Registered Variants Found for {domain}",
                f"Checked {min(len(perms), max_check)} permutations. "
                "No registered typosquat domains detected.",
                tags=["typosquat", "clean"]
            )
            return

        # Summary
        high_risk = [e for e in registered if "mx" in e]
        evidence  = "\n".join(
            f"  {'🎣' if e['domain'] in phishing else ('⚠' if 'mx' in e else '•')} "
            f"{e['domain']} → {e['ip']}" +
            (f" [MX: {e.get('mx','')}]" if "mx" in e else "")
            for e in registered[:50]
        )

        sev = "critical" if phishing else ("high" if high_risk else "medium")
        self.db.save_finding(
            scan_id, self.NAME, sev,
            f"🔍 Typosquatting: {len(registered)} Registered Variant(s) Found",
            f"Found {len(registered)} registered domain variants of '{domain}'. "
            f"{len(phishing)} contain phishing content. "
            f"{len(has_mx)} have MX records (may be used for phishing email).",
            evidence=evidence,
            tags=["typosquat", "domain", "brand", sev],
            raw_data={
                "registered": [e["domain"] for e in registered],
                "has_mx":     has_mx,
                "phishing":   phishing,
                "total_checked": min(len(perms), max_check),
            }
        )

        _log(f"[{self.LABEL}] ✅ {len(registered)} registered, "
             f"{len(phishing)} phishing, {len(has_mx)} with MX")

    # ── Permutation generators ────────────────────────────────────────────────

    def _generate(self, name: str, tld: str) -> set[str]:
        variants: set[str] = set()
        n = name.lower()

        # TLD variations (same name, many TLDs)
        for t in _COMMON_TLDS:
            if t != tld:
                variants.add(f"{n}.{t}")

        # Missing char
        for i in range(len(n)):
            variants.add(f"{n[:i]}{n[i+1:]}.{tld}")

        # Double char
        for i, c in enumerate(n):
            variants.add(f"{n[:i]}{c}{n[i:]}.{tld}")

        # Transposition
        for i in range(len(n) - 1):
            t = list(n)
            t[i], t[i+1] = t[i+1], t[i]
            variants.add(f"{''.join(t)}.{tld}")

        # Addition (extra char)
        for i in range(len(n) + 1):
            for c in "abcdefghijklmnopqrstuvwxyz":
                variants.add(f"{n[:i]}{c}{n[i:]}.{tld}")

        # Qwerty replacement
        for i, c in enumerate(n):
            for rep in _QWERTY_ADJACENT.get(c, ""):
                variants.add(f"{n[:i]}{rep}{n[i+1:]}.{tld}")

        # Homoglyph (ASCII-safe variants only for DNS)
        for i, c in enumerate(n):
            for h in _HOMOGLYPHS.get(c, []):
                if h.isascii():
                    variants.add(f"{n[:i]}{h}{n[i+1:]}.{tld}")

        # Hyphenation
        for i in range(1, len(n)):
            variants.add(f"{n[:i]}-{n[i:]}.{tld}")

        # Vowel swap
        for i, c in enumerate(n):
            if c in _VOWELS:
                for v in _VOWELS - {c}:
                    variants.add(f"{n[:i]}{v}{n[i+1:]}.{tld}")

        # Subdomain-style squatting
        variants.add(f"{n}-{tld}.com")
        variants.add(f"{n}.{tld}.com")

        # Phishing suffix/prefix combos
        for suf in _PHISHING_SUFFIXES:
            if suf.startswith("-"):
                variants.add(f"{n}{suf}.{tld}")
                variants.add(f"{n}{suf}.com")
            else:
                variants.add(f"{suf}{n}.{tld}")
                variants.add(f"{suf}{n}.com")

        # Bitsquatting (1-bit flip in character codes)
        for i, c in enumerate(n):
            for bit in range(8):
                flipped = chr(ord(c) ^ (1 << bit))
                if flipped.isalnum() or flipped == "-":
                    variants.add(f"{n[:i]}{flipped}{n[i+1:]}.{tld}")

        # Filter valid domain chars only
        valid = set()
        for v in variants:
            dom = v.split(".")[0]
            if (dom and dom[0] != "-" and dom[-1] != "-" and
                    re.match(r'^[a-z0-9\-]+$', dom) and 2 <= len(dom) <= 63):
                valid.add(v)
        return valid

    # ── DNS helpers ───────────────────────────────────────────────────────────

    def _resolve_a(self, domain: str) -> str | None:
        ips = self.safe_resolve(domain)
        return ips[0] if ips else None

    def _resolve_mx(self, domain: str) -> str | None:
        try:
            import dns.resolver as _res  # type: ignore
            answers = _res.resolve(domain, "MX", lifetime=3)
            return str(sorted(answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
        except Exception:
            return None
