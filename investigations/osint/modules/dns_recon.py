"""FEROXSEI OSINT - DNS Reconnaissance module."""
from __future__ import annotations

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target

try:
    import dns.resolver, dns.zone, dns.query, dns.name, dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class DNSReconModule(BaseOSINTModule):
    """Comprehensive DNS reconnaissance + subdomain brute-force."""
    NAME  = "dns"
    LABEL = "DNS Recon"
    ICON  = "🌐"
    ORDER = 20
    TARGET_TYPES: list = ['domain']

    WORDLIST_SMALL = [
        "www","mail","remote","blog","webmail","server","ns","ns1","ns2",
        "smtp","secure","vpn","m","shop","ftp","api","dev","stage","test",
        "admin","portal","dashboard","app","mobile","beta","cloud","cdn",
        "static","media","images","img","assets","docs","help","support",
        "git","gitlab","github","jira","confluence","jenkins","ci","build",
        "prod","staging","preprod","uat","qa","demo","sandbox","lab","int",
        "internal","intranet","extranet","remote","vpn","ldap","smtp","pop",
        "imap","exchange","owa","autodiscover","cpanel","whm","plesk",
        "mysql","db","database","mongodb","redis","elasticsearch","kibana",
        "grafana","prometheus","jenkins","bamboo","sonar","feroxsei","registry",
        "docker","k8s","kubernetes","rancher","vault","consul","nomad",
    ]

    def run(self, scan_id, target, config):
        if _is_keyword_target(target):
            self.db.save_finding(scan_id, self.NAME, "info",
                f"DNS Recon: Skipped - keyword target '{target}'",
                "DNS Recon requires a domain or URL. For keyword/phrase targets, "
                "use the Dark Web Monitor or Google Dork modules.",
                tags=["dns","skip","keyword"])
            return
        domain = _extract_domain(target)
        _log(f"[{self.LABEL}] Starting DNS recon for {domain}")
        self.emit_task(scan_id, f"Starting DNS recon for {domain}")
        results = {}

        if not HAS_DNS:
            self.db.save_finding(scan_id, self.NAME, "info",
                "DNS: dnspython not installed",
                "Install: pip install dnspython --break-system-packages",
                tags=["dns","setup"])
            return

        if self.use_tor:
            self._run_via_doh(scan_id, domain, results)
        else:
            self._run_via_dnspython(scan_id, domain, results)

        _log(f"[{self.LABEL}] Done - {len(results)} record types")

    def _save_records(self, scan_id, domain, rtype, records):
        if not records:
            return
        if rtype == "SPF":
            spf_records = [r for r in records if "v=spf1" in r.lower()]
            if not spf_records:
                return
            records = spf_records
        if rtype == "TXT":
            for rec in records:
                if "v=spf1" in rec.lower():
                    self.db.save_finding(scan_id, self.NAME, "info", "DNS SPF Record Found",
                        rec, tags=["dns","spf","recon"])
                if "google-site-verification" in rec:
                    self.db.save_finding(scan_id, self.NAME, "info",
                        "DNS TXT: Google verification (confirms Google Workspace)",
                        rec, tags=["dns","txt","recon"])
                if "MS=" in rec:
                    self.db.save_finding(scan_id, self.NAME, "info",
                        "DNS TXT: Microsoft verification (confirms M365)",
                        rec, tags=["dns","txt","recon"])
                if "stripe" in rec.lower():
                    self.db.save_finding(scan_id, self.NAME, "info",
                        "DNS TXT: Stripe domain verification",
                        rec, tags=["dns","txt","recon"])
        if rtype == "DMARC":
            has_dmarc = any("v=DMARC1" in r for r in records)
            if has_dmarc:
                for rec in records:
                    policy = "none"
                    if "p=reject" in rec: policy = "reject"
                    elif "p=quarantine" in rec: policy = "quarantine"
                    sev = "info" if policy == "reject" else "medium"
                    self.db.save_finding(scan_id, self.NAME, sev,
                        f"DNS DMARC: policy={policy}", rec, tags=["dns","dmarc","recon"])
            else:
                self.db.save_finding(scan_id, self.NAME, "medium",
                    "DNS DMARC: Missing - domain vulnerable to email spoofing",
                    f"No DMARC record at _dmarc.{domain}",
                    tags=["dns","dmarc","email-spoofing"])
            return
        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"DNS {rtype} Records for {domain}",
            f"{len(records)} {rtype} record(s) found",
            evidence="\n".join(records),
            tags=["dns", rtype.lower(), "recon"],
            raw_data={rtype: records}
        )

    def _run_via_doh(self, scan_id, domain, results):
        """DNS recon via DNS-over-HTTPS (Cloudflare) - routes through TOR SOCKS5. No raw socket calls."""
        self.emit_task(scan_id, "DNS recon via TOR (DoH)", detail="Using Cloudflare DoH through TOR proxy")
        DOH = "https://cloudflare-dns.com/dns-query"
        HDR = {"Accept": "application/dns-json"}
        TYPE_NUM = {"A":1,"AAAA":28,"MX":15,"NS":2,"TXT":16,"CNAME":5,"SOA":6,"CAA":257}

        record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]
        for rtype in record_types:
            if self.should_skip(scan_id):
                break
            queries = []
            if rtype == "TXT":
                queries = [(domain, "TXT"), (f"_dmarc.{domain}", "TXT")]
            else:
                queries = [(domain, rtype)]
            for qname, qtype in queries:
                try:
                    r = self.http._session.get(
                        f"{DOH}?name={qname}&type={qtype}",
                        headers=HDR, timeout=12)
                    if not r or r.status_code != 200:
                        continue
                    data = r.json()
                    answers = data.get("Answer") or []
                    type_num = TYPE_NUM.get(qtype, 0)
                    records = [a["data"] for a in answers if a.get("type") == type_num]
                    if records:
                        results[rtype] = results.get(rtype, []) + records
                        self._save_records(scan_id, domain, rtype, records)
                except Exception:
                    pass

        found_subs = []
        self.emit_task(scan_id, "Brute-forcing subdomains via TOR (DoH)",
                       detail=f"Testing {len(self.WORDLIST_SMALL)} candidates")
        for word in self.WORDLIST_SMALL:
            if self.should_skip(scan_id):
                break
            sub = f"{word}.{domain}"
            try:
                r = self.http._session.get(
                    f"{DOH}?name={sub}&type=A",
                    headers=HDR, timeout=8)
                if not r or r.status_code != 200:
                    continue
                data = r.json()
                answers = data.get("Answer") or []
                ips = [a["data"] for a in answers if a.get("type") == 1]
                if ips:
                    found_subs.append({"subdomain": sub, "ips": ips})
            except Exception:
                pass
        if found_subs:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"DNS Brute-Force: {len(found_subs)} Subdomains Resolved",
                "Active subdomains discovered via brute-force (DoH/TOR)",
                evidence="\n".join(f"{s['subdomain']} → {','.join(s['ips'])}" for s in found_subs),
                tags=["dns","subdomain","brute-force","recon"],
                raw_data={"subdomains": found_subs}
            )

    def _run_via_dnspython(self, scan_id, domain, results):
        """DNS recon via dnspython (direct) - only used when TOR is OFF."""
        if not HAS_DNS:
            self.db.save_finding(scan_id, self.NAME, "info",
                "DNS: dnspython not installed",
                "Install: pip install dnspython --break-system-packages",
                tags=["dns","setup"])
            return
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","DMARC","SPF"]
        self.emit_task(scan_id, "Querying DNS records", detail=f"Types: {', '.join(record_types)}")
        for rtype in record_types:
            try:
                if rtype == "DMARC":
                    qname = f"_dmarc.{domain}"; rtype_q = "TXT"
                elif rtype == "SPF":
                    qname = domain; rtype_q = "TXT"
                else:
                    qname = domain; rtype_q = rtype
                answers = resolver.resolve(qname, rtype_q)
                records = [str(r) for r in answers]
                results[rtype] = records
                self._save_records(scan_id, domain, rtype, records)
            except Exception:
                pass

        if "DMARC" not in results:
            self.db.save_finding(scan_id, self.NAME, "medium",
                "DNS DMARC: Missing - domain vulnerable to email spoofing",
                f"No DMARC record found at _dmarc.{domain}. "
                f"Attackers can spoof email from @{domain}.",
                tags=["dns","dmarc","email-spoofing"])

        try:
            ns_records = results.get("NS", [])
            for ns in ns_records[:3]:
                ns = ns.rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                    names = [str(n) for n in z.nodes.keys()]
                    if names:
                        self.db.save_finding(
                            scan_id, self.NAME, "critical",
                            f"⚠️ Zone Transfer SUCCESSFUL on {ns}",
                            f"DNS Zone Transfer allowed from {ns} - full zone data obtained!",
                            evidence="\n".join(names[:100]),
                            tags=["dns","zone-transfer","critical","exposure"]
                        )
                except Exception:
                    pass
        except Exception:
            pass

        found_subs = []
        self.emit_task(scan_id, "Brute-forcing subdomains",
                       detail=f"Testing {len(self.WORDLIST_SMALL)} candidates against {domain}")
        for word in self.WORDLIST_SMALL:
            if self.should_skip(scan_id):
                break
            sub = f"{word}.{domain}"
            try:
                answers = resolver.resolve(sub, "A")
                ips = [str(r) for r in answers]
                found_subs.append({"subdomain": sub, "ips": ips})
            except Exception:
                pass
        if found_subs:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"DNS Brute-Force: {len(found_subs)} Subdomains Resolved",
                "Active subdomains discovered via brute-force",
                evidence="\n".join(f"{s['subdomain']} → {','.join(s['ips'])}" for s in found_subs),
                tags=["dns","subdomain","brute-force","recon"],
                raw_data={"subdomains": found_subs}
            )
