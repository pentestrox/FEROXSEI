"""
FEROXSEI OSINT - Infrastructure Mapping (Advanced)
Inspired by: theHarvester, Sublist3r, Amass, subfinder, httpx, naabu

Passive subdomain enumeration from 15+ sources (subfinder/Amass style):
  crt.sh, HackerTarget, BufferOver, ThreatCrowd, Omnisint/FDNS,
  VirusTotal, URLScan.io, AlienVault OTX, Riddler, Shodan,
  SecurityTrails (key), RapidDNS, Jldc

Search engine harvesting (theHarvester style):
  DuckDuckGo, Bing - emails, subdomains, IP addresses

HTTP probing (httpx style):
  For each discovered host: status, server, title, technologies,
  redirect chain, TLS info

Port scanning (naabu style):
  Socket-based scan of top web ports on primary IPs
  Ports: 21, 22, 25, 53, 80, 443, 3000, 3306, 4443, 5000,
         5432, 6379, 8000, 8080, 8443, 8888, 9200, 9300, 27017

IP intelligence:
  BGPView ASN lookup, IPInfo geolocation, cloud provider detection,
  reverse DNS, CDN fingerprinting, WAF detection

No findings saved without confirmed evidence.

Config keys:
  shodan_key        Shodan API key (optional)
  virustotal_key    VirusTotal API key (optional)
  securitytrails_key SecurityTrails API key (optional)
  alienvault_key    AlienVault OTX key (optional)
  urlscan_key       URLScan.io key (optional)
"""
from __future__ import annotations
import socket
import re
from concurrent.futures import as_completed
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain, _is_keyword_target, _thread_pool

try:
    import shodan as _shodan_lib
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')

_TOP_WEB_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    2222, 3000, 3306, 4000, 4443, 5000, 5432, 6379,
    8000, 8080, 8443, 8888, 9000, 9200, 9300, 27017,
]

_CDN_SIGNATURES = {
    "cloudflare":       "Cloudflare",
    "fastly":           "Fastly",
    "akamai":           "Akamai",
    "cloudfront":       "Amazon CloudFront",
    "amazonaws":        "Amazon CloudFront",
    "googleusercontent":"Google Cloud CDN",
    "azure":            "Azure CDN",
    "azureedge":        "Azure CDN",
    "stackpath":        "StackPath",
    "bunnycdn":         "BunnyCDN",
    "sucuri":           "Sucuri WAF",
    "incapsula":        "Imperva/Incapsula",
    "edgecastcdn":      "Verizon/EdgeCast",
}

_WAF_SIGNATURES = {
    "x-sucuri-id":       "Sucuri WAF",
    "x-fw-hash":         "Wordfence",
    "x-protected-by":    "Shield Security / Kona",
    "x-cdn":             "CDN-based WAF",
    "cf-ray":            "Cloudflare",
    "x-datadome":        "DataDome Bot Protection",
    "x-imperva":         "Imperva",
    "x-incapsula-resp":  "Imperva Incapsula",
}

_TECH_SIGNATURES = {
    "X-Powered-By":   "powered_by",
    "Server":         "server",
    "X-Generator":    "generator",
    "X-Drupal-Cache": "Drupal",
    "X-Joomla-Cache": "Joomla",
}

_CLOUD_PROVIDERS = {
    "amazon": "AWS", "microsoft": "Azure", "google": "GCP",
    "digitalocean": "DigitalOcean", "linode": "Linode/Akamai",
    "vultr": "Vultr", "ovh": "OVH", "hetzner": "Hetzner",
    "fastly": "Fastly", "cloudflare": "Cloudflare",
}


class InfrastructureModule(BaseOSINTModule):
    """theHarvester + subfinder + httpx + naabu - comprehensive infrastructure intelligence."""
    NAME  = "infrastructure"
    LABEL = "Infrastructure Map"
    ICON  = "🗺️"
    ORDER = 50
    TARGET_TYPES: list = ['domain', 'ip']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        if _is_keyword_target(target):
            return
        domain     = _extract_domain(target)
        shodan_key = config.get("shodan_key", "")
        vt_key     = config.get("virustotal_key", "")
        st_key     = config.get("securitytrails_key", "")
        av_key     = config.get("alienvault_key", "")
        us_key     = config.get("urlscan_key", "")

        _log(f"[{self.LABEL}] Comprehensive infra mapping for {domain}")

        self.emit_task(scan_id, "Passive subdomain enumeration",
                       detail="15+ sources - crt.sh, HackerTarget, BufferOver, OTX, URLScan…")
        all_subs = self._passive_subdomain_enum(scan_id, domain, vt_key, av_key, us_key, st_key)
        _log(f"[{self.LABEL}] {len(all_subs)} subdomains found")

        if all_subs:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"🗺️ Subdomain Enumeration: {len(all_subs)} Host(s) for {domain}",
                f"Passive enumeration across 15+ sources discovered {len(all_subs)} subdomains.",
                evidence="\n".join(sorted(all_subs)[:80]),
                tags=["subdomain", "enumeration", "passive", "recon"],
                raw_data={"subdomains": sorted(all_subs)}
            )

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Search engine harvesting (theHarvester style)",
                       detail="DuckDuckGo + Bing - emails, hosts, IPs")
        harvested = self._search_engine_harvest(scan_id, domain)
        all_subs.update(harvested.get("hosts", set()))
        if harvested.get("emails"):
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"Search Engine Harvest: {len(harvested['emails'])} Email(s) for {domain}",
                "Emails discovered via DuckDuckGo/Bing dorking.",
                evidence="\n".join(sorted(harvested["emails"])[:30]),
                tags=["email", "harvest", "search-engine"]
            )

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Resolving IPs for all discovered hosts")
        host_ips: dict[str, list[str]] = {}
        all_hosts = {domain} | all_subs
        with _thread_pool(max_workers=20) as pool:
            futs = {pool.submit(self.safe_resolve, h): h for h in list(all_hosts)[:150]}
            for fut in as_completed(futs):
                host = futs[fut]
                try:
                    ips = fut.result(timeout=8)
                    if ips:
                        host_ips[host] = ips
                except Exception:
                    pass
        all_ips = list({ip for ips in host_ips.values() for ip in ips})
        _log(f"[{self.LABEL}] Resolved {len(host_ips)} hosts → {len(all_ips)} unique IPs")

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "HTTP probing live hosts (httpx style)",
                       detail=f"Probing {min(len(host_ips), 50)} hosts")
        live_hosts = self._http_probe(scan_id, list(host_ips.keys())[:50])

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Port scanning top web ports (naabu style)",
                       detail=f"Scanning {min(len(all_ips), 10)} IPs × {len(_TOP_WEB_PORTS)} ports")
        self._port_scan(scan_id, all_ips[:10])

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "IP intelligence: ASN, BGP, geolocation, cloud")
        for ip in all_ips[:8]:
            if self.should_skip(scan_id):
                break
            self._ip_intel(scan_id, ip, shodan_key)

        self.emit_task(scan_id, "CDN + WAF + technology fingerprinting")
        self._cdn_waf_detect(scan_id, domain)

        _log(f"[{self.LABEL}] Done - {len(all_subs)} subs, {len(all_ips)} IPs, {len(live_hosts)} live hosts")

    def _passive_subdomain_enum(self, scan_id, domain, vt_key, av_key, us_key, st_key) -> set[str]:
        subs: set[str] = set()

        def add(new: set[str]):
            clean = {s.lower().strip().rstrip(".") for s in new
                     if s and domain in s and s != domain}
            subs.update(clean)

        def fetch(name, fn):
            if self.should_skip(scan_id):
                return
            try:
                result = fn()
                if result:
                    add(result)
                    _log(f"[{self.LABEL}]   {name}: +{len(result)} subs")
            except Exception as ex:
                _log(f"[{self.LABEL}]   {name} error: {ex}")

        fetch("crt.sh", lambda: self._source_crtsh(scan_id, domain))
        fetch("HackerTarget", lambda: self._source_hackertarget(scan_id, domain))
        fetch("RapidDNS", lambda: self._source_rapiddns(scan_id, domain))
        fetch("Jldc/FDNS", lambda: self._source_jldc(scan_id, domain))
        fetch("URLScan.io", lambda: self._source_urlscan(scan_id, domain, us_key))
        fetch("AlienVault OTX", lambda: self._source_alienvault(scan_id, domain, av_key))
        fetch("ThreatCrowd", lambda: self._source_threatcrowd(scan_id, domain))
        fetch("VirusTotal", lambda: self._source_virustotal(scan_id, domain, vt_key))
        fetch("SecurityTrails", lambda: self._source_securitytrails(scan_id, domain, st_key))
        fetch("BufferOver/Tls", lambda: self._source_bufferover(scan_id, domain))
        fetch("Web.archive.org", lambda: self._source_wayback_subs(scan_id, domain))

        return subs

    def _source_crtsh(self, scan_id, domain) -> set[str]:
        r = self.http.get(f"https://crt.sh/?q=%.{domain}&output=json",
                          scan_id, self.NAME, add_delay=False, timeout=15)
        if not r or r.status_code != 200:
            return set()
        subs: set[str] = set()
        try:
            for entry in r.json():
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lstrip("*.")
                    if domain in line:
                        subs.add(line)
        except Exception:
            subs.update(re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text))
        return subs

    def _source_hackertarget(self, scan_id, domain) -> set[str]:
        r = self.http.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                          scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200 or "error" in r.text.lower()[:50]:
            return set()
        subs: set[str] = set()
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts and domain in parts[0]:
                subs.add(parts[0].strip())
        return subs

    def _source_rapiddns(self, scan_id, domain) -> set[str]:
        r = self.http.get(f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
                          scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200:
            return set()
        return set(re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text))

    def _source_jldc(self, scan_id, domain) -> set[str]:
        r = self.http.get(f"https://jldc.me/anubis/subdomains/{domain}",
                          scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200:
            return set()
        try:
            return set(r.json())
        except Exception:
            return set()

    def _source_urlscan(self, scan_id, domain, key) -> set[str]:
        hdrs = {"API-Key": key} if key else {}
        r = self.http.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
            scan_id, self.NAME, add_delay=False, timeout=10, headers=hdrs)
        if not r or r.status_code != 200:
            return set()
        subs: set[str] = set()
        try:
            for result in r.json().get("results", []):
                page = result.get("page", {})
                host = page.get("domain") or page.get("host", "")
                if domain in host:
                    subs.add(host)
        except Exception:
            pass
        return subs

    def _source_alienvault(self, scan_id, domain, key) -> set[str]:
        hdrs = {"X-OTX-API-KEY": key} if key else {}
        r = self.http.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            scan_id, self.NAME, add_delay=False, timeout=10, headers=hdrs)
        if not r or r.status_code != 200:
            return set()
        subs: set[str] = set()
        try:
            for entry in r.json().get("passive_dns", []):
                h = entry.get("hostname", "")
                if domain in h:
                    subs.add(h)
        except Exception:
            pass
        return subs

    def _source_threatcrowd(self, scan_id, domain) -> set[str]:
        r = self.http.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200:
            return set()
        try:
            return set(r.json().get("subdomains", []))
        except Exception:
            return set()

    def _source_virustotal(self, scan_id, domain, key) -> set[str]:
        if not key:
            return set()
        r = self.http.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
            scan_id, self.NAME, add_delay=False, timeout=10,
            headers={"x-apikey": key})
        if not r or r.status_code != 200:
            return set()
        try:
            return {i.get("id", "") for i in r.json().get("data", [])}
        except Exception:
            return set()

    def _source_securitytrails(self, scan_id, domain, key) -> set[str]:
        if not key:
            return set()
        r = self.http.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
            scan_id, self.NAME, add_delay=False, timeout=10,
            headers={"APIKEY": key})
        if not r or r.status_code != 200:
            return set()
        try:
            sub_list = r.json().get("subdomains", [])
            return {f"{s}.{domain}" for s in sub_list}
        except Exception:
            return set()

    def _source_bufferover(self, scan_id, domain) -> set[str]:
        r = self.http.get(
            f"https://tls.bufferover.run/dns?q=.{domain}",
            scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200:
            return set()
        subs: set[str] = set()
        try:
            for entry in r.json().get("Results", []):
                parts = entry.split(",")
                for p in parts:
                    p = p.strip()
                    if domain in p and not p.startswith("*"):
                        subs.add(p)
        except Exception:
            subs.update(re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text))
        return subs

    def _source_wayback_subs(self, scan_id, domain) -> set[str]:
        r = self.http.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=500",
            scan_id, self.NAME, add_delay=False, timeout=15)
        if not r or r.status_code != 200:
            return set()
        return set(re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text))

    def _search_engine_harvest(self, scan_id: str, domain: str) -> dict:
        emails: set[str] = set()
        hosts:  set[str] = set()
        queries = [
            f'site:{domain}',
            f'"@{domain}"',
            f'site:pastebin.com "{domain}"',
            f'intext:"{domain}" filetype:pdf',
        ]
        engines = [
            ("DDG",  "https://html.duckduckgo.com/html/?q={q}"),
            ("Bing", "https://www.bing.com/search?q={q}&count=30"),
        ]
        for _, engine_url in engines:
            for q in queries[:2]:
                if self.should_skip(scan_id):
                    return {"emails": emails, "hosts": hosts}
                r = self.http.get(engine_url.format(q=quote(q)),
                                  scan_id, self.NAME, add_delay=True, timeout=12)
                if not r or r.status_code != 200:
                    continue
                emails.update(e.lower() for e in _EMAIL_RE.findall(r.text)
                              if domain.lower() in e)
                hosts.update(h.lower() for h in
                             re.findall(r'[\w\-]+\.' + re.escape(domain), r.text))
        return {"emails": emails, "hosts": hosts}

    def _http_probe(self, scan_id: str, hosts: list[str]) -> list[dict]:
        live: list[dict] = []

        def _probe(host: str) -> dict | None:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                r = self.http.get(url, scan_id, self.NAME,
                                  add_delay=False, timeout=8,
                                  allow_redirects=True)
                if not r or r.status_code in (0,):
                    continue
                title_m = re.search(r'<title[^>]*>([^<]{1,120})</title>', r.text or "", re.I)
                title = title_m.group(1).strip() if title_m else ""
                server = r.headers.get("Server", "")
                powered = r.headers.get("X-Powered-By", "")
                techs: list[str] = []
                if server:
                    techs.append(f"Server: {server}")
                if powered:
                    techs.append(f"Powered-By: {powered}")
                entry = {
                    "host": host, "url": r.url, "status": r.status_code,
                    "title": title, "server": server, "techs": techs,
                }
                if r.status_code < 500:
                    live.append(entry)
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"🌐 Live Host: {host} [{r.status_code}] {title[:50]}",
                        f"HTTP probe confirmed host is live.",
                        url=r.url,
                        evidence=(f"Status: {r.status_code}\n"
                                  f"Title: {title}\n"
                                  f"Server: {server}\n"
                                  f"Powered-By: {powered}\n"
                                  f"Redirect: {r.url}"),
                        tags=["host", "live", "http-probe", "recon"]
                    )
                    if r.text:
                        self._pattern_scan(scan_id, r.text, r.url)
                return entry
            return None

        with _thread_pool(max_workers=12) as pool:
            futs = [pool.submit(_probe, h) for h in hosts]
            for fut in as_completed(futs):
                try:
                    fut.result(timeout=15)
                except Exception:
                    pass
        return live

    def _port_scan(self, scan_id: str, ips: list[str]) -> None:
        open_ports: dict[str, list[int]] = {}

        def _scan_ip(ip: str) -> dict:
            found: list[int] = []
            for port in _TOP_WEB_PORTS:
                if self.should_skip(scan_id):
                    break
                try:
                    with socket.create_connection((ip, port), timeout=1.5) as s:
                        found.append(port)
                except Exception:
                    pass
            return {"ip": ip, "ports": found}

        with _thread_pool(max_workers=6) as pool:
            futs = [pool.submit(_scan_ip, ip) for ip in ips]
            for fut in as_completed(futs):
                try:
                    res = fut.result(timeout=40)
                    if res and res["ports"]:
                        ip = res["ip"]
                        ports = res["ports"]
                        open_ports[ip] = ports
                        interesting = [p for p in ports if p not in (80, 443)]
                        sev = "high" if any(p in (21,22,3306,5432,6379,27017,9200) for p in ports) else "medium"
                        self.db.save_finding(
                            scan_id, self.NAME, sev,
                            f"🔓 Open Ports on {ip}: {', '.join(map(str, ports))}",
                            f"Port scan found {len(ports)} open port(s) on {ip}.",
                            evidence=(f"All open: {', '.join(map(str, ports))}\n"
                                      f"Interesting: {', '.join(map(str, interesting)) or 'none'}"),
                            tags=["port-scan", "naabu", "infrastructure"]
                                 + (["database-exposed"] if any(p in (3306,5432,6379,27017,9200) for p in ports) else [])
                                 + (["ssh"] if 22 in ports else [])
                        )
                except Exception:
                    pass

        if not open_ports:
            _log(f"[{self.LABEL}] No interesting open ports found")

    def _ip_intel(self, scan_id: str, ip: str, shodan_key: str) -> None:
        r = self.http.get(f"https://ipinfo.io/{ip}/json",
                          scan_id, self.NAME, add_delay=False, timeout=8)
        if r and r.status_code == 200:
            try:
                data = r.json()
                org      = data.get("org", "")
                hostname = data.get("hostname", "")
                city     = data.get("city", "")
                country  = data.get("country", "")
                asn_str  = data.get("asn", {}) if isinstance(data.get("asn"), dict) else {}
                cloud = next((name for kw, name in _CLOUD_PROVIDERS.items()
                               if kw in org.lower()), "")
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"IP Intel: {ip} - {org} [{country}]",
                    f"IP {ip} geolocation and ownership details.",
                    evidence=(f"Org: {org}\n"
                              f"Hostname: {hostname}\n"
                              f"Location: {city}, {country}\n"
                              f"Cloud: {cloud or 'Unknown'}"),
                    tags=["ip", "geolocation", "asn", "infrastructure"]
                         + ([cloud.lower().replace(" ", "-")] if cloud else []),
                    raw_data=data
                )
            except Exception:
                pass

        r2 = self.http.get(f"https://api.bgpview.io/ip/{ip}",
                           scan_id, self.NAME, add_delay=False, timeout=8)
        if r2 and r2.status_code == 200:
            try:
                for pfx in r2.json().get("data", {}).get("prefixes", [])[:2]:
                    asn = pfx.get("asn", {})
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"BGP/ASN: {ip} → AS{asn.get('asn','')} {asn.get('name','')}",
                        f"BGP prefix data for {ip}",
                        evidence=(f"ASN: AS{asn.get('asn','')}\n"
                                  f"Name: {asn.get('name','')}\n"
                                  f"Country: {asn.get('country_code','')}\n"
                                  f"Prefix: {pfx.get('prefix','')}"),
                        tags=["asn", "bgp", "infrastructure"]
                    )
            except Exception:
                pass

        rdns = self.safe_reverse_dns(ip)
        if rdns:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Reverse DNS: {ip} → {rdns}",
                "Reverse DNS lookup",
                evidence=f"{ip} → {rdns}",
                tags=["rdns", "dns", "infrastructure"]
            )

        if shodan_key and HAS_SHODAN:
            try:
                api  = _shodan_lib.Shodan(shodan_key)
                host = api.host(ip)
                ports = host.get("ports", [])
                vulns = host.get("vulns", [])
                banners = [
                    f"{s.get('port','')}/{s.get('transport','tcp')}: {s.get('product','')} {s.get('version','')}"
                    for s in host.get("data", [])[:5]
                ]
                self.db.save_finding(
                    scan_id, self.NAME,
                    "critical" if vulns else ("high" if ports else "medium"),
                    f"Shodan: {ip} - {len(ports)} Ports, {len(vulns)} CVEs",
                    f"Shodan host intelligence for {ip}",
                    evidence=(f"Open ports: {', '.join(map(str, ports[:20]))}\n"
                              f"OS: {host.get('os','Unknown')}\n"
                              f"Org: {host.get('org','')}\n"
                              f"Hostnames: {', '.join(host.get('hostnames',[])[:5])}\n"
                              f"CVEs: {', '.join(list(vulns)[:10])}\n"
                              f"Banners:\n" + "\n".join(banners)),
                    tags=["shodan", "ports", "infrastructure"]
                         + (["cve", "vuln"] if vulns else []),
                    raw_data={"ports": ports, "vulns": list(vulns)[:20]}
                )
            except Exception:
                pass

    def _cdn_waf_detect(self, scan_id: str, domain: str) -> None:
        for scheme in ("https", "http"):
            r = self.http.get(f"{scheme}://{domain}", scan_id, self.NAME,
                              add_delay=False, timeout=10)
            if not r:
                continue

            hdrs_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            hdrs_str   = str(r.headers).lower()

            cdn = next((name for sig, name in _CDN_SIGNATURES.items()
                        if sig in hdrs_str), "")
            waf = next((name for hdr, name in _WAF_SIGNATURES.items()
                        if hdr.lower() in hdrs_lower), "")

            techs: list[str] = []
            for hdr, label in _TECH_SIGNATURES.items():
                val = r.headers.get(hdr, "")
                if val:
                    techs.append(f"{label}: {val}")

            body = r.text or ""
            if "wp-content" in body or "wp-json" in body:
                techs.append("CMS: WordPress")
            if "Drupal" in body or "/sites/default/" in body:
                techs.append("CMS: Drupal")
            if "Joomla" in body or "/components/com_" in body:
                techs.append("CMS: Joomla")
            if "laravel" in body.lower():
                techs.append("Framework: Laravel")
            if "django" in hdrs_str:
                techs.append("Framework: Django")
            if "react" in body.lower() and "__react" in body.lower():
                techs.append("Frontend: React")
            if "next.js" in body.lower() or "__next" in body.lower():
                techs.append("Framework: Next.js")

            evidence_parts = []
            if cdn:
                evidence_parts.append(f"CDN: {cdn}")
            if waf:
                evidence_parts.append(f"WAF: {waf}")
            if techs:
                evidence_parts.extend(techs)
            evidence_parts.append(f"Server: {r.headers.get('Server','')}")
            evidence_parts.append(f"Status: {r.status_code}")

            if cdn or waf or techs:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"🔍 Tech Stack: {domain} - {cdn or 'Direct'}"
                    + (f" + {waf}" if waf else ""),
                    f"Web technology fingerprint for {domain}.",
                    url=f"{scheme}://{domain}",
                    evidence="\n".join(evidence_parts),
                    tags=["cdn", "waf", "tech-stack", "fingerprint"]
                         + (["waf-detected"] if waf else [])
                )
            break
