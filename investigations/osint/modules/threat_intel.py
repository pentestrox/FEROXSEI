"""FEROXSEI OSINT - Threat Intelligence module."""
from __future__ import annotations
import json

from .base import BaseOSINTModule, _log, _extract_domain


class ThreatIntelModule(BaseOSINTModule):
    """VirusTotal + AbuseIPDB + AlienVault OTX correlation."""
    NAME  = "threatIntel"
    LABEL = "Threat Intel"
    ICON  = "⚡"
    ORDER = 55
    TARGET_TYPES: list = ['domain', 'ip', 'string']

    def run(self, scan_id, target, config):
        domain  = _extract_domain(target)
        vt_key  = config.get("virustotal_key","")
        otx_key = config.get("otx_key","")
        _log(f"[{self.LABEL}] Running threat intel for {domain}")

        if vt_key:
            self._virustotal_domain(scan_id, domain, vt_key)
        else:
            self._virustotal_free(scan_id, domain)

        if otx_key:
            self._otx_lookup(scan_id, domain, otx_key)

        # URLhaus (free, no key)
        self._urlhaus(scan_id, domain)

        abuseipdb_key = config.get("abuseipdb_key","")
        if abuseipdb_key:
            ips = self.safe_resolve(domain)
            for ip in ips[:3]:
                self._abuseipdb(scan_id, ip, abuseipdb_key)

    def _virustotal_free(self, scan_id, domain):
        pub_url = f"https://www.virustotal.com/gui/domain/{domain}"
        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"VirusTotal: Domain Report Available",
            f"Check VirusTotal report for {domain}",
            url=pub_url,
            tags=["virustotal","threat","recon"]
        )

    def _virustotal_domain(self, scan_id, domain, key):
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={key}&domain={domain}"
        r   = self.http.get(url, scan_id, self.NAME)
        if not r or r.status_code != 200:
            return
        try:
            data      = r.json()
            detected  = data.get("detected_urls",[])
            positives = sum(d.get("positives",0) for d in detected)
            sev = "critical" if positives > 5 else ("high" if positives > 0 else "info")
            self.db.save_finding(
                scan_id, self.NAME, sev,
                f"VirusTotal: {positives} Detections for {domain}",
                f"{len(detected)} URLs checked, {positives} total AV detections",
                evidence=json.dumps(detected[:5], indent=2),
                tags=["virustotal","malware","threat"]
            )
        except Exception:
            pass

    def _otx_lookup(self, scan_id, domain, key):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        r   = self.http.get(url, scan_id, self.NAME,
                            headers={"X-OTX-API-KEY": key})
        if not r or r.status_code != 200:
            return
        try:
            data   = r.json()
            pulses = data.get("pulse_info",{}).get("count",0)
            if pulses > 0:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"OTX AlienVault: {pulses} Threat Pulses for {domain}",
                    "Domain referenced in AlienVault OTX threat intelligence feeds",
                    url=f"https://otx.alienvault.com/indicator/domain/{domain}",
                    tags=["otx","threat","malware"]
                )
        except Exception:
            pass

    def _urlhaus(self, scan_id, domain):
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        r   = self.http.post(url, scan_id, self.NAME, data={"host": domain})
        if not r or r.status_code != 200:
            return
        try:
            data   = r.json()
            status = data.get("query_status","")
            if status == "is_host":
                urls = data.get("urls",[])
                self.db.save_finding(
                    scan_id, self.NAME, "critical",
                    f"⚠️ URLhaus: {domain} Flagged as Malware Host",
                    f"{len(urls)} malicious URL(s) reported for this domain",
                    evidence="\n".join(u.get("url","") for u in urls[:10]),
                    tags=["urlhaus","malware","threat","critical"]
                )
        except Exception:
            pass

    def _abuseipdb(self, scan_id, ip, key):
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        r   = self.http.get(url, scan_id, self.NAME,
                            headers={"Key": key, "Accept": "application/json"})
        if not r or r.status_code != 200:
            return
        try:
            data  = r.json().get("data",{})
            score = data.get("abuseConfidenceScore",0)
            if score > 0:
                sev = "critical" if score > 80 else ("high" if score > 40 else "medium")
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"AbuseIPDB: {ip} - Abuse Score {score}%",
                    f"IP {ip} has been reported for abuse (confidence: {score}%)\n"
                    f"Total reports: {data.get('totalReports',0)}\n"
                    f"Last reported: {data.get('lastReportedAt','')}",
                    tags=["abuseipdb","threat","ip"]
                )
        except Exception:
            pass
