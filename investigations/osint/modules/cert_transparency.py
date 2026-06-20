"""FEROXSEI OSINT - Certificate Transparency module."""
from __future__ import annotations
import json

from .base import BaseOSINTModule, _log, _extract_domain


class CertTransparencyModule(BaseOSINTModule):
    """Certificate Transparency logs - subdomain discovery via crt.sh."""
    NAME  = "certTransparency"
    LABEL = "Cert Transparency"
    ICON  = "📜"
    ORDER = 15
    TARGET_TYPES: list = ['domain']

    def run(self, scan_id, target, config):
        domain = _extract_domain(target)
        _log(f"[{self.LABEL}] Querying crt.sh for {domain}")
        subdomains = set()

        # Query crt.sh
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = self.http.get(url, scan_id, self.NAME, add_delay=False)
        if r and r.status_code == 200:
            try:
                certs = r.json()
                for c in certs:
                    for name in (c.get("name_value","") or "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
                    # Check issuer info
                    common = c.get("common_name","")
                    if common and common.endswith(domain):
                        subdomains.add(common.lstrip("*."))
            except Exception:
                pass

        # Also query certspotter
        url2 = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        r2 = self.http.get(url2, scan_id, self.NAME, add_delay=False)
        if r2 and r2.status_code == 200:
            try:
                for cert in r2.json():
                    for name in cert.get("dns_names", []):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain):
                            subdomains.add(name)
            except Exception:
                pass

        _log(f"[{self.LABEL}] Found {len(subdomains)} unique subdomains")

        if subdomains:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Certificate Transparency: {len(subdomains)} Subdomains",
                f"Found via CT logs (crt.sh + certspotter)",
                evidence="\n".join(sorted(subdomains)),
                tags=["ct","subdomains","recon"],
                raw_data={"subdomains": sorted(subdomains)}
            )
        else:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Certificate Transparency: No SSL Certificates Found for {domain}",
                f"crt.sh and CertSpotter returned no certificate records for {domain}. "
                f"The domain likely uses HTTP only or is a very new/private deployment. "
                f"No subdomain exposure via CT logs.",
                tags=["ct","no-ssl","recon"]
            )

        # Store subdomains for other modules to use
        try:
            existing = self.db.one("SELECT notes FROM osint_scans WHERE id=?", (scan_id,))
            notes = {}
            if existing and existing.get("notes"):
                import json as _json
                try: notes = _json.loads(existing["notes"])
                except Exception: notes = {}
            notes["ct_subdomains"] = sorted(subdomains)
            self.db.upd("osint_scans", {"notes": __import__("json").dumps(notes)}, "id=?", (scan_id,))
        except Exception:
            pass

        return sorted(subdomains)
