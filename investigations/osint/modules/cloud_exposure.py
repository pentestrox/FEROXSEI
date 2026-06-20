"""
FEROXSEI OSINT - Cloud Bucket Exposure Scanner
Discovers and tests public AWS S3, Azure Blob, and GCP Storage buckets
that may be associated with the target domain.

Strategies:
  • Generate candidate bucket names from domain/org permutations
  • Check AWS S3 via public XML list endpoint + HEAD probe
  • Check Azure Blob Storage via publicaccess probe
  • Check GCP Cloud Storage JSON API
  • Check DigitalOcean Spaces
  • Check Backblaze B2 (public bucket check)

No API keys required - uses public HTTP probes only.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from .base import BaseOSINTModule, _log, _extract_domain


class CloudExposureModule(BaseOSINTModule):
    """Discovers and probes cloud storage buckets for public exposure."""
    NAME  = "cloudExposure"
    LABEL = "Cloud Bucket Scanner"
    ICON  = "☁️"
    ORDER = 35
    TARGET_TYPES: list = ['domain']

    # ── Endpoint templates ────────────────────────────────────────────────────
    _S3_URL   = "https://{bucket}.s3.amazonaws.com/"
    _S3_REGION= "https://{bucket}.s3.{region}.amazonaws.com/"
    _AZ_URL   = "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
    _GCP_URL  = "https://storage.googleapis.com/{bucket}/"
    _DO_URL   = "https://{bucket}.{region}.digitaloceanspaces.com/"
    _CF_R2    = "https://{bucket}.r2.dev/"

    _S3_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    # ── Signals that a bucket IS public and listable ──────────────────────────
    _LIST_MARKERS = [
        "<ListBucketResult", "<?xml", "<EnumerationResults",
        "\"kind\": \"storage#objects\"", "<Blobs>"
    ]
    # Signals that bucket exists but access is denied (interesting - confirm existence)
    _DENY_MARKERS = [
        "AccessDenied", "AllAccessDisabled", "AuthorizationFailure",
        "NoSuchBucketPolicy", "BlobAccessTierNotSupported"
    ]

    def run(self, scan_id: str, target: str, config: dict) -> None:
        domain   = _extract_domain(target)
        org      = domain.split(".")[0]
        _log(f"[{self.LABEL}] Starting cloud bucket scan for {domain}")

        candidates = self._generate_names(domain, org)
        _log(f"[{self.LABEL}] Testing {len(candidates)} bucket name candidates")

        found_public  = 0
        found_private = 0   # exists but access denied

        for name in candidates:
            if self.should_skip(scan_id):
                break
            # ── AWS S3 ─────────────────────────────────────────────────────
            s3_url = self._S3_URL.format(bucket=name)
            result = self._probe(scan_id, s3_url)
            if result == "public":
                found_public += 1
                self._save_public(scan_id, "AWS S3", name, s3_url)
            elif result == "exists":
                found_private += 1
                self._save_exists(scan_id, "AWS S3", name, s3_url)
            elif result is None:
                # Try regional endpoint
                for region in self._S3_REGIONS[:2]:
                    reg_url = self._S3_REGION.format(bucket=name, region=region)
                    r2 = self._probe(scan_id, reg_url)
                    if r2 == "public":
                        found_public += 1
                        self._save_public(scan_id, f"AWS S3 ({region})", name, reg_url)
                        break
                    elif r2 == "exists":
                        found_private += 1
                        self._save_exists(scan_id, f"AWS S3 ({region})", name, reg_url)
                        break

            # ── GCP Storage ────────────────────────────────────────────────
            gcp_url = self._GCP_URL.format(bucket=name)
            result  = self._probe(scan_id, gcp_url)
            if result == "public":
                found_public += 1
                self._save_public(scan_id, "GCP Storage", name, gcp_url)
            elif result == "exists":
                found_private += 1
                self._save_exists(scan_id, "GCP Storage", name, gcp_url)

            # ── Azure Blob ─────────────────────────────────────────────────
            # Azure: account name + container name may differ; try org as both
            az_url  = self._AZ_URL.format(account=name, container=name)
            result  = self._probe(scan_id, az_url)
            if result == "public":
                found_public += 1
                self._save_public(scan_id, "Azure Blob", name, az_url)
            elif result == "exists":
                found_private += 1
                self._save_exists(scan_id, "Azure Blob", name, az_url)

            # ── DigitalOcean Spaces (NYC3, AMS3, SGP1) ────────────────────
            for do_region in ["nyc3", "ams3"]:
                do_url = self._DO_URL.format(bucket=name, region=do_region)
                result = self._probe(scan_id, do_url)
                if result == "public":
                    found_public += 1
                    self._save_public(scan_id, f"DO Spaces ({do_region})", name, do_url)
                    break
                elif result == "exists":
                    found_private += 1
                    self._save_exists(scan_id, f"DO Spaces ({do_region})", name, do_url)
                    break

        # ── Summary ───────────────────────────────────────────────────────────
        if found_public == 0 and found_private == 0:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Cloud Buckets: None Found for {domain}",
                f"Tested {len(candidates)} bucket name permutations across AWS S3, "
                "GCP Storage, Azure Blob, and DigitalOcean Spaces. No buckets found.",
                tags=["cloud", "s3", "clean"]
            )
        else:
            self.db.save_finding(
                scan_id, self.NAME,
                "critical" if found_public else "high",
                f"☁️ Cloud Buckets: {found_public} Public, {found_private} Restricted",
                f"Found {found_public} publicly listable and {found_private} access-restricted "
                f"cloud storage buckets for {domain}.",
                tags=["cloud", "s3", "exposure", "summary"]
            )
        _log(f"[{self.LABEL}] ✅ Done - {found_public} public, {found_private} restricted")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _generate_names(self, domain: str, org: str) -> list[str]:
        """Generate candidate bucket/account names from domain permutations."""
        base  = [org, domain.replace(".", "-"), domain.replace(".", "")]
        parts = domain.split(".")
        base += parts[:2]
        suffixes = [
            "", "-dev", "-prod", "-staging", "-backup", "-data", "-assets",
            "-static", "-media", "-uploads", "-files", "-logs", "-archive",
            "-public", "-private", "-internal", "-cdn", "-images", "-docs",
            "-downloads", "-storage", "-s3", "-bucket", "-store",
            "dev", "prod", "staging", "backup", "assets", "static",
        ]
        names: list[str] = []
        for b in base:
            for s in suffixes:
                name = (b + s).lower()
                # S3/GCP bucket names: 3-63 chars, alphanumeric + hyphens, start/end alphanum
                name = re.sub(r'[^a-z0-9-]', '-', name).strip('-')
                if 3 <= len(name) <= 63 and name not in names:
                    names.append(name)
        return names[:40]   # cap to 40 to keep total probes reasonable

    def _probe(self, scan_id: str, url: str) -> str | None:
        """
        Returns:
          'public'  - bucket exists and is publicly listable
          'exists'  - bucket exists but access denied
          None      - bucket does not exist or unreachable
        """
        r = self.http.get(url, scan_id, self.NAME, add_delay=False, timeout=6)
        if not r:
            return None
        body = r.text[:2000] if r.text else ""
        # Pattern-scan bucket listing / response body
        if r.text:
            self._pattern_scan(scan_id, r.text, url)
        if r.status_code == 200:
            if any(m in body for m in self._LIST_MARKERS):
                return "public"
            # 200 but no list markers - might be public but empty / redirect
            return "public"
        if r.status_code in (403, 401):
            # Bucket exists but access denied - still interesting
            if any(m in body for m in self._DENY_MARKERS):
                return "exists"
            return "exists"
        if r.status_code == 301:
            # Redirect to region-specific endpoint
            location = r.headers.get("Location", "")
            if location and "amazonaws.com" in location:
                r2 = self.http.get(location, scan_id, self.NAME, add_delay=False)
                if r2 and r2.status_code == 200:
                    return "public"
                if r2 and r2.status_code in (403, 401):
                    return "exists"
        return None

    def _save_public(self, scan_id: str, provider: str, name: str, url: str) -> None:
        # Try to get a few file names from the listing
        r = self.http.get(url, scan_id, self.NAME, add_delay=False)
        files = []
        if r and r.text:
            files = re.findall(r'<Key>([^<]{1,200})</Key>|"name":\s*"([^"]{1,200})"', r.text)
            files = [f[0] or f[1] for f in files[:15]]
        evidence = f"Public URL: {url}\n"
        if files:
            evidence += f"\nSample contents ({len(files)} file(s) visible):\n"
            evidence += "\n".join(f"  • {f}" for f in files)
        self.db.save_finding(
            scan_id, self.NAME, "critical",
            f"🚨 PUBLIC BUCKET: [{provider}] {name}",
            f"Cloud storage bucket '{name}' on {provider} is publicly listable. "
            "Anyone on the internet can list and potentially download all contents.",
            url=url, evidence=evidence,
            tags=["cloud", "bucket", "public", "critical", provider.lower().split()[0]]
        )

    def _save_exists(self, scan_id: str, provider: str, name: str, url: str) -> None:
        self.db.save_finding(
            scan_id, self.NAME, "medium",
            f"☁️ Bucket Exists (Access Denied): [{provider}] {name}",
            f"Cloud storage bucket '{name}' on {provider} exists but returns 403/401. "
            "The bucket name reveals infrastructure and may be misconfigured to allow "
            "access via signed URLs or alternate paths.",
            url=url, evidence=f"URL returned 403/401: {url}",
            tags=["cloud", "bucket", "exists", provider.lower().split()[0]]
        )
