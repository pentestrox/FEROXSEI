"""
FEROXSEI OSINT - Image Search OSINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Multi-layer intelligence from a single image upload.

Phase 1 : EXIF metadata extraction (device make/model, timestamps, author)
Phase 2 : GPS geolocation + reverse geocoding (Nominatim)
Phase 3 : Cryptographic + perceptual fingerprinting (MD5/SHA256/pHash)
Phase 4 : OCR text extraction (pytesseract - graceful if not installed)
Phase 5 : AI Vision analysis (Anthropic Claude - scene, location, persons, text, search queries)
Phase 6 : Reverse image search (Yandex, TinEye, Bing Visual Search)
Phase 7 : DDG content search (AI description queries + optional context fields)

Optional context fields (set via scan form) for deeper matching:
  img_subject_name  - person's full name
  img_username      - social media handle
  img_email         - email address
  img_phone         - phone number
  img_keyword       - any extra keywords / location / event

Config keys read:
  image_path         - absolute path to the uploaded image (set by route handler)
  img_subject_name   - optional subject name
  img_username       - optional username/handle
  img_email          - optional email
  img_phone          - optional phone
  img_keyword        - optional keyword / context
  anthropic_key      - Anthropic API key for vision analysis
"""
from __future__ import annotations
import os
import re
import time
import json
import hashlib
import base64
from pathlib import Path
from typing import Optional

from .base import BaseOSINTModule, _log


class ImageOSINTModule(BaseOSINTModule):
    NAME  = "imageOsint"
    LABEL = "Image OSINT"
    ICON  = "🖼️"
    ORDER = 26
    TARGET_TYPES: list = ["image"]
    DESCRIPTION = (
        "Multi-layer image intelligence: EXIF+GPS, AI vision (Claude), "
        "OCR, perceptual hashing, reverse image search, DDG correlation"
    )

    # ─── EXIF / GPS ──────────────────────────────────────────────────────────

    def _load_pil(self, path: str):
        try:
            from PIL import Image
            return Image.open(path)
        except Exception:
            return None

    def _exif_data(self, path: str) -> tuple:
        """Returns (exif_dict, gps_dict_or_None)."""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            img = Image.open(path)
            raw = img._getexif()
            if not raw:
                return {}, None
            exif = {}
            gps_raw = {}
            for tag_id, val in raw.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if tag == "GPSInfo":
                    for k, v in val.items():
                        gps_raw[GPSTAGS.get(k, str(k))] = v
                else:
                    try:
                        if isinstance(val, bytes):
                            val = val.decode("utf-8", errors="replace").strip("\x00")
                        exif[str(tag)] = str(val)[:500]
                    except Exception:
                        exif[str(tag)] = repr(val)[:200]
            return exif, (gps_raw if gps_raw else None)
        except ImportError:
            _log("[ImageOSINT] Pillow not installed - no EXIF extraction")
            return {}, None
        except Exception as e:
            _log(f"[ImageOSINT] EXIF error: {e}")
            return {}, None

    def _gps_to_decimal(self, val) -> Optional[float]:
        try:
            if hasattr(val[0], "numerator"):
                d = val[0].numerator / val[0].denominator
                m = val[1].numerator / val[1].denominator
                s = val[2].numerator / val[2].denominator
            else:
                d, m, s = float(val[0]), float(val[1]), float(val[2])
            return d + m / 60 + s / 3600
        except Exception:
            return None

    def _reverse_geocode(self, lat: float, lon: float, scan_id: str) -> str:
        try:
            r = self.http.get(
                f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json",
                scan_id, self.NAME,
                headers={"User-Agent": "FEROXSEI-OSINT/2.0 image-recon"},
                add_delay=False, timeout=10,
            )
            if r and r.status_code == 200:
                return r.json().get("display_name", "")
        except Exception:
            pass
        return ""

    # ─── Fingerprinting + pHash similarity ───────────────────────────────────

    def _fingerprint(self, path: str) -> tuple:
        try:
            data = open(path, "rb").read()
            return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()
        except Exception:
            return None, None

    def _phash_bits(self, path: str) -> Optional[str]:
        """Return 64-bit perceptual hash as a string of '0'/'1' characters."""
        try:
            from PIL import Image
            img = Image.open(path).convert("L").resize((8, 8), Image.LANCZOS)
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels)
            return "".join("1" if p >= avg else "0" for p in pixels)
        except Exception:
            return None

    def _phash_bits_from_bytes(self, data: bytes) -> Optional[str]:
        """Compute pHash bits directly from raw image bytes (for thumbnails)."""
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(data)).convert("L").resize((8, 8), Image.LANCZOS)
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels)
            return "".join("1" if p >= avg else "0" for p in pixels)
        except Exception:
            return None

    def _phash(self, path: str) -> Optional[str]:
        """Hex representation of the pHash (for display)."""
        bits = self._phash_bits(path)
        if bits:
            try:
                return format(int(bits, 2), "016x")
            except Exception:
                pass
        return None

    def _similarity_pct(self, bits1: str, bits2: str) -> int:
        """Hamming distance between two 64-bit hash strings → similarity 0-100."""
        if not bits1 or not bits2 or len(bits1) != len(bits2):
            return 0
        hamming = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
        return int((len(bits1) - hamming) / len(bits1) * 100)

    def _thumb_similarity(self, our_bits: str, thumb_url: str, scan_id: str) -> int:
        """Download a thumbnail directly (no TOR) and return pHash similarity % vs our image."""
        if not our_bits or not thumb_url:
            return 0
        try:
            import requests as _req
            url = ("https:" + thumb_url) if thumb_url.startswith("//") else thumb_url
            r = _req.get(url, timeout=6,
                         headers={"User-Agent": "Mozilla/5.0 (compatible)"})
            if r and r.status_code == 200 and r.content:
                thumb_bits = self._phash_bits_from_bytes(r.content)
                return self._similarity_pct(our_bits, thumb_bits)
        except Exception:
            pass
        return 0

    def _image_dimensions(self, path: str) -> str:
        try:
            from PIL import Image
            img = Image.open(path)
            return f"{img.width}x{img.height} px, mode={img.mode}"
        except Exception:
            return ""

    # ─── OCR ─────────────────────────────────────────────────────────────────

    def _ocr_text(self, path: str) -> Optional[str]:
        try:
            import pytesseract
            from PIL import Image
            return pytesseract.image_to_string(Image.open(path)).strip()
        except ImportError:
            return None
        except Exception:
            return None

    # ─── AI Vision ───────────────────────────────────────────────────────────

    def _image_to_b64(self, path: str) -> tuple:
        try:
            ext = Path(path).suffix.lower()
            mime_map = {
                ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".png": "image/png",  ".gif": "image/gif",
                ".webp": "image/webp", ".bmp": "image/jpeg",
                ".tiff": "image/jpeg", ".tif": "image/jpeg",
            }
            mime = mime_map.get(ext, "image/jpeg")
            with open(path, "rb") as f:
                data = f.read()
            return base64.b64encode(data).decode(), mime
        except Exception:
            return None, None

    def _ai_vision(self, path: str, context: dict, api_key: str, scan_id: str) -> Optional[str]:
        """Send image to Anthropic Claude for deep OSINT analysis."""
        b64, mime = self._image_to_b64(path)
        if not b64 or not api_key:
            return None

        ctx_lines = []
        if context.get("subject_name"):
            ctx_lines.append(f"Subject name provided: {context['subject_name']}")
        if context.get("username"):
            ctx_lines.append(f"Known username/handle: {context['username']}")
        if context.get("email"):
            ctx_lines.append(f"Known email: {context['email']}")
        if context.get("phone"):
            ctx_lines.append(f"Known phone: {context['phone']}")
        if context.get("keyword"):
            ctx_lines.append(f"Additional context: {context['keyword']}")
        ctx_block = ("\n\nAdditional investigator context:\n" + "\n".join(ctx_lines)) if ctx_lines else ""

        prompt = (
            "You are an elite OSINT analyst performing image intelligence collection. "
            "Analyze this image exhaustively and provide a structured intelligence report.\n\n"
            "## Required sections:\n\n"
            "### 1. SCENE DESCRIPTION\n"
            "What is depicted? (people, objects, setting, activity, time of day, indoor/outdoor)\n\n"
            "### 2. LOCATION INTELLIGENCE\n"
            "Architecture style, language of signs, vegetation type, road/vehicle type, "
            "landmarks, storefront names, license plate format, terrain, climate indicators. "
            "Provide best-guess country/city/region.\n\n"
            "### 3. PERSON DETAILS (if any faces/people visible)\n"
            "Approximate age range, gender, hair color/style, skin tone, clothing brands/logos, "
            "tattoos, accessories, unique identifiers. Be factual and neutral.\n\n"
            "### 4. VISIBLE TEXT & SYMBOLS\n"
            "ALL readable text (signs, labels, watermarks, usernames, URLs, phone numbers, "
            "email addresses, barcodes, QR codes, social media handles, company names)\n\n"
            "### 5. TECHNICAL & DEVICE CLUES\n"
            "Image quality (professional/amateur/screenshot/scan), likely camera/phone model "
            "indicators, screenshot UI elements (OS, app, browser), editing artifacts, filters\n\n"
            "### 6. SOCIAL MEDIA & PLATFORM CLUES\n"
            "Profile picture style, platform watermarks, UI frames, engagement metrics visible, "
            "post overlays, story formats\n\n"
            "### 7. TEMPORAL CLUES\n"
            "Season, approximate year (car models, fashion, tech devices visible), "
            "event indicators, news in background, holiday decorations\n\n"
            "### 8. DDG SEARCH QUERIES\n"
            "Provide exactly 5 highly specific DuckDuckGo/Google search queries "
            "that would identify the person, location, or event in this image. "
            "Format as a numbered list.\n\n"
            "### 9. OSINT LEADS\n"
            "Specific actionable intelligence leads (e.g., 'search Instagram for #EventName', "
            "'check Twitter for @CompanyName employee photos', "
            "'Google Maps Street View at approximate coordinates')\n\n"
            "### 10. CONFIDENCE SCORES\n"
            "Location ID confidence: X/10\n"
            "Person ID confidence: X/10\n"
            "Temporal ID confidence: X/10"
            + ctx_block
        )

        try:
            r = self.http.post(
                "https://api.anthropic.com/v1/messages",
                scan_id, self.NAME,
                json={
                    "model": "claude-opus-4-5",
                    "max_tokens": 2500,
                    "messages": [{
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": mime,
                                    "data": b64,
                                },
                            },
                            {"type": "text", "text": prompt},
                        ],
                    }],
                },
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                add_delay=False,
                timeout=120,
            )
            if r and r.status_code == 200:
                return r.json()["content"][0]["text"]
            if r:
                _log(f"[ImageOSINT] Anthropic vision HTTP {r.status_code}: {r.text[:300]}")
        except Exception as ex:
            _log(f"[ImageOSINT] Anthropic vision exception: {ex}")
        return None

    # ─── Reverse Image Search ─────────────────────────────────────────────────
    #
    # Each method returns a list of dicts:
    #   source   - engine name
    #   url      - source page where image was found (or results page)
    #   title    - page / result title
    #   thumb    - thumbnail URL (used for pHash similarity scoring, may be "")
    #   domain   - hostname of the source page
    #   similarity - int 0-100 (filled in later by run() using pHash comparison)
    #

    def _direct_session(self):
        """Return a direct requests.Session (no TOR) for reverse image uploads."""
        import requests as _requests
        sess = _requests.Session()
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
        })
        return sess

    def _log_traffic(self, scan_id: str, method: str, url: str,
                     status_code: int, duration_ms: int, error: str = "") -> None:
        """Log a direct (non-TOR) HTTP request to the traffic_log table."""
        try:
            from urllib.parse import urlparse as _up
            p = _up(url)
            self.engine.db.log_traffic(
                scan_id=scan_id, module=self.NAME,
                method=method.upper(), url=url,
                status_code=status_code,
                source_ip="direct",
                dest_host=p.hostname or "",
                dest_port=p.port or (443 if url.startswith("https") else 80),
                duration_ms=duration_ms,
                via_tor=False,
                tor_exit_ip="",
                error=error,
            )
        except Exception:
            pass

    def _reverse_yandex(self, path: str, scan_id: str, our_bits: str) -> list:
        results = []
        try:
            import html as _htmlmod
            with open(path, "rb") as f:
                img_bytes = f.read()
            sess = self._direct_session()

            # Step 1: Upload image and get cbirId + originalImageUrl from JSON response
            _t0 = time.time()
            r = sess.post(
                "https://yandex.com/images/search",
                params={"rpt": "imageview", "format": "json",
                        "request": '{"blocks":[{"block":"b-page_type_search-by-image__link"}]}'},
                files={"upfile": ("image.jpg", img_bytes, "image/jpeg")},
                headers={"Accept": "text/html,application/xhtml+xml",
                         "Referer": "https://yandex.com/images/"},
                timeout=22, allow_redirects=True,
            )
            self._log_traffic(scan_id, "POST", "https://yandex.com/images/search",
                               r.status_code if r else 0, int((time.time()-_t0)*1000))
            if not r or r.status_code != 200:
                return results

            cbir_m = re.search(r'"cbirId"\s*:\s*"([^"]+)"', r.text)
            orig_m = re.search(r'"originalImageUrl"\s*:\s*"([^"]+)"', r.text)
            if not cbir_m or not orig_m:
                return results

            cbir_id  = cbir_m.group(1)
            orig_url = orig_m.group(1)
            search_url = (
                "https://yandex.com/images/search"
                f"?rpt=imageview&url={orig_url}&cbir_id={cbir_id}"
            )

            # Step 2: Fetch the search results HTML page
            _t0 = time.time()
            rp = sess.get(
                "https://yandex.com/images/search",
                params={"rpt": "imageview", "url": orig_url, "cbir_id": cbir_id},
                headers={"Accept": "text/html,application/xhtml+xml",
                         "Referer": "https://yandex.com/images/"},
                timeout=15,
            )
            self._log_traffic(scan_id, "GET", "https://yandex.com/images/search",
                               rp.status_code if rp else 0, int((time.time()-_t0)*1000))
            if not rp or rp.status_code != 200:
                return results

            # Step 3: Yandex embeds result data as HTML-entity-escaped JSON in the page.
            # Unescape once so we can use straightforward regex on the data.
            text = _htmlmod.unescape(rp.text)

            # Each result entry looks like:
            #   "title":"<title>","description":"<desc>","url":"https://...","domain":"<dom>"
            #   followed by "thumb":{"url":"//<cdn>..."}
            entry_pat = re.compile(
                r'"title":"([^"]{1,200})","description":"[^"]{0,400}",'
                r'"url":"(https?://(?!yandex)[^"]{10,250})","domain":"([^"]{1,80})"'
            )
            thumb_pat = re.compile(r'"thumb":\{"url":"(//[^"]+)"')

            entry_hits = list(entry_pat.finditer(text))
            thumb_hits = list(thumb_pat.finditer(text))

            seen_pages: set = set()
            for i, m in enumerate(entry_hits[:20]):
                title    = m.group(1)
                page_url = m.group(2)
                domain   = m.group(3)

                # Strip utm tracking params for dedup
                clean_url = re.sub(r"[?&]utm_[^&]*", "", page_url).rstrip("?&")
                if clean_url in seen_pages:
                    continue
                seen_pages.add(clean_url)

                # Find the next thumb URL after this entry's position
                thumb_url = ""
                for th in thumb_hits:
                    if th.start() > m.start():
                        raw = th.group(1)
                        thumb_url = ("https:" + raw) if raw.startswith("//") else raw
                        break

                sim = self._thumb_similarity(our_bits, thumb_url, scan_id) if thumb_url else 0
                results.append({
                    "source":     "Yandex",
                    "url":        page_url,
                    "title":      title or f"Yandex match on {domain}",
                    "thumb":      thumb_url,
                    "domain":     domain,
                    "similarity": sim,
                })

            # Always add the Yandex search page as a reference
            results.insert(0, {
                "source":     "Yandex",
                "url":        search_url,
                "title":      f"Yandex Reverse Image Search Results ({len(entry_hits)} pages found)",
                "thumb":      "",
                "domain":     "yandex.com",
                "similarity": 0,
            })
        except Exception as ex:
            _log(f"[ImageOSINT] Yandex reverse error: {ex}")
        return results

    def _reverse_tineye(self, path: str, scan_id: str, our_bits: str) -> list:
        results = []
        try:
            with open(path, "rb") as f:
                img_bytes = f.read()
            sess = self._direct_session()
            _t0 = time.time()
            r = sess.post(
                "https://tineye.com/search",
                files={"image": ("image.jpg", img_bytes, "image/jpeg")},
                headers={"Accept": "text/html,*/*",
                         "Referer": "https://tineye.com/"},
                timeout=28, allow_redirects=True,
            )
            self._log_traffic(scan_id, "POST", "https://tineye.com/search",
                               r.status_code if r else 0, int((time.time()-_t0)*1000))
            if not r or r.status_code != 200:
                return results

            html = r.text
            count_m = re.search(r'([\d,]+)\s+(?:results?|match(?:es)?)', html, re.I)
            match_count = int(count_m.group(1).replace(",", "")) if count_m else 0

            # Add the results page link
            results.append({
                "source": "TinEye",
                "url": r.url,
                "title": f"TinEye: {match_count} match(es) found",
                "thumb": "",
                "domain": "tineye.com",
                "similarity": 95 if match_count > 0 else 0,  # TinEye only returns exact/near-exact
            })

            # Parse individual match entries
            # TinEye HTML: <div class="match"> ... <img src="THUMB"> ... <a href="SOURCE_PAGE">
            match_blocks = re.findall(
                r'<div[^>]+class="[^"]*match[^"]*"[^>]*>(.*?)</div>\s*</div>',
                html, re.DOTALL | re.I
            )
            if not match_blocks:
                # Alternate selector for newer TinEye layout
                match_blocks = re.findall(
                    r'class="[^"]*result[^"]*"[^>]*>(.*?)</(?:article|div)>',
                    html, re.DOTALL | re.I
                )
            seen_urls = set()
            for blk in match_blocks[:8]:
                # Extract source page URL
                page_m = re.search(r'href="(https?://(?!tineye)[^"]+)"', blk)
                if not page_m:
                    continue
                page_url = page_m.group(1)
                if page_url in seen_urls:
                    continue
                seen_urls.add(page_url)

                # Extract thumbnail
                thumb_m = re.search(r'<img[^>]+src="(https?://[^"]+)"', blk, re.I)
                thumb = thumb_m.group(1) if thumb_m else ""

                # Extract date (first/last seen)
                date_m = re.search(r'(?:First|Last)\s+(?:seen|crawled)[:\s]+(\w+ \d+,? \d{4})', blk, re.I)
                date_str = date_m.group(1) if date_m else ""

                try:
                    from urllib.parse import urlparse as _up
                    dom = _up(page_url).netloc
                except Exception:
                    dom = ""

                sim = self._thumb_similarity(our_bits, thumb, scan_id) if thumb else 90
                results.append({
                    "source": "TinEye",
                    "url": page_url,
                    "title": f"Match on {dom}" + (f" (first seen {date_str})" if date_str else ""),
                    "thumb": thumb,
                    "domain": dom,
                    "similarity": sim,
                    "date": date_str,
                })
        except Exception as ex:
            _log(f"[ImageOSINT] TinEye reverse error: {ex}")
        return results

    def _reverse_bing(self, path: str, scan_id: str, our_bits: str) -> list:
        """Bing Visual Search - upload image and return the search results URL as reference.
        Bing renders results client-side via React, so only the search page link is extractable."""
        results = []
        try:
            with open(path, "rb") as f:
                img_bytes = f.read()
            sess = self._direct_session()
            sess.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            })
            _t0 = time.time()
            r = sess.post(
                "https://www.bing.com/images/search",
                params={"view": "detailv2", "iss": "sbiupload", "FORM": "SBIVSP"},
                files={"imageStream": ("image.jpg", img_bytes, "image/jpeg")},
                data={"imgurl": "", "cbir": "sbi", "imageBin": ""},
                headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         "Referer": "https://www.bing.com/images/"},
                timeout=22, allow_redirects=True,
            )
            self._log_traffic(scan_id, "POST", "https://www.bing.com/images/search",
                               r.status_code if r else 0, int((time.time()-_t0)*1000))
            if not r or r.status_code != 200 or "bing.com" not in r.url:
                return results

            # Bing returns a React SPA; actual results load client-side.
            # Return the search page URL so the analyst can open it in a browser.
            results.append({
                "source":     "Bing Visual",
                "url":        r.url,
                "title":      "Bing Visual Search Results (open in browser to view matches)",
                "thumb":      "",
                "domain":     "bing.com",
                "similarity": 0,
            })
        except Exception as ex:
            _log(f"[ImageOSINT] Bing Visual error: {ex}")
        return results

    def _reverse_google(self, path: str, scan_id: str, our_bits: str) -> list:
        """Google Lens - upload image and return the search results URL as reference."""
        results = []
        try:
            with open(path, "rb") as f:
                img_bytes = f.read()
            sess = self._direct_session()
            sess.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            })
            _t0 = time.time()
            r = sess.post(
                "https://lens.google.com/v3/upload",
                files={"encoded_image": ("image.jpg", img_bytes, "image/jpeg")},
                data={"image_url": "", "sbisrc": "cr_1_5_2"},
                headers={"Accept": "text/html,application/xhtml+xml",
                         "Referer": "https://lens.google.com/"},
                timeout=22, allow_redirects=True,
            )
            self._log_traffic(scan_id, "POST", "https://lens.google.com/v3/upload",
                               r.status_code if r else 0, int((time.time()-_t0)*1000))
            if r and r.status_code == 200 and "lens.google.com" in r.url:
                results.append({
                    "source":     "Google Lens",
                    "url":        r.url,
                    "title":      "Google Lens Visual Search Results (open in browser)",
                    "thumb":      "",
                    "domain":     "lens.google.com",
                    "similarity": 0,
                })
        except Exception as ex:
            _log(f"[ImageOSINT] Google Lens error: {ex}")
        return results

    def _reverse_flickr(self, path: str, scan_id: str, our_bits: str, context: dict) -> list:
        """Flickr public-feed search for image correlation (no API key needed).
        Builds keyword tags from context fields, fetches the public photo feed,
        and scores each thumbnail with pHash similarity."""
        try:
            import urllib.parse as _urlparse
        except ImportError:
            return []
        results = []
        try:
            tags = []
            if context.get("img_subject_name"):
                for _p in context["img_subject_name"].strip().split():
                    if len(_p) >= 3:
                        tags.append(_p.lower())
            if context.get("img_keyword"):
                tags.extend(context["img_keyword"].lower().split())
            if not tags:
                tags = [os.path.splitext(os.path.basename(path))[0].replace("_", " ").replace("-", " ")]
            tag_str = ",".join(tags[:5])
            feed_url = (
                "https://api.flickr.com/services/feeds/photos_public.gne"
                f"?tags={_urlparse.quote(tag_str)}&format=json&nojsoncallback=1&per_page=15"
            )
            sess = self._direct_session()
            sess.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "application/json, text/javascript, */*",
                "Referer": "https://www.flickr.com/",
            })
            _t0 = time.time()
            r = sess.get(feed_url, timeout=14)
            self._log_traffic(scan_id, "GET", feed_url,
                              r.status_code if r else 0, int((time.time() - _t0) * 1000))
            if not r or r.status_code != 200:
                return results
            data = r.json()
            for item in data.get("items", [])[:15]:
                thumb = item.get("media", {}).get("m", "")
                page_url = item.get("link", "")
                title = item.get("title", "")
                tags_in = item.get("tags", "")
                sim = 0
                if our_bits and thumb:
                    try:
                        _t1 = time.time()
                        tr = sess.get(thumb, timeout=7)
                        self._log_traffic(scan_id, "GET", thumb,
                                          tr.status_code if tr else 0,
                                          int((time.time() - _t1) * 1000))
                        if tr and tr.status_code == 200:
                            sim = self._thumb_similarity(our_bits, tr.content)
                    except Exception:
                        pass
                results.append({
                    "source":     "Flickr",
                    "url":        page_url,
                    "title":      title or tags_in,
                    "thumb":      thumb,
                    "domain":     "flickr.com",
                    "similarity": sim,
                })
        except Exception as ex:
            _log(f"[ImageOSINT] Flickr error: {ex}")
        return results

    # ─── DDG Content Search ───────────────────────────────────────────────────

    def _ddg_search(self, queries: list) -> list:
        all_results = []
        seen = set()
        try:
            try:
                from ddgs import DDGS
            except ImportError:
                from duckduckgo_search import DDGS
            with DDGS() as ddgs:
                for q in queries[:8]:
                    if not q or len(q.strip()) < 5:
                        continue
                    try:
                        hits = list(ddgs.text(q.strip(), max_results=7))
                        for h in hits:
                            url = h.get("href", "") or h.get("url", "")
                            if url and url not in seen:
                                seen.add(url)
                                all_results.append({
                                    "query": q[:80],
                                    "url": url,
                                    "title": h.get("title", ""),
                                    "snippet": h.get("body", "") or h.get("description", ""),
                                })
                        time.sleep(0.4)
                    except Exception:
                        continue
        except ImportError:
            _log("[ImageOSINT] ddgs not installed - skipping DDG search")
        except Exception as ex:
            _log(f"[ImageOSINT] DDG error: {ex}")
        return all_results

    def _expand_name_to_usernames(self, subject_name: str) -> list:
        """Apply username_patterns table to a full name and return candidate handles.
        Patterns use {first}, {last}, {f} (first initial), {m} (middle initial), {l} (last initial)."""
        parts = subject_name.strip().split()
        if not parts:
            return []
        first  = parts[0].lower()
        last   = parts[-1].lower() if len(parts) > 1 else ""
        middle = parts[1].lower() if len(parts) >= 3 else ""
        f = first[0]  if first  else ""
        l = last[0]   if last   else ""
        m = middle[0] if middle else ""
        try:
            rows = self.db.rows("SELECT pattern FROM username_patterns WHERE enabled=1")
        except Exception:
            rows = []
        candidates: list = []
        seen: set = set()
        for row in rows:
            pat = row["pattern"]
            if "{last}" in pat and not last:
                continue
            if ("{middle}" in pat or "{m}" in pat or "{l}" in pat) and not middle:
                continue
            v = (pat.replace("{first}", first).replace("{last}", last)
                    .replace("{middle}", middle).replace("{f}", f)
                    .replace("{m}", m).replace("{l}", l))
            if "{" in v:
                continue
            v = v.strip("._-")
            if v and v not in seen and len(v) >= 3:
                seen.add(v)
                candidates.append(v)
        return candidates[:12]

    def _run_userhunt_context(self, scan_id: str, username: str) -> list:
        """Check a username against enabled userhunt sites from DB.
        Returns list of confirmed profile URLs."""
        if not username:
            return []
        try:
            sites = self.db.get_userhunt_sites(enabled_only=True)
        except Exception:
            return []
        confirmed = []
        checked = 0
        for site in sites[:30]:
            url_tpl = site.get("url", "")
            if not url_tpl or "{u}" not in url_tpl:
                continue
            url       = url_tpl.replace("{u}", username)
            check_type = site.get("check_type", "status_code")
            found_status = int(site.get("found_status", 200) or 200)
            _fs_raw = (site.get("found_str", "") or "").replace("{u}", username)
            _es_raw = (site.get("error_str", "") or "").replace("{u}", username)
            found_strs = [s.strip() for s in _fs_raw.split("|") if s.strip()]
            error_strs = [s.strip() for s in _es_raw.split("|") if s.strip()]
            try:
                r = self.http.get(url, timeout=6, allow_redirects=True)
                if not r:
                    continue
                body = r.text or ""
                found = False
                if check_type == "status_code":
                    found = (r.status_code == found_status)
                elif check_type == "message":
                    has_found = any(fs.lower() in body.lower() for fs in found_strs) if found_strs else False
                    has_error = any(es.lower() in body.lower() for es in error_strs) if error_strs else False
                    found = has_found and not has_error
                elif check_type == "response_url":
                    final = r.url or url
                    has_error = any(es.lower() in final.lower() for es in error_strs) if error_strs else False
                    found = not has_error and r.status_code == 200
                if found:
                    confirmed.append({"name": site["name"], "url": url})
                checked += 1
            except Exception:
                continue
        if confirmed:
            ev_lines = [f"Active profiles for username '{username}' ({len(confirmed)}/{checked} sites checked):"]
            ev_lines.append("")
            for c in confirmed:
                ev_lines.append(f"  ✓  {c['name']:<28}  {c['url']}")
            self.db.save_finding(
                scan_id, self.NAME, "high",
                f"Context Username Hunt: '{username}' found on {len(confirmed)} platform(s)",
                f"The username '{username}' (from image optional context) was checked against "
                f"{checked} configured userhunt sites. Found on {len(confirmed)} platform(s).",
                confirmed[0]["url"],
                "\n".join(ev_lines),
                ["image", "username", "userhunt", "context", "identity"]
            )
        return [c["url"] for c in confirmed]

    def _extract_ddg_queries(self, ai_text: str) -> list:
        """Extract the 5 DDG queries Claude put in its response."""
        queries = []
        m = re.search(
            r"DDG SEARCH QUER(?:Y|IES)[^\n]*\n(.*?)(?=###|\Z)",
            ai_text, re.IGNORECASE | re.DOTALL,
        )
        if m:
            block = m.group(1)
            for line in block.split("\n"):
                q = re.sub(r"^\d+[\.\)]\s*", "", line.strip()).strip('"\'').strip()
                if len(q) > 8:
                    queries.append(q)
        return queries[:5]

    # ─── Main run ─────────────────────────────────────────────────────────────

    def run(self, scan_id: str, target: str, config: dict) -> None:
        image_path = config.get("image_path", "")
        if not image_path or not os.path.exists(image_path):
            self.emit_task(scan_id, "Image not found",
                           detail=f"Path: {image_path or '(not set)'}")
            self.db.save_finding(scan_id, self.NAME, "error",
                                 "Image File Not Found",
                                 "The uploaded image could not be located. "
                                 "Re-upload and try again.",
                                 "", f"Path checked: {image_path}", ["image", "error"])
            return

        fname = os.path.basename(image_path)
        fsize = os.path.getsize(image_path)
        api_key = config.get("anthropic_key", "")
        context = {
            "subject_name": config.get("img_subject_name", ""),
            "username":     config.get("img_username", ""),
            "email":        config.get("img_email", ""),
            "phone":        config.get("img_phone", ""),
            "keyword":      config.get("img_keyword", ""),
        }

        ai_description = ""
        ocr_text = ""
        found_coords = None
        md5_hash = None

        _log(f"[ImageOSINT] Starting analysis of {fname} ({fsize} bytes)")

        # ── Phase 1: EXIF Extraction ─────────────────────────────────────────
        self.emit_task(scan_id, "Phase 1: Extracting EXIF metadata")
        exif, gps_raw = self._exif_data(image_path)
        dims = self._image_dimensions(image_path)

        if exif or dims:
            interesting_keys = [
                "Make", "Model", "Software", "LensMake", "LensModel",
                "DateTime", "DateTimeOriginal", "DateTimeDigitized",
                "Artist", "Copyright", "ImageDescription", "UserComment",
                "XPComment", "XPAuthor", "XPTitle", "XPSubject",
                "GPSDateStamp", "GPSAltitude", "GPSSpeed",
                "HostComputer", "CameraOwnerName", "BodySerialNumber",
            ]
            exif_lines = []
            if dims:
                exif_lines.append(f"Dimensions: {dims}")
            exif_lines.append(f"File size: {fsize:,} bytes")
            for k in interesting_keys:
                if k in exif:
                    exif_lines.append(f"{k}: {exif[k]}")
            for k, v in exif.items():
                if k not in interesting_keys and not k.startswith("Exif") and k not in (
                    "ColorSpace", "FlashPixVersion", "ExifImageWidth", "ExifImageHeight",
                    "ResolutionUnit", "YCbCrPositioning", "BitsPerSample",
                ):
                    exif_lines.append(f"{k}: {v}")

            sev = "medium" if any(k in exif for k in ["Artist","Copyright","Make","Model","XPAuthor"]) else "info"
            self.db.save_finding(scan_id, self.NAME, sev,
                                 f"EXIF Metadata: {len(exif)} field(s) extracted",
                                 "Image contains embedded metadata - may reveal device, author, "
                                 "timestamps, or editing software. Identity leak risk.",
                                 image_path,
                                 "\n".join(exif_lines[:80]),
                                 ["image", "exif", "metadata"])

        # ── Phase 2: GPS Geolocation ─────────────────────────────────────────
        self.emit_task(scan_id, "Phase 2: GPS geolocation")
        if gps_raw:
            lat_raw = gps_raw.get("GPSLatitude")
            lon_raw = gps_raw.get("GPSLongitude")
            lat_ref = gps_raw.get("GPSLatitudeRef", "N")
            lon_ref = gps_raw.get("GPSLongitudeRef", "E")
            if lat_raw and lon_raw:
                lat = self._gps_to_decimal(lat_raw)
                lon = self._gps_to_decimal(lon_raw)
                if lat is not None and lon is not None:
                    if lat_ref == "S":
                        lat = -lat
                    if lon_ref == "W":
                        lon = -lon
                    found_coords = (lat, lon)
                    maps_url = f"https://maps.google.com/?q={lat:.8f},{lon:.8f}"
                    self.emit_task(scan_id, f"GPS: {lat:.6f},{lon:.6f} - reverse geocoding")
                    geo_name = self._reverse_geocode(lat, lon, scan_id)

                    alt = gps_raw.get("GPSAltitude")
                    alt_str = ""
                    if alt and hasattr(alt, "numerator"):
                        alt_str = f"\nAltitude: {alt.numerator / alt.denominator:.1f} m"

                    speed = gps_raw.get("GPSSpeed")
                    speed_str = ""
                    if speed and hasattr(speed, "numerator") and speed.numerator > 0:
                        speed_str = f"\nSpeed: {speed.numerator / speed.denominator:.1f} km/h"

                    evidence = (
                        f"Latitude:  {lat:.8f} ({lat_ref})\n"
                        f"Longitude: {lon:.8f} ({lon_ref})"
                        + alt_str + speed_str
                        + f"\nGoogle Maps: {maps_url}"
                        + (f"\nResolved:  {geo_name}" if geo_name else "")
                    )
                    self.db.save_finding(scan_id, self.NAME, "high",
                                         "GPS Coordinates Extracted from Image",
                                         f"Photo location: {geo_name or 'Unknown'}\n"
                                         f"Coordinates: {lat:.6f}, {lon:.6f}\n"
                                         f"Maps: {maps_url}",
                                         maps_url, evidence,
                                         ["image", "gps", "geolocation", "critical"])
        else:
            self.emit_task(scan_id, "GPS: no GPS data found (may have been stripped)")

        # ── Phase 3: Fingerprinting ───────────────────────────────────────────
        self.emit_task(scan_id, "Phase 3: Cryptographic + perceptual fingerprinting")
        md5_hash, sha256_hash = self._fingerprint(image_path)
        phash_val = self._phash(image_path)
        if md5_hash:
            evidence = (
                f"MD5:    {md5_hash}\n"
                f"SHA256: {sha256_hash}\n"
                f"pHash:  {phash_val or 'unavailable (Pillow resize failed)'}\n"
                f"File:   {fname}\n"
                f"Size:   {fsize:,} bytes"
            )
            self.db.save_finding(scan_id, self.NAME, "info",
                                 "Image Fingerprints (MD5 / SHA256 / pHash)",
                                 "Use these hashes to track the image across databases, "
                                 "breach dumps, and reverse image search engines. "
                                 "pHash can match visually similar images even after minor edits.",
                                 image_path, evidence,
                                 ["image", "fingerprint", "hash"])

        # ── Phase 4: OCR Text Extraction ──────────────────────────────────────
        self.emit_task(scan_id, "Phase 4: OCR text extraction")
        ocr_text = self._ocr_text(image_path)
        if ocr_text and len(ocr_text.strip()) > 5:
            self.emit_task(scan_id, f"OCR: {len(ocr_text)} characters extracted")
            self.db.save_finding(scan_id, self.NAME, "medium",
                                 f"OCR Text Extracted ({len(ocr_text)} chars)",
                                 "Readable text found in image. May contain usernames, URLs, "
                                 "credentials, addresses, or location names.",
                                 image_path, ocr_text[:4000],
                                 ["image", "ocr", "text"])
        else:
            msg = "No readable text found" if ocr_text is not None else "pytesseract not installed - install with: pip install pytesseract --break-system-packages"
            self.emit_task(scan_id, f"OCR: {msg}")

        # ── Phase 5: AI Vision Analysis ───────────────────────────────────────
        self.emit_task(scan_id, "Phase 5: AI vision analysis (Claude)")
        if api_key:
            self.emit_task(scan_id, "Sending image to Anthropic Claude for OSINT analysis")
            ai_description = self._ai_vision(image_path, context, api_key, scan_id)
            if ai_description:
                self.emit_task(scan_id, f"AI vision complete: {len(ai_description)} chars")
                self.db.save_finding(scan_id, self.NAME, "high",
                                     "AI Vision Intelligence Report (Claude)",
                                     "Claude analyzed the image and produced a structured OSINT "
                                     "report covering: scene, location, persons, visible text, "
                                     "temporal clues, social media indicators, and search queries.",
                                     image_path, ai_description[:4000],
                                     ["image", "ai", "vision", "intelligence"])
            else:
                self.emit_task(scan_id, "AI vision failed - check Anthropic API key or model access")
        else:
            self.emit_task(scan_id, "AI vision skipped - no Anthropic API key configured in scan/settings")

        # ── Phase 6: Reverse Image Search (with similarity scoring) ───────────
        # Read enabled engines from settings (defaults: yandex + bing on, tineye + google + flickr off)
        _eng_defaults = {"yandex": True, "bing": True, "tineye": False, "google": False, "flickr": False}
        _custom_engines = []
        try:
            _eng_rows = self.engine.db.one(
                "SELECT value FROM settings WHERE key='image_search_engines'")
            if _eng_rows and _eng_rows.get("value"):
                for _e in json.loads(_eng_rows["value"]):
                    if _e.get("is_default", True):
                        _eng_defaults[_e["id"]] = _e.get("enabled", False)
                    elif _e.get("enabled") and _e.get("url","").strip():
                        _custom_engines.append(_e)
        except Exception:
            pass
        _eng_label_parts = [n for n, en in [
            ("Yandex",      _eng_defaults.get("yandex")),
            ("Bing",        _eng_defaults.get("bing")),
            ("TinEye",      _eng_defaults.get("tineye")),
            ("Google Lens", _eng_defaults.get("google")),
            ("Flickr",      _eng_defaults.get("flickr")),
        ] if en]
        _eng_label_parts += [c.get("name","Custom") for c in _custom_engines]
        _eng_label = ", ".join(_eng_label_parts)
        self.emit_task(scan_id, f"Phase 6: Reverse image search ({_eng_label or 'none enabled'})")
        SIMILARITY_THRESHOLD = 60   # only report matches ≥60%

        # Compute our image's pHash bits once - used for thumbnail comparisons
        our_bits = self._phash_bits(image_path)
        rev_all = []

        if _eng_defaults.get("yandex"):
            yandex = self._reverse_yandex(image_path, scan_id, our_bits)
            if yandex:
                rev_all.extend(yandex)
                self.emit_task(scan_id, f"Yandex: {len(yandex)} result(s) - scoring similarity")
            else:
                self.emit_task(scan_id, "Yandex: no results or upload was bot-blocked")

        if _eng_defaults.get("tineye"):
            tineye = self._reverse_tineye(image_path, scan_id, our_bits)
            if tineye:
                rev_all.extend(tineye)
                self.emit_task(scan_id, f"TinEye: {len(tineye)} result(s) found")
            else:
                self.emit_task(scan_id, "TinEye: no matches found")

        if _eng_defaults.get("bing"):
            bing = self._reverse_bing(image_path, scan_id, our_bits)
            if bing:
                rev_all.extend(bing)
                self.emit_task(scan_id, f"Bing Visual: {len(bing)} result(s)")
            else:
                self.emit_task(scan_id, "Bing Visual: no results")

        if _eng_defaults.get("google"):
            google = self._reverse_google(image_path, scan_id, our_bits)
            if google:
                rev_all.extend(google)
                self.emit_task(scan_id, f"Google Lens: {len(google)} result(s)")
            else:
                self.emit_task(scan_id, "Google Lens: no results or blocked")

        if _eng_defaults.get("flickr"):
            flickr = self._reverse_flickr(image_path, scan_id, our_bits, context)
            if flickr:
                rev_all.extend(flickr)
                self.emit_task(scan_id, f"Flickr: {len(flickr)} photo(s) fetched, scoring similarity")
            else:
                self.emit_task(scan_id, "Flickr: no results returned")

        for _ce in _custom_engines:
            _ce_name = _ce.get("name","Custom Engine")
            _ce_url  = _ce.get("url","")
            _ce_built = _ce_url.replace("{image_url}", "")
            rev_all.append({
                "source":     _ce_name,
                "url":        _ce_built if _ce_built else _ce_url,
                "title":      f"{_ce_name} - manual image upload required",
                "domain":     "",
                "similarity": 0,
            })
            self.emit_task(scan_id, f"Custom engine: {_ce_name} added as reference link")

        if rev_all:
            # Separate into high-confidence (≥threshold) and reference/search links
            matched   = [m for m in rev_all if m.get("similarity", 0) >= SIMILARITY_THRESHOLD]
            reference = [m for m in rev_all if m.get("similarity", 0) < SIMILARITY_THRESHOLD]

            ev_lines = []

            # Reference links first - guarantees they appear within the 4000-char evidence cap
            if reference:
                ev_lines.append("SEARCH REFERENCE LINKS (open manually to search):")
                for m in reference:
                    ev_lines.append(f"  [{m.get('source','')}]  {m.get('url','')}")
                    if m.get("title") and m["title"] not in ("Bing Visual Search Results",
                                                              "Yandex Reverse Image Search Results"):
                        ev_lines.append(f"    ↳ {m['title']}")
                ev_lines.append("")

            if matched:
                ev_lines.append(
                    f"MATCHED IMAGES (similarity >= {SIMILARITY_THRESHOLD}%): "
                    f"{len(matched)} result(s)\n"
                )
                ev_lines.append(f"{'Sim%':<8}  {'Source':<14}  {'Domain':<28}  Page / Image URL")
                ev_lines.append("-" * 92)
                for m in sorted(matched, key=lambda x: x.get("similarity", 0), reverse=True):
                    sim_pct = m.get("similarity", 0)
                    sim_str = f"{sim_pct}%"
                    src     = m.get("source", "")[:13]
                    dom     = (m.get("domain", "") or "")[:27]
                    url     = m.get("url", "")
                    title   = m.get("title", "")[:70]
                    ev_lines.append(f"{sim_str:<8}  {src:<14}  {dom:<28}  {url}")
                    if title:
                        ev_lines.append(f"{'':6}   {'':14}  {'':28}  ↳ {title}")
                    if m.get("date"):
                        ev_lines.append(f"{'':6}   {'':14}  {'':28}  ↳ First seen: {m['date']}")
                ev_lines.append("")

            sev = "high" if matched else "medium"
            title_str = (
                f"Reverse Image Search: {len(matched)} Matched Image(s) ≥{SIMILARITY_THRESHOLD}% "
                f"+ {len(reference)} reference link(s)"
                if matched else
                f"Reverse Image Search: {len(reference)} Reference Link(s) (no ≥{SIMILARITY_THRESHOLD}% match)"
            )
            first_url = matched[0]["url"] if matched else (rev_all[0].get("url", "") if rev_all else "")
            # Store structured match data in raw_data so the UI can render thumbnails + links
            _raw_matches = {
                "matched": [
                    {
                        "url":        m.get("url", ""),
                        "thumb":      m.get("thumb", ""),
                        "similarity": m.get("similarity", 0),
                        "source":     m.get("source", ""),
                        "domain":     m.get("domain", ""),
                        "title":      m.get("title", ""),
                    }
                    for m in matched
                ],
                "reference": [
                    {
                        "url":    m.get("url", ""),
                        "source": m.get("source", ""),
                        "title":  m.get("title", ""),
                    }
                    for m in reference
                ],
            }
            self.db.save_finding(scan_id, self.NAME, sev,
                                 title_str,
                                 "Reverse image search across Yandex, TinEye, and Bing. "
                                 f"Entries with ≥{SIMILARITY_THRESHOLD}% perceptual similarity "
                                 "are shown first with source page links. "
                                 "Lower-confidence results are listed as reference links.",
                                 first_url,
                                 "\n".join(ev_lines),
                                 ["image", "reverse-search", "similarity"],
                                 raw_data=_raw_matches)
            self.emit_task(scan_id,
                           f"Reverse search complete: {len(matched)} matched ≥{SIMILARITY_THRESHOLD}%, "
                           f"{len(reference)} reference links")

        # ── Phase 7: DDG Content Search ───────────────────────────────────────
        self.emit_task(scan_id, "Phase 7: DDG content search")
        queries = []

        # 1. Queries from AI description (most accurate)
        if ai_description:
            ai_queries = self._extract_ddg_queries(ai_description)
            queries.extend(ai_queries)

        # 2. Queries from OCR text
        if ocr_text and len(ocr_text.strip()) > 5:
            clean_ocr = " ".join(ocr_text.split()[:15])
            queries.append(clean_ocr)
            # Try to detect URLs or handles in OCR
            urls_in_ocr = re.findall(r'(?:https?://\S+|www\.\S+)', ocr_text)
            queries.extend(urls_in_ocr[:2])
            handles_in_ocr = re.findall(r'@([A-Za-z0-9_.]{3,30})', ocr_text)
            for h in handles_in_ocr[:2]:
                queries.append(h + " site:twitter.com OR site:instagram.com OR site:facebook.com")

        # 3. Queries from context fields
        if context.get("subject_name"):
            sn = context["subject_name"]
            queries.insert(0, f'"{sn}" site:linkedin.com OR site:facebook.com OR site:instagram.com')
            queries.insert(1, f'"{sn}" profile photo')
            # Generate username candidates from name patterns and add as DDG queries
            _name_variants = self._expand_name_to_usernames(sn)
            for v in _name_variants[:5]:
                queries.append(
                    f'"{v}" site:github.com OR site:twitter.com OR site:instagram.com OR site:tiktok.com'
                )
        if context.get("username"):
            un = context["username"]
            queries.append(f'{un} site:instagram.com OR site:twitter.com OR site:github.com')
        if context.get("email"):
            queries.append(context["email"])
        if context.get("keyword"):
            queries.append(context["keyword"])

        # 4. Filename hint (if meaningful)
        stem = re.sub(r"[_\-.]", " ", Path(fname).stem).strip()
        if stem and len(stem) > 3 and not re.match(r"^[0-9a-f]{8,}$", stem, re.I):
            queries.append(stem)

        # 5. GPS location search
        if found_coords:
            lat, lon = found_coords
            queries.append(
                f"photos taken near {lat:.4f} {lon:.4f} "
                "site:flickr.com OR site:instagram.com OR site:twitter.com"
            )

        # 6. Hash search in breach databases
        if md5_hash:
            queries.append(f'"{md5_hash}" image')

        # Deduplicate + limit
        seen_q: set = set()
        unique_queries = []
        for q in queries:
            q = q.strip()
            if q and q not in seen_q and len(q) >= 5:
                seen_q.add(q)
                unique_queries.append(q)
        unique_queries = unique_queries[:10]

        if unique_queries:
            self.emit_task(scan_id, f"Running {len(unique_queries)} DDG search queries")
            ddg_results = self._ddg_search(unique_queries)
            if ddg_results:
                ev_lines = []
                for dr in ddg_results[:25]:
                    ev_lines.append(f"Query: {dr['query']}")
                    ev_lines.append(f"  Title:   {dr['title']}")
                    ev_lines.append(f"  URL:     {dr['url']}")
                    if dr.get("snippet"):
                        ev_lines.append(f"  Snippet: {dr['snippet'][:200]}")
                    ev_lines.append("")
                self.db.save_finding(scan_id, self.NAME, "medium",
                                     f"DDG Content Search: {len(ddg_results)} Web Hit(s)",
                                     "Web content matching image context found - check URLs for "
                                     "original source, social profiles, or related identities.",
                                     ddg_results[0]["url"] if ddg_results else "",
                                     "\n".join(ev_lines),
                                     ["image", "ddg", "search", "context"])
                self.emit_task(scan_id,
                               f"DDG complete: {len(ddg_results)} results from {len(unique_queries)} queries")
            else:
                self.emit_task(scan_id, "DDG: no relevant results found")
        else:
            self.emit_task(scan_id, "DDG: no queries generated (no AI output, OCR, or context)")

        # ── Phase 7b: Userhunt & pattern check from context ────────────────────
        _uh_username = context.get("username", "")
        _sn = context.get("subject_name", "")

        if _uh_username or _sn:
            self.emit_task(scan_id, "Phase 7b: Username platform hunt from context")

            # When only a subject name is given, generate the most likely username candidates
            _candidates: list = []
            if _uh_username:
                _candidates.append(_uh_username)
            if _sn:
                _name_cands = self._expand_name_to_usernames(_sn)
                for _c in _name_cands[:2]:
                    if _c not in _candidates:
                        _candidates.append(_c)

            _all_confirmed: list = []
            for _un in _candidates:
                self.emit_task(scan_id, f"  Checking userhunt sites for '{_un}'")
                _urls = self._run_userhunt_context(scan_id, _un)
                _all_confirmed.extend(_urls)

            # Add confirmed profile URLs to entity graph
            if _all_confirmed:
                try:
                    _scan_row = self.db.one(
                        "SELECT investigation_id FROM osint_scans WHERE id=?", (scan_id,))
                    _inv_id = _scan_row["investigation_id"] if _scan_row else None
                    if _inv_id:
                        for _cu in _all_confirmed:
                            _ent_label = _uh_username or _candidates[0] if _candidates else _cu
                            self.db.ensure_entity(
                                _inv_id, "username", _ent_label,
                                label=_ent_label, confidence=80,
                                source_module=self.NAME, scan_id=scan_id)
                except Exception:
                    pass
                self.emit_task(scan_id,
                               f"Phase 7b complete: {len(_all_confirmed)} profile(s) found "
                               f"for {len(_candidates)} candidate username(s)")
            else:
                self.emit_task(scan_id, "Phase 7b: no confirmed profiles found via userhunt sites")

        self.emit_task(scan_id, "Image OSINT complete - all phases finished")
        _log(f"[ImageOSINT] Analysis complete for {fname}")
