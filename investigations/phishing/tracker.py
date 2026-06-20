"""
FEROXSEI Phishing · Tracking Server
==================================
Lightweight Flask-based tracking endpoints that record:
  • Email opens   - via a 1×1 transparent PNG pixel
  • Link clicks   - redirect-then-track to landing page
  • Form submits  - credential capture on landing page POST

These routes are registered on the main FEROXSEI Flask app when the
phishing tracker is enabled (see feroxsei_osint.py: register_tracker_routes).

Tracking DB schema (phishing_results table):
  campaign_id, target_email, target_first, target_last,
  status (sent/opened/clicked/submitted),
  opened_at, clicked_at, submitted_at,
  ip_address, user_agent, submitted_data
"""

from __future__ import annotations
import base64
import json
import logging
from datetime import datetime
from typing import Callable, Optional

log = logging.getLogger("feroxsei.phishing.tracker")

# 1×1 transparent PNG (base64-encoded)
_PIXEL_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhf"
    "DwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
TRACKING_PIXEL_BYTES = base64.b64decode(_PIXEL_B64)


def _now() -> str:
    return datetime.now().isoformat()


# ── Event recorder ────────────────────────────────────────────────────────────

class PhishingTracker:
    """
    Records tracking events to the database.

    Parameters
    ----------
    db : OSINTDatabase
        The main app DB instance (passed from feroxsei_osint.py).
    base_url : str
        Public base URL of this FEROXSEI instance, e.g. "https://feroxsei.example.com"
        Used to generate open/click/submit tracking URLs.
    """

    def __init__(self, db, base_url: str = "http://localhost:5000"):
        self.db       = db
        self.base_url = base_url.rstrip("/")

    # ── URL builders ──────────────────────────────────────────────────────────

    def open_pixel_url(self, campaign_id: str, rid: str) -> str:
        return f"{self.base_url}/phish/track/open/{campaign_id}/{rid}.png"

    def click_url(self, campaign_id: str, rid: str, landing: str = "") -> str:
        return f"{self.base_url}/phish/track/click/{campaign_id}/{rid}"

    def submit_url(self, campaign_id: str, rid: str) -> str:
        return f"{self.base_url}/phish/track/submit/{campaign_id}/{rid}"

    # ── Event handlers ────────────────────────────────────────────────────────

    def record_open(self, campaign_id: str, rid: str, ip: str, ua: str) -> None:
        """Mark the phishing result row as opened (first open only)."""
        try:
            row = self.db.one(
                "SELECT * FROM phishing_results WHERE campaign_id=? AND id=?",
                (campaign_id, rid)
            )
            if row and row.get("status") in ("sent", None):
                self.db.exec(
                    "UPDATE phishing_results SET status='opened', opened_at=?, "
                    "ip_address=?, user_agent=? WHERE campaign_id=? AND id=?",
                    (_now(), ip, ua, campaign_id, rid)
                )
                log.info("[OPEN] campaign=%s rid=%s ip=%s", campaign_id, rid, ip)
        except Exception as e:
            log.error("record_open error: %s", e)

    def record_click(self, campaign_id: str, rid: str, ip: str, ua: str) -> Optional[str]:
        """
        Mark the result as clicked and return the campaign's landing URL.
        Returns None if campaign not found.
        """
        try:
            row = self.db.one(
                "SELECT * FROM phishing_results WHERE campaign_id=? AND id=?",
                (campaign_id, rid)
            )
            if row:
                new_status = "clicked" if row.get("status") != "submitted" else "submitted"
                self.db.exec(
                    "UPDATE phishing_results SET status=?, clicked_at=?, "
                    "ip_address=?, user_agent=? WHERE campaign_id=? AND id=?",
                    (new_status, _now(), ip, ua, campaign_id, rid)
                )
                log.info("[CLICK] campaign=%s rid=%s ip=%s", campaign_id, rid, ip)
                # Return landing page URL from campaign
                camp = self.db.one(
                    "SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,)
                )
                if camp:
                    return camp.get("landing_url") or camp.get("url")
            return None
        except Exception as e:
            log.error("record_click error: %s", e)
            return None

    def record_submit(self, campaign_id: str, rid: str, ip: str, ua: str,
                      form_data: dict) -> None:
        """Record a credential submit on the landing page."""
        try:
            self.db.exec(
                "UPDATE phishing_results SET status='submitted', submitted_at=?, "
                "ip_address=?, user_agent=?, submitted_data=? "
                "WHERE campaign_id=? AND id=?",
                (_now(), ip, ua, json.dumps(form_data), campaign_id, rid)
            )
            log.info("[SUBMIT] campaign=%s rid=%s fields=%s",
                     campaign_id, rid, list(form_data.keys()))
        except Exception as e:
            log.error("record_submit error: %s", e)

    # ── Campaign statistics ───────────────────────────────────────────────────

    def get_stats(self, campaign_id: str) -> dict:
        """Return aggregated stats for a campaign."""
        rows = self.db.rows(
            "SELECT status FROM phishing_results WHERE campaign_id=?",
            (campaign_id,)
        )
        stats = {
            "total":     len(rows),
            "sent":      0,
            "opened":    0,
            "clicked":   0,
            "submitted": 0,
        }
        for r in rows:
            s = r.get("status", "sent")
            if s in stats:
                stats[s] += 1
            # opened/clicked/submitted all count as "sent"
            if s in ("opened", "clicked", "submitted"):
                stats["sent"] += 1
        return stats


# ── Flask route registration helper ──────────────────────────────────────────

def register_tracker_routes(app, db, base_url: str = "http://localhost:5000"):
    """
    Register /phish/track/* routes on the given Flask app.
    Call this once from feroxsei_osint.py after app is created.

    Routes added:
        GET  /phish/track/open/<campaign_id>/<rid>.png   → tracking pixel
        GET  /phish/track/click/<campaign_id>/<rid>      → redirect to landing
        POST /phish/track/submit/<campaign_id>/<rid>     → credential capture
    """
    from flask import request, redirect as flask_redirect, Response

    tracker = PhishingTracker(db, base_url)

    @app.route("/phish/track/open/<campaign_id>/<rid>.png")
    def phish_track_open(campaign_id, rid):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "")
        tracker.record_open(campaign_id, rid, ip, ua)
        return Response(
            TRACKING_PIXEL_BYTES,
            mimetype="image/png",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )

    @app.route("/phish/track/click/<campaign_id>/<rid>")
    def phish_track_click(campaign_id, rid):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "")
        landing = tracker.record_click(campaign_id, rid, ip, ua)
        if landing:
            # Append campaign_id + rid so landing page JS can build the submit URL
            sep = "&" if "?" in landing else "?"
            return flask_redirect(f"{landing}{sep}cid={campaign_id}&rid={rid}")
        return flask_redirect("/")

    @app.route("/phish/track/submit/<campaign_id>/<rid>", methods=["POST"])
    def phish_track_submit(campaign_id, rid):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "")
        # Scrub credential fields - never store real passwords/tokens
        SCRUB_FIELDS = {"password","passwd","pass","pwd","secret","token","pin","ssn","cc","cvv","card"}
        form_data = {
            k: ("***REDACTED***" if any(s in k.lower() for s in SCRUB_FIELDS) else v)
            for k, v in request.form.items()
        }
        tracker.record_submit(campaign_id, rid, ip, ua, form_data)
        # Redirect to a benign page after capture
        return flask_redirect(f"/phish/awareness/{campaign_id}/{rid}")

    return tracker
