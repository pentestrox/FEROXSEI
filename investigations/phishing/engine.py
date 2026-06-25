"""
FEROXSEI Phishing · Campaign Engine
===================================
Orchestrates a full phishing campaign:
  1. Load campaign + targets + template from DB
  2. Render per-target personalised email (renderer.py)
  3. Deliver via SMTP (sender.py) - TOR-aware
  4. Inject open-tracking pixel + click-redirect URLs (tracker.py)
  5. Update phishing_results row after each send
  6. Expose live progress via campaign status field

Usage (from Flask route):
    from investigations.phishing.engine import PhishingEngine
    engine = PhishingEngine(db)
    engine.run_campaign(campaign_id)          # blocking
    engine.start_campaign(campaign_id)        # background thread
    engine.stop_campaign(campaign_id)         # signal stop
    engine.get_progress(campaign_id) → dict  # live stats
"""

from __future__ import annotations
import json
import logging
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .renderer import render_template, render_subject
from .sender   import PhishingSender
from .tracker  import PhishingTracker

log = logging.getLogger("feroxsei.phishing.engine")


def _now() -> str:
    return datetime.now().isoformat()


class PhishingEngine:
    """
    Phishing campaign runner.

    Parameters
    ----------
    db : OSINTDatabase
        Main app DB instance with .one() / .rows() / .exec() helpers.
    base_url : str
        Public URL of the FEROXSEI instance - used to build tracking URLs.
    """

    def __init__(self, db, base_url: str = "http://localhost:5000", system_smtp: dict | None = None):
        self.db          = db
        self.base_url    = base_url.rstrip("/")
        self.system_smtp = system_smtp or {}   # global SMTP cfg from app settings
        self._stop    : set[str] = set()       # campaign IDs requested to stop
        self._threads : dict[str, threading.Thread] = {}

    # ── Campaign lifecycle ────────────────────────────────────────────────────

    def start_campaign(self, campaign_id: str) -> threading.Thread:
        """Launch campaign delivery in a background thread."""
        if campaign_id in self._threads and self._threads[campaign_id].is_alive():
            log.warning("Campaign %s already running", campaign_id)
            return self._threads[campaign_id]

        self._stop.discard(campaign_id)
        t = threading.Thread(
            target=self.run_campaign,
            args=(campaign_id,),
            daemon=True,
            name=f"phish-{campaign_id[:8]}"
        )
        self._threads[campaign_id] = t
        t.start()
        log.info("Campaign %s started", campaign_id)
        return t

    def stop_campaign(self, campaign_id: str) -> None:
        """Request a running campaign to stop after the current send."""
        self._stop.add(campaign_id)
        log.info("Stop requested for campaign %s", campaign_id)

    def is_running(self, campaign_id: str) -> bool:
        t = self._threads.get(campaign_id)
        return t is not None and t.is_alive()

    def get_progress(self, campaign_id: str) -> dict:
        """Return live stats from DB for a campaign."""
        rows = self.db.rows(
            "SELECT status FROM phishing_results WHERE campaign_id=?",
            (campaign_id,)
        )
        total     = len(rows)
        sent      = sum(1 for r in rows if r.get("status") != "pending")
        opened    = sum(1 for r in rows if r.get("status") in ("opened","clicked","submitted"))
        clicked   = sum(1 for r in rows if r.get("status") in ("clicked","submitted"))
        submitted = sum(1 for r in rows if r.get("status") == "submitted")
        failed    = sum(1 for r in rows if r.get("status") == "failed")
        return {
            "total":     total,
            "sent":      sent,
            "opened":    opened,
            "clicked":   clicked,
            "submitted": submitted,
            "failed":    failed,
            "running":   self.is_running(campaign_id),
        }

    # ── Main runner ───────────────────────────────────────────────────────────

    def run_campaign(self, campaign_id: str) -> None:
        """
        Blocking campaign runner. Called in background thread by start_campaign().

        Flow:
          1. Load campaign row → sending profile → template → target list
          2. Set campaign status = 'sending'
          3. For each pending target:
               a. Render subject + HTML body
               b. Inject open-pixel + click URL
               c. Send via PhishingSender
               d. Update phishing_results status = sent / failed
          4. Set campaign status = 'completed' (or 'stopped')
        """
        try:
            self._run_impl(campaign_id)
        except Exception as e:
            log.exception("Campaign %s crashed: %s", campaign_id, e)
            self._set_campaign_status(campaign_id, "error")

    def _run_impl(self, campaign_id: str) -> None:
        # ── 1. Load campaign ──────────────────────────────────────────────────
        campaign = self.db.one(
            "SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,)
        )
        if not campaign:
            log.error("Campaign %s not found", campaign_id)
            return

        # ── ETHICAL GATE: require admin approval before any delivery ──────────
        if not campaign.get("approved_by"):
            log.error(
                "Campaign %s blocked - not approved by an administrator. "
                "An admin must approve via the campaign dashboard before launch.",
                campaign_id
            )
            self._set_campaign_status(campaign_id, "pending_approval")
            return

        template_id = campaign.get("template_id")
        template    = self.db.one(
            "SELECT * FROM phishing_templates WHERE id=?", (template_id,)
        ) if template_id else None

        if not template:
            log.error("Template not found for campaign %s", campaign_id)
            self._set_campaign_status(campaign_id, "error")
            return

        # ── 2. Load sending profile ───────────────────────────────────────────
        profile_id = campaign.get("sending_profile_id")
        profile_row = self.db.one(
            "SELECT * FROM phishing_sending_profiles WHERE id=?", (profile_id,)
        ) if profile_id else None

        # Build profile dict from the selected sending profile.
        # The global System SMTP mode only affects system emails (OTP, notifications).
        # Phishing campaigns always use their configured sending profile.
        if profile_row:
            profile = {
                "smtp_host":  profile_row.get("smtp_host", "localhost"),
                "smtp_port":  int(profile_row.get("smtp_port", 587)),
                "smtp_user":  profile_row.get("smtp_user", ""),
                "smtp_pass":  profile_row.get("smtp_password", "") or profile_row.get("smtp_pass", ""),
                "smtp_tls":   bool(profile_row.get("use_tls", True)),
                "smtp_ssl":   bool(profile_row.get("use_ssl", False)),
                "from_name":  profile_row.get("from_name", ""),
                "from_email": profile_row.get("from_address", "") or profile_row.get("from_email", ""),
                "reply_to":   profile_row.get("reply_to", ""),
                "send_delay": float(profile_row.get("send_delay", 2.0)),
            }
        else:
            # No profile - dry-run mode (log only, no actual sends)
            log.warning("No sending profile configured - dry-run mode for campaign %s", campaign_id)
            profile = {}

        # Merge TOR settings from campaign / global settings
        use_tor = bool(campaign.get("use_tor"))
        if use_tor:
            profile.update({
                "use_tor":       True,
                "tor_host":      campaign.get("tor_host", "127.0.0.1"),
                "tor_port":      int(campaign.get("tor_port", 9050)),
                "tor_ctrl_port": int(campaign.get("tor_ctrl_port", 9051)),
                "tor_ctrl_pass": campaign.get("tor_ctrl_pass", ""),
                "rotate_every":  int(campaign.get("tor_rotate_every", 10)),
            })

        send_delay = float(campaign.get("send_delay") or profile.get("send_delay") or 2.0)
        profile["send_delay"] = send_delay

        # ── 3. Build tracker + sender ─────────────────────────────────────────
        tracker = PhishingTracker(self.db, self.base_url)
        sender  = PhishingSender(profile) if profile.get("smtp_host") else None

        landing_url = campaign.get("landing_url") or ""

        # ── 4. Fetch pending targets ──────────────────────────────────────────
        targets = self.db.rows(
            "SELECT * FROM phishing_results WHERE campaign_id=? AND status='pending' "
            "ORDER BY id",
            (campaign_id,)
        )

        if not targets:
            log.info("No pending targets for campaign %s", campaign_id)
            self._set_campaign_status(campaign_id, "completed")
            return

        self._set_campaign_status(campaign_id, "sending")
        log.info("Campaign %s: sending to %d targets", campaign_id, len(targets))

        # Parse scheduled_end if set
        _sched_end_dt = None
        _sched_end_raw = (campaign.get("scheduled_end") or "").strip()
        if _sched_end_raw:
            try:
                from datetime import datetime as _dt_cls
                _sched_end_dt = _dt_cls.fromisoformat(_sched_end_raw.replace("T"," "))
            except Exception:
                pass

        sent_count = 0
        for row in targets:
            # ── Stop signal check ─────────────────────────────────────────────
            if campaign_id in self._stop:
                log.info("Campaign %s stopped after %d sends", campaign_id, sent_count)
                self._set_campaign_status(campaign_id, "stopped")
                return

            # ── Scheduled end check ───────────────────────────────────────────
            if _sched_end_dt and datetime.now() >= _sched_end_dt:
                log.info("Campaign %s auto-stopped at scheduled_end after %d sends", campaign_id, sent_count)
                self._set_campaign_status(campaign_id, "completed")
                return

            rid   = row.get("id") or str(uuid.uuid4())[:8]
            email = row.get("target_email", "")
            target = {
                "email":    email,
                "first":    row.get("target_first", ""),
                "last":     row.get("target_last", ""),
                "position": row.get("target_position", ""),
            }

            # ── Build tracking URLs ───────────────────────────────────────────
            open_px_url   = tracker.open_pixel_url(campaign_id, rid)
            click_url     = tracker.click_url(campaign_id, rid, landing_url)
            awareness_url = tracker.awareness_url(campaign_id, rid)

            # ── Render template ───────────────────────────────────────────────
            html_body = render_template(
                template.get("html_body", "") or template.get("body_html", ""),
                target=target,
                campaign_url=click_url,
                tracking_url=open_px_url,
                awareness_url=awareness_url,
                sender_name=profile.get("from_name", ""),
                rid=rid,
            )
            # Inject open-tracking pixel before </body>
            pixel_tag = f'<img src="{open_px_url}" width="1" height="1" style="display:none" alt="">'
            if "</body>" in html_body.lower():
                html_body = html_body.replace("</body>", f"{pixel_tag}\n</body>")
            else:
                html_body += f"\n{pixel_tag}"

            subject = render_subject(
                template.get("subject", ""),
                target=target,
                rid=rid,
            )

            # ── Send ──────────────────────────────────────────────────────────
            if sender:
                result = sender.send(target, html_body, subject)
                new_status = "sent" if result.get("ok") else "failed"
                send_error = "" if result.get("ok") else str(result.get("error", ""))
            else:
                # Dry-run: mark as sent without actual delivery
                new_status = "sent"
                send_error = ""
                log.info("[DRY-RUN] Would send to %s", email)

            self.db.exec(
                "UPDATE phishing_results SET status=?, sent_at=?, last_error=? "
                "WHERE campaign_id=? AND id=?",
                (new_status, _now(), send_error, campaign_id, rid)
            )
            sent_count += 1

        # ── 5. Mark campaign complete ─────────────────────────────────────────
        self._set_campaign_status(campaign_id, "completed")
        log.info("Campaign %s completed: %d emails processed", campaign_id, sent_count)

        # ── Notify campaign creator ───────────────────────────────────────────
        try:
            camp_full = self.db.one(
                "SELECT user_id, name FROM phishing_campaigns WHERE id=?",
                (campaign_id,))
            if camp_full and camp_full.get("user_id"):
                _cuid = camp_full["user_id"]
                _cname = camp_full.get("name", campaign_id)
                import uuid as _uuid_pn
                _pnid = str(_uuid_pn.uuid4())
                self.db.exec(
                    "INSERT OR IGNORE INTO notifications"
                    "(id,user_id,type,title,body,is_read,link,created_at)"
                    " VALUES(?,?,?,?,?,0,?,?)",
                    (_pnid, _cuid, "phishing",
                     f"Campaign complete: {_cname[:60]}",
                     f"Sent: {sent_count} emails",
                     f"/investigation/{campaign.get('investigation_id','')}",
                     datetime.now().isoformat())
                )
        except Exception as _pne:
            log.warning("Phishing completion notification failed: %s", _pne)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_campaign_status(self, campaign_id: str, status: str) -> None:
        try:
            self.db.exec(
                "UPDATE phishing_campaigns SET status=?, updated_at=? WHERE id=?",
                (status, _now(), campaign_id)
            )
        except Exception as e:
            log.warning("Could not update campaign status: %s", e)
