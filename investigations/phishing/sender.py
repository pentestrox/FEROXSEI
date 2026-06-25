"""
FEROXSEI Phishing · Email Sender
================================
Handles SMTP delivery with:
  • TOR SOCKS5 proxy support (via socks / socksio)
  • TOR identity rotation between batches
  • Rate limiting / send delay
  • DKIM signing (if private key provided)
  • Per-target personalised From / Reply-To spoofing
  • Bounce detection via Return-Path

Usage:
    sender = PhishingSender(profile)
    sender.send(target, rendered_html, rendered_subject)
"""

from __future__ import annotations
import smtplib
import ssl
import time
import socket
import logging
import threading
import email.policy as _email_policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate
from email.header import Header
import base64
import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional

log = logging.getLogger("feroxsei.phishing.sender")


# ── Microsoft OAuth2 token refresh ────────────────────────────────────────────

def _ms_refresh_token(client_id: str, client_secret: str,
                      tenant_id: str, refresh_token: str) -> str:
    """
    Exchange a Microsoft refresh_token for a fresh access_token.
    Requires an Azure App Registration with Mail.Send permission.
    Returns the access_token string, or raises on failure.
    """
    url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urllib.parse.urlencode({
        "client_id":     client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type":    "refresh_token",
        "scope":         "https://outlook.office365.com/SMTP.Send offline_access",
    }).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = json.loads(resp.read())
    if "access_token" not in body:
        raise RuntimeError(f"OAuth2 token refresh failed: {body.get('error_description', body)}")
    return body["access_token"]


def _xoauth2_string(user_email: str, access_token: str) -> str:
    """Build the base64-encoded XOAUTH2 SASL string for SMTP AUTH."""
    raw = f"user={user_email}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode()).decode()


# ── TOR identity rotation ─────────────────────────────────────────────────────

def _rotate_tor_identity(control_host: str = "127.0.0.1", control_port: int = 9051,
                          password: str = "") -> bool:
    """Send NEWNYM signal to TOR control port to get a fresh circuit."""
    try:
        with socket.create_connection((control_host, control_port), timeout=5) as s:
            s.sendall(b'AUTHENTICATE "' + password.encode() + b'"\r\n')
            resp = s.recv(128)
            if b"250" not in resp:
                log.warning("TOR auth failed: %s", resp)
                return False
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(128)
            return b"250" in resp
    except Exception as e:
        log.warning("TOR identity rotation failed: %s", e)
        return False


# ── SOCKS-patched socket ──────────────────────────────────────────────────────

def _make_socks_smtp(host: str, port: int, proxy_host: str = "127.0.0.1",
                     proxy_port: int = 9050) -> smtplib.SMTP:
    """
    Returns an SMTP connection tunnelled through a SOCKS5 proxy (TOR).
    Requires the 'socks' package (PySocks).
    """
    try:
        import socks
        real_socket = socks.socksocket()
        real_socket.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        real_socket.settimeout(30)
        real_socket.connect((host, port))
        smtp = smtplib.SMTP.__new__(smtplib.SMTP)
        smtplib.SMTP.__init__(smtp, timeout=30)
        smtp.sock = real_socket
        smtp.file = smtp.sock.makefile("rb")
        smtp._get_socket = lambda *a, **kw: real_socket
        smtp.ehlo_or_helo_if_needed()
        return smtp
    except ImportError:
        log.warning("PySocks not installed - falling back to direct connection")
        return smtplib.SMTP(host, port, timeout=30)


# ── Main Sender class ─────────────────────────────────────────────────────────

class PhishingSender:
    """
    SMTP email sender for phishing campaigns.

    Profile dict fields:
        smtp_host      str     SMTP server hostname
        smtp_port      int     SMTP port (25 / 465 / 587)
        smtp_user      str     Login username
        smtp_pass      str     Login password
        smtp_tls       bool    Use STARTTLS (port 587)
        smtp_ssl       bool    Use SSL/TLS wrapper (port 465)
        from_name      str     Display name in From header
        from_email     str     Sender email address
        reply_to       str     Optional Reply-To address
        use_tor        bool    Route via TOR SOCKS5
        tor_host       str     TOR SOCKS5 host (default 127.0.0.1)
        tor_port       int     TOR SOCKS5 port (default 9050)
        tor_ctrl_port  int     TOR control port (default 9051)
        tor_ctrl_pass  str     TOR control password
        send_delay     float   Seconds between sends (default 2.0)
        rotate_every   int     Rotate TOR identity every N emails (0 = never)
        dkim_key_path  str     Path to DKIM private key file (optional)
        dkim_selector  str     DKIM selector (optional)
        dkim_domain    str     DKIM signing domain (optional)
    """

    def __init__(self, profile: dict):
        self.profile = profile
        self._lock   = threading.Lock()
        self._sent   = 0

    # ── Build MIME message ────────────────────────────────────────────────────

    def _build_message(self, target: dict, subject: str, html_body: str,
                       text_body: str = "") -> MIMEMultipart:
        msg = MIMEMultipart("alternative")
        from_name  = self.profile.get("from_name", "")
        from_email = self.profile.get("from_email", "")
        reply_to   = self.profile.get("reply_to", "")

        msg["Date"]    = formatdate(localtime=True)
        msg["Subject"] = str(Header(subject, "utf-8"))
        msg["From"]    = f'"{from_name}" <{from_email}>' if from_name else from_email
        msg["To"]      = target.get("email", "")
        if reply_to:
            msg["Reply-To"] = reply_to
        msg["X-Mailer"] = "Microsoft Outlook 16.0"   # blend in

        # Plain-text fallback
        if not text_body:
            text_body = "Please view this email in an HTML-capable client."
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html",  "utf-8"))
        return msg

    # ── DKIM signing ──────────────────────────────────────────────────────────

    def _sign_message(self, msg: MIMEMultipart) -> bytes:
        """Optionally sign the raw message with DKIM."""
        # Use default compat32 serialization - it correctly base64-encodes UTF-8
        # MIMEText parts and RFC-2047-encodes Subject, so the output is ASCII-safe.
        # email.policy.SMTP (new EmailPolicy) fails on compat32-created MIME objects
        # that contain non-ASCII / emoji characters (raises 'ascii' codec error).
        # After serialisation, normalise line endings to CRLF as required by RFC 5321.
        raw = msg.as_bytes()
        raw = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        key_path = self.profile.get("dkim_key_path", "")
        selector  = self.profile.get("dkim_selector", "")
        domain    = self.profile.get("dkim_domain", "")
        if key_path and selector and domain and Path(key_path).exists():
            try:
                import dkim
                with open(key_path, "rb") as f:
                    private_key = f.read()
                sig = dkim.sign(
                    raw,
                    selector.encode(),
                    domain.encode(),
                    private_key,
                    include_headers=[b"from", b"to", b"subject"],
                )
                return sig + raw
            except ImportError:
                log.warning("dkimpy not installed - sending unsigned")
            except Exception as e:
                log.warning("DKIM signing failed: %s", e)
        return raw

    # ── SMTP connection factory ───────────────────────────────────────────────

    def _get_smtp(self) -> smtplib.SMTP:
        host = self.profile.get("smtp_host", "localhost")
        port = int(self.profile.get("smtp_port", 587))
        use_tor = self.profile.get("use_tor", False)

        if use_tor:
            tor_host = self.profile.get("tor_host", "127.0.0.1")
            tor_port = int(self.profile.get("tor_port", 9050))
            smtp = _make_socks_smtp(host, port, tor_host, tor_port)
        elif self.profile.get("smtp_ssl"):
            ctx  = ssl.create_default_context()
            smtp = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
        else:
            smtp = smtplib.SMTP(host, port, timeout=30)

        if self.profile.get("smtp_tls") and not self.profile.get("smtp_ssl"):
            smtp.starttls()

        auth_type = self.profile.get("auth_type", "basic")
        user = self.profile.get("smtp_user", "")
        pwd  = self.profile.get("smtp_pass", "")

        if auth_type == "oauth2":
            # Microsoft OAuth2 / XOAUTH2 flow
            client_id     = self.profile.get("oauth_client_id", "")
            client_secret = self.profile.get("oauth_client_secret", "")
            tenant_id     = self.profile.get("oauth_tenant_id", "common")
            refresh_token = self.profile.get("oauth_refresh_token", "")
            if not refresh_token:
                raise ValueError("OAuth2 auth_type requires oauth_refresh_token in profile")
            access_token = _ms_refresh_token(client_id, client_secret, tenant_id, refresh_token)
            xoauth_str   = _xoauth2_string(user, access_token)
            smtp.ehlo()
            smtp.docmd("AUTH", f"XOAUTH2 {xoauth_str}")
        elif user and pwd:
            smtp.login(user, pwd)

        return smtp

    # ── Public API ────────────────────────────────────────────────────────────

    def send(self, target: dict, html_body: str, subject: str,
             text_body: str = "") -> dict:
        """
        Send a phishing email to one target.

        Returns:
            {"ok": True, "rid": "...", "email": "..."}
            {"ok": False, "error": "...", "email": "..."}
        """
        email = target.get("email", "")
        delay = float(self.profile.get("send_delay", 2.0))

        with self._lock:
            # Rotate TOR identity if configured
            rotate_every = int(self.profile.get("rotate_every", 0))
            if rotate_every and self._sent and self._sent % rotate_every == 0:
                ctrl_port = int(self.profile.get("tor_ctrl_port", 9051))
                ctrl_pass = self.profile.get("tor_ctrl_pass", "")
                tor_host  = self.profile.get("tor_host", "127.0.0.1")
                rotated = _rotate_tor_identity(tor_host, ctrl_port, ctrl_pass)
                if rotated:
                    log.info("TOR identity rotated after %d sends", self._sent)
                    time.sleep(3)  # wait for new circuit

            try:
                msg = self._build_message(target, subject, html_body, text_body)
                raw = self._sign_message(msg)
                smtp = self._get_smtp()
                smtp.sendmail(
                    self.profile.get("from_email", ""),
                    [email],
                    raw,
                )
                smtp.quit()
                self._sent += 1
                log.info("Sent to %s", email)
                time.sleep(delay)
                return {"ok": True, "email": email}

            except Exception as e:
                log.error("Send failed to %s: %s", email, e)
                return {"ok": False, "email": email, "error": str(e)}

    def test_connection(self) -> dict:
        """Test SMTP connection and authentication without sending."""
        try:
            smtp = self._get_smtp()
            smtp.noop()
            smtp.quit()
            return {"ok": True, "message": "SMTP connection successful"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
