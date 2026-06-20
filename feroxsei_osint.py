#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  FEROXSEI OSINT  -  Production-Grade Intelligence Platform          ║
║  Investigation Workspace · Evidence Engine · Entity Graph        ║
║  Confidence Scoring · Contradiction Detection · Audit Trail      ║
╚══════════════════════════════════════════════════════════════════╝
Run:  python feroxsei_osint.py
URL:  http://127.0.0.1:5001
"""
from __future__ import annotations
import os, sys, json, time, uuid, hashlib, re, threading, traceback, subprocess, html as _html, ipaddress as _iplib
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse, quote

from flask import (Flask, request, jsonify, redirect, url_for,
                   session as flask_session, make_response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash

# ── Bootstrap sys.path so engine is importable ────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from feroxsei_osint_engine import OSINTDatabase, OSINTEngine, PatternEngine, _now, _extract_domain, HAS_PLAYWRIGHT

# ═════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════════════
APP_NAME    = "FEROXSEI"           # ← change this one line to rename the whole app
APP_TAGLINE = "Intelligence Platform · by PentestRox"
APP_ICON    = "⬡"
BASE_DIR   = Path(__file__).parent
DB_PATH    = str(BASE_DIR / "osint.db")
PORT       = 5001
# Docker detection - available throughout the process (not just in __main__)
IN_DOCKER  = os.path.exists("/.dockerenv")
SECRET_KEY = os.environ.get("FEROXSEI_SECRET", "feroxsei-osint-secret-2025-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

# Trust X-Forwarded-For from one upstream hop (nginx/Docker reverse proxy)
# so audit logs capture the real client IP instead of the Docker bridge IP.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db      = OSINTDatabase(DB_PATH)
engine  = OSINTEngine(db, DB_PATH)
patterns= PatternEngine(db, str(BASE_DIR / "osint_patterns.json"))

def _log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Extra DB tables for investigation platform ────────────────────────────────
def _init_extra_tables():
    db.exec("""CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        title TEXT NOT NULL, description TEXT DEFAULT '',
        target TEXT DEFAULT '', status TEXT DEFAULT 'active',
        tags TEXT DEFAULT '[]', color TEXT DEFAULT '#00d4ff',
        created_at TEXT, updated_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS evidence_items (
        id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
        scan_id TEXT DEFAULT '', module TEXT DEFAULT '',
        title TEXT NOT NULL, content TEXT DEFAULT '',
        source_url TEXT DEFAULT '', content_hash TEXT DEFAULT '',
        severity TEXT DEFAULT 'info', confidence INTEGER DEFAULT 50,
        tags TEXT DEFAULT '[]', analyst_notes TEXT DEFAULT '',
        screenshot_path TEXT DEFAULT '',
        collected_by TEXT DEFAULT '', collected_at TEXT,
        custody_chain TEXT DEFAULT '[]', is_contradiction INTEGER DEFAULT 0,
        related_entity_ids TEXT DEFAULT '[]')""")
    db.exec("""CREATE TABLE IF NOT EXISTS entities (
        id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        value TEXT NOT NULL, label TEXT DEFAULT '',
        confidence INTEGER DEFAULT 50,
        confidence_explanation TEXT DEFAULT '',
        source_modules TEXT DEFAULT '[]',
        evidence_count INTEGER DEFAULT 0,
        contradiction_count INTEGER DEFAULT 0,
        first_seen TEXT, last_seen TEXT,
        scan_ids TEXT DEFAULT '[]',
        metadata TEXT DEFAULT '{}')""")
    try:
        db.exec("ALTER TABLE entities ADD COLUMN scan_ids TEXT DEFAULT '[]'")
    except Exception:
        pass
    db.exec("""CREATE TABLE IF NOT EXISTS entity_relationships (
        id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
        source_id TEXT NOT NULL, target_id TEXT NOT NULL,
        relationship_type TEXT DEFAULT 'related',
        confidence INTEGER DEFAULT 50,
        confidence_explanation TEXT DEFAULT '',
        evidence_ids TEXT DEFAULT '[]',
        contradiction_ids TEXT DEFAULT '[]',
        created_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY, user_id TEXT, username TEXT,
        action TEXT NOT NULL, resource_type TEXT DEFAULT '',
        resource_id TEXT DEFAULT '', detail TEXT DEFAULT '',
        ip_address TEXT DEFAULT '', geo_location TEXT DEFAULT '',
        user_agent TEXT DEFAULT '', created_at TEXT)""")
    # Migrate: add geo_location + user_agent to existing audit_log tables
    for _col, _def in [("geo_location","''"), ("user_agent","''")]:
        try:
            db.exec(f"ALTER TABLE audit_log ADD COLUMN {_col} TEXT DEFAULT {_def}")
        except Exception:
            pass
    db.exec("""CREATE TABLE IF NOT EXISTS investigation_replay (
        id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
        step_number INTEGER DEFAULT 0, action_type TEXT,
        description TEXT, data TEXT DEFAULT '{}',
        analyst TEXT DEFAULT '', created_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS analyst_notes (
        id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
        evidence_id TEXT DEFAULT '', content TEXT NOT NULL,
        author TEXT DEFAULT '', linked_entities TEXT DEFAULT '[]',
        created_at TEXT, updated_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT DEFAULT '')""")
    # ── User status column (pending / active / disabled) ─────────────────────
    try:
        db.exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
    except Exception:
        pass
    # Ensure all pre-existing users are active
    db.exec("UPDATE users SET status='active' WHERE status IS NULL OR status=''")
    # ── OTP store for email-verified registration ─────────────────────────────
    db.exec("""CREATE TABLE IF NOT EXISTS otp_store (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL, email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        otp TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT)""")
    # ── Phishing engine tables ────────────────────────────────────────────────
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_templates (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        name TEXT NOT NULL, subject TEXT NOT NULL,
        html_body TEXT DEFAULT '', text_body TEXT DEFAULT '',
        category TEXT DEFAULT 'general', is_default INTEGER DEFAULT 0,
        created_at TEXT, updated_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_landing_pages (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        name TEXT NOT NULL, html_content TEXT DEFAULT '',
        capture_credentials INTEGER DEFAULT 0,
        capture_passwords INTEGER DEFAULT 0,
        redirect_url TEXT DEFAULT '', is_default INTEGER DEFAULT 0,
        created_at TEXT, updated_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_target_groups (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        investigation_id TEXT DEFAULT '',
        name TEXT NOT NULL, targets TEXT DEFAULT '[]',
        created_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_sending_profiles (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        name TEXT NOT NULL, from_name TEXT DEFAULT '',
        from_address TEXT NOT NULL, from_email TEXT DEFAULT '',
        smtp_host TEXT DEFAULT '', smtp_port INTEGER DEFAULT 587,
        smtp_user TEXT DEFAULT '', smtp_password TEXT DEFAULT '',
        use_tls INTEGER DEFAULT 1, use_ssl INTEGER DEFAULT 0,
        use_tor INTEGER DEFAULT 0, ignore_cert_errors INTEGER DEFAULT 0,
        reply_to TEXT DEFAULT '', send_delay REAL DEFAULT 2.0,
        auth_type TEXT DEFAULT 'basic',
        oauth_client_id TEXT DEFAULT '', oauth_client_secret TEXT DEFAULT '',
        oauth_tenant_id TEXT DEFAULT 'common', oauth_refresh_token TEXT DEFAULT '',
        created_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_campaigns (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        investigation_id TEXT DEFAULT '',
        name TEXT NOT NULL, status TEXT DEFAULT 'draft',
        template_id TEXT DEFAULT '', template_name TEXT DEFAULT '',
        template_subject TEXT DEFAULT '',
        landing_page_id TEXT DEFAULT '',
        target_group_id TEXT DEFAULT '', sending_profile_id TEXT DEFAULT '',
        phishing_url TEXT DEFAULT '', landing_url TEXT DEFAULT '',
        launch_date TEXT DEFAULT '', scheduled_end TEXT DEFAULT '',
        completed_date TEXT DEFAULT '',
        approved_by TEXT DEFAULT '', approved_at TEXT DEFAULT '',
        use_tor INTEGER DEFAULT 0,
        created_at TEXT, updated_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS phishing_results (
        id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL,
        target_email TEXT NOT NULL,
        target_first TEXT DEFAULT '', target_last TEXT DEFAULT '',
        target_position TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        sent_at TEXT DEFAULT '', opened_at TEXT DEFAULT '',
        clicked_at TEXT DEFAULT '', submitted_at TEXT DEFAULT '',
        submitted_data TEXT DEFAULT '{}',
        ip_address TEXT DEFAULT '', user_agent TEXT DEFAULT '',
        last_error TEXT DEFAULT '')""")
    # ── Migrations for existing DBs ───────────────────────────────────────────
    for _mig in [
        "ALTER TABLE osint_scans ADD COLUMN investigation_id TEXT DEFAULT ''",
        "ALTER TABLE investigations ADD COLUMN deleted_by_user INTEGER DEFAULT 0",
        "ALTER TABLE investigations ADD COLUMN inv_type TEXT DEFAULT 'osint'",
        "ALTER TABLE phishing_sending_profiles ADD COLUMN use_ssl INTEGER DEFAULT 0",
        "ALTER TABLE phishing_sending_profiles ADD COLUMN reply_to TEXT DEFAULT ''",
        "ALTER TABLE phishing_sending_profiles ADD COLUMN send_delay REAL DEFAULT 2.0",
        "ALTER TABLE phishing_sending_profiles ADD COLUMN from_email TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN approved_by TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN approved_at TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN landing_url TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN use_tor INTEGER DEFAULT 0",
        "ALTER TABLE phishing_campaigns ADD COLUMN template_name TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN template_subject TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN perm_osint INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_phishing INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_scans INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_patterns INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_audit INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_tor INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN perm_leaks INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN perm_settings INTEGER DEFAULT 0",
        "ALTER TABLE notifications ADD COLUMN link TEXT DEFAULT ''",
        "ALTER TABLE phishing_campaigns ADD COLUMN scheduled_end TEXT DEFAULT ''",
    ]:
        try:
            db.exec(_mig)
        except Exception:
            pass  # column already exists
    # One-time reset: existing analyst users got DEFAULT=1 for perm_* from the
    # ALTER TABLE migration - set them to NULL so they fall back to global defaults
    if not db.one("SELECT 1 FROM settings WHERE key='_perm_reset_v1'"):
        try:
            db.exec(
                "UPDATE users SET perm_osint=NULL, perm_phishing=NULL, perm_scans=NULL, "
                "perm_patterns=NULL, perm_audit=NULL, perm_tor=NULL, perm_leaks=NULL, "
                "perm_settings=NULL WHERE role='analyst'"
            )
            db.exec("INSERT OR IGNORE INTO settings(key,value) VALUES('_perm_reset_v1','1')")
        except Exception:
            pass
    # One-time fix: update over-broad patterns that caused false positives in wayback scans
    if not db.one("SELECT 1 FROM settings WHERE key='_pattern_fix_v1'"):
        try:
            db.exec(
                "UPDATE osint_patterns SET "
                "pattern=?, description=? WHERE id='op048'",
                (
                    r"(?<!\d)(?:\+1[-\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-\s][0-9]{3}[-\s][0-9]{4}(?!\d)",
                    "US phone number with proper formatting separators (dashes/spaces required to avoid matching digit sequences in URLs/filenames)"
                )
            )
            db.exec(
                "UPDATE osint_patterns SET "
                "pattern=?, description=? WHERE id='op012'",
                (
                    r"(?i)(?:heroku[_\-\s]*(?:api[_\-\s]*key|token|secret|key)[_\-\s]*[=:\s]+['\"]?|HEROKU_API_KEY=['\"]?)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                    "Heroku API Key with required context keyword - prevents false positives on generic UUIDs in URLs and filenames"
                )
            )
            db.exec("INSERT OR IGNORE INTO settings(key,value) VALUES('_pattern_fix_v1','1')")
        except Exception:
            pass
    # ── Chat tables ──────────────────────────────────────────────────────────
    db.exec("""CREATE TABLE IF NOT EXISTS chat_channels (
        id TEXT PRIMARY KEY, name TEXT NOT NULL,
        type TEXT DEFAULT 'group',
        created_by TEXT DEFAULT '', created_at TEXT)""")
    db.exec("""CREATE TABLE IF NOT EXISTS chat_members (
        channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
        joined_at TEXT,
        PRIMARY KEY (channel_id, user_id))""")
    db.exec("""CREATE TABLE IF NOT EXISTS chat_messages (
        id TEXT PRIMARY KEY, channel_id TEXT NOT NULL,
        user_id TEXT NOT NULL, username TEXT NOT NULL,
        content TEXT NOT NULL, created_at TEXT)""")
    # Seed a General channel if none exists
    try:
        if not db.one("SELECT id FROM chat_channels WHERE name='General'"):
            _gen_cid = str(uuid.uuid4())
            db.exec(
                "INSERT INTO chat_channels(id,name,type,created_by,created_at) VALUES(?,?,?,?,?)",
                (_gen_cid, "General", "group", "system", _now())
            )
    except Exception:
        pass
    # Seed default settings
    for k, v in [
        ("tor_enabled","0"), ("tor_user_disabled","0"),
        ("tor_socks_host","127.0.0.1"),
        ("tor_socks_port","9050"), ("anthropic_key",""),
        ("openai_key",""), ("github_token",""), ("shodan_key",""),
        ("virustotal_key",""), ("hunter_key",""), ("hibp_key",""),
        ("otx_key",""), ("abuseipdb_key",""),
        ("phishing_public_url",""),
        ("default_crawl_depth","2"), ("default_modules",
         '["wayback","certTransparency","dns","webCrawl","gitLeaks",'
         '"googleDork","infrastructure","threatIntel","aiOsint"]'),
    ]:
        try:
            db.exec("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(k,v))
        except Exception:
            pass
    # ── Analyst role permission flags (defaults for newly registered users) ─────
    for k, v in [
        ("analyst_perm_scans",    "1"),   # create/run scans
        ("analyst_perm_patterns", "1"),   # view/use patterns
        ("analyst_perm_audit",    "1"),   # view audit log
        ("analyst_perm_tor",      "1"),   # use TOR anonymous mode
        ("analyst_perm_osint",    "1"),   # access OSINT investigations
        ("analyst_perm_phishing", "1"),   # access phishing investigations
        ("analyst_perm_leaks",    "0"),   # access search leaks (off by default)
        ("analyst_perm_settings", "0"),   # access settings pages (off by default)
        ("leak_directories",      "[]"),  # JSON list of leak data directories
    ]:
        try:
            db.exec("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        except Exception:
            pass
    # ── Auto-create default admin account if no users exist ──────────────────
    if db.one("SELECT id FROM users LIMIT 1") is None:
        try:
            db.ins("users", {
                "id": "admin-default",
                "username": "admin",
                "email": "admin@feroxsei.local",
                "password_hash": generate_password_hash("admin"),
                "role": "admin",
                "api_keys": "{}",
                "created_at": _now()
            })
        except Exception:
            pass

_init_extra_tables()

def _seed_userhunt_sites():
    from investigations.osint.modules.username_hunt import SITES as _BUILTIN_SITES
    count = db.seed_userhunt_sites(_BUILTIN_SITES)
    if count:
        pass

try:
    _seed_userhunt_sites()
except Exception:
    pass

def _seed_image_engines():
    _builtin_defaults = [
        {"id":"yandex",   "name":"Yandex Images",      "enabled":True,  "is_default":True,  "note":"Upload → full match + pHash similarity (recommended)", "url":""},
        {"id":"bing",     "name":"Bing Visual Search",  "enabled":True,  "is_default":True,  "note":"Upload → returns search results URL (React SPA)",        "url":""},
        {"id":"tineye",   "name":"TinEye",              "enabled":False, "is_default":True,  "note":"Exact/near-exact match - may return 403 from some IPs",  "url":""},
        {"id":"google",   "name":"Google Lens",         "enabled":False, "is_default":True,  "note":"Upload → experimental, may require CAPTCHA from some IPs","url":""},
        {"id":"flickr",   "name":"Flickr Photo Search", "enabled":False, "is_default":True,  "note":"Public photo feed search by context tags + pHash thumbnail similarity","url":""},
    ]
    _seeded_customs = [
        {"id":"custom_1", "name":"SauceNAO",         "enabled":True, "is_default":False, "note":"Anime/manga/artwork reverse search",        "url":"https://saucenao.com/search.php?url={image_url}"},
        {"id":"custom_2", "name":"OSINT.Industries", "enabled":True, "is_default":False, "note":"Person/face OSINT lookup",                  "url":"https://osint.industries/results#image={image_url}"},
        {"id":"custom_3", "name":"PimEyes",          "enabled":True, "is_default":False, "note":"Facial recognition reverse image search",   "url":"https://pimeyes.com/en/results?url={image_url}"},
    ]
    existing_raw = _get_setting("image_search_engines", "")
    if not existing_raw:
        _save_setting("image_search_engines", json.dumps(_builtin_defaults + _seeded_customs))
        return
    try:
        existing = json.loads(existing_raw)
        existing_ids = {e["id"] for e in existing}
        added = False
        for c in _seeded_customs:
            if c["id"] not in existing_ids:
                existing.append(c)
                added = True
        if added:
            _save_setting("image_search_engines", json.dumps(existing))
    except Exception:
        pass

try:
    _seed_image_engines()
except Exception:
    pass

# ── Default username/email combination patterns ───────────────────────────────
# Placeholders: {first} {last} {middle} {f}=first-letter-of-first {m}=first-letter-of-middle {l}=first-letter-of-last
_DEFAULT_USERNAME_PATTERNS = [
    ("{first}.{last}",         "First.Last",                    "john.doe"),
    ("{f}.{last}",             "F.Last  (1st letter + last)",   "j.doe"),
    ("{f}{last}",              "FLast  (no separator)",         "jdoe"),
    ("{first}{last}",           "FirstLast  (no separator)",    "johndoe"),
    ("{first}_{last}",          "First_Last",                   "john_doe"),
    ("{last}.{first}",          "Last.First",                   "doe.john"),
    ("{last}{f}",               "LastF",                        "doej"),
    ("{last}_{first}",          "Last_First",                   "doe_john"),
    ("{first}",                 "First name only",              "john"),
    ("{last}",                  "Last name only",               "doe"),
    ("{first}.{m}.{last}",      "First.M.Last  (middle initial)", "john.m.doe"),
    ("{f}.{m}.{last}",          "F.M.Last  (both initials)",    "j.m.doe"),
    ("{first}{m}{last}",        "FirstMLast  (no separator)",   "johnmdoe"),
    ("{f}{m}{last}",            "FMLast  (initials + last)",    "jmdoe"),
    ("{first}{last}{l}",        "FirstLastL  (last initial)",   "johndoed"),
]

def _seed_username_patterns():
    db.seed_username_patterns(_DEFAULT_USERNAME_PATTERNS)

try:
    _seed_username_patterns()
except Exception:
    pass

# ── Default phishing templates ────────────────────────────────────────────────
_DEFAULT_PHISHING_TEMPLATES = [
    {
        "id": "phish-tpl-001",
        "name": "IT Security Alert - Password Expiry",
        "category": "IT",
        "subject": "Action Required: Your {{.Company}} password expires in 24 hours",
        "html_body": """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0">
<table width="100%" bgcolor="#f4f4f4"><tr><td align="center" style="padding:30px 0">
<table width="600" bgcolor="#ffffff" style="border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
  <tr><td bgcolor="#0078d4" style="padding:24px 32px">
    <p style="color:#fff;font-size:22px;font-weight:700;margin:0">🔐 IT Security Notice</p>
    <p style="color:#c8e6ff;font-size:13px;margin:4px 0 0">{{.Company}} Information Security Team</p>
  </td></tr>
  <tr><td style="padding:32px">
    <p style="font-size:15px;color:#333">Dear <strong>{{.FirstName}}</strong>,</p>
    <p style="color:#555;line-height:1.6">Our records indicate your corporate account password will <strong style="color:#d32f2f">expire within 24 hours</strong>. To avoid losing access to company systems, please reset your password immediately.</p>
    <table align="center" style="margin:24px auto"><tr><td bgcolor="#0078d4" style="border-radius:5px">
      <a href="{{.URL}}" style="color:#fff;text-decoration:none;padding:12px 28px;display:block;font-weight:600;font-size:14px">Reset Password Now →</a>
    </td></tr></table>
    <p style="color:#888;font-size:12px">If you did not request this, please contact IT Support immediately at it-support@{{.Company}}.com<br>This link expires in 24 hours.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <p style="font-size:11px;color:#aaa">{{.Company}} IT Security Department · This is an automated message · {{.TrackingURL}}</p>
  </td></tr>
</table></td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-002",
        "name": "HR - Benefits Open Enrollment",
        "category": "HR",
        "subject": "⏰ Last Chance: Benefits Enrollment Closes Friday",
        "html_body": """<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8f8f8;margin:0">
<table width="100%"><tr><td align="center" style="padding:24px">
<table width="580" bgcolor="#ffffff" style="border-radius:8px;border:1px solid #e8e8e8">
  <tr><td bgcolor="#2e7d32" style="padding:20px 28px;border-radius:8px 8px 0 0">
    <p style="color:#fff;font-size:20px;font-weight:700;margin:0">👤 HR Benefits Portal</p>
    <p style="color:#c8e6c9;font-size:12px;margin:4px 0 0">{{.Company}} Human Resources</p>
  </td></tr>
  <tr><td style="padding:28px">
    <p style="font-size:15px;color:#222">Hi <strong>{{.FirstName}} {{.LastName}}</strong>,</p>
    <p style="color:#444;line-height:1.7">The annual <strong>Benefits Open Enrollment period closes this <span style="color:#c62828">Friday at 5:00 PM</span></strong>. Employees who do not make their elections will be automatically enrolled in the default plan.</p>
    <p style="color:#444">Please log in to review and update your elections for:</p>
    <ul style="color:#444;line-height:2">
      <li>Health, Dental &amp; Vision Insurance</li>
      <li>401(k) Contribution Rate</li>
      <li>Life &amp; Disability Insurance</li>
      <li>Flexible Spending Accounts (FSA/HSA)</li>
    </ul>
    <table align="center" style="margin:20px auto"><tr><td bgcolor="#2e7d32" style="border-radius:5px">
      <a href="{{.URL}}" style="color:#fff;text-decoration:none;padding:11px 26px;display:block;font-weight:600">Access Benefits Portal →</a>
    </td></tr></table>
    <p style="font-size:11px;color:#aaa;margin-top:20px">Questions? Contact HR at hr@{{.Company}}.com | {{.TrackingURL}}</p>
  </td></tr>
</table></td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-003",
        "name": "Microsoft - Unusual Sign-in Activity",
        "category": "Cloud",
        "subject": "Microsoft account: Unusual sign-in activity detected",
        "html_body": """<!DOCTYPE html><html><body style="font-family:'Segoe UI',Tahoma,sans-serif;background:#f3f3f3;margin:0">
<table width="100%"><tr><td align="center" style="padding:20px">
<table width="560" bgcolor="#ffffff" style="border:1px solid #ddd">
  <tr><td style="padding:18px 24px;border-bottom:3px solid #0078d4">
    <span style="font-size:20px;font-weight:600;color:#0078d4">Microsoft</span>
  </td></tr>
  <tr><td style="padding:28px 24px">
    <p style="font-size:22px;color:#222;margin-bottom:4px">Review your account activity</p>
    <p style="color:#666;font-size:13px">Please review this notice for {{.Email}}</p>
    <div style="background:#fff8e1;border-left:4px solid #ffb300;padding:12px 16px;margin:20px 0;border-radius:2px">
      <strong style="color:#e65100">⚠ Unusual sign-in</strong><br>
      <span style="font-size:13px;color:#555">A sign-in was attempted from a location we don't recognize.</span>
    </div>
    <table style="width:100%;border:1px solid #eee;border-radius:4px;font-size:13px;color:#444">
      <tr><td style="padding:8px 12px;background:#fafafa;font-weight:600;width:140px">Country/region</td><td style="padding:8px 12px">Unknown / Tor Network</td></tr>
      <tr><td style="padding:8px 12px;background:#fafafa;font-weight:600">IP address</td><td style="padding:8px 12px">185.220.xxx.xxx</td></tr>
      <tr><td style="padding:8px 12px;background:#fafafa;font-weight:600">Date &amp; time</td><td style="padding:8px 12px">{{.Date}} (UTC)</td></tr>
      <tr><td style="padding:8px 12px;background:#fafafa;font-weight:600">Platform</td><td style="padding:8px 12px">Linux / Unknown Browser</td></tr>
    </table>
    <p style="color:#444;margin-top:16px">If this was you, you can ignore this message. If you don't recognise this activity, please secure your account now.</p>
    <table align="center" style="margin:20px auto"><tr><td bgcolor="#0078d4" style="border-radius:3px">
      <a href="{{.URL}}" style="color:#fff;text-decoration:none;padding:10px 24px;display:block;font-weight:600">Review Activity</a>
    </td></tr></table>
    <p style="font-size:11px;color:#aaa">Microsoft Corporation · One Microsoft Way · Redmond WA · {{.TrackingURL}}</p>
  </td></tr>
</table></td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-004",
        "name": "CEO - Urgent Wire Transfer Request",
        "category": "Executive",
        "subject": "Confidential - Urgent wire transfer needed today",
        "html_body": """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#fff;margin:0;padding:20px">
<div style="max-width:520px;margin:0 auto">
  <p style="color:#333;font-size:14px">Hi {{.FirstName}},</p>
  <p style="color:#333;font-size:14px;line-height:1.7">I need you to process an urgent wire transfer today. I'm in back-to-back meetings and I need this done before the markets close at 4 PM.</p>
  <p style="color:#333;font-size:14px;line-height:1.7">Please log into the payments portal and process a transfer of <strong>$47,500</strong> to our new vendor. The details are in the secure document I've shared.</p>
  <div style="background:#f5f5f5;border-radius:4px;padding:12px 16px;margin:16px 0">
    <a href="{{.URL}}" style="color:#0066cc;font-size:14px;font-weight:600">→ View Secure Payment Document</a>
  </div>
  <p style="color:#333;font-size:14px;line-height:1.7">This is time-sensitive and confidential - please do not discuss with other team members until completed. I'll explain everything after the board meeting.</p>
  <p style="color:#333;font-size:14px">Thanks,<br><strong>{{.CEO}}</strong><br>Chief Executive Officer, {{.Company}}</p>
  <p style="font-size:10px;color:#ccc;margin-top:24px">Sent from mobile · {{.TrackingURL}}</p>
</div></body></html>""",
    },
    {
        "id": "phish-tpl-005",
        "name": "Package Delivery - Action Required",
        "category": "Delivery",
        "subject": "Your package could not be delivered - action required",
        "html_body": """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0">
<table width="100%"><tr><td align="center" style="padding:20px">
<table width="560" bgcolor="#ffffff" style="border-radius:6px;overflow:hidden">
  <tr><td bgcolor="#f4a700" style="padding:18px 24px">
    <span style="font-size:20px;font-weight:700;color:#333">📦 Delivery Notification</span>
  </td></tr>
  <tr><td style="padding:28px 24px">
    <p style="font-size:16px;color:#222;font-weight:600">We attempted to deliver your package</p>
    <p style="color:#555;line-height:1.6">Dear <strong>{{.FirstName}}</strong>, we attempted delivery of your package at <strong>{{.Date}}</strong> but were unable to complete the delivery. A small customs/handling fee is required to reschedule delivery.</p>
    <div style="background:#fff3e0;border:1px solid #ffcc80;border-radius:4px;padding:12px 16px;margin:16px 0">
      <p style="margin:0;color:#e65100;font-size:13px"><strong>Tracking:</strong> TRACK-{{.TrackID}} &nbsp;|&nbsp; <strong>Fee:</strong> $2.99 &nbsp;|&nbsp; <strong>Deadline:</strong> 48 hours</p>
    </div>
    <table align="center" style="margin:20px auto"><tr><td bgcolor="#f4a700" style="border-radius:5px">
      <a href="{{.URL}}" style="color:#333;text-decoration:none;padding:11px 26px;display:block;font-weight:700">Pay &amp; Reschedule Delivery →</a>
    </td></tr></table>
    <p style="font-size:11px;color:#aaa">If you did not order anything, disregard this message · {{.TrackingURL}}</p>
  </td></tr>
</table></td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-006",
        "name": "IT - VPN Access Credential Update",
        "category": "IT",
        "subject": "[IT NOTICE] VPN gateway migration - update credentials by EOD",
        "html_body": """<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f0f0f0;margin:0">
<table width="100%"><tr><td align="center" style="padding:24px">
<table width="580" bgcolor="#ffffff" style="border-radius:6px;border:1px solid #ddd">
  <tr><td bgcolor="#263238" style="padding:20px 28px;border-radius:6px 6px 0 0">
    <p style="color:#00bcd4;font-size:18px;font-weight:700;margin:0">🔒 {{.Company}} IT Operations</p>
    <p style="color:#90a4ae;font-size:12px;margin:4px 0 0">Secure Infrastructure Team</p>
  </td></tr>
  <tr><td style="padding:28px">
    <p style="font-size:15px;color:#222">Hello <strong>{{.FirstName}}</strong>,</p>
    <p style="color:#444;line-height:1.7">As part of our scheduled <strong>VPN infrastructure migration</strong>, all remote access credentials must be re-verified by <strong>end of business today</strong>.</p>
    <p style="color:#444;line-height:1.7">Employees who do not complete re-verification will lose VPN access at <strong>6:00 PM EST</strong>.</p>
    <div style="background:#e8f5e9;border-left:3px solid #43a047;padding:10px 14px;margin:16px 0;font-size:13px;color:#2e7d32">
      ✅ This takes less than 60 seconds. Your existing password remains unchanged.
    </div>
    <table align="center" style="margin:20px auto"><tr><td bgcolor="#263238" style="border-radius:5px">
      <a href="{{.URL}}" style="color:#00bcd4;text-decoration:none;padding:11px 26px;display:block;font-weight:600">Verify VPN Credentials →</a>
    </td></tr></table>
    <p style="font-size:11px;color:#bbb;margin-top:16px">Reference ticket: INC-{{.TicketID}} · Questions: it-support@{{.Company}}.com · {{.TrackingURL}}</p>
  </td></tr>
</table></td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-007",
        "name": "Google - Verify Your Account",
        "category": "Clone Login",
        "subject": "Security alert: Unusual sign-in attempt on your Google Account",
        "html_body": """<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#fff;font-family:'Google Sans',Roboto,Arial,sans-serif;color:#202124}</style></head>
<body style="padding:0;margin:0;background:#f1f3f4">
<table width="100%" bgcolor="#f1f3f4"><tr><td align="center" style="padding:30px 10px">
<table width="480" bgcolor="#ffffff" style="border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.2)">
  <tr><td style="padding:40px 40px 28px;text-align:center">
    <!-- Google Logo -->
    <svg viewBox="0 0 272 92" width="80" xmlns="http://www.w3.org/2000/svg"><path fill="#EA4335" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#FBBC05" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#4285F4" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/><path fill="#34A853" d="M225 3v65h-9.5V3h9.5z"/><path fill="#EA4335" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/></svg>
    <p style="font-size:24px;color:#202124;margin:20px 0 8px;font-weight:400">Verify your identity</p>
    <p style="color:#5f6368;font-size:14px">A sign-in attempt requires further verification</p>
  </td></tr>
  <tr><td style="padding:0 40px 28px">
    <div style="background:#fce8e6;border-left:4px solid #d93025;padding:12px 16px;border-radius:4px;margin-bottom:20px">
      <p style="color:#d93025;font-size:13px;font-weight:600">⚠ Unusual activity detected</p>
      <p style="color:#3c4043;font-size:13px;margin-top:4px">We noticed a sign-in attempt from an unrecognized device. Please verify it's you.</p>
    </div>
    <p style="color:#3c4043;font-size:14px;margin-bottom:6px">Sign-in details</p>
    <table width="100%" style="background:#f8f9fa;border-radius:4px;padding:12px;margin-bottom:20px">
      <tr><td style="font-size:13px;color:#5f6368;padding:4px 0">Account</td><td style="font-size:13px;color:#202124;font-weight:500">{{.Email}}</td></tr>
      <tr><td style="font-size:13px;color:#5f6368;padding:4px 0">Time</td><td style="font-size:13px;color:#202124">{{.Time}}</td></tr>
      <tr><td style="font-size:13px;color:#5f6368;padding:4px 0">Location</td><td style="font-size:13px;color:#202124">Unknown location</td></tr>
    </table>
    <table align="center" style="margin:0 auto 20px"><tr>
      <td bgcolor="#1a73e8" style="border-radius:4px"><a href="{{.URL}}" style="color:#fff;text-decoration:none;padding:10px 24px;display:block;font-size:14px;font-weight:500">Verify it's you</a></td>
    </tr></table>
    <p style="color:#5f6368;font-size:12px;text-align:center">If you didn't try to sign in, <a href="{{.URL}}" style="color:#1a73e8">secure your account</a></p>
    <p style="color:#fff;font-size:1px">{{.TrackingURL}}</p>
  </td></tr>
  <tr><td style="padding:16px 40px;border-top:1px solid #e0e0e0;text-align:center">
    <p style="font-size:11px;color:#5f6368">Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043</p>
  </td></tr>
</table>
</td></tr></table></body></html>""",
    },
    {
        "id": "phish-tpl-008",
        "name": "Microsoft - Verify Sign-In",
        "category": "Clone Login",
        "subject": "Microsoft account security alert - action required",
        "html_body": """<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f2f2f2;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif">
<table width="100%" bgcolor="#f2f2f2"><tr><td align="center" style="padding:20px 10px">
<table width="500" bgcolor="#ffffff" style="border:1px solid #d2d2d2">
  <!-- MS Header -->
  <tr><td style="padding:20px 30px;background:#0078d4">
    <svg xmlns="http://www.w3.org/2000/svg" width="108" height="24" viewBox="0 0 108 24">
      <rect x="0" y="0" width="11" height="11" fill="#f25022"/><rect x="12" y="0" width="11" height="11" fill="#7fba00"/>
      <rect x="0" y="12" width="11" height="11" fill="#00a4ef"/><rect x="12" y="12" width="11" height="11" fill="#ffb900"/>
      <text x="28" y="17" fill="#fff" font-size="16" font-family="Segoe UI,Arial">Microsoft</text>
    </svg>
  </td></tr>
  <tr><td style="padding:32px 30px 20px">
    <p style="font-size:22px;font-weight:300;color:#1b1b1b;margin:0 0 16px">Review recent activity</p>
    <p style="color:#444;font-size:14px;line-height:1.6">Dear <strong>{{.FirstName}}</strong>,</p>
    <p style="color:#444;font-size:14px;line-height:1.6;margin:12px 0">We detected unusual activity on your Microsoft account <strong>{{.Email}}</strong>. Please review and verify this activity to keep your account secure.</p>
    <table width="100%" style="background:#f9f9f9;border:1px solid #e0e0e0;border-radius:2px;padding:16px;margin:16px 0">
      <tr><td style="font-size:13px;color:#666;padding:4px 0;width:120px">When</td><td style="font-size:13px;color:#1b1b1b">Today at {{.Time}}</td></tr>
      <tr><td style="font-size:13px;color:#666;padding:4px 0">Platform</td><td style="font-size:13px;color:#1b1b1b">Windows 11</td></tr>
      <tr><td style="font-size:13px;color:#666;padding:4px 0">Browser</td><td style="font-size:13px;color:#1b1b1b">Chrome / Unknown</td></tr>
      <tr><td style="font-size:13px;color:#666;padding:4px 0">IP address</td><td style="font-size:13px;color:#1b1b1b">Unknown location</td></tr>
    </table>
    <p style="color:#444;font-size:14px;margin-bottom:20px">If this was you, you can safely dismiss this alert. If you don't recognise this activity, please verify your account immediately.</p>
    <table><tr>
      <td bgcolor="#0078d4" style="border-radius:2px;margin-right:8px"><a href="{{.URL}}" style="color:#fff;text-decoration:none;padding:10px 22px;display:block;font-size:14px;font-weight:500">Review activity</a></td>
      <td width="10"></td>
      <td style="border:1px solid #0078d4;border-radius:2px"><a href="{{.URL}}" style="color:#0078d4;text-decoration:none;padding:10px 22px;display:block;font-size:14px">No, it wasn't me</a></td>
    </tr></table>
    <p style="color:#fff;font-size:1px">{{.TrackingURL}}</p>
  </td></tr>
  <tr><td style="padding:16px 30px;background:#f2f2f2;border-top:1px solid #d2d2d2">
    <p style="font-size:11px;color:#737373">Microsoft Corporation · One Microsoft Way · Redmond, WA 98052</p>
    <p style="font-size:11px;color:#737373;margin-top:4px">This is an automated message. <a href="{{.URL}}" style="color:#0078d4">Unsubscribe</a> from security alerts.</p>
  </td></tr>
</table>
</td></tr></table></body></html>""",
    },
]

def _seed_phishing_templates():
    for t in _DEFAULT_PHISHING_TEMPLATES:
        try:
            db.exec("""INSERT OR IGNORE INTO phishing_templates
                (id,user_id,name,subject,html_body,category,is_default,created_at,updated_at)
                VALUES(?,?,?,?,?,?,1,?,?)""",
                (t["id"],"system",t["name"],t["subject"],t["html_body"],
                 t["category"],_now(),_now()))
        except Exception:
            pass

try:
    _seed_phishing_templates()
except Exception:
    pass

# ── Load API keys from environment variables (Docker / CI mode) ───────────────
def _load_env_settings():
    """
    If env vars are set, write them into the DB settings so the app picks them
    up without manual UI configuration. Already-set DB values are NOT overwritten
    (env vars are treated as defaults, not overrides).
    """
    _ENV_MAP = {
        "ANTHROPIC_KEY":   "anthropic_key",
        "OPENAI_KEY":      "openai_key",
        "GITHUB_TOKEN":    "github_token",
        "SHODAN_KEY":      "shodan_key",
        "VIRUSTOTAL_KEY":  "virustotal_key",
        "HUNTER_KEY":      "hunter_key",
        "HIBP_KEY":        "hibp_key",
        "OTX_KEY":         "otx_key",
        "ABUSEIPDB_KEY":   "abuseipdb_key",
        "FLASK_SECRET":    None,               # handled separately
        # TOR docker env
        "TOR_SOCKS_HOST":  "tor_socks_host",
        "TOR_SOCKS_PORT":  "tor_socks_port",
    }
    for env_key, db_key in _ENV_MAP.items():
        if db_key is None:
            continue
        val = os.environ.get(env_key, "").strip()
        if not val:
            continue
        existing = db.one("SELECT value FROM settings WHERE key=?", (db_key,))
        if not existing or not existing["value"]:
            db.exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                    (db_key, val))
    # If running in Docker with external TOR service, auto-enable TOR
    if os.environ.get("TOR_EXTERNAL","") == "1":
        existing = db.one("SELECT value FROM settings WHERE key='tor_enabled'")
        if not existing or not existing["value"]:
            db.exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                    ("tor_enabled", "1"))

_load_env_settings()

# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════
def _get_setting(key, default=""):
    r = db.one("SELECT value FROM settings WHERE key=?", (key,))
    return r["value"] if r else default

def _save_setting(key, value):
    db.exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))

# ── Geo-IP lookup cache (IP → "City, Country" string) ────────────────────────
_geo_cache: dict = {}

# ── Public IP helpers ─────────────────────────────────────────────────────────
_server_pub_ip_cache: dict = {"ip": "", "fetched": False}

def _get_server_public_ip() -> str:
    """Fetch and cache the server's own public IP (runs once, background-safe).
    In a Docker-on-same-host setup, this equals the client's public IP."""
    if _server_pub_ip_cache["fetched"]:
        return _server_pub_ip_cache["ip"]
    _server_pub_ip_cache["fetched"] = True  # mark before trying (avoid repeat on failure)
    import urllib.request as _urlreq, re as _re2
    for url in [
        "https://api.ipify.org?format=text",
        "https://api4.ipify.org?format=text",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    ]:
        try:
            req = _urlreq.Request(url, headers={"User-Agent": "curl/7.0"})
            with _urlreq.urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip and _re2.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    _server_pub_ip_cache["ip"] = ip
                    return ip
        except Exception:
            continue
    return ""

def _is_private_ip(ip: str) -> bool:
    """True if ip is RFC-1918/loopback/link-local (i.e. not a public internet address)."""
    try:
        import ipaddress as _ipa
        # Strip hop-chain decoration if present
        raw = ip.split("→")[0].strip().split(" ")[0]
        a = _ipa.ip_address(raw)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False

def _geo_lookup(ip: str) -> str:
    """Return 'City, Country' for an IP address (cached, non-blocking best-effort)."""
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return "Local"
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        import requests as _req
        resp = _req.get(f"http://ip-api.com/json/{ip}?fields=status,city,country,regionName",
                        timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            geo = ", ".join(filter(None, [data.get("city",""), data.get("regionName",""), data.get("country","")]))
        else:
            geo = ""
    except Exception:
        geo = ""
    _geo_cache[ip] = geo
    return geo


def _docker_default_gateway() -> str:
    """Read the actual default gateway from /proc/net/route (accurate for any Docker network).
    Returns the gateway IP string, e.g. '192.168.16.1', or '' on failure."""
    try:
        with open("/proc/net/route") as _f:
            for _line in _f:
                _parts = _line.split()
                if len(_parts) >= 3 and _parts[1] == "00000000":   # destination 0.0.0.0 = default
                    _b = bytes.fromhex(_parts[2])                   # little-endian hex → bytes
                    return f"{_b[3]}.{_b[2]}.{_b[1]}.{_b[0]}"
    except Exception:
        pass
    return ""


def _mailhog_default_host() -> str:
    """Best-guess MailHog hostname for the current runtime environment.

    Priority:
    1. MAILHOG_HOST env var  (set by docker-compose.yml → 'mailhog')
    2. DNS resolution of 'mailhog' succeeds (service on same Docker network)
    3. Docker default gateway from /proc/net/route  (standalone docker run)
    4. 'localhost'  (bare-metal / dev)
    """
    import os as _os2, socket as _sock
    # 1. Explicit env var (docker-compose sets MAILHOG_HOST=mailhog)
    env_host = _os2.environ.get("MAILHOG_HOST", "").strip()
    if env_host:
        return env_host
    if not IN_DOCKER:
        return "localhost"
    # 2. Try Docker Compose service name via DNS
    try:
        _sock.gethostbyname("mailhog")
        return "mailhog"
    except Exception:
        pass
    # 3. Gateway IP (for standalone 'docker run -p 1025:1025 mailhog/mailhog')
    gw = _docker_default_gateway()
    return gw if gw else "172.17.0.1"


def _sys_smtp_cfg() -> dict:
    """Return system SMTP configuration from settings. Mode: 'mailhog' or 'custom'."""
    mode = _get_setting("sys_smtp_mode", "mailhog")
    from_addr = _get_setting("sys_smtp_from", "feroxsei@localhost") or "feroxsei@localhost"
    if mode == "mailhog":
        # Resolve best MailHog host: env var → Docker Compose DNS → gateway → localhost
        default_mhog = _mailhog_default_host()
        saved_host   = _get_setting("sys_smtp_mailhog_host", "").strip()
        mhog_host    = saved_host if saved_host else default_mhog
        import os as _os3
        mhog_port    = int(_os3.environ.get("MAILHOG_PORT","") or
                           _get_setting("sys_smtp_mailhog_port", "1025") or 1025)
        return {
            "mode":     "mailhog",
            "host":     mhog_host,
            "port":     mhog_port,
            "user":     "",
            "password": "",
            "from":     from_addr,
            "tls":      False,
            "ssl":      False,
        }
    return {
        "mode":     "custom",
        "host":     _get_setting("sys_smtp_host",  ""),
        "port":     int(_get_setting("sys_smtp_port", "587")),
        "user":     _get_setting("sys_smtp_user",  ""),
        "password": _get_setting("sys_smtp_pass",  ""),
        "from":     from_addr,
        "tls":      _get_setting("sys_smtp_tls",   "0") == "1",
        "ssl":      _get_setting("sys_smtp_ssl",   "0") == "1",
    }

def _smtp_is_enabled() -> bool:
    """True if email sending is enabled and SMTP is usable."""
    if _get_setting("sys_email_enabled", "1") != "1":
        return False  # master switch explicitly off
    mode = _get_setting("sys_smtp_mode", "mailhog")
    if mode == "mailhog":
        return True   # MailHog is always considered available
    # Custom mode only ready if host is configured
    return bool(_get_setting("sys_smtp_host", "").strip())


def _send_system_email(to_addr: str, subject: str, body_html: str, body_text: str = "") -> tuple[bool, str]:
    """Send a system email (OTP / approval notification). Returns (ok, error_msg)."""
    import smtplib, email.policy as _epol
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.utils import formatdate
    cfg = _sys_smtp_cfg()
    if not cfg.get("host"):
        return False, "SMTP host not configured. Set MailHog host or Custom SMTP host in Settings → General."
    from_addr = cfg["from"] or "feroxsei@localhost"
    try:
        msg = MIMEMultipart("alternative")
        msg["Date"]    = formatdate(localtime=True)
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        if body_text:
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))
        if cfg["ssl"]:
            s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=10)
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=10)
        if cfg["tls"]:
            s.starttls()
        if cfg["user"]:
            s.login(cfg["user"], cfg["password"])
        s.sendmail(from_addr, [to_addr], msg.as_bytes(policy=_epol.SMTP))
        s.quit()
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _audit(action, resource_type="", resource_id="", detail=""):
    uid   = flask_session.get("uid","")
    uname = flask_session.get("username","anon")
    ua    = request.headers.get("User-Agent","")[:300]

    # JS-reported public IP (browser called /api/client-ip after page loaded)
    js_public_ip = (flask_session.get("client_public_ip","") or "").strip()

    # Build hop chain from HTTP headers
    xff    = request.headers.get("X-Forwarded-For","").strip()
    remote = (request.remote_addr or "").strip()
    for hdr in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
        val = request.headers.get(hdr,"").strip()
        if val:
            xff = val + (", " + xff if xff else "")
            break
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if remote and (not hops or hops[-1] != remote):
            hops.append(remote)
        ip_chain  = " → ".join(hops)
        client_ip = hops[0]
    else:
        ip_chain  = remote
        client_ip = remote

    # ── Public IP resolution ──────────────────────────────────────────────
    # Priority 1: JS-reported public IP (browser fetched from ipify/etc.)
    # Priority 2: Server-side public IP lookup - valid when client and server
    #             run on the same host (typical Docker-on-laptop setup).
    # Priority 3: Whatever headers gave us (may be Docker bridge / private).
    real_public = ""
    if js_public_ip and not _is_private_ip(js_public_ip):
        real_public = js_public_ip          # browser told us
    elif _is_private_ip(client_ip):
        # client_ip is a Docker/private address - look up server's public IP
        # in a background thread so we don't block the request
        pass  # handled below in _do_insert

    import threading as _thr
    def _do_insert(chain, cli, audit_ua, pre_public):
        pub = pre_public
        if not pub and _is_private_ip(cli):
            # Lazy server-side lookup (cached after first call)
            pub = _get_server_public_ip()

        if pub and pub != cli:
            chain = pub + " → " + chain if chain else pub
            cli   = pub

        geo = _geo_lookup(cli)
        db.ins("audit_log", {
            "id": str(uuid.uuid4()), "user_id": uid, "username": uname,
            "action": action, "resource_type": resource_type,
            "resource_id": resource_id, "detail": detail[:500],
            "ip_address": chain, "geo_location": geo,
            "user_agent": audit_ua, "created_at": _now()
        })
    _thr.Thread(target=_do_insert,
                args=(ip_chain, client_ip, ua, real_public),
                daemon=True).start()

def _notify(user_id, type_, title, body, link=""):
    """Insert a real-time notification for a user. Runs in background thread."""
    import threading as _nth
    def _ins():
        try:
            db.exec(
                "INSERT INTO notifications(id,user_id,type,title,body,is_read,link,created_at) VALUES(?,?,?,?,?,0,?,?)",
                (str(uuid.uuid4()), user_id, type_, title[:200], body[:500], link, _now())
            )
        except Exception:
            pass
    _nth.Thread(target=_ins, daemon=True).start()

def _notify_admins(type_, title, body, link=""):
    """Notify all admin users."""
    try:
        admins = db.rows("SELECT id FROM users WHERE role='admin' AND status='active'")
        for a in admins:
            _notify(a["id"], type_, title, body, link)
    except Exception:
        pass

def _replay_step(inv_id, action_type, description, data=None, analyst=""):
    steps = db.one("SELECT COUNT(*) as c FROM investigation_replay WHERE investigation_id=?",
                   (inv_id,))
    n = (steps["c"] if steps else 0) + 1
    db.ins("investigation_replay", {
        "id": str(uuid.uuid4()), "investigation_id": inv_id,
        "step_number": n, "action_type": action_type,
        "description": description, "data": json.dumps(data or {}),
        "analyst": analyst, "created_at": _now()
    })

def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]

def _confidence_score(evidence_count, source_diversity, contradictions, recency_days=0):
    score = 40
    score += min(source_diversity * 12, 30)
    score += min(evidence_count * 4, 20)
    if recency_days < 7:   score += 10
    elif recency_days < 30: score += 5
    score -= contradictions * 18
    return max(0, min(100, score))

def _severity_color(sev):
    return {"critical":"#ff1744","high":"#ff5722","medium":"#ffab00",
            "low":"#69f0ae","info":"#40c4ff"}.get(sev, "#90a4ae")

# ═════════════════════════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════════════════════════
def _user_is_live(uid):
    """Returns True only if user exists in DB and status is 'active'.
    Called on every authenticated request - if admin deletes or deactivates
    a user, their next request is immediately denied regardless of session."""
    u = db.one("SELECT status FROM users WHERE id=?", (uid,))
    return u is not None and (u.get("status") or "active") == "active"

def _parse_ua(ua_string):
    """Return (browser, os_name) from a User-Agent string."""
    ua = ua_string or ""
    if "Edg/" in ua or "EdgA/" in ua:
        browser = "Edge"
    elif "OPR/" in ua or "Opera/" in ua:
        browser = "Opera"
    elif "Chrome/" in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome" not in ua:
        browser = "Safari"
    elif "curl/" in ua:
        browser = "curl"
    else:
        browser = "Unknown"
    if "Windows NT 10" in ua or "Windows NT 11" in ua:
        os_name = "Windows 10/11"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "iPhone" in ua:
        os_name = "iOS (iPhone)"
    elif "iPad" in ua:
        os_name = "iOS (iPad)"
    elif "Android" in ua:
        os_name = "Android"
    elif "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown"
    return browser, os_name

def _create_session(uid, username):
    """Create a new user_sessions row and store token in Flask session."""
    import secrets as _sec
    token = _sec.token_urlsafe(32)
    flask_session["session_token"] = token
    ua   = request.headers.get("User-Agent", "")
    # Prefer JS-reported public IP (_cip field, already validated + stored in session)
    # This avoids showing the Docker gateway IP (172.x) for all users
    ip   = (flask_session.get("client_public_ip") or
            request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip())
    browser, os_name = _parse_ua(ua)
    geo  = _geo_lookup(ip) if ip and ip not in ("127.0.0.1", "::1") else "Local"
    now  = _now()
    db.exec(
        "INSERT OR REPLACE INTO user_sessions "
        "(token, user_id, username, ip_address, geo_location, user_agent, browser, os_name, created_at, last_active) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (token, uid, username, ip, geo, ua, browser, os_name, now, now)
    )

def _touch_session():
    """Update last_active and validate session token still exists in DB.
    Returns False if the token has been revoked (admin destroy / logout-all)."""
    token = flask_session.get("session_token")
    if not token:
        return True  # legacy session before feature - allow through
    row = db.one("SELECT token FROM user_sessions WHERE token=?", (token,))
    if not row:
        return False  # revoked - force re-login
    db.exec("UPDATE user_sessions SET last_active=? WHERE token=?", (_now(), token))
    return True

def _revoke_session(token):
    """Delete a single session token from DB."""
    db.exec("DELETE FROM user_sessions WHERE token=?", (token,))

def _revoke_all_sessions(uid, keep_token=None):
    """Delete all sessions for a user except keep_token (current session)."""
    if keep_token:
        db.exec("DELETE FROM user_sessions WHERE user_id=? AND token!=?", (uid, keep_token))
    else:
        db.exec("DELETE FROM user_sessions WHERE user_id=?", (uid,))

def require_login(f):
    @wraps(f)
    def inner(*a, **kw):
        uid = flask_session.get("uid")
        if not uid:
            return redirect(url_for("login", next=request.url))
        if not _user_is_live(uid):
            flask_session.clear()
            return redirect(url_for("login"))
        if not _touch_session():
            flask_session.clear()
            return redirect(url_for("login"))
        return f(*a, **kw)
    return inner

def require_api_auth(f):
    @wraps(f)
    def inner(*a, **kw):
        uid = flask_session.get("uid")
        if not uid:
            return jsonify({"error": "unauthenticated"}), 401
        if not _user_is_live(uid):
            flask_session.clear()
            return jsonify({"error": "session invalid - account deactivated or deleted"}), 401
        if not _touch_session():
            flask_session.clear()
            return jsonify({"error": "session revoked"}), 401
        return f(*a, **kw)
    return inner

def require_admin(f):
    """Decorator: allow only admin-role users, redirect others to dashboard."""
    @wraps(f)
    def inner(*a, **kw):
        uid = flask_session.get("uid")
        if not uid:
            return redirect(url_for("login", next=request.url))
        if not _user_is_live(uid):
            flask_session.clear()
            return redirect(url_for("login"))
        if not _touch_session():
            flask_session.clear()
            return redirect(url_for("login"))
        if flask_session.get("role") != "admin":
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return inner

def _is_admin():
    return flask_session.get("role") == "admin"


_PORTAL_OPEN_PREFIXES = ("/phish/", "/static/")

@app.before_request
def _portal_ip_allowlist():
    for _pfx in _PORTAL_OPEN_PREFIXES:
        if request.path.startswith(_pfx):
            return None
    allowed_raw = _get_setting("portal_allowed_ips", "").strip()
    if not allowed_raw:
        return None
    client_ip = request.remote_addr or ""
    try:
        client_addr = _iplib.ip_address(client_ip)
        for _cidr in [r.strip() for r in allowed_raw.replace("\n", ",").split(",") if r.strip()]:
            try:
                if client_addr in _iplib.ip_network(_cidr, strict=False):
                    return None
            except ValueError:
                continue
    except ValueError:
        pass
    _cip_esc = _html.escape(client_ip)
    return (f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Access Restricted</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
background:#0d1117;color:#e6edf3;display:flex;align-items:center;
justify-content:center;min-height:100vh;padding:20px}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:12px;
padding:48px 40px;max-width:480px;width:100%;text-align:center}}
h1{{font-size:22px;font-weight:700;color:#f85149;margin:0 0 16px}}
p{{color:#8b949e;font-size:14px;line-height:1.7;margin:0 0 10px}}
code{{background:#21262d;color:#58a6ff;padding:2px 8px;border-radius:4px;font-size:13px}}
</style></head><body><div class="box">
<div style="font-size:48px;margin-bottom:16px">&#128274;</div>
<h1>Access Restricted</h1>
<p>This portal is restricted to authorised IP addresses.</p>
<p>Your IP: <code>{_cip_esc}</code></p>
<p style="margin-top:20px;font-size:12px;color:#484f58">
Contact your administrator for access.</p>
</div></body></html>"""), 403


def _perm_row(label: str, key, checked: bool, editable: bool = True,
              always_on: bool = False, admin_only: bool = False) -> str:
    """Render one row of the analyst permissions table."""
    # Analyst column
    if admin_only:
        analyst_cell = '<span style="color:#ef4444;font-size:15px">✕</span>'
    elif always_on:
        analyst_cell = ('<span style="color:#64748b;font-size:13px" title="Always granted">🔒 Always</span>')
    elif editable and key:
        chk = 'checked' if checked else ''
        analyst_cell = (
            f'<label style="display:inline-flex;align-items:center;gap:6px;cursor:pointer">'
            f'<input type="checkbox" name="perm_{key}" value="1" {chk}'
            f' style="width:16px;height:16px;accent-color:#6366f1;cursor:pointer">'
            f'</label>'
        )
    else:
        analyst_cell = '<span style="color:#64748b">-</span>'

    # Admin column - always ticked
    admin_cell = '<span style="color:#4ade80;font-size:15px">✓</span>'

    return (f'<tr style="border-bottom:1px solid var(--border)">'
            f'<td style="padding:10px 14px;color:var(--text)">{label}'
            + (f' <span style="color:var(--muted);font-size:10px">(admin only)</span>' if admin_only else '')
            + f'</td>'
            f'<td style="padding:10px 14px;text-align:center">{analyst_cell}</td>'
            f'<td style="padding:10px 14px;text-align:center">{admin_cell}</td>'
            f'</tr>')

def _analyst_can(perm: str) -> bool:
    """Return True if the current user is allowed to use `perm`.
    Admins are always allowed.
    For analysts: checks per-user perm_<perm> column (takes precedence),
    then falls back to the global analyst_perm_<perm> setting.
    """
    if _is_admin():
        return True
    uid = flask_session.get("uid", "")
    if uid:
        row = db.one(f"SELECT perm_{perm} FROM users WHERE id=?", (uid,))
        if row and row.get(f"perm_{perm}") is not None:
            return bool(row[f"perm_{perm}"])
    return _get_setting(f"analyst_perm_{perm}", "1") == "1"

def _first_run():
    return db.one("SELECT id FROM users LIMIT 1") is None

# ═════════════════════════════════════════════════════════════════════════════
# TOR BADGE SCRIPT  (injected into every page)
# ═════════════════════════════════════════════════════════════════════════════
_TOR_SCRIPT = """
<style>
#tor-badge{display:inline-flex;align-items:center;gap:8px;padding:4px 12px;
  border-radius:20px;border:1px solid #1e3a5f;cursor:pointer;
  background:#0a1220;transition:all .3s;font-family:'JetBrains Mono',monospace;user-select:none}
#tb-dot{font-size:10px;transition:color .3s}
#tb-main{display:flex;flex-direction:column;line-height:1.2}
#tb-label{font-size:9px;color:#334155;letter-spacing:1.5px;text-transform:uppercase}
#tb-info{font-size:11px;font-weight:600;transition:color .3s}
#tb-meta{font-size:9px;color:#475569}
#tor-modal{display:none;position:fixed;inset:0;z-index:9999;
  background:rgba(0,0,0,.75);align-items:center;justify-content:center}
#tor-modal-inner{background:#0a0f1a;border:1px solid #1e3a5f;border-radius:14px;
  padding:24px;max-width:580px;width:96%;max-height:88vh;overflow-y:auto;
  box-shadow:0 12px 50px rgba(0,0,0,.9)}
</style>
<script>
document.addEventListener("DOMContentLoaded",function(){
  if(document.getElementById("tor-badge"))return;
  var topRight=document.querySelector(".topbar-right");
  if(topRight){
    var badge=document.createElement("div");
    badge.id="tor-badge";badge.title="TOR Anonymous Mode - click for circuit";
    badge.innerHTML=[
      '<span id="tb-dot">&#x25CF;</span>',
      '<div id="tb-main">',
      '  <span id="tb-label">ANON MODE</span>',
      '  <span id="tb-info">Disabled</span>',
      '  <span id="tb-meta"></span>',
      '</div>'
    ].join("");
    badge.addEventListener("click",function(){openTorModal();});
    topRight.insertBefore(badge,topRight.firstChild);
  }
  var modal=document.createElement("div");
  modal.id="tor-modal";
  modal.innerHTML=[
    '<div id="tor-modal-inner">',
    '  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px">',
    '    <div style="display:flex;align-items:center;gap:10px">',
    '      <span style="font-size:20px">&#x1F9C5;</span>',
    '      <h3 style="color:#f1f5f9;margin:0;font-size:16px">TOR Anonymous Mode</h3>',
    '    </div>',
    '    <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap" id="tor-modal-btns">',
    '      <button onclick="torCheckDeps()" title="Check dependencies &amp; show install guide"',
    '        style="background:#0f172a;border:1px solid #334155;color:#94a3b8;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer">',
    '        &#x2699; Deps</button>',
    '      <button onclick="document.getElementById(\\'tor-modal\\').style.display=\\'none\\'"',
    '        style="background:none;border:none;color:#64748b;font-size:20px;cursor:pointer;line-height:1;margin-left:4px">&#x2715;</button>',
    '    </div>',
    '  </div>',
    '  <div id="tor-modal-body" style="color:#94a3b8;font-size:13px">Loading&#x2026;</div>',
    '</div>'
  ].join("");
  document.body.appendChild(modal);
  /* Inject admin-only action buttons if the current user is an admin */
  if(window._torIsAdmin){
    var _btnBar=document.getElementById("tor-modal-btns");
    if(_btnBar){
      var _adminBtns=[
        '<button id="tm-start" onclick="torModalAction(\\'start\\')" style="background:#14532d;border:1px solid #16a34a;color:#86efac;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer">&#x25B6; Start</button>',
        '<button id="tm-newnym" onclick="torModalAction(\\'newnym\\')" style="background:#1e3a5f;border:1px solid #4338ca;color:#818cf8;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer">&#x1F504; New Identity</button>',
        '<button onclick="torRefreshIP()" title="Force-refresh source IP &amp; exit IP" style="background:#0f172a;border:1px solid #334155;color:#94a3b8;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer">&#x1F5A7; Refresh IP</button>',
        '<button id="tm-stop" onclick="torModalAction(\\'stop\\')" style="background:#451a03;border:1px solid #b45309;color:#fcd34d;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer">&#x23F9; Stop</button>',
        '<button id="tm-panic" onclick="torModalAction(\\'panic\\')" style="background:#7f1d1d;border:1px solid #dc2626;color:#fca5a5;border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer;font-weight:bold">&#x1F6A8; Panic</button>'
      ];
      var _firstChild=_btnBar.firstChild;
      _adminBtns.forEach(function(btnHtml){
        var _tmp=document.createElement("div");
        _tmp.innerHTML=btnHtml;
        _btnBar.insertBefore(_tmp.firstChild,_firstChild);
      });
    }
  }
  var _C={
    disabled:    {dot:"#334155",border:"#1e3a5f",text:"#475569"},
    connecting:  {dot:"#f59e0b",border:"#92400e",text:"#fbbf24"},
    connected:   {dot:"#22c55e",border:"#166534",text:"#4ade80"},
    disconnected:{dot:"#ef4444",border:"#7f1d1d",text:"#f87171"},
    error:       {dot:"#ef4444",border:"#7f1d1d",text:"#f87171"},
    unavailable: {dot:"#334155",border:"#1e3a5f",text:"#475569"},
  };
  function updateBadge(d){
    var st=d.status||"unavailable",col=_C[st]||_C.unavailable;
    var b=document.getElementById("tor-badge");if(!b)return;
    b.style.borderColor=col.border;
    var dot=document.getElementById("tb-dot");if(dot)dot.style.color=col.dot;
    var info=document.getElementById("tb-info");
    if(info){info.style.color=col.text;
      if(!d.enabled){info.textContent="Disabled";}
      else if(st==="connected"){info.textContent="TOR: Connected"+(d.exit_ip?" | "+d.exit_ip:"");}
      else if(st==="connecting"){info.textContent="TOR: Connecting…";}
      else{info.textContent="TOR: "+st.charAt(0).toUpperCase()+st.slice(1);}
    }
    var meta=document.getElementById("tb-meta");
    if(meta){
      if(d.enabled&&st==="connected"){
        var parts=[];
        if(d.exit_country)parts.push(d.exit_country);
        if(d.hop_count)parts.push(d.hop_count+" hops");
        if(d.latency_ms)parts.push(d.latency_ms+"ms");
        meta.style.color="#64748b";meta.textContent=parts.join(" • ");
      }else{meta.textContent="";}
    }
    if(b){b.style.boxShadow=st==="connected"?"0 0 8px rgba(34,197,94,.25)":
      st==="connecting"?"0 0 8px rgba(245,158,11,.2)":
      (st==="disconnected"||st==="error")?"0 0 8px rgba(239,68,68,.25)":"none";}
  }
  function pollTor(){
    fetch("/api/tor/status").then(function(r){return r.json();}).then(updateBadge).catch(function(){});
  }
  pollTor();setInterval(pollTor,7000);
  window.openTorModal=function(){
    document.getElementById("tor-modal").style.display="flex";
    var body=document.getElementById("tor-modal-body");
    body.innerHTML="<p style='color:#64748b;text-align:center;padding:20px'>Loading circuit…</p>";
    Promise.all([
      fetch("/api/tor/circuit").then(function(r){return r.json();}),
      fetch("/api/tor/status").then(function(r){return r.json();})
    ]).then(function(res){renderCircuit(body,res[0],res[1]);})
      .catch(function(e){body.innerHTML="<p style='color:#ef4444'>Error: "+e+"</p>";});
  };
  var _fastPollTimer=null;
  function startFastPoll(secs){
    if(_fastPollTimer)clearInterval(_fastPollTimer);
    var ticks=secs*2;
    _fastPollTimer=setInterval(function(){pollTor();if(--ticks<=0){clearInterval(_fastPollTimer);_fastPollTimer=null;}},500);
  }
  
  function renderInstallGuide(body, d) {
    var guide = d.install_guide || d.message || "";
    var missing = d.missing || [];
    var html = "<div style='background:#1a0a00;border:1px solid #b45309;border-radius:10px;padding:16px;margin-bottom:14px'>";
    html += "<div style='color:#fbbf24;font-size:13px;font-weight:bold;margin-bottom:10px'>&#x26A0; TOR Dependencies Missing</div>";
    if(missing.length){
      html += "<div style='color:#94a3b8;font-size:11px;margin-bottom:8px'>Missing: "+missing.map(function(m){return"<span style='color:#f87171;background:#7f1d1d;padding:2px 6px;border-radius:4px;margin:2px;display:inline-block'>"+m+"</span>";}).join(" ")+"</div>";
    }
    if(guide){
      html += "<pre style='background:#0a0f1a;border:1px solid #334155;border-radius:6px;padding:12px;color:#86efac;font-size:11px;overflow-x:auto;white-space:pre-wrap;margin:8px 0'>"+guide+"</pre>";
    }
    html += "<div style='display:flex;gap:8px;margin-top:12px'>";
    html += "<button onclick='torAutoInstall()' style='background:#14532d;border:1px solid #16a34a;color:#86efac;border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer'>&#x25B6; Auto-Install</button>";
    html += "<button onclick='torCheckDeps()' style='background:#1e3a5f;border:1px solid #4338ca;color:#818cf8;border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer'>&#x21BA; Re-Check</button>";
    html += "</div></div>";
    body.innerHTML = html;
  }
  window.torAutoInstall = function(){
    var body = document.getElementById("tor-modal-body");
    body.innerHTML = "<p style='color:#f59e0b;text-align:center;padding:20px'>&#x23F3; Installing TOR dependencies… this may take 1-2 minutes…</p>";
    fetch("/api/tor/install",{method:"POST"}).then(function(r){return r.json();})
      .then(function(d){
        if(d.ok){
          body.innerHTML = "<div style='background:#14532d;border:1px solid #16a34a;border-radius:8px;padding:14px;color:#86efac'>&#x2713; All TOR dependencies installed successfully! Click Start to connect.</div>";
          startFastPoll(5);
        } else {
          var html = "<div style='color:#f87171;margin-bottom:10px'>&#x2717; Auto-install incomplete: "+(d.message||"")+"</div>";
          if(d.results){Object.entries(d.results).forEach(function(kv){
            var col = kv[1].ok ? "#4ade80" : "#f87171";
            html += "<div style='color:"+col+";font-size:11px;margin:3px 0'>"+kv[0]+": "+(kv[1].ok?"OK":"FAILED - "+kv[1].output.slice(-100))+"</div>";
          });}
          html += "<p style='color:#94a3b8;font-size:11px;margin-top:10px'>Run the commands manually in your terminal, then click Re-Check.</p>";
          html += "<button onclick='torCheckDeps()' style='background:#1e3a5f;border:1px solid #4338ca;color:#818cf8;border-radius:6px;padding:5px 12px;font-size:11px;cursor:pointer;margin-top:8px'>&#x21BA; Re-Check</button>";
          body.innerHTML = html;
        }
      }).catch(function(e){body.innerHTML="<p style='color:#ef4444'>Install error: "+e+"</p>";});
  };
  window.torCheckDeps = function(){
    var body = document.getElementById("tor-modal-body");
    body.innerHTML = "<p style='color:#64748b;text-align:center;padding:16px'>Checking dependencies…</p>";
    fetch("/api/tor/check_deps").then(function(r){return r.json();})
      .then(function(d){
        if(d.ok){
          var html = "<div style='background:#14532d;border:1px solid #16a34a;border-radius:8px;padding:12px;color:#86efac;margin-bottom:10px'>&#x2713; All TOR dependencies are installed and ready.</div>";
          html += "<div style='display:grid;grid-template-columns:repeat(2,1fr);gap:6px'>";
          Object.entries(d.deps||{}).forEach(function(kv){
            var ok=kv[1].installed,col=ok?"#4ade80":"#f87171";
            html += "<div style='background:#0f172a;border:1px solid "+(ok?"#166534":"#7f1d1d")+";border-radius:6px;padding:8px'>";
            html += "<span style='color:"+col+"'>"+(ok?"&#x2713;":"&#x2717;")+" "+kv[0]+"</span>";
            if(!ok)html += "<div style='color:#64748b;font-size:10px;margin-top:3px'>"+kv[1].install+"</div>";
            html += "</div>";
          });
          html += "</div>";
          body.innerHTML = html;
        } else {
          renderInstallGuide(body, d);
        }
      }).catch(function(e){body.innerHTML="<p style='color:#ef4444'>Error: "+e+"</p>";});
  };
  window.torRefreshIP = function(){
    var body = document.getElementById("tor-modal-body");
    body.innerHTML = "<p style='color:#64748b;text-align:center;padding:16px'>&#x23F3; Refreshing IP addresses… (takes 3-8s)</p>";
    fetch("/api/tor/refresh_ip",{method:"POST"}).then(function(r){return r.json();})
      .then(function(d){
        var html = "<div style='background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:14px'>";
        html += "<div style='color:#4ade80;margin-bottom:8px'>&#x2713; "+d.message+"</div>";
        if(d.current_source_ip) html += "<div style='color:#94a3b8;font-size:12px'>Source IP: <span style='color:#f1f5f9;font-weight:bold'>"+d.current_source_ip+"</span></div>";
        if(d.current_exit_ip)   html += "<div style='color:#94a3b8;font-size:12px;margin-top:4px'>Exit IP: <span style='color:#f1f5f9;font-weight:bold'>"+d.current_exit_ip+"</span></div>";
        html += "</div><p style='color:#475569;font-size:11px;margin-top:8px;text-align:center'>Polling for updated values…</p>";
        body.innerHTML = html;
        startFastPoll(10);
        setTimeout(window.openTorModal, 10000);
      }).catch(function(e){body.innerHTML="<p style='color:#ef4444'>Error: "+e+"</p>";});
  };
  
  function _doTorAction(action,body,btn){
    body.innerHTML="<p style='color:#f59e0b;text-align:center;padding:16px'>&#x23F3; "+action+" in progress…</p>";
    fetch("/api/tor/"+action,{method:"POST"}).then(function(r){return r.json();})
      .then(function(d){
        if (action === 'newnym' && window._invalidateTorCircuitCache)
          window._invalidateTorCircuitCache();
        
        if(d.ok===false && d.install_guide){
          renderInstallGuide(body, d);
          if(btn)btn.disabled=false;
          return;
        }
        var msg=d.message||d.error||JSON.stringify(d,null,2),col=d.ok===false?"#f87171":"#4ade80";
        body.innerHTML="<div style='background:#051015;border:1px solid #1e3a5f;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:"+col+";white-space:pre-wrap'>"+msg+"</div>"+
          "<p style='color:#475569;font-size:11px;margin-top:10px;text-align:center'>Status polling every 0.5s…</p>";
        if(btn)btn.disabled=false;startFastPoll(30);setTimeout(window.openTorModal,13000);
      }).catch(function(e){body.innerHTML="<p style='color:#ef4444'>Error: "+e+"</p>";if(btn)btn.disabled=false;});
  }
  window.torModalAction=function(action){
    var btn=document.getElementById("tm-"+action);if(btn)btn.disabled=true;
    var body=document.getElementById("tor-modal-body");
    if(action==="newnym"){
      body.innerHTML="<p style='color:#64748b;text-align:center;padding:16px'>Checking TOR status…</p>";
      fetch("/api/tor/status").then(function(r){return r.json();})
        .then(function(st){
          if(st.status!=="connected"){
            body.innerHTML="<p style='color:#f59e0b;text-align:center;padding:16px'>&#x25B6; TOR not connected - starting…</p>";
            startFastPoll(15);
            fetch("/api/tor/start",{method:"POST"}).then(function(r){return r.json();})
              .then(function(sd){
                if(sd.ok===false){
                  if(sd.install_guide){renderInstallGuide(body,sd);}
                  else{body.innerHTML="<p style='color:#ef4444'>Start failed: "+(sd.error||sd.message)+"</p>";}
                  if(btn)btn.disabled=false;
                }else{_doTorAction("newnym",body,btn);}
              }).catch(function(e){body.innerHTML="<p style='color:#ef4444'>Start error: "+e+"</p>";if(btn)btn.disabled=false;});
          }else{_doTorAction("newnym",body,btn);}
        }).catch(function(){_doTorAction("newnym",body,btn);});
    }else{_doTorAction(action,body,btn);}
  };
  
  function renderCircuit(el,data,st){
    var nodes=data.nodes||[],html="";
    var stColor=st.status==="connected"?"#4ade80":st.status==="connecting"?"#fbbf24":"#f87171";
    
    html+="<div style='display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:18px'>";
    [{l:"STATUS",v:(st.status||"-").toUpperCase(),c:stColor},
     {l:"SOURCE IP",v:st.source_ip||"-",c:"#a5b4fc"},
     {l:"EXIT IP",  v:st.exit_ip||"-",  c:"#f1f5f9"},
     {l:"COUNTRY",  v:st.exit_country||"-",c:"#f1f5f9"},
     {l:"LATENCY",  v:st.latency_ms?(st.latency_ms+"ms"):"-",c:"#f1f5f9"}
    ].forEach(function(chip){
      html+="<div style='background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:9px 10px'>";
      html+="<div style='color:#475569;font-size:9px;letter-spacing:.8px;margin-bottom:3px'>"+chip.l+"</div>";
      html+="<div style='color:"+chip.c+";font-size:11px;font-weight:bold;word-break:break-all'>"+chip.v+"</div></div>";
    });
    html+="</div>";
    html+="<div style='color:#475569;font-size:10px;letter-spacing:.8px;margin-bottom:12px'>CIRCUIT PATH</div>";
    var srcIp = st.source_ip || "Your IP";
    var flow=[{label:"YOU",role:"Local",ip:srcIp,isLocal:true}].concat(nodes).concat([{label:"TARGET",role:"Server",isTarget:true}]);
    flow.forEach(function(n,i){
      var rc=n.isLocal?"#6366f1":n.isTarget?"#f59e0b":n.role==="Guard"?"#22c55e":n.role==="Exit"?"#ef4444":"#818cf8";
      html+="<div style='display:flex;align-items:stretch;gap:10px;margin-bottom:4px'>";
      html+="<div style='display:flex;flex-direction:column;align-items:center;flex-shrink:0'>";
      html+="<div style='width:28px;height:28px;border-radius:50%;background:"+rc+"1a;border:2px solid "+rc+";display:flex;align-items:center;justify-content:center;font-size:10px;color:"+rc+";font-weight:bold'>"+(i+1)+"</div>";
      if(i<flow.length-1)html+="<div style='width:2px;flex:1;background:linear-gradient("+rc+",#1e3a5f);min-height:12px;margin:2px auto'></div>";
      html+="</div><div style='flex:1;background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:8px 12px;margin-bottom:4px'>";
      html+="<div style='display:flex;justify-content:space-between;align-items:center'>";
      html+="<span style='color:#f1f5f9;font-size:12px;font-weight:bold'>"+(n.label||n.nickname||n.role)+"</span>";
      html+="<span style='color:"+rc+";font-size:10px;background:"+rc+"1a;padding:2px 7px;border-radius:4px'>"+n.role+"</span></div>";
      if(n.isLocal){
        html+="<div style='color:#a5b4fc;font-size:10px;margin-top:4px'>&#x1F5A7; "+n.ip+" → SOCKS5 127.0.0.1:9050 &#x1F512;</div>";
      }else if(!n.isTarget&&n.ip){
        html+="<div style='margin-top:4px;display:flex;flex-wrap:wrap;gap:8px'>";
        html+="<span style='color:#64748b;font-size:10px'>&#x1F5A7; "+n.ip+"</span>";
        if(n.country)html+="<span style='color:#64748b;font-size:10px'>&#x1F30D; "+n.country+"</span>";
        if(n.latency_ms)html+="<span style='color:#64748b;font-size:10px'>&#x23F1; "+n.latency_ms+"ms</span>";
        if(n.asn)html+="<span style='color:#475569;font-size:10px'>"+n.asn+"</span>";
        html+="</div>";
      }
      html+="</div></div>";
    });
    if(st.last_newnym){
      var rot=st.last_newnym.slice(0,19).replace("T"," ");
      html+="<div style='margin-top:14px;text-align:center;color:#475569;font-size:11px'>&#x1F504; Last rotation: "+rot+"</div>";
    }
    html+="<div style='margin-top:12px;display:flex;gap:8px;justify-content:center'>";
    html+=(st.kill_switch?"<span style='background:#166534;color:#4ade80;border-radius:6px;padding:3px 10px;font-size:11px'>&#x1F6A8; Kill-Switch ON</span>":
      "<span style='background:#7f1d1d;color:#f87171;border-radius:6px;padding:3px 10px;font-size:11px'>&#x26A0; Kill-Switch OFF</span>");
    html+="<a href='/settings' style='background:#1e293b;color:#818cf8;border-radius:6px;padding:3px 10px;font-size:11px;text-decoration:none'>&#x2699; Settings</a></div>";
    el.innerHTML=html;
  }
  document.getElementById("tor-modal").addEventListener("click",function(e){if(e.target===this)this.style.display="none";});
});
</script>
"""

# ═════════════════════════════════════════════════════════════════════════════
# THEMES
# ═════════════════════════════════════════════════════════════════════════════
_THEMES = {
    "default": {
        "label": "Default (Dark Blue)",
        "category": "Default",
        "preview": "#060b14,#00d4ff,#00ff9d",
        "css": ""
    },
    "silver_red": {
        "label": "Silver White / Red Border",
        "category": "Silver",
        "preview": "#f4f6f9,#cc0000,#ff4444",
        "css": """
:root {
  --bg:#f4f6f9;--bg2:#e8ecf2;--bg3:#dde3ec;--bg4:#cfd8e5;
  --border:#cc0000;--border2:#ff2222;
  --primary:#cc0000;--primary-d:#990000;
  --secondary:#ff4444;--secondary-d:#cc2222;
  --danger:#dd0000;--warning:#e67e00;--info:#5567cc;--purple:#8855cc;
  --text:#1a1a2e;--text2:#333355;--muted:#7788aa;
  --card-shadow:0 4px 24px rgba(204,0,0,.12);
  --glow:0 0 20px rgba(204,0,0,.25);
}
body{background:linear-gradient(135deg,#f4f6f9 0%,#e8ecf2 100%)}
.sidebar{background:linear-gradient(180deg,#1a1a2e 0%,#2d1f1f 100%);border-right:2px solid #cc0000}
.sidebar .nav-item{color:#d0d8e8}
.sidebar .nav-item:hover,.sidebar .nav-item.active{color:#ff4444;border-left-color:#cc0000}
.logo-text{color:#ff4444}
.topbar{background:#e8ecf2;border-bottom:2px solid #cc0000}
.topbar-title,.card-title{color:#1a1a2e}
.card{background:#fff;border:1px solid #dde3ec;box-shadow:0 2px 8px rgba(204,0,0,.08)}
.card-header{border-bottom:1px solid #cc000033;background:#fff5f5}
input,select,textarea{background:#f8f9fb;border-color:#ccd;color:#1a1a2e}
input:focus,select:focus,textarea:focus{border-color:#cc0000}
label{color:#333355}
th{background:#e8ecf2;color:#333355}
td{color:#1a1a2e}
.sidebar-footer{color:#aaa}
"""
    },
    "abstract_rw": {
        "label": "Abstract - Red & White",
        "category": "Abstract",
        "preview": "#0d0000,#ff3333,#ff8888",
        "css": """
:root {
  --bg:#0d0000;--bg2:#1a0505;--bg3:#220808;--bg4:#2d0a0a;
  --border:#6d0000;--border2:#aa1111;
  --primary:#ff3333;--primary-d:#cc0000;
  --secondary:#ff8888;--secondary-d:#dd4444;
  --danger:#ff0000;--warning:#ff8800;--info:#ff6677;--purple:#dd44aa;
  --text:#ffe8e8;--text2:#ffbbbb;--muted:#994444;
  --card-shadow:0 4px 24px rgba(255,0,0,.15);
  --glow:0 0 20px rgba(255,51,51,.35);
}
body{background:radial-gradient(ellipse at top,#1a0505 0%,#0d0000 70%);background-color:#0d0000}
.sidebar{background:linear-gradient(180deg,#1a0505 0%,#0d0000 100%)}
.logo-text{color:#ff3333;text-shadow:0 0 12px rgba(255,51,51,.6)}
"""
    },
    "abstract_wg": {
        "label": "Abstract - White & Green",
        "category": "Abstract",
        "preview": "#f8fdf9,#007733,#00cc55",
        "css": """
:root {
  --bg:#f8fdf9;--bg2:#edf7f0;--bg3:#e0f0e5;--bg4:#d0eadb;
  --border:#009944;--border2:#00cc55;
  --primary:#007733;--primary-d:#005522;
  --secondary:#00cc55;--secondary-d:#009944;
  --danger:#cc2200;--warning:#cc8800;--info:#2266cc;--purple:#8833cc;
  --text:#0a1f0f;--text2:#1a3d24;--muted:#6a9975;
  --card-shadow:0 4px 24px rgba(0,153,68,.12);
  --glow:0 0 20px rgba(0,204,85,.25);
}
body{background:linear-gradient(135deg,#f8fdf9 0%,#edf7f0 100%)}
.sidebar{background:linear-gradient(180deg,#0a1f0f 0%,#0d2a14 100%);border-right:2px solid #009944}
.sidebar .nav-item{color:#b0d8bc}
.sidebar .nav-item:hover,.sidebar .nav-item.active{color:#00cc55;border-left-color:#009944}
.logo-text{color:#00cc55}
.topbar{background:#edf7f0;border-bottom:2px solid #009944}
.topbar-title,.card-title{color:#0a1f0f}
.card{background:#fff;border:1px solid #c8e8d0}
.card-header{background:#f0faf3;border-bottom:1px solid #c0e8cc}
input,select,textarea{background:#f5fdf7;border-color:#b8d8c4;color:#0a1f0f}
input:focus,select:focus,textarea:focus{border-color:#009944}
label{color:#1a3d24}
th{background:#e0f0e5;color:#1a3d24}
td{color:#0a1f0f}
"""
    },
    "abstract_mc": {
        "label": "Abstract - Multicolor",
        "category": "Abstract",
        "preview": "#080814,#ff6b6b,#4ecdc4",
        "css": """
:root {
  --bg:#080814;--bg2:#0d0d20;--bg3:#121228;--bg4:#161632;
  --border:#2d1a5e;--border2:#4422aa;
  --primary:#ff6b6b;--primary-d:#ee4444;
  --secondary:#4ecdc4;--secondary-d:#35b0a8;
  --danger:#ff3860;--warning:#ffdd59;--info:#45b7d1;--purple:#c084fc;
  --text:#e8e8ff;--text2:#b0b0dd;--muted:#5555aa;
  --card-shadow:0 4px 24px rgba(255,107,107,.1);
  --glow:0 0 20px rgba(78,205,196,.2);
}
body{background:linear-gradient(135deg,#080814 0%,#0d0820 50%,#080e14 100%)}
.sidebar{background:linear-gradient(180deg,#0d0d20 0%,#14081c 100%)}
.logo-text{background:linear-gradient(135deg,#ff6b6b,#ffd166,#4ecdc4);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav-item:hover,.nav-item.active{border-left-color:#ff6b6b}
.progress-fill{background:linear-gradient(90deg,#ff6b6b,#ffd166,#4ecdc4,#c084fc)}
"""
    },
    "space_deep": {
        "label": "Space - Deep Cosmos",
        "category": "Space",
        "preview": "#03030f,#6c77f7,#a78bfa",
        "css": """
:root {
  --bg:#03030f;--bg2:#050516;--bg3:#07071f;--bg4:#09092a;
  --border:#1a1a4e;--border2:#2a2a7e;
  --primary:#6c77f7;--primary-d:#4a56e0;
  --secondary:#a78bfa;--secondary-d:#8b6fe0;
  --danger:#f87171;--warning:#fbbf24;--info:#60a5fa;--purple:#c084fc;
  --text:#c8ccff;--text2:#8890d0;--muted:#404080;
  --card-shadow:0 4px 24px rgba(108,119,247,.12);
  --glow:0 0 30px rgba(108,119,247,.3);
}
body{background:radial-gradient(ellipse at 20% 30%,#0a0a2e 0%,#03030f 60%),radial-gradient(ellipse at 80% 70%,#0a0520 0%,transparent 50%);background-color:#03030f}
.sidebar{background:linear-gradient(180deg,#05051a 0%,#03030f 100%);border-right:1px solid #1a1a5e}
.logo-text{color:#a78bfa;text-shadow:0 0 10px rgba(167,139,250,.5)}
.card{box-shadow:0 4px 24px rgba(108,119,247,.1),inset 0 1px 0 rgba(108,119,247,.05)}
"""
    },
    "space_nebula": {
        "label": "Space - Nebula Storm",
        "category": "Space",
        "preview": "#07020f,#e040fb,#40c4ff",
        "css": """
:root {
  --bg:#07020f;--bg2:#0e0518;--bg3:#140720;--bg4:#1a0928;
  --border:#3d1155;--border2:#6622aa;
  --primary:#e040fb;--primary-d:#aa00cc;
  --secondary:#40c4ff;--secondary-d:#0099dd;
  --danger:#ff5252;--warning:#ffab40;--info:#40c4ff;--purple:#ea80fc;
  --text:#f0d0ff;--text2:#c090e0;--muted:#6030a0;
  --card-shadow:0 4px 24px rgba(224,64,251,.15);
  --glow:0 0 30px rgba(224,64,251,.4);
}
body{background:radial-gradient(ellipse at 30% 20%,#1a0330 0%,#07020f 50%),radial-gradient(ellipse at 70% 80%,#120220 0%,transparent 60%);background-color:#07020f}
.sidebar{background:linear-gradient(180deg,#0e0518 0%,#07020f 100%);border-right:1px solid #3d1155}
.logo-text{color:#e040fb;text-shadow:0 0 15px rgba(224,64,251,.6)}
.progress-fill{background:linear-gradient(90deg,#e040fb,#40c4ff)}
"""
    },
    "space_solar": {
        "label": "Space - Solar Flare",
        "category": "Space",
        "preview": "#0a0500,#ff9500,#ffcc00",
        "css": """
:root {
  --bg:#0a0500;--bg2:#140a00;--bg3:#1e1000;--bg4:#281600;
  --border:#553300;--border2:#885500;
  --primary:#ff9500;--primary-d:#cc7000;
  --secondary:#ffcc00;--secondary-d:#ddaa00;
  --danger:#ff4422;--warning:#ffcc00;--info:#44aaff;--purple:#cc88ff;
  --text:#fff5e0;--text2:#ffd880;--muted:#885533;
  --card-shadow:0 4px 24px rgba(255,149,0,.15);
  --glow:0 0 30px rgba(255,149,0,.4);
}
body{background:radial-gradient(ellipse at 50% 0%,#281600 0%,#0a0500 70%);background-color:#0a0500}
.sidebar{background:linear-gradient(180deg,#140a00 0%,#0a0500 100%);border-right:1px solid #553300}
.logo-text{color:#ff9500;text-shadow:0 0 15px rgba(255,149,0,.6)}
.progress-fill{background:linear-gradient(90deg,#ff4422,#ff9500,#ffcc00)}
.card{border-color:#553300}
"""
    },
    "hack_matrix": {
        "label": "Hacking - Matrix",
        "category": "Hacking",
        "preview": "#000300,#00ff41,#00cc33",
        "css": """
:root {
  --bg:#000300;--bg2:#000800;--bg3:#000d00;--bg4:#001200;
  --border:#003300;--border2:#006600;
  --primary:#00ff41;--primary-d:#00cc33;
  --secondary:#00dd33;--secondary-d:#00aa22;
  --danger:#ff0000;--warning:#ffff00;--info:#00ccff;--purple:#cc00ff;
  --text:#00ff41;--text2:#00cc33;--muted:#005500;
  --card-shadow:0 4px 24px rgba(0,255,65,.1);
  --glow:0 0 20px rgba(0,255,65,.5);
  --font:'JetBrains Mono',monospace;
}
body{background:#000300;background-image:repeating-linear-gradient(0deg,rgba(0,255,65,.015) 0px,rgba(0,255,65,.015) 1px,transparent 1px,transparent 2px)}
.sidebar{background:#000800;border-right:1px solid #003300}
.logo-text{color:#00ff41;text-shadow:0 0 10px rgba(0,255,65,.8),0 0 30px rgba(0,255,65,.4)}
.logo-sub{color:#00aa22}
.card{background:#000800;border-color:#003300;box-shadow:0 0 15px rgba(0,255,65,.05),inset 0 0 30px rgba(0,255,65,.02)}
.card-header{background:#000d00;border-bottom-color:#003300}
.card-title{color:#00ff41}
input,select,textarea{background:#000500;border-color:#004400;color:#00ff41;font-family:'JetBrains Mono',monospace}
input:focus,select:focus,textarea:focus{border-color:#00ff41;box-shadow:0 0 8px rgba(0,255,65,.3)}
label{color:#00cc33}
th{background:#000d00;color:#00ff41}
td{color:#00cc33}
a{color:#00ff41}
a:hover{color:#00cc33}
.topbar{background:#000800;border-bottom-color:#003300}
.topbar-title{color:#00ff41}
"""
    },
    "hack_blood": {
        "label": "Hacking - Blood Terminal",
        "category": "Hacking",
        "preview": "#080000,#ff0033,#ff4455",
        "css": """
:root {
  --bg:#080000;--bg2:#100000;--bg3:#180000;--bg4:#200000;
  --border:#440000;--border2:#880000;
  --primary:#ff0033;--primary-d:#cc0022;
  --secondary:#ff4455;--secondary-d:#dd2233;
  --danger:#ff0000;--warning:#ff8800;--info:#ff6699;--purple:#ff00aa;
  --text:#ffcccc;--text2:#ff9999;--muted:#880000;
  --card-shadow:0 4px 24px rgba(255,0,51,.15);
  --glow:0 0 20px rgba(255,0,51,.5);
  --font:'JetBrains Mono',monospace;
}
body{background:#080000;background-image:repeating-linear-gradient(0deg,rgba(255,0,0,.01) 0px,rgba(255,0,0,.01) 1px,transparent 1px,transparent 2px)}
.sidebar{background:linear-gradient(180deg,#100000 0%,#080000 100%);border-right:1px solid #440000}
.logo-text{color:#ff0033;text-shadow:0 0 10px rgba(255,0,51,.8),0 0 30px rgba(255,0,51,.4)}
.card{background:#100000;border-color:#440000}
.card-header{background:#180000;border-bottom-color:#440000}
input,select,textarea{background:#0a0000;border-color:#550000;color:#ffcccc}
input:focus,select:focus,textarea:focus{border-color:#ff0033;box-shadow:0 0 8px rgba(255,0,51,.3)}
label{color:#ff9999}
th{background:#180000;color:#ff0033}
td{color:#ffcccc}
.topbar{background:#100000;border-bottom-color:#440000}
.topbar-title{color:#ff0033}
"""
    },
    "hack_ghost": {
        "label": "Hacking - Ghost Protocol",
        "category": "Hacking",
        "preview": "#040810,#00e5ff,#18ffff",
        "css": """
:root {
  --bg:#040810;--bg2:#060d18;--bg3:#081220;--bg4:#0a1728;
  --border:#0a2a4a;--border2:#0e4070;
  --primary:#00e5ff;--primary-d:#00b8d9;
  --secondary:#18ffff;--secondary-d:#00e5ff;
  --danger:#ff1744;--warning:#ffea00;--info:#40c4ff;--purple:#d500f9;
  --text:#b0e8ff;--text2:#70b8e0;--muted:#204060;
  --card-shadow:0 4px 24px rgba(0,229,255,.1);
  --glow:0 0 20px rgba(0,229,255,.5);
  --font:'JetBrains Mono',monospace;
}
body{background:#040810;background-image:linear-gradient(rgba(0,229,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.02) 1px,transparent 1px);background-size:40px 40px}
.sidebar{background:rgba(6,13,24,.95);border-right:1px solid #0a2a4a}
.logo-text{color:#00e5ff;text-shadow:0 0 10px rgba(0,229,255,.8),0 0 30px rgba(0,229,255,.4)}
.card{background:rgba(6,13,24,.8);border-color:#0a2a4a}
.card-header{background:rgba(8,18,32,.9);border-bottom-color:#0a2a4a}
input,select,textarea{background:rgba(4,8,16,.9);border-color:#0a2a4a;color:#b0e8ff}
input:focus,select:focus,textarea:focus{border-color:#00e5ff;box-shadow:0 0 8px rgba(0,229,255,.3)}
label{color:#70b8e0}
th{background:#081220;color:#00e5ff}
td{color:#b0e8ff}
.topbar{background:rgba(6,13,24,.95);border-bottom-color:#0a2a4a}
.topbar-title{color:#00e5ff}
"""
    },
}

# ═════════════════════════════════════════════════════════════════════════════
# BASE TEMPLATE
# ═════════════════════════════════════════════════════════════════════════════
def _base(title, content, active=""):
    user  = flask_session.get("username","")
    role  = flask_session.get("role","user")
    tor   = _get_setting("tor_enabled","0") == "1"
    tor_badge = ('<span class="tor-on">⬡ TOR ON</span>' if tor
                 else '<span class="tor-off">⬡ TOR OFF</span>')
    notif_count = db.one(
        "SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND is_read=0",
        (flask_session.get("uid",""),))
    nc = notif_count["c"] if notif_count else 0
    nc_badge = f'<span class="notif-badge">{nc}</span>' if nc else ""

    nav_items = [
        ("dashboard","🏠","Dashboard","/"),
        ("investigations","🗂️","Investigations","/investigations"),
    ]
    if role == "admin" or _analyst_can("leaks"):
        nav_items.append(("leaks","🔐","Search Leaks","/leaks"))
    nav_items.append(("chat","💬","Team Chat","/chat"))
    if role == "admin":
        nav_items.append(("settings","⚙️","Settings","/settings"))
    elif _analyst_can("settings"):
        nav_items.append(("settings","⚙️","Settings","/settings/osint"))
    if role == "admin" or _analyst_can("audit"):
        nav_items.append(("audit","📋","Audit Log","/audit"))
    if role == "admin":
        nav_items.append(("users","👥","User Management","/users"))
        nav_items.append(("access","🔑","Access Management","/access"))

    settings_active = active.startswith("settings")
    nav_html = ""
    for key, icon, label, href in nav_items:
        is_active = active == key or (key == "settings" and settings_active)
        cls = "active" if is_active else ""
        nav_html += f'<a href="{href}" class="nav-item {cls}">{icon} <span>{label}</span></a>'
        if key == "settings":
            show = "block" if settings_active else "none"
            nav_html += f'<div class="nav-subitems" style="display:{show}">'
            sub_items = [
                ("settings_general","🔧","General","/settings"),
                ("settings_osint","🔍","OSINT","/settings/osint"),
                ("settings_phishing","🎣","Phishing","/settings/phishing"),
                ("settings_leaks","🔐","Leaks","/settings/leaks"),
            ]
            for sk, si, sl, sh in sub_items:
                sc = "active" if active == sk else ""
                nav_html += f'<a href="{sh}" class="nav-item nav-subitem {sc}">{si} <span>{sl}</span></a>'
            nav_html += '</div>'

    # ── Theme CSS injection ──────────────────────────────────────────────────
    _active_theme = _get_setting("theme", "default")
    _theme_css    = _THEMES.get(_active_theme, _THEMES["default"])["css"]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - {APP_NAME}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script>window._torIsAdmin={'true' if role == 'admin' else 'false'};</script>
{_TOR_SCRIPT}
<style>
:root{{
  --bg:#060b14;--bg2:#0a1220;--bg3:#0f1a2e;--bg4:#142038;
  --border:#1e3050;--border2:#264070;
  --primary:#00d4ff;--primary-d:#0099bb;
  --secondary:#00ff9d;--secondary-d:#00cc7a;
  --danger:#ff3860;--warning:#ffad00;--info:#7b8cde;--purple:#c084fc;
  --text:#c8d6ef;--text2:#8aa0c0;--muted:#4a6080;
  --card-shadow:0 4px 24px rgba(0,212,255,.07);
  --glow:0 0 20px rgba(0,212,255,.25);
  --font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace;
}}
{_theme_css}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;min-height:100vh;display:flex}}
a{{color:var(--primary);text-decoration:none}}a:hover{{color:var(--secondary)}}

.sidebar{{width:220px;min-height:100vh;background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;top:0;left:0;z-index:100}}
.sidebar-logo{{padding:20px 16px;border-bottom:1px solid var(--border)}}
.logo-text{{font-size:18px;font-weight:700;color:var(--primary);letter-spacing:.5px;font-family:var(--mono)}}
.logo-sub{{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-top:2px}}
.nav-section{{padding:8px 0;flex:1}}
.nav-item{{display:flex;align-items:center;gap:10px;padding:10px 16px;color:var(--text2);
  cursor:pointer;transition:all .2s;border-left:3px solid transparent;font-size:13px}}
.nav-item:hover,.nav-item.active{{background:var(--bg3);color:var(--primary);
  border-left-color:var(--primary);text-decoration:none}}
.sidebar-footer{{padding:12px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--muted)}}
.nav-subitems{{margin:0;padding:0}}
.nav-subitem{{padding:7px 16px 7px 34px!important;font-size:12px!important;border-left:2px solid transparent}}
.nav-subitem.active{{border-left-color:var(--primary);color:var(--primary)!important;background:rgba(0,212,255,.06)}}

.main{{margin-left:220px;flex:1;display:flex;flex-direction:column;min-height:100vh}}
.topbar{{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:0 24px;height:56px;display:flex;align-items:center;
  justify-content:space-between;position:sticky;top:0;z-index:90}}
.topbar-title{{font-size:16px;font-weight:600;color:var(--text)}}
.topbar-right{{display:flex;align-items:center;gap:16px}}
.tor-on{{background:rgba(0,255,157,.15);color:var(--secondary);border:1px solid var(--secondary-d);
  padding:3px 10px;border-radius:20px;font-size:11px;font-family:var(--mono);font-weight:600}}
.tor-off{{background:rgba(74,96,128,.15);color:var(--muted);border:1px solid var(--border);
  padding:3px 10px;border-radius:20px;font-size:11px;font-family:var(--mono)}}
.notif-badge{{background:var(--danger);color:#fff;border-radius:10px;
  padding:1px 6px;font-size:10px;font-weight:700}}
.page{{padding:24px;flex:1}}

.card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  box-shadow:var(--card-shadow);margin-bottom:20px}}
.card-header{{padding:14px 18px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between}}
.card-title{{font-size:13px;font-weight:600;color:var(--text);letter-spacing:.3px}}
.card-body{{padding:18px}}

.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}}
.stat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  padding:16px;display:flex;flex-direction:column;gap:6px}}
.stat-icon{{font-size:22px}}
.stat-value{{font-size:26px;font-weight:700;color:var(--primary);font-family:var(--mono)}}
.stat-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}

table{{width:100%;border-collapse:collapse}}
th{{background:var(--bg3);color:var(--text2);font-weight:500;font-size:11px;
   text-transform:uppercase;letter-spacing:.8px;padding:10px 12px;text-align:left;
   border-bottom:1px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid var(--border);color:var(--text);font-size:13px;vertical-align:top}}
tr:hover td{{background:rgba(0,212,255,.03)}}

.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;
  font-size:11px;font-weight:600;font-family:var(--mono)}}
.badge-critical{{background:rgba(255,56,96,.2);color:#ff3860;border:1px solid rgba(255,56,96,.4)}}
.badge-high{{background:rgba(255,87,34,.2);color:#ff5722;border:1px solid rgba(255,87,34,.4)}}
.badge-medium{{background:rgba(255,173,0,.2);color:#ffad00;border:1px solid rgba(255,173,0,.4)}}
.badge-low{{background:rgba(105,240,174,.2);color:#69f0ae;border:1px solid rgba(105,240,174,.4)}}
.badge-info{{background:rgba(64,196,255,.15);color:#40c4ff;border:1px solid rgba(64,196,255,.3)}}
.badge-blue{{background:rgba(123,140,222,.2);color:#7b8cde;border:1px solid rgba(123,140,222,.3)}}

.btn{{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:7px;
  font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all .2s;font-family:var(--font)}}
.btn-primary{{background:var(--primary-d);color:#fff}}
.btn-primary:hover{{background:var(--primary);color:#000;text-decoration:none}}
.btn-secondary{{background:var(--secondary-d);color:#000}}
.btn-secondary:hover{{background:var(--secondary);color:#000;text-decoration:none}}
.btn-danger{{background:rgba(255,56,96,.2);color:var(--danger);border:1px solid rgba(255,56,96,.4)}}
.btn-danger:hover{{background:var(--danger);color:#fff;text-decoration:none}}
.btn-ghost{{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}}
.btn-ghost:hover{{background:var(--bg4);color:var(--text);text-decoration:none}}
.btn-sm{{padding:5px 10px;font-size:11px}}

.form-group{{margin-bottom:16px}}
label{{display:block;font-size:12px;color:var(--text2);margin-bottom:6px;font-weight:500;letter-spacing:.3px}}
input[type=text],input[type=email],input[type=password],input[type=number],
select,textarea{{width:100%;background:var(--bg3);border:1px solid var(--border2);
  border-radius:7px;padding:9px 12px;color:var(--text);font-size:13px;font-family:var(--font);
  outline:none;transition:border-color .2s}}
input:focus,select:focus,textarea:focus{{border-color:var(--primary)}}
textarea{{resize:vertical;min-height:80px}}
.form-row{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
.form-row3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}}

.module-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}}
.module-card{{background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:14px;cursor:pointer;transition:all .2s;position:relative}}
.module-card.selected{{border-color:var(--primary);background:rgba(0,212,255,.06)}}
.module-card:hover{{border-color:var(--border2)}}
.module-card input[type=checkbox]{{position:absolute;top:12px;right:12px;
  width:16px;height:16px;accent-color:var(--primary)}}
.module-icon{{font-size:22px;margin-bottom:6px}}
.module-name{{font-size:13px;font-weight:600;color:var(--text)}}
.module-desc{{font-size:11px;color:var(--muted);margin-top:3px}}

.progress-bar{{height:4px;background:var(--bg4);border-radius:4px;overflow:hidden}}
.progress-fill{{height:100%;background:linear-gradient(90deg,var(--primary),var(--secondary));
  border-radius:4px;transition:width .5s ease}}

.confidence{{display:flex;align-items:center;gap:8px}}
.conf-bar{{flex:1;height:6px;background:var(--bg4);border-radius:4px;overflow:hidden}}
.conf-fill{{height:100%;border-radius:4px;transition:width .3s}}
.conf-label{{font-size:11px;font-family:var(--mono);width:32px;text-align:right}}

.traffic-log{{background:var(--bg);border:1px solid var(--border);border-radius:8px;
  font-family:var(--mono);font-size:11px;height:calc(100vh - 320px);min-height:300px;
  overflow-y:auto;padding:10px}}
.tlog-entry{{padding:2px 0;border-bottom:1px solid rgba(30,48,80,.5);
  display:flex;gap:8px;align-items:baseline}}
.tlog-ts{{color:var(--muted);min-width:70px}}
.tlog-module{{color:var(--secondary);min-width:80px}}
.tlog-src{{color:var(--text2)}}
.tlog-arrow{{color:var(--warning)}}
.tlog-dest{{color:var(--primary)}}
.tlog-method{{color:var(--purple)}}
.tlog-status{{min-width:36px}}
.tlog-dur{{color:var(--muted)}}
.tlog-tor{{color:var(--secondary);font-size:9px}}

#entity-graph{{width:100%;height:520px;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;position:relative;overflow:hidden}}
.graph-legend{{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px}}
.legend-item{{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)}}
.legend-dot{{width:10px;height:10px;border-radius:50%}}

.scan-status-running{{animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}

.alert{{padding:12px 16px;border-radius:7px;margin-bottom:16px;font-size:13px}}
.alert-danger{{background:rgba(255,56,96,.1);border:1px solid rgba(255,56,96,.3);color:var(--danger)}}
.alert-success{{background:rgba(0,255,157,.1);border:1px solid rgba(0,255,157,.3);color:var(--secondary)}}
.alert-info{{background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:var(--primary)}}

.tabs{{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px}}
.tab{{padding:10px 18px;font-size:13px;color:var(--text2);cursor:pointer;
  border-bottom:2px solid transparent;transition:all .2s;user-select:none}}
.tab.active{{color:var(--primary);border-bottom-color:var(--primary)}}
.tab:hover{{color:var(--text)}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}

.contradiction-flag{{background:rgba(255,56,96,.1);border:1px solid rgba(255,56,96,.3);
  border-radius:6px;padding:8px 12px;font-size:12px;color:var(--danger);margin:4px 0}}

.timeline{{position:relative;padding-left:24px}}
.timeline::before{{content:'';position:absolute;left:8px;top:0;bottom:0;
  width:2px;background:var(--border)}}
.timeline-item{{position:relative;margin-bottom:16px}}
.timeline-dot{{position:absolute;left:-20px;top:4px;width:10px;height:10px;
  border-radius:50%;background:var(--primary);border:2px solid var(--bg)}}
.timeline-content{{background:var(--bg3);border:1px solid var(--border);
  border-radius:7px;padding:10px 14px}}
.timeline-time{{font-size:10px;color:var(--muted);font-family:var(--mono)}}
.timeline-title{{font-size:13px;font-weight:600;color:var(--text);margin:2px 0}}
.timeline-desc{{font-size:12px;color:var(--text2)}}

.flex{{display:flex}}.items-center{{align-items:center}}.gap-2{{gap:8px}}.gap-3{{gap:12px}}
.justify-between{{justify-content:space-between}}.flex-wrap{{flex-wrap:wrap}}
.text-muted{{color:var(--muted)}}.text-sm{{font-size:12px}}.mono{{font-family:var(--mono)}}
.truncate{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px}}
.mt-1{{margin-top:4px}}.mt-2{{margin-top:8px}}.mt-3{{margin-top:16px}}.mb-2{{margin-bottom:8px}}
.w-full{{width:100%}}.text-right{{text-align:right}}
.section-title{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;
  color:var(--muted);font-weight:600;margin-bottom:12px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}}
</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-text">{APP_ICON} {APP_NAME}</div>
    <div class="logo-sub">{APP_TAGLINE}</div>
  </div>
  <div class="nav-section">
    {nav_html}
  </div>
  <div class="sidebar-footer">
    👤 {user} &nbsp;·&nbsp; {role}<br>
    <small style="color:var(--muted)">by PentestRox</small><br>
    <a href="/license" style="color:var(--muted);font-size:10px;text-decoration:none" title="MIT License &amp; Disclaimer">⚖️ MIT License</a>
  </div>
</nav>
<div class="main">
  <div class="topbar">
    <span class="topbar-title">{title}</span>
    <div class="topbar-right">
      <div style="position:relative;display:inline-block">
        <button id="bell-btn" onclick="toggleNotifDropdown()" title="Notifications"
          style="background:none;border:none;cursor:pointer;font-size:18px;color:var(--text2);
                 position:relative;padding:4px 6px;border-radius:6px;line-height:1">
          🔔{nc_badge}
        </button>
        <div id="notif-dropdown" style="display:none;position:absolute;right:0;top:110%;
             width:340px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;
             box-shadow:0 8px 24px rgba(0,0,0,.35);z-index:9999;overflow:hidden">
          <div style="display:flex;align-items:center;justify-content:space-between;
                      padding:10px 14px;border-bottom:1px solid var(--border)">
            <span style="font-weight:600;font-size:13px">Notifications</span>
            <div style="display:flex;gap:8px;align-items:center">
              <button onclick="markAllNotifRead()" style="font-size:11px;color:var(--primary);
                background:none;border:none;cursor:pointer;padding:0">Mark all read</button>
              <a href="/notifications" style="font-size:11px;color:var(--muted);text-decoration:none">View all →</a>
            </div>
          </div>
          <div id="notif-list" style="max-height:320px;overflow-y:auto">
            <div style="padding:20px;text-align:center;color:var(--muted);font-size:13px">Loading…</div>
          </div>
        </div>
      </div>
      <a href="/settings" class="btn btn-ghost btn-sm">⚙️</a>
      <a href="/sessions" class="btn btn-ghost btn-sm" title="Active Sessions">🔐</a>
      <a href="/logout" class="btn btn-ghost btn-sm">Sign out</a>
    </div>
  </div>
  <div class="page">
    {content}
  </div>
</div>
<script>
/* ── Client public IP detection ────────────────────────────────────────
   Docker NAT makes the server see 192.168.x/172.x instead of the real
   public IP. The browser knows its own public IP via an external echo
   service. We report it back each page load so audit logs are accurate. */
(function() {{
  var cached = sessionStorage.getItem('_nx_cip');
  if (cached) {{
    /* Already fetched this session - just ensure server has it */
    fetch('/api/client-ip', {{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{ip:cached}})}});
    return;
  }}
  var services = [
    'https://api.ipify.org?format=json',
    'https://api4.ipify.org?format=json',
    'https://api64.ipify.org?format=json'
  ];
  function tryService(idx) {{
    if (idx >= services.length) return;
    var ctrl = new AbortController();
    var t = setTimeout(function(){{ ctrl.abort(); }}, 4000);
    fetch(services[idx], {{cache:'no-store', signal:ctrl.signal}})
      .then(function(r){{ return r.json(); }})
      .then(function(d){{
        clearTimeout(t);
        if (d && d.ip) {{
          sessionStorage.setItem('_nx_cip', d.ip);
          fetch('/api/client-ip', {{method:'POST',
            headers:{{'Content-Type':'application/json'}},
            body:JSON.stringify({{ip:d.ip}})}});
        }} else {{ tryService(idx+1); }}
      }})
      .catch(function(){{ clearTimeout(t); tryService(idx+1); }});
  }}
  tryService(0);
}})();

/* ── Notification dropdown ────────────────────────────────────────────── */
(function() {{
  var _ndOpen = false;
  var _ndPoll = null;
  var _ndBadge = document.querySelector('#bell-btn .notif-badge');

  window.toggleNotifDropdown = function() {{
    var dd = document.getElementById('notif-dropdown');
    if (!dd) return;
    _ndOpen = !_ndOpen;
    dd.style.display = _ndOpen ? 'block' : 'none';
    if (_ndOpen) {{ loadNotifDropdown(); }}
  }};

  document.addEventListener('click', function(e) {{
    if (!_ndOpen) return;
    var wrap = document.getElementById('bell-btn') && document.getElementById('bell-btn').closest('div');
    if (wrap && !wrap.contains(e.target)) {{
      _ndOpen = false;
      var dd = document.getElementById('notif-dropdown');
      if (dd) dd.style.display = 'none';
    }}
  }});

  function loadNotifDropdown() {{
    fetch('/api/notifications/recent').then(function(r) {{ return r.json(); }}).then(function(d) {{
      if (!d.ok) return;
      var list = document.getElementById('notif-list');
      if (!list) return;
      var items = d.items || [];
      if (!items.length) {{
        list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);font-size:13px">&#x1F514; All caught up!</div>';
        return;
      }}
      var icons = {{scan:'&#x26A1;', success:'&#x2705;', info:'&#x2139;', warning:'&#x26A0;', error:'&#x274C;', phishing:'&#x1F3A3;', chat:'&#x1F4AC;'}};
      var html = '';
      items.forEach(function(n) {{
        var icon = icons[n.type] || '&#x1F514;';
        var bg = n.is_read ? 'transparent' : 'rgba(0,212,255,.05)';
        var dot = n.is_read ? '' : '<span style="width:7px;height:7px;border-radius:50%;background:var(--primary);flex-shrink:0;margin-top:4px"></span>';
        var href = n.link || '/notifications';
        var ts = (n.created_at || '').replace('T', ' ').slice(0, 16);
        html += '<a href="' + href + '" style="display:flex;gap:10px;padding:10px 14px;text-decoration:none;border-bottom:1px solid var(--border);background:' + bg + ';color:var(--text)">';
        html += '<span style="font-size:18px;flex-shrink:0">' + icon + '</span>';
        html += '<div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:' + (n.is_read ? '400' : '600') + ';white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + n.title + '</div>';
        html += '<div style="font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + (n.body || '') + '</div>';
        html += '<div style="font-size:10px;color:var(--muted);margin-top:3px">' + ts + '</div></div>' + dot + '</a>';
      }});
      list.innerHTML = html;
      updateBellBadge(d.unread);
    }}).catch(function() {{}});
  }}

  function updateBellBadge(count) {{
    var btn = document.getElementById('bell-btn');
    if (!btn) return;
    var existing = btn.querySelector('.notif-badge');
    if (existing) existing.remove();
    if (count > 0) {{
      var span = document.createElement('span');
      span.className = 'notif-badge';
      span.textContent = count;
      btn.appendChild(span);
    }}
  }}

  window.markAllNotifRead = function() {{
    fetch('/api/notifications/read-all', {{method:'POST'}}).then(function() {{
      loadNotifDropdown();
      updateBellBadge(0);
    }});
  }};

  function pollNotifCount() {{
    fetch('/api/notifications/recent').then(function(r) {{ return r.json(); }}).then(function(d) {{
      if (d.ok) updateBellBadge(d.unread || 0);
    }}).catch(function() {{}});
  }}
  _ndPoll = setInterval(pollNotifCount, 30000);
}})();
</script>
</body></html>"""

# ═════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═════════════════════════════════════════════════════════════════════════════
_AUTH_BASE = """<!DOCTYPE html><html><head><meta charset=UTF-8>
<title>{title} - {APP_NAME}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;
  align-items:center;justify-content:center}}
.box{{background:#1e293b;border:1px solid #334155;border-radius:12px;
  padding:40px;width:100%;max-width:400px;box-shadow:0 8px 40px rgba(0,0,0,.6)}}
.logo-wrap{{text-align:center;margin-bottom:30px}}
.logo-wrap h1{{font-size:26px;color:#fff;font-weight:700}}
.logo-wrap h1 span{{color:#818cf8}}
.logo-wrap p{{color:#64748b;font-size:13px;margin-top:6px}}
.form-group{{margin-bottom:18px}}
label{{display:block;font-size:12px;font-weight:500;color:#94a3b8;
  margin-bottom:6px;text-transform:uppercase;letter-spacing:.4px}}
input[type=text],input[type=email],input[type=password]{{
  width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;
  border-radius:6px;color:#e2e8f0;font-size:14px;font-family:inherit;transition:border .2s}}
input:focus{{outline:none;border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.15)}}
.btn{{width:100%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;
  font-size:14px;font-weight:500;cursor:pointer;transition:background .2s;margin-top:4px}}
.btn:hover{{background:#4f46e5}}
.alert{{padding:12px 16px;border-radius:6px;font-size:13px;margin-bottom:16px}}
.alert-error{{background:#450a0a;border:1px solid #7f1d1d;color:#fca5a5}}
.alert-info{{background:#0c1a2e;border:1px solid #1e3a5f;color:#93c5fd}}
a{{color:#818cf8}}a:hover{{color:#a5b4fc}}
</style></head><body>
<div class="box">
  <div class="logo-wrap">
    <h1>{APP_ICON} <span>{APP_NAME}</span></h1>
    <p>{subtitle}</p>
  </div>
  {alert}
  {form}
</div>
<script>
/* Silently detect browser's public IP and inject into any _cip hidden fields.
   Runs on login + register pages so the form POST carries the real client IP. */
(function() {{
  var services = [
    'https://api.ipify.org?format=json',
    'https://api4.ipify.org?format=json',
    'https://api64.ipify.org?format=json'
  ];
  function fill(ip) {{
    document.querySelectorAll('input[name="_cip"]').forEach(function(el) {{
      el.value = ip;
    }});
  }}
  function tryNext(idx) {{
    if (idx >= services.length) return;
    var ctrl = new AbortController();
    var t = setTimeout(function() {{ ctrl.abort(); }}, 4000);
    fetch(services[idx], {{ cache: 'no-store', signal: ctrl.signal }})
      .then(function(r) {{ return r.json(); }})
      .then(function(d) {{
        clearTimeout(t);
        if (d && d.ip) {{ fill(d.ip); }} else {{ tryNext(idx + 1); }}
      }})
      .catch(function() {{ clearTimeout(t); tryNext(idx + 1); }});
  }}
  tryNext(0);
}})();
</script>
</body></html>"""

@app.route("/login", methods=["GET","POST"])
def login():
    if _first_run():
        return redirect("/register")
    err = ""
    if request.method == "POST":
        un  = request.form.get("username","").strip()
        pw  = request.form.get("password","")
        u   = db.one("SELECT * FROM users WHERE username=?", (un,))
        if u and check_password_hash(u["password_hash"], pw):
            status = u.get("status", "active") or "active"
            if status == "pending":
                err = "Your account is awaiting admin approval. Please check back later."
            elif status in ("disabled", "inactive"):
                err = "Your account has been deactivated. Contact an administrator."
            else:
                flask_session.permanent = True
                flask_session["uid"]      = u["id"]
                flask_session["username"] = u["username"]
                flask_session["role"]     = u["role"]
                # Capture browser-reported public IP from hidden form field
                # (JS fills this from ipify while the user types their credentials)
                _cip = request.form.get("_cip","").strip()
                import re as _re_ip
                if _cip and _re_ip.match(r'^[\d\.:a-fA-F]+$', _cip) and len(_cip) <= 45:
                    flask_session["client_public_ip"] = _cip
                else:
                    # Clear stale IP from previous session so audit uses fresh detection
                    flask_session.pop("client_public_ip", None)
                flask_session.modified = True
                _create_session(u["id"], u["username"])
                _audit("login")
                return redirect(request.args.get("next","/"))
        else:
            err = "Invalid username or password"
    alert = f'<div class="alert alert-error">{err}</div>' if err else ""
    allow_reg = _get_setting("allow_registration", "0") == "1"
    reg_link = (
        '<p style="text-align:center;margin-top:14px;font-size:13px">'
        '<a href="/register" style="color:var(--primary);text-decoration:none">'
        'Create an account →</a></p>'
    ) if allow_reg else ""
    form = f"""<form method="POST">
    <input type="hidden" name="_cip" id="_cip_login">
    <div class="form-group"><label>Username</label>
      <input type="text" name="username" autofocus required placeholder="analyst"></div>
    <div class="form-group"><label>Password</label>
      <input type="password" name="password" required placeholder="••••••••"></div>
    <button class="btn">Sign In →</button>
  </form>
  {reg_link}
  <p style="text-align:center;margin-top:20px;font-size:12px;color:#475569">
    FEROXSEI OSINT v2.0 &nbsp;·&nbsp; Authorized Use Only<br>
    <a href="/license" style="color:#475569;font-size:11px;text-decoration:underline">⚖️ MIT License &amp; Disclaimer</a></p>"""
    return _AUTH_BASE.format(title="Sign In", subtitle="Intelligence Platform", alert=alert, form=form, APP_NAME=APP_NAME, APP_ICON=APP_ICON)

@app.route("/register", methods=["GET","POST"])
def register():
    is_first = _first_run()
    # First-run always allowed; otherwise check allow_registration setting
    if not is_first and flask_session.get("role") != "admin":
        if _get_setting("allow_registration", "0") != "1":
            return redirect("/login")

    smtp_enabled = _smtp_is_enabled()
    step = request.args.get("step","form")   # form | otp
    token = request.args.get("token","")
    err = info = ""

    if request.method == "POST":
        step = request.form.get("step","form")

        # ── Step 1: collect details, send OTP (or skip OTP if first run / no SMTP) ──
        if step == "form":
            un = request.form.get("username","").strip()
            em = request.form.get("email","").strip()
            pw = request.form.get("password","")
            # Capture real public IP from JS-injected hidden field
            _cip_r = request.form.get("_cip","").strip()
            import re as _re_ip2
            if _cip_r and _re_ip2.match(r'^[\d\.:a-fA-F]+$', _cip_r) and len(_cip_r) <= 45:
                flask_session["client_public_ip"] = _cip_r
                flask_session.modified = True
            else:
                flask_session.pop("client_public_ip", None)
                flask_session.modified = True
            if not un or not pw:
                err = "Username and password are required."
            elif len(pw) < 6:
                err = "Password must be at least 6 characters."
            elif db.one("SELECT id FROM users WHERE username=?", (un,)):
                err = "Username already taken."
            elif not is_first and smtp_enabled and not em:
                err = "Email address is required for OTP verification."
            else:
                if is_first:
                    # First run - create admin immediately, no OTP
                    uid_new = str(uuid.uuid4())
                    db.ins("users", {
                        "id": uid_new, "username": un, "email": em,
                        "password_hash": generate_password_hash(pw),
                        "role": "admin", "api_keys": "{}", "status": "active", "created_at": _now()
                    })
                    _audit("register_admin", "user", uid_new, f"username={un}")
                    return redirect("/login")
                elif smtp_enabled:
                    # Send OTP email
                    import random as _rand
                    otp_code = str(_rand.randint(100000, 999999))
                    tok = str(uuid.uuid4())
                    from datetime import datetime as _dt, timedelta as _td
                    # Use local time (matches _now() which also uses datetime.now())
                    expires = (_dt.now() + _td(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
                    # Clean old OTPs for this username
                    db.exec("DELETE FROM otp_store WHERE username=?", (un,))
                    db.exec(
                        "INSERT INTO otp_store(token,username,email,password_hash,otp,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
                        (tok, un, em, generate_password_hash(pw), otp_code, expires, _now())
                    )
                    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#0a1220;color:#c8d6ef;padding:32px;border-radius:12px;border:1px solid #1e3050">
  <h2 style="color:#00d4ff;margin-bottom:8px">FEROXSEI OSINT</h2>
  <p style="color:#8aa0c0">Your registration OTP:</p>
  <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#00d4ff;text-align:center;padding:16px;background:#060b14;border-radius:8px;margin:16px 0">{otp_code}</div>
  <p style="color:#8aa0c0;font-size:13px">This code expires in <strong>15 minutes</strong>.<br>
  Your account will require <strong>admin approval</strong> before you can log in.</p>
  <p style="color:#4a6080;font-size:11px;margin-top:24px">If you did not request this, ignore this email.</p>
</div>"""
                    ok, smtp_err = _send_system_email(em, "FEROXSEI OSINT - Registration OTP", body_html, f"Your OTP: {otp_code}")
                    if not ok:
                        err = f"Could not send OTP email: {smtp_err}"
                    else:
                        return redirect(f"/register?step=otp&token={tok}")
                else:
                    # No SMTP - create user immediately
                    uid_new = str(uuid.uuid4())
                    _auto_approve = _get_setting("auto_approve_registration","0") == "1"
                    _reg_status   = "active" if _auto_approve else "pending"
                    db.ins("users", {
                        "id": uid_new, "username": un, "email": em,
                        "password_hash": generate_password_hash(pw),
                        "role": "analyst", "api_keys": "{}", "status": _reg_status, "created_at": _now(),
                        "perm_osint": None, "perm_phishing": None, "perm_scans": None,
                        "perm_patterns": None, "perm_audit": None, "perm_tor": None, "perm_leaks": None, "perm_settings": None
                    })
                    if _auto_approve:
                        _audit("register_auto_approved", "user", uid_new, f"username={un}")
                        info = "approved"
                    else:
                        _audit("register_pending", "user", uid_new, f"username={un}")
                        _notify_admins("info", "New User Pending Approval",
                                       f"User '{un}' registered and is awaiting approval.", "/users")
                        info = "awaiting"

        # ── Step 2: verify OTP ────────────────────────────────────────────────
        elif step == "otp":
            tok  = request.form.get("token","")
            code = request.form.get("otp","").strip()
            rec  = db.one("SELECT * FROM otp_store WHERE token=?", (tok,))
            if not rec:
                err = "Invalid or expired session. Please register again."
            elif rec["otp"] != code:
                err = "Incorrect OTP. Please try again."
            elif rec["expires_at"] < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
                db.exec("DELETE FROM otp_store WHERE token=?", (tok,))
                err = "OTP has expired. Please register again."
            else:
                uid_new = str(uuid.uuid4())
                _auto_approve = _get_setting("auto_approve_registration","0") == "1"
                _reg_status   = "active" if _auto_approve else "pending"
                db.ins("users", {
                    "id": uid_new, "username": rec["username"], "email": rec["email"],
                    "password_hash": rec["password_hash"],
                    "role": "analyst", "api_keys": "{}", "status": _reg_status, "created_at": _now(),
                    "perm_osint": None, "perm_phishing": None, "perm_scans": None,
                    "perm_patterns": None, "perm_audit": None, "perm_tor": None, "perm_leaks": None
                })
                db.exec("DELETE FROM otp_store WHERE token=?", (tok,))
                if _auto_approve:
                    _audit("register_auto_approved", "user", uid_new, f"username={rec['username']}")
                    info = "approved"
                else:
                    _audit("register_pending", "user", uid_new, f"username={rec['username']}")
                    _notify_admins("info", "New User Pending Approval",
                                   f"User '{rec['username']}' registered and is awaiting approval.", "/users")
                    info = "awaiting"

    # ── Render ─────────────────────────────────────────────────────────────────
    alert = (f'<div class="alert alert-error">{_html.escape(err)}</div>' if err else
             f'<div class="alert alert-info">⏳ Account created! An admin will review and approve it before you can log in.</div>' if info == "awaiting" else
             f'<div class="alert alert-success">✅ Account created and approved! You can now <a href="/login">sign in</a>.</div>' if info == "approved" else "")

    if info in ("awaiting", "approved"):
        form = '<p style="text-align:center;margin-top:20px;font-size:12px;color:#475569"><a href="/login">← Back to Sign In</a></p>'
        subtitle = "Registration Complete" if info == "approved" else "Registration Submitted"

    elif step == "otp" and not err and not info:
        # OTP entry form
        tok_val = request.args.get("token","") or request.form.get("token","")
        otp_tok_html = _html.escape(tok_val)
        form = f"""<form method="POST">
    <input type="hidden" name="step" value="otp">
    <input type="hidden" name="token" value="{otp_tok_html}">
    <div class="form-group">
      <label>Enter the 6-digit OTP sent to your email</label>
      <input type="text" name="otp" required maxlength="6" placeholder="123456"
             style="font-size:24px;letter-spacing:6px;text-align:center" autofocus>
    </div>
    <button class="btn">Verify OTP →</button>
  </form>
  <p style="text-align:center;margin-top:16px;font-size:12px;color:#475569">
    Check your inbox (or <a href="http://localhost:8025" target="_blank" style="color:#00d4ff">MailHog</a> if testing).
    &nbsp;·&nbsp; <a href="/register">Start over</a></p>"""
        subtitle = "Verify Email"

    else:
        # Main registration form
        first_note = '<div class="alert alert-info" style="margin-top:16px">First run - this account will be <strong>admin</strong>.</div>' if is_first else ''
        otp_note = ('' if is_first else
                    '<div style="font-size:11px;color:#8aa0c0;margin-top:4px">An OTP will be sent to verify your email.</div>'
                    if smtp_enabled else
                    '<div style="font-size:11px;color:#f59e0b;margin-top:4px">⚠ SMTP not configured - account will be created as <strong>pending</strong> and requires admin approval.</div>')
        em_required = '' if is_first else ('required' if smtp_enabled else '')
        form = f"""<form method="POST">
    <input type="hidden" name="step" value="form">
    <input type="hidden" name="_cip" id="_cip_reg">
    <div class="form-group"><label>Username</label><input type="text" name="username" required placeholder="analyst01"></div>
    <div class="form-group"><label>Email {'(required for OTP)' if smtp_enabled and not is_first else '(optional)'}</label>
      <input type="email" name="email" {em_required} placeholder="analyst@org.com">{otp_note}</div>
    <div class="form-group"><label>Password (min 6 chars)</label><input type="password" name="password" required placeholder="••••••••"></div>
    <button class="btn">{'Create Admin Account →' if is_first else 'Register →'}</button>
  </form>
  {first_note}
  <p style="text-align:center;margin-top:16px;font-size:12px;color:#475569">
    <a href="/login">← Back to Sign In</a></p>"""
        subtitle = "Create Admin Account" if is_first else "Create Account"

    return _AUTH_BASE.format(title="Register", subtitle=subtitle, alert=alert, form=form, APP_NAME=APP_NAME, APP_ICON=APP_ICON)

@app.route("/logout")
def logout():
    token  = flask_session.get("session_token")
    uid    = flask_session.get("uid")
    uname  = flask_session.get("username","")
    _audit("logout")
    if token:
        _revoke_session(token)
    flask_session.clear()
    if uid:
        others = db.rows("SELECT * FROM user_sessions WHERE user_id=? ORDER BY last_active DESC", (uid,))
        if others:
            rows_html = ""
            for s in others:
                br    = _html.escape(s.get("browser","?"))
                osn   = _html.escape(s.get("os_name","?"))
                geo   = _html.escape(s.get("geo_location","?"))
                ip    = _html.escape(s.get("ip_address","?"))
                la    = _html.escape(s.get("last_active","?"))
                tok   = _html.escape(s.get("token",""))
                rows_html += f"""<tr>
<td style="padding:10px 12px"><span style="font-size:18px">{'🌐' if 'Chrome' in br else '🦊' if 'Firefox' in br else '🔵' if 'Edge' in br else '🔮'}</span> {br}</td>
<td style="padding:10px 12px;color:#94a3b8">{osn}</td>
<td style="padding:10px 12px;color:#94a3b8">{geo}</td>
<td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#64748b">{ip}</td>
<td style="padding:10px 12px;color:#64748b;font-size:12px">{la}</td>
<td style="padding:10px 12px">
  <button onclick="revokeOne('{tok}',this)" style="background:#ef4444;color:#fff;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px">Revoke</button>
</td></tr>"""
            uname_safe = _html.escape(uname)
            page = f"""<!DOCTYPE html><html><head><title>Signed Out - FEROXSEI</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px;max-width:820px;width:95%}}
h2{{font-size:22px;margin-bottom:6px;color:#f1f5f9}}p.sub{{color:#94a3b8;font-size:14px;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;padding:8px 12px;color:#64748b;border-bottom:1px solid #334155;font-weight:500}}
tr:not(:last-child) td{{border-bottom:1px solid #1e293b}}.btn-all{{background:#ef4444;color:#fff;border:none;padding:9px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}}
.btn-go{{background:#6366f1;color:#fff;border:none;padding:9px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none;display:inline-block}}
</style></head><body><div class="card">
<h2>✅ You've been signed out</h2>
<p class="sub">Signed out as <strong>{uname_safe}</strong>. The following sessions are still active in other browsers or devices.</p>
<table><thead><tr><th>Browser</th><th>OS</th><th>Location</th><th>IP</th><th>Last Active</th><th></th></tr></thead>
<tbody id="sess-tbody">{rows_html}</tbody></table>
<div style="margin-top:20px;display:flex;gap:12px;align-items:center">
<button class="btn-all" onclick="revokeAll()">Revoke All Sessions</button>
<a href="/login" class="btn-go">Go to Login →</a>
</div></div>
<script>
var _uid="{_html.escape(str(uid))}";
function revokeOne(tok,btn){{
  fetch("/api/sessions/revoke",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{token:tok,uid:_uid}})}})
  .then(function(){{btn.closest("tr").remove();if(!document.querySelector("#sess-tbody tr")){{document.querySelector(".btn-all").style.display="none";}}}});
}}
function revokeAll(){{
  fetch("/api/sessions/logout-all",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{uid:_uid}})}})
  .then(function(){{document.getElementById("sess-tbody").innerHTML="<tr><td colspan=6 style=\\"padding:16px;color:#64748b;text-align:center\\">All sessions revoked.</td></tr>";document.querySelector(".btn-all").style.display="none";}});
}}
</script></body></html>"""
            return page
    return redirect("/login")

@app.route("/sessions")
@require_login
def sessions_page():
    uid      = flask_session.get("uid")
    uname    = flask_session.get("username","")
    cur_tok  = flask_session.get("session_token","")
    sessions = db.rows("SELECT * FROM user_sessions WHERE user_id=? ORDER BY last_active DESC", (uid,))
    rows = ""
    for s in sessions:
        tok  = s.get("token","")
        br   = _html.escape(s.get("browser","?"))
        osn  = _html.escape(s.get("os_name","?"))
        geo  = _html.escape(s.get("geo_location","?"))
        ip   = _html.escape(s.get("ip_address","?"))
        ca   = _html.escape(s.get("created_at","?"))
        la   = _html.escape(s.get("last_active","?"))
        ua   = _html.escape(s.get("user_agent","")[:80])
        is_cur = tok == cur_tok
        cur_badge = '<span style="background:#22c55e;color:#000;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:700;margin-left:6px">CURRENT</span>' if is_cur else ""
        icon = "🌐" if "Chrome" in br else "🦊" if "Firefox" in br else "🔵" if "Edge" in br else "🔮" if "Opera" in br else "🖥️"
        revoke_btn = "" if is_cur else f'<button onclick="revokeOne(\'{_html.escape(tok)}\',this)" style="background:#ef4444;color:#fff;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px">Revoke</button>'
        rows += f"""<tr>
<td style="padding:12px 14px"><span style="font-size:18px">{icon}</span> <strong>{br}</strong>{cur_badge}
  <div style="font-size:11px;color:#64748b;margin-top:2px" title="{ua}">{ua[:60]}{"…" if len(ua)>60 else ""}</div></td>
<td style="padding:12px 14px;color:#94a3b8">{osn}</td>
<td style="padding:12px 14px;color:#94a3b8">{geo}</td>
<td style="padding:12px 14px;font-family:monospace;font-size:12px;color:#64748b">{ip}</td>
<td style="padding:12px 14px;font-size:12px;color:#64748b">{ca}<br><span style="color:#475569">Active: {la}</span></td>
<td style="padding:12px 14px">{revoke_btn}</td></tr>"""
    if not rows:
        rows = '<tr><td colspan="6" style="padding:24px;text-align:center;color:#475569">No active sessions found.</td></tr>'
    has_others = any(s.get("token","") != cur_tok for s in sessions)
    logout_all_btn = ""
    if has_others:
        logout_all_btn = '<button onclick="revokeOthers()" style="background:#ef4444;color:#fff;border:none;padding:9px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600">Revoke All Other Sessions</button>'
    uname_safe = _html.escape(uname)
    html = f"""<!DOCTYPE html><html lang="en"><head><title>Active Sessions - FEROXSEI</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif}}
.topbar{{background:#1e293b;border-bottom:1px solid #334155;padding:0 24px;height:52px;display:flex;align-items:center;gap:16px}}
.topbar a{{color:#94a3b8;text-decoration:none;font-size:13px}}
.topbar a:hover{{color:#e2e8f0}}
.container{{max-width:1000px;margin:32px auto;padding:0 20px}}
h1{{font-size:24px;font-weight:700;margin-bottom:6px}}
.sub{{color:#94a3b8;font-size:14px;margin-bottom:24px}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:10px 14px;color:#64748b;border-bottom:1px solid #334155;font-weight:500;background:#0f172a}}
tr:not(:last-child) td{{border-bottom:1px solid #273348}}
.actions{{display:flex;gap:12px;align-items:center;margin-top:20px}}
</style></head><body>
<div class="topbar">
  <a href="/" style="font-weight:700;font-size:15px;color:#e2e8f0">⬡ FEROXSEI</a>
  <a href="/investigations">Investigations</a>
  <a href="/settings">Settings</a>
  <a href="/logout" style="margin-left:auto;color:#ef4444">Sign Out</a>
</div>
<div class="container">
  <h1>🔐 Active Sessions</h1>
  <p class="sub">Signed in as <strong>{uname_safe}</strong> - all active sessions across browsers and devices.</p>
  <div class="card">
    <table><thead><tr>
      <th>Browser / Device</th><th>OS</th><th>Location</th><th>IP Address</th><th>Created / Last Active</th><th></th>
    </tr></thead>
    <tbody id="sess-tbody">{rows}</tbody></table>
  </div>
  <div class="actions">
    {logout_all_btn}
    <a href="/" style="color:#94a3b8;font-size:13px">← Back to Dashboard</a>
  </div>
</div>
<script>
function revokeOne(tok,btn){{
  fetch("/api/sessions/revoke",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{token:tok}})}})
  .then(function(r){{return r.json();}})
  .then(function(){{btn.closest("tr").remove();}});
}}
function revokeOthers(){{
  fetch("/api/sessions/logout-all",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{keep_current:true}})}})
  .then(function(r){{return r.json();}})
  .then(function(){{location.reload();}});
}}
</script></body></html>"""
    return html

@app.route("/api/sessions/revoke", methods=["POST"])
@require_login
def api_session_revoke():
    data    = request.get_json(silent=True) or {}
    token   = data.get("token","")
    uid     = flask_session.get("uid")
    is_adm  = _is_admin()
    if not token:
        return jsonify({"ok": False, "error": "no token"}), 400
    row = db.one("SELECT user_id, username FROM user_sessions WHERE token=?", (token,))
    if not row:
        return jsonify({"ok": False, "error": "session not found"}), 404
    if not is_adm and row["user_id"] != uid:
        return jsonify({"ok": False, "error": "not yours"}), 403
    _revoke_session(token)
    target = row.get("username","?")
    _audit("session_revoke", "session", token[:8], f"user={target}")
    return jsonify({"ok": True})

@app.route("/api/sessions/admin-destroy-all", methods=["POST"])
@require_login
def api_sessions_admin_destroy_all():
    if not _is_admin():
        return jsonify({"ok": False, "error": "admin only"}), 403
    my_tok = flask_session.get("session_token","")
    if my_tok:
        db.exec("DELETE FROM user_sessions WHERE token!=?", (my_tok,))
    else:
        db.exec("DELETE FROM user_sessions", ())
    _audit("session_admin_destroy_all", "sessions", "", "all sessions destroyed except current admin session")
    return jsonify({"ok": True})

@app.route("/api/sessions/logout-all", methods=["POST"])
def api_sessions_logout_all():
    data = request.get_json(silent=True) or {}
    keep_current = data.get("keep_current", False)
    uid_from_body = data.get("uid","")
    uid = flask_session.get("uid") or uid_from_body
    if not uid:
        return jsonify({"ok": False, "error": "no uid"}), 400
    keep_tok = flask_session.get("session_token") if keep_current else None
    _revoke_all_sessions(uid, keep_token=keep_tok)
    _audit("session_logout_all", "user", str(uid))
    return jsonify({"ok": True})

# ═════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT  (admin only)
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/users", methods=["GET","POST"])
@require_admin
def users_page():
    msg = err = ""
    action = request.form.get("action","")

    if request.method == "POST":
        # ── Save analyst permissions ──────────────────────────────────────────
        if action == "save_perms":
            _perm_keys = ["scans", "patterns", "audit", "tor"]
            for k in _perm_keys:
                val = "1" if request.form.get(f"perm_{k}") == "1" else "0"
                _save_setting(f"analyst_perm_{k}", val)
            # Registration toggles
            _save_setting("allow_registration",       "1" if request.form.get("allow_registration") else "0")
            _save_setting("auto_approve_registration","1" if request.form.get("auto_approve_registration") else "0")
            _audit("admin.save_perms")
            msg = "✅ Permissions & registration settings saved."

        # ── Approve pending user ──────────────────────────────────────────────
        elif action == "approve":
            target_id = request.form.get("user_id","")
            target_u  = db.one("SELECT * FROM users WHERE id=?", (target_id,))
            if not target_u:
                err = "User not found."
            else:
                db.exec("UPDATE users SET status='active' WHERE id=?", (target_id,))
                _audit("admin.approve_user", "user", target_id, f"username={target_u['username']}")
                _notify(target_id, "success", "Account Approved",
                        "Your FEROXSEI OSINT account has been approved. You can now log in.", "/")
                # Send approval email if possible
                if target_u.get("email",""):
                    body = f"""<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#0a1220;color:#c8d6ef;padding:32px;border-radius:12px">
<h2 style="color:#00d4ff">Access Approved</h2>
<p>Your FEROXSEI OSINT account <strong>{_html.escape(target_u['username'])}</strong> has been approved. You can now log in.</p>
<a href="/login" style="color:#00d4ff">Log in →</a></div>"""
                    _send_system_email(target_u["email"], "FEROXSEI OSINT - Account Approved", body)
                msg = f"✅ User '{target_u['username']}' approved and can now log in."

        # ── Reject / delete pending user ──────────────────────────────────────
        elif action == "reject":
            target_id = request.form.get("user_id","")
            target_u  = db.one("SELECT * FROM users WHERE id=?", (target_id,))
            if target_u:
                db.exec("DELETE FROM users WHERE id=?", (target_id,))
                _audit("admin.reject_user", "user", target_id, f"username={target_u['username']}")
                msg = f"✅ Registration for '{target_u['username']}' rejected and removed."

        # ── Add user ─────────────────────────────────────────────────────────
        elif action == "add":
            un   = request.form.get("username","").strip()
            em   = request.form.get("email","").strip() or f"{un}@argus.local"
            pw   = request.form.get("password","")
            role = request.form.get("role","analyst")
            if role not in ("admin","analyst"):
                role = "analyst"
            if not un or not pw:
                err = "Username and password are required."
            elif len(pw) < 6:
                err = "Password must be at least 6 characters."
            elif db.one("SELECT id FROM users WHERE username=?", (un,)):
                err = f"Username '{un}' is already taken."
            else:
                uid_new = str(uuid.uuid4())
                db.ins("users", {
                    "id": uid_new, "username": un, "email": em,
                    "password_hash": generate_password_hash(pw),
                    "role": role, "api_keys": "{}", "status": "active", "created_at": _now(),
                    "perm_osint": None, "perm_phishing": None, "perm_scans": None,
                    "perm_patterns": None, "perm_audit": None, "perm_tor": None, "perm_leaks": None
                })
                _audit("admin.add_user", "user", uid_new, f"username={un} role={role}")
                msg = f"✅ User '{un}' created with role '{role}'."

        # ── Edit user ─────────────────────────────────────────────────────────
        elif action == "edit":
            target_id  = request.form.get("user_id","")
            new_role   = request.form.get("role","analyst")
            new_status = request.form.get("status","active")
            new_pw     = request.form.get("password","").strip()
            target_u   = db.one("SELECT * FROM users WHERE id=?", (target_id,))
            if not target_u:
                err = "User not found."
            elif target_u["username"] == "admin" and new_role != "admin":
                err = "Cannot change the admin user's role."
            else:
                if new_role in ("admin","analyst"):
                    db.exec("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
                if new_status in ("active","disabled","pending","inactive"):
                    db.exec("UPDATE users SET status=? WHERE id=?", (new_status, target_id))
                if new_pw:
                    if len(new_pw) < 6:
                        err = "New password must be at least 6 characters."
                    else:
                        db.exec("UPDATE users SET password_hash=? WHERE id=?",
                                (generate_password_hash(new_pw), target_id))
                if not err:
                    _audit("admin.edit_user", "user", target_id,
                           f"role={new_role} status={new_status} pw_reset={'yes' if new_pw else 'no'}")
                    msg = f"✅ User '{target_u['username']}' updated."

        # ── Delete user ───────────────────────────────────────────────────────
        elif action == "delete":
            target_id = request.form.get("user_id","")
            target_u  = db.one("SELECT * FROM users WHERE id=?", (target_id,))
            if not target_u:
                err = "User not found."
            elif target_u["username"] == "admin":
                err = "The default admin account cannot be deleted."
            elif target_u["id"] == flask_session.get("uid"):
                err = "You cannot delete your own account."
            else:
                db.exec("DELETE FROM users WHERE id=?", (target_id,))
                _audit("admin.delete_user", "user", target_id, f"username={target_u['username']}")
                msg = f"✅ User '{target_u['username']}' deleted."

        # ── Toggle active / inactive ──────────────────────────────────────────
        elif action == "toggle_status":
            target_id = request.form.get("user_id","")
            target_u  = db.one("SELECT * FROM users WHERE id=?", (target_id,))
            if not target_u:
                err = "User not found."
            elif target_u["username"] == "admin":
                err = "Cannot deactivate the default admin account."
            elif target_u["id"] == flask_session.get("uid"):
                err = "Cannot deactivate your own account."
            else:
                cur = target_u.get("status") or "active"
                new_st = "active" if cur == "inactive" else "inactive"
                db.exec("UPDATE users SET status=? WHERE id=?", (new_st, target_id))
                verb = "activated" if new_st == "active" else "deactivated"
                _audit(f"admin.{verb}_user", "user", target_id,
                       f"username={target_u['username']} new_status={new_st}")
                msg = f"✅ User '{target_u['username']}' {verb}."

    all_users    = db.rows("SELECT id,username,email,role,status,created_at FROM users ORDER BY created_at ASC")
    pending      = [u for u in all_users if (u.get("status") or "active") == "pending"]
    active_users = [u for u in all_users if (u.get("status") or "active") != "pending"]
    allow_reg        = _get_setting("allow_registration","0") == "1"
    auto_approve_reg = _get_setting("auto_approve_registration","0") == "1"

    def _status_badge(s):
        s = s or "active"
        if s == "active":
            return '<span style="background:#16a34a22;color:#4ade80;border:1px solid #4ade8044;border-radius:4px;padding:1px 8px;font-size:11px">active</span>'
        if s in ("disabled","inactive"):
            return '<span style="background:#7f1d1d22;color:#f87171;border:1px solid #f8717144;border-radius:4px;padding:1px 8px;font-size:11px">inactive</span>'
        return '<span style="background:#92400e22;color:#fbbf24;border:1px solid #fbbf2444;border-radius:4px;padding:1px 8px;font-size:11px">pending</span>'

    # ── Pending approval rows ─────────────────────────────────────────────────
    pending_rows = ""
    for u in pending:
        uid_esc = _html.escape(u["id"])
        un_esc  = _html.escape(u["username"])
        em_esc  = _html.escape(u.get("email","") or "")
        pending_rows += f"""<tr style="background:rgba(251,191,36,.04)">
          <td style="font-weight:600;color:#fbbf24">{un_esc}</td>
          <td style="color:var(--muted)">{em_esc}</td>
          <td style="color:var(--muted);font-size:11px">{(u.get('created_at') or '')[:16]}</td>
          <td style="display:flex;gap:6px">
            <form method="POST" style="display:inline">
              <input type="hidden" name="action" value="approve">
              <input type="hidden" name="user_id" value="{uid_esc}">
              <button class="btn btn-sm" style="background:#16a34a;color:#fff;border-color:#16a34a;padding:3px 10px">✅ Approve</button>
            </form>
            <form method="POST" style="display:inline">
              <input type="hidden" name="action" value="reject">
              <input type="hidden" name="user_id" value="{uid_esc}">
              <button class="btn btn-sm" style="background:#7f1d1d;color:#fca5a5;border-color:#7f1d1d;padding:3px 10px" onclick="return confirm('Reject and delete this registration?')">✗ Reject</button>
            </form>
          </td>
        </tr>"""

    # ── Active/disabled user rows ─────────────────────────────────────────────
    rows_html = ""
    for u in active_users:
        uid_esc       = _html.escape(u["id"])
        un_esc        = _html.escape(u["username"])
        is_admin_user = u["username"] == "admin"
        is_self       = u["id"] == flask_session.get("uid")
        role_badge    = ('<span class="badge" style="background:#6366f133;color:#818cf8">admin</span>'
                         if u["role"] == "admin" else
                         '<span class="badge" style="background:#0369a133;color:#38bdf8">analyst</span>')
        status_badge  = _status_badge(u.get("status","active"))
        can_delete    = not is_admin_user and not is_self
        cur_status    = u.get("status") or "active"
        is_inactive   = cur_status in ("inactive", "disabled")
        del_btn = (f'<form method="POST" style="display:inline">'
                   f'<input type="hidden" name="action" value="delete">'
                   f'<input type="hidden" name="user_id" value="{uid_esc}">'
                   f'<button class="btn btn-sm" style="background:#7f1d1d;color:#fca5a5;padding:3px 10px" '
                   f'onclick="return confirm(\'Delete {un_esc}?\')">🗑 Delete</button></form>'
                   if can_delete else
                   '<span style="color:var(--muted);font-size:11px">protected</span>')
        toggle_btn = ""
        if can_delete:
            if is_inactive:
                toggle_btn = (f'<form method="POST" style="display:inline">'
                              f'<input type="hidden" name="action" value="toggle_status">'
                              f'<input type="hidden" name="user_id" value="{uid_esc}">'
                              f'<button class="btn btn-sm" style="background:#16a34a22;color:#4ade80;border:1px solid #4ade8044;padding:3px 10px">'
                              f'🟢 Activate</button></form>')
            else:
                toggle_btn = (f'<form method="POST" style="display:inline">'
                              f'<input type="hidden" name="action" value="toggle_status">'
                              f'<input type="hidden" name="user_id" value="{uid_esc}">'
                              f'<button class="btn btn-sm" style="background:#92400e22;color:#fbbf24;border:1px solid #fbbf2444;padding:3px 10px" '
                              f'onclick="return confirm(\'Deactivate {un_esc}? Their active session will be terminated immediately.\')">'
                              f'🔴 Deactivate</button></form>')
        rows_html += f"""<tr>
          <td style="font-weight:600;color:var(--text)">{un_esc}</td>
          <td style="color:var(--muted)">{_html.escape(u.get('email','') or '')}</td>
          <td>{role_badge}</td>
          <td>{status_badge}</td>
          <td style="color:var(--muted);font-size:11px">{(u.get('created_at') or '')[:10]}</td>
          <td style="display:flex;gap:4px;flex-wrap:wrap">
            <button onclick="openEdit('{uid_esc}','{un_esc}','{_html.escape(u['role'])}','{_html.escape(cur_status)}')"
                    class="btn btn-sm btn-ghost" style="padding:3px 10px">✏️ Edit</button>
            {toggle_btn}
            {del_btn}
          </td>
        </tr>"""

    alert = (f'<div class="alert alert-info">{_html.escape(msg)}</div>' if msg else
             f'<div class="alert alert-error">{_html.escape(err)}</div>' if err else "")

    pending_section = ""
    if pending:
        pending_section = f"""
<div class="card" style="margin-bottom:20px;border-color:#fbbf24">
  <div class="card-header" style="background:rgba(251,191,36,.06)">
    <span class="card-title" style="color:#fbbf24">⏳ Pending Approval ({len(pending)})</span>
    <span style="font-size:11px;color:var(--muted)">These users registered and are awaiting admin review</span>
  </div>
  <div class="card-body" style="padding:0">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr style="background:var(--bg2);font-size:11px;color:var(--muted);letter-spacing:.5px">
        <th style="padding:10px 14px;text-align:left">USERNAME</th>
        <th style="padding:10px 14px;text-align:left">EMAIL</th>
        <th style="padding:10px 14px;text-align:left">REGISTERED</th>
        <th style="padding:10px 14px;text-align:left">ACTIONS</th>
      </tr></thead>
      <tbody>{pending_rows}</tbody>
    </table>
  </div>
</div>"""

    reg_checked          = 'checked' if allow_reg else ''
    auto_approve_checked = 'checked' if auto_approve_reg else ''
    smtp_ok = _smtp_is_enabled()
    _smtp_mode_display = _get_setting("sys_smtp_mode","mailhog")
    _smtp_ok_label = ("🐳 MailHog" if _smtp_mode_display == "mailhog" else "✅ Custom SMTP") + " - OTP email will be sent"
    smtp_note = (f'<span style="color:#4ade80;font-size:11px">{_smtp_ok_label}</span>'
                 if smtp_ok else
                 '<span style="color:#f59e0b;font-size:11px">⚠ SMTP not configured (General Settings) - OTP skipped, account goes straight to pending</span>')

    html = f"""
{alert}
{pending_section}
<div style="display:grid;grid-template-columns:1fr 380px;gap:24px;align-items:start">

  <!-- Users table -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">👥 Active Users ({len(active_users)})</span>
    </div>
    <div class="card-body" style="padding:0">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:var(--bg2);font-size:11px;color:var(--muted);letter-spacing:.5px">
          <th style="padding:10px 14px;text-align:left">USERNAME</th>
          <th style="padding:10px 14px;text-align:left">EMAIL</th>
          <th style="padding:10px 14px;text-align:left">ROLE</th>
          <th style="padding:10px 14px;text-align:left">STATUS</th>
          <th style="padding:10px 14px;text-align:left">CREATED</th>
          <th style="padding:10px 14px;text-align:left">ACTIONS</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>

  <!-- Right panel -->
  <div style="display:flex;flex-direction:column;gap:16px">

    <!-- Registration settings -->
    <div class="card">
      <div class="card-header"><span class="card-title">🔗 Self-Registration</span></div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="save_perms">
          <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;margin-bottom:12px">
            <input type="checkbox" name="allow_registration" value="1" {reg_checked}
                   style="margin-top:3px;width:16px;height:16px">
            <div>
              <div style="font-size:13px;font-weight:500">Allow public self-registration</div>
              <div style="font-size:11px;color:var(--muted);margin-top:2px">
                Shows a Register link on the login page. New accounts require admin approval before access is granted.
              </div>
            </div>
          </label>
          <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;margin-bottom:12px">
            <input type="checkbox" name="auto_approve_registration" value="1" {auto_approve_checked}
                   style="margin-top:3px;width:16px;height:16px">
            <div>
              <div style="font-size:13px;font-weight:500">Auto Approve new registrations</div>
              <div style="font-size:11px;color:var(--muted);margin-top:2px">
                New accounts are activated immediately without admin approval. Use only on trusted networks.
              </div>
            </div>
          </label>
          <div style="margin-bottom:12px">{smtp_note}</div>
          <button class="btn" style="width:100%;padding:7px">💾 Save</button>
        </form>
      </div>
    </div>

    <!-- Add user -->
    <div class="card">
      <div class="card-header"><span class="card-title">➕ Add User (Direct)</span></div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="add">
          <div class="form-group" style="margin-bottom:10px">
            <label style="font-size:12px">Username</label>
            <input type="text" name="username" required placeholder="analyst01"
                   style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label style="font-size:12px">Email (optional)</label>
            <input type="email" name="email" placeholder="user@org.com"
                   style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label style="font-size:12px">Password (min 6 chars)</label>
            <input type="password" name="password" required placeholder="••••••••"
                   style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
          </div>
          <div class="form-group" style="margin-bottom:14px">
            <label style="font-size:12px">Role</label>
            <select name="role" style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
              <option value="analyst">Analyst (standard)</option>
              <option value="admin">Admin (full access)</option>
            </select>
          </div>
          <button class="btn" style="width:100%">Create Active User →</button>
        </form>
      </div>
    </div>

    <!-- Edit user (hidden until Edit clicked) -->
    <div class="card" id="edit-panel" style="display:none">
      <div class="card-header">
        <span class="card-title">✏️ Edit: <span id="edit-uname"></span></span>
      </div>
      <div class="card-body">
        <form method="POST" id="edit-form">
          <input type="hidden" name="action" value="edit">
          <input type="hidden" name="user_id" id="edit-uid">
          <div class="form-group" style="margin-bottom:10px">
            <label style="font-size:12px">Role</label>
            <select name="role" id="edit-role" style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:10px">
            <label style="font-size:12px">Account Status</label>
            <select name="status" id="edit-status" style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
              <option value="active">Active</option>
              <option value="disabled">Disabled (cannot log in)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:14px">
            <label style="font-size:12px">Reset Password (leave blank to keep)</label>
            <input type="password" name="password" placeholder="New password…"
                   style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px">
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn" style="flex:1">Save Changes</button>
            <button type="button" onclick="document.getElementById('edit-panel').style.display='none'" class="btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>

  </div>
</div>

<script>
function openEdit(uid, uname, role, status) {{
  document.getElementById('edit-panel').style.display = 'block';
  document.getElementById('edit-uid').value = uid;
  document.getElementById('edit-uname').textContent = uname;
  var rsel = document.getElementById('edit-role');
  for (var i=0;i<rsel.options.length;i++) rsel.options[i].selected = rsel.options[i].value===role;
  var ssel = document.getElementById('edit-status');
  for (var i=0;i<ssel.options.length;i++) ssel.options[i].selected = ssel.options[i].value===status;
  document.getElementById('edit-panel').scrollIntoView({{behavior:'smooth'}});
}}
</script>
"""
    return _base("User Management", html, "users")

# ═════════════════════════════════════════════════════════════════════════════
# ACCESS MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/access", methods=["GET","POST"])
@require_login
def access_management():
    if not _is_admin():
        return redirect("/")

    PERMS = [
        ("osint",    "🔍", "OSINT Investigations",   "Can view and create OSINT investigations"),
        ("phishing", "🎣", "Phishing Investigations", "Can view and manage phishing campaigns"),
        ("scans",    "⚡", "Run Scans",               "Can start OSINT scans"),
        ("patterns", "🧩", "Patterns / SAST",         "Can access the patterns and SAST page"),
        ("audit",    "📋", "Audit Log",               "Can view the audit log"),
        ("tor",      "🧅", "TOR Anonymous Mode",      "Can enable/disable TOR anonymisation"),
        ("leaks",    "🔐", "Search Leaks",            "Can search credential leak databases"),
        ("settings", "⚙️",  "Settings",               "Can access the OSINT settings page"),
    ]

    if request.method == "POST":
        action = request.form.get("action","")
        if action == "save_user":
            uid = request.form.get("user_id","").strip()
            if uid:
                updates = {}
                for pk, *_ in PERMS:
                    updates[f"perm_{pk}"] = 1 if request.form.get(f"perm_{pk}") == "1" else 0
                db.upd("users", updates, "id=?", (uid,))
                _audit("access_update", "user", uid,
                       ",".join(f"{k}={v}" for k,v in updates.items()))
        elif action == "save_defaults":
            for pk, *_ in PERMS:
                val = "1" if request.form.get(f"default_{pk}") == "1" else "0"
                _save_setting(f"analyst_perm_{pk}", val)
            _audit("access_defaults_update", "settings", "", "analyst permission defaults updated")
        elif action == "save_ip_allowlist":
            raw = request.form.get("portal_allowed_ips", "").strip()
            _save_setting("portal_allowed_ips", raw)
            _audit("access_ip_allowlist_update", "settings", "",
                   f"allowlist={'(cleared)' if not raw else raw[:120]}")
        return redirect("/access")

    users_list = db.rows(
        "SELECT id, username, email, role, "
        "perm_osint, perm_phishing, perm_scans, perm_patterns, "
        "perm_audit, perm_tor, perm_leaks, perm_settings "
        "FROM users ORDER BY role DESC, username"
    )

    all_sessions = db.rows(
        "SELECT s.token, s.user_id, s.username, s.browser, s.os_name, "
        "s.ip_address, s.geo_location, s.user_agent, s.created_at, s.last_active, "
        "u.role "
        "FROM user_sessions s LEFT JOIN users u ON u.id=s.user_id "
        "ORDER BY s.last_active DESC"
    )
    my_tok = flask_session.get("session_token","")
    sess_rows_html = ""
    for s in all_sessions:
        tok  = s.get("token","")
        br   = _html.escape(s.get("browser","?"))
        osn  = _html.escape(s.get("os_name","?"))
        geo  = _html.escape(s.get("geo_location","?"))
        ip   = _html.escape(s.get("ip_address","?"))
        la   = _html.escape(s.get("last_active","?"))
        ua   = _html.escape(s.get("user_agent","")[:80])
        unam = _html.escape(s.get("username","?"))
        role = s.get("role","analyst")
        role_badge = ('<span class="badge badge-high" style="font-size:10px">ADMIN</span>' if role == "admin"
                      else '<span class="badge badge-blue" style="font-size:10px">ANALYST</span>')
        is_cur = tok == my_tok
        cur_badge = ('<span style="background:#22c55e;color:#000;font-size:10px;padding:2px 7px;'
                     'border-radius:10px;font-weight:700;margin-left:6px">YOUR SESSION</span>') if is_cur else ""
        icon = ("🌐" if "Chrome" in br else "🦊" if "Firefox" in br else
                "🔵" if "Edge" in br else "🔮" if "Opera" in br else "🖥️")
        tok_safe = _html.escape(tok)
        destroy_btn = (
            '<button onclick="destroySession(\'' + tok_safe + '\',\'' + _html.escape(s.get("user_id","")) + '\',this)" '
            'style="background:#ef4444;color:#fff;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px">Destroy</button>'
        ) if not is_cur else '<span style="color:#475569;font-size:12px">Current</span>'
        sess_rows_html += f"""<tr>
<td style="padding:10px 12px">
  <div style="font-weight:600">{unam} {role_badge}</div>
</td>
<td style="padding:10px 12px"><span style="font-size:15px">{icon}</span> {br}{cur_badge}
  <div style="font-size:11px;color:var(--muted)">{ua[:60]}{"…" if len(ua)>60 else ""}</div></td>
<td style="padding:10px 12px;color:var(--muted-text)">{osn}</td>
<td style="padding:10px 12px;color:var(--muted-text)">{geo}</td>
<td style="padding:10px 12px;font-family:monospace;font-size:12px;color:var(--muted)">{ip}</td>
<td style="padding:10px 12px;font-size:12px;color:var(--muted)">{la}</td>
<td style="padding:10px 12px">{destroy_btn}</td></tr>"""

    if not sess_rows_html:
        sess_rows_html = '<tr><td colspan="7" style="padding:20px;text-align:center;color:var(--muted)">No active sessions.</td></tr>'
    # For NULL perm values, substitute the effective global default so the
    # checkbox reflects what the user actually gets, not a hardcoded 1
    _perm_global_defaults = {
        pk: (_get_setting(f"analyst_perm_{pk}", "0") == "1")
        for pk, *_ in PERMS
    }
    for _u in users_list:
        for _pk, *_ in PERMS:
            _col = f"perm_{_pk}"
            if _u.get(_col) is None:
                _u[_col] = 1 if _perm_global_defaults[_pk] else 0

    _perm_headers = "".join(
        f'<th style="text-align:center;font-size:11px;padding:8px 6px">{icon} {label}</th>'
        for _, icon, label, _ in PERMS
    )

    rows_html = ""
    for u in users_list:
        is_admin_user = u.get("role") == "admin"
        role_badge = ('<span class="badge badge-high" style="font-size:10px">ADMIN</span>'
                      if is_admin_user else
                      '<span class="badge badge-blue" style="font-size:10px">ANALYST</span>')
        cells = ""
        for pk, *_ in PERMS:
            col = f"perm_{pk}"
            checked = "checked" if (is_admin_user or u.get(col, 1)) else ""
            disabled = "disabled" if is_admin_user else ""
            cells += (
                f'<td style="text-align:center">'
                f'<input type="checkbox" name="{col}" value="1" {checked} {disabled}'
                f' onchange="markDirty(this,\'{u["id"]}\')" style="width:16px;height:16px"></td>'
            )
        rows_html += f"""<tr id="row-{u['id']}" data-uid="{_html.escape(u['id'])}">
          <td>
            <div style="font-weight:600;color:var(--text)">{_html.escape(u['username'])}</div>
            <div style="font-size:11px;color:var(--muted)">{_html.escape(u.get('email',''))}</div>
          </td>
          <td>{role_badge}</td>
          {cells}
          <td>
            <button id="save-{u['id']}" onclick="saveUser('{u['id']}')"
              class="btn btn-primary btn-sm" style="opacity:.4;cursor:default" disabled>Save</button>
          </td>
        </tr>"""

    default_rows = ""
    for pk, icon, label, desc in PERMS:
        checked = "checked" if _get_setting(f"analyst_perm_{pk}", "1") == "1" else ""
        default_rows += f"""<tr>
          <td><span style="font-size:14px">{icon}</span> <strong>{label}</strong>
              <div style="font-size:11px;color:var(--muted)">{desc}</div></td>
          <td style="text-align:center">
            <input type="checkbox" name="default_{pk}" value="1" {checked}
              style="width:16px;height:16px"></td>
        </tr>"""

    _cur_allowed_ips = _html.escape(_get_setting("portal_allowed_ips", ""))
    _admin_ip = _html.escape(request.remote_addr or "")
    _ip_warn = ('<div style="background:#7c3aed22;border:1px solid #7c3aed;border-radius:8px;'
                'padding:10px 14px;margin-bottom:12px;font-size:13px;color:#c4b5fd">'
                '&#9888; IP restriction is <strong>active</strong>. '
                'Ensure your IP is in the list or you may lose access after saving.</div>'
                if _cur_allowed_ips else "")

    html = f"""
<div class="flex justify-between items-center mb-3">
  <h2 style="font-size:20px;font-weight:700;color:var(--text)">🔑 Access Management</h2>
  <span style="font-size:12px;color:var(--muted)">Per-user permission overrides · changes take effect immediately</span>
</div>

<div class="card mb-4">
  <div class="card-header">
    <span class="card-title">👥 User Permissions</span>
    <span style="font-size:12px;color:var(--muted)">Admin users always have full access</span>
  </div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>User</th><th>Role</th>
      {_perm_headers}
      <th></th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>
</div>

<div class="card mb-4">
  <div class="card-header">
    <span class="card-title">🔐 Analyst Role Defaults</span>
    <span style="font-size:12px;color:var(--muted)">Applied to newly self-registered users before per-user override is set</span>
  </div>
  <form method="POST">
    <input type="hidden" name="action" value="save_defaults">
    <table>
      <thead><tr><th>Permission</th><th style="text-align:center">Enabled by Default</th></tr></thead>
      <tbody>{default_rows}</tbody>
    </table>
    <div style="padding:14px 0 0">
      <button type="submit" class="btn btn-primary">💾 Save Defaults</button>
    </div>
  </form>
</div>

<div class="card mb-4">
  <div class="card-header">
    <span class="card-title">🌐 Portal IP Allowlist</span>
    <span style="font-size:12px;color:var(--muted)">Restrict portal access · phishing /phish/* paths are always public</span>
  </div>
  <form method="POST">
    <input type="hidden" name="action" value="save_ip_allowlist">
    <div style="padding:0 0 14px">
      {_ip_warn}
      <p style="font-size:13px;color:var(--muted);margin-bottom:10px">
        Enter one IP or CIDR range per line (or comma-separated). Leave empty to allow all IPs.<br>
        Only <code>/phish/*</code> paths remain accessible to unlisted IPs - all other pages including login are blocked.
      </p>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;
                  font-size:12px;color:#8b949e;margin-bottom:10px;font-family:monospace">
        Your current IP: <span style="color:#58a6ff;font-weight:600">{_admin_ip}</span>
        &nbsp;&#8592; add this to avoid locking yourself out
      </div>
      <textarea name="portal_allowed_ips" rows="5"
        style="width:100%;background:var(--input-bg);border:1px solid var(--border);
               border-radius:6px;padding:10px 12px;font-family:monospace;font-size:13px;
               color:var(--text);resize:vertical"
        placeholder="192.168.1.0/24&#10;10.0.0.0/8&#10;203.0.113.42">{_cur_allowed_ips}</textarea>
      <div style="padding:12px 0 0;display:flex;gap:10px;align-items:center">
        <button type="submit" class="btn btn-primary">💾 Save Allowlist</button>
        <span style="font-size:12px;color:var(--muted)">Applies immediately to all new requests</span>
      </div>
    </div>
  </form>
</div>

<div class="card">
  <div class="card-header">
    <span class="card-title">🖥️ Active Sessions - All Users</span>
    <button onclick="nukeAllSessions()" style="background:#ef4444;color:#fff;border:none;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">Destroy All (except mine)</button>
  </div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>User</th><th>Browser / Device</th><th>OS</th><th>Location</th><th>IP</th><th>Last Active</th><th></th>
    </tr></thead>
    <tbody id="admin-sess-tbody">{sess_rows_html}</tbody>
  </table>
  </div>
</div>

<script>
function markDirty(cb, uid) {{
  var btn = document.getElementById('save-' + uid);
  if (btn) {{ btn.disabled = false; btn.style.opacity = '1'; btn.style.cursor = 'pointer'; }}
}}
function saveUser(uid) {{
  var row = document.getElementById('row-' + uid);
  var data = new FormData();
  data.append('action','save_user');
  data.append('user_id', uid);
  row.querySelectorAll('input[type=checkbox]').forEach(function(cb) {{
    data.append(cb.name, cb.checked ? '1' : '0');
  }});
  fetch('/access', {{method:'POST', body:data}})
    .then(function(r) {{
      if (r.ok) {{
        var btn = document.getElementById('save-' + uid);
        if (btn) {{ btn.textContent = '\\u2713 Saved'; btn.style.opacity = '.5'; btn.disabled = true; setTimeout(function(){{ btn.textContent = 'Save'; }}, 2000); }}
      }}
    }});
}}
function destroySession(tok, uid, btn) {{
  fetch('/api/sessions/revoke', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{token:tok,admin:true}})}})
  .then(function(r){{ return r.json(); }})
  .then(function(d){{
    if (d.ok) {{ btn.closest('tr').remove(); }}
    else {{ alert('Error: ' + (d.error||'unknown')); }}
  }});
}}
function nukeAllSessions() {{
  if (!confirm('Destroy all sessions except yours? Users will be forced to log in again.')) return;
  fetch('/api/sessions/admin-destroy-all', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:'{{}}'}})
  .then(function(r){{ return r.json(); }})
  .then(function(d){{
    if (d.ok) {{
      var tbody = document.getElementById('admin-sess-tbody');
      var rows = tbody.querySelectorAll('tr');
      rows.forEach(function(r){{
        if (!r.querySelector('.badge') || r.textContent.indexOf('YOUR SESSION')>-1) return;
        var btn = r.querySelector('button');
        if (btn) r.remove();
      }});
    }}
  }});
}}
</script>
"""
    return _base("Access Management", html, "access")


@app.route("/api/users", methods=["GET"])
@require_login
def api_users_list_admin():
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    username_filter = request.args.get("username", "").strip()
    if username_filter:
        rows = db.rows(
            "SELECT id, username, email, role, status, "
            "perm_osint, perm_phishing, perm_scans, perm_patterns, "
            "perm_audit, perm_tor, perm_leaks, perm_settings FROM users WHERE username=?",
            (username_filter,))
    else:
        rows = db.rows(
            "SELECT id, username, email, role, status, "
            "perm_osint, perm_phishing, perm_scans, perm_patterns, "
            "perm_audit, perm_tor, perm_leaks, perm_settings FROM users ORDER BY role DESC, username")
    return jsonify({"ok": True, "users": [dict(r) for r in rows]})

@app.route("/api/access/<uid>", methods=["POST"])
@require_login
def api_access_update(uid):
    if not _is_admin():
        return jsonify({"ok": False, "error": "admin only"}), 403
    data = request.get_json(force=True) or {}
    allowed = {"perm_osint","perm_phishing","perm_scans","perm_patterns","perm_audit","perm_tor","perm_leaks","perm_settings"}
    updates = {k: (1 if v else 0) for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"ok": False, "error": "no valid fields"}), 400
    db.upd("users", updates, "id=?", (uid,))
    _audit("access_update", "user", uid, str(updates))
    return jsonify({"ok": True})

@app.route("/api/users/<uid>/status", methods=["POST"])
@require_login
def api_user_set_status(uid):
    """Admin API: set user status to 'active' or 'inactive'.
    Immediate effect - _user_is_live() is checked on every request."""
    if not _is_admin():
        return jsonify({"ok": False, "error": "admin only"}), 403
    data       = request.get_json(force=True) or {}
    new_status = data.get("status", "")
    if new_status not in ("active", "inactive"):
        return jsonify({"ok": False, "error": "status must be 'active' or 'inactive'"}), 400
    target_u = db.one("SELECT * FROM users WHERE id=?", (uid,))
    if not target_u:
        return jsonify({"ok": False, "error": "user not found"}), 404
    if target_u["username"] == "admin":
        return jsonify({"ok": False, "error": "cannot deactivate the default admin"}), 403
    if uid == flask_session.get("uid"):
        return jsonify({"ok": False, "error": "cannot deactivate yourself"}), 403
    db.exec("UPDATE users SET status=? WHERE id=?", (new_status, uid))
    verb = "activated" if new_status == "active" else "deactivated"
    _audit(f"admin.{verb}_user", "user", uid,
           f"username={target_u['username']} status={new_status}")
    return jsonify({"ok": True, "status": new_status, "username": target_u["username"]})

# ═════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/")
@require_login
def dashboard():
    uid      = flask_session["uid"]
    is_admin = _is_admin()
    # Stats - admin sees platform-wide totals; user sees their own
    if is_admin:
        total_inv   = db.one("SELECT COUNT(*) as c FROM investigations WHERE COALESCE(deleted_by_user,0)=0")["c"]
        total_scans = db.one("SELECT COUNT(*) as c FROM osint_scans WHERE COALESCE(deleted_by_user,0)=0")["c"]
        total_finds = db.one("SELECT COUNT(*) as c FROM osint_findings f JOIN osint_scans s ON f.scan_id=s.id WHERE COALESCE(s.deleted_by_user,0)=0")["c"]
        total_ent   = db.one("SELECT COUNT(*) as c FROM entities")["c"] if db.one("SELECT 1 FROM entities LIMIT 1") else 0
        running_scans = db.rows("SELECT * FROM osint_scans WHERE status='running' AND COALESCE(deleted_by_user,0)=0 ORDER BY started_at DESC")
        recent_inv    = db.rows("SELECT i.*, u.username as owner_name FROM investigations i LEFT JOIN users u ON i.user_id=u.id WHERE COALESCE(i.deleted_by_user,0)=0 ORDER BY i.updated_at DESC LIMIT 6")
        recent_finds  = db.rows("""SELECT f.*,s.target FROM osint_findings f
            JOIN osint_scans s ON f.scan_id=s.id WHERE COALESCE(s.deleted_by_user,0)=0
            ORDER BY f.created_at DESC LIMIT 12""")
    else:
        total_inv   = db.one("SELECT COUNT(*) as c FROM investigations WHERE user_id=? AND COALESCE(deleted_by_user,0)=0",(uid,))["c"]
        total_scans = db.one("SELECT COUNT(*) as c FROM osint_scans WHERE user_id=? AND COALESCE(deleted_by_user,0)=0",(uid,))["c"]
        total_finds = db.one("SELECT COUNT(*) as c FROM osint_findings f JOIN osint_scans s ON f.scan_id=s.id WHERE s.user_id=? AND COALESCE(s.deleted_by_user,0)=0",(uid,))["c"]
        total_ent   = db.one("SELECT COUNT(*) as c FROM entities e JOIN investigations i ON e.investigation_id=i.id WHERE i.user_id=?",(uid,))["c"] if db.one("SELECT 1 FROM entities LIMIT 1") else 0
        running_scans = db.rows("SELECT * FROM osint_scans WHERE user_id=? AND status='running' AND COALESCE(deleted_by_user,0)=0 ORDER BY started_at DESC",(uid,))
        recent_inv    = db.rows("SELECT i.*, '' as owner_name FROM investigations i WHERE i.user_id=? AND COALESCE(i.deleted_by_user,0)=0 ORDER BY i.updated_at DESC LIMIT 6",(uid,))
        recent_finds  = db.rows("""SELECT f.*,s.target FROM osint_findings f
            JOIN osint_scans s ON f.scan_id=s.id WHERE s.user_id=? AND COALESCE(s.deleted_by_user,0)=0
            ORDER BY f.created_at DESC LIMIT 12""",(uid,))

    # Running scan progress bars
    running_html = ""
    for s in running_scans:
        prog = s.get("progress",0)
        mod  = s.get("current_module","")
        running_html += f"""
        <div style="margin-bottom:14px">
          <div class="flex justify-between mb-2">
            <span style="font-size:13px;font-weight:500">{s['target']}</span>
            <span class="badge badge-info scan-status-running">RUNNING</span>
          </div>
          <div class="progress-bar"><div class="progress-fill" style="width:{prog}%"></div></div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">{mod} - {prog}%</div>
        </div>"""
    if not running_html:
        running_html = '<div class="text-muted text-sm">No active scans</div>'

    # Recent investigations cards
    inv_cards = ""
    for inv in recent_inv:
        owner_tag = (f'<div style="font-size:10px;color:var(--warning);margin-top:2px">👤 {_html.escape(inv.get("owner_name","") or "")}</div>'
                     if is_admin and inv.get("owner_name") else "")
        inv_cards += f"""
        <a href="/investigation/{inv['id']}" style="text-decoration:none">
        <div class="card" style="cursor:pointer;margin-bottom:0;border-left:3px solid {inv.get('color','#00d4ff')}">
          <div class="card-body" style="padding:14px">
            <div class="flex justify-between items-center">
              <div style="font-weight:600;font-size:13px;color:var(--text)">{_html.escape(inv['title'])}</div>
              <span class="badge badge-{'info' if inv['status']=='active' else 'low'}">{inv['status']}</span>
            </div>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">{_html.escape(inv.get('target',''))}</div>
            {owner_tag}
            <div style="font-size:11px;color:var(--muted);margin-top:4px">{inv['created_at'][:10]}</div>
          </div>
        </div></a>"""
    if not inv_cards:
        inv_cards = '<div class="text-muted text-sm">No investigations yet. <a href="/investigation/new">Create one →</a></div>'

    # Recent findings
    finds_html = ""
    for f in recent_finds:
        sev  = f.get("severity","info")
        finds_html += f"""<tr>
          <td><span class="badge badge-{sev}">{sev}</span></td>
          <td class="mono" style="font-size:11px;color:var(--text2)">{f.get('module','')}</td>
          <td class="truncate">{f.get('title','')[:80]}</td>
          <td style="font-size:11px;color:var(--muted)">{f.get('target','')}</td>
          <td style="font-size:11px;color:var(--muted)">{str(f.get('created_at',''))[:16]}</td>
        </tr>"""
    if not finds_html:
        finds_html = '<tr><td colspan=5 class="text-muted text-sm" style="text-align:center;padding:20px">No findings yet</td></tr>'

    html = f"""
<div class="stats-grid">
  <div class="stat-card"><div class="stat-icon">🗂️</div><div class="stat-value">{total_inv}</div><div class="stat-label">Investigations</div></div>
  <div class="stat-card"><div class="stat-icon">🔍</div><div class="stat-value">{total_scans}</div><div class="stat-label">Scans Run</div></div>
  <div class="stat-card"><div class="stat-icon">🎯</div><div class="stat-value">{total_finds}</div><div class="stat-label">Findings</div></div>
  <div class="stat-card"><div class="stat-icon">🕸️</div><div class="stat-value">{total_ent}</div><div class="stat-label">Entities Mapped</div></div>
</div>
<div class="grid2" style="gap:20px;align-items:start">
  <div>
    <div class="card">
      <div class="card-header">
        <span class="card-title">🗂️ Investigations</span>
        <a href="/investigation/new" class="btn btn-primary btn-sm">+ New</a>
      </div>
      <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        {inv_cards}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">⚡ Active Scans</span></div>
      <div class="card-body">{running_html}</div>
    </div>
  </div>
  <div class="card">
    <div class="card-header">
      <span class="card-title">🎯 Recent Findings</span>
      <a href="/investigations" class="btn btn-ghost btn-sm">View All</a>
    </div>
    <div class="card-body" style="padding:0">
      <table>
        <thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Target</th><th>When</th></tr></thead>
        <tbody>{finds_html}</tbody>
      </table>
    </div>
  </div>
</div>
<script>
{'setTimeout(()=>location.reload(),8000)' if running_scans else ''}
</script>"""
    return _base("Dashboard", html, "dashboard")

# ═════════════════════════════════════════════════════════════════════════════
# INVESTIGATIONS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/investigations")
@require_login
def investigations():
    uid      = flask_session["uid"]
    is_admin = _is_admin()
    # Admin sees every investigation; standard users see their own only
    if is_admin:
        rows = db.rows("SELECT i.*, u.username as owner_name FROM investigations i LEFT JOIN users u ON i.user_id=u.id ORDER BY i.updated_at DESC")
    else:
        rows = db.rows("SELECT i.*, '' as owner_name FROM investigations i WHERE i.user_id=? ORDER BY i.updated_at DESC", (uid,))

    active_rows  = [r for r in rows if not r.get("deleted_by_user")]
    deleted_rows = [r for r in rows if r.get("deleted_by_user")]
    deleted_count = len(deleted_rows)

    def _inv_row(inv, is_deleted=False):
        itype     = inv.get("inv_type", "osint")
        type_badge = ('<span style="background:#ff6b35;color:#fff;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;margin-left:6px">🎣 PHISHING</span>'
                      if itype == "phishing" else
                      '<span style="background:var(--primary);color:#000;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;margin-left:6px">🔍 OSINT</span>')
        owner_tag = (f'<div class="text-sm" style="color:var(--warning);font-size:10px">👤 {_html.escape(inv.get("owner_name","") or inv["user_id"])}</div>'
                     if is_admin and inv.get("user_id") != uid else "")
        del_badge = '<span class="badge badge-high" style="font-size:10px;margin-left:4px">DELETED</span>' if is_deleted else ""
        row_cls   = "inv-row-deleted" if is_deleted else ""
        row_sty   = "display:none;opacity:0.55;background:rgba(255,80,80,0.06)" if is_deleted else ""
        if is_deleted:
            _iid = inv['id']
            _purge_inv = (
                '<button onclick="hardDeleteInv(\'' + _iid + '\',this.closest(\'tr\'))" class="btn btn-danger btn-sm">🗑 Purge</button>'
                if is_admin else ''
            )
            actions = f"""
              <a href="/investigation/{inv['id']}" class="btn btn-ghost btn-sm">Open</a>
              <button onclick="restoreInv('{inv['id']}',this.closest('tr'))" class="btn btn-ghost btn-sm" style="color:var(--success)">♻ Restore</button>
              {_purge_inv}"""
        else:
            if itype == "phishing":
                add_btn = f'<a href="/investigation/{inv["id"]}/campaign/new" class="btn btn-sm" style="background:#ff6b35;border-color:#ff6b35;color:#fff">+ Campaign</a>'
            else:
                add_btn = f'<a href="/investigation/{inv["id"]}/scan/new" class="btn btn-primary btn-sm">+ Scan</a>'
            actions = f"""
              <a href="/investigation/{inv['id']}" class="btn btn-ghost btn-sm">Open</a>
              {add_btn}
              <button onclick="deleteInv('{inv['id']}',this.closest('tr'))" class="btn btn-danger btn-sm" title="Delete">🗑</button>"""
        return f"""<tr class="{row_cls}" style="{row_sty}">
          <td>
            <div style="display:flex;align-items:center;gap:0;flex-wrap:wrap">
              <a href="/investigation/{inv['id']}" style="font-weight:600;color:var(--primary)">{_html.escape(inv['title'])}</a>{del_badge}{type_badge}
            </div>
            <div class="text-sm text-muted mt-1">{_html.escape(inv.get('description','')[:80])}</div>
            {owner_tag}
          </td>
          <td class="mono text-sm">{_html.escape(inv.get('target',''))}</td>
          <td><span class="badge badge-{'info' if inv['status']=='active' else 'low'}">{inv['status']}</span></td>
          <td class="text-sm text-muted">{str(inv['created_at'])[:10]}</td>
          <td><div class="flex gap-2">{actions}</div></td>
        </tr>"""

    rows_html = "".join(_inv_row(inv) for inv in active_rows)
    rows_html += "".join(_inv_row(inv, is_deleted=True) for inv in deleted_rows)

    if not active_rows and not deleted_rows:
        rows_html = '<tr><td colspan=5 style="text-align:center;padding:30px;color:var(--muted)">No investigations yet. <a href="/investigation/new">Create your first →</a></td></tr>'

    show_del_cb = (f'<label style="font-size:12px;color:var(--muted);cursor:pointer;display:flex;align-items:center;gap:5px">'
                   f'<input type="checkbox" id="showDelInvCb" onchange="toggleDeletedInvs(this.checked)"> Show deleted ({deleted_count})</label>'
                   if deleted_count > 0 or is_admin else "")

    html = f"""
<div class="flex justify-between items-center mb-3">
  <div class="section-title">{"All Users' Investigations" if is_admin else "My Investigations"}</div>
  <div class="flex gap-2" style="align-items:center">
    {show_del_cb}
    <a href="/investigation/new" class="btn btn-primary">+ New Investigation</a>
  </div>
</div>
<div class="card">
  <table>
    <thead><tr><th>Title</th><th>Target</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody id="inv-tbody">{rows_html}</tbody>
  </table>
</div>
<script>
function toggleDeletedInvs(show) {{
  document.querySelectorAll('#inv-tbody tr.inv-row-deleted').forEach(function(r){{ r.style.display = show ? '' : 'none'; }});
}}
function deleteInv(iid, row) {{
  if (!confirm('Delete this investigation? You can restore it later.')) return;
  fetch('/api/investigation/' + iid + '/delete', {{method:'POST'}})
    .then(r=>r.json()).then(function(d) {{
      if (!d.ok) return;
      if (d.soft) {{
        row.classList.add('inv-row-deleted');
        row.style.opacity = '0.55';
        row.style.background = 'rgba(255,80,80,0.06)';
        var cb = document.getElementById('showDelInvCb');
        if (!cb || !cb.checked) row.style.display = 'none';
      }} else {{
        row.remove();
      }}
    }});
}}
function restoreInv(iid, row) {{
  fetch('/api/investigation/' + iid + '/restore', {{method:'POST'}})
    .then(r=>r.json()).then(function(d) {{
      if (!d.ok) return;
      row.classList.remove('inv-row-deleted');
      row.style.display = '';
      row.style.opacity = '';
      row.style.background = '';
    }});
}}
function hardDeleteInv(iid, row) {{
  if (!confirm('Permanently delete this investigation and ALL its data? This cannot be undone.')) return;
  fetch('/api/investigation/' + iid + '/delete', {{method:'POST'}})
    .then(r=>r.json()).then(function(d) {{ if (d.ok && row) row.remove(); }});
}}
</script>"""
    return _base("Investigations", html, "investigations")

@app.route("/investigation/new", methods=["GET","POST"])
@require_login
def new_investigation():
    uid      = flask_session["uid"]
    inv_type = request.args.get("type","")   # ?type=osint or ?type=phishing

    if request.method == "POST":
        inv_type = request.form.get("inv_type", "osint")
        iid = str(uuid.uuid4())
        db.ins("investigations", {
            "id":iid, "user_id":uid,
            "title":    request.form.get("title","Untitled Investigation"),
            "description": request.form.get("description",""),
            "target":   request.form.get("target",""),
            "status":   "active",
            "inv_type": inv_type,
            "tags":     json.dumps([t.strip() for t in request.form.get("tags","").split(",") if t.strip()]),
            "color":    request.form.get("color","#00d4ff"),
            "created_at": _now(), "updated_at": _now()
        })
        _audit("create_investigation","investigation",iid,request.form.get("title",""))
        _replay_step(iid,"create","Investigation created",
                     {"target":request.form.get("target",""),"type":inv_type},
                     flask_session["username"])
        return redirect(f"/investigation/{iid}")

    # ── Type selector (no ?type param yet) ───────────────────────────────────
    if not inv_type:
        html = """
<div style="max-width:820px;margin:0 auto">
  <div style="text-align:center;margin-bottom:32px">
    <h2 style="font-size:22px;font-weight:700;color:var(--text)">What type of investigation?</h2>
    <p style="color:var(--muted);font-size:14px">Choose the investigation type to get started with the right workflow and tools.</p>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">

    <a href="/investigation/new?type=osint" style="text-decoration:none">
    <div class="card" style="cursor:pointer;border:2px solid var(--border);transition:all .2s;padding:0"
         onmouseover="this.style.borderColor='var(--primary)';this.style.transform='translateY(-2px)'"
         onmouseout="this.style.borderColor='var(--border)';this.style.transform=''">
      <div style="background:linear-gradient(135deg,#0a1f3a,#0d2d50);padding:28px;border-radius:6px 6px 0 0;text-align:center">
        <div style="font-size:52px;margin-bottom:8px">🔍</div>
        <div style="font-size:20px;font-weight:700;color:var(--primary)">OSINT Investigation</div>
        <div style="font-size:12px;color:var(--muted);margin-top:4px">Open-Source Intelligence</div>
      </div>
      <div style="padding:20px">
        <p style="font-size:13px;color:var(--text2);line-height:1.7">Automated recon across 22+ modules - domain intel, email harvesting, social media, dark web, DNS, certificate transparency, and more.</p>
        <ul style="font-size:12px;color:var(--muted);line-height:2;padding-left:16px;margin:10px 0">
          <li>Domain / IP / Email / Username targets</li>
          <li>22+ intelligence modules</li>
          <li>Entity graph &amp; relationship mapping</li>
          <li>AI-powered analysis &amp; reporting</li>
        </ul>
        <div class="btn btn-primary" style="display:inline-block;margin-top:8px">Start OSINT Investigation →</div>
      </div>
    </div></a>

    <a href="/investigation/new?type=phishing" style="text-decoration:none">
    <div class="card" style="cursor:pointer;border:2px solid var(--border);transition:all .2s;padding:0"
         onmouseover="this.style.borderColor='#ff6b35';this.style.transform='translateY(-2px)'"
         onmouseout="this.style.borderColor='var(--border)';this.style.transform=''">
      <div style="background:linear-gradient(135deg,#2d1a0a,#3d2010);padding:28px;border-radius:6px 6px 0 0;text-align:center">
        <div style="font-size:52px;margin-bottom:8px">🎣</div>
        <div style="font-size:20px;font-weight:700;color:#ff6b35">Phishing Campaign</div>
        <div style="font-size:12px;color:var(--muted);margin-top:4px">Social Engineering Simulation</div>
      </div>
      <div style="padding:20px">
        <p style="font-size:13px;color:var(--text2);line-height:1.7">Plan and track phishing simulations - email templates, target groups, sending profiles, TOR-aware delivery, and per-user click/open/submit tracking.</p>
        <ul style="font-size:12px;color:var(--muted);line-height:2;padding-left:16px;margin:10px 0">
          <li>6+ built-in realistic templates</li>
          <li>TOR-aware SMTP delivery</li>
          <li>Per-target open/click/submit tracking</li>
          <li>Campaign analytics &amp; reports</li>
        </ul>
        <div class="btn" style="display:inline-block;margin-top:8px;background:#ff6b35;color:#fff">Start Phishing Campaign →</div>
      </div>
    </div></a>

  </div>
  <div style="text-align:center;margin-top:20px">
    <a href="/investigations" class="btn btn-ghost">← Cancel</a>
  </div>
</div>"""
        return _base("New Investigation", html, "investigations")

    # ── Type-specific creation form ───────────────────────────────────────────
    if inv_type == "phishing":
        type_badge = '<span style="background:#ff6b35;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:600;margin-left:8px">🎣 PHISHING</span>'
        target_hint = "Target organization domain (e.g. acme.com)"
        placeholder_title = "Acme Corp Phishing Assessment 2025"
    else:
        type_badge = '<span style="background:var(--primary);color:#000;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:600;margin-left:8px">🔍 OSINT</span>'
        target_hint = "Primary target (domain / email / username / IP)"
        placeholder_title = "Operation Shadow Fox"

    html = f"""
<div style="max-width:700px;margin:0 auto">
<div class="card">
  <div class="card-header">
    <span class="card-title">🗂️ New Investigation{type_badge}</span>
    <a href="/investigation/new" class="btn btn-ghost btn-sm">← Change type</a>
  </div>
  <div class="card-body">
  <form method="POST">
    <input type="hidden" name="inv_type" value="{inv_type}">
    <div class="form-group"><label>Investigation Title *</label>
      <input type="text" name="title" placeholder="{placeholder_title}" required></div>
    <div class="form-group"><label>Primary Target</label>
      <input type="text" name="target" placeholder="{target_hint}"></div>
    <div class="form-group"><label>Description</label>
      <textarea name="description" placeholder="Scope, objective, authorized by..."></textarea></div>
    <div class="form-row">
      <div class="form-group"><label>Tags (comma-separated)</label>
        <input type="text" name="tags" placeholder="corporate, phishing, q4-2025"></div>
      <div class="form-group"><label>Color Label</label>
        <input type="color" name="color" value="{'#ff6b35' if inv_type=='phishing' else '#00d4ff'}" style="height:40px;padding:4px"></div>
    </div>
    <div class="flex gap-2 mt-3">
      <button class="btn btn-primary">Create Investigation →</button>
      <a href="/investigations" class="btn btn-ghost">Cancel</a>
    </div>
  </form>
  </div>
</div>
</div>"""
    return _base("New Investigation", html, "investigations")

def _phishing_campaigns_tab(inv_id, uid):
    """Render the phishing campaigns tab panel for an investigation."""
    campaigns = db.rows(
        "SELECT c.*,COALESCE(t.name, c.template_name) as template_name,g.name as group_name FROM phishing_campaigns c "
        "LEFT JOIN phishing_templates t ON c.template_id=t.id AND c.template_id!='' "
        "LEFT JOIN phishing_target_groups g ON c.target_group_id=g.id AND c.target_group_id!='' "
        "WHERE c.investigation_id=? ORDER BY c.created_at DESC", (inv_id,))
    status_badge = {"draft":"badge-blue","active":"badge-info","completed":"badge-low","paused":"badge-medium","cancelled":"badge-high"}
    rows_html = ""
    for c in campaigns:
        sb = status_badge.get(c.get("status","draft"),"badge-blue")
        total_r = db.one("SELECT COUNT(*) as c FROM phishing_results WHERE campaign_id=?",(c["id"],)) or {"c":0}
        opened  = db.one("SELECT COUNT(*) as c FROM phishing_results WHERE campaign_id=? AND opened_at!=''",(c["id"],)) or {"c":0}
        clicked = db.one("SELECT COUNT(*) as c FROM phishing_results WHERE campaign_id=? AND clicked_at!=''",(c["id"],)) or {"c":0}
        submitted= db.one("SELECT COUNT(*) as c FROM phishing_results WHERE campaign_id=? AND submitted_at!=''",(c["id"],)) or {"c":0}
        rows_html += f"""<tr>
          <td><strong style="color:var(--primary)">{_html.escape(c.get('name',''))}</strong>
              <div class="text-sm text-muted">{_html.escape(c.get('template_name','') or 'No template')}</div></td>
          <td><span class="badge {sb}">{c.get('status','draft').upper()}</span></td>
          <td class="text-sm text-muted">{_html.escape(c.get('group_name','') or '-')}</td>
          <td class="text-sm mono">{total_r['c']} sent · {opened['c']} opened · {clicked['c']} clicked · {submitted['c']} submitted</td>
          <td class="text-sm text-muted">{str(c.get('created_at',''))[:10]}</td>
          <td>
            <a href="/investigation/{inv_id}/campaign/{c['id']}" class="btn btn-ghost btn-sm">📊 Results</a>
            <button onclick="deleteCampaign('{c['id']}',this.closest('tr'))" class="btn btn-danger btn-sm">🗑</button>
          </td>
        </tr>"""
    if not rows_html:
        rows_html = f'<tr><td colspan=6 style="text-align:center;padding:30px;color:var(--muted)">No campaigns yet · <a href="/investigation/{inv_id}/campaign/new" style="color:#ff6b35">Create your first phishing campaign →</a></td></tr>'
    return f"""<div id="tab-phishing" class="tab-pane active">
  <div class="card">
    <div class="card-header">
      <span class="card-title" style="color:#ff6b35">🎣 Phishing Campaigns</span>
      <a href="/investigation/{inv_id}/campaign/new" class="btn btn-sm" style="background:#ff6b35;color:#fff;border-color:#ff6b35">+ New Campaign</a>
    </div>
    <table>
      <thead><tr><th>Campaign</th><th>Status</th><th>Target Group</th><th>Results</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
<script>
function deleteCampaign(cid, row) {{
  if (!confirm('Delete this campaign and all results?')) return;
  fetch('/api/phishing/campaign/' + cid + '/delete', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{ if(d.ok && row) row.remove(); }});
}}
</script>"""

@app.route("/investigation/<inv_id>")
@require_login
def view_investigation(inv_id):
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    if not inv:
        return redirect("/investigations")
    # Non-admin users may only view their own investigations
    if not _is_admin() and inv["user_id"] != uid:
        return redirect("/investigations")
    # Soft-deleted investigations are hidden from the owning user (admin still sees them)
    if not _is_admin() and inv.get("deleted_by_user"):
        return redirect("/investigations")
    # Gate on investigation-type-specific access permission
    if not _is_admin():
        _itype = inv.get("inv_type", "osint")
        if _itype == "osint" and not _analyst_can("osint"):
            return redirect("/investigations")
        if _itype == "phishing" and not _analyst_can("phishing"):
            return redirect("/investigations")

    # All scans for this investigation (admin sees all including soft-deleted; users see all too for count but hide in UI)
    scans   = db.rows(
        "SELECT * FROM osint_scans WHERE investigation_id=? ORDER BY created_at DESC",
        (inv_id,))
    notes   = db.rows("SELECT * FROM analyst_notes WHERE investigation_id=? ORDER BY created_at DESC",(inv_id,))
    replay  = db.rows("SELECT * FROM investigation_replay WHERE investigation_id=? ORDER BY step_number ASC",(inv_id,))
    entities= db.rows("SELECT * FROM entities WHERE investigation_id=? ORDER BY confidence DESC",(inv_id,))
    rels    = db.rows("SELECT * FROM entity_relationships WHERE investigation_id=?",(inv_id,))

    # Auto-fix stale "running" scans (engine no longer has an active thread for them)
    active_ids = set(engine._running_scans.keys()) if hasattr(engine, '_running_scans') else set()
    for s in scans:
        if s.get("status") == "running" and s["id"] not in active_ids:
            db.upd("osint_scans", {"status": "stopped", "completed_at": _now()},
                   "id=?", (s["id"],))
            s["status"] = "stopped"

    # Active scans only for findings count (exclude soft-deleted)
    active_scans = [s for s in scans if not s.get("deleted_by_user")]
    scan_ids = tuple(s["id"] for s in active_scans) or ("__none__",)
    ph = ",".join("?" * len(scan_ids))
    all_findings = db.rows(f"SELECT * FROM osint_findings WHERE scan_id IN ({ph})", scan_ids)
    sev_counts = {}
    for f in all_findings:
        sv = f["severity"]
        sev_counts[sv] = sev_counts.get(sv,0)+1

    total_findings = len(all_findings)
    deleted_count  = sum(1 for s in scans if s.get("deleted_by_user"))

    # ── Found Images tab - matched images from reverse image search ────────────
    # Collect all imageOsint "Reverse Image Search" findings across every scan
    _img_matches_all = []   # list of {scan_id, target, match:{url,thumb,sim,source,domain,title}}
    _img_refs_all    = []   # reference links (no high-confidence match)
    for _f in all_findings:
        if _f.get("module") != "imageOsint" or "Reverse" not in _f.get("title", ""):
            continue
        _sid2   = _f["scan_id"]
        _scan2  = next((s for s in scans if s["id"] == _sid2), None)
        _target2 = (_scan2.get("target", "") if _scan2 else "")
        try:
            _rd2 = json.loads(_f.get("raw_data", "{}") or "{}")
        except Exception:
            _rd2 = {}
        for _m in _rd2.get("matched", []):
            _img_matches_all.append({"scan_id": _sid2, "target": _target2, "match": _m})
        for _r in _rd2.get("reference", []):
            _img_refs_all.append({"scan_id": _sid2, "target": _target2, "ref": _r})

    _images_tab_html = ""

    if _img_matches_all:
        _images_tab_html += (
            '<div style="font-size:11px;color:var(--muted);margin-bottom:12px">'
            f'{len(_img_matches_all)} matched image(s) found across all scans '
            '(perceptual similarity ≥ 60%)</div>'
        )
        _images_tab_html += (
            '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px">'
        )
        for _im in _img_matches_all:
            _m2   = _im["match"]
            _url2 = _html.escape(_m2.get("url", ""))
            _th2  = _html.escape(_m2.get("thumb", ""))
            _sim2 = _m2.get("similarity", 0)
            _src2 = _html.escape(_m2.get("source", ""))
            _dom2 = _html.escape(_m2.get("domain", "")[:30])
            _ttl2 = _html.escape(_m2.get("title", "")[:60])
            _tgt2 = _html.escape(_im.get("target", "")[:30])
            _scl2 = _html.escape(_im.get("scan_id", ""))
            _sim_color2 = "#4ade80" if _sim2 >= 80 else "#facc15" if _sim2 >= 60 else "#94a3b8"
            _thumb_html2 = (
                f'<a href="{_url2}" target="_blank" rel="noopener noreferrer">'
                f'<img src="{_th2}" alt="Match thumbnail" loading="lazy"'
                f' style="width:100%;height:140px;object-fit:cover;border-radius:6px 6px 0 0;'
                f'background:#111;display:block"'
                f' onerror="this.style.display=\'none\'"></a>'
            ) if _th2 else (
                f'<a href="{_url2}" target="_blank" rel="noopener noreferrer">'
                f'<div style="width:100%;height:140px;background:var(--bg3);'
                f'border-radius:6px 6px 0 0;display:flex;align-items:center;'
                f'justify-content:center;font-size:32px;color:var(--muted)">🖼️</div></a>'
            )
            _images_tab_html += (
                f'<div style="background:var(--bg2);border:1px solid var(--border);'
                f'border-radius:8px;overflow:hidden">'
                f'{_thumb_html2}'
                f'<div style="padding:10px">'
                f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">'
                f'<span style="background:{_sim_color2}22;color:{_sim_color2};'
                f'border:1px solid {_sim_color2}44;border-radius:4px;'
                f'font-size:10px;padding:1px 6px;font-weight:700">{_sim2}% match</span>'
                f'<span style="font-size:10px;color:var(--muted)">{_src2}</span>'
                f'</div>'
                f'<div style="font-size:11px;color:var(--text2);margin-bottom:4px">{_dom2}</div>'
                f'<div style="font-size:10px;color:var(--muted);margin-bottom:8px">{_ttl2}</div>'
                f'<a href="{_url2}" target="_blank" rel="noopener noreferrer"'
                f' style="font-size:10px;color:var(--primary);word-break:break-all">'
                f'Open Source Page →</a>'
                f'<div style="font-size:9px;color:var(--muted);margin-top:6px;'
                f'border-top:1px solid var(--border);padding-top:5px">'
                f'From scan: <a href="/scan/{_scl2}"'
                f' style="color:var(--muted)">{_tgt2}</a></div>'
                f'</div></div>'
            )
        _images_tab_html += '</div>'

    if _img_refs_all:
        _images_tab_html += (
            '<div style="margin-top:20px">'
            '<div style="font-size:11px;color:var(--muted);text-transform:uppercase;'
            'letter-spacing:.6px;margin-bottom:10px">Search Result Pages (no direct match)</div>'
        )
        for _ir in _img_refs_all[:20]:
            _r2   = _ir["ref"]
            _rurl2 = _html.escape(_r2.get("url", ""))
            _rsrc2 = _html.escape(_r2.get("source", ""))
            _rttl2 = _html.escape(_r2.get("title", "")[:70])
            if _rurl2:
                _images_tab_html += (
                    f'<div style="padding:6px 0;border-bottom:1px solid var(--border)20;'
                    f'font-size:11px">'
                    f'<span style="color:var(--muted);margin-right:8px">[{_rsrc2}]</span>'
                    f'<a href="{_rurl2}" target="_blank" rel="noopener noreferrer"'
                    f' style="color:var(--primary)">{_rttl2 or _rurl2[:60]}</a>'
                    f'</div>'
                )
        _images_tab_html += '</div>'

    if not _img_matches_all and not _img_refs_all:
        _images_tab_html = (
            '<div style="text-align:center;padding:40px;color:var(--muted)">'
            '<div style="font-size:36px;margin-bottom:12px">🖼️</div>'
            '<div style="font-size:14px">No matched images found yet.</div>'
            '<div style="font-size:12px;margin-top:8px">'
            'Run an Image OSINT scan - reverse image search will populate this tab.</div>'
            '</div>'
        )

    # Scans table with rescan + delete/restore actions
    scans_html = ""
    for s in scans:
        prog     = s.get("progress",0)
        status   = s.get("status","pending")
        is_del   = bool(s.get("deleted_by_user"))
        badge    = {"running":"badge-info","completed":"badge-low","failed":"badge-high",
                    "stopped":"badge-medium","pending":"badge-blue"}.get(status,"badge-blue")
        fcount   = db.one("SELECT COUNT(*) as c FROM osint_findings WHERE scan_id=?",(s["id"],))
        fc       = fcount["c"] if fcount else 0
        row_class = "scan-row-deleted" if is_del else ""
        row_style = "display:none;opacity:0.55;background:rgba(255,80,80,0.06)" if is_del else ""
        # Owner label for admin viewing other users' scans
        owner_note = ""
        if _is_admin() and s.get("user_id") != uid:
            owner_user = db.one("SELECT username FROM users WHERE id=?", (s["user_id"],))
            owner_note = f'<div class="text-sm" style="color:var(--warning);font-size:10px">👤 {owner_user["username"] if owner_user else s["user_id"]}</div>'
        deleted_badge = '<span class="badge badge-high" style="font-size:10px;margin-left:4px">DELETED</span>' if is_del else ""
        if is_del:
            # Deleted scan: show restore button
            _sid = s['id']
            _purge_scan = (
                '<button onclick="hardDeleteScan(\'' + _sid + '\',this.closest(\'tr\'))" class="btn btn-danger btn-sm" title="Permanently delete">🗑 Purge</button>'
                if _is_admin() else ''
            )
            action_btns = f"""
              <a href="/scan/{s['id']}" class="btn btn-ghost btn-sm">👁 View</a>
              <button onclick="restoreScan('{s['id']}',this.closest('tr'))" class="btn btn-ghost btn-sm" title="Restore scan" style="color:var(--success)">♻ Restore</button>
              {_purge_scan}"""
        else:
            action_btns = f"""
              <a href="/scan/{s['id']}" class="btn btn-ghost btn-sm">👁 View</a>
              <a href="/scan/{s['id']}/rescan" class="btn btn-ghost btn-sm" title="Run again">🔁</a>
              <button onclick="deleteScan('{s['id']}',this.closest('tr'))" class="btn btn-danger btn-sm" title="Delete">🗑</button>"""
        scans_html += f"""<tr class="{row_class}" style="{row_style}">
          <td>
            <a href="/scan/{s['id']}" style="color:var(--primary);font-weight:500">{s['target']}</a>{deleted_badge}
            <div class="text-sm text-muted">{s.get('scan_name','')}</div>
            {owner_note}
          </td>
          <td><span class="badge {badge}">{status.upper()}</span></td>
          <td>
            <div class="progress-bar" style="width:80px;display:inline-block">
              <div class="progress-fill" style="width:{prog}%"></div>
            </div>
            <span class="text-sm text-muted" style="margin-left:6px">{prog}%</span>
          </td>
          <td class="text-sm text-muted mono">{fc} findings</td>
          <td class="text-sm text-muted">{str(s.get('created_at',''))[:16]}</td>
          <td>
            <div class="flex gap-2">
              {action_btns}
            </div>
          </td>
        </tr>"""
    if not scans_html:
        scans_html = f'<tr><td colspan=6 style="text-align:center;padding:30px;color:var(--muted)">No scans yet · <a href="/investigation/{inv_id}/scan/new">Start your first scan →</a></td></tr>'

    # Notes
    notes_html = ""
    for n in notes:
        notes_html += f"""
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px;margin-bottom:10px">
          <div class="flex justify-between items-center mb-2">
            <span style="font-size:12px;font-weight:600;color:var(--text)">{n['author']}</span>
            <span class="text-sm text-muted mono">{str(n['created_at'])[:16]}</span>
          </div>
          <div style="font-size:13px;color:var(--text2);white-space:pre-wrap">{n['content']}</div>
        </div>"""

    # Timeline/Replay
    timeline_html = ""
    for step in replay[-15:]:
        timeline_html += f"""
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div class="timeline-content">
            <div class="timeline-time mono">{str(step['created_at'])[:16]} · {step.get('analyst','')}</div>
            <div class="timeline-title">{step.get('description','')}</div>
            <div class="timeline-desc text-muted">{step.get('action_type','')}</div>
          </div>
        </div>"""

    # Entity nodes for D3 graph
    if inv.get("inv_type") == "phishing":
        # Build graph from phishing campaign data: campaigns → targets → domains
        _p_nodes = {}  # id → node dict
        _p_links = []
        _p_camps = db.rows(
            "SELECT * FROM phishing_campaigns WHERE investigation_id=? ORDER BY created_at", (inv_id,)
        )
        for _pc in _p_camps:
            _cid  = _pc["id"]
            _cname = (_pc.get("name") or "Campaign")[:28]
            _p_nodes[_cid] = {"id": _cid, "label": _cname, "type": "campaign", "confidence": 100}
            _p_results = db.rows(
                "SELECT * FROM phishing_results WHERE campaign_id=?", (_cid,)
            )
            for _pr in _p_results:
                _email  = _pr.get("target_email", "")
                if not _email:
                    continue
                _eid    = "e:" + _email
                _status = _pr.get("status", "pending")
                _fname  = (_pr.get("target_first", "") or "").strip()
                _lname  = (_pr.get("target_last",  "") or "").strip()
                _label  = (_fname + " " + _lname).strip() or _email.split("@")[0]
                if _eid not in _p_nodes:
                    _p_nodes[_eid] = {
                        "id": _eid, "label": _label[:28],
                        "type": "email", "confidence": 90, "status": _status
                    }
                else:
                    # Escalate to highest status seen
                    _order = {"pending":0,"sent":1,"opened":2,"clicked":3,"submitted":4}
                    if _order.get(_status,0) > _order.get(_p_nodes[_eid].get("status","pending"),0):
                        _p_nodes[_eid]["status"] = _status
                _p_links.append({
                    "source": _cid, "target": _eid,
                    "type": _status, "confidence": 85
                })
                if "@" in _email:
                    _domain = _email.split("@")[1]
                    _did    = "d:" + _domain
                    if _did not in _p_nodes:
                        _p_nodes[_did] = {
                            "id": _did, "label": _domain,
                            "type": "domain", "confidence": 80
                        }
                    _p_links.append({
                        "source": _eid, "target": _did,
                        "type": "belongs_to", "confidence": 70
                    })
        entity_nodes = json.dumps(list(_p_nodes.values()))
        entity_links = json.dumps(_p_links)
    else:
        entity_nodes = json.dumps([{
            "id": e["id"], "label": e["value"][:30], "type": e["entity_type"],
            "confidence": e["confidence"],
            "contradictions": e.get("contradiction_count",0)
        } for e in entities])
        entity_links = json.dumps([{
            "source": r["source_id"], "target": r["target_id"],
            "type": r["relationship_type"],
            "confidence": r.get("confidence",50)
        } for r in rels])

    # Has any OSINT scans? Used to auto-trigger entity graph rebuild in JS
    _has_scans_js = "true" if scans else "false"

    # Scan list for per-scan graph filter dropdown (active scans only)
    _scan_list_js = json.dumps([
        {"id": s["id"], "target": s["target"][:40], "status": s.get("status", "")}
        for s in active_scans
    ])

    # Pre-compute tab strings outside f-string (backslash in {} illegal Python < 3.12)
    _itype = inv.get('inv_type', 'osint')
    _first_tab = (
        '<div class="tab active" onclick="showTab(\'scans\')">🔍 Scans</div>'
        if _itype == 'osint' else
        '<div class="tab active" onclick="showTab(\'phishing\')">🎣 Campaigns</div>'
    )
    _type_pill = (
        '<span style="background:#ff6b35;color:#fff;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:600">🎣 PHISHING</span>'
        if _itype == 'phishing' else
        '<span style="background:var(--primary);color:#000;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:600">🔍 OSINT</span>'
    )
    _new_scan_btn = (
        f'<a href="/investigation/{inv_id}/scan/new" class="btn btn-primary">+ New Scan</a>'
        if _itype == 'osint' and _analyst_can('scans') else ''
    )
    _new_camp_btn = (
        f'<a href="/investigation/{inv_id}/campaign/new" class="btn btn-primary" style="background:#ff6b35;border-color:#ff6b35">+ New Campaign</a>'
        if _itype == 'phishing' and _analyst_can('scans') else ''
    )

    html = f"""
<div class="flex justify-between items-center mb-3">
  <div>
    <h2 style="font-size:20px;font-weight:700;color:var(--text)">{inv['title']}</h2>
    <div style="font-size:12px;color:var(--muted);margin-top:2px">{inv.get('description','')}</div>
  </div>
  <div class="flex gap-2" style="align-items:center">
    {_type_pill}
    {_new_scan_btn}
    {_new_camp_btn}
    <a href="/report/investigation/{inv_id}" class="btn btn-ghost">📄 Report</a>
  </div>
</div>

<div class="tabs" id="inv-tabs">
  {_first_tab}
  <div class="tab" onclick="showTab('graph')">🕸️ Entity Graph</div>
  <div class="tab" onclick="showTab('images')">🖼️ Found Images</div>
  <div class="tab" onclick="showTab('notes')">📝 Analyst Notes</div>
  <div class="tab" onclick="showTab('timeline')">⏱️ Timeline</div>
</div>

{'<div id="tab-scans" class="tab-pane">' if inv.get("inv_type","osint")=="phishing" else '<div id="tab-scans" class="tab-pane active">'}
  <div class="card">
    <div class="card-header">
      <span class="card-title">OSINT Scans ({len(active_scans)} active · {total_findings} findings)</span>
      <div class="flex gap-2" style="align-items:center">
        {f'<label style="font-size:12px;color:var(--muted);cursor:pointer;display:flex;align-items:center;gap:5px"><input type="checkbox" id="showDeletedCb" onchange="toggleDeletedRows(this.checked)"> Show deleted ({deleted_count})</label>' if deleted_count > 0 or _is_admin() else ''}
        {'<a href="/investigation/'+inv_id+'/scan/new" class="btn btn-primary btn-sm">+ New Scan</a>' if inv.get("inv_type","osint")=="osint" and _analyst_can("scans") else ''}
      </div>
    </div>
    <table>
      <thead><tr><th>Target</th><th>Status</th><th>Progress</th><th>Findings</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody id="scans-tbody">{scans_html}</tbody>
    </table>
  </div>
</div>
<script>
function toggleDeletedRows(show) {{
  document.querySelectorAll('#scans-tbody tr.scan-row-deleted').forEach(function(row) {{
    row.style.display = show ? '' : 'none';
  }});
}}
function deleteScan(sid, row) {{
  if (!confirm('Delete this scan? You can restore it later.')) return;
  fetch('/api/scan/' + sid + '/delete', {{method:'POST'}})
    .then(r => r.json()).then(function(d) {{
      if (!d.ok) return;
      if (d.soft) {{
        // Soft delete: mark row as deleted, hide it unless "show deleted" checked
        row.classList.add('scan-row-deleted');
        row.style.opacity = '0.55';
        row.style.background = 'rgba(255,80,80,0.06)';
        var showCb = document.getElementById('showDeletedCb');
        if (!showCb || !showCb.checked) row.style.display = 'none';
        // Swap delete button for restore button
        var btns = row.querySelector('.flex.gap-2');
        if (btns) {{
          var delBtn = btns.querySelector('.btn-danger');
          if (delBtn) {{
            delBtn.textContent = '♻ Restore';
            delBtn.className = 'btn btn-ghost btn-sm';
            delBtn.style.color = 'var(--success)';
            delBtn.setAttribute('onclick', 'restoreScan("'+sid+'",this.closest("tr"))');
          }}
        }}
        // Update counter
        var title = document.querySelector('#tab-scans .card-title');
        if (title) title.textContent = title.textContent.replace(/\\d+ active/, function(m) {{ return (parseInt(m)-1)+' active'; }});
      }} else {{
        // Hard delete (admin): remove row entirely
        if (row) row.remove();
      }}
    }});
}}
function restoreScan(sid, row) {{
  fetch('/api/scan/' + sid + '/restore', {{method:'POST'}})
    .then(r => r.json()).then(function(d) {{
      if (!d.ok) return;
      row.classList.remove('scan-row-deleted');
      row.style.display = '';
      row.style.opacity = '';
      row.style.background = '';
      // Swap restore button back to delete
      var btns = row.querySelector('.flex.gap-2');
      if (btns) {{
        var restBtn = Array.from(btns.querySelectorAll('button')).find(b => b.textContent.includes('Restore'));
        if (restBtn) {{
          restBtn.textContent = '🗑';
          restBtn.className = 'btn btn-danger btn-sm';
          restBtn.style.color = '';
          restBtn.setAttribute('onclick', 'deleteScan("'+sid+'",this.closest("tr"))');
        }}
      }}
      var title = document.querySelector('#tab-scans .card-title');
      if (title) title.textContent = title.textContent.replace(/\\d+ active/, function(m) {{ return (parseInt(m)+1)+' active'; }});
    }});
}}
function hardDeleteScan(sid, row) {{
  if (!confirm('Permanently delete this scan and ALL its findings? This cannot be undone.')) return;
  fetch('/api/scan/' + sid + '/delete', {{method:'POST'}})
    .then(r => r.json()).then(function(d) {{ if (d.ok && row) row.remove(); }});
}}
</script>

{_phishing_campaigns_tab(inv_id, uid) if inv.get("inv_type")=="phishing" else ''}

<div id="tab-graph" class="tab-pane">
  <div class="card">
    <div class="card-header" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span class="card-title">🕸️ Entity Relationship Graph</span>
      <select id="graph-scan-filter"
        onchange="graphChangeScan('{inv_id}',this.value)"
        style="font-size:12px;padding:3px 8px;border-radius:6px;border:1px solid var(--border);
               background:var(--bg3);color:var(--text);cursor:pointer;max-width:240px">
        <option value="">🔍 All Scans</option>
      </select>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-left:auto;align-items:center">
        <div id="graph-filters" style="display:flex;gap:4px;flex-wrap:wrap">
          <button class="gf-pill active" data-type="all"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid var(--border);
                   background:var(--primary);color:#000;cursor:pointer"
            onclick="graphFilter('all',this)">All</button>
          <button class="gf-pill" data-type="domain"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #00d4ff44;
                   background:transparent;color:#00d4ff;cursor:pointer"
            onclick="graphFilter('domain',this)">🌐 Domain</button>
          <button class="gf-pill" data-type="ip"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #ff386044;
                   background:transparent;color:#ff3860;cursor:pointer"
            onclick="graphFilter('ip',this)">🔴 IP</button>
          <button class="gf-pill" data-type="email"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #00ff9d44;
                   background:transparent;color:#00ff9d;cursor:pointer"
            onclick="graphFilter('email',this)">📧 Email</button>
          <button class="gf-pill" data-type="username"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #ffad0044;
                   background:transparent;color:#ffad00;cursor:pointer"
            onclick="graphFilter('username',this)">👤 Username</button>
          <button class="gf-pill" data-type="organization"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #c084fc44;
                   background:transparent;color:#c084fc;cursor:pointer"
            onclick="graphFilter('organization',this)">🏢 Org</button>
          <button class="gf-pill" data-type="person"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #7b8cde44;
                   background:transparent;color:#7b8cde;cursor:pointer"
            onclick="graphFilter('person',this)">🧑 Person</button>
          <button class="gf-pill" data-type="flickr_id"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #ff008444;
                   background:transparent;color:#ff0084;cursor:pointer"
            onclick="graphFilter('flickr_id',this)">📷 Flickr ID</button>
          <button class="gf-pill" data-type="location"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #34d39944;
                   background:transparent;color:#34d399;cursor:pointer"
            onclick="graphFilter('location',this)">📍 Location</button>
          <button class="gf-pill" data-type="image"
            style="font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid #a78bfa44;
                   background:transparent;color:#a78bfa;cursor:pointer"
            onclick="graphFilter('image',this)">🖼️ Image</button>
        </div>
        <button onclick="graphRebuild('{inv_id}')"
          id="graph-rebuild-btn"
          style="font-size:11px;padding:3px 10px;border-radius:6px;cursor:pointer;
                 border:1px solid var(--border);background:var(--bg3);color:var(--muted)">
          🔄 Rebuild
        </button>
        <button onclick="graphReset()"
          style="font-size:11px;padding:3px 10px;border-radius:6px;cursor:pointer;
                 border:1px solid var(--border);background:var(--bg3);color:var(--muted)">
          ↺ Reset View
        </button>
        <span id="graph-count" style="font-size:11px;color:var(--muted)"></span>
      </div>
    </div>
    <div style="padding:8px 14px;border-bottom:1px solid var(--border);
                display:flex;align-items:center;gap:8px">
      <span style="font-size:12px;color:var(--muted)">🔍</span>
      <input id="graph-search" type="text" placeholder="Search nodes…"
        oninput="graphSearch(this.value)"
        style="flex:1;max-width:280px;padding:4px 10px;border-radius:6px;
               border:1px solid var(--border);background:var(--bg3);
               color:var(--text);font-size:12px;outline:none">
      <span id="graph-search-count" style="font-size:11px;color:var(--muted)"></span>
      <button onclick="document.getElementById('graph-search').value='';graphSearch('')"
        style="font-size:11px;padding:2px 8px;border-radius:6px;cursor:pointer;
               border:1px solid var(--border);background:var(--bg3);color:var(--muted)">
        ✕ Clear
      </button>
    </div>
    <div class="card-body" style="padding:0;display:flex;gap:0">
      <!-- Graph canvas -->
      <div style="flex:1;min-width:0;position:relative">
        <div id="entity-graph" style="width:100%;height:560px;background:var(--bg);
             border-right:1px solid var(--border);overflow:hidden;cursor:grab"></div>
        <!-- Zoom controls -->
        <div style="position:absolute;bottom:12px;left:12px;display:flex;flex-direction:column;gap:4px">
          <button onclick="graphZoom(1.3)"
            style="width:28px;height:28px;border-radius:6px;border:1px solid var(--border);
                   background:var(--bg2);color:var(--text);cursor:pointer;font-size:16px">+</button>
          <button onclick="graphZoom(0.77)"
            style="width:28px;height:28px;border-radius:6px;border:1px solid var(--border);
                   background:var(--bg2);color:var(--text);cursor:pointer;font-size:14px">−</button>
        </div>
        <!-- Empty state -->
        <div id="graph-empty"
          style="display:none;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                 text-align:center;color:var(--muted)">
          <div style="font-size:40px;margin-bottom:12px">🕸️</div>
          <div style="font-size:14px;font-weight:600;margin-bottom:6px">No entities yet</div>
          <div style="font-size:12px;margin-bottom:12px">Run a scan, then click Rebuild to populate the graph</div>
          <button onclick="graphRebuild('{inv_id}')"
            style="font-size:12px;padding:6px 16px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--primary);background:rgba(0,212,255,.1);color:var(--primary)">
            🔄 Build Graph Now
          </button>
        </div>
      </div>
      <!-- Detail sidebar -->
      <div id="graph-sidebar"
        style="width:240px;flex-shrink:0;padding:14px;background:var(--bg2);
               display:none;overflow-y:auto;max-height:560px;font-size:12px">
        <div style="font-size:11px;color:var(--muted);text-transform:uppercase;
                    letter-spacing:.8px;margin-bottom:10px">Entity Detail</div>
        <div id="sidebar-icon" style="font-size:28px;text-align:center;margin-bottom:6px"></div>
        <div id="sidebar-value"
          style="font-weight:700;font-size:13px;color:var(--text);word-break:break-all;
                 text-align:center;margin-bottom:6px"></div>
        <div id="sidebar-type"
          style="text-align:center;margin-bottom:10px;font-size:11px"></div>
        <div id="sidebar-meta"
          style="color:var(--text2);line-height:1.6;margin-bottom:10px"></div>
        <div id="sidebar-rels"
          style="border-top:1px solid var(--border);padding-top:8px;color:var(--muted)"></div>
      </div>
    </div>
    <!-- Legend -->
    <div style="padding:10px 16px;border-top:1px solid var(--border);
                display:flex;gap:14px;flex-wrap:wrap;align-items:center">
      <span style="font-size:10px;color:var(--muted);text-transform:uppercase;
                   letter-spacing:.6px">Legend:</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#00d4ff;display:inline-block"></span>Domain</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#00ff9d;display:inline-block"></span>Email</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#ffad00;display:inline-block"></span>Username</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#ff3860;display:inline-block"></span>IP</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#c084fc;display:inline-block"></span>Org</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#7b8cde;display:inline-block"></span>Person</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#ff9d00;display:inline-block"></span>Phone</span>
      <span style="font-size:11px;display:flex;align-items:center;gap:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:#ff6b35;display:inline-block"></span>Campaign</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">
        Drag nodes · Scroll to zoom · Click for detail</span>
    </div>
  </div>
</div>

<div id="tab-images" class="tab-pane">
  <div class="card">
    <div class="card-header">
      <span class="card-title">🖼️ Found Images</span>
      <span style="font-size:11px;color:var(--muted)">Matched images from reverse image search across all scans</span>
    </div>
    <div class="card-body">
      {_images_tab_html}
    </div>
  </div>
</div>

<div id="tab-notes" class="tab-pane">
  <div class="card">
    <div class="card-header"><span class="card-title">📝 Analyst Notes</span></div>
    <div class="card-body">
      <form method="POST" action="/investigation/{inv_id}/note">
        <div class="form-group">
          <textarea name="content" placeholder="Add investigation note, hypothesis, or observation..." rows="3"></textarea>
        </div>
        <button class="btn btn-primary btn-sm">Add Note</button>
      </form>
      <div class="mt-3">{notes_html or '<div class="text-muted text-sm">No notes yet</div>'}</div>
    </div>
  </div>
</div>

<div id="tab-timeline" class="tab-pane">
  <div class="card">
    <div class="card-header">
      <span class="card-title">⏱️ Investigation Replay</span>
      <div style="font-size:11px;color:var(--muted)">Reproducible investigation trail</div>
    </div>
    <div class="card-body">
      <div class="timeline">
        {timeline_html or '<div class="text-muted text-sm">No actions recorded yet</div>'}
      </div>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
/* ── Tab switcher ─────────────────────────────────────────── */
function showTab(name) {{
  /* Match tab buttons by their onclick text - avoids index mismatch between
     OSINT (first tab = scans) and phishing (first tab = phishing) investigations. */
  document.querySelectorAll('#inv-tabs .tab').forEach(function(t) {{
    var oc = t.getAttribute('onclick') || '';
    t.classList.toggle('active',
      oc.indexOf("'" + name + "'") > -1 || oc.indexOf('"' + name + '"') > -1);
  }});
  /* Show/hide every known pane by ID - only touches investigation panes. */
  ['scans','phishing','graph','images','notes','timeline'].forEach(function(n) {{
    var el = document.getElementById('tab-' + n);
    if (el) el.classList.toggle('active', n === name);
  }});
  if (name === 'graph') initGraph();
}}

/* ── Entity Graph ─────────────────────────────────────────── */
var graphInited = false;
var _gSim, _gSvg, _gZoom, _gAllNodes, _gAllLinks, _gFilter = 'all';
const SCAN_LIST = {_scan_list_js};

const _TYPE_COLOR = {{
  domain:'#00d4ff', email:'#00ff9d', username:'#ffad00',
  ip:'#ff3860', organization:'#c084fc', person:'#7b8cde',
  phone:'#ff9d00', string:'#aabbcc', campaign:'#ff6b35',
  flickr_id:'#ff0084', location:'#34d399', image:'#a78bfa'
}};
const _TYPE_ICON = {{
  domain:'🌐', email:'📧', username:'👤', ip:'🔴',
  organization:'🏢', person:'🧑', phone:'📞', string:'🔤', campaign:'🎣',
  flickr_id:'📷', location:'📍', image:'🖼️'
}};
const _REL_LABEL = {{
  subdomain_of:'subdomain', resolves_to:'→IP', associated_with:'linked',
  belongs_to:'@domain', hosts:'hosts', operates:'operates',
  found_on:'found on', leaked_from:'leaked', typosquat_of:'spoof',
  cloud_asset_of:'cloud', mentions:'mentions', gps_from:'GPS',
  found_in_image:'in image', depicted_in:'depicted', identity_linked_to:'identity',
  flickr_id_of:'Flickr ID',
  pending:'pending', sent:'sent', opened:'opened', clicked:'clicked', submitted:'submitted'
}};

function _populateScanFilter() {{
  var sel = document.getElementById('graph-scan-filter');
  if (!sel || sel.childElementCount > 1) return;
  SCAN_LIST.forEach(function(s) {{
    var opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.target + ' [' + s.status + ']';
    sel.appendChild(opt);
  }});
}}

function initGraph() {{
  if (graphInited) return; graphInited = true;
  _populateScanFilter();
  var nodes = {entity_nodes};
  var links = {entity_links};
  if (!nodes.length && {_has_scans_js}) {{
    graphRebuild('{inv_id}');
    return;
  }}
  _gAllNodes = nodes; _gAllLinks = links;
  _renderGraph(nodes, links);
}}

function _renderGraph(nodes, links) {{
  const el = document.getElementById('entity-graph');
  if (!el) return;
  /* clear previous */
  d3.select(el).selectAll('*').remove();
  document.getElementById('graph-sidebar').style.display = 'none';

  const cnt = document.getElementById('graph-count');
  if (cnt) cnt.textContent = nodes.length + ' nodes · ' + links.length + ' edges';

  if (!nodes.length) {{
    document.getElementById('graph-empty').style.display = 'block';
    return;
  }}
  document.getElementById('graph-empty').style.display = 'none';

  const W = el.clientWidth || 800, H = 560;
  const svg = d3.select(el).append('svg')
    .attr('width', W).attr('height', H)
    .style('display','block');

  /* zoom/pan */
  const g = svg.append('g');
  _gZoom = d3.zoom().scaleExtent([0.1, 4]).on('zoom', e => g.attr('transform', e.transform));
  svg.call(_gZoom);
  _gSvg = svg;

  /* arrow marker */
  svg.append('defs').append('marker')
    .attr('id','arrow').attr('viewBox','0 -5 10 10')
    .attr('refX',22).attr('refY',0)
    .attr('markerWidth',6).attr('markerHeight',6)
    .attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#2a4060');

  /* edge labels group */
  const edgeLabelG = g.append('g').attr('class','edge-labels');
  /* link group */
  const linkG = g.append('g');
  /* node group */
  const nodeG = g.append('g');

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d=>d.id).distance(d=>120 + (1 - (d.confidence||60)/100)*80))
    .force('charge', d3.forceManyBody().strength(-350))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(32));
  _gSim = sim;

  const link = linkG.selectAll('line').data(links).join('line')
    .attr('class','graph-link')
    .attr('data-source', d => d.source.id||d.source)
    .attr('data-target', d => d.target.id||d.target)
    .attr('stroke','#1e3050')
    .attr('stroke-width', d => Math.max(1, (d.confidence||60)/35))
    .attr('stroke-opacity', 0.6)
    .attr('marker-end','url(#arrow)');

  const edgeLabel = edgeLabelG.selectAll('text').data(links).join('text')
    .text(d => _REL_LABEL[d.type] || d.type || '')
    .attr('font-size', 9).attr('fill','#4a6080')
    .attr('text-anchor','middle').attr('dy', -4);

  const node = nodeG.selectAll('g.node-g').data(nodes).join('g')
    .attr('class','node-g')
    .attr('data-id', d => d.id)
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start', (e,d) => {{ if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; }})
      .on('drag',  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
      .on('end',   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}))
    .on('click', (e,d) => {{ e.stopPropagation(); showNodeDetail(d, links); }});

  node.append('circle')
    .attr('r', d => d.label && d.label.length > 0 ? 14 : 10)
    .attr('fill', d => _TYPE_COLOR[d.type] || '#4a6080')
    .attr('stroke', d => d.contradictions > 0 ? '#ff3860' : '#0a1220')
    .attr('stroke-width', d => d.contradictions > 0 ? 2.5 : 1.5)
    .attr('fill-opacity', 0.9);

  node.append('text')
    .text(d => (_TYPE_ICON[d.type] || '●'))
    .attr('text-anchor','middle').attr('dy','0.35em')
    .attr('font-size', 11).attr('fill','#000a')
    .style('pointer-events','none');

  node.append('text')
    .text(d => d.label && d.label.length > 20 ? d.label.slice(0,18)+'…' : d.label)
    .attr('text-anchor','middle').attr('dy', 28)
    .attr('font-size', 9).attr('fill','#c8d6ef')
    .style('pointer-events','none');

  /* click on canvas → close sidebar */
  svg.on('click', () => {{ document.getElementById('graph-sidebar').style.display='none'; }});

  sim.on('tick', () => {{
    link
      .attr('x1', d=>d.source.x).attr('y1', d=>d.source.y)
      .attr('x2', d=>d.target.x).attr('y2', d=>d.target.y);
    edgeLabel
      .attr('x', d=>(d.source.x+d.target.x)/2)
      .attr('y', d=>(d.source.y+d.target.y)/2);
    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
  }});
  sim.on('end', () => {{ if (_gSearchTerm) graphSearch(_gSearchTerm); }});
}}

function showNodeDetail(d, links) {{
  const sb = document.getElementById('graph-sidebar');
  sb.style.display = 'block';
  document.getElementById('sidebar-icon').textContent = _TYPE_ICON[d.type] || '●';
  document.getElementById('sidebar-value').textContent = d.label || d.id;
  const typeEl = document.getElementById('sidebar-type');
  typeEl.innerHTML = `<span style="background:${{_TYPE_COLOR[d.type]||'#4a6080'}}22;
    color:${{_TYPE_COLOR[d.type]||'#888'}};padding:2px 8px;border-radius:10px;
    border:1px solid ${{_TYPE_COLOR[d.type]||'#888'}}44;font-size:11px">${{d.type||''}}</span>`;
  document.getElementById('sidebar-meta').innerHTML =
    `<div><b>Confidence:</b> ${{d.confidence||'?'}}%</div>` +
    (d.contradictions ? `<div style="color:#ff3860"><b>⚠ Contradictions:</b> ${{d.contradictions}}</div>` : '');

  /* connected relationships */
  const nodeLinks = (links||[]).filter(l =>
    (l.source.id||l.source) === d.id || (l.target.id||l.target) === d.id);
  if (nodeLinks.length) {{
    let html = `<div style="font-size:10px;color:var(--muted);text-transform:uppercase;
      letter-spacing:.6px;margin-bottom:6px">${{nodeLinks.length}} connection(s)</div>`;
    nodeLinks.slice(0,10).forEach(l => {{
      const other = (l.source.id||l.source)===d.id
        ? (l.target.label||l.target.id||l.target)
        : (l.source.label||l.source.id||l.source);
      const arrow = (l.source.id||l.source)===d.id ? '→' : '←';
      html += `<div style="padding:3px 0;border-bottom:1px solid var(--border)33;font-size:11px">
        ${{arrow}} <b>${{l.type||''}}</b> ${{String(other).slice(0,30)}}</div>`;
    }});
    document.getElementById('sidebar-rels').innerHTML = html;
  }} else {{
    document.getElementById('sidebar-rels').innerHTML = '<div style="color:var(--muted);font-size:11px">No connections</div>';
  }}
}}

function graphFilter(type, btn) {{
  _gFilter = type;
  document.querySelectorAll('.gf-pill').forEach(p => {{
    p.style.background = p.dataset.type === type ? 'var(--primary)' : 'transparent';
    p.style.color = p.dataset.type === type ? '#000' : (_TYPE_COLOR[p.dataset.type]||'var(--muted)');
  }});
  if (!_gAllNodes) return;
  if (type === 'all') {{
    var rawLinks = _gAllLinks.map(function(l) {{
      return {{source: l.source.id||l.source, target: l.target.id||l.target, label: l.label||'', count: l.count||1}};
    }});
    _renderGraph(_gAllNodes, rawLinks);
  }} else {{
    var primary = new Set(_gAllNodes.filter(function(n){{return n.type===type;}}).map(function(n){{return n.id;}}));
    var rawLinks = _gAllLinks.map(function(l) {{
      return {{source: l.source.id||l.source, target: l.target.id||l.target, label: l.label||'', count: l.count||1}};
    }});
    var fl = rawLinks.filter(function(l) {{
      return primary.has(l.source) || primary.has(l.target);
    }});
    var needed = new Set();
    fl.forEach(function(l) {{ needed.add(l.source); needed.add(l.target); }});
    var fn = _gAllNodes.filter(function(n){{return needed.has(n.id);}});
    _renderGraph(fn, fl);
  }}
  graphInited = true;
}}

var _gSearchTerm = '';
function graphSearch(q) {{
  _gSearchTerm = (q || '').toLowerCase().trim();
  var cnt = document.getElementById('graph-search-count');
  var el  = document.getElementById('entity-graph');
  if (!el) return;

  if (!_gSearchTerm) {{
    el.querySelectorAll('circle,text').forEach(function(n) {{
      n.style.opacity = '';
    }});
    el.querySelectorAll('line').forEach(function(l) {{
      l.style.opacity = '';
    }});
    if (cnt) cnt.textContent = '';
    return;
  }}

  var matchIds = new Set();
  if (_gAllNodes) {{
    _gAllNodes.forEach(function(n) {{
      if ((n.id||'').toLowerCase().indexOf(_gSearchTerm) > -1 ||
          (n.type||'').toLowerCase().indexOf(_gSearchTerm) > -1) {{
        matchIds.add(n.id);
      }}
    }});
  }}

  el.querySelectorAll('g.node-g').forEach(function(g) {{
    var nid = g.getAttribute('data-id') || '';
    var hit = matchIds.has(nid);
    g.querySelectorAll('circle,text').forEach(function(ch) {{
      ch.style.opacity = hit ? '1' : '0.08';
    }});
  }});

  el.querySelectorAll('line.graph-link').forEach(function(l) {{
    var src = l.getAttribute('data-source') || '';
    var tgt = l.getAttribute('data-target') || '';
    l.style.opacity = (matchIds.has(src) || matchIds.has(tgt)) ? '0.7' : '0.04';
  }});

  if (cnt) cnt.textContent = matchIds.size + ' match' + (matchIds.size === 1 ? '' : 'es');
}}

function graphZoom(factor) {{
  if (_gSvg && _gZoom) _gSvg.transition().duration(300).call(_gZoom.scaleBy, factor);
}}

function graphReset() {{
  if (_gSvg && _gZoom) _gSvg.transition().duration(400).call(_gZoom.transform, d3.zoomIdentity);
  if (_gSim) _gSim.alpha(0.3).restart();
}}

function graphLoadFromAPI(invId, scanId) {{
  var url = '/api/investigation/' + invId + '/graph';
  if (scanId) url += '?scan_id=' + encodeURIComponent(scanId);
  var cnt = document.getElementById('graph-count');
  if (cnt) cnt.textContent = '⏳ Loading…';
  fetch(url).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (!d.ok) return;
    _gAllNodes = d.nodes; _gAllLinks = d.links;
    graphInited = true;
    _gFilter = 'all';
    document.querySelectorAll('.gf-pill').forEach(function(p) {{
      p.style.background = p.dataset.type === 'all' ? 'var(--primary)' : 'transparent';
      p.style.color = p.dataset.type === 'all' ? '#000' : (_TYPE_COLOR[p.dataset.type] || 'var(--muted)');
    }});
    _renderGraph(d.nodes, d.links);
  }}).catch(function() {{ if (cnt) cnt.textContent = ''; }});
}}

function graphChangeScan(invId, scanId) {{
  _populateScanFilter();
  graphLoadFromAPI(invId, scanId);
}}

function graphRebuild(invId) {{
  const btn = document.getElementById('graph-rebuild-btn');
  if (btn) {{ btn.textContent = '⏳ Building…'; btn.disabled = true; }}
  fetch('/api/investigation/' + invId + '/rebuild-graph', {{method:'POST'}})
    .then(r=>r.json()).then(function(d) {{
      if (btn) {{ btn.textContent = '🔄 Rebuild'; btn.disabled = false; }}
      if (d.ok) {{
        var sel = document.getElementById('graph-scan-filter');
        if (sel) sel.value = '';
        graphLoadFromAPI(invId, '');
      }} else {{
        alert('Rebuild failed: ' + (d.error||'unknown'));
      }}
    }}).catch(function() {{ if(btn) {{ btn.textContent='🔄 Rebuild'; btn.disabled=false; }} }});
}}
</script>"""
    return _base(inv["title"], html, "investigations")

@app.route("/investigation/<inv_id>/note", methods=["POST"])
@require_login
def add_note(inv_id):
    content = request.form.get("content","").strip()
    if content:
        db.ins("analyst_notes", {
            "id":str(uuid.uuid4()), "investigation_id":inv_id,
            "content":content, "author":flask_session.get("username",""),
            "linked_entities":"[]", "created_at":_now(), "updated_at":_now()
        })
        _replay_step(inv_id,"note",f"Analyst note added: {content[:60]}...",
                     analyst=flask_session.get("username",""))
    return redirect(f"/investigation/{inv_id}#notes")

# ═════════════════════════════════════════════════════════════════════════════
# NEW SCAN
# ═════════════════════════════════════════════════════════════════════════════
_MODULES_META = [
    ("wayback",          "🕰️",  "Wayback Machine",        "Historical URLs, deleted pages, sensitive file detection via Internet Archive CDX API"),
    ("certTransparency", "📜",  "Cert Transparency",      "Subdomain discovery via crt.sh + Certspotter CT logs"),
    ("dns",              "🌐",  "DNS Recon",               "Full DNS enumeration, zone transfer, subdomain brute-force (150+ words)"),
    ("securityHeaders",  "🛡️", "Security Headers",       "OWASP-aligned HTTP header audit: HSTS, CSP, CORS, cookies, server leakage"),
    ("faviconHash",      "🔮",  "Favicon Hash Intel",     "MurmurHash3 favicon pivot to find hidden infra via Shodan/FOFA/urlscan"),
    ("webCrawl",         "🕷️", "Web Crawler",             "Playwright depth crawl, form discovery, pattern scanning, screenshots"),
    ("gitLeaks",         "🔓",  "Git Leaks",               "Exposed .git directories, GitHub/GitLab code search for secrets"),
    ("emailHarvest",     "📧",  "Email Harvester",         "Hunter.io, PhoneBook.cz, DuckDuckGo dork, GitHub commit email extraction"),
    ("metaHarvest",      "📑",  "Metadata Harvester",     "Metagoofil-style doc discovery + PDF/DOCX/XLSX metadata extraction"),
    ("jsRecon",          "🔬",  "JS Intelligence",         "JavaScript file mining for endpoints, secrets, API keys, and hidden paths"),
    ("googleDork",       "🔍",  "Google Dorking",          "15+ auto-built dorks via DuckDuckGo/Bing: admin panels, exposed files, email leaks"),
    ("username",         "👤",  "Username Hunt",           "137+ platform username enumeration - DB-driven, fully configurable. Manage sites in Settings."),
    ("identity",         "🧬",  "Identity Intel",          "WHOIS, email format discovery, MX provider fingerprinting, breach checks"),
    ("phoneOsint",       "📞",  "Phone OSINT",             "Carrier lookup, spam/scam check, reverse lookup, social presence (WhatsApp/Telegram)"),
    ("infrastructure",   "🗺️", "Infrastructure Map",      "Shodan, ASN/BGP lookup, CDN detection, cloud provider identification"),
    ("cloudExposure",    "☁️",  "Cloud Bucket Scanner",   "S3, GCS, Azure Blob - public bucket enumeration and content exposure"),
    ("subTakeover",      "🎯",  "Subdomain Takeover",     "Dangling CNAME detector for 40+ providers: GitHub Pages, Heroku, Netlify, Vercel…"),
    ("threatIntel",      "⚡",  "Threat Intel",            "VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX, ThreatFox correlation"),
    ("typosquat",        "🔍",  "Typosquatting Detector", "Generate 1000s of domain permutations and detect registered phishing variants"),
    ("socialMedia",      "📱",  "Social Media OSINT",     "GitHub org intelligence, LinkedIn presence, Twitter/X recon"),
    ("darkWeb",          "🕳️", "Dark Web Monitor",        "Ahmia.fi onion search (TOR required), pastebin leak detection, ransomware feeds"),
    ("aiOsint",          "🤖",  "AI Analysis",             "Claude/GPT-powered correlation, entity extraction, new pattern generation"),
    ("imageOsint",       "🖼️", "Image Search OSINT",      "Multi-layer image intelligence: EXIF+GPS, AI vision, OCR, reverse search (Yandex/TinEye/Bing), DDG correlation"),
]

# Which target types each module is relevant for.
# Mirrors the TARGET_TYPES class attribute on each module class.
# Used by the new-scan form JS to show/hide module cards per selected target type.
_MODULE_TARGET_TYPES = {
    "wayback":          ["domain"],
    "certTransparency": ["domain"],
    "dns":              ["domain"],
    "securityHeaders":  ["domain"],
    "faviconHash":      ["domain"],
    "webCrawl":         ["domain"],
    "jsRecon":          ["domain"],
    "metaHarvest":      ["domain"],
    "cloudExposure":    ["domain"],
    "subTakeover":      ["domain"],
    "typosquat":        ["domain"],
    "gitLeaks":         ["domain", "string"],
    "googleDork":       ["domain", "username", "email", "string"],
    "infrastructure":   ["domain", "ip"],
    "emailHarvest":     ["domain", "email"],
    "identity":         ["domain", "email", "username"],
    "threatIntel":      ["domain", "ip", "string"],
    "username":         ["username"],
    "socialMedia":      ["username", "domain", "string"],
    "darkWeb":          ["domain", "username", "email", "string", "phone", "ip"],
    "phoneOsint":       ["phone"],
    "aiOsint":          ["domain", "username", "email", "phone", "ip", "string"],
    "imageOsint":       ["image"],
}

# Sub-sources for each module - rendered as expandable checkboxes in Settings → Modules.
# Format: { module_id: [(config_key, label, default_enabled), ...] }
_MODULE_SUBSOURCES = {
    "wayback": [
        ("src_cdx",          "Internet Archive CDX API",    True),
        ("src_availability", "Wayback Availability API",    True),
    ],
    "certTransparency": [
        ("src_crtsh",        "crt.sh CT logs",              True),
        ("src_certspotter",  "Certspotter CT logs",         True),
    ],
    "dns": [
        ("src_dns_records",    "Standard records (A/MX/NS/TXT/SOA)", True),
        ("src_zone_transfer",  "Zone transfer attempt",              True),
        ("src_subdomain_brute","Subdomain brute-force wordlist",     True),
        ("src_dnssec",         "DNSSEC validation check",           True),
    ],
    "securityHeaders": [
        ("src_hsts",   "HSTS / HTTPS enforcement",     True),
        ("src_csp",    "Content-Security-Policy",       True),
        ("src_cors",   "CORS policy (wildcard/creds)",  True),
        ("src_cookies","Cookie security flags",          True),
        ("src_server", "Server version leakage",        True),
    ],
    "faviconHash": [
        ("src_shodan",   "Shodan pivot search",   True),
        ("src_urlscan",  "urlscan.io pivot",      True),
        ("src_fofa",     "FOFA pivot (key req.)", True),
        ("src_zoomeye",  "ZoomEye pivot links",   True),
    ],
    "webCrawl": [
        ("src_playwright",   "Playwright headless browser", True),
        ("src_forms",        "Form discovery",              True),
        ("src_screenshots",  "Screenshot capture",          True),
        ("src_patterns",     "Sensitive pattern scanning",  True),
    ],
    "gitLeaks": [
        ("src_git_dir",  "Exposed .git directory",   True),
        ("src_github",   "GitHub code search",       True),
        ("src_gitlab",   "GitLab code search",       True),
        ("src_commits",  "Commit history scan",      True),
    ],
    "emailHarvest": [
        ("src_hunter",    "Hunter.io API",             True),
        ("src_phonebook", "PhoneBook.cz",              True),
        ("src_ddg",       "DuckDuckGo email dork",    True),
        ("src_github",    "GitHub commit emails",      True),
    ],
    "metaHarvest": [
        ("src_pdf",   "PDF documents",       True),
        ("src_docx",  "Word documents",      True),
        ("src_xlsx",  "Excel spreadsheets",  True),
        ("src_pptx",  "PowerPoint files",    True),
        ("src_dork",  "Search engine dork",  True),
    ],
    "jsRecon": [
        ("src_endpoints",  "Hidden endpoint extraction",  True),
        ("src_secrets",    "Secret / API key patterns",   True),
        ("src_sourcemap",  "Source-map file detection",   True),
        ("src_frameworks", "Framework fingerprinting",    True),
    ],
    "googleDork": [
        ("src_duckduckgo", "DuckDuckGo dorking", True),
        ("src_bing",       "Bing dorking",        True),
    ],
    "username": [
        ("src_github",    "GitHub",     True),
        ("src_twitter",   "Twitter/X",  True),
        ("src_reddit",    "Reddit",     True),
        ("src_instagram", "Instagram",  True),
        ("src_facebook",  "Facebook",   True),
        ("src_linkedin",  "LinkedIn",   True),
        ("src_tiktok",    "TikTok",     True),
        ("src_telegram",  "Telegram",   True),
        ("src_youtube",   "YouTube",    True),
        ("src_steam",     "Steam",      True),
        ("src_discord",   "Discord",    True),
        ("src_twitch",    "Twitch",     True),
        ("src_mastodon",  "Mastodon",   True),
        ("src_keybase",   "Keybase",    True),
    ],
    "identity": [
        ("src_whois",    "WHOIS lookup",            True),
        ("src_email",    "Email format discovery",  True),
        ("src_mx",       "MX provider fingerprint", True),
        ("src_hibp",     "HaveIBeenPwned breaches", True),
        ("src_gravatar", "Gravatar lookup",          True),
    ],
    "infrastructure": [
        ("src_shodan", "Shodan host lookup",      True),
        ("src_asn",    "ASN / BGP lookup",        True),
        ("src_cdn",    "CDN detection",            True),
        ("src_cloud",  "Cloud provider ID",       True),
        ("src_ipinfo", "IPinfo geolocation",      True),
    ],
    "cloudExposure": [
        ("src_s3",    "AWS S3 buckets",       True),
        ("src_gcs",   "Google Cloud Storage", True),
        ("src_azure", "Azure Blob Storage",   True),
    ],
    "subTakeover": [
        ("src_crtsh",  "crt.sh subdomain enum",       True),
        ("src_brute",  "Brute-force wordlist",         True),
        ("src_body",   "Body fingerprint check",       True),
    ],
    "threatIntel": [
        ("src_virustotal",  "VirusTotal",       True),
        ("src_abuseipdb",   "AbuseIPDB",        True),
        ("src_urlhaus",     "URLhaus",           True),
        ("src_otx",         "AlienVault OTX",   True),
        ("src_threatfox",   "ThreatFox",        True),
    ],
    "typosquat": [
        ("src_dns",   "DNS A-record resolution",         True),
        ("src_mx",    "MX record check (email phishing)",True),
        ("src_body",  "Phishing body content check",     True),
    ],
    "socialMedia": [
        ("src_github",   "GitHub org recon",   True),
        ("src_linkedin", "LinkedIn presence",  True),
        ("src_twitter",  "Twitter/X search",   True),
        ("src_facebook", "Facebook page",      True),
    ],
    "darkWeb": [
        ("src_ahmia",       "Ahmia.fi onion search",    True),
        ("src_darksearch",  "DarkSearch.io",             True),
        ("src_ransomwatch", "RansomWatch leak monitor",  True),
        ("src_psbdmp",      "Pastebin / psbdmp",         True),
        ("src_hibp",        "HaveIBeenPwned",            True),
    ],
    "aiOsint": [
        ("src_claude",  "Anthropic Claude", True),
        ("src_openai",  "OpenAI GPT",       True),
    ],
}

@app.route("/investigation/<inv_id>/scan/new", methods=["GET","POST"])
@require_login
def new_scan(inv_id):
    if not _analyst_can("scans"):
        return redirect(url_for("view_investigation", inv_id=inv_id))
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    default_mods  = json.loads(_get_setting("default_modules","[]"))
    default_depth = _get_setting("default_crawl_depth","2")

    if request.method == "POST":
        scan_type = request.form.get("scan_type","osint")

        # ── Target types + per-type values ────────────────────────────────────
        # The form sends one hidden "target_types" field (comma-sep) and one
        # visible input per type (target_domain, target_username, etc.).
        # At least one type must be present (enforced by JS + server-side).
        raw_types = [t.strip() for t in
                     request.form.get("target_types","domain").split(",")
                     if t.strip()]
        if not raw_types:
            raw_types = ["domain"]

        # Advanced name-builder mode for username / email types
        adv_username = bool(request.form.get("adv_username"))
        adv_email    = bool(request.form.get("adv_email"))

        # Helper: extract first entry from name_users_json as a display target value
        def _adv_target(json_key, domain=""):
            raw = request.form.get(json_key, "").strip()
            try:
                users = json.loads(raw) if raw else []
                if users:
                    u = users[0]
                    name = f"{u.get('first','')} {u.get('last','')}".strip()
                    return f"{name}@{domain}" if domain else name
            except Exception:
                pass
            return domain or ""

        # Image upload - read filename for display (file saved later after api_cfg is built)
        _img_file_obj = request.files.get("target_image")
        _img_filename  = (_img_file_obj.filename or "").strip() if _img_file_obj else ""

        # Map type → form value (advanced modes read from name_users_json array)
        type_values = {
            "domain":   request.form.get("target_domain","").strip(),
            "username": (request.form.get("target_username","").strip() if not adv_username
                         else _adv_target("name_users_json")),
            "email":    (request.form.get("target_email","").strip() if not adv_email
                         else _adv_target("email_users_json",
                                          request.form.get("email_domain","").strip())),
            "phone":    request.form.get("target_phone","").strip(),
            "ip":       request.form.get("target_ip","").strip(),
            "string":   request.form.get("target_string","").strip(),
            "image":    _img_filename,
        }

        # Primary target = value of first selected type (or fallback to legacy field)
        target = ""
        for tt in raw_types:
            if type_values.get(tt):
                target = type_values[tt]
                break
        if not target:
            target = request.form.get("target","").strip() or (inv["target"] if inv else "")

        # Server-side guard: at least one type with a value required
        if not target:
            return _base("New Scan", "<div class='alert alert-danger'>At least one target value is required.</div>", "investigations")

        mods_sel = request.form.getlist("modules")
        mods_cfg = {m: (m in mods_sel) for m,_,_,_ in _MODULES_META}
        # API keys override from form
        api_cfg = {}
        for k in ["github_token","shodan_key","anthropic_key","openai_key",
                  "virustotal_key","hunter_key","hibp_key","otx_key","abuseipdb_key"]:
            v = request.form.get(k,"").strip()
            if not v:
                v = _get_setting(k,"")
            if v:
                api_cfg[k] = v

        # Store target types + per-type values in config for engine + modules
        api_cfg["target_types"]    = raw_types
        api_cfg["target_type"]     = raw_types[0]   # primary (convenience)
        for tt in raw_types:
            if type_values.get(tt):
                api_cfg[tt] = type_values[tt]

        # Advanced name-builder - store name parts so modules can expand patterns
        if adv_username:
            api_cfg["adv_username"] = True
            raw_un = request.form.get("name_users_json","").strip()
            try:
                name_users = json.loads(raw_un) if raw_un else []
            except Exception:
                name_users = []
            if not name_users:
                nf = request.form.get("name_first","").strip()
                nl = request.form.get("name_last","").strip()
                if nf or nl:
                    name_users = [{"first": nf, "middle": request.form.get("name_middle","").strip(), "last": nl}]
            api_cfg["name_users"]  = name_users
            if name_users:
                api_cfg["name_first"]  = name_users[0].get("first","")
                api_cfg["name_middle"] = name_users[0].get("middle","")
                api_cfg["name_last"]   = name_users[0].get("last","")
        if adv_email:
            api_cfg["adv_email"]    = True
            raw_em = request.form.get("email_users_json","").strip()
            try:
                email_users = json.loads(raw_em) if raw_em else []
            except Exception:
                email_users = []
            if not email_users:
                ef = request.form.get("email_first","").strip()
                el = request.form.get("email_last","").strip()
                if ef or el:
                    email_users = [{"first": ef, "middle": request.form.get("email_middle","").strip(), "last": el}]
            api_cfg["email_users"]  = email_users
            api_cfg["email_domain"] = request.form.get("email_domain","").strip()
            if email_users:
                api_cfg["email_first"]  = email_users[0].get("first","")
                api_cfg["email_middle"] = email_users[0].get("middle","")
                api_cfg["email_last"]   = email_users[0].get("last","")

        # Wayback config
        if request.form.get("wayback_limit"):
            api_cfg["wayback_limit"] = int(request.form.get("wayback_limit",500))
        if request.form.get("wayback_extensions"):
            api_cfg["wayback_extensions"] = request.form.get("wayback_extensions","").strip()
        # Merge default sub-source settings (from settings page) into scan config
        # Modules read config.get("src_github", True) etc. to decide which sources to use
        try:
            saved_subsrc = json.loads(_get_setting("module_subsources","{}") or "{}")
            for mid, src_map in saved_subsrc.items():
                for src_key, val in src_map.items():
                    # Only add if not already set (allow per-scan override later)
                    if src_key not in api_cfg:
                        api_cfg[src_key] = val == "1"
        except Exception:
            pass

        # Image upload - save file to disk and store path in api_cfg
        if "image" in raw_types and _img_file_obj and _img_filename:
            import os as _os
            _img_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "screenshots", "image_osint")
            _os.makedirs(_img_dir, exist_ok=True)
            _img_ext  = _os.path.splitext(_img_filename)[1].lower() or ".jpg"
            _img_save = _os.path.join(_img_dir, str(uuid.uuid4()) + _img_ext)
            _img_file_obj.save(_img_save)
            api_cfg["image_path"] = _img_save
            for _ctx_k in ["img_subject_name","img_username","img_email","img_phone","img_keyword"]:
                _v = request.form.get(_ctx_k,"").strip()
                if _v:
                    api_cfg[_ctx_k] = _v

        # Build per-person scan list for advanced builder (one scan per person)
        _scan_targets = []
        if adv_username and api_cfg.get("name_users"):
            for _u in api_cfg["name_users"]:
                _nm = f"{_u.get('first','')} {_u.get('last','')}".strip()
                if not _nm:
                    continue
                _c = dict(api_cfg)
                _c["name_users"]  = [_u]
                _c["name_first"]  = _u.get("first","")
                _c["name_middle"] = _u.get("middle","")
                _c["name_last"]   = _u.get("last","")
                _c["username"]    = _nm
                _scan_targets.append((_nm, _c))
        elif adv_email and api_cfg.get("email_users"):
            _edom = api_cfg.get("email_domain","")
            for _u in api_cfg["email_users"]:
                _nm = f"{_u.get('first','')} {_u.get('last','')}".strip()
                _et = f"{_nm}@{_edom}" if (_nm and _edom) else (_nm or _edom)
                if not _et:
                    continue
                _c = dict(api_cfg)
                _c["email_users"]  = [_u]
                _c["email_first"]  = _u.get("first","")
                _c["email_middle"] = _u.get("middle","")
                _c["email_last"]   = _u.get("last","")
                _c["email"]        = _et
                _scan_targets.append((_et, _c))
        if not _scan_targets:
            _scan_targets = [(target, api_cfg)]

        use_tor    = "1" if request.form.get("use_tor") else "0"
        _base_name = request.form.get("scan_name","").strip()
        _last_sid  = None
        for _tgt, _cfg in _scan_targets:
            sid    = str(uuid.uuid4())
            _sname = (_base_name if (len(_scan_targets) == 1 and _base_name)
                      else f"Scan of {_tgt}")
            db.ins("osint_scans", {
                "id": sid, "user_id": uid,
                "investigation_id": inv_id,
                "scan_name": _sname,
                "target": _tgt, "scan_type": scan_type,
                "modules": json.dumps(mods_cfg),
                "status": "pending", "progress": 0,
                "crawl_depth": int(request.form.get("crawl_depth", default_depth)),
                "file_types": request.form.get("file_types","*"),
                "use_tor": int(use_tor),
                "notes": json.dumps(_cfg),
                "source_path": request.form.get("source_path",""),
                "created_at": _now()
            })
            _audit("create_scan","scan",sid,_tgt)
            _replay_step(inv_id,"scan_created",f"Scan created for {_tgt}",
                         {"scan_id":sid,"modules":mods_sel},
                         flask_session["username"])
            if request.form.get("start_now"):
                engine.start_scan(sid)
                db.upd("osint_scans",{"status":"running","started_at":_now()},"id=?",(sid,))
                _replay_step(inv_id,"scan_started",f"Scan started for {_tgt}",
                             analyst=flask_session["username"])
            _last_sid = sid
        if len(_scan_targets) > 1:
            return redirect(f"/investigation/{inv_id}")
        return redirect(f"/scan/{_last_sid}")

    # Build module cards - if default_mods is set in settings, only show those modules
    mod_cards = ""
    for mid, icon, name, desc in _MODULES_META:
        # When default_mods is non-empty, skip modules not listed (they're disabled in settings)
        if default_mods and mid not in default_mods:
            continue
        # All shown modules are pre-checked (they're the settings-enabled set)
        tgt_list = " ".join(_MODULE_TARGET_TYPES.get(mid, ["domain"]))
        mod_cards += f"""
        <div class="module-card selected"
             data-targets="{tgt_list}" onclick="toggleMod(this)">
          <input type="checkbox" name="modules" value="{mid}" checked id="mod-{mid}">
          <div class="module-icon">{icon}</div>
          <div class="module-name">{name}</div>
          <div class="module-desc">{desc}</div>
        </div>"""

    import html as _html
    tor_checked = 'checked' if _get_setting('tor_enabled') == '1' else ''
    inv_title   = _html.escape(inv["title"]) if inv else ""
    inv_target  = _html.escape(inv["target"]) if inv else ""

    html = f"""
<style>
.tt-pill {{
  display:inline-flex;align-items:center;gap:6px;padding:7px 14px;
  border-radius:20px;border:2px solid var(--border);background:var(--bg2);
  cursor:pointer;font-size:13px;font-weight:500;color:var(--muted);
  transition:all .15s;user-select:none;
}}
.tt-pill.active {{
  border-color:var(--primary);background:rgba(0,212,255,0.12);
  color:var(--primary);
}}
.tt-pill:hover {{ border-color:var(--primary);color:var(--text); }}
.tt-input-row {{ display:none; margin-top:8px; }}
.tt-input-row.visible {{ display:block; }}
.mod-hidden {{ display:none !important; }}
.type-badge {{
  font-size:9px;padding:1px 5px;border-radius:8px;
  background:var(--bg3);color:var(--muted);margin-left:4px;
  text-transform:uppercase;letter-spacing:.5px;font-weight:600;
}}
</style>

<div style="max-width:1200px;margin:0 auto">
<div class="flex justify-between items-center mb-3">
  <div>
    <div class="section-title">New OSINT Scan</div>
    {f'<div style="font-size:12px;color:var(--muted)">Investigation: {inv_title}</div>' if inv else ''}
  </div>
  <a href="/investigation/{inv_id}" class="btn btn-ghost btn-sm">← Back</a>
</div>
<form method="POST" id="scan-form" enctype="multipart/form-data">

<!-- ═══════════════════════ TARGET TYPES ═══════════════════════ -->
<div class="card">
  <div class="card-header"><span class="card-title">🎯 What are you investigating?</span></div>
  <div class="card-body">
    <div style="font-size:12px;color:var(--muted);margin-bottom:10px">
      Click one or more target types below - <strong>Domain / URL</strong> is pre-selected.
      Each type shows its own input field and filters the module list to only relevant modules.
    </div>

    <!-- Type pills - plain divs; clicks wired via addEventListener in <script> below -->
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px" id="type-pills">
      <div class="tt-pill active" data-type="domain">🌐 Domain / URL</div>
      <div class="tt-pill" data-type="username">👤 Username / Handle</div>
      <div class="tt-pill" data-type="email">📧 Email Address</div>
      <div class="tt-pill" data-type="phone">📞 Phone Number</div>
      <div class="tt-pill" data-type="ip">🖥️ IP Address</div>
      <div class="tt-pill" data-type="string">🔍 Keyword / String</div>
      <div class="tt-pill" data-type="image">🖼️ Image OSINT</div>
    </div>

    <!-- Per-type input fields (shown/hidden by JS) -->
    <div id="tt-domain" class="tt-input-row visible">
      <label>Domain / URL <span style="font-size:11px;color:var(--muted)">- example.com, https://app.target.io</span></label>
      <input type="text" name="target_domain" value="{inv_target}"
             placeholder="example.com or https://target.io"
             style="font-family:var(--mono);font-size:13px">
    </div>
    <div id="tt-username" class="tt-input-row">
      <label style="display:flex;align-items:center;gap:8px">
        Username / Handle <span style="font-size:11px;color:var(--muted)">- without @, e.g. john_doe</span>
        <label style="display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer;
                      font-size:11px;font-weight:500;color:var(--primary)">
          <input type="checkbox" id="adv-username-toggle" name="adv_username" value="1"
                 onchange="toggleAdvUsername(this.checked)" style="accent-color:var(--primary)">
          ⚙ Advanced (build from name)
        </label>
      </label>
      <div id="adv-username-simple">
        <input type="text" name="target_username" id="target_username_simple"
               placeholder="john_doe  (no @ prefix needed)"
               style="font-family:var(--mono);font-size:13px">
      </div>
      <div id="adv-username-fields" style="display:none">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
          <span style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">People to scan</span>
          <button type="button" onclick="addNameRow('un')"
            style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--primary);border-radius:4px;color:var(--primary);cursor:pointer">+ Add Person</button>
          <label style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);cursor:pointer">
            ⬆ Import CSV
            <input type="file" accept=".csv" style="display:none" onchange="importNameCsv(this,'un')">
          </label>
          <a href="/api/download-template?type=username" download="username_template.csv"
            style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);text-decoration:none;cursor:pointer">⬇ Template</a>
        </div>
        <div id="un-rows" style="margin-bottom:4px"></div>
        <input type="hidden" name="name_users_json" id="name-users-json">
        <div style="margin-top:6px;font-size:11px;color:var(--muted)">
          Generates usernames like <code style="color:var(--primary)">john.doe</code>,
          <code style="color:var(--primary)">j.doe</code>… per enabled patterns in
          <a href="/settings/username-patterns" target="_blank" style="color:var(--primary)">Settings → Patterns</a>.
          CSV columns: <code style="color:var(--primary)">first,middle,last</code>
        </div>
      </div>
    </div>
    <div id="tt-email" class="tt-input-row">
      <label style="display:flex;align-items:center;gap:8px">
        Email Address <span style="font-size:11px;color:var(--muted)">- used for HIBP, holehe, Gravatar checks</span>
        <label style="display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer;
                      font-size:11px;font-weight:500;color:var(--primary)">
          <input type="checkbox" id="adv-email-toggle" name="adv_email" value="1"
                 onchange="toggleAdvEmail(this.checked)" style="accent-color:var(--primary)">
          ⚙ Advanced (build from name)
        </label>
      </label>
      <div id="adv-email-simple">
        <input type="email" name="target_email" id="target_email_simple"
               placeholder="target@example.com"
               style="font-family:var(--mono);font-size:13px">
      </div>
      <div id="adv-email-fields" style="display:none">
        <div style="margin-bottom:10px">
          <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:3px">Domain <span style="color:var(--danger)">*</span> <span style="color:var(--muted)">(shared across all targets)</span></label>
          <input type="text" name="email_domain" id="email-domain-shared" placeholder="company.com"
                 style="width:100%;max-width:300px;background:var(--bg2);border:1px solid var(--border);
                        border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:13px">
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
          <span style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">Email targets</span>
          <button type="button" onclick="addNameRow('em')"
            style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--primary);border-radius:4px;color:var(--primary);cursor:pointer">+ Add Person</button>
          <label style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);cursor:pointer">
            ⬆ Import CSV
            <input type="file" accept=".csv" style="display:none" onchange="importNameCsv(this,'em')">
          </label>
          <a href="/api/download-template?type=email" download="email_template.csv"
            style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);text-decoration:none;cursor:pointer">⬇ Template</a>
        </div>
        <div id="em-rows" style="margin-bottom:4px"></div>
        <input type="hidden" name="email_users_json" id="email-users-json">
        <div style="margin-top:6px;font-size:11px;color:var(--muted)">
          Scans <code style="color:var(--primary)">john.doe@company.com</code>,
          <code style="color:var(--primary)">j.doe@company.com</code>… for each person across enabled patterns.
          CSV columns: <code style="color:var(--primary)">first,middle,last</code>
        </div>
      </div>
    </div>
    <div id="tt-phone" class="tt-input-row">
      <label>Phone Number <span style="font-size:11px;color:var(--muted)">- E.164 preferred: +1-555-0100</span></label>
      <input type="text" name="target_phone"
             placeholder="+1-555-0100 or 07911123456"
             style="font-family:var(--mono);font-size:13px">
    </div>
    <div id="tt-ip" class="tt-input-row">
      <label>IP Address <span style="font-size:11px;color:var(--muted)">- IPv4 or IPv6</span></label>
      <input type="text" name="target_ip"
             placeholder="192.168.1.1 or 2001:db8::1"
             style="font-family:var(--mono);font-size:13px">
    </div>
    <div id="tt-string" class="tt-input-row">
      <label>Keyword / Search String <span style="font-size:11px;color:var(--muted)">- dark web + dork searches, paste monitoring</span></label>
      <input type="text" name="target_string"
             placeholder="Acme Corp breach  /  leaked credentials  /  project codename"
             style="font-family:var(--mono);font-size:13px">
    </div>
    <div id="tt-image" class="tt-input-row">
      <label>Upload Image <span style="font-size:11px;color:var(--muted)">- JPG, PNG, WebP, GIF, BMP (max 20 MB)</span></label>
      <div style="display:flex;align-items:center;gap:12px;margin-top:6px">
        <label style="display:inline-flex;align-items:center;gap:8px;padding:10px 18px;
                      background:var(--bg3);border:2px dashed var(--border);border-radius:8px;
                      cursor:pointer;font-size:13px;color:var(--text2);transition:border-color .15s"
               id="img-upload-label">
          📁 Choose Image File
          <input type="file" name="target_image" id="target-image-input" accept="image/*"
                 style="display:none" onchange="imgFileSelected(this)">
        </label>
        <span id="img-filename-display" style="font-size:12px;color:var(--primary);font-family:var(--mono)"></span>
      </div>
      <div id="img-preview-wrap" style="display:none;margin-top:10px">
        <img id="img-preview" src="" alt="preview"
             style="max-width:320px;max-height:200px;border-radius:6px;border:1px solid var(--border)">
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
        <div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;
                    letter-spacing:0.8px;margin-bottom:10px">
          🔍 Optional context - improves matching accuracy
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Subject Name <span style="font-size:10px;color:var(--muted)">(person in photo)</span></label>
            <input type="text" name="img_subject_name" placeholder="John Doe"
                   style="font-size:13px">
          </div>
          <div class="form-group">
            <label>Username / Handle <span style="font-size:10px;color:var(--muted)">(no @ needed)</span></label>
            <input type="text" name="img_username" placeholder="john_doe"
                   style="font-family:var(--mono);font-size:13px">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="img_email" placeholder="john@example.com"
                   style="font-family:var(--mono);font-size:13px">
          </div>
          <div class="form-group">
            <label>Phone Number</label>
            <input type="text" name="img_phone" placeholder="+1-555-0100"
                   style="font-family:var(--mono);font-size:13px">
          </div>
        </div>
        <div class="form-group">
          <label>Keywords / Context <span style="font-size:10px;color:var(--muted)">(location, event, company, anything relevant)</span></label>
          <input type="text" name="img_keyword"
                 placeholder="Eiffel Tower 2023  /  Acme Corp conference  /  Berlin startup"
                 style="font-size:13px">
        </div>
      </div>
    </div>

    <!-- Hidden field collects comma-sep list of active types for backend -->
    <input type="hidden" name="target_types" id="target-types-hidden" value="domain">

    <div id="tt-error" style="display:none;color:var(--danger);font-size:12px;margin-top:8px">
      ⚠️ Please select at least one target type and fill in its value.
    </div>
  </div>
</div>

<!-- ═══════════════════════ SCAN SETTINGS ═══════════════════════ -->
<div class="card">
  <div class="card-header"><span class="card-title">⚙️ Scan Settings</span></div>
  <div class="card-body">
    <div class="form-row">
      <div class="form-group"><label>Scan Name</label>
        <input type="text" name="scan_name" placeholder="Optional label for this scan"></div>
      <div class="form-group"><label>Scan Type</label>
        <select name="scan_type">
          <option value="osint">Advanced OSINT</option>
          <option value="sast">Source Code Analysis</option>
        </select>
      </div>
    </div>
    <div id="domain-settings" class="form-row3">
      <div class="form-group"><label>Crawl Depth (1–5)</label>
        <input type="number" name="crawl_depth" value="{default_depth}" min="1" max="5"></div>
      <div class="form-group" style="grid-column:span 2"><label>File Types (web crawler)</label>
        <input type="text" name="file_types" placeholder=".sql,.env,.bak,*"></div>
    </div>
    <!-- Wayback config: only relevant for domain targets -->
    <div id="wayback-settings" class="card" style="background:var(--bg3);padding:14px;margin-bottom:16px">
      <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">🕰️ Wayback Machine Config</div>
      <div class="form-row3">
        <div class="form-group">
          <label>URL Limit per Query</label>
          <input type="number" name="wayback_limit" value="500" min="50" max="5000">
          <div style="font-size:10px;color:var(--muted);margin-top:3px">50–5000 (default 500)</div>
        </div>
        <div class="form-group" style="grid-column:span 2">
          <label>Sensitive Extensions</label>
          <input type="text" name="wayback_extensions"
            value="xls,xml,xlsx,json,pdf,sql,doc,docx,pptx,txt,git,zip,tar.gz,tgz,bak,7z,rar,log,cache,secret,db,backup,yaml,gz,config,csv,md,env,pem,key,pub,asc,passwd,htpasswd,dockerenv,tfstate"
            style="font-size:11px;font-family:var(--mono)">
          <div style="font-size:10px;color:var(--muted);margin-top:3px">Comma-separated CDX filter</div>
        </div>
      </div>
    </div>
    <div class="form-group">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
        <input type="checkbox" name="use_tor" {tor_checked}>
        <span>Route all scan traffic through TOR Anonymous Mode</span>
        <span class="badge badge-info" style="margin-left:4px">Recommended</span>
      </label>
    </div>
    <div id="sast-section" style="display:none">
      <div class="form-group"><label>Source Code Path</label>
        <input type="text" name="source_path" placeholder="/path/to/source/code"></div>
    </div>
  </div>
</div>

<!-- ═══════════════════════ MODULES ═══════════════════════ -->
<div class="card">
  <div class="card-header">
    <div>
      <span class="card-title">🧩 OSINT Modules</span>
      <span id="mod-count-label" style="font-size:11px;color:var(--muted);margin-left:8px"></span>
    </div>
    <div style="display:flex;gap:6px;align-items:center">
      <button type="button" class="btn btn-ghost btn-sm" onclick="selVisible(true)">Select Visible</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selVisible(false)">Deselect Visible</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selAll(true)">All</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selAll(false)">None</button>
    </div>
  </div>
  <div class="card-body">
    <div id="mod-filter-hint" style="font-size:11px;color:var(--muted);margin-bottom:10px">
      Showing modules relevant to your selected target types. Greyed-out modules are hidden (not applicable).
    </div>
    <div class="module-grid" id="module-grid">{mod_cards}</div>
  </div>
</div>

<!-- ═══════════════════════ API KEYS ═══════════════════════ -->
<div class="card">
  <div class="card-header"><span class="card-title">🔑 API Keys (optional - override settings)</span></div>
  <div class="card-body">
    <div class="form-row">
      <div class="form-group"><label>GitHub Token</label><input type="password" name="github_token" placeholder="ghp_..."></div>
      <div class="form-group"><label>Shodan API Key</label><input type="password" name="shodan_key" placeholder=""></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Anthropic/Claude Key</label><input type="password" name="anthropic_key" placeholder="sk-ant-..."></div>
      <div class="form-group"><label>VirusTotal Key</label><input type="password" name="virustotal_key" placeholder=""></div>
    </div>
  </div>
</div>

<div class="flex gap-2">
  <button class="btn btn-primary" name="start_now" value="1" onclick="return validateForm()">🚀 Start Scan Now</button>
  <button class="btn btn-ghost" onclick="return validateForm()">💾 Save Only</button>
</div>
</form>
</div>

<script>
/* ── Target type pill system ─────────────────────────────────── */
var MODULE_TARGETS = {{
{chr(10).join(f'  "{mid}": {json.dumps(_MODULE_TARGET_TYPES.get(mid, ["domain"]))},' for mid,_,_,_ in _MODULES_META)}
}};

function getActiveTypes() {{
  var types = [];
  document.querySelectorAll('#type-pills .tt-pill').forEach(function(pill) {{
    if (pill.classList.contains('active')) types.push(pill.dataset.type);
  }});
  return types;
}}

function syncTargetTypesField() {{
  var types = getActiveTypes();
  document.getElementById('target-types-hidden').value = types.join(',');
  filterModules(types);
  toggleDomainSettings(types);
  updateModCount();
}}

function filterModules(types) {{
  var grid = document.getElementById('module-grid');
  if (!grid) return;
  grid.querySelectorAll('.module-card').forEach(function(card) {{
    var cardTargets = (card.dataset.targets || 'domain').split(' ');
    var relevant = types.some(function(t) {{ return cardTargets.indexOf(t) >= 0; }});
    if (relevant) {{
      card.classList.remove('mod-hidden');
    }} else {{
      card.classList.add('mod-hidden');
    }}
  }});
}}

function updateModCount() {{
  var total   = document.querySelectorAll('.module-card').length;
  var visible = document.querySelectorAll('.module-card:not(.mod-hidden)').length;
  var checked = document.querySelectorAll('.module-card:not(.mod-hidden) input:checked').length;
  var lbl = document.getElementById('mod-count-label');
  if (lbl) lbl.textContent = checked + ' selected · ' + visible + ' relevant of ' + total;
}}

function toggleDomainSettings(types) {{
  var isDomain = types.indexOf('domain') >= 0;
  var ds = document.getElementById('domain-settings');
  var ws = document.getElementById('wayback-settings');
  if (ds) ds.style.display = isDomain ? '' : 'none';
  if (ws) ws.style.display = isDomain ? '' : 'none';
}}

/* Pill click handler */
function ttPillClick(pill) {{
  var active = getActiveTypes();
  var isActive = pill.classList.contains('active');
  /* Prevent deselecting the last active pill */
  if (isActive && active.length === 1) return;
  pill.classList.toggle('active', !isActive);
  /* Show/hide corresponding input row */
  var tt = pill.dataset.type;
  var row = document.getElementById('tt-' + tt);
  if (row) row.classList.toggle('visible', !isActive);
  syncTargetTypesField();
}}

/* Wire pill clicks via addEventListener - more reliable than onclick attrs */
document.querySelectorAll('#type-pills .tt-pill').forEach(function(pill) {{
  pill.addEventListener('click', function() {{ ttPillClick(pill); }});
}});

/* Init */
syncTargetTypesField();

/* ── Module toggle ───────────────────────────────────────────── */
function toggleMod(card) {{
  if (card.classList.contains('mod-hidden')) return;
  var cb = card.querySelector('input[type=checkbox]');
  cb.checked = !cb.checked;
  card.classList.toggle('selected', cb.checked);
  updateModCount();
}}
function selVisible(on) {{
  document.querySelectorAll('.module-card:not(.mod-hidden)').forEach(function(c) {{
    c.querySelector('input').checked = on;
    c.classList.toggle('selected', on);
  }});
  updateModCount();
}}
function selAll(on) {{
  document.querySelectorAll('.module-card').forEach(function(c) {{
    c.querySelector('input').checked = on;
    c.classList.toggle('selected', on);
  }});
  updateModCount();
}}

/* ── Scan type ───────────────────────────────────────────────── */
document.querySelector('[name=scan_type]').addEventListener('change', function() {{
  document.getElementById('sast-section').style.display = this.value === 'sast' ? 'block' : 'none';
}});

/* ── Multi-user name builder ──────────────────────────────────── */
var _INP_STYLE = 'background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:6px 10px;color:var(--text);font-size:13px;width:100%';
function addNameRow(prefix, data) {{
  data = data || {{}};
  var row = document.createElement('div');
  row.className = 'name-row';
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr 1fr 28px;gap:6px;margin-bottom:6px';
  row.innerHTML =
    '<input type="text" class="name-first" placeholder="First *" value="'+(data.first||'')+'" style="'+_INP_STYLE+'">' +
    '<input type="text" class="name-middle" placeholder="Middle" value="'+(data.middle||'')+'" style="'+_INP_STYLE+'">' +
    '<input type="text" class="name-last" placeholder="Last" value="'+(data.last||'')+'" style="'+_INP_STYLE+'">' +
    '<button type="button" onclick="removeNameRow(this)" title="Remove" style="background:none;border:1px solid var(--border);border-radius:5px;color:var(--danger);cursor:pointer;font-size:16px;padding:0">×</button>';
  document.getElementById(prefix+'-rows').appendChild(row);
}}
function removeNameRow(btn) {{
  var row = btn.closest('.name-row');
  if (row) row.remove();
}}
function collectUsersJson(prefix) {{
  var rows = document.querySelectorAll('#'+prefix+'-rows .name-row');
  var users = [];
  rows.forEach(function(r) {{
    var f=(r.querySelector('.name-first')||{{}}).value||'';
    var m=(r.querySelector('.name-middle')||{{}}).value||'';
    var l=(r.querySelector('.name-last')||{{}}).value||'';
    f=f.trim(); m=m.trim(); l=l.trim();
    if (f||l) users.push({{first:f,middle:m,last:l}});
  }});
  var fid = prefix==='un' ? 'name-users-json' : 'email-users-json';
  var fld = document.getElementById(fid);
  if (fld) fld.value = JSON.stringify(users);
  return users;
}}
function importNameCsv(input, prefix) {{
  var file = input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {{
    var lines = e.target.result.split('\\n');
    var container = document.getElementById(prefix+'-rows');
    container.innerHTML = '';
    lines.forEach(function(line, idx) {{
      line = line.trim();
      if (!line) return;
      var cols = line.split(',');
      var first=(cols[0]||'').trim(), mid=(cols[1]||'').trim(), last=(cols[2]||'').trim();
      if (idx===0 && first.toLowerCase()==='first') return;
      if (first||last) addNameRow(prefix,{{first:first,middle:mid,last:last}});
    }});
    input.value='';
  }};
  reader.readAsText(file);
}}

/* ── Advanced name builder toggles ──────────────────────────── */
function toggleAdvUsername(on) {{
  document.getElementById('adv-username-simple').style.display = on ? 'none' : '';
  document.getElementById('adv-username-fields').style.display = on ? '' : 'none';
  var s = document.getElementById('target_username_simple');
  if (s) s.disabled = on;
  if (on && document.getElementById('un-rows').children.length===0) addNameRow('un');
}}
function toggleAdvEmail(on) {{
  document.getElementById('adv-email-simple').style.display = on ? 'none' : '';
  document.getElementById('adv-email-fields').style.display = on ? '' : 'none';
  var s = document.getElementById('target_email_simple');
  if (s) s.disabled = on;
  if (on && document.getElementById('em-rows').children.length===0) addNameRow('em');
}}

/* ── Image file preview ─────────────────────────────────────── */
function imgFileSelected(input) {{
  var label = document.getElementById('img-upload-label');
  var disp  = document.getElementById('img-filename-display');
  var wrap  = document.getElementById('img-preview-wrap');
  var prev  = document.getElementById('img-preview');
  if (!input.files || !input.files[0]) return;
  var file = input.files[0];
  if (disp) disp.textContent = file.name + ' (' + (file.size / 1024).toFixed(0) + ' KB)';
  if (label) label.style.borderColor = 'var(--primary)';
  if (wrap && prev && file.type.startsWith('image/')) {{
    var reader = new FileReader();
    reader.onload = function(e) {{
      prev.src = e.target.result;
      wrap.style.display = 'block';
    }};
    reader.readAsDataURL(file);
  }}
}}

/* ── Form validation + JSON collect ─────────────────────────── */
function validateForm() {{
  collectUsersJson('un');
  collectUsersJson('em');
  var types  = getActiveTypes();
  var hasVal = false;
  types.forEach(function(tt) {{
    if (tt==='username' && document.getElementById('adv-username-toggle') &&
        document.getElementById('adv-username-toggle').checked) {{
      var rows = document.querySelectorAll('#un-rows .name-row');
      for (var i=0;i<rows.length;i++) {{
        var f=rows[i].querySelector('.name-first');
        if (f&&f.value.trim()) {{ hasVal=true; break; }}
      }}
      return;
    }}
    if (tt==='email' && document.getElementById('adv-email-toggle') &&
        document.getElementById('adv-email-toggle').checked) {{
      var ed = document.getElementById('email-domain-shared');
      var rows = document.querySelectorAll('#em-rows .name-row');
      if (ed&&ed.value.trim()&&rows.length>0) {{
        var f=rows[0].querySelector('.name-first');
        if (f&&f.value.trim()) hasVal=true;
      }}
      return;
    }}
    var inp = document.querySelector('[name=target_'+tt+']');
    if (inp&&inp.value.trim()) hasVal=true;
  }});
  if (!hasVal) {{
    document.getElementById('tt-error').style.display='block';
    window.scrollTo(0,0);
    return false;
  }}
  return true;
}}
</script>"""
    return _base("New Scan", html, "investigations")

# ═════════════════════════════════════════════════════════════════════════════
# SCAN VIEW
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/scan/<scan_id>")
@require_login
def view_scan(scan_id):
    uid  = flask_session["uid"]
    scan = db.one("SELECT * FROM osint_scans WHERE id=?", (scan_id,))
    if not scan:
        return redirect("/investigations")
    # Non-admin users may only view their own scans
    if not _is_admin() and scan.get("user_id") != uid:
        return redirect("/investigations")
    # Soft-deleted scans are hidden from the user who deleted them
    if not _is_admin() and scan.get("deleted_by_user"):
        return redirect("/investigations")
    status  = scan.get("status","")
    prog    = scan.get("progress",0)
    curmod  = scan.get("current_module","")
    findings= db.get_findings(scan_id, limit=500)
    traffic = db.get_traffic(scan_id, limit=200)

    # Severity summary
    sev_summary = {}
    for f in findings:
        s = f["severity"]
        sev_summary[s] = sev_summary.get(s,0)+1

    sev_pills = ""
    for sev in ["critical","high","medium","low","info"]:
        c = sev_summary.get(sev,0)
        if c:
            sev_pills += f'<span class="badge badge-{sev}">{c} {sev}</span> '

    # Findings table grouped by module
    import html as _html
    findings_html = ""
    for f in findings:
        sev       = f.get("severity","info")
        fid       = f.get("id","")
        url       = f.get("url","") or ""
        ss_id     = f.get("screenshot_id","") or ""
        ts_str    = str(f.get('created_at',''))[:16]
        # Fully escape all text from DB to prevent HTML injection / page breakage
        title_raw = str(f.get('title','') or '')
        desc_raw  = str(f.get('description','') or '')
        title_esc = _html.escape(title_raw[:100])
        desc_esc  = _html.escape(desc_raw[:150])
        mod_label = _html.escape(str(f.get("module","") or ""))
        ev_raw    = str(f.get("evidence","") or "")
        ev_full   = _html.escape(ev_raw)
        ev_full   = re.sub(
            r'(https?://[^\s<>"]{5,})',
            r'<a href="\1" target="_blank" rel="noopener noreferrer" '
            r'style="color:var(--primary);text-decoration:underline">\1</a>',
            ev_full
        )
        ev_short  = _html.escape(ev_raw[:120]) + ("…" if len(ev_raw)>120 else "")
        tags_raw  = str(f.get("tags","") or "")
        raw_str   = ""
        try:
            rd = json.loads(f.get("raw_data","{}") or "{}")
            if rd:
                raw_str = _html.escape(json.dumps(rd, indent=2)[:800])
        except Exception:
            pass
        # data-search: full text index for JS filtering (no HTML, no escaping for search)
        search_corpus = " ".join([
            title_raw, desc_raw, ev_raw, str(f.get("module","")),
            url, tags_raw, sev, ts_str
        ]).lower()
        search_esc = _html.escape(search_corpus, quote=True)
        # PoC section: WHERE / HOW / WHAT
        target_esc = _html.escape(str(scan.get('target','') or ''))
        poc_where  = _html.escape(url[:300]) if url else f"Target: {target_esc}"
        poc_how    = f"Module: {mod_label} | Severity: {sev.upper()}"
        url_esc    = _html.escape(url, quote=True)
        if url:
            url_link = f'<a href="{url_esc}" target="_blank" style="color:var(--primary);font-size:10px;word-break:break-all;font-family:monospace">{_html.escape(url[:80])}</a>'
        else:
            url_link = ""
        # Screenshot thumbnail (if captured during scan)
        ss_row = db.get_screenshot(ss_id) if ss_id else None
        if not ss_row and url:
            ss_row = db.get_screenshot_for_url(f.get("scan_id",""), url)
        ss_html = ""
        if ss_row and ss_row.get("thumbnail"):
            ss_id_actual = ss_row["id"]
            ss_html = f"""
            <div style="margin-top:10px">
              <div style="font-size:9px;color:var(--muted);letter-spacing:.6px;
                          margin-bottom:5px;text-transform:uppercase">📸 Screenshot</div>
              <div style="position:relative;display:inline-block;border:1px solid var(--border);
                          border-radius:6px;overflow:hidden;cursor:pointer;max-width:100%"
                   onclick="window.open('/api/screenshot/{ss_id_actual}','_blank')">
                <img src="data:image/png;base64,{ss_row['thumbnail']}"
                     alt="Screenshot" loading="lazy"
                     style="max-width:100%;max-height:300px;display:block;
                            border-radius:5px;object-fit:contain">
                <div style="position:absolute;bottom:4px;right:6px;font-size:9px;
                            background:rgba(0,0,0,.7);color:#fff;padding:2px 5px;border-radius:3px">
                  🔍 Click to open full size
                </div>
              </div>
            </div>"""
        elif url and url.startswith("http"):
            ss_html = f"""
            <div style="margin-top:10px">
              <button onclick="takeScreenshot('{fid}','{url_esc}')"
                id="ss-btn-{fid}"
                style="font-size:10px;padding:3px 10px;border-radius:5px;cursor:pointer;
                       border:1px solid var(--border);background:var(--bg3);color:var(--muted)">
                📸 Capture Screenshot
              </button>
              <div id="ss-result-{fid}" style="margin-top:6px"></div>
            </div>"""
        results_detail_html = ""
        try:
            _rd2 = json.loads(f.get("raw_data","{}") or "{}")
            if f.get("module") == "googleDork" and _rd2.get("results"):
                _thresh   = _rd2.get("threshold", 60)
                _rejected = _rd2.get("rejected", 0)
                _dork_esc = _html.escape(_rd2.get("dork",""))
                _cards    = []
                for _ri, _r in enumerate(_rd2["results"][:20]):
                    _conf  = _r.get("confidence", 0)
                    _rurl  = _html.escape(_r.get("url",""), quote=True)
                    _rurl_display = _html.escape(_r.get("url",""))[:100]
                    _rtitle = _html.escape(_r.get("title",""))[:90]
                    _rsnip  = _html.escape(_r.get("snippet",""))[:160]
                    _col   = ("#22c55e" if _conf >= 85
                              else "#f59e0b" if _conf >= 60
                              else "#ef4444")
                    _bar   = "█" * (_conf // 10) + "░" * (10 - _conf // 10)
                    _uid   = f"{fid}_{_ri}"
                    _cards.append(
                        f'<div style="border:1px solid var(--border);border-radius:6px;'
                        f'padding:8px 10px;margin-bottom:6px;background:var(--bg)">'
                        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                        f'<span style="font-size:10px;font-weight:700;color:{_col};'
                        f'background:{_col}22;padding:1px 7px;border-radius:10px;'
                        f'font-family:monospace;letter-spacing:.5px">{_conf}%</span>'
                        f'<span style="font-size:9px;color:var(--muted);font-family:monospace">'
                        f'{_bar}</span>'
                        f'<span style="font-size:11px;font-weight:600;color:#e2e8f0;'
                        f'flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
                        f'{_rtitle}</span>'
                        f'</div>'
                        f'<div style="font-size:9px;font-family:monospace;margin-bottom:3px">'
                        f'<a href="{_rurl}" target="_blank" style="color:#818cf8;word-break:break-all">'
                        f'{_rurl_display}</a></div>'
                        f'<div style="font-size:10px;color:var(--muted);margin-bottom:6px">'
                        f'{_rsnip}</div>'
                        f'<div style="display:flex;gap:6px;align-items:center">'
                        f'<a href="{_rurl}" target="_blank" style="font-size:9px;padding:2px 8px;'
                        f'border:1px solid var(--border);border-radius:4px;background:var(--bg3);'
                        f'color:var(--muted);text-decoration:none">🔗 Open</a>'
                        f'<button onclick="captureUrlSS(\'{_html.escape(_r.get("url",""), quote=True)}\','
                        f'\'ss-url-{_uid}\',this,\'{scan_id}\')" '
                        f'style="font-size:9px;padding:2px 8px;border:1px solid var(--border);'
                        f'border-radius:4px;background:var(--bg3);color:var(--muted);cursor:pointer">'
                        f'📸 Screenshot</button>'
                        f'</div>'
                        f'<div id="ss-url-{_uid}" style="margin-top:6px"></div>'
                        f'</div>'
                    )
                _reject_note = (f' &nbsp;·&nbsp; <span style="color:#ef4444">'
                                f'{_rejected} filtered</span>' if _rejected else "")
                results_detail_html = (
                    f'<div style="margin-top:10px">'
                    f'<div style="font-size:9px;color:var(--muted);letter-spacing:.6px;'
                    f'text-transform:uppercase;margin-bottom:6px">'
                    f'🔍 Results &nbsp;·&nbsp; ≥{_thresh}% confidence'
                    f'{_reject_note}</div>'
                    f'<div style="font-size:9px;color:#64748b;font-family:monospace;'
                    f'padding:4px 7px;background:var(--bg3);border-radius:4px;'
                    f'margin-bottom:7px;word-break:break-all">Dork: {_dork_esc}</div>'
                    + "".join(_cards)
                    + "</div>"
                )
                raw_str = ""
        except Exception:
            pass

        poc_html = f"""
          <tr id="poc-{fid}" style="display:none">
            <td colspan="5" style="padding:0 8px 12px 8px;background:var(--bg1)">
              <div style="border:1px solid var(--border);border-radius:7px;padding:12px 14px;
                          font-size:11px;font-family:monospace;background:var(--bg)">
                <div style="display:grid;grid-template-columns:60px 1fr;gap:4px 10px;margin-bottom:10px">
                  <span style="color:var(--muted);font-size:10px;padding-top:2px">📍 WHERE</span>
                  <span style="color:#818cf8;word-break:break-all">{poc_where}</span>
                  <span style="color:var(--muted);font-size:10px;padding-top:2px">⚙️ HOW</span>
                  <span style="color:#f59e0b">{poc_how}</span>
                  <span style="color:var(--muted);font-size:10px;padding-top:2px">🔍 WHAT</span>
                  <span style="color:#f1f5f9;white-space:pre-wrap;word-break:break-all;{"max-height:400px;overflow-y:auto;display:block;padding-right:4px;scrollbar-width:thin" if len(ev_full)>600 else ""}">{ev_full or "(no evidence recorded)"}</span>
                </div>
                {results_detail_html}
                {f'<div style="margin-top:6px;padding:6px 8px;background:var(--bg3);border-radius:4px;border:1px solid var(--border);color:#64748b;white-space:pre-wrap;word-break:break-all;font-size:10px">{raw_str}</div>' if raw_str else ''}
                {('<div style="margin-top:6px"><a href="' + url_esc + '" target="_blank" class="btn btn-ghost btn-sm" style="font-size:10px">🔗 Open URL</a></div>') if url else ''}
                {ss_html}
              </div>
            </td>
          </tr>"""
        findings_html += f"""<tr onclick="togglePoc('{fid}')" style="cursor:pointer"
          data-fid="{fid}"
          data-search="{search_esc}"
          data-sev="{sev}"
          data-mod="{_html.escape(str(f.get('module','')), quote=True)}"
          data-ev="{_html.escape(ev_raw[:500], quote=True)}"
          data-time="{ts_str}"
          title="Click to expand PoC details">
          <td><span class="badge badge-{sev}">{sev}</span></td>
          <td class="mono text-sm" style="color:var(--secondary)">{mod_label}</td>
          <td>
            <div style="font-weight:500;font-size:13px">{title_esc}</div>
            <div class="text-sm text-muted mt-1">{desc_esc}</div>
            {url_link}
          </td>
          <td>
            <div class="mono text-sm" style="background:var(--bg);padding:4px 8px;border-radius:4px;
              max-width:280px;overflow:hidden;white-space:pre-wrap;word-break:break-all;font-size:10px;
              color:var(--warning)">{ev_short}</div>
          </td>
          <td class="text-sm text-muted mono" style="white-space:nowrap">{ts_str}</td>
        </tr>
        {poc_html}"""
    if not findings_html:
        findings_html = '<tr><td colspan=5 style="text-align:center;padding:30px;color:var(--muted)">No findings yet</td></tr>'

    scan_use_tor = 1 if (scan.get('use_tor', 0) or engine.http.use_tor) else 0

    # Traffic log
    tlog_html = ""
    for t in traffic[:100]:
        via_tor  = bool(t.get("via_tor",0)) or bool(scan_use_tor)
        exit_ip  = t.get("tor_exit_ip","") or ""
        src_ip   = t.get("source_ip","?") or "?"
        req_url  = t.get("url","") or ""
        s = t.get("status_code",0)
        sc = "color:#69f0ae" if s<300 else ("color:#ffad00" if s<400 else "color:#ff3860")
        try:
            from urllib.parse import urlparse as _up
            _p = _up(req_url)
            disp_path = (_p.path or "/") + (("?" + _p.query) if _p.query else "")
            if len(disp_path) > 50: disp_path = disp_path[:47] + "…"
            disp_path = _html.escape(disp_path)
        except Exception:
            disp_path = ""
        tor_badge = f'<span style="color:#00ff9d;font-size:9px;margin-left:4px">⬡TOR{("→"+exit_ip[:15]) if exit_ip else ""}</span>' if via_tor else ""
        tlog_html += f"""<div class="tlog-entry{' tlog-tor-row' if via_tor else ''}"
          data-via-tor="{'1' if via_tor else '0'}"
          data-exit-ip="{exit_ip}"
          data-src-ip="{src_ip}"
          data-url="{req_url[:300].replace(chr(34),'&quot;')}">
          <button class="hop-path-btn" onclick="showHopPath(this)" title="{'Show TOR circuit' if via_tor else 'Show hop path'}"
            style="font-size:9px;padding:1px 5px;border-radius:3px;cursor:pointer;
                   border:1px solid {'#1e3a5f' if via_tor else 'var(--border)'};
                   background:{'#0a1628' if via_tor else 'var(--bg3)'};
                   color:{'#60a5fa' if via_tor else 'var(--muted)'};margin-right:4px;
                   font-family:monospace;flex-shrink:0">{'⬡⟶' if via_tor else '⟶'}</button>
          <span class="tlog-ts">{str(t.get('ts',''))[-8:-3]}</span>
          <span class="tlog-module">[{(t.get('module','?'))[:8]}]</span>
          <span class="tlog-src">{src_ip}</span>
          <span class="tlog-arrow" style="color:{'#00ff9d' if via_tor else 'var(--muted)'}">{' ─TOR─►' if via_tor else ' ──────►'}</span>
          <span class="tlog-dest">{t.get('dest_host','?')}:{t.get('dest_port',443)}</span>
          {f'<span class="tlog-path" style="color:#475569;font-size:9px;margin-left:2px">{disp_path}</span>' if disp_path else ''}
          {tor_badge}
          <span class="tlog-method" style="margin-left:4px">{t.get('method','GET')}</span>
          <span class="tlog-status" style="{sc}">{s}</span>
          <span class="tlog-dur">{t.get('duration_ms',0)}ms</span>
        </div>"""
    if not tlog_html:
        tlog_html = '<div style="color:var(--muted);padding:10px">No traffic recorded yet</div>'

    # Status bar
    status_color = {"running":"var(--primary)","completed":"var(--secondary)",
                    "failed":"var(--danger)","pending":"var(--warning)"}.get(status,"var(--muted)")
    running = status == "running"

    mods_cfg = {}
    try:
        mods_cfg = json.loads(scan.get("modules") or "{}")
    except Exception:
        pass
    enabled_mods = [name for name, enabled in mods_cfg.items() if enabled]
    mods_str      = " · ".join(enabled_mods[:8])
    target_esc    = _html.escape(str(scan.get('target','') or ''))
    scan_name_esc = _html.escape(str(scan.get('scan_name','') or ''))
    curmod_esc    = _html.escape(str(curmod or ''))

    # Build initial task log HTML
    tasks = db.get_tasks(scan_id, limit=200)
    _STATUS_ICON = {
        "running": '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
                   'background:#818cf8;animation:pulse 1.5s infinite;flex-shrink:0"></span>',
        "done":    '<span style="color:#69f0ae;flex-shrink:0">✓</span>',
        "skipped": '<span style="color:#ffad00;flex-shrink:0">⏭</span>',
        "error":   '<span style="color:#ff3860;flex-shrink:0">✗</span>',
    }
    task_rows_html = ""
    from datetime import datetime as _dt
    for t in tasks:
        st        = t.get("status","running")
        icon      = t.get("module_icon","🔌")
        label     = _html.escape(str(t.get("module_label","") or t.get("module","") or ""))
        task_txt  = _html.escape(str(t.get("task","") or ""))
        detail    = _html.escape(str((t.get("detail","") or ""))[:140])
        is_child  = bool(t.get("parent_id",""))
        # Duration
        dur_str = ""
        try:
            s = _dt.fromisoformat(t.get("started_at",""))
            e = _dt.fromisoformat(t.get("completed_at","")) if t.get("completed_at") else _dt.now()
            ms = int((e-s).total_seconds()*1000)
            dur_str = f"{ms}ms" if ms < 3000 else f"{ms//1000}s"
        except Exception:
            pass
        st_icon    = _STATUS_ICON.get(st, _STATUS_ICON["running"])
        is_running = st == "running"
        btn_html   = ""
        if is_running and not is_child:
            btn_html = f"""
              <button onclick="skipModule()" title="Skip this module"
                style="font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;
                       border:1px solid #ffad00;background:#0a1628;color:#ffad00">⏭ Skip</button>
              <button onclick="stopScan()" title="Stop scan"
                style="font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;
                       border:1px solid #ff3860;background:#0a1628;color:#ff3860">⏹ Stop</button>"""
        if is_child:
            # Indented child sub-task row
            row_bg    = "rgba(129,140,248,0.04)" if is_running else ""
            tree_line = '<span style="color:#1e3a5f;margin-right:4px;font-size:11px">└─</span>'
            task_rows_html += f"""
      <div class="tlog-entry" style="gap:6px;align-items:flex-start;padding:5px 12px 5px 32px;background:{row_bg}">
        {tree_line}
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap">
            {st_icon}
            <span style="font-size:11px;color:var(--fg)">{task_txt}</span>
            {f'<span style="color:var(--muted);font-size:9px;margin-left:4px">{dur_str}</span>' if dur_str else ''}
          </div>
          {f'<div style="font-size:10px;color:var(--muted);margin-top:1px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{detail}</div>' if detail else ''}
        </div>
      </div>"""
        else:
            # Parent module row
            row_bg = "rgba(129,140,248,0.07)" if is_running else ""
            task_rows_html += f"""
      <div class="tlog-entry" style="gap:8px;align-items:flex-start;padding:8px 12px;background:{row_bg};border-top:1px solid var(--border)">
        <span style="font-size:15px;flex-shrink:0">{icon}</span>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            {st_icon}
            <span style="font-weight:600;font-size:12px">{label}</span>
            <span style="color:var(--muted);font-size:11px">·</span>
            <span style="font-size:11px;color:var(--fg)">{task_txt}</span>
            {f'<span style="color:var(--muted);font-size:10px;margin-left:6px">{dur_str}</span>' if dur_str else ''}
          </div>
          {f'<div style="font-size:10px;color:var(--muted);margin-top:2px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{detail}</div>' if detail else ''}
        </div>
        <div style="display:flex;gap:4px;flex-shrink:0">{btn_html}</div>
      </div>"""
    if not task_rows_html:
        task_rows_html = '<div style="color:var(--muted);padding:14px">No tasks logged yet - start a scan to see activity here.</div>'

    # ── Found Images: collect matched/reference images from imageOsint findings ─
    _scan_img_matches = []
    _scan_img_refs    = []
    for _f in findings:
        if _f.get("module") != "imageOsint" or "Reverse" not in _f.get("title",""):
            continue
        try:
            _rd = json.loads(_f.get("raw_data","{}") or "{}")
        except Exception:
            _rd = {}
        for _m in _rd.get("matched",[]):
            _scan_img_matches.append(_m)
        for _r in _rd.get("reference",[]):
            _scan_img_refs.append(_r)

    import html as _html_mod
    _scan_images_html = ""
    if _scan_img_matches:
        _scan_images_html += (
            '<div style="font-size:11px;color:var(--muted);margin-bottom:12px">'
            + str(len(_scan_img_matches))
            + ' matched image(s) found (perceptual similarity ≥ 60%)</div>'
            '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px">'
        )
        for _m2 in _scan_img_matches:
            _url2  = _html_mod.escape(_m2.get("url",""))
            _th2   = _html_mod.escape(_m2.get("thumb",""))
            _sim2  = _m2.get("similarity",0)
            _src2  = _html_mod.escape(_m2.get("source",""))
            _dom2  = _html_mod.escape(_m2.get("domain","")[:30])
            _ttl2  = _html_mod.escape(_m2.get("title","")[:60])
            _sc2   = "#4ade80" if _sim2 >= 80 else "#facc15" if _sim2 >= 60 else "#94a3b8"
            _th_html2 = (
                '<a href="' + _url2 + '" target="_blank" rel="noopener noreferrer">'
                '<img src="' + _th2 + '" alt="Match thumbnail" loading="lazy"'
                ' style="width:100%;height:140px;object-fit:cover;border-radius:6px 6px 0 0;'
                'background:#111;display:block"'
                ' onerror="this.style.display=\'none\'"></a>'
            ) if _th2 else (
                '<a href="' + _url2 + '" target="_blank" rel="noopener noreferrer">'
                '<div style="width:100%;height:140px;background:var(--bg3);'
                'border-radius:6px 6px 0 0;display:flex;align-items:center;'
                'justify-content:center;font-size:32px;color:var(--muted)">\U0001f5bc️</div></a>'
            )
            _scan_images_html += (
                '<div style="background:var(--bg2);border:1px solid var(--border);'
                'border-radius:8px;overflow:hidden">'
                + _th_html2
                + '<div style="padding:10px">'
                '<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">'
                '<span style="background:' + _sc2 + '22;color:' + _sc2 + ';'
                'border:1px solid ' + _sc2 + '44;border-radius:4px;'
                'font-size:10px;padding:1px 6px;font-weight:700">' + str(_sim2) + '% match</span>'
                '<span style="font-size:10px;color:var(--muted)">' + _src2 + '</span>'
                '</div>'
                '<div style="font-size:11px;color:var(--text2);margin-bottom:4px">' + _dom2 + '</div>'
                '<div style="font-size:10px;color:var(--muted);margin-bottom:8px">' + _ttl2 + '</div>'
                '<a href="' + _url2 + '" target="_blank" rel="noopener noreferrer"'
                ' style="font-size:10px;color:var(--primary);word-break:break-all">'
                'Open Source Page →</a>'
                '</div></div>'
            )
        _scan_images_html += '</div>'
    if _scan_img_refs:
        _scan_images_html += (
            '<div style="margin-top:20px">'
            '<div style="font-size:11px;color:var(--muted);text-transform:uppercase;'
            'letter-spacing:.6px;margin-bottom:10px">Search Result Pages (no direct match)</div>'
        )
        for _ir2 in _scan_img_refs[:20]:
            _rurl2 = _html_mod.escape(_ir2.get("url",""))
            _rsrc2 = _html_mod.escape(_ir2.get("source",""))
            _rttl2 = _html_mod.escape(_ir2.get("title","")[:70])
            if _rurl2:
                _scan_images_html += (
                    '<div style="padding:6px 0;border-bottom:1px solid var(--border)20;font-size:11px">'
                    '<span style="color:var(--muted);margin-right:8px">[' + _rsrc2 + ']</span>'
                    '<a href="' + _rurl2 + '" target="_blank" rel="noopener noreferrer"'
                    ' style="color:var(--primary)">' + (_rttl2 or _rurl2[:60]) + '</a>'
                    '</div>'
                )
        _scan_images_html += '</div>'
    if not _scan_img_matches and not _scan_img_refs:
        _scan_images_html = (
            '<div style="text-align:center;padding:40px;color:var(--muted)">'
            '<div style="font-size:36px;margin-bottom:12px">\U0001f5bc️</div>'
            '<div style="font-size:14px">No matched images found.</div>'
            '<div style="font-size:12px;margin-top:8px">'
            'Run an Image OSINT scan - reverse image search will populate this tab.</div>'
            '</div>'
        )

    # ── Entity graph: build from this scan's findings (in-memory, no DB writes) ─
    import re as _re2
    _IP_RE2    = _re2.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _EMAIL_RE2 = _re2.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')
    _DOM_RE2   = _re2.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)'
        r'+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|onion|[a-z]{2,6})\b', _re2.I)
    _SKIP_IPS2 = {"127.0.0.1","0.0.0.0","255.255.255.255","8.8.8.8","8.8.4.4","1.1.1.1"}
    _SKIP_DOMS2 = {
        "com","net","org","io","gov","edu","co","uk","de","fr","ru","cn","info",
        "cloudflare.com","google.com","amazonaws.com","github.com",
        "googleapis.com","gstatic.com","jquery.com","cdnjs.cloudflare.com",
    }
    _sc_nodes = {}
    _sc_links_raw = []
    _target_val = scan.get("target","")
    try:
        _scan_notes = json.loads(scan.get("notes","{}") or "{}")
    except Exception:
        _scan_notes = {}
    _target_type_val = _scan_notes.get("target_type", "domain")
    _root_id = "t::" + _target_val
    _sc_nodes[_root_id] = {"id":_root_id,"label":_target_val[:28],"type":_target_type_val,"count":0,"root":True}
    _conf_map2 = {"critical":95,"high":85,"medium":70,"low":55,"info":40}
    for _f2 in findings:
        _mod2 = _f2.get("module","")
        _text2 = " ".join(filter(None,[
            _f2.get("title",""), _f2.get("description",""),
            _f2.get("evidence",""), _f2.get("url","")
        ]))
        _sev2  = _f2.get("severity","info")
        _conf2 = _conf_map2.get(_sev2, 60)
        for _email2 in set(_EMAIL_RE2.findall(_text2)):
            _eid2 = "e::" + _email2
            if _eid2 not in _sc_nodes:
                _sc_nodes[_eid2] = {"id":_eid2,"label":_email2[:28],"type":"email","count":1}
            else:
                _sc_nodes[_eid2]["count"] = _sc_nodes[_eid2].get("count",0) + 1
            _sc_links_raw.append({"source":_root_id,"target":_eid2,"type":"found","confidence":_conf2,"module":_mod2})
        for _ip2 in set(_IP_RE2.findall(_text2)):
            if _ip2 in _SKIP_IPS2: continue
            _iid2 = "i::" + _ip2
            if _iid2 not in _sc_nodes:
                _sc_nodes[_iid2] = {"id":_iid2,"label":_ip2,"type":"ip","count":1}
            else:
                _sc_nodes[_iid2]["count"] = _sc_nodes[_iid2].get("count",0) + 1
            _sc_links_raw.append({"source":_root_id,"target":_iid2,"type":"resolves_to","confidence":_conf2,"module":_mod2})
        for _dom2 in set(_DOM_RE2.findall(_text2)):
            _dom2 = _dom2.lower()
            if _dom2 in _SKIP_DOMS2 or _dom2 == _target_val: continue
            _did2 = "d::" + _dom2
            if _did2 not in _sc_nodes:
                _sc_nodes[_did2] = {"id":_did2,"label":_dom2[:28],"type":"domain","count":1}
            else:
                _sc_nodes[_did2]["count"] = _sc_nodes[_did2].get("count",0) + 1
            _sc_links_raw.append({"source":_root_id,"target":_did2,"type":"subdomain_of","confidence":_conf2,"module":_mod2})
    _link_map2 = {}
    for _lk2 in _sc_links_raw:
        _lkey2 = (_lk2["source"], _lk2["target"])
        if _lkey2 not in _link_map2 or _lk2["confidence"] > _link_map2[_lkey2]["confidence"]:
            _link_map2[_lkey2] = _lk2
    _scan_entity_nodes_json = json.dumps(list(_sc_nodes.values())[:200])
    _scan_entity_links_json = json.dumps(list(_link_map2.values())[:400])
    _scan_entity_count = len(_sc_nodes)
    _scan_entity_edge_count = len(_link_map2)

    _d3_script_tag = '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>'

    # Plain string - contains raw JS so { } must not be in an f-string context
    _sgraph_js = (
        '\nvar _sgInited=false;'
        '\nvar _sgNodes=' + _scan_entity_nodes_json + ';'
        '\nvar _sgLinks=' + _scan_entity_links_json + ';'
        '\nvar _sgZoom,_sgSim;'
        '\nvar _TYPE_COL_SG={'
        '"domain":"#00d4ff","email":"#00ff9d","username":"#ffad00","ip":"#ff3860",'
        '"organization":"#c084fc","person":"#7b8cde","phone":"#ff9d00","string":"#aabbcc"'
        '};'
        '\nfunction initSGraph(){'
        '\nif(_sgInited)return;_sgInited=true;'
        '\nvar svg=d3.select("#sgraph");'
        '\nvar wrap=document.getElementById("sgraph-svg-wrap");'
        '\nif(!wrap)return;'
        '\nvar W=wrap.clientWidth||800,H=wrap.clientHeight||520;'
        '\nsvg.attr("viewBox","0 0 "+W+" "+H);'
        '\nvar defs=svg.append("defs");'
        '\nvar arrowId="sg-arrow";'
        '\ndefs.append("marker").attr("id",arrowId).attr("viewBox","0 -4 8 8")'
        '.attr("refX",18).attr("markerWidth",6).attr("markerHeight",6)'
        '.attr("orient","auto")'
        '.append("path").attr("d","M0,-4L8,0L0,4").attr("fill","#475569");'
        '\nvar g=svg.append("g").attr("class","sg-root");'
        '\nvar link=g.append("g").selectAll("line")'
        '.data(_sgLinks).enter().append("line")'
        '.attr("stroke","#334155").attr("stroke-width",1.5)'
        '.attr("marker-end","url(#"+arrowId+")");'
        '\nvar node=g.append("g").selectAll("circle")'
        '.data(_sgNodes).enter().append("circle")'
        '.attr("r",function(d){return d.root?18:d.count>3?12:8;})'
        '.attr("fill",function(d){'
        'var c=_TYPE_COL_SG[d.type]||"#64748b";'
        'return c+"44";})'
        '.attr("stroke",function(d){return _TYPE_COL_SG[d.type]||"#64748b";})'
        '.attr("stroke-width",function(d){return d.root?3:1.5;})'
        '.style("cursor","pointer")'
        '.on("click",function(ev,d){'
        'var sb=document.getElementById("sgraph-sidebar");'
        'var det=document.getElementById("sgraph-node-detail");'
        '\nif(sb)sb.style.display="block";'
        '\nif(det)det.innerHTML='
        '"<div style=\\"font-weight:700;margin-bottom:6px;word-break:break-all\\">"+d.label+"</div>"'
        '+"<div style=\\"font-size:10px;color:var(--muted)\\">Type: "+d.type+"</div>"'
        '+"<div style=\\"font-size:10px;color:var(--muted)\\">Seen: "+(d.count||0)+" times</div>";'
        '});'
        '\nvar label=g.append("g").selectAll("text")'
        '.data(_sgNodes).enter().append("text")'
        '.text(function(d){return d.label;})'
        '.attr("font-size","9").attr("fill","#94a3b8")'
        '.attr("text-anchor","middle").attr("dy","22");'
        '\n_sgSim=d3.forceSimulation(_sgNodes)'
        '.force("link",d3.forceLink(_sgLinks).id(function(d){return d.id;}).distance(90))'
        '.force("charge",d3.forceManyBody().strength(-180))'
        '.force("center",d3.forceCenter(W/2,H/2))'
        '.force("collision",d3.forceCollide(22))'
        '.on("tick",function(){'
        'link.attr("x1",function(d){return d.source.x;})'
        '.attr("y1",function(d){return d.source.y;})'
        '.attr("x2",function(d){return d.target.x;})'
        '.attr("y2",function(d){return d.target.y;});'
        'node.attr("cx",function(d){return d.x;}).attr("cy",function(d){return d.y;});'
        'label.attr("x",function(d){return d.x;}).attr("y",function(d){return d.y;});'
        '});'
        '\n_sgZoom=d3.zoom().scaleExtent([0.2,5]).on("zoom",function(ev){'
        'g.attr("transform",ev.transform);});'
        '\nsvg.call(_sgZoom);'
        '\nnode.call(d3.drag()'
        '.on("start",function(ev,d){if(!ev.active)_sgSim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})'
        '.on("drag",function(ev,d){d.fx=ev.x;d.fy=ev.y;})'
        '.on("end",function(ev,d){if(!ev.active)_sgSim.alphaTarget(0);d.fx=null;d.fy=null;}));'
        '\n}'
        '\nfunction resetSGraphZoom(){'
        'if(_sgZoom&&document.getElementById("sgraph")){'
        'var svg=d3.select("#sgraph");'
        'svg.transition().duration(500).call(_sgZoom.transform,d3.zoomIdentity);'
        '}}'
    )

    # Plain (non-f) string - safe to contain raw JS { } without escaping
    _circuit_tooltip_js = '''

(function(){
  var _circuitCache = null;
  var _circuitCacheTs = 0;
  var _torStatusCache = null;
  var _modalEl      = null;

  
  function _initModal() {
    if (_modalEl) return;
    _modalEl = document.createElement('div');
    _modalEl.id = 'circuit-modal';
    _modalEl.style.cssText = [
      'display:none','position:fixed','inset:0','z-index:9000',
      'background:rgba(0,0,0,.65)','backdrop-filter:blur(3px)',
      'align-items:center','justify-content:center'
    ].join(';');
    var panel = document.createElement('div');
    panel.style.cssText = [
      'background:#0a1628','border:1px solid #1e3a5f',
      'border-radius:14px','padding:20px 22px',
      'min-width:340px','max-width:460px','width:90%',
      'box-shadow:0 12px 48px rgba(0,0,0,.8)',
      'font-family:monospace','font-size:11px','position:relative'
    ].join(';');
    var closeBtn = document.createElement('button');
    closeBtn.innerHTML = '✕';
    closeBtn.style.cssText = 'position:absolute;top:12px;right:14px;background:none;border:none;color:#475569;font-size:16px;cursor:pointer;line-height:1';
    closeBtn.onclick = _closeModal;
    var content = document.createElement('div');
    content.id  = 'circuit-modal-body';
    panel.appendChild(closeBtn);
    panel.appendChild(content);
    _modalEl.appendChild(panel);
    _modalEl.addEventListener('click', function(e){ if (e.target === _modalEl) _closeModal(); });
    document.addEventListener('keydown', function(e){ if (e.key === 'Escape') { _closeModal(); _closeHop(); } });
    document.body.appendChild(_modalEl);
  }

  function _closeModal() {
    if (_modalEl) { _modalEl.style.display = 'none'; _modalEl.style.flexDirection = ''; }
  }

  function _closeHop() {
    var p = document.getElementById('hop-popover');
    if (p) p.style.display = 'none';
  }

  
  function _renderNodes(nodes, exitIp) {
    var ROLE_COL = {Guard:'#22c55e', Middle:'#818cf8', Exit:'#ef4444'};
    var flow = [{label:'YOU', role:'Local', isLocal:true}]
               .concat(nodes || [])
               .concat([{label:'TARGET', role:'Server', isTarget:true}]);
    var h = '<div style="color:#475569;font-size:9px;letter-spacing:.8px;margin-bottom:12px;'
          + 'border-bottom:1px solid #1e293b;padding-bottom:8px">⧡ TOR CIRCUIT PATH</div>';
    flow.forEach(function(n, i){
      var col = n.isLocal ? '#6366f1' : n.isTarget ? '#f59e0b' : (ROLE_COL[n.role] || '#818cf8');
      var isLast = i === flow.length - 1;
      h += '<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:4px">';
      h += '<div style="display:flex;flex-direction:column;align-items:center;flex-shrink:0;padding-top:2px">';
      h += '<div style="width:24px;height:24px;border-radius:50%;border:2px solid '+col
         + ';background:'+col+'1a;display:flex;align-items:center;justify-content:center;'
         + 'color:'+col+';font-size:9px;font-weight:bold">'+(i+1)+'</div>';
      if (!isLast) h += '<div style="width:2px;height:16px;background:'+col+'55;margin:2px auto"></div>';
      h += '</div>';
      h += '<div style="flex:1;background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:6px 10px;margin-bottom:2px">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center">';
      h += '<span style="color:#f1f5f9;font-size:11px;font-weight:bold">'+(n.label||n.nickname||n.role||'?')+'</span>';
      h += '<span style="color:'+col+';font-size:9px;background:'+col+'1a;padding:2px 7px;border-radius:3px">'+(n.role||'')+'</span></div>';
      if (!n.isLocal && !n.isTarget) {
        var meta = [];
        if (n.ip)         meta.push('🖧 '+n.ip);
        if (n.country)    meta.push('🌍 '+n.country);
        if (n.latency_ms) meta.push('⏱ '+n.latency_ms+'ms');
        if (n.asn)        meta.push(n.asn);
        if (meta.length) h += '<div style="color:#64748b;font-size:10px;margin-top:3px">'+meta.join('  ')+'</div>';
      } else if (n.isLocal) {
        h += '<div style="color:#475569;font-size:10px;margin-top:2px">SOCKS5 127.0.0.1:9050 🔒 Encrypted</div>';
      } else if (n.isTarget && exitIp) {
        h += '<div style="color:#475569;font-size:10px;margin-top:2px">via exit '+exitIp+'</div>';
      }
      h += '</div></div>';
    });
    if (!nodes || nodes.length === 0)
      h += '<div style="color:#475569;font-size:10px;margin-top:6px;text-align:center;padding:10px">⚠ Circuit details unavailable - TOR may still be warming up</div>';
    h += '<div style="margin-top:12px;color:#334155;font-size:9px;text-align:center;border-top:1px solid #1e293b;padding-top:8px">Press Esc or click outside to close</div>';
    return h;
  }

  
  function _renderHopChain(srcIp, nodes, exitIp, destHost, reqUrl, viaTor) {
    var chips = [];
    var ROLE_COL = {Guard:'#22c55e', Middle:'#818cf8', Exit:'#ef4444'};

    if (!viaTor) {
      chips.push({label: srcIp||'YOU', color:'#6366f1', role:'Source', sub:'your machine'});
    }

    if (viaTor) {
      var hasNodes = nodes && nodes.length > 0;
      if (hasNodes) {
        nodes.forEach(function(n){
          var col = ROLE_COL[n.role] || '#818cf8';
          var parts = [];
          if (n.ip)          parts.push(n.ip);
          if (n.country && n.country !== '??') parts.push('🌍 '+n.country);
          if (n.latency_ms)  parts.push('⏱ '+n.latency_ms+'ms');
          var sub = parts.join('  ');
          chips.push({label: n.nickname||n.role||'?', color:col, role:n.role||'', sub:sub});
        });
        var lastNode = nodes[nodes.length-1];
        var eIpDisplay = exitIp || (lastNode && lastNode.role === 'Exit' ? lastNode.ip : '');
        if (eIpDisplay && (!lastNode || lastNode.ip !== eIpDisplay)) {
          chips.push({label: eIpDisplay, color:'#ef4444', role:'Exit IP', sub:''});
        }
      } else {
        chips.push({label:'Guard', color:'#22c55e', role:'Guard', sub:'resolving…'});
        chips.push({label:'Middle', color:'#818cf8', role:'Middle', sub:'resolving…'});
        chips.push({label: exitIp||'Exit', color:'#ef4444', role:'Exit', sub:exitIp||'resolving…'});
      }
    }

    
    var destLabel = destHost||'TARGET';
    try {
      var pu = new URL(reqUrl);
      var path = pu.pathname + (pu.search||'');
      if (path.length > 40) path = path.slice(0,37)+'…';
      destLabel = (pu.hostname||destHost) + (path !== '/' ? path : '');
    } catch(e) {}
    chips.push({label: destLabel, color:'#f59e0b', role:'Target', sub:''});

    
    var h = '<div style="display:flex;align-items:flex-start;flex-wrap:wrap;gap:6px">';
    chips.forEach(function(c, i){
      
      h += '<div style="display:flex;flex-direction:column;align-items:center;gap:3px">';
      h += '<div style="background:'+c.color+'18;border:1px solid '+c.color+'55;border-radius:6px;'
         + 'padding:4px 10px;font-size:11px;color:'+c.color+';font-weight:bold;white-space:nowrap">'
         + c.label + '</div>';
      h += '<div style="font-size:9px;color:#475569;text-align:center">' + c.role + '</div>';
      if (c.sub) h += '<div style="font-size:9px;color:#334155;text-align:center;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+c.sub+'</div>';
      h += '</div>';
      
      if (i < chips.length - 1) {
        var arrowColor = viaTor ? '#1e3a5f' : '#334155';
        h += '<div style="color:'+arrowColor+';font-size:14px;padding-top:4px;flex-shrink:0">──►</div>';
      }
    });
    h += '</div>';

    
    if (reqUrl) {
      var disp = reqUrl.length > 80 ? reqUrl.slice(0,77)+'…' : reqUrl;
      h += '<div style="margin-top:8px;padding:5px 8px;background:#0f172a;border-radius:4px;'
         + 'border:1px solid #1e293b;font-size:10px;color:#64748b;word-break:break-all">'
         + '🔗 ' + disp + '</div>';
    }
    return h;
  }

  
  function _getCircuit(cb) {
    var now = Date.now();
    if (_circuitCache && _circuitCache.nodes && _circuitCache.nodes.length > 0 && (now - _circuitCacheTs) < 30000) {
      cb(_circuitCache);
      return;
    }
    fetch('/api/tor/circuit').then(function(r){ return r.json(); })
      .then(function(d){ _circuitCache = d; _circuitCacheTs = Date.now(); cb(d); })
      .catch(function(){ cb({nodes:[], ok:false}); });
  }

  function _getTorStatus(cb) {
    if (_torStatusCache) { cb(_torStatusCache); return; }
    fetch('/api/tor/status').then(function(r){ return r.json(); })
      .then(function(d){ _torStatusCache = d; setTimeout(function(){ _torStatusCache=null; }, 15000); cb(d); })
      .catch(function(){ cb({}); });
  }

  
  window.updateTmonIpBar = function() {
    _getTorStatus(function(d){
      var srcEl  = document.getElementById('tmon-src-ip');
      var arrEl  = document.getElementById('tmon-arrow');
      var exitEl = document.getElementById('tmon-exit-ip');
      if (!srcEl) return;
      
      var firstRow = document.querySelector('.tlog-entry[data-src-ip]');
      var srcIp = firstRow ? firstRow.getAttribute('data-src-ip') : '…';
      srcEl.textContent = '🖧 ' + (srcIp||'…');

      if (d.enabled && d.status === 'connected') {
        arrEl.textContent  = ' ─⬡─► ';
        arrEl.style.color  = '#00ff9d';
        var exitIp = d.exit_ip || '';
        
        var torRows = document.querySelectorAll('.tlog-tor-row[data-exit-ip]');
        if (!exitIp && torRows.length)
          exitIp = torRows[torRows.length-1].getAttribute('data-exit-ip') || '';
        exitEl.textContent = exitIp ? '⬡ ' + exitIp + ' (Exit)' : '⬡ TOR (no exit IP yet)';
        exitEl.style.color = '#00ff9d';
      } else {
        arrEl.textContent  = ' ──► ';
        arrEl.style.color  = 'var(--muted)';
        exitEl.textContent = 'Direct';
        exitEl.style.color = 'var(--muted)';
      }
    });
  };

  
  window.showHopPath = function(btn) {
    var row    = btn.closest('.tlog-entry') || btn.parentElement;
    var viaTor = row.getAttribute('data-via-tor') === '1';
    var exitIp = row.getAttribute('data-exit-ip') || '';
    var srcIp  = row.getAttribute('data-src-ip') || '';
    var reqUrl = row.getAttribute('data-url') || '';
    
    var destSpan = row.querySelector('.tlog-dest');
    var destHost = destSpan ? destSpan.textContent.trim() : '';

    var pop  = document.getElementById('hop-popover');
    var body = document.getElementById('hop-popover-body');

    
    if (pop.style.display !== 'none' && pop._openRow === row) {
      pop.style.display = 'none';
      pop._openRow = null;
      return;
    }
    pop._openRow = row;

    var useTor = viaTor || (typeof _scanViaTor !== 'undefined' && _scanViaTor);
    if (useTor) {
      body.innerHTML = '<div style="color:#64748b;text-align:center;padding:6px">Loading TOR circuit…</div>';
      pop.style.display = 'block';
      _positionPop(pop, btn);
      _getCircuit(function(data){
        var nodes = data.nodes || [];
        var eIp   = exitIp || data.exit_ip || '';
        body.innerHTML = _renderHopChain(srcIp, nodes, eIp, destHost, reqUrl, true);
        _positionPop(pop, btn);
      });
    } else {
      body.innerHTML = _renderHopChain(srcIp, [], '', destHost, reqUrl, false);
      pop.style.display = 'block';
      _positionPop(pop, btn);
    }
  };

  function _positionPop(pop, btn) {
    var rect = btn.getBoundingClientRect();
    var pw   = pop.offsetWidth  || 360;
    var ph   = pop.offsetHeight || 120;
    var left = rect.left;
    var top  = rect.bottom + 8;
    
    if (left + pw > window.innerWidth - 12)  left = window.innerWidth - pw - 12;
    if (top  + ph > window.innerHeight - 12) top  = rect.top - ph - 8;
    if (left < 8) left = 8;
    pop.style.left = left + 'px';
    pop.style.top  = top  + 'px';
  }

  
  document.addEventListener('click', function(e){
    var pop = document.getElementById('hop-popover');
    if (pop && pop.style.display !== 'none') {
      if (!pop.contains(e.target) && !e.target.classList.contains('hop-path-btn'))
        pop.style.display = 'none';
    }
  });

  
  window._invalidateTorCircuitCache = function() {
    _circuitCache   = null;
    _torStatusCache = null;
  };

  
  window.openCircuitPanel = function() {
    _initModal();
    var body = document.getElementById('circuit-modal-body');
    body.innerHTML = '<div style="color:#64748b;text-align:center;padding:20px">Loading circuit…</div>';
    _modalEl.style.display = 'flex';
    _getCircuit(function(data){
      var exitIp = '';
      var rows = document.querySelectorAll('.tlog-tor-row[data-exit-ip]');
      if (rows.length) exitIp = rows[rows.length-1].getAttribute('data-exit-ip') || '';
      body.innerHTML = _renderNodes(data.nodes, exitIp || data.exit_ip);
    });
  };

  
  window.attachCircuitTooltips = function() {
    var hasTor = document.querySelectorAll('.tlog-tor-row').length > 0;
    var globalTor = (typeof _scanViaTor !== 'undefined' && _scanViaTor);
    var btn = document.getElementById('circuit-btn');
    if (btn) btn.style.display = (hasTor || globalTor) ? 'inline-block' : 'none';
  };

  document.addEventListener('DOMContentLoaded', function(){
    window.attachCircuitTooltips();
    window.updateTmonIpBar();
  });
})();
'''

    html = f"""
<div class="flex justify-between items-center mb-3">
  <div>
    <h2 style="font-size:18px;font-weight:700;color:var(--text)">{target_esc}</h2>
    <div style="font-size:12px;color:var(--muted);margin-top:2px">{scan_name_esc} · {scan.get('scan_type','osint').upper()}</div>
  </div>
  <div class="flex gap-2">
    {'<button onclick="stopScan()" class="btn btn-danger btn-sm">⏹ Stop</button>' if running else ''}
    {'<button onclick="startScan()" class="btn btn-primary btn-sm">▶ Start</button>' if status in ('pending','saved','stopped','failed') else ''}
    {'<a href="/scan/'+scan_id+'/rescan" class="btn btn-ghost btn-sm">🔁 Rescan</a>' if status in ('completed','stopped','failed') else ''}
    {'<a href="/scan/'+scan_id+'/edit" class="btn btn-ghost btn-sm">✏️ Edit</a>' if not running else ''}
    <a href="/report/scan/{scan_id}" class="btn btn-ghost btn-sm">📄 Report</a>
    <button onclick="deleteScanFromView('{scan_id}')" class="btn btn-danger btn-sm">🗑 Delete</button>
  </div>
</div>

<div class="card">
  <div class="card-body" style="padding:14px">
    <div class="flex justify-between items-center mb-2">
      <div class="flex items-center gap-2">
        <span style="width:10px;height:10px;border-radius:50%;background:{status_color};
          display:inline-block{'animation:pulse 2s infinite' if running else ''}"></span>
        <span style="font-weight:600;color:{status_color}">{status.upper()}</span>
        {f'<span class="text-muted text-sm">{curmod_esc}</span>' if curmod else ''}
      </div>
      <span class="mono text-sm" style="color:var(--muted)">{prog}%</span>
    </div>
    <div class="progress-bar"><div class="progress-fill" id="prog-fill" style="width:{prog}%"></div></div>
    <div style="font-size:11px;color:var(--muted);margin-top:6px">{mods_str}</div>
  </div>
</div>

<div style="margin-bottom:12px">{sev_pills}</div>

<div class="tabs">
  <div class="tab active" id="tab-btn-findings" onclick="showTab('findings')">🎯 Findings ({len(findings)})</div>
  <div class="tab" id="tab-btn-tasks" onclick="showTab('tasks')">🗂 Tasks ({len(tasks)})</div>
  <div class="tab" id="tab-btn-traffic" onclick="showTab('traffic')">📡 Traffic Log ({len(traffic)})</div>
  <div class="tab" id="tab-btn-images" onclick="showTab('images')">🖼️ Found Images</div>
  <div class="tab" id="tab-btn-graph" onclick="showTab('graph')">🕸️ Entity Graph ({_scan_entity_count})</div>
</div>

<div id="tab-findings" class="tab-pane active" style="display:block">
<div class="card">
  <div class="card-header">
    <span class="card-title">Findings <span id="find-count-badge"
      style="background:var(--bg3);border:1px solid var(--border);border-radius:10px;
             padding:1px 8px;font-size:11px;color:var(--muted);font-weight:400;margin-left:6px">
      {len(findings)}
    </span></span>
    <div class="flex gap-2" style="align-items:center">
      <input type="text" id="find-global" placeholder="🔍 Search all columns…"
             style="width:200px;padding:5px 10px;font-size:12px;border-radius:6px"
             oninput="applyFindingFilters()">
      <button onclick="clearFindingFilters()" class="btn btn-ghost btn-sm" title="Clear all filters">✕ Clear</button>
      <a href="/api/scan/{scan_id}/findings?fmt=csv" class="btn btn-ghost btn-sm">⬇ CSV</a>
    </div>
  </div>
  <div style="overflow-x:auto">
  <table id="findings-table">
    <thead>
      <tr>
        <th>Severity</th><th>Module</th><th>Finding</th><th>Evidence</th>
        <th style="white-space:nowrap">Time
          <span style="font-size:9px;font-weight:400;color:var(--muted)"> · click row for PoC</span>
        </th>
      </tr>
      <tr id="find-filter-row" style="background:var(--bg3)">
        <td style="padding:4px 6px">
          <select id="ff-sev" onchange="applyFindingFilters()"
            style="width:100%;padding:3px 5px;font-size:11px;background:var(--bg);
                   border:1px solid var(--border);border-radius:4px;color:var(--text)">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </td>
        <td style="padding:4px 6px">
          <input id="ff-mod" placeholder="Module…" oninput="applyFindingFilters()"
            style="width:100%;padding:3px 5px;font-size:11px;background:var(--bg);
                   border:1px solid var(--border);border-radius:4px;color:var(--text)">
        </td>
        <td style="padding:4px 6px">
          <input id="ff-title" placeholder="Title / URL…" oninput="applyFindingFilters()"
            style="width:100%;padding:3px 5px;font-size:11px;background:var(--bg);
                   border:1px solid var(--border);border-radius:4px;color:var(--text)">
        </td>
        <td style="padding:4px 6px">
          <input id="ff-ev" placeholder="Evidence…" oninput="applyFindingFilters()"
            style="width:100%;padding:3px 5px;font-size:11px;background:var(--bg);
                   border:1px solid var(--border);border-radius:4px;color:var(--text)">
        </td>
        <td style="padding:4px 6px">
          <input id="ff-time" placeholder="Time…" oninput="applyFindingFilters()"
            style="width:100%;padding:3px 5px;font-size:11px;background:var(--bg);
                   border:1px solid var(--border);border-radius:4px;color:var(--text)">
        </td>
      </tr>
    </thead>
    <tbody id="findings-body">{findings_html}</tbody>
  </table>
  </div>
</div>
</div>

<div id="tab-tasks" class="tab-pane" style="display:none">
<div class="card">
  <div class="card-header" style="flex-wrap:wrap;gap:6px">
    <span class="card-title">🗂 Task Activity Log</span>
    <div class="flex items-center gap-2">
      <span style="font-size:10px;color:var(--muted)">Real-time module activity · click row for detail</span>
      {'<button onclick="skipModule()" style="font-size:11px;padding:3px 10px;border-radius:6px;border:1px solid #ffad00;background:transparent;color:#ffad00;cursor:pointer">⏭ Skip Current Module</button>' if running else ''}
      {'<button onclick="stopScan()" style="font-size:11px;padding:3px 10px;border-radius:6px;border:1px solid #ff3860;background:transparent;color:#ff3860;cursor:pointer">⏹ Stop Scan</button>' if running else ''}
      {'<button onclick="startScan()" style="font-size:11px;padding:3px 10px;border-radius:6px;border:1px solid var(--primary);background:transparent;color:var(--primary);cursor:pointer">▶ Resume</button>' if status in ("stopped","paused","failed") else ''}
    </div>
  </div>
  <div class="card-body" style="padding:0">
    <div class="traffic-log" id="task-log">
      {task_rows_html}
    </div>
  </div>
</div>
</div>

<div id="tab-traffic" class="tab-pane" style="display:none">
<div class="card">
  <div class="card-header" style="flex-wrap:wrap;gap:6px">
    <span class="card-title">📡 Traffic Monitor</span>
    <div class="flex items-center gap-2" style="flex-wrap:wrap">
      <!-- Live IP status bar -->
      <div id="tmon-ip-bar" style="font-size:10px;font-family:monospace;color:var(--muted);
           background:var(--bg3);border:1px solid var(--border);border-radius:5px;
           padding:3px 8px;display:flex;align-items:center;gap:6px">
        <span id="tmon-src-ip" style="color:#818cf8">🖧 …</span>
        <span id="tmon-arrow" style="color:var(--muted)">──►</span>
        <span id="tmon-exit-ip" style="color:var(--muted)">Direct</span>
      </div>
      <button onclick="openCircuitPanel()" id="circuit-btn"
        style="display:none;font-size:11px;padding:3px 10px;border-radius:12px;
               background:linear-gradient(135deg,#1e3a5f,#0f2744);
               border:1px solid #2563eb;color:#60a5fa;cursor:pointer;
               font-family:monospace;letter-spacing:.3px"
        title="View TOR circuit path">🔀 View Circuit</button>
    </div>
  </div>
  <div class="card-body" style="padding:0">
    <div class="traffic-log" id="traffic-log">{tlog_html}</div>
  </div>
</div>
</div>

<div id="tab-images" class="tab-pane" style="display:none">
<div class="card">
  <div class="card-header">
    <span class="card-title">🖼️ Found Images</span>
    <span style="font-size:11px;color:var(--muted)">Matched images from reverse image search</span>
  </div>
  <div class="card-body">
    {_scan_images_html}
  </div>
</div>
</div>

<div id="tab-graph" class="tab-pane" style="display:none">
<div class="card">
  <div class="card-header">
    <span class="card-title">🕸️ Entity Graph</span>
    <div style="display:flex;align-items:center;gap:10px">
      <span id="sgraph-count" style="font-size:11px;color:var(--muted)">{_scan_entity_count} nodes · {_scan_entity_edge_count} edges</span>
      <button onclick="resetSGraphZoom()" class="btn btn-ghost btn-sm" style="font-size:10px">↺ Reset</button>
    </div>
  </div>
  <div class="card-body" style="padding:0;position:relative">
    <div style="display:flex;height:520px">
      <div id="sgraph-svg-wrap" style="flex:1;position:relative;overflow:hidden">
        <svg id="sgraph" width="100%" height="100%"></svg>
      </div>
      <div id="sgraph-sidebar" style="display:none;width:220px;border-left:1px solid var(--border);
           padding:14px;font-size:12px;overflow-y:auto;background:var(--bg2)">
        <div style="font-size:10px;color:var(--muted);letter-spacing:.6px;text-transform:uppercase;
                    margin-bottom:8px">Selected Node</div>
        <div id="sgraph-node-detail"></div>
      </div>
    </div>
  </div>
</div>
</div>

<!-- Hop path popover - OUTSIDE all tab panes so position:fixed works even when traffic tab is hidden -->
<div id="hop-popover" style="display:none;position:fixed;z-index:8000;
     background:#0a1628;border:1px solid #1e3a5f;border-radius:10px;
     padding:14px 16px;max-width:90vw;box-shadow:0 8px 32px rgba(0,0,0,.8);
     font-family:monospace;font-size:11px;min-width:320px">
  <div style="display:flex;justify-content:space-between;align-items:center;
              margin-bottom:10px;color:#475569;font-size:9px;letter-spacing:.8px">
    <span>⧡ HOP PATH</span>
    <button onclick="document.getElementById('hop-popover').style.display='none'"
      style="background:none;border:none;color:#475569;cursor:pointer;font-size:14px;line-height:1">✕</button>
  </div>
  <div id="hop-popover-body"></div>
</div>

{_d3_script_tag}
<script>
var _scanViaTor = {scan_use_tor};
function showTab(name) {{
  ['findings','tasks','traffic','images','graph'].forEach(function(n) {{
    var btn  = document.getElementById('tab-btn-' + n);
    var pane = document.getElementById('tab-' + n);
    var sel  = (n === name);
    if (btn)  btn.className  = sel ? 'tab active' : 'tab';
    if (pane) pane.style.display = sel ? 'block' : 'none';
  }});
  if (name === 'graph') initSGraph();
}}
function skipModule() {{
  fetch('/api/scan/{scan_id}/skip_module', {{method:'POST'}})
    .then(r=>r.json()).then(function(d){{ console.log('Skip:', d.message); }});
}}
function applyFindingFilters() {{
  var global  = (document.getElementById('find-global')  ||{{value:''}}).value.toLowerCase().trim();
  var fSev    = (document.getElementById('ff-sev')       ||{{value:''}}).value.toLowerCase().trim();
  var fMod    = (document.getElementById('ff-mod')       ||{{value:''}}).value.toLowerCase().trim();
  var fTitle  = (document.getElementById('ff-title')     ||{{value:''}}).value.toLowerCase().trim();
  var fEv     = (document.getElementById('ff-ev')        ||{{value:''}}).value.toLowerCase().trim();
  var fTime   = (document.getElementById('ff-time')      ||{{value:''}}).value.toLowerCase().trim();
  var visible = 0;
  document.querySelectorAll('#findings-body tr[data-fid]').forEach(function(tr) {{
    var search = (tr.getAttribute('data-search')||'').toLowerCase();
    var sev    = (tr.getAttribute('data-sev')   ||'').toLowerCase();
    var mod    = (tr.getAttribute('data-mod')   ||'').toLowerCase();
    var ev     = (tr.getAttribute('data-ev')    ||'').toLowerCase();
    var time   = (tr.getAttribute('data-time')  ||'').toLowerCase();
    var ok = true;
    if (global) {{
      var terms = global.split(/[ \t]+/);
      ok = terms.every(function(t){{ return search.includes(t); }});
    }}
    if (ok && fSev   && !sev.includes(fSev))   ok = false;
    if (ok && fMod   && !mod.includes(fMod))   ok = false;
    if (ok && fTitle && !search.includes(fTitle)) ok = false;
    if (ok && fEv    && !ev.includes(fEv))     ok = false;
    if (ok && fTime  && !time.includes(fTime)) ok = false;
    tr.style.display = ok ? '' : 'none';
    var fid   = tr.getAttribute('data-fid');
    var pocTr = fid ? document.getElementById('poc-'+fid) : null;
    if (pocTr && !ok) pocTr.style.display = 'none';
    if (ok) visible++;
  }});
  var badge = document.getElementById('find-count-badge');
  if (badge) badge.textContent = visible;
}}
function clearFindingFilters() {{
  ['find-global','ff-mod','ff-title','ff-ev','ff-time'].forEach(function(id){{
    var el = document.getElementById(id);
    if (el) el.value = '';
  }});
  var sel = document.getElementById('ff-sev');
  if (sel) sel.value = '';
  applyFindingFilters();
}}
function filterFindings(q) {{
  var el = document.getElementById('find-global');
  if (el) el.value = q;
  applyFindingFilters();
}}
function togglePoc(fid) {{
  var row = document.getElementById('poc-' + fid);
  if (!row) return;
  var open = row.style.display !== 'none';
  document.querySelectorAll('[id^="poc-"]').forEach(function(r) {{
    r.style.display = 'none';
  }});
  if (!open) row.style.display = '';
}}
function takeScreenshot(fid, url) {{
  var btn = document.getElementById('ss-btn-'+fid);
  var res = document.getElementById('ss-result-'+fid);
  if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Capturing…'; }}
  fetch('/api/finding/'+fid+'/screenshot', {{method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{url: url}})
  }}).then(function(r){{ return r.json(); }}).then(function(d){{
    if (btn) btn.style.display = 'none';
    if (res) {{
      if (d.ok && d.thumbnail) {{
        /* Bake d.id directly into the onclick URL - onclick attr runs in global
           scope so referencing the closure variable d.id would fail silently. */
        var ssUrl = '/api/screenshot/' + d.id;
        res.innerHTML = '<div style="border:1px solid var(--border);border-radius:6px;overflow:hidden;cursor:pointer;display:inline-block;max-width:100%" onclick="window.open(\\'' + ssUrl + '\\',\\'_blank\\')">'
          + '<img src="data:image/png;base64,' + d.thumbnail + '" style="max-width:100%;max-height:300px;display:block" loading="lazy">'
          + '<div style="font-size:9px;text-align:center;padding:3px;color:var(--muted)">🔍 Click for full size</div></div>';
      }} else {{
        res.innerHTML = '<span style="color:var(--danger);font-size:11px">⚠ ' + (d.error||'Screenshot failed') + '</span>';
        if (btn) {{ btn.disabled = false; btn.textContent = '📸 Retry'; }}
      }}
    }}
  }}).catch(function(){{
    if (btn) {{ btn.disabled = false; btn.textContent = '📸 Retry'; }}
    if (res) res.innerHTML = '<span style="color:var(--danger);font-size:11px">⚠ Network error</span>';
  }});
}}
function captureUrlSS(url, containerId, btn, scanId) {{
  if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Capturing…'; }}
  fetch('/api/screenshot/capture', {{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{url: url, scan_id: scanId}})
  }}).then(function(r){{ return r.json(); }}).then(function(d){{
    var el = document.getElementById(containerId);
    if (!el) return;
    if (d.ok && d.thumbnail) {{
      var ssUrl = '/api/screenshot/' + d.screenshot_id;
      el.innerHTML = '<div style="border:1px solid var(--border);border-radius:5px;'
        + 'overflow:hidden;cursor:pointer;display:inline-block;max-width:100%"'
        + ' onclick="window.open(\\'' + ssUrl + '\\',\\'_blank\\')">'
        + '<img src="data:image/png;base64,' + d.thumbnail + '"'
        + ' style="max-width:100%;max-height:220px;display:block" loading="lazy">'
        + '<div style="font-size:9px;text-align:center;padding:3px;color:var(--muted)">'
        + '🔍 Click for full size</div></div>';
      if (btn) btn.style.display = 'none';
    }} else {{
      el.innerHTML = '<span style="color:var(--danger);font-size:10px">⚠ '
        + (d.error||'Screenshot failed') + '</span>';
      if (btn) {{ btn.disabled = false; btn.textContent = '📸 Retry'; }}
    }}
  }}).catch(function(){{
    if (btn) {{ btn.disabled = false; btn.textContent = '📸 Retry'; }}
    var el = document.getElementById(containerId);
    if (el) el.innerHTML = '<span style="color:var(--danger);font-size:10px">⚠ Network error</span>';
  }});
}}
function stopScan() {{
  fetch('/api/scan/{scan_id}/stop', {{method:'POST'}})
    .then(()=>location.reload());
}}
function startScan() {{
  fetch('/api/scan/{scan_id}/start', {{method:'POST'}})
    .then(()=>setTimeout(()=>location.reload(),500));
}}
function deleteScanFromView(sid) {{
  var msg = {"'Permanently delete this scan and ALL findings? This cannot be undone.'" if _is_admin() else "'Delete this scan? You can restore it later from the investigation page.'"};
  if (!confirm(msg)) return;
  fetch('/api/scan/' + sid + '/delete', {{method:'POST'}})
    .then(r => r.json()).then(function(d) {{
      if (d.ok) history.back();
    }});
}}
{'''
var pollTimer = setInterval(function() {
  fetch('/api/scan/''' + scan_id + '''/status')
    .then(r=>r.json()).then(d=>{
      document.getElementById('prog-fill').style.width = d.progress + '%';
      if (d.status !== 'running') { clearInterval(pollTimer); setTimeout(()=>location.reload(),1000); }
      fetch('/api/scan/''' + scan_id + '''/traffic').then(r=>r.json()).then(td=>{
        var logEl = document.getElementById('traffic-log');
        if (td.entries && td.entries.length) {
          logEl.innerHTML = td.entries.map(t => {
            var viaTor = !!(t.via_tor) || !!_scanViaTor;
            var exitIp = (t.tor_exit_ip||'');
            var srcIp  = (t.source_ip||'?');
            var url    = (t.url||'');
            var sc     = t.status_code < 300 ? '#69f0ae' : (t.status_code < 400 ? '#ffad00' : '#ff3860');
            var arr    = viaTor ? ' ─TOR─► ' : ' ──────► ';
            var torCls = viaTor ? ' tlog-tor-row' : '';
            var dispPath = '';
            try {
              var pu = new URL(url);
              dispPath = pu.pathname + (pu.search || '');
              if (dispPath.length > 50) dispPath = dispPath.slice(0,47) + '…';
            } catch(e) {}
            var torBadge = viaTor ? '<span style="color:#00ff9d;font-size:9px;margin-left:4px">⬡TOR'+(exitIp?'→'+exitIp.slice(0,15):'')+'</span>' : '';
            var hopBtn = '<button class="hop-path-btn" onclick="showHopPath(this)" title="Show TOR hop path"'
              + ' style="font-size:9px;padding:1px 5px;border-radius:3px;cursor:pointer;'
              + 'border:1px solid '+(viaTor?'#1e3a5f':'var(--border)')+';'
              + 'background:'+(viaTor?'#0a1628':'var(--bg3)')+';'
              + 'color:'+(viaTor?'#60a5fa':'var(--muted)')+';margin-right:4px;'
              + 'font-family:monospace;flex-shrink:0">'+(viaTor?'⬡⟶':'⟶')+'</button>';
            return '<div class="tlog-entry'+torCls+'"'
              + ' data-via-tor="'+(viaTor?'1':'0')+'"'
              + ' data-exit-ip="'+exitIp+'"'
              + ' data-src-ip="'+srcIp+'"'
              + ' data-url="'+url.slice(0,300).replace(/"/g,'&quot;')+'">'
              + hopBtn
              + '<span class="tlog-ts">'+(t.ts||'').slice(-8,-3)+'</span>'
              + '<span class="tlog-module">['+(t.module||'?').slice(0,8)+']</span>'
              + '<span class="tlog-src">'+srcIp+'</span>'
              + '<span class="tlog-arrow" style="color:'+(viaTor?'#00ff9d':'var(--muted)')+'">'+arr+'</span>'
              + '<span class="tlog-dest">'+(t.dest_host||'?')+':'+(t.dest_port||443)+'</span>'
              + (dispPath ? '<span class="tlog-path" style="color:#475569;font-size:9px;margin-left:2px">'+dispPath+'</span>' : '')
              + torBadge
              + '<span class="tlog-method" style="margin-left:4px">'+(t.method||'GET')+'</span>'
              + '<span class="tlog-status" style="color:'+sc+'">'+t.status_code+'</span>'
              + '<span class="tlog-dur">'+(t.duration_ms||0)+'ms</span>'
              + '</div>';
          }).join('');
          if (logEl.scrollTop < 120) { logEl.scrollTop = 0; }
          attachCircuitTooltips();
          updateTmonIpBar();
        }
      });
      fetch('/api/scan/''' + scan_id + '''/tasks').then(r=>r.json()).then(td=>{
        var taskEl = document.getElementById('task-log');
        if (!taskEl || !td.tasks) return;
        var STATUS_ICON = {
          running: '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#818cf8;animation:pulse 1.5s infinite;flex-shrink:0"></span>',
          done:    '<span style="color:#69f0ae;flex-shrink:0;font-size:13px">✓</span>',
          skipped: '<span style="color:#ffad00;flex-shrink:0;font-size:13px">⏭</span>',
          error:   '<span style="color:#ff3860;flex-shrink:0;font-size:13px">✗</span>',
        };
        taskEl.innerHTML = td.tasks.map(function(t) {
          var st       = t.status || 'running';
          var stIcon   = STATUS_ICON[st] || STATUS_ICON.running;
          var isRunning= (st === 'running');
          var isChild  = !!(t.parent_id);
          var detail   = (t.detail||'').slice(0,140);
          var duration = '';
          if (t.started_at) {
            var ms = Math.round((new Date(t.completed_at||new Date())-new Date(t.started_at)));
            if (ms >= 0) duration = ms < 3000 ? ms+'ms' : Math.round(ms/1000)+'s';
          }
          var durSpan = duration ? '<span style="color:var(--muted);font-size:9px;margin-left:6px">'+duration+'</span>' : '';
          if (isChild) {
            var rowBg = isRunning ? 'rgba(129,140,248,0.04)' : '';
            return '<div class="tlog-entry" style="gap:6px;align-items:flex-start;padding:5px 12px 5px 32px;background:'+rowBg+'">'
              + '<span style="color:#1e3a5f;margin-right:4px;font-size:11px">└─</span>'
              + '<div style="flex:1;min-width:0">'
              + '<div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap">'
              + stIcon
              + '<span style="font-size:11px;color:var(--fg)">'+(t.task||'')+'</span>'
              + durSpan
              + '</div>'
              + (detail ? '<div style="font-size:10px;color:var(--muted);margin-top:1px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+detail+'</div>' : '')
              + '</div>'
              + '</div>';
          } else {
            var rowBg = isRunning ? 'rgba(129,140,248,0.07)' : '';
            var btnHtml = (isRunning)
              ? '<button onclick="skipModule()" style="font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;border:1px solid #ffad00;background:#0a1628;color:#ffad00" title="Skip current module">⏭ Skip</button>'
              + '<button onclick="stopScan()" style="font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;border:1px solid #ff3860;background:#0a1628;color:#ff3860" title="Stop scan">⏹ Stop</button>'
              : '';
            return '<div class="tlog-entry" style="gap:8px;align-items:flex-start;padding:8px 12px;background:'+rowBg+';border-top:1px solid var(--border)">'
              + '<span style="font-size:15px;flex-shrink:0">'+(t.module_icon||'🔌')+'</span>'
              + '<div style="flex:1;min-width:0">'
              + '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
              + stIcon
              + '<span style="font-weight:600;font-size:12px">'+(t.module_label||t.module||'')+'</span>'
              + '<span style="color:var(--muted);font-size:11px">·</span>'
              + '<span style="font-size:11px;color:var(--fg)">'+(t.task||'')+'</span>'
              + durSpan
              + '</div>'
              + (detail ? '<div style="font-size:10px;color:var(--muted);margin-top:2px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+detail+'</div>' : '')
              + '</div>'
              + (btnHtml ? '<div style="display:flex;gap:4px;flex-shrink:0;align-items:center">'+btnHtml+'</div>' : '')
              + '</div>';
          }
        }).join('');
        if (taskEl.scrollHeight - taskEl.scrollTop - taskEl.clientHeight < 80) {
          taskEl.scrollTop = taskEl.scrollHeight;
        }
      });
    });
}, 3000);
''' if running else ''}
{_circuit_tooltip_js}
{_sgraph_js}
</script>"""
    return _base(f"Scan: {scan['target']}", html, "investigations")

# ═════════════════════════════════════════════════════════════════════════════
# PATTERNS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/patterns", methods=["GET","POST"])
@require_login
def patterns_page():
    if not _analyst_can("patterns"):
        return redirect(url_for("dashboard"))
    err = msg = ""
    if request.method == "POST":
        action = request.form.get("action","add")
        if action == "add":
            name     = request.form.get("name","").strip()
            pattern  = request.form.get("pattern","").strip()
            category = request.form.get("category","custom")
            severity = request.form.get("severity","medium")
            desc     = request.form.get("description","")
            tags_raw = request.form.get("tags","")
            tags     = [t.strip() for t in tags_raw.split(",") if t.strip()]
            if not name or not pattern:
                err = "Name and pattern are required"
            else:
                ok = patterns.add_pattern(name, pattern, category, severity, desc, tags, "user")
                if ok:
                    _audit("add_pattern","pattern","",name)
                    msg = f"Pattern '{name}' added successfully"
                else:
                    err = f"Pattern '{name}' already exists or regex is invalid"
        elif action == "delete":
            pid = request.form.get("pattern_id","")
            db.exec("DELETE FROM osint_patterns WHERE id=? AND source!='builtin'",(pid,))
            msg = "Pattern deleted"
        elif action == "toggle":
            pid = request.form.get("pattern_id","")
            row = db.one("SELECT enabled FROM osint_patterns WHERE id=?",(pid,))
            if row:
                db.exec("UPDATE osint_patterns SET enabled=? WHERE id=?",
                        (0 if row["enabled"] else 1, pid))
                patterns.reload()

    all_pats  = db.rows("SELECT * FROM osint_patterns ORDER BY category,name")
    categories= sorted(set(p["category"] for p in all_pats))

    # Category filter
    cat_filter = request.args.get("cat","")
    if cat_filter:
        all_pats = [p for p in all_pats if p["category"] == cat_filter]

    cat_buttons = '<a href="/patterns" class="btn btn-ghost btn-sm" style="' + ('background:var(--bg4)' if not cat_filter else '') + '">All</a> '
    for c in categories:
        active = 'background:var(--primary-d);color:#fff' if cat_filter==c else ''
        cat_buttons += f'<a href="/patterns?cat={c}" class="btn btn-ghost btn-sm" style="{active}">{c}</a> '

    rows_html = ""
    for p in all_pats:
        enabled  = p.get("enabled",1)
        src_badge= {"builtin":"badge-info","user":"badge-low","ai":"badge-blue"}.get(p.get("source","user"),"badge-blue")
        rows_html += f"""<tr style="opacity:{'1' if enabled else '0.45'}">
          <td style="font-weight:500;font-size:13px">{p['name']}</td>
          <td><span class="badge badge-blue">{p['category']}</span></td>
          <td class="mono" style="font-size:10px;color:var(--warning);max-width:220px;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{p['pattern']}</td>
          <td><span class="badge badge-{p['severity']}">{p['severity']}</span></td>
          <td><span class="badge {src_badge}">{p.get('source','user')}</span></td>
          <td class="mono text-sm">{p.get('hit_count',0)}</td>
          <td>
            <form method="POST" style="display:inline">
              <input type="hidden" name="action" value="toggle">
              <input type="hidden" name="pattern_id" value="{p['id']}">
              <button class="btn btn-ghost btn-sm">{'Disable' if enabled else 'Enable'}</button>
            </form>
            {f'''<form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="pattern_id" value="{p['id']}">
              <button class="btn btn-danger btn-sm">Del</button>
            </form>''' if p.get('source') != 'builtin' else ''}
          </td>
        </tr>"""
    if not rows_html:
        rows_html = '<tr><td colspan=7 style="text-align:center;padding:20px;color:var(--muted)">No patterns found</td></tr>'

    html = f"""
{'<div class="alert alert-danger">'+err+'</div>' if err else ''}
{'<div class="alert alert-success">'+msg+'</div>' if msg else ''}
<div class="grid2" style="gap:20px;align-items:start">
  <div class="card">
    <div class="card-header">
      <span class="card-title">➕ Add Pattern</span>
    </div>
    <div class="card-body">
    <form method="POST">
      <input type="hidden" name="action" value="add">
      <div class="form-group"><label>Name *</label>
        <input type="text" name="name" placeholder="AWS Secret Key v2" required></div>
      <div class="form-group"><label>Regex Pattern *</label>
        <input type="text" name="pattern" id="pat-input" placeholder="(?i)aws.{{0,20}}secret" required>
        <div id="pat-test-result" style="margin-top:4px;font-size:11px;font-family:var(--mono)"></div>
      </div>
      <div class="form-group"><label>Test Text</label>
        <input type="text" id="pat-test-text" placeholder="Paste sample to test pattern against...">
      </div>
      <div class="form-row">
        <div class="form-group"><label>Category</label>
          <select name="category">
            {''.join(f'<option value="{c}">{c}</option>' for c in ['secrets','git-exposure','file-exposure','personal-info','cloud','infrastructure','technology','recon','social','custom'])}
          </select>
        </div>
        <div class="form-group"><label>Severity</label>
          <select name="severity">
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium" selected>medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
      </div>
      <div class="form-group"><label>Description</label>
        <input type="text" name="description" placeholder="What does this pattern detect?"></div>
      <div class="form-group"><label>Tags (comma-separated)</label>
        <input type="text" name="tags" placeholder="aws, secret, api-key"></div>
      <button class="btn btn-primary">Add Pattern</button>
    </form>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <span class="card-title">🧩 Pattern Library ({len(all_pats)})</span>
      <div style="display:flex;gap:4px;flex-wrap:wrap">{cat_buttons}</div>
    </div>
    <div class="card-body" style="padding:0">
      <div style="max-height:600px;overflow-y:auto">
      <table>
        <thead><tr><th>Name</th><th>Category</th><th>Pattern</th><th>Severity</th><th>Source</th><th>Hits</th><th></th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      </div>
    </div>
  </div>
</div>
<script>
var patInput = document.getElementById('pat-input');
var testText = document.getElementById('pat-test-text');
var result   = document.getElementById('pat-test-result');
function testPattern() {{
  var pat = patInput.value, txt = testText.value;
  if (!pat || !txt) {{ result.textContent=''; return; }}
  try {{
    var re = new RegExp(pat, 'gi');
    var m  = txt.match(re);
    if (m) {{
      result.style.color = '#69f0ae';
      result.textContent = '✓ ' + m.length + ' match(es): ' + m.slice(0,3).join(', ');
    }} else {{
      result.style.color = '#ff3860';
      result.textContent = '✗ No match';
    }}
  }} catch(e) {{
    result.style.color = '#ffad00';
    result.textContent = '⚠ Invalid regex: ' + e.message;
  }}
}}
patInput.addEventListener('input', testPattern);
testText.addEventListener('input', testPattern);
</script>"""
    return _base(f"Patterns ({len(all_pats)})", html, "patterns")

# ═════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/settings", methods=["GET","POST"])
@require_admin
def settings():
    msg = ""
    if request.method == "POST":
        for k in ["tor_enabled","tor_socks_host","tor_socks_port",
                  "anthropic_key","openai_key","github_token","shodan_key",
                  "virustotal_key","hunter_key","hibp_key","otx_key","abuseipdb_key"]:
            if k == "tor_enabled":
                _save_setting(k, "1" if request.form.get(k) else "0")
            else:
                v = request.form.get(k,"").strip()
                if v:
                    _save_setting(k, v)
        # Save SMTP settings
        _save_setting("sys_email_enabled", "1" if request.form.get("sys_email_enabled") == "1" else "0")
        mode_val = request.form.get("sys_smtp_mode", "mailhog")
        if mode_val not in ("mailhog", "custom"):
            mode_val = "mailhog"
        _save_setting("sys_smtp_mode", mode_val)
        for k in ["sys_smtp_host","sys_smtp_port","sys_smtp_user","sys_smtp_from",
                  "sys_smtp_mailhog_host","sys_smtp_mailhog_port"]:
            _save_setting(k, request.form.get(k,"").strip())
        smtp_pass = request.form.get("sys_smtp_pass","").strip()
        if smtp_pass:  # only overwrite password if non-empty
            _save_setting("sys_smtp_pass", smtp_pass)
        _save_setting("sys_smtp_tls", "1" if request.form.get("sys_smtp_tls") else "0")
        _save_setting("sys_smtp_ssl", "1" if request.form.get("sys_smtp_ssl") else "0")
        # Save theme
        chosen_theme = request.form.get("theme", "default")
        if chosen_theme in _THEMES:
            _save_setting("theme", chosen_theme)
        _audit("save_settings")
        msg = "Settings saved"

    s = {k: _get_setting(k) for k in [
        "tor_enabled","tor_socks_host","tor_socks_port",
        "anthropic_key","openai_key","github_token","shodan_key",
        "virustotal_key","hunter_key","hibp_key","otx_key","abuseipdb_key",
        "theme"
    ]}
    # SMTP config values
    _default_mhog_host = _mailhog_default_host()
    smtp_s = {
        "email_enabled":   _get_setting("sys_email_enabled", "1"),
        "mode":            _get_setting("sys_smtp_mode", "mailhog"),
        "mailhog_host":    _get_setting("sys_smtp_mailhog_host", "") or _default_mhog_host,
        "mailhog_port":    _get_setting("sys_smtp_mailhog_port", "1025") or "1025",
        "host":            _get_setting("sys_smtp_host",  ""),
        "port":            _get_setting("sys_smtp_port",  "587"),
        "user":            _get_setting("sys_smtp_user",  ""),
        "from":            _get_setting("sys_smtp_from",  "feroxsei@localhost"),
        "tls":             _get_setting("sys_smtp_tls",   "0"),
        "ssl":             _get_setting("sys_smtp_ssl",   "0"),
    }
    _email_on      = smtp_s["email_enabled"] == "1"
    _smtp_on_color = '#4ade80' if _email_on else '#374151'
    _smtp_knob_pos = '22px'    if _email_on else '2px'
    _is_mailhog   = smtp_s["mode"] == "mailhog"
    _mhog_ch      = 'checked' if _is_mailhog else ''
    _cust_ch      = '' if _is_mailhog else 'checked'
    _mhog_border  = 'var(--primary)' if _is_mailhog else 'var(--border)'
    _cust_border  = 'var(--border)' if _is_mailhog else 'var(--primary)'
    _mhog_bg      = 'rgba(0,212,255,.06)' if _is_mailhog else 'var(--bg3)'
    _cust_bg      = 'var(--bg3)' if _is_mailhog else 'rgba(0,212,255,.06)'
    _mhog_disp    = 'block' if _is_mailhog else 'none'
    _cust_disp    = 'none' if _is_mailhog else 'block'
    _tls_ch       = 'checked' if smtp_s['tls'] == '1' else ''
    _ssl_ch       = 'checked' if smtp_s['ssl'] == '1' else ''
    _email_body_disp  = 'block' if _email_on else 'none'
    _auto_mhog_host   = _mailhog_default_host()
    import os as _os_set
    _mhog_src = ("Docker Compose service name" if _os_set.environ.get("MAILHOG_HOST","") else
                 ("Docker Compose DNS" if _auto_mhog_host == "mailhog" else
                  ("Docker gateway" if IN_DOCKER else "localhost")))
    _mhog_host_hint   = f'(auto-detected: <code>{_auto_mhog_host}</code> via {_mhog_src})'
    # ── Headless browser status check ────────────────────────────────────────
    pw_browser_ok = False
    pw_version    = ""
    if HAS_PLAYWRIGHT:
        try:
            from playwright.sync_api import sync_playwright as _sp
            with _sp() as _pw:
                _b = _pw.chromium.launch(headless=True)
                pw_version    = _b.version
                pw_browser_ok = True
                _b.close()
        except Exception:
            pw_browser_ok = False

    if pw_browser_ok:
        headless_card = f"""
    <div class="card" style="margin-bottom:16px">
      <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-headless">
        <span class="card-title">📸 Headless Browser</span>
        <span style="background:rgba(0,255,157,.12);color:#00ff9d;border:1px solid #00cc7a;
                     padding:2px 10px;border-radius:12px;font-size:11px;font-family:monospace">
          ✅ Chromium {pw_version}
        </span>
      </div>
      <div class="scoll-body card-body" id="body-headless">
        <div style="font-size:13px;color:var(--text)">
          Playwright + Chromium is installed and working.<br>
          Screenshots will be captured automatically during scans and can be taken
          on-demand from any finding with a URL.
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
          <button type="button" onclick="testScreenshot()"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--text)">
            🧪 Test Screenshot
          </button>
          <div id="ss-test-result" style="font-size:12px;color:var(--muted);padding-top:6px"></div>
        </div>
      </div>
    </div>"""
    else:
        missing_lib  = "" if HAS_PLAYWRIGHT else "playwright Python library not installed"
        missing_br   = "" if not HAS_PLAYWRIGHT else "Chromium browser not downloaded"
        missing_desc = missing_lib or missing_br or "Playwright/Chromium unavailable"
        headless_card = f"""
    <div class="card" style="margin-bottom:16px;border-color:var(--warning)">
      <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-headless">
        <span class="card-title">📸 Headless Browser</span>
        <span style="background:rgba(255,173,0,.12);color:var(--warning);border:1px solid var(--warning);
                     padding:2px 10px;border-radius:12px;font-size:11px;font-family:monospace">
          ⚠ Not Ready
        </span>
      </div>
      <div class="scoll-body card-body" id="body-headless">
        <div style="font-size:13px;color:var(--warning);margin-bottom:12px">
          {missing_desc}. Screenshots in findings will be unavailable until installed.
        </div>

        <div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-weight:600;
                    text-transform:uppercase;letter-spacing:.6px">📋 Installation Guide</div>

        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;
                    padding:14px;font-family:monospace;font-size:12px">

          <div style="color:var(--muted);margin-bottom:8px">Step 1 - Install Playwright Python library:</div>
          <div style="background:var(--bg);padding:7px 10px;border-radius:5px;margin-bottom:12px;
                      color:var(--secondary);border-left:3px solid var(--secondary)">
            pip install playwright --break-system-packages
          </div>

          <div style="color:var(--muted);margin-bottom:8px">Step 2 - Download Chromium browser (one-time ~130 MB):</div>
          <div style="background:var(--bg);padding:7px 10px;border-radius:5px;margin-bottom:12px;
                      color:var(--secondary);border-left:3px solid var(--secondary)">
            playwright install chromium
          </div>

          <div style="color:var(--muted);margin-bottom:8px">Step 3 - Install system dependencies (Debian/Kali/Ubuntu):</div>
          <div style="background:var(--bg);padding:7px 10px;border-radius:5px;margin-bottom:12px;
                      color:var(--secondary);border-left:3px solid var(--secondary)">
            playwright install-deps chromium
          </div>

          <div style="color:var(--muted);margin-bottom:8px">Step 4 - Verify it works:</div>
          <div style="background:var(--bg);padding:7px 10px;border-radius:5px;
                      color:var(--secondary);border-left:3px solid var(--secondary)">
            python3 -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); print('OK', b.version); b.close(); p.stop()"
          </div>
        </div>

        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <button type="button" onclick="autoInstallPlaywright()"
            id="pw-install-btn"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--warning);background:rgba(255,173,0,.08);color:var(--warning)">
            ⚡ Auto-Install (pip + playwright install chromium)
          </button>
          <button type="button" onclick="location.reload()"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--muted)">
            🔄 Re-check Status
          </button>
        </div>
        <div id="pw-install-log"
             style="display:none;margin-top:10px;background:var(--bg);border:1px solid var(--border);
                    border-radius:6px;padding:10px;font-family:monospace;font-size:11px;
                    color:#69f0ae;max-height:200px;overflow-y:auto;white-space:pre-wrap"></div>
      </div>
    </div>"""

    # ── Build theme selector HTML ─────────────────────────────────────────────
    active_theme = s.get("theme","") or "default"
    _categories  = {}
    for tid, tdata in _THEMES.items():
        cat = tdata["category"]
        _categories.setdefault(cat, []).append((tid, tdata))

    theme_cards_html = ""
    for cat_name, themes_in_cat in _categories.items():
        theme_cards_html += f"""
      <div style="margin-bottom:18px">
        <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;
                    margin-bottom:8px;font-weight:600">{cat_name}</div>
        <div style="display:flex;flex-wrap:wrap;gap:10px">"""
        for tid, tdata in themes_in_cat:
            colors   = tdata["preview"].split(",")
            bg_c     = colors[0] if len(colors) > 0 else "#060b14"
            pri_c    = colors[1] if len(colors) > 1 else "#00d4ff"
            sec_c    = colors[2] if len(colors) > 2 else "#00ff9d"
            is_light = bg_c.startswith("#f") or bg_c.startswith("#e") or bg_c.startswith("#d")
            txt_c    = "#1a1a2e" if is_light else "#ffffff"
            sel_ring = "box-shadow:0 0 0 2px var(--primary),0 0 0 4px rgba(0,212,255,.3);" if tid == active_theme else ""
            sel_dot  = "✓ " if tid == active_theme else ""
            theme_cards_html += f"""
          <label style="cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:6px">
            <input type="radio" name="theme" value="{tid}" {'checked' if tid==active_theme else ''}
                   style="display:none" onchange="applyThemePreview(this)">
            <div style="width:88px;height:56px;border-radius:8px;overflow:hidden;border:2px solid {'var(--primary)' if tid==active_theme else 'var(--border)'};
                        {sel_ring}transition:all .2s;position:relative;background:{bg_c}"
                 onclick="this.parentElement.querySelector('input').click()">
              <div style="position:absolute;top:0;left:0;right:0;height:16px;
                          background:{bg_c};border-bottom:1px solid {pri_c}40;
                          display:flex;align-items:center;padding:0 5px;gap:3px">
                <div style="width:5px;height:5px;border-radius:50%;background:{pri_c};opacity:.8"></div>
                <div style="width:5px;height:5px;border-radius:50%;background:{sec_c};opacity:.6"></div>
              </div>
              <div style="position:absolute;top:18px;left:6px;right:6px;bottom:4px;
                          background:{bg_c};border:1px solid {pri_c}30;border-radius:4px;
                          display:flex;flex-direction:column;gap:2px;padding:3px">
                <div style="height:4px;background:{pri_c};border-radius:2px;opacity:.8;width:70%"></div>
                <div style="height:3px;background:{sec_c};border-radius:2px;opacity:.5;width:50%"></div>
                <div style="height:3px;background:{txt_c};border-radius:2px;opacity:.2;width:90%"></div>
              </div>
              {'<div style="position:absolute;top:2px;right:4px;color:' + pri_c + ';font-size:10px;font-weight:700">✓</div>' if tid==active_theme else ''}
            </div>
            <span style="font-size:10px;color:{'var(--primary)' if tid==active_theme else 'var(--text2)'};
                         text-align:center;max-width:88px;line-height:1.2;font-weight:{'600' if tid==active_theme else '400'}">
              {sel_dot}{tdata['label'].split(' - ')[-1] if ' - ' in tdata['label'] else tdata['label']}
            </span>
          </label>"""
        theme_cards_html += """
        </div>
      </div>"""

    html = f"""
{'<div class="alert alert-success">'+msg+'</div>' if msg else ''}
<style>
.scoll-hdr {{
  display:flex;align-items:center;justify-content:space-between;
  cursor:pointer;padding:10px 14px;user-select:none;
  border-radius:8px;transition:background .15s;
}}
.scoll-hdr:hover {{ background:rgba(255,255,255,.04); }}
.scoll-hdr .scoll-arrow {{
  font-size:12px;color:var(--muted);transition:transform .2s;display:inline-block;
}}
.scoll-hdr.open .scoll-arrow {{ transform:rotate(90deg); }}
.scoll-body {{ overflow:hidden;transition:max-height .25s ease; }}
</style>
<form method="POST">

<!-- ── Theme Selector ─────────────────────────────────────────────────── -->
<div class="card" style="margin-bottom:16px">
  <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-theme">
    <span class="card-title">🎨 Interface Theme</span>
    <span class="scoll-arrow">▶</span>
  </div>
  <div class="scoll-body card-body" id="body-theme">
    <div style="font-size:12px;color:var(--muted);margin-bottom:14px">
      Choose a theme - changes apply instantly after saving.
    </div>
    {theme_cards_html}
  </div>
</div>

<div class="grid2" style="gap:16px;align-items:start">
  <div>

    <!-- TOR -->
    <div class="card" style="margin-bottom:16px">
      <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-tor">
        <span class="card-title">⬡ Anonymous Mode (TOR)</span>
        <span class="scoll-arrow">▶</span>
      </div>
      <div class="scoll-body card-body" id="body-tor">
        <div class="form-group">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:12px">
            <input type="checkbox" name="tor_enabled" {'checked' if s['tor_enabled']=='1' else ''}>
            <span style="font-weight:500">Enable TOR for all scan traffic</span>
          </label>
        </div>
        <div class="form-row">
          <div class="form-group"><label>SOCKS5 Host</label>
            <input type="text" name="tor_socks_host" value="{s['tor_socks_host']}"></div>
          <div class="form-group"><label>SOCKS5 Port</label>
            <input type="number" name="tor_socks_port" value="{s['tor_socks_port']}"></div>
        </div>
        <div class="alert alert-info" style="font-size:12px;margin-top:8px">
          When enabled: all HTTP requests route through TOR. Traffic log shows<br>
          <span class="mono">SOURCE_IP ──TOR──► EXIT_NODE ──► DEST_HOST</span>
        </div>
      </div>
    </div>

    {headless_card}

    <!-- System SMTP -->
    <div class="card" style="margin-bottom:16px">
      <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-smtp">
        <span class="card-title">📧 System Email (SMTP)</span>
        <span class="scoll-arrow">▶</span>
      </div>
      <div class="scoll-body card-body" id="body-smtp">

        <!-- Master on/off toggle -->
        <div style="display:flex;align-items:center;justify-content:space-between;
                    padding:10px 14px;background:var(--bg3);border-radius:8px;
                    border:1px solid var(--border);margin-bottom:14px">
          <div>
            <div style="font-weight:600;font-size:13px">Email Sending</div>
            <div style="font-size:11px;color:var(--muted)">
              Off = registrations create pending users with no OTP step
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:12px;color:var(--muted)">OFF</span>
            <div onclick="toggleEmailEnabled()" id="email-toggle"
              style="width:46px;height:24px;border-radius:12px;cursor:pointer;
                     transition:background .2s;position:relative;
                     background:{_smtp_on_color}">
              <div id="email-toggle-knob"
                style="position:absolute;top:2px;width:20px;height:20px;
                       border-radius:50%;background:#fff;transition:left .2s;
                       left:{_smtp_knob_pos}"></div>
            </div>
            <span style="font-size:12px;color:var(--muted)">ON</span>
          </div>
          <input type="hidden" name="sys_email_enabled" id="sys_email_enabled_input"
                 value="{smtp_s['email_enabled']}">
        </div>

        <!-- All SMTP config (hidden when email disabled) -->
        <div id="smtp-enabled-body" style="display:{_email_body_disp}">
          <div style="font-size:12px;color:var(--muted);margin-bottom:14px">
            Controls how <strong>all</strong> outgoing emails are delivered - registration OTPs,
            admin approval alerts, and phishing campaign emails.
          </div>

          <!-- Mode selector -->
          <div style="display:flex;gap:10px;margin-bottom:16px">
            <label onclick="switchSmtpMode('mailhog')" id="mode-lbl-mailhog"
              style="display:flex;align-items:center;gap:10px;cursor:pointer;padding:10px 16px;
                     border-radius:8px;border:2px solid {_mhog_border};background:{_mhog_bg};
                     transition:all .15s;flex:1">
              <input type="radio" name="sys_smtp_mode" value="mailhog" {_mhog_ch} style="display:none">
              <span style="font-size:22px">🐳</span>
              <div>
                <div style="font-weight:600;font-size:13px">MailHog (Testing)</div>
                <div style="font-size:11px;color:var(--muted)">
                  All emails captured locally - registration OTPs <em>and</em>
                  phishing campaign mails appear in MailHog. Nothing reaches real inboxes.
                </div>
              </div>
            </label>
            <label onclick="switchSmtpMode('custom')" id="mode-lbl-custom"
              style="display:flex;align-items:center;gap:10px;cursor:pointer;padding:10px 16px;
                     border-radius:8px;border:2px solid {_cust_border};background:{_cust_bg};
                     transition:all .15s;flex:1">
              <input type="radio" name="sys_smtp_mode" value="custom" {_cust_ch} style="display:none">
              <span style="font-size:22px">⚙️</span>
              <div>
                <div style="font-weight:600;font-size:13px">Custom SMTP (Production)</div>
                <div style="font-size:11px;color:var(--muted)">
                  System emails (OTP, alerts) sent via this server.
                  Phishing campaigns use their own Sending Profile SMTP.
                </div>
              </div>
            </label>
          </div>

          <!-- MailHog section -->
          <div id="smtp-mailhog-section" style="display:{_mhog_disp}">
            <div class="alert alert-info" style="font-size:12px;line-height:1.8;margin-bottom:12px">
              <strong>MailHog (Testing Mode)</strong> - all FEROXSEI outgoing email is captured here:<br>
              &nbsp;• Registration OTP &amp; account approval emails<br>
              &nbsp;• Phishing campaign emails (even if a sending profile is configured)<br>
              Nothing reaches real inboxes. View captured mail at
              <a href="http://localhost:8025" target="_blank" style="color:var(--primary)">localhost:8025</a><br>
              Start standalone: <code style="background:rgba(0,0,0,.25);padding:1px 6px;border-radius:4px">docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog</code>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label>MailHog Host
                  <span style="font-size:11px;color:var(--muted);font-weight:400">
                    {_mhog_host_hint}
                  </span>
                </label>
                <input type="text" name="sys_smtp_mailhog_host"
                       value="{smtp_s['mailhog_host']}" placeholder="{_default_mhog_host}">
              </div>
              <div class="form-group"><label>MailHog Port</label>
                <input type="number" name="sys_smtp_mailhog_port"
                       value="{smtp_s['mailhog_port']}" placeholder="1025">
              </div>
            </div>
          </div>

          <!-- Custom SMTP section -->
          <div id="smtp-custom-section" style="display:{_cust_disp}">
            <div class="form-row">
              <div class="form-group"><label>SMTP Host</label>
                <input type="text" name="sys_smtp_host" value="{smtp_s['host']}"
                       placeholder="smtp.gmail.com / mail.company.com"></div>
              <div class="form-group"><label>SMTP Port</label>
                <input type="number" name="sys_smtp_port" value="{smtp_s['port']}"
                       placeholder="587 = STARTTLS / 465 = SSL"></div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label>Username <span style="color:var(--muted);font-weight:400">(blank = no auth)</span></label>
                <input type="text" name="sys_smtp_user" value="{smtp_s['user']}" placeholder="you@company.com">
              </div>
              <div class="form-group"><label>Password</label>
                <input type="password" name="sys_smtp_pass" placeholder="Leave blank to keep saved value">
              </div>
            </div>
            <div style="display:flex;gap:20px;margin-bottom:12px">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" name="sys_smtp_tls" {_tls_ch}> STARTTLS (port 587)
              </label>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" name="sys_smtp_ssl" {_ssl_ch}> SSL/TLS (port 465)
              </label>
            </div>
          </div>

          <!-- From address - always visible -->
          <div class="form-group"><label>From Address</label>
            <input type="text" name="sys_smtp_from" value="{smtp_s['from']}"
                   placeholder="feroxsei@localhost">
          </div>

          <!-- Test email with explicit recipient -->
          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;margin-top:8px">
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Test Email</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input type="email" id="smtp-test-to" placeholder="test@example.com"
                     style="flex:1;min-width:180px;padding:5px 10px;border-radius:6px;font-size:12px;
                            border:1px solid var(--border);background:var(--bg);color:var(--text)">
              <button type="button" onclick="testSmtp()"
                style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                       border:1px solid var(--primary);background:rgba(0,212,255,.08);
                       color:var(--primary);white-space:nowrap">
                Send Test →
              </button>
            </div>
            <div id="smtp-test-result" style="font-size:12px;margin-top:6px"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- API Keys -->
    <div class="card" style="margin-bottom:16px">
      <div class="scoll-hdr open" onclick="toggleSection(this)" id="hdr-apikeys">
        <span class="card-title">🔑 API Keys</span>
        <span class="scoll-arrow">▶</span>
      </div>
      <div class="scoll-body card-body" id="body-apikeys">
        <div class="form-group"><label>🤖 Anthropic/Claude API Key</label>
          <input type="password" name="anthropic_key" value="{s['anthropic_key']}" placeholder="sk-ant-..."></div>
        <div class="form-group"><label>🤖 OpenAI API Key (fallback)</label>
          <input type="password" name="openai_key" value="{s['openai_key']}" placeholder="sk-..."></div>
        <div style="display:none">
        <div class="form-group"><label>🐙 GitHub Token</label>
          <input type="password" name="github_token" value="{s['github_token']}" placeholder="ghp_..."></div>
        <div class="form-group"><label>🔭 Shodan API Key</label>
          <input type="password" name="shodan_key" value="{s['shodan_key']}" placeholder=""></div>
        <div class="form-group"><label>🦠 VirusTotal API Key</label>
          <input type="password" name="virustotal_key" value="{s['virustotal_key']}" placeholder=""></div>
        <div class="form-group"><label>📧 Hunter.io API Key</label>
          <input type="password" name="hunter_key" value="{s['hunter_key']}" placeholder=""></div>
        <div class="form-group"><label>🔓 HaveIBeenPwned Key</label>
          <input type="password" name="hibp_key" value="{s['hibp_key']}" placeholder=""></div>
        <div class="form-group"><label>⚡ AlienVault OTX Key</label>
          <input type="password" name="otx_key" value="{s['otx_key']}" placeholder=""></div>
        <div class="form-group"><label>🚨 AbuseIPDB Key</label>
          <input type="password" name="abuseipdb_key" value="{s['abuseipdb_key']}" placeholder=""></div>
        </div>
      </div>
    </div>
  </div>
</div>
<button class="btn btn-primary" style="justify-content:center;margin-top:16px">💾 Save Settings</button>
</form>
<script>
/* ── Collapsible section toggle ─────────────────────────────────────── */
function toggleSection(hdr) {{
  var bodyId = hdr.id.replace('hdr-', 'body-');
  var body   = document.getElementById(bodyId);
  if (!body) return;
  var isOpen = hdr.classList.contains('open');
  if (isOpen) {{
    body.style.maxHeight = body.scrollHeight + 'px';
    requestAnimationFrame(function() {{
      body.style.maxHeight = '0';
      body.style.paddingTop = '0';
      body.style.paddingBottom = '0';
    }});
    hdr.classList.remove('open');
  }} else {{
    body.style.maxHeight = body.scrollHeight + 2000 + 'px';
    body.style.paddingTop = '';
    body.style.paddingBottom = '';
    hdr.classList.add('open');
  }}
}}
/* Init - set explicit heights on open sections so CSS transitions work */
document.querySelectorAll('.scoll-body').forEach(function(b) {{
  b.style.maxHeight = b.scrollHeight + 2000 + 'px';
}});

/* ── Theme preview selector ──────────────────────────────────────────── */
function applyThemePreview(radio) {{
  /* Highlight the selected theme card border */
  document.querySelectorAll('input[name="theme"]').forEach(function(r) {{
    var wrap = r.parentElement.querySelector('div');
    var lbl  = r.parentElement.querySelector('span');
    if (!wrap) return;
    if (r === radio) {{
      wrap.style.borderColor = 'var(--primary)';
      wrap.style.boxShadow  = '0 0 0 2px var(--primary),0 0 0 4px rgba(0,212,255,.3)';
      if (lbl) {{ lbl.style.color = 'var(--primary)'; lbl.style.fontWeight = '600'; }}
    }} else {{
      wrap.style.borderColor = 'var(--border)';
      wrap.style.boxShadow  = 'none';
      if (lbl) {{ lbl.style.color = 'var(--text2)'; lbl.style.fontWeight = '400'; }}
    }}
  }});
}}

function toggleEmailEnabled() {{
  var inp    = document.getElementById('sys_email_enabled_input');
  var toggle = document.getElementById('email-toggle');
  var knob   = document.getElementById('email-toggle-knob');
  var body   = document.getElementById('smtp-enabled-body');
  var isOn   = inp && inp.value === '1';
  var nowOn  = !isOn;
  if (inp)    inp.value              = nowOn ? '1' : '0';
  if (toggle) toggle.style.background = nowOn ? '#4ade80' : '#374151';
  if (knob)   knob.style.left        = nowOn ? '22px' : '2px';
  if (body)   body.style.display     = nowOn ? 'block' : 'none';
  /* Recalculate collapsible height */
  var outer = document.getElementById('body-smtp');
  if (outer) outer.style.maxHeight = outer.scrollHeight + 2000 + 'px';
}}

function switchSmtpMode(mode) {{
  /* Update radio values */
  document.querySelectorAll('[name=sys_smtp_mode]').forEach(function(r) {{
    r.checked = r.value === mode;
  }});
  /* Toggle sections */
  var mhog = document.getElementById('smtp-mailhog-section');
  var cust = document.getElementById('smtp-custom-section');
  if (mhog) mhog.style.display = mode === 'mailhog' ? 'block' : 'none';
  if (cust) cust.style.display = mode === 'custom'   ? 'block' : 'none';
  /* Update label borders / backgrounds */
  var lMhog = document.getElementById('mode-lbl-mailhog');
  var lCust = document.getElementById('mode-lbl-custom');
  var on  = '2px solid var(--primary)';
  var off = '2px solid var(--border)';
  var onBg  = 'rgba(0,212,255,.06)';
  var offBg = 'var(--bg3)';
  if (lMhog) {{ lMhog.style.border = mode==='mailhog' ? on : off; lMhog.style.background = mode==='mailhog' ? onBg : offBg; }}
  if (lCust) {{ lCust.style.border = mode==='custom'   ? on : off; lCust.style.background = mode==='custom'   ? onBg : offBg; }}
  /* Expand the collapsible section so newly shown fields are visible */
  var body = document.getElementById('body-smtp');
  if (body) body.style.maxHeight = body.scrollHeight + 2000 + 'px';
}}

function testSmtp() {{
  var res  = document.getElementById('smtp-test-result');
  var toEl = document.getElementById('smtp-test-to');
  var toAddr = toEl ? toEl.value.trim() : '';
  if (!toAddr) {{
    if (res) {{ res.textContent = '⚠ Enter a recipient email address first'; res.style.color = '#f59e0b'; }}
    if (toEl) toEl.focus();
    return;
  }}
  if (res) {{ res.textContent = '⏳ Sending…'; res.style.color = 'var(--muted)'; }}
  /* Grab current form values (unsaved state) so the test reflects what will be saved */
  var mode = (document.querySelector('[name=sys_smtp_mode]:checked') || {{}}).value || 'mailhog';
  var host, port, user, pass, tls, ssl;
  if (mode === 'mailhog') {{
    var mhEl = document.querySelector('[name=sys_smtp_mailhog_host]');
    var mpEl = document.querySelector('[name=sys_smtp_mailhog_port]');
    host = mhEl ? mhEl.value.trim() : '';
    port = mpEl ? mpEl.value.trim() : '1025';
    user = ''; pass = ''; tls = false; ssl = false;
  }} else {{
    var hEl = document.querySelector('[name=sys_smtp_host]');
    var pEl = document.querySelector('[name=sys_smtp_port]');
    var uEl = document.querySelector('[name=sys_smtp_user]');
    var pwEl = document.querySelector('[name=sys_smtp_pass]');
    var tlsEl = document.querySelector('[name=sys_smtp_tls]');
    var sslEl = document.querySelector('[name=sys_smtp_ssl]');
    host = hEl ? hEl.value.trim() : '';
    port = pEl ? pEl.value.trim() : '587';
    user = uEl ? uEl.value.trim() : '';
    pass = pwEl ? pwEl.value : '';
    tls  = tlsEl ? tlsEl.checked : false;
    ssl  = sslEl ? sslEl.checked : false;
  }}
  var from = (document.querySelector('[name=sys_smtp_from]') || {{}}).value || '';
  fetch('/api/smtp/test', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{host, port, user, pass, from_addr: from, tls, ssl, to_addr: toAddr, mode}})
  }}).then(r=>r.json()).then(d=>{{
    if (!res) return;
    if (d.ok) {{
      res.textContent = '✅ ' + (d.message || 'Email sent!');
      res.style.color = '#4ade80';
    }} else {{
      res.textContent = '❌ ' + (d.error || 'Failed');
      res.style.color = 'var(--danger)';
    }}
  }}).catch(()=>{{ if(res){{ res.textContent='❌ Network error'; res.style.color='var(--danger)'; }} }});
}}

function testScreenshot() {{
  var res = document.getElementById('ss-test-result');
  if (res) res.textContent = '⏳ Taking test screenshot of example.com…';
  fetch('/api/headless/test', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{
      if (!res) return;
      if (d.ok) {{
        res.innerHTML = '<span style="color:#69f0ae">✅ Screenshot captured successfully (' + (d.size_kb||'?') + ' KB)</span>';
      }} else {{
        res.innerHTML = '<span style="color:var(--danger)">❌ ' + (d.error||'Failed') + '</span>';
      }}
    }}).catch(()=>{{ if (res) res.innerHTML = '<span style="color:var(--danger)">❌ Network error</span>'; }});
}}
function autoInstallPlaywright() {{
  var btn = document.getElementById('pw-install-btn');
  var log = document.getElementById('pw-install-log');
  if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Installing…'; }}
  if (log) {{ log.style.display = 'block'; log.textContent = 'Starting installation…\\n'; }}
  fetch('/api/headless/install', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{
      if (log) {{
        log.textContent = d.output || '(no output)';
        log.scrollTop = log.scrollHeight;
      }}
      if (d.ok) {{
        if (log) log.textContent += '\\n\\n✅ Done - click Re-check Status to verify.';
      }} else {{
        if (log) log.textContent += '\\n\\n❌ Error: ' + (d.error||'Unknown');
        if (btn) {{ btn.disabled = false; btn.textContent = '⚡ Retry Install'; }}
      }}
    }}).catch(()=>{{
      if (log) log.textContent += '\\n❌ Network error';
      if (btn) {{ btn.disabled = false; btn.textContent = '⚡ Retry Install'; }}
    }});
}}
</script>"""
    return _base("Settings - General", html, "settings_general")

# ═════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/audit")
@require_login
def audit():
    if not _analyst_can("audit"):
        return redirect(url_for("dashboard"))

    # ── Filters from query string ──────────────────────────────────────────────
    f_user   = request.args.get("user","").strip()
    f_action = request.args.get("action","").strip()
    f_ip     = request.args.get("ip","").strip()
    f_date   = request.args.get("date","").strip()   # YYYY-MM-DD
    f_rtype  = request.args.get("rtype","").strip()
    limit    = int(request.args.get("limit","500"))

    where_parts = []
    params = []
    if f_user:
        where_parts.append("LOWER(username) LIKE ?");  params.append(f"%{f_user.lower()}%")
    if f_action:
        where_parts.append("action LIKE ?");            params.append(f"%{f_action}%")
    if f_ip:
        where_parts.append("ip_address LIKE ?");        params.append(f"%{f_ip}%")
    if f_date:
        where_parts.append("created_at LIKE ?");        params.append(f"{f_date}%")
    if f_rtype:
        where_parts.append("resource_type=?");          params.append(f_rtype)
    where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    logs = db.rows(f"SELECT * FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ?",
                   tuple(params) + (limit,))

    # ── Stats ──────────────────────────────────────────────────────────────────
    total_count  = db.one("SELECT COUNT(*) as c FROM audit_log")["c"]
    unique_users = db.rows("SELECT DISTINCT username FROM audit_log WHERE username!=''")
    unique_ips   = db.rows("SELECT DISTINCT ip_address FROM audit_log WHERE ip_address!=''")
    action_types = db.rows("SELECT DISTINCT action FROM audit_log ORDER BY action")
    rtypes       = db.rows("SELECT DISTINCT resource_type FROM audit_log WHERE resource_type!='' ORDER BY resource_type")

    # ── Action badge colour mapping ────────────────────────────────────────────
    def _action_color(act: str) -> str:
        act = act.lower()
        if any(k in act for k in ("login","register")):  return "#4ade80"
        if any(k in act for k in ("delete","suspend","remove")): return "#f87171"
        if any(k in act for k in ("edit","update","save","approve")): return "#fbbf24"
        if any(k in act for k in ("launch","send","create")): return "#60a5fa"
        return "var(--primary)"

    # ── Table rows ─────────────────────────────────────────────────────────────
    rows_html = ""
    for l in logs:
        ac  = _action_color(l["action"])
        ua  = (l.get("user_agent","") or "")
        # Shorten user-agent for display
        ua_short = ua[:60] + ("…" if len(ua) > 60 else "")
        geo = l.get("geo_location","") or ""
        rid_short = (l.get("resource_id","") or "")[:12]
        detail_s  = (l.get("detail","") or "")[:100]
        # Render hop chain: replace " → " with styled arrows
        raw_ip = l.get("ip_address","") or ""
        hops = raw_ip.split(" → ")
        if len(hops) > 1:
            hop_html = " <span style='color:var(--muted)'>→</span> ".join(
                f'<span style="color:{"var(--primary)" if i==0 else "var(--text2)"}">{_html.escape(h)}</span>'
                for i, h in enumerate(hops)
            )
        else:
            hop_html = f'<span style="color:var(--primary)">{_html.escape(raw_ip)}</span>'
        rows_html += (
            f'<tr>'
            f'<td class="mono" style="font-size:11px;white-space:nowrap">{str(l["created_at"])[:19]}</td>'
            f'<td style="font-weight:500;color:var(--secondary)">{_html.escape(l["username"] or "")}</td>'
            f'<td><span style="background:{ac}22;color:{ac};border:1px solid {ac}55;'
            f'border-radius:4px;padding:1px 7px;font-size:11px;white-space:nowrap">'
            f'{_html.escape(l["action"])}</span></td>'
            f'<td style="font-size:11px;color:var(--text2)">'
            f'{_html.escape(l.get("resource_type","") or "")}'
            f'{"&nbsp;<code style=color:var(--muted)>"+rid_short+"</code>" if rid_short else ""}</td>'
            f'<td style="font-size:11px;color:var(--muted)" title="{_html.escape(l.get("detail","") or "")}">'
            f'{_html.escape(detail_s)}{"…" if len(l.get("detail","") or "") > 100 else ""}</td>'
            f'<td class="mono" style="font-size:11px;white-space:nowrap">{hop_html}</td>'
            f'<td style="font-size:11px;color:var(--text2)">{_html.escape(geo)}</td>'
            f'<td style="font-size:10px;color:var(--muted)" title="{_html.escape(ua)}">{_html.escape(ua_short)}</td>'
            f'</tr>'
        )
    if not rows_html:
        rows_html = '<tr><td colspan=8 style="text-align:center;padding:24px;color:var(--muted)">No audit records match your filters</td></tr>'

    # ── Filter dropdowns ───────────────────────────────────────────────────────
    user_opts  = "".join(f'<option value="{_html.escape(u["username"])}" {"selected" if f_user==u["username"] else ""}>{_html.escape(u["username"])}</option>' for u in unique_users)
    act_opts   = "".join(f'<option value="{_html.escape(a["action"])}" {"selected" if f_action==a["action"] else ""}>{_html.escape(a["action"])}</option>' for a in action_types)
    rtype_opts = "".join(f'<option value="{_html.escape(r["resource_type"])}" {"selected" if f_rtype==r["resource_type"] else ""}>{_html.escape(r["resource_type"])}</option>' for r in rtypes)

    # ── Entity graph data ──────────────────────────────────────────────────────
    # Build nodes/edges from ALL logs (up to 2000) for graph
    graph_logs = db.rows(
        "SELECT username,action,resource_type,resource_id FROM audit_log "
        "WHERE username!='' ORDER BY created_at DESC LIMIT 2000"
    )
    graph_nodes = {}  # id → {id,label,type,count}
    graph_edges = []  # {source,target,label,count}
    edge_map    = {}  # (src,tgt,action) → count
    for gl in graph_logs:
        uname = gl["username"] or "anon"
        rtype = gl["resource_type"] or "system"
        rid   = (gl["resource_id"] or "")[:8]
        act   = gl["action"]
        # User node
        if uname not in graph_nodes:
            graph_nodes[uname] = {"id": uname, "label": uname, "type": "user", "count": 0}
        graph_nodes[uname]["count"] += 1
        # Resource node
        rnode_id = f"{rtype}:{rid}" if rid else rtype
        if rnode_id not in graph_nodes:
            graph_nodes[rnode_id] = {"id": rnode_id, "label": f"{rtype}\n{rid}" if rid else rtype, "type": rtype, "count": 0}
        graph_nodes[rnode_id]["count"] += 1
        # Edge
        ek = (uname, rnode_id, act)
        edge_map[ek] = edge_map.get(ek, 0) + 1

    for (src, tgt, lbl), cnt in edge_map.items():
        graph_edges.append({"source": src, "target": tgt, "label": lbl, "count": cnt})

    import json as _json
    graph_data_json = _json.dumps({
        "nodes": list(graph_nodes.values()),
        "edges": graph_edges
    })

    # ── Per-user activity summary ──────────────────────────────────────────────
    user_stats = db.rows(
        "SELECT username, COUNT(*) as cnt, MAX(created_at) as last_seen, "
        "COUNT(DISTINCT ip_address) as ips, COUNT(DISTINCT action) as acts "
        "FROM audit_log WHERE username!='' GROUP BY username ORDER BY cnt DESC LIMIT 50"
    )
    user_rows = ""
    for us in user_stats:
        user_rows += (
            f'<tr>'
            f'<td style="font-weight:500;color:var(--secondary)">{_html.escape(us["username"])}</td>'
            f'<td style="text-align:center">{us["cnt"]}</td>'
            f'<td style="text-align:center">{us["ips"]}</td>'
            f'<td style="text-align:center">{us["acts"]}</td>'
            f'<td class="mono" style="font-size:11px">{str(us["last_seen"])[:19]}</td>'
            f'<td><a href="/audit?user={_html.escape(us["username"])}" class="btn btn-ghost btn-sm" style="font-size:11px">Filter →</a></td>'
            f'</tr>'
        )

    # ── Top actions by frequency ───────────────────────────────────────────────
    top_acts = db.rows(
        "SELECT action, COUNT(*) as cnt FROM audit_log GROUP BY action ORDER BY cnt DESC LIMIT 15"
    )
    max_cnt = max((a["cnt"] for a in top_acts), default=1)
    act_bars = ""
    for ta in top_acts:
        pct = int(ta["cnt"] / max_cnt * 100)
        col = _action_color(ta["action"])
        act_bars += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
            f'<span style="min-width:200px;font-size:12px;color:var(--text2)">{_html.escape(ta["action"])}</span>'
            f'<div style="flex:1;background:var(--bg3);border-radius:3px;height:14px">'
            f'<div style="width:{pct}%;background:{col};height:14px;border-radius:3px;'
            f'min-width:4px"></div></div>'
            f'<span style="min-width:40px;font-size:12px;text-align:right;color:{col}">{ta["cnt"]}</span>'
            f'</div>'
        )

    html = f"""
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
.audit-tabs {{display:flex;gap:0;margin-bottom:0;border-bottom:1px solid var(--border)}}
.audit-tab {{padding:10px 20px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;
  font-size:13px;font-weight:500;background:none;border-top:none;border-left:none;border-right:none;
  transition:all .2s}}
.audit-tab.active {{color:var(--primary);border-bottom-color:var(--primary)}}
.audit-pane {{display:none}}.audit-pane.active {{display:block}}
.stat-mini {{background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:12px 16px;text-align:center}}
.stat-mini .val {{font-size:24px;font-weight:700;color:var(--primary)}}
.stat-mini .lbl {{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}}
#audit-graph {{width:100%;height:520px;background:var(--bg2);border-radius:8px;overflow:hidden}}
.graph-tooltip {{position:absolute;background:var(--bg4);border:1px solid var(--border);
  border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;display:none;
  color:var(--text);z-index:999}}
</style>

<!-- IP visibility note -->
<div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.15);border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:var(--text2)">
  <strong style="color:var(--primary)">ℹ IP Capture:</strong>
  The <strong>IP column shows the full hop chain</strong> - leftmost IP is the real client, rightmost is the direct-connect IP to this server (e.g. <code style="font-size:11px">203.0.113.5 → 10.0.0.1 → 172.17.0.1</code>).
  The chain comes from <code style="font-size:11px">X-Forwarded-For</code> / <code style="font-size:11px">CF-Connecting-IP</code> headers set by upstream proxies.
  <strong style="color:var(--warning)">VPN or TOR users:</strong> the server only sees the VPN/TOR exit node - the real source IP is hidden by design and cannot be recovered server-side.
</div>

<!-- Stats row -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
  <div class="stat-mini"><div class="val">{total_count}</div><div class="lbl">Total Events</div></div>
  <div class="stat-mini"><div class="val">{len(unique_users)}</div><div class="lbl">Unique Users</div></div>
  <div class="stat-mini"><div class="val">{len(unique_ips)}</div><div class="lbl">Unique IPs</div></div>
  <div class="stat-mini"><div class="val">{len(action_types)}</div><div class="lbl">Action Types</div></div>
</div>

<!-- Tabs -->
<div class="card" style="overflow:visible">
  <div class="audit-tabs">
    <button class="audit-tab active" onclick="showAuditTab('log')">📋 Audit Log</button>
    <button class="audit-tab" onclick="showAuditTab('graph')">🕸 Entity Graph</button>
    <button class="audit-tab" onclick="showAuditTab('users')">👥 User Activity</button>
    <button class="audit-tab" onclick="showAuditTab('actions')">📊 Action Stats</button>
  </div>

  <!-- LOG TAB -->
  <div id="audit-pane-log" class="audit-pane active" style="padding:16px">
    <!-- Filter bar -->
    <form method="GET" action="/audit" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;align-items:flex-end">
      <div class="form-group" style="margin:0;min-width:140px">
        <label style="font-size:11px">User</label>
        <select name="user" style="padding:4px 8px;font-size:12px;height:30px">
          <option value="">All users</option>{user_opts}
        </select>
      </div>
      <div class="form-group" style="margin:0;min-width:160px">
        <label style="font-size:11px">Action</label>
        <select name="action" style="padding:4px 8px;font-size:12px;height:30px">
          <option value="">All actions</option>{act_opts}
        </select>
      </div>
      <div class="form-group" style="margin:0;min-width:130px">
        <label style="font-size:11px">Resource Type</label>
        <select name="rtype" style="padding:4px 8px;font-size:12px;height:30px">
          <option value="">All types</option>{rtype_opts}
        </select>
      </div>
      <div class="form-group" style="margin:0;min-width:120px">
        <label style="font-size:11px">Date (YYYY-MM-DD)</label>
        <input type="date" name="date" value="{_html.escape(f_date)}" style="padding:4px 8px;font-size:12px;height:30px">
      </div>
      <div class="form-group" style="margin:0;min-width:100px">
        <label style="font-size:11px">IP Address</label>
        <input type="text" name="ip" value="{_html.escape(f_ip)}" placeholder="192.168.…" style="padding:4px 8px;font-size:12px;height:30px">
      </div>
      <div class="form-group" style="margin:0;min-width:80px">
        <label style="font-size:11px">Limit</label>
        <select name="limit" style="padding:4px 8px;font-size:12px;height:30px">
          {"".join(f'<option value="{n}" {"selected" if limit==n else ""}>{n}</option>' for n in [100,250,500,1000,2000])}
        </select>
      </div>
      <button type="submit" class="btn btn-primary" style="height:30px;font-size:12px;padding:0 14px">Filter</button>
      <a href="/audit" class="btn btn-ghost" style="height:30px;font-size:12px;padding:0 14px">Reset</a>
    </form>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Showing {len(logs)} of {total_count} records</div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th>
        <th>Detail</th><th>IP</th><th>Geo</th><th>User-Agent</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
  </div>

  <!-- GRAPH TAB -->
  <div id="audit-pane-graph" class="audit-pane" style="padding:16px">
    <div style="font-size:12px;color:var(--muted);margin-bottom:12px">
      Force-directed entity graph of audit activity.
      <span style="color:#4ade80">●</span> Users &nbsp;
      <span style="color:#60a5fa">●</span> Investigations &nbsp;
      <span style="color:#f59e0b">●</span> Campaigns &nbsp;
      <span style="color:var(--muted)">●</span> Other &nbsp; | Drag to explore · Scroll to zoom
    </div>
    <div id="audit-graph"></div>
    <div class="graph-tooltip" id="graph-tip"></div>
  </div>

  <!-- USER ACTIVITY TAB -->
  <div id="audit-pane-users" class="audit-pane" style="padding:16px">
    <table>
      <thead><tr><th>Username</th><th>Events</th><th>Unique IPs</th><th>Actions Used</th><th>Last Seen</th><th></th></tr></thead>
      <tbody>{user_rows or '<tr><td colspan=6 style="color:var(--muted);text-align:center;padding:20px">No user data</td></tr>'}</tbody>
    </table>
  </div>

  <!-- ACTION STATS TAB -->
  <div id="audit-pane-actions" class="audit-pane" style="padding:16px">
    <h3 style="font-size:14px;color:var(--text2);margin-bottom:16px">Top Actions by Frequency</h3>
    {act_bars or '<p style="color:var(--muted)">No data yet</p>'}
  </div>
</div>

<script>
// ── Tab switching ─────────────────────────────────────────────────────────────
function showAuditTab(name) {{
  document.querySelectorAll('.audit-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.audit-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('audit-pane-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'graph') buildGraph();
}}

// ── Entity graph (D3 v7) ──────────────────────────────────────────────────────
var _graphBuilt = false;
var _graphData  = {graph_data_json};

function _nodeColor(type) {{
  if (type === 'user')          return '#4ade80';
  if (type === 'investigation') return '#60a5fa';
  if (type === 'campaign')      return '#f59e0b';
  if (type === 'scan')          return '#c084fc';
  if (type === 'profile')       return '#fb923c';
  return '#94a3b8';
}}

function buildGraph() {{
  if (_graphBuilt || typeof d3 === 'undefined') return;
  _graphBuilt = true;
  var el  = document.getElementById('audit-graph');
  var W   = el.clientWidth || 800;
  var H   = el.clientHeight || 520;
  var tip = document.getElementById('graph-tip');

  var svg = d3.select('#audit-graph').append('svg')
    .attr('width','100%').attr('height','100%')
    .attr('viewBox','0 0 '+W+' '+H);

  // Arrow markers per colour
  var defs = svg.append('defs');
  ['#4ade80','#60a5fa','#f59e0b','#c084fc','#fb923c','#94a3b8'].forEach(function(col) {{
    var id = 'arr-' + col.replace('#','');
    defs.append('marker').attr('id',id).attr('viewBox','0 -4 8 8')
      .attr('refX',18).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6)
      .attr('orient','auto')
      .append('path').attr('d','M0,-4L8,0L0,4').attr('fill',col).attr('opacity',.6);
  }});

  var simulation = d3.forceSimulation(_graphData.nodes)
    .force('link', d3.forceLink(_graphData.edges).id(function(d){{return d.id;}})
      .distance(function(d){{return 80 + d.count*5;}}).strength(.5))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(28));

  var gMain = svg.append('g');

  // Zoom
  svg.call(d3.zoom().scaleExtent([.1,4]).on('zoom', function(event){{
    gMain.attr('transform', event.transform);
  }}));

  // Edges
  var link = gMain.append('g').selectAll('line').data(_graphData.edges).enter()
    .append('line')
    .attr('stroke', function(d){{ return _nodeColor(_graphData.nodes.find(function(n){{return n.id===d.source.id||n.id===d.source;}})&&_graphData.nodes.find(function(n){{return n.id===d.source.id||n.id===d.source;}}).type||''); }})
    .attr('stroke-opacity',.4).attr('stroke-width',function(d){{return Math.min(1+d.count*.3,6);}})
    .attr('marker-end', function(d){{
      var src = _graphData.nodes.find(function(n){{return n.id===(d.source.id||d.source);}});
      var col = src ? _nodeColor(src.type) : '#94a3b8';
      return 'url(#arr-'+col.replace('#','')+')';
    }});

  // Edge labels
  var edgeLbl = gMain.append('g').selectAll('text').data(_graphData.edges).enter()
    .append('text').attr('font-size',9).attr('fill','rgba(200,214,239,.4)')
    .attr('text-anchor','middle').text(function(d){{return d.label;}});

  // Node groups
  var node = gMain.append('g').selectAll('g').data(_graphData.nodes).enter()
    .append('g').call(d3.drag()
      .on('start', function(event,d){{ if(!event.active) simulation.alphaTarget(.3).restart(); d.fx=d.x;d.fy=d.y; }})
      .on('drag',  function(event,d){{ d.fx=event.x;d.fy=event.y; }})
      .on('end',   function(event,d){{ if(!event.active) simulation.alphaTarget(0); d.fx=null;d.fy=null; }}));

  var radius = function(d){{ return Math.max(10, Math.min(30, 10 + Math.sqrt(d.count||1)*2)); }};

  node.append('circle')
    .attr('r', radius)
    .attr('fill', function(d){{ return _nodeColor(d.type); }})
    .attr('fill-opacity',.85)
    .attr('stroke','rgba(255,255,255,.15)').attr('stroke-width',1.5);

  // Icon overlay
  node.append('text').attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size', function(d){{ return Math.max(10, radius(d)-4); }})
    .text(function(d){{
      if(d.type==='user')          return '👤';
      if(d.type==='investigation') return '🗂';
      if(d.type==='campaign')      return '📧';
      if(d.type==='scan')          return '🔍';
      return '⬡';
    }});

  node.append('text').attr('dy',function(d){{return radius(d)+12;}})
    .attr('text-anchor','middle').attr('font-size',10).attr('fill','var(--text2)')
    .text(function(d){{ var lbl = d.label||d.id; return lbl.length>18?lbl.slice(0,16)+'…':lbl; }});

  // Tooltip
  node.on('mouseover', function(event,d) {{
    tip.style.display='block';
    tip.innerHTML='<b>'+d.label+'</b><br>Type: '+d.type+'<br>Events: '+d.count;
  }}).on('mousemove', function(event) {{
    tip.style.left=(event.pageX+12)+'px'; tip.style.top=(event.pageY-28)+'px';
  }}).on('mouseout', function() {{ tip.style.display='none'; }});

  simulation.on('tick', function() {{
    link.attr('x1',function(d){{return d.source.x;}}).attr('y1',function(d){{return d.source.y;}})
        .attr('x2',function(d){{return d.target.x;}}).attr('y2',function(d){{return d.target.y;}});
    edgeLbl.attr('x',function(d){{return (d.source.x+d.target.x)/2;}})
            .attr('y',function(d){{return (d.source.y+d.target.y)/2;}});
    node.attr('transform',function(d){{return 'translate('+d.x+','+d.y+')';}});
  }});
}}
</script>"""
    return _base("Audit Log", html, "audit")


# ═════════════════════════════════════════════════════════════════════════════
# SEARCH LEAKS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/leaks")
@require_login
def leaks():
    if not _analyst_can("leaks"):
        return redirect(url_for("dashboard"))
    import os as _os
    _script_dir = _os.path.dirname(_os.path.abspath(__file__))
    _builtin_data = _os.path.join(_script_dir, "leaks", "data")
    _extra_dirs   = json.loads(_get_setting("leak_directories", "[]") or "[]")
    _all_dirs     = [_builtin_data] + [d for d in _extra_dirs if d and _os.path.isdir(d)]
    _total = 0
    for _ddir in _all_dirs:
        if _os.path.isdir(_ddir):
            for _fn in _os.listdir(_ddir):
                if _fn.endswith(".txt"):
                    try:
                        with open(_os.path.join(_ddir, _fn), encoding="utf-8", errors="ignore") as _fh:
                            _total += sum(1 for _ in _fh)
                    except Exception:
                        pass
    _dir_count    = len(_all_dirs)
    _total_fmt    = f"{_total:,}"
    _can_admin    = _is_admin()
    _cfg_link     = '<a href="/settings/leaks" class="btn btn-ghost btn-sm">⚙️ Config Leaks</a>' if _can_admin else ''
    html = f"""
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
  <div>
    <h2 style="font-size:20px;font-weight:700;color:var(--text)">🔐 Credential Leak Search</h2>
    <p style="color:var(--muted);font-size:13px">Search across <strong>{_total_fmt}</strong> indexed records in <strong>{_dir_count}</strong> data source(s). Authorised security use only.</p>
  </div>
  {_cfg_link}
</div>

<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px">
  <div style="display:flex;gap:10px;align-items:center">
    <input id="leak-q" type="text" class="form-control" placeholder="Search by email, domain, or username…" style="flex:1;font-size:15px;padding:10px 14px" autocomplete="off" autofocus>
    <button class="btn btn-primary" onclick="leakSearch()" style="padding:10px 20px">🔍 Search</button>
  </div>
  <p style="color:var(--muted);font-size:12px;margin-top:8px">Examples: <code>@example.com</code> · <code>alice@</code> · <code>john.doe</code></p>
</div>

<div id="leak-status" style="display:none;color:var(--muted);font-size:13px;margin-bottom:10px"></div>
<div id="leak-results"></div>

<script>
document.getElementById('leak-q').addEventListener('keydown', function(e) {{
  if (e.key === 'Enter') leakSearch();
}});
function leakSearch() {{
  var q = document.getElementById('leak-q').value.trim();
  if (!q || q.length < 3) {{
    document.getElementById('leak-status').style.display = 'block';
    document.getElementById('leak-status').textContent = 'Enter at least 3 characters.';
    return;
  }}
  var st = document.getElementById('leak-status');
  var res = document.getElementById('leak-results');
  st.style.display = 'block';
  st.textContent = '⏳ Searching…';
  res.innerHTML = '';
  fetch('/api/leaks/search', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{q: q, limit: 500}})
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (!d.ok) {{
      st.textContent = '❌ ' + (d.error || 'Search failed');
      return;
    }}
    var hits = d.count;
    var cap  = d.capped ? ' (capped at 500 - refine query)' : '';
    st.textContent = hits + ' result(s) for "' + d.query + '"' + cap;
    if (hits === 0) {{ res.innerHTML = '<p style="color:var(--muted)">No records found.</p>'; return; }}
    var rows = '';
    d.results.forEach(function(line) {{
      var parts  = line.split(':');
      var email  = parts[0] || '';
      var pass   = parts.slice(1).join(':') || '';
      var eid    = 'pw-' + Math.random().toString(36).slice(2);
      rows += '<tr>'
        + '<td style="font-family:monospace;font-size:13px">' + escHtml(email) + '</td>'
        + '<td><span id="' + eid + '" style="filter:blur(4px);cursor:pointer;font-family:monospace;font-size:13px" '
        +   'onclick="document.getElementById(\\'' + eid + '\\').style.filter=\\'none\\'" title="Click to reveal">'
        +   escHtml(pass) + '</span></td>'
        + '</tr>';
    }});
    res.innerHTML = '<table class="table"><thead><tr><th>Email</th><th>Password (click to reveal)</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }}).catch(function() {{ st.textContent = '❌ Network error'; }});
}}
function escHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}
</script>"""
    _audit("view_leaks")
    return _base("Search Leaks", html, "leaks")


def _leaks_server_call(method, path, payload=None, timeout=30):
    """Call the remote leaks server. Returns (dict, http_status) or raises."""
    import urllib.request as _ureq, urllib.error as _uerr
    srv_url = (_get_setting("leaks_server_url","") or "").rstrip("/")
    srv_key = _get_setting("leaks_server_key","") or ""
    if not srv_url or not srv_key:
        return None, 0
    url  = srv_url + path
    body = json.dumps(payload or {}).encode()
    req  = _ureq.Request(url, data=body if method != "GET" else None, method=method)
    req.add_header("X-Leaks-Key", srv_key)
    req.add_header("Content-Type", "application/json")
    try:
        with _ureq.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()), r.status
    except _uerr.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"ok": False, "error": str(e)}, e.code
    except Exception as e:
        return {"ok": False, "error": str(e)}, 0

@app.route("/api/leaks/search", methods=["POST"])
@require_api_auth
def api_leaks_search():
    if not _analyst_can("leaks"):
        return jsonify({"ok": False, "error": "Access denied"}), 403
    data  = request.json or {}
    q     = data.get("q", "").strip()
    limit = min(int(data.get("limit", 200)), 1000)
    if not q or len(q) < 3:
        return jsonify({"ok": False, "error": "Query too short (minimum 3 characters)"}), 400

    # ── Try remote leaks server first ────────────────────────────────────────
    srv_url = (_get_setting("leaks_server_url","") or "").strip()
    if srv_url:
        resp, status = _leaks_server_call("POST", "/api/search", {"q": q, "limit": limit})
        if resp is None:
            return jsonify({"ok": False, "error": "Leaks server not configured"}), 503
        _audit("search_leaks", detail=f"q={q} via=server hits={resp.get('count',0)}")
        return jsonify(resp), (status or 200)

    # ── Fallback: local search ───────────────────────────────────────────────
    import os as _os
    _script_dir   = _os.path.dirname(_os.path.abspath(__file__))
    _builtin_data = _os.path.join(_script_dir, "leaks", "data")
    _extra_dirs   = json.loads(_get_setting("leak_directories", "[]") or "[]")
    _all_dirs     = [_builtin_data] + [d for d in _extra_dirs if d and _os.path.isdir(d)]
    q_lower = q.lower()
    results = []
    capped  = False
    for ddir in _all_dirs:
        if not _os.path.isdir(ddir):
            continue
        for fname in sorted(_os.listdir(ddir)):
            if not fname.endswith(".txt"):
                continue
            fpath = _os.path.join(ddir, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.rstrip()
                        if not line:
                            continue
                        if q_lower in line.lower():
                            results.append(line)
                            if len(results) >= limit:
                                capped = True
                                break
            except Exception:
                pass
            if capped:
                break
        if capped:
            break
    _audit("search_leaks", detail=f"q={q} via=local hits={len(results)}")
    return jsonify({"ok": True, "query": q, "count": len(results),
                    "results": results, "capped": capped})


# ═════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/report/scan/<scan_id>")
@require_login
def report_scan(scan_id):
    import html as _html
    uid  = flask_session["uid"]
    scan = db.one("SELECT * FROM osint_scans WHERE id=?", (scan_id,))
    if not scan:
        return "Scan not found", 404
    # Admin can view any scan; standard users only their own
    if not _is_admin() and scan.get("user_id") != uid:
        return "Access denied", 403
    # Soft-deleted scans are not accessible to the user who deleted them
    if not _is_admin() and scan.get("deleted_by_user"):
        return "This scan has been deleted.", 410
    findings= db.get_findings(scan_id, limit=1000)
    traffic = db.get_traffic(scan_id, limit=200)
    sev_summary = {}
    for f in findings:
        s = f["severity"]
        sev_summary[s] = sev_summary.get(s,0)+1

    finds_html = ""
    for f in findings:
        sev       = f.get("severity","info")
        c         = _severity_color(sev)
        ev        = _html.escape(str(f.get("evidence","") or ""))
        url       = str(f.get("url","") or "")
        url_esc   = _html.escape(url, quote=True)
        mod       = _html.escape(str(f.get("module","") or ""))
        title_esc = _html.escape(str(f.get("title","") or ""))
        desc_esc  = _html.escape(str(f.get("description","") or ""))
        raw_poc   = ""
        try:
            rd = json.loads(f.get("raw_data","{}") or "{}")
            if rd:
                raw_poc = _html.escape(json.dumps(rd, indent=2)[:1000])
        except Exception:
            pass
        # Determine POC WHERE/HOW from module and url
        poc_where = _html.escape(url[:400]) if url else ("Target: " + _html.escape(str(scan.get('target','') or '')))
        poc_how   = f"Module: {mod} | Technique: OSINT reconnaissance | Severity: {sev.upper()}"
        # Pre-compute conditional blocks (avoids backslash-in-f-string for Python < 3.12)
        raw_poc_div = (
            '<div style="margin-top:8px;padding:6px 8px;background:#f1f5f9;border-radius:4px;'
            'border:1px solid #e2e8f0;color:#475569;white-space:pre-wrap;word-break:break-all;'
            'font-size:10px"><span style="color:#94a3b8">Raw Data:</span>\n' + raw_poc + '</div>'
        ) if raw_poc else ''
        url_link_div = (
            '<div style="margin-top:6px"><a href="' + url_esc +
            '" style="color:#0066cc;font-size:10px">🔗 ' + _html.escape(url[:120]) + '</a></div>'
        ) if url else ''
        finds_html += f"""
        <div style="border-left:4px solid {c};padding:12px 16px;margin-bottom:14px;
          background:#f8f9fa;border-radius:0 8px 8px 0;page-break-inside:avoid">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="background:{c}22;color:{c};font-size:11px;font-weight:700;
              padding:2px 8px;border-radius:3px;border:1px solid {c}44">{sev.upper()}</span>
            <span style="font-size:11px;color:#666;font-family:monospace">{mod}</span>
          </div>
          <div style="font-size:14px;font-weight:700;margin:6px 0 4px;color:#111">{title_esc}</div>
          <div style="font-size:12px;color:#444;margin-bottom:10px;line-height:1.5">{desc_esc}</div>
          <!-- PoC Block -->
          <div style="background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px;font-family:monospace;font-size:11px">
            <div style="font-size:9px;color:#94a3b8;letter-spacing:.8px;text-transform:uppercase;
              margin-bottom:8px;border-bottom:1px solid #e2e8f0;padding-bottom:5px">Proof of Concept</div>
            <table style="width:100%;border-collapse:collapse">
              <tr>
                <td style="color:#64748b;font-size:10px;padding:3px 8px 3px 0;vertical-align:top;white-space:nowrap;font-weight:700">📍 WHERE</td>
                <td style="color:#4f46e5;word-break:break-all;padding:3px 0">{poc_where}</td>
              </tr>
              <tr>
                <td style="color:#64748b;font-size:10px;padding:3px 8px 3px 0;vertical-align:top;white-space:nowrap;font-weight:700">⚙️ HOW</td>
                <td style="color:#b45309;padding:3px 0">{poc_how}</td>
              </tr>
              <tr>
                <td style="color:#64748b;font-size:10px;padding:3px 8px 3px 0;vertical-align:top;white-space:nowrap;font-weight:700">🔍 WHAT</td>
                <td style="color:#111;white-space:pre-wrap;word-break:break-all;padding:3px 0">{ev or '(no evidence recorded)'}</td>
              </tr>
            </table>
            {raw_poc_div}
            {url_link_div}
          </div>
        </div>"""

    sev_rows = "".join(f"<tr><td><strong>{s}</strong></td><td style='color:{_severity_color(s)}'>{c}</td></tr>"
                       for s,c in sev_summary.items())

    report = f"""<!DOCTYPE html><html><head><meta charset=UTF-8>
<title>FEROXSEI OSINT Report - {scan['target']}</title>
<style>
body{{font-family:Inter,sans-serif;color:#222;background:#fff;margin:0;padding:0}}
.header{{background:#060b14;color:#00d4ff;padding:32px 40px}}
.header h1{{font-size:24px;margin:0;font-family:monospace}}
.header p{{color:#4a6080;margin:6px 0 0}}
.body{{padding:32px 40px;max-width:1000px}}
h2{{font-size:16px;border-bottom:2px solid #eee;padding-bottom:6px;color:#333}}
table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
th{{background:#f0f4f8;padding:8px 12px;text-align:left;font-size:12px;text-transform:uppercase}}
td{{padding:8px 12px;border-bottom:1px solid #eee;font-size:13px}}
.meta{{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:20px}}
.meta-item{{background:#f8f9fa;padding:10px 14px;border-radius:6px}}
.meta-label{{font-size:10px;text-transform:uppercase;color:#666;letter-spacing:1px}}
.meta-value{{font-size:18px;font-weight:700;color:#333}}
</style></head><body>
<div class="header">
  <h1>⬡ FEROXSEI OSINT - Intelligence Report</h1>
  <p>Target: {scan['target']} · Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
</div>
<div class="body">
  <div class="meta">
    <div class="meta-item"><div class="meta-label">Status</div><div class="meta-value">{scan.get('status','').upper()}</div></div>
    <div class="meta-item"><div class="meta-label">Total Findings</div><div class="meta-value">{len(findings)}</div></div>
    <div class="meta-item"><div class="meta-label">Scan Type</div><div class="meta-value">{scan.get('scan_type','osint').upper()}</div></div>
    <div class="meta-item"><div class="meta-label">Traffic Events</div><div class="meta-value">{len(traffic)}</div></div>
  </div>
  <h2>Findings Summary</h2>
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>{sev_rows}</tbody></table>
  <h2>Detailed Findings</h2>
  {finds_html}
  <hr style="margin:24px 0;border:none;border-top:1px solid #eee">
  <p style="font-size:11px;color:#999;text-align:center">
    Generated by FEROXSEI OSINT Intelligence Platform · {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
    All findings are observational. Treat inferred relationships as hypotheses requiring supporting evidence.
  </p>
</div></body></html>"""
    resp = make_response(report)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/report/investigation/<inv_id>")
@require_login
def report_investigation(inv_id):
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    if not inv:
        return "Investigation not found", 404
    if not _is_admin() and inv["user_id"] != uid:
        return "Access denied", 403

    # All non-deleted scans in this investigation
    scans = db.rows(
        "SELECT * FROM osint_scans WHERE investigation_id=? AND COALESCE(deleted_by_user,0)=0 ORDER BY created_at ASC",
        (inv_id,))

    if not scans:
        return "<html><body style='font-family:sans-serif;padding:40px'><h2>No scans in this investigation.</h2><a href='/investigation/"+inv_id+"'>← Back</a></body></html>"

    all_findings = []
    scan_summaries = []
    for s in scans:
        finds = db.get_findings(s["id"], limit=1000)
        sev_map = {}
        for f in finds:
            sev_map[f["severity"]] = sev_map.get(f["severity"], 0) + 1
        scan_summaries.append({"scan": s, "findings": finds, "sev_map": sev_map})
        all_findings.extend(finds)

    # Overall severity counts
    total_sev = {}
    for f in all_findings:
        total_sev[f["severity"]] = total_sev.get(f["severity"], 0) + 1

    sev_colors = {"critical":"#c0392b","high":"#e74c3c","medium":"#f39c12","low":"#27ae60","info":"#2980b9"}

    # Summary table rows
    summary_rows = ""
    for ss in scan_summaries:
        s   = ss["scan"]
        sm  = ss["sev_map"]
        total = len(ss["findings"])
        pills = " ".join(f'<span style="background:{sev_colors.get(sv,"#888")};color:#fff;padding:2px 6px;border-radius:3px;font-size:11px">{sv}: {c}</span>'
                         for sv, c in sm.items())
        summary_rows += f"""<tr>
          <td><strong>{_html.escape(s.get('target',''))}</strong><br><small style='color:#666'>{_html.escape(s.get('scan_name',''))}</small></td>
          <td>{_html.escape(s.get('status',''))}</td>
          <td>{total}</td>
          <td>{pills or '<span style="color:#999">-</span>'}</td>
          <td style='font-size:11px;color:#666'>{str(s.get('created_at',''))[:16]}</td>
        </tr>"""

    # All findings grouped by severity
    findings_by_sev = {}
    for f in all_findings:
        sv = f.get("severity","info")
        findings_by_sev.setdefault(sv, []).append(f)

    finds_html = ""
    for sv in ["critical","high","medium","low","info"]:
        bucket = findings_by_sev.get(sv, [])
        if not bucket:
            continue
        finds_html += f'<h2 style="color:{sev_colors.get(sv,"#333")};border-bottom:2px solid {sev_colors.get(sv,"#ccc")};padding-bottom:6px;margin-top:30px">{sv.upper()} ({len(bucket)})</h2>'
        for f in bucket:
            ev  = _html.escape(str(f.get("evidence","") or ""))
            url = str(f.get("url","") or "")
            url_esc = _html.escape(url, quote=True)
            mod = _html.escape(str(f.get("module","") or ""))
            title_esc = _html.escape(str(f.get("title","") or ""))
            desc_esc  = _html.escape(str(f.get("description","") or ""))
            # Scan target for context
            scan_target = ""
            for ss in scan_summaries:
                if any(ff["id"] == f["id"] for ff in ss["findings"]):
                    scan_target = _html.escape(ss["scan"].get("target",""))
                    break
            raw_poc = ""
            try:
                rd = json.loads(f.get("raw_data","{}") or "{}")
                poc = rd.get("poc") or rd.get("proof") or rd.get("payload")
                if poc:
                    raw_poc = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap">{_html.escape(str(poc))}</pre>'
            except Exception:
                pass
            url_link = f'<div style="margin-top:6px"><a href="{url_esc}" target="_blank" style="font-size:11px;color:#2980b9">{url_esc}</a></div>' if url else ""
            finds_html += f"""
            <div style="border:1px solid {sev_colors.get(sv,'#ccc')};border-left:4px solid {sev_colors.get(sv,'#ccc')};border-radius:4px;padding:14px;margin-bottom:12px;background:#fafafa">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px">
                <strong style="font-size:14px">{title_esc}</strong>
                <div>
                  <span style="background:{sev_colors.get(sv,'#888')};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">{sv.upper()}</span>
                  <span style="background:#eee;color:#555;padding:2px 8px;border-radius:3px;font-size:11px;margin-left:4px">{mod}</span>
                  {f'<span style="background:#d0f0ff;color:#2980b9;padding:2px 8px;border-radius:3px;font-size:11px;margin-left:4px">{scan_target}</span>' if scan_target else ""}
                </div>
              </div>
              <p style="color:#555;font-size:13px;margin:8px 0 0">{desc_esc}</p>
              {url_link}
              {f'<pre style="background:#f5f5f5;padding:10px;border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap;margin-top:8px">{ev}</pre>' if ev else ''}
              {raw_poc}
            </div>"""

    sev_summary_rows = "".join(
        f"<tr><td style='color:{sev_colors.get(sv,'#333')}'><strong>{sv.upper()}</strong></td><td>{c}</td></tr>"
        for sv, c in sorted(total_sev.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99)
    )

    report = f"""<!DOCTYPE html><html><head><meta charset=UTF-8>
<title>FEROXSEI OSINT Report - {_html.escape(inv['title'])}</title>
<style>
body{{font-family:Inter,sans-serif;color:#222;background:#fff;margin:0;padding:0}}
.header{{background:#060b14;color:#00d4ff;padding:32px 40px}}
.header h1{{font-size:24px;margin:0;font-family:monospace}}
.header p{{color:#4a6080;margin:6px 0 0}}
.body{{padding:32px 40px;max-width:1100px}}
h2{{font-size:16px;padding-bottom:6px;color:#333}}
table{{width:100%;border-collapse:collapse;margin-bottom:16px}}
th{{background:#f0f4f8;padding:8px 12px;text-align:left;font-size:12px;text-transform:uppercase}}
td{{padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top}}
.stat-box{{display:inline-block;background:#f0f4f8;border-radius:6px;padding:14px 24px;margin:0 10px 12px 0;text-align:center}}
.stat-num{{font-size:28px;font-weight:700;color:#060b14}}
.stat-lbl{{font-size:12px;color:#666;margin-top:2px}}
@media print{{.no-print{{display:none}}}}
</style></head><body>
<div class="header">
  <div class="no-print" style="margin-bottom:16px">
    <a href="/investigation/{inv_id}" style="color:#00d4ff;font-size:13px">← Back to Investigation</a>
    &nbsp;&nbsp;
    <button onclick="window.print()" style="background:#00d4ff;color:#060b14;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-weight:600">🖨 Print / Save PDF</button>
  </div>
  <h1>📋 FEROXSEI OSINT - Investigation Report</h1>
  <p>{_html.escape(inv['title'])} &nbsp;·&nbsp; Generated {_now()[:16]}</p>
  {f'<p style="color:#4a6080;font-size:12px">{_html.escape(inv.get("description",""))}</p>' if inv.get("description") else ''}
</div>
<div class="body">
  <h2 style="border-bottom:2px solid #eee;padding-bottom:6px">Executive Summary</h2>
  <div style="margin:16px 0">
    <div class="stat-box"><div class="stat-num">{len(scans)}</div><div class="stat-lbl">Scans</div></div>
    <div class="stat-box"><div class="stat-num">{len(all_findings)}</div><div class="stat-lbl">Total Findings</div></div>
    {"".join(f'<div class="stat-box"><div class="stat-num" style="color:{sev_colors.get(sv,"#333")}">{c}</div><div class="stat-lbl">{sv.capitalize()}</div></div>' for sv,c in sorted(total_sev.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99))}
  </div>

  <h2 style="border-bottom:2px solid #eee;padding-bottom:6px;margin-top:24px">Scan Summary</h2>
  <table>
    <thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Severity Breakdown</th><th>Date</th></tr></thead>
    <tbody>{summary_rows}</tbody>
  </table>

  <h2 style="border-bottom:2px solid #eee;padding-bottom:6px;margin-top:24px">Severity Summary</h2>
  <table style="max-width:320px">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{sev_summary_rows}</tbody>
  </table>

  <div style="margin-top:16px">{finds_html}</div>
</div>
</body></html>"""
    resp = make_response(report)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# ═════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/api/scan/<scan_id>/status")
@require_api_auth
def api_scan_status(scan_id):
    s = db.get_scan(scan_id)
    if not s:
        return jsonify({"error":"not found"}),404
    return jsonify({"status":s["status"],"progress":s["progress"],
                    "current_module":s.get("current_module","")})

@app.route("/api/scan/<scan_id>/start", methods=["POST"])
@require_api_auth
def api_scan_start(scan_id):
    s = db.get_scan(scan_id)
    if not s:
        return jsonify({"error":"not found"}),404
    if s["status"] in ("running",):
        return jsonify({"ok":False,"error":"already running"})
    engine.start_scan(scan_id)
    db.upd("osint_scans",{"status":"running","started_at":_now()},"id=?",(scan_id,))
    return jsonify({"ok":True})

@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
@require_api_auth
def api_scan_stop(scan_id):
    engine.stop_scan(scan_id)
    db.upd("osint_scans",{"status":"stopped","completed_at":_now()},"id=?",(scan_id,))
    return jsonify({"ok":True})

@app.route("/api/scan/<scan_id>/delete", methods=["POST"])
@require_api_auth
def api_scan_delete(scan_id):
    uid      = flask_session["uid"]
    is_admin = _is_admin()
    # Admin can delete any scan; standard users can only touch their own
    if is_admin:
        s = db.one("SELECT * FROM osint_scans WHERE id=?", (scan_id,))
    else:
        s = db.one("SELECT * FROM osint_scans WHERE id=? AND user_id=?", (scan_id, uid))
    if not s:
        return jsonify({"ok": False, "error": "not found"}), 404
    engine.stop_scan(scan_id)
    if is_admin:
        # Hard delete - permanently remove scan + all associated data
        db.exec("DELETE FROM osint_findings WHERE scan_id=?", (scan_id,))
        db.exec("DELETE FROM osint_traffic WHERE scan_id=?", (scan_id,))
        db.exec("DELETE FROM osint_task_logs WHERE scan_id=?", (scan_id,))
        db.exec("DELETE FROM osint_scans WHERE id=?", (scan_id,))
        _audit("delete_scan_permanent", "scan", scan_id, s.get("target", ""))
        return jsonify({"ok": True, "soft": False})
    else:
        # Soft delete - hide from user, admin still sees it
        db.upd("osint_scans", {"deleted_by_user": 1}, "id=?", (scan_id,))
        _audit("delete_scan_soft", "scan", scan_id, s.get("target", ""))
        return jsonify({"ok": True, "soft": True})

@app.route("/api/scan/<scan_id>/restore", methods=["POST"])
@require_api_auth
def api_scan_restore(scan_id):
    uid = flask_session["uid"]
    s   = db.one("SELECT * FROM osint_scans WHERE id=? AND user_id=?", (scan_id, uid))
    if not s:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.upd("osint_scans", {"deleted_by_user": 0}, "id=?", (scan_id,))
    _audit("restore_scan", "scan", scan_id, s.get("target", ""))
    return jsonify({"ok": True})

@app.route("/api/investigation/<inv_id>/delete", methods=["POST"])
@require_api_auth
def api_investigation_delete(inv_id):
    uid      = flask_session["uid"]
    is_admin = _is_admin()
    if is_admin:
        inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    else:
        inv = db.one("SELECT * FROM investigations WHERE id=? AND user_id=?", (inv_id, uid))
    if not inv:
        return jsonify({"ok": False, "error": "not found"}), 404

    if is_admin:
        # Hard delete - wipe everything: scans, findings, traffic, logs, notes, entities, rels
        scan_ids = [s["id"] for s in db.rows("SELECT id FROM osint_scans WHERE investigation_id=?", (inv_id,))]
        for sid in scan_ids:
            engine.stop_scan(sid)
            db.exec("DELETE FROM osint_findings WHERE scan_id=?", (sid,))
            db.exec("DELETE FROM osint_traffic WHERE scan_id=?", (sid,))
            db.exec("DELETE FROM osint_task_logs WHERE scan_id=?", (sid,))
        db.exec("DELETE FROM osint_scans WHERE investigation_id=?", (inv_id,))
        db.exec("DELETE FROM analyst_notes WHERE investigation_id=?", (inv_id,))
        db.exec("DELETE FROM investigation_replay WHERE investigation_id=?", (inv_id,))
        db.exec("DELETE FROM entities WHERE investigation_id=?", (inv_id,))
        db.exec("DELETE FROM entity_relationships WHERE investigation_id=?", (inv_id,))
        db.exec("DELETE FROM investigations WHERE id=?", (inv_id,))
        _audit("delete_investigation_permanent", "investigation", inv_id, inv.get("title", ""))
        return jsonify({"ok": True, "soft": False})
    else:
        # Soft delete - just flag it hidden for the user
        db.upd("investigations", {"deleted_by_user": 1}, "id=?", (inv_id,))
        _audit("delete_investigation_soft", "investigation", inv_id, inv.get("title", ""))
        return jsonify({"ok": True, "soft": True})

@app.route("/api/investigation/<inv_id>/restore", methods=["POST"])
@require_api_auth
def api_investigation_restore(inv_id):
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=? AND user_id=?", (inv_id, uid))
    if not inv:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.upd("investigations", {"deleted_by_user": 0}, "id=?", (inv_id,))
    _audit("restore_investigation", "investigation", inv_id, inv.get("title", ""))
    return jsonify({"ok": True})

@app.route("/api/investigation/<inv_id>/graph", methods=["GET"])
@require_login
def api_investigation_graph(inv_id):
    """Return entity graph data for an investigation.
    Optional ?scan_id= to filter to entities from one scan only."""
    uid = flask_session["uid"]
    inv = db.one("SELECT id FROM investigations WHERE id=?", (inv_id,))
    if not inv:
        return jsonify({"ok": False, "error": "not found"}), 404
    if not _is_admin():
        inv_full = db.one("SELECT user_id FROM investigations WHERE id=?", (inv_id,))
        if inv_full and inv_full["user_id"] != uid:
            return jsonify({"ok": False, "error": "forbidden"}), 403
    scan_id = request.args.get("scan_id", "").strip()
    if scan_id:
        entities = db.rows(
            "SELECT * FROM entities WHERE investigation_id=? AND "
            "EXISTS (SELECT 1 FROM json_each(scan_ids) WHERE value=?)",
            (inv_id, scan_id))
    else:
        entities = db.rows(
            "SELECT * FROM entities WHERE investigation_id=? ORDER BY confidence DESC",
            (inv_id,))
    entity_ids = {e["id"] for e in entities}
    all_rels = db.rows("SELECT * FROM entity_relationships WHERE investigation_id=?", (inv_id,))
    rels = [r for r in all_rels
            if r["source_id"] in entity_ids and r["target_id"] in entity_ids]
    nodes = [{"id": e["id"], "label": e["value"][:30], "type": e["entity_type"],
              "confidence": e["confidence"],
              "contradictions": e.get("contradiction_count", 0)}
             for e in entities]
    links = [{"source": r["source_id"], "target": r["target_id"],
              "type": r["relationship_type"], "confidence": r.get("confidence", 50)}
             for r in rels]
    return jsonify({"ok": True, "nodes": nodes, "links": links,
                    "scan_id": scan_id, "total": len(nodes)})


@app.route("/api/investigation/<inv_id>/rebuild-graph", methods=["POST"])
@require_login
def api_rebuild_graph(inv_id):
    """Re-extract entities from ALL scans in an investigation (manual trigger)."""
    uid  = flask_session["uid"]
    inv  = db.one("SELECT * FROM investigations WHERE id=? AND user_id=?", (inv_id, uid))
    if not inv:
        return jsonify({"ok": False, "error": "not found"}), 404
    # Clear existing entities + rels for this investigation so we start fresh
    db.exec("DELETE FROM entities WHERE investigation_id=?", (inv_id,))
    db.exec("DELETE FROM entity_relationships WHERE investigation_id=?", (inv_id,))
    scans = db.rows("SELECT * FROM osint_scans WHERE investigation_id=?", (inv_id,))
    total_e = total_r = 0
    for s in scans:
        target_types = []
        try:
            extra = json.loads(s.get("notes") or "{}")
            target_types = extra.get("target_types", ["domain"])
        except Exception:
            target_types = ["domain"]
        tt = target_types[0] if target_types else "domain"
        try:
            ne, nr = engine._extract_entities_from_scan(
                s["id"], inv_id, s["target"], tt)
            total_e += ne; total_r += nr
        except Exception as ex:
            pass
    _audit("rebuild_graph", "investigation", inv_id, f"{total_e} entities, {total_r} rels")
    return jsonify({"ok": True, "entities": total_e, "relationships": total_r})


@app.route("/scan/<scan_id>/rescan")
@require_login
def rescan(scan_id):
    """Clone a completed scan and start it fresh."""
    uid = flask_session["uid"]
    s   = db.one("SELECT * FROM osint_scans WHERE id=? AND user_id=?",(scan_id,uid))
    if not s:
        return redirect("/investigations")
    new_id = str(uuid.uuid4())
    db.ins("osint_scans", {
        "id": new_id, "user_id": uid,
        "investigation_id": s.get("investigation_id",""),
        "scan_name": (s.get("scan_name","") or "") + " [Rescan]",
        "target": s["target"], "scan_type": s.get("scan_type","osint"),
        "modules": s.get("modules","{}"),
        "status": "running", "progress": 0,
        "crawl_depth": s.get("crawl_depth",2),
        "file_types": s.get("file_types","*"),
        "use_tor": s.get("use_tor",0),
        "notes": s.get("notes","{}"),
        "source_path": s.get("source_path",""),
        "created_at": _now(), "started_at": _now()
    })
    engine.start_scan(new_id)
    _audit("rescan","scan",new_id,s["target"])
    inv_id = s.get("investigation_id","")
    if inv_id:
        _replay_step(inv_id,"rescan",f"Rescan of {s['target']} started",
                     {"original_scan":scan_id,"new_scan":new_id},
                     flask_session["username"])
    return redirect(f"/scan/{new_id}")

# ─────────────────────────────────────────────────────────────────────────────
# EDIT SCAN
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/scan/<scan_id>/edit", methods=["GET","POST"])
@require_login
def edit_scan(scan_id):
    if not _analyst_can("scans"):
        return redirect(f"/scan/{scan_id}")
    uid  = flask_session["uid"]
    scan = db.one("SELECT * FROM osint_scans WHERE id=?", (scan_id,))
    if not scan:
        return redirect("/investigations")
    if not _is_admin() and scan.get("user_id") != uid:
        return redirect("/investigations")
    # Don't allow editing a running scan
    if scan.get("status") == "running":
        return redirect(f"/scan/{scan_id}")

    if request.method == "POST":
        mods_sel = request.form.getlist("modules")
        mods_cfg = {m: (m in mods_sel) for m,_,_,_ in _MODULES_META}
        api_cfg  = json.loads(scan.get("notes","{}") or "{}")

        # ── Target types (same logic as new_scan) ─────────────────────────────
        raw_types    = [t.strip() for t in
                        request.form.get("target_types","domain").split(",")
                        if t.strip()]
        if not raw_types:
            raw_types = ["domain"]
        adv_username = bool(request.form.get("adv_username"))
        adv_email    = bool(request.form.get("adv_email"))
        def _adv_target(json_key, domain=""):
            raw = request.form.get(json_key, "").strip()
            try:
                users = json.loads(raw) if raw else []
                if users:
                    u = users[0]
                    name = f"{u.get('first','')} {u.get('last','')}".strip()
                    return f"{name}@{domain}" if domain else name
            except Exception:
                pass
            return domain or ""
        _img_file_obj  = request.files.get("target_image")
        _img_filename  = (_img_file_obj.filename or "").strip() if _img_file_obj else ""
        type_values = {
            "domain":   request.form.get("target_domain","").strip(),
            "username": (request.form.get("target_username","").strip() if not adv_username
                         else _adv_target("name_users_json")),
            "email":    (request.form.get("target_email","").strip() if not adv_email
                         else _adv_target("email_users_json",
                                          request.form.get("email_domain","").strip())),
            "phone":    request.form.get("target_phone","").strip(),
            "ip":       request.form.get("target_ip","").strip(),
            "string":   request.form.get("target_string","").strip(),
            "image":    _img_filename or api_cfg.get("image", scan.get("target", "")),
        }
        new_target = ""
        for tt in raw_types:
            if type_values.get(tt):
                new_target = type_values[tt]; break
        if not new_target:
            new_target = request.form.get("target","").strip() or scan["target"]

        api_cfg["target_types"] = raw_types
        api_cfg["target_type"]  = raw_types[0]
        for tt in raw_types:
            if type_values.get(tt):
                api_cfg[tt] = type_values[tt]

        if adv_username:
            api_cfg["adv_username"] = True
            raw_un = request.form.get("name_users_json","").strip()
            try:
                name_users = json.loads(raw_un) if raw_un else []
            except Exception:
                name_users = []
            if not name_users:
                nf = request.form.get("name_first","").strip()
                nl = request.form.get("name_last","").strip()
                if nf or nl:
                    name_users = [{"first": nf, "middle": request.form.get("name_middle","").strip(), "last": nl}]
            api_cfg["name_users"]  = name_users
            if name_users:
                api_cfg["name_first"]  = name_users[0].get("first","")
                api_cfg["name_middle"] = name_users[0].get("middle","")
                api_cfg["name_last"]   = name_users[0].get("last","")
        else:
            for k in ["adv_username","name_users","name_first","name_middle","name_last"]:
                api_cfg.pop(k, None)
        if adv_email:
            api_cfg["adv_email"]    = True
            raw_em = request.form.get("email_users_json","").strip()
            try:
                email_users = json.loads(raw_em) if raw_em else []
            except Exception:
                email_users = []
            if not email_users:
                ef = request.form.get("email_first","").strip()
                el = request.form.get("email_last","").strip()
                if ef or el:
                    email_users = [{"first": ef, "middle": request.form.get("email_middle","").strip(), "last": el}]
            api_cfg["email_users"]  = email_users
            api_cfg["email_domain"] = request.form.get("email_domain","").strip()
            if email_users:
                api_cfg["email_first"]  = email_users[0].get("first","")
                api_cfg["email_middle"] = email_users[0].get("middle","")
                api_cfg["email_last"]   = email_users[0].get("last","")
        else:
            for k in ["adv_email","email_users","email_first","email_middle","email_last","email_domain"]:
                api_cfg.pop(k, None)

        # ── API keys ──────────────────────────────────────────────────────────
        for k in ["github_token","shodan_key","anthropic_key","openai_key",
                  "virustotal_key","hunter_key","hibp_key","otx_key","abuseipdb_key"]:
            v = request.form.get(k,"").strip()
            if v:
                api_cfg[k] = v
        if request.form.get("wayback_limit"):
            api_cfg["wayback_limit"] = int(request.form.get("wayback_limit",500))
        if request.form.get("wayback_extensions"):
            api_cfg["wayback_extensions"] = request.form.get("wayback_extensions","").strip()

        # Image upload - save new file if provided, else keep existing path
        if "image" in raw_types and _img_file_obj and _img_filename:
            import os as _os
            _img_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "screenshots", "image_osint")
            _os.makedirs(_img_dir, exist_ok=True)
            _img_ext  = _os.path.splitext(_img_filename)[1].lower() or ".jpg"
            _img_save = _os.path.join(_img_dir, str(uuid.uuid4()) + _img_ext)
            _img_file_obj.save(_img_save)
            api_cfg["image_path"] = _img_save
            api_cfg["image"]      = _img_filename
            for _ctx_k in ["img_subject_name","img_username","img_email","img_phone","img_keyword"]:
                _v = request.form.get(_ctx_k,"").strip()
                if _v:
                    api_cfg[_ctx_k] = _v

        db.upd("osint_scans", {
            "target":      new_target,
            "scan_name":   request.form.get("scan_name","").strip(),
            "scan_type":   request.form.get("scan_type","osint"),
            "modules":     json.dumps(mods_cfg),
            "crawl_depth": int(request.form.get("crawl_depth",2)),
            "file_types":  request.form.get("file_types","*"),
            "use_tor":     1 if request.form.get("use_tor") else 0,
            "notes":       json.dumps(api_cfg),
            "source_path": request.form.get("source_path",""),
        }, "id=?", (scan_id,))
        _audit("edit_scan","scan",scan_id,scan["target"])
        if request.form.get("start_now"):
            db.upd("osint_scans",{"status":"running","started_at":_now(),"progress":0},"id=?",(scan_id,))
            engine.start_scan(scan_id)
        return redirect(f"/scan/{scan_id}")

    # ── GET - show pre-filled form ─────────────────────────────────────────────
    import html as _html
    saved_mods   = json.loads(scan.get("modules","{}") or "{}")
    api_cfg      = json.loads(scan.get("notes","{}") or "{}")
    wbl          = api_cfg.get("wayback_limit",500)
    wbe          = api_cfg.get("wayback_extensions",
                               "xls,xml,xlsx,json,pdf,sql,doc,docx,pptx,txt,git,zip,tar.gz,tgz,"
                               "bak,7z,rar,log,cache,secret,db,backup,yaml,gz,config,csv,md,env,"
                               "pem,key,pub,asc,passwd,htpasswd,dockerenv,tfstate")

    # Restore saved target types and per-type values
    saved_types  = api_cfg.get("target_types", ["domain"])
    if isinstance(saved_types, str):
        saved_types = [t.strip() for t in saved_types.split(",") if t.strip()]
    if not saved_types:
        saved_types = ["domain"]

    # Per-type saved values - fall back to scan["target"] for the primary type
    saved_vals = {
        "domain":   _html.escape(api_cfg.get("domain",   scan["target"] if "domain" in saved_types   else "")),
        "username": _html.escape(api_cfg.get("username", scan["target"] if "username" in saved_types else "")),
        "email":    _html.escape(api_cfg.get("email",    scan["target"] if "email" in saved_types    else "")),
        "phone":    _html.escape(api_cfg.get("phone",    scan["target"] if "phone" in saved_types    else "")),
        "ip":       _html.escape(api_cfg.get("ip",       scan["target"] if "ip" in saved_types       else "")),
        "string":   _html.escape(api_cfg.get("string",   scan["target"] if "string" in saved_types   else "")),
        "image":    _html.escape(api_cfg.get("image",    scan["target"] if "image" in saved_types    else "")),
    }

    # Generate module cards - filter by settings-enabled modules when configured
    _settings_enabled_mods = json.loads(_get_setting("default_modules","[]") or "[]")
    mod_cards = ""
    for mid, icon, name, desc in _MODULES_META:
        # If default_mods is configured, only show modules that are settings-enabled
        # (exception: always show modules that were explicitly selected in this saved scan)
        if _settings_enabled_mods and mid not in _settings_enabled_mods and not saved_mods.get(mid):
            continue
        checked   = "checked" if saved_mods.get(mid, True) else ""
        tgt_list  = " ".join(_MODULE_TARGET_TYPES.get(mid, ["domain"]))
        mod_cards += f"""
        <div class="module-card {'selected' if checked else ''}"
             data-targets="{tgt_list}" onclick="toggleMod(this)">
          <input type="checkbox" name="modules" value="{mid}" {checked} id="mod-{mid}">
          <div class="module-icon">{icon}</div>
          <div class="module-name">{name}</div>
          <div class="module-desc">{desc}</div>
        </div>"""

    tor_checked = "checked" if scan.get("use_tor") else ""
    sast_disp   = "block" if scan.get("scan_type") == "sast" else "none"
    scan_target_esc  = _html.escape(scan["target"])
    scan_name_esc    = _html.escape(scan.get("scan_name",""))
    source_path_esc  = _html.escape(scan.get("source_path",""))

    # Build type pill HTML - mark saved types as active
    def _pill(tt, icon_label):
        is_active = tt in saved_types
        row_vis   = "visible" if is_active else ""
        return (
            f'<label class="tt-pill {"active" if is_active else ""}" data-type="{tt}">'
            f'<input type="checkbox" name="_tt_{tt}" value="{tt}"'
            f'{"checked" if is_active else ""} style="display:none">'
            f'{icon_label}</label>',
            f'<div id="tt-{tt}" class="tt-input-row {row_vis}">'
        )

    # Advanced mode restore
    _adv_un  = bool(api_cfg.get("adv_username"))
    _adv_em  = bool(api_cfg.get("adv_email"))
    _nf  = _html.escape(api_cfg.get("name_first",""))
    _nm  = _html.escape(api_cfg.get("name_middle",""))
    _nl  = _html.escape(api_cfg.get("name_last",""))
    _ef  = _html.escape(api_cfg.get("email_first",""))
    _em  = _html.escape(api_cfg.get("email_middle",""))
    _el  = _html.escape(api_cfg.get("email_last",""))
    _ed  = _html.escape(api_cfg.get("email_domain",""))

    pills_html = ""
    inputs_html = ""
    pill_defs = [
        ("domain",   "🌐 Domain / URL"),
        ("username", "👤 Username / Handle"),
        ("email",    "📧 Email Address"),
        ("phone",    "📞 Phone Number"),
        ("ip",       "🖥️ IP Address"),
        ("string",   "🔍 Keyword / String"),
        ("image",    "🖼️ Image File"),
    ]
    placeholders = {
        "domain":   "example.com or https://target.io",
        "username": "john_doe  (no @ prefix needed)",
        "email":    "target@example.com",
        "phone":    "+1-555-0100 or 07911123456",
        "ip":       "192.168.1.1 or 2001:db8::1",
        "string":   "Acme Corp breach  /  leaked credentials",
        "image":    "upload a new image file",
    }
    _existing_image = _html.escape(api_cfg.get("image", scan["target"] if "image" in saved_types else ""))
    for tt, icon_label in pill_defs:
        pills_html += f'<div class="tt-pill {"active" if tt in saved_types else ""}" data-type="{tt}">{icon_label}</div> '
        row_vis     = "visible" if tt in saved_types else ""
        short_label = icon_label.split(" ",1)[1]

        if tt == "username":
            _un_adv_checked = "checked" if _adv_un else ""
            _un_simple_disp = "none" if _adv_un else ""
            _un_adv_disp    = "" if _adv_un else "none"
            inputs_html += f"""
<div id="tt-username" class="tt-input-row {row_vis}">
  <label style="display:flex;align-items:center;gap:8px">
    {short_label}
    <label style="display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer;
                  font-size:11px;font-weight:500;color:var(--primary)">
      <input type="checkbox" id="adv-username-toggle" name="adv_username" value="1"
             {_un_adv_checked} onchange="toggleAdvUsername(this.checked)"
             style="accent-color:var(--primary)">
      ⚙ Advanced (build from name)
    </label>
  </label>
  <div id="adv-username-simple" style="display:{_un_simple_disp}">
    <input type="text" name="target_username" id="target_username_simple"
           value="{saved_vals['username']}" placeholder="{placeholders['username']}"
           style="font-family:var(--mono);font-size:13px" {"disabled" if _adv_un else ""}>
  </div>
  <div id="adv-username-fields" style="display:{_un_adv_disp}">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
      <span style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">People to scan</span>
      <button type="button" onclick="addNameRow('un')"
        style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--primary);border-radius:4px;color:var(--primary);cursor:pointer">+ Add Person</button>
      <label style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);cursor:pointer">
        ⬆ Import CSV
        <input type="file" accept=".csv" style="display:none" onchange="importNameCsv(this,'un')">
      </label>
      <a href="/api/download-template?type=username" download="username_template.csv"
        style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);text-decoration:none">⬇ Template</a>
    </div>
    <div id="un-rows" style="margin-bottom:4px"></div>
    <input type="hidden" name="name_users_json" id="name-users-json">
    <div style="margin-top:5px;font-size:11px;color:var(--muted)">Generates usernames via
      <a href="/settings/username-patterns" target="_blank" style="color:var(--primary)">enabled patterns</a>.
      CSV: <code style="color:var(--primary)">first,middle,last</code>
    </div>
  </div>
</div>"""
        elif tt == "email":
            _em_adv_checked = "checked" if _adv_em else ""
            _em_simple_disp = "none" if _adv_em else ""
            _em_adv_disp    = "" if _adv_em else "none"
            inputs_html += f"""
<div id="tt-email" class="tt-input-row {row_vis}">
  <label style="display:flex;align-items:center;gap:8px">
    {short_label}
    <label style="display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer;
                  font-size:11px;font-weight:500;color:var(--primary)">
      <input type="checkbox" id="adv-email-toggle" name="adv_email" value="1"
             {_em_adv_checked} onchange="toggleAdvEmail(this.checked)"
             style="accent-color:var(--primary)">
      ⚙ Advanced (build from name)
    </label>
  </label>
  <div id="adv-email-simple" style="display:{_em_simple_disp}">
    <input type="email" name="target_email" id="target_email_simple"
           value="{saved_vals['email']}" placeholder="{placeholders['email']}"
           style="font-family:var(--mono);font-size:13px" {"disabled" if _adv_em else ""}>
  </div>
  <div id="adv-email-fields" style="display:{_em_adv_disp}">
    <div style="margin-bottom:10px">
      <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:3px">Domain <span style="color:var(--danger)">*</span> <span style="color:var(--muted)">(shared)</span></label>
      <input type="text" name="email_domain" id="email-domain-shared" value="{_ed}" placeholder="company.com"
             style="width:100%;max-width:300px;background:var(--bg2);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:13px">
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
      <span style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">Email targets</span>
      <button type="button" onclick="addNameRow('em')"
        style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--primary);border-radius:4px;color:var(--primary);cursor:pointer">+ Add Person</button>
      <label style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);cursor:pointer">
        ⬆ Import CSV
        <input type="file" accept=".csv" style="display:none" onchange="importNameCsv(this,'em')">
      </label>
      <a href="/api/download-template?type=email" download="email_template.csv"
        style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);text-decoration:none">⬇ Template</a>
    </div>
    <div id="em-rows" style="margin-bottom:4px"></div>
    <input type="hidden" name="email_users_json" id="email-users-json">
    <div style="margin-top:5px;font-size:11px;color:var(--muted)">
      CSV: <code style="color:var(--primary)">first,middle,last</code>
    </div>
  </div>
</div>"""
        elif tt == "image":
            _ctx_sn   = _html.escape(api_cfg.get("img_subject_name",""))
            _ctx_un   = _html.escape(api_cfg.get("img_username",""))
            _ctx_em   = _html.escape(api_cfg.get("img_email",""))
            _ctx_ph   = _html.escape(api_cfg.get("img_phone",""))
            _ctx_kw   = _html.escape(api_cfg.get("img_keyword",""))
            _cur_img_note = (
                '<div style="margin-bottom:8px;font-size:12px;color:var(--muted)">Current: '
                '<code style="color:var(--primary)">' + _existing_image + '</code>'
                ' - leave blank to keep</div>'
                if _existing_image else ""
            )
            inputs_html += (
                f'<div id="tt-image" class="tt-input-row {row_vis}">'
                f'<label>Image File</label>'
                + _cur_img_note +
                f'<input type="file" name="target_image" accept="image/*"'
                f' style="font-size:13px;padding:6px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);width:100%">'
                f'<div style="margin-top:8px;font-size:11px;color:var(--muted)">Optional context - improves DDG search + AI analysis</div>'
                f'<div class="form-row" style="margin-top:6px;gap:8px">'
                f'<div class="form-group"><label style="font-size:11px">Subject Name</label>'
                f'<input type="text" name="img_subject_name" value="{_ctx_sn}" placeholder="John Doe"></div>'
                f'<div class="form-group"><label style="font-size:11px">Username / Handle</label>'
                f'<input type="text" name="img_username" value="{_ctx_un}" placeholder="@john_doe"></div>'
                f'</div>'
                f'<div class="form-row" style="margin-top:0;gap:8px">'
                f'<div class="form-group"><label style="font-size:11px">Email</label>'
                f'<input type="text" name="img_email" value="{_ctx_em}" placeholder="john@example.com"></div>'
                f'<div class="form-group"><label style="font-size:11px">Keyword / Context</label>'
                f'<input type="text" name="img_keyword" value="{_ctx_kw}" placeholder="company, event, location"></div>'
                f'</div>'
                f'</div>'
            )
        else:
            inputs_html += (
                f'<div id="tt-{tt}" class="tt-input-row {row_vis}">'
                f'<label>{short_label}</label>'
                f'<input type="text" name="target_{tt}" value="{saved_vals[tt]}"'
                f' placeholder="{placeholders[tt]}" style="font-family:var(--mono);font-size:13px">'
                f'</div>'
            )

    init_types = ",".join(saved_types)

    # Pre-compute JSON strings (avoid backslash-in-expression for Python 3.10 compat)
    _un_json  = json.dumps(api_cfg.get("name_users",  [])).replace("</", "<\\/")
    _em_json  = json.dumps(api_cfg.get("email_users", [])).replace("</", "<\\/")
    _un_adv   = json.dumps(bool(api_cfg.get("adv_username")))
    _em_adv   = json.dumps(bool(api_cfg.get("adv_email")))

    html = f"""
<style>
.tt-pill{{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:20px;
  border:2px solid var(--border);background:var(--bg2);cursor:pointer;font-size:13px;
  font-weight:500;color:var(--muted);transition:all .15s;user-select:none;}}
.tt-pill.active{{border-color:var(--primary);background:rgba(0,212,255,0.12);color:var(--primary);}}
.tt-pill:hover{{border-color:var(--primary);color:var(--text);}}
.tt-input-row{{display:none;margin-top:8px;}}
.tt-input-row.visible{{display:block;}}
.mod-hidden{{display:none !important;}}
</style>
<div style="max-width:1200px;margin:0 auto">
<div class="flex justify-between items-center mb-3">
  <div>
    <div class="section-title">✏️ Edit Scan Configuration</div>
    <div style="font-size:12px;color:var(--muted)">{scan_target_esc} · {scan_name_esc}</div>
  </div>
  <a href="/scan/{scan_id}" class="btn btn-ghost btn-sm">← Back</a>
</div>
<form method="POST" id="scan-form" enctype="multipart/form-data">

<!-- Target types -->
<div class="card">
  <div class="card-header"><span class="card-title">🎯 Target</span></div>
  <div class="card-body">
    <div style="font-size:12px;color:var(--muted);margin-bottom:10px">
      Select target types - activate a pill to edit its value.
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px" id="type-pills">
      {pills_html}
    </div>
    {inputs_html}
    <input type="hidden" name="target_types" id="target-types-hidden" value="{init_types}">
  </div>
</div>

<!-- Scan settings -->
<div class="card">
  <div class="card-header"><span class="card-title">⚙️ Settings</span></div>
  <div class="card-body">
    <div class="form-row">
      <div class="form-group"><label>Scan Name</label>
        <input type="text" name="scan_name" value="{scan_name_esc}"></div>
      <div class="form-group"><label>Scan Type</label>
        <select name="scan_type" id="scan-type-sel">
          <option value="osint" {'selected' if scan.get('scan_type','osint')=='osint' else ''}>Advanced OSINT</option>
          <option value="sast"  {'selected' if scan.get('scan_type')=='sast' else ''}>Source Code Analysis</option>
        </select>
      </div>
    </div>
    <div id="domain-settings" class="form-row3" style="{'display:none' if 'domain' not in saved_types else ''}">
      <div class="form-group"><label>Crawl Depth (1–5)</label>
        <input type="number" name="crawl_depth" value="{scan.get('crawl_depth',2)}" min="1" max="5"></div>
      <div class="form-group" style="grid-column:span 2"><label>File Types</label>
        <input type="text" name="file_types" value="{scan.get('file_types','*')}"></div>
    </div>
    <div id="wayback-settings" class="card" style="background:var(--bg3);padding:14px;margin-bottom:16px;{'display:none' if 'domain' not in saved_types else ''}">
      <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">🕰️ Wayback Machine Config</div>
      <div class="form-row3">
        <div class="form-group">
          <label>URL Limit per Query</label>
          <input type="number" name="wayback_limit" value="{wbl}" min="50" max="5000">
        </div>
        <div class="form-group" style="grid-column:span 2">
          <label>Sensitive Extensions</label>
          <input type="text" name="wayback_extensions" value="{_html.escape(wbe)}" style="font-size:11px;font-family:var(--mono)">
        </div>
      </div>
    </div>
    <div class="form-group">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
        <input type="checkbox" name="use_tor" {tor_checked}>
        <span>Route all scan traffic through TOR Anonymous Mode</span>
      </label>
    </div>
    <div id="sast-section" style="display:{sast_disp}">
      <div class="form-group"><label>Source Code Path</label>
        <input type="text" name="source_path" value="{source_path_esc}"></div>
    </div>
  </div>
</div>

<!-- Modules -->
<div class="card">
  <div class="card-header">
    <div>
      <span class="card-title">🧩 OSINT Modules</span>
      <span id="mod-count-label" style="font-size:11px;color:var(--muted);margin-left:8px"></span>
    </div>
    <div style="display:flex;gap:6px">
      <button type="button" class="btn btn-ghost btn-sm" onclick="selVisible(true)">Select Visible</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selVisible(false)">Deselect Visible</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selAll(true)">All</button>
      <button type="button" class="btn btn-ghost btn-sm" onclick="selAll(false)">None</button>
    </div>
  </div>
  <div class="card-body">
    <div class="module-grid" id="module-grid">{mod_cards}</div>
  </div>
</div>

<!-- API Keys -->
<div class="card">
  <div class="card-header"><span class="card-title">🔑 API Keys (leave blank to keep existing)</span></div>
  <div class="card-body">
    <div class="form-row">
      <div class="form-group"><label>GitHub Token</label><input type="password" name="github_token" placeholder="unchanged"></div>
      <div class="form-group"><label>Shodan API Key</label><input type="password" name="shodan_key" placeholder="unchanged"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Anthropic/Claude Key</label><input type="password" name="anthropic_key" placeholder="unchanged"></div>
      <div class="form-group"><label>VirusTotal Key</label><input type="password" name="virustotal_key" placeholder="unchanged"></div>
    </div>
  </div>
</div>

<div class="flex gap-2">
  <button class="btn btn-primary" name="start_now" value="1">💾 Save &amp; Start Scan</button>
  <button class="btn btn-ghost">💾 Save Only</button>
  <a href="/scan/{scan_id}" class="btn btn-ghost">Cancel</a>
</div>
</form>
</div>

<script>
/* Same pill/filter system as new_scan */
function getActiveTypes() {{
  var types = [];
  document.querySelectorAll('#type-pills .tt-pill').forEach(function(p) {{
    if (p.classList.contains('active')) types.push(p.dataset.type);
  }});
  return types;
}}
function syncTargetTypesField() {{
  var types = getActiveTypes();
  document.getElementById('target-types-hidden').value = types.join(',');
  filterModules(types);
  var ds = document.getElementById('domain-settings');
  var ws = document.getElementById('wayback-settings');
  var isDomain = types.indexOf('domain') >= 0;
  if (ds) ds.style.display = isDomain ? '' : 'none';
  if (ws) ws.style.display = isDomain ? '' : 'none';
  updateModCount();
}}
function filterModules(types) {{
  document.querySelectorAll('.module-card').forEach(function(card) {{
    var ct = (card.dataset.targets || 'domain').split(' ');
    var ok = types.some(function(t) {{ return ct.indexOf(t) >= 0; }});
    card.classList.toggle('mod-hidden', !ok);
  }});
}}
function updateModCount() {{
  var total   = document.querySelectorAll('.module-card').length;
  var visible = document.querySelectorAll('.module-card:not(.mod-hidden)').length;
  var checked = document.querySelectorAll('.module-card:not(.mod-hidden) input:checked').length;
  var lbl = document.getElementById('mod-count-label');
  if (lbl) lbl.textContent = checked + ' selected · ' + visible + ' relevant of ' + total;
}}
document.querySelectorAll('#type-pills .tt-pill').forEach(function(pill) {{
  pill.addEventListener('click', function() {{
    var active = getActiveTypes();
    var isActive = pill.classList.contains('active');
    if (isActive && active.length === 1) return;
    pill.classList.toggle('active', !isActive);
    var tt = pill.dataset.type;
    var row = document.getElementById('tt-' + tt);
    if (row) row.classList.toggle('visible', !isActive);
    syncTargetTypesField();
  }});
}});
function toggleMod(card) {{
  if (card.classList.contains('mod-hidden')) return;
  var cb = card.querySelector('input[type=checkbox]');
  cb.checked = !cb.checked;
  card.classList.toggle('selected', cb.checked);
  updateModCount();
}}
function selVisible(on) {{
  document.querySelectorAll('.module-card:not(.mod-hidden)').forEach(function(c) {{
    c.querySelector('input').checked = on;
    c.classList.toggle('selected', on);
  }});
  updateModCount();
}}
function selAll(on) {{
  document.querySelectorAll('.module-card').forEach(function(c) {{
    c.querySelector('input').checked = on;
    c.classList.toggle('selected', on);
  }});
  updateModCount();
}}
document.getElementById('scan-type-sel').addEventListener('change', function() {{
  document.getElementById('sast-section').style.display = this.value==='sast' ? 'block' : 'none';
}});

/* ── Multi-user name builder ──────────────────────────────────── */
var _INP_STYLE = 'background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:6px 10px;color:var(--text);font-size:13px;width:100%';
function addNameRow(prefix, data) {{
  data = data || {{}};
  var row = document.createElement('div');
  row.className = 'name-row';
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr 1fr 28px;gap:6px;margin-bottom:6px';
  row.innerHTML =
    '<input type="text" class="name-first" placeholder="First *" value="'+(data.first||'')+'" style="'+_INP_STYLE+'">' +
    '<input type="text" class="name-middle" placeholder="Middle" value="'+(data.middle||'')+'" style="'+_INP_STYLE+'">' +
    '<input type="text" class="name-last" placeholder="Last" value="'+(data.last||'')+'" style="'+_INP_STYLE+'">' +
    '<button type="button" onclick="removeNameRow(this)" title="Remove" style="background:none;border:1px solid var(--border);border-radius:5px;color:var(--danger);cursor:pointer;font-size:16px;padding:0">×</button>';
  document.getElementById(prefix+'-rows').appendChild(row);
}}
function removeNameRow(btn) {{
  var row = btn.closest('.name-row');
  if (row) row.remove();
}}
function collectUsersJson(prefix) {{
  var rows = document.querySelectorAll('#'+prefix+'-rows .name-row');
  var users = [];
  rows.forEach(function(r) {{
    var f=(r.querySelector('.name-first')||{{}}).value||'';
    var m=(r.querySelector('.name-middle')||{{}}).value||'';
    var l=(r.querySelector('.name-last')||{{}}).value||'';
    f=f.trim(); m=m.trim(); l=l.trim();
    if (f||l) users.push({{first:f,middle:m,last:l}});
  }});
  var fid = prefix==='un' ? 'name-users-json' : 'email-users-json';
  var fld = document.getElementById(fid);
  if (fld) fld.value = JSON.stringify(users);
  return users;
}}
function importNameCsv(input, prefix) {{
  var file = input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {{
    var lines = e.target.result.split('\\n');
    var container = document.getElementById(prefix+'-rows');
    container.innerHTML = '';
    lines.forEach(function(line, idx) {{
      line = line.trim();
      if (!line) return;
      var cols = line.split(',');
      var first=(cols[0]||'').trim(), mid=(cols[1]||'').trim(), last=(cols[2]||'').trim();
      if (idx===0 && first.toLowerCase()==='first') return;
      if (first||last) addNameRow(prefix,{{first:first,middle:mid,last:last}});
    }});
    input.value='';
  }};
  reader.readAsText(file);
}}
function toggleAdvUsername(on) {{
  document.getElementById('adv-username-simple').style.display = on ? 'none' : '';
  document.getElementById('adv-username-fields').style.display = on ? '' : 'none';
  var s = document.getElementById('target_username_simple');
  if (s) s.disabled = on;
  if (on && document.getElementById('un-rows').children.length===0) addNameRow('un');
}}
function toggleAdvEmail(on) {{
  document.getElementById('adv-email-simple').style.display = on ? 'none' : '';
  document.getElementById('adv-email-fields').style.display = on ? '' : 'none';
  var s = document.getElementById('target_email_simple');
  if (s) s.disabled = on;
  if (on && document.getElementById('em-rows').children.length===0) addNameRow('em');
}}
/* Restore saved rows from api_cfg (populated by inline script below) */
function restoreNameRows(prefix, users) {{
  if (!users || !users.length) return;
  var container = document.getElementById(prefix+'-rows');
  if (container) container.innerHTML='';
  users.forEach(function(u) {{ addNameRow(prefix,u); }});
}}

/* Init */
syncTargetTypesField();
/* Collect JSON before any submit */
document.getElementById('scan-form').addEventListener('submit', function() {{
  collectUsersJson('un');
  collectUsersJson('em');
}});
</script>
<script>
(function(){{
  var savedUN = {_un_json};
  var savedEM = {_em_json};
  if (savedUN.length) restoreNameRows('un', savedUN);
  else if ({_un_adv}) addNameRow('un');
  if (savedEM.length) restoreNameRows('em', savedEM);
  else if ({_em_adv}) addNameRow('em');
}})();
</script>"""
    return _base(f"Edit Scan: {scan_target_esc}", html, "investigations")

@app.route("/api/download-template")
@require_login
def api_download_template():
    """Return a downloadable CSV template for username/email/phishing imports."""
    from flask import Response as _Resp
    ttype = request.args.get("type", "username")
    if ttype == "username":
        content = "first,middle,last\nJohn,Michael,Doe\nJane,,Smith\nRobert,James,Chen\n"
        fname   = "username_import_template.csv"
    elif ttype == "email":
        content = "first,middle,last\nJohn,Michael,Doe\nJane,,Smith\nRobert,James,Chen\n"
        fname   = "email_import_template.csv"
    elif ttype == "phishing":
        content = (
            "email,first,last,position\n"
            "john.doe@acme.com,John,Doe,Engineer\n"
            "jane.smith@acme.com,Jane,Smith,Manager\n"
            "cfo@acme.com,Robert,Chen,CFO\n"
            "admin@acme.com,Sarah,Johnson,IT Admin\n"
        )
        fname   = "phishing_targets_template.csv"
    else:
        return "Invalid type", 400
    resp = _Resp(content, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/api/client-ip", methods=["POST"])
def api_client_ip():
    """Browser reports its own public IP (bypasses Docker NAT) for audit log accuracy.
    No auth required - called from login page before session exists."""
    data = request.get_json(silent=True) or {}
    ip   = (data.get("ip","") or "").strip()
    import re as _re2
    # Basic sanity: IPv4/IPv6 characters only, not a private/loopback address
    if ip and _re2.match(r'^[\d\.:a-fA-F]+$', ip) and len(ip) <= 45 and not _is_private_ip(ip):
        flask_session["client_public_ip"] = ip
        flask_session.modified = True
    return jsonify({"ok": True})


@app.route("/api/smtp/test", methods=["POST"])
@require_admin
def api_smtp_test():
    """Send a test email using the provided (or saved) SMTP settings."""
    import smtplib, email.mime.text, email.mime.multipart, email.policy as _epol2
    from email.utils import formatdate as _fmtdate
    data = request.get_json(silent=True) or {}

    # Recipient - explicitly provided in request (the new test-to input)
    to_addr = (data.get("to_addr","") or "").strip()
    if not to_addr:
        return jsonify({"ok": False, "error": "Enter a recipient address in the Test Email field."})

    # Determine host/port from mode
    mode = (data.get("mode","") or _get_setting("sys_smtp_mode","mailhog")).strip()
    if mode == "mailhog":
        _def_mhog = _mailhog_default_host()
        host      = (data.get("host","") or "").strip() or _get_setting("sys_smtp_mailhog_host","").strip() or _def_mhog
        port      = int((data.get("port","") or _get_setting("sys_smtp_mailhog_port","1025") or 1025))
        user      = ""
        password  = ""
        use_tls   = False
        use_ssl   = False
    else:
        host     = (data.get("host","") or "").strip() or _get_setting("sys_smtp_host","")
        port     = int(data.get("port") or _get_setting("sys_smtp_port","587") or 587)
        user     = (data.get("user","") or "").strip() or _get_setting("sys_smtp_user","")
        password = (data.get("pass","") or "").strip() or _get_setting("sys_smtp_pass","")
        use_tls  = bool(data.get("tls", _get_setting("sys_smtp_tls","0") == "1"))
        use_ssl  = bool(data.get("ssl", _get_setting("sys_smtp_ssl","0") == "1"))

    from_addr = (data.get("from_addr","") or "").strip() or _get_setting("sys_smtp_from","feroxsei@localhost")

    if not host:
        return jsonify({"ok": False, "error": "SMTP host is required. Fill in the host field first."})

    try:
        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Date"]    = _fmtdate(localtime=True)
        msg["Subject"] = "FEROXSEI OSINT - SMTP Test"
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        html_body = (
            '<div style="font-family:sans-serif;padding:24px;background:#0d1117;color:#e2e8f0">'
            '<h2 style="color:#00d4ff;margin:0 0 12px">✅ SMTP is working!</h2>'
            '<p>Test sent from <strong>FEROXSEI OSINT</strong>.</p>'
            f'<p>Server: <code>{host}:{port}</code> &nbsp;|&nbsp; Mode: <code>{mode}</code></p>'
            '</div>'
        )
        msg.attach(email.mime.text.MIMEText(f"FEROXSEI OSINT SMTP Test - {host}:{port}", "plain", "utf-8"))
        msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

        if use_ssl:
            s = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            s = smtplib.SMTP(host, port, timeout=10)
            if use_tls:
                s.starttls()
        if user and password:
            s.login(user, password)
        s.sendmail(from_addr, [to_addr], msg.as_bytes(policy=_epol2.SMTP))
        s.quit()
        return jsonify({"ok": True, "message": f"Test email sent to {to_addr} via {host}:{port}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/headless/test", methods=["POST"])
@require_login
def api_headless_test():
    """Take a quick test screenshot of example.com to verify Playwright works."""
    try:
        png = engine.http.take_screenshot("https://example.com", timeout_ms=20000)
        return jsonify({"ok": True, "size_kb": round(len(png)/1024, 1)})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/headless/install", methods=["POST"])
@require_login
def api_headless_install():
    """Run pip install playwright + playwright install chromium and stream output."""
    import subprocess, sys
    try:
        out_lines = []
        cmds = [
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--break-system-packages", "playwright"],
            ["playwright", "install", "chromium"],
            ["playwright", "install-deps", "chromium"],
        ]
        for cmd in cmds:
            out_lines.append(f"$ {' '.join(cmd)}")
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if r.stdout.strip():
                    out_lines.append(r.stdout.strip())
                if r.stderr.strip():
                    out_lines.append(r.stderr.strip())
                if r.returncode != 0:
                    out_lines.append(f"[exit {r.returncode}]")
            except FileNotFoundError:
                out_lines.append(f"  ⚠ Command not found: {cmd[0]}")
            except subprocess.TimeoutExpired:
                out_lines.append("  ⚠ Timed out after 5 min")
        # Verify
        ok = False
        try:
            from playwright.sync_api import sync_playwright as _sp
            with _sp() as _pw:
                _b = _pw.chromium.launch(headless=True)
                ver = _b.version
                _b.close()
            ok = True
            out_lines.append(f"\n✅ Chromium {ver} is ready!")
        except Exception as ve:
            out_lines.append(f"\n❌ Verification failed: {ve}")
        return jsonify({"ok": ok, "output": "\n".join(out_lines)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "output": str(e)})


@app.route("/api/screenshot/<sid>")
@require_login
def api_serve_screenshot(sid):
    """Serve a full-size screenshot PNG from disk (or fall back to stored base64)."""
    import base64
    row = db.get_screenshot(sid)
    if not row:
        return "Not found", 404
    # Try disk file first
    fp = row.get("file_path","")
    if fp and os.path.exists(fp):
        with open(fp, "rb") as f:
            data = f.read()
        resp = make_response(data)
        resp.headers["Content-Type"] = "image/png"
        resp.headers["Content-Disposition"] = f'inline; filename="screenshot-{sid[:8]}.png"'
        return resp
    # Fallback: thumbnail base64
    thumb = row.get("thumbnail","")
    if thumb:
        try:
            data = base64.b64decode(thumb)
            resp = make_response(data)
            resp.headers["Content-Type"] = "image/png"
            return resp
        except Exception:
            pass
    return "Screenshot data missing", 404


@app.route("/api/finding/<fid>/screenshot", methods=["POST"])
@require_api_auth
def api_take_screenshot(fid):
    """Take an on-demand screenshot of a finding URL and attach it to the finding."""
    import base64
    try:
        body = request.get_json(silent=True) or {}
        url  = body.get("url","").strip()
        if not url:
            row = db.one("SELECT * FROM osint_findings WHERE id=?", (fid,))
            if row:
                url = row.get("url","") or ""
        if not url or not url.startswith("http"):
            return jsonify({"ok": False, "error": "No URL to screenshot"}), 400
        row = db.one("SELECT scan_id FROM osint_findings WHERE id=?", (fid,))
        if not row:
            return jsonify({"ok": False, "error": "Finding not found"}), 404
        scan_id  = row["scan_id"]
        is_onion = ".onion" in url.lower()
        if is_onion and not engine.http.probe_socks():
            return jsonify({
                "ok": False,
                "error": "TOR is not running. Enable TOR via the header badge before capturing .onion screenshots."
            })
        try:
            png_bytes = engine.http.take_screenshot(url)
        except RuntimeError as e:
            return jsonify({"ok": False, "error": str(e)})
        if not png_bytes:
            return jsonify({"ok": False, "error": "Screenshot failed - Playwright returned no data"})
        # Build thumbnail
        thumb_b64 = ""
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(png_bytes))
            img.thumbnail((600, 1000))
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            thumb_b64 = base64.b64encode(buf.getvalue()).decode()
        except Exception:
            thumb_b64 = base64.b64encode(png_bytes[:300_000]).decode()
        sid = db.save_screenshot(scan_id, "manual", url, png_bytes, thumb_b64)
        # Attach to finding
        db.exec("UPDATE osint_findings SET screenshot_id=? WHERE id=?", (sid, fid))
        _audit("screenshot", "finding", fid, url)
        return jsonify({"ok": True, "id": sid, "thumbnail": thumb_b64})
    except Exception as e:
        _log(f"[API] Screenshot error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/screenshot/capture", methods=["POST"])
@require_api_auth
def api_capture_url_screenshot():
    """Capture an on-demand screenshot of any URL (used by per-result dork cards)."""
    import base64
    try:
        body    = request.get_json(silent=True) or {}
        url     = (body.get("url") or "").strip()
        scan_id = (body.get("scan_id") or "").strip()
        if not url or not url.startswith("http"):
            return jsonify({"ok": False, "error": "Invalid URL"}), 400
        is_onion = ".onion" in url.lower()
        if is_onion and not engine.http.probe_socks():
            return jsonify({"ok": False,
                            "error": "TOR required for .onion URLs"}), 400
        try:
            png_bytes = engine.http.take_screenshot(url)
        except RuntimeError as e:
            return jsonify({"ok": False, "error": str(e)})
        if not png_bytes:
            return jsonify({"ok": False,
                            "error": "Screenshot failed - Playwright returned no data"})
        # Thumbnail
        thumb_b64 = ""
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(png_bytes))
            img.thumbnail((600, 1000))
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            thumb_b64 = base64.b64encode(buf.getvalue()).decode()
        except Exception:
            thumb_b64 = base64.b64encode(png_bytes[:300_000]).decode()
        sid = db.save_screenshot(scan_id or "manual", "manual", url, png_bytes, thumb_b64)
        return jsonify({"ok": True, "screenshot_id": sid, "thumbnail": thumb_b64})
    except Exception as e:
        _log(f"[API] capture screenshot error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scan/<scan_id>/findings")
@require_api_auth
def api_scan_findings(scan_id):
    fmt = request.args.get("fmt","json")
    findings = db.get_findings(scan_id, limit=2000)
    if fmt == "csv":
        lines = ["severity,module,title,url,evidence,created_at"]
        for f in findings:
            ev = (f.get("evidence","") or "").replace('"','""')[:200]
            lines.append(f'"{f["severity"]}","{f["module"]}","{f["title"]}","{f.get("url","")}","{ev}","{f["created_at"]}"')
        resp = make_response("\n".join(lines))
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = f'attachment; filename="feroxsei-osint-{scan_id[:8]}.csv"'
        return resp
    return jsonify({"findings": findings, "total": len(findings)})

@app.route("/api/scan/<scan_id>/traffic")
@require_api_auth
def api_scan_traffic(scan_id):
    entries = db.get_traffic(scan_id, limit=300)
    return jsonify({"entries": entries, "total": len(entries)})

@app.route("/api/scan/<scan_id>/tasks")
@require_api_auth
def api_scan_tasks(scan_id):
    tasks = db.get_tasks(scan_id, limit=500)
    return jsonify({"tasks": tasks, "total": len(tasks)})

@app.route("/api/scan/<scan_id>/skip_module", methods=["POST"])
@require_api_auth
def api_scan_skip_module(scan_id):
    if not _analyst_can("scans"):
        return jsonify({"ok": False, "error": "Not permitted"}), 403
    engine.skip_module(scan_id)
    return jsonify({"ok": True, "message": "Skip signal sent to current module"})

@app.route("/api/patterns")
@require_api_auth
def api_patterns():
    pats = db.rows("SELECT id,name,category,pattern,severity,enabled,hit_count FROM osint_patterns")
    return jsonify({"patterns": pats, "total": len(pats)})

@app.route("/api/patterns/<pid>", methods=["PATCH"])
@require_admin
def api_pattern_update(pid):
    """Admin-only: update pattern regex, severity, or description in-place."""
    data     = request.get_json(silent=True) or {}
    allowed  = {"pattern", "severity", "description", "enabled"}
    updates  = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"ok": False, "error": "No valid fields"}), 400
    if "pattern" in updates:
        import re as _re2
        try:
            _re2.compile(updates["pattern"])
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid regex: {e}"}), 400
    set_clause = ", ".join(f"{k}=?" for k in updates)
    db.exec(f"UPDATE osint_patterns SET {set_clause} WHERE id=?",
            list(updates.values()) + [pid])
    patterns.reload()
    engine.patterns.reload()
    _audit("update_pattern", "pattern", pid, str(list(updates.keys())))
    return jsonify({"ok": True, "updated": list(updates.keys())})

# ═════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS PAGE
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/notifications")
@require_login
def notifications_page():
    uid = flask_session["uid"]
    notifs = db.rows("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 200", (uid,))
    # Mark all read
    db.exec("UPDATE notifications SET is_read=1 WHERE user_id=?", (uid,))

    icon_map = {"info":"&#x2139;","warning":"&#x26A0;","error":"&#x274C;",
                "success":"&#x2705;","message":"&#x1F4AC;","scan":"&#x1F50D;",
                "darkweb":"&#x1F578;","login":"&#x1F512;","threat":"&#x26A1;"}
    rows = ""
    for n in notifs:
        nid   = n.get("id","")
        icon  = icon_map.get(n.get("type","info"),"&#x2139;")
        ts    = (n.get("created_at") or "")[:16].replace("T"," ")
        title = n.get("title","")
        body  = n.get("body","")
        opac  = "1" if not n.get("is_read") else "0.65"
        sev_col = {"warning":"#ffad00","error":"#ff3860","threat":"#ff5722"}.get(n.get("type",""),"#40c4ff")
        rows += f"""<div class="card notif-card" data-nid="{nid}"
  style="padding:14px;margin-bottom:10px;opacity:{opac};display:flex;justify-content:space-between;align-items:flex-start;gap:12px;border-left:3px solid {sev_col}">
  <label style="display:flex;gap:10px;flex:1;cursor:pointer">
    <input type="checkbox" class="notif-chk" value="{nid}" style="margin-top:3px;accent-color:var(--primary)">
    <div>
      <div style="display:flex;align-items:center;gap:6px">
        <span style="font-size:16px">{icon}</span>
        <strong style="color:var(--text)">{title}</strong>
        <span style="color:var(--muted);font-size:11px;margin-left:6px">{ts}</span>
      </div>
      <p style="margin-top:6px;color:var(--text2);font-size:13px">{body}</p>
    </div>
  </label>
  <button class="btn btn-danger btn-sm" onclick="delOne('{nid}',this.closest('.notif-card'))">&#x1F5D1;</button>
</div>"""

    if not notifs:
        rows = '<p style="color:var(--muted);text-align:center;padding:60px 0">&#x1F514; No notifications - you are all caught up!</p>'

    content = f"""
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px">
  <h2 style="color:var(--text)">&#x1F514; Notifications</h2>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn btn-ghost btn-sm" onclick="selAll()">&#x2611; Select All</button>
    <button class="btn btn-danger btn-sm" onclick="delSelected()">&#x1F5D1; Delete Selected</button>
    <button class="btn btn-danger btn-sm" onclick="clearAll()">&#x1F9F9; Clear All</button>
  </div>
</div>
{rows}
<script>
function delOne(nid,el){{
  fetch("/api/notifications/delete/"+nid,{{method:"POST"}}).then(function(){{if(el)el.remove();}});
}}
function clearAll(){{
  if(!confirm("Delete ALL notifications?"))return;
  fetch("/api/notifications/clear-all",{{method:"POST"}}).then(function(){{location.reload();}});
}}
function selAll(){{
  var chks=document.querySelectorAll(".notif-chk");
  var allChecked=Array.from(chks).every(function(c){{return c.checked;}});
  chks.forEach(function(c){{c.checked=!allChecked;}});
}}
function delSelected(){{
  var ids=Array.from(document.querySelectorAll(".notif-chk:checked")).map(function(c){{return c.value;}});
  if(!ids.length){{alert("Select at least one notification.");return;}}
  if(!confirm("Delete "+ids.length+" selected notification(s)?"))return;
  fetch("/api/notifications/delete-selected",{{
    method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{ids:ids}})
  }}).then(function(){{location.reload();}});
}}
</script>"""
    return _base("Notifications", content, "notifications")

# ═════════════════════════════════════════════════════════════════════════════
# NOTIFICATION API ROUTES
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/api/notifications/recent")
@require_login
def api_notifications_recent():
    uid   = flask_session.get("uid","")
    items = db.rows(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
        (uid,))
    unread_row = db.one(
        "SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND is_read=0", (uid,))
    unread = unread_row["c"] if unread_row else 0
    return jsonify({"ok": True, "items": [dict(r) for r in items], "unread": unread})

@app.route("/api/notifications/read-all", methods=["POST"])
@require_login
def api_notifications_read_all():
    db.exec("UPDATE notifications SET is_read=1 WHERE user_id=?",
            (flask_session.get("uid",""),))
    return jsonify({"ok": True})

@app.route("/api/notifications/delete/<nid>", methods=["POST"])
@require_api_auth
def api_notif_delete(nid):
    uid = flask_session["uid"]
    db.exec("DELETE FROM notifications WHERE id=? AND user_id=?", (nid, uid))
    return jsonify({"ok": True})

@app.route("/api/notifications/clear-all", methods=["POST"])
@require_api_auth
def api_notif_clear_all():
    uid = flask_session["uid"]
    db.exec("DELETE FROM notifications WHERE user_id=?", (uid,))
    return jsonify({"ok": True})

@app.route("/api/notifications/delete-selected", methods=["POST"])
@require_api_auth
def api_notif_delete_selected():
    uid  = flask_session["uid"]
    data = request.get_json(force=True) or {}
    ids  = data.get("ids", [])
    for nid in ids:
        db.exec("DELETE FROM notifications WHERE id=? AND user_id=?", (nid, uid))
    return jsonify({"ok": True, "deleted": len(ids)})

# ═════════════════════════════════════════════════════════════════════════════
# CHAT ROUTES + API
# ═════════════════════════════════════════════════════════════════════════════

def _chat_ensure_member(channel_id: str, user_id: str):
    """Add user to channel if not already a member."""
    existing = db.one(
        "SELECT 1 FROM chat_members WHERE channel_id=? AND user_id=?",
        (channel_id, user_id))
    if not existing:
        db.exec(
            "INSERT OR IGNORE INTO chat_members(channel_id,user_id,joined_at) VALUES(?,?,?)",
            (channel_id, user_id, _now()))

def _chat_get_or_create_dm(uid_a: str, uid_b: str) -> str:
    """Return existing DM channel id between two users, or create one."""
    rows = db.rows(
        "SELECT m1.channel_id FROM chat_members m1 "
        "JOIN chat_members m2 ON m1.channel_id=m2.channel_id "
        "JOIN chat_channels c ON c.id=m1.channel_id "
        "WHERE m1.user_id=? AND m2.user_id=? AND c.type='dm'",
        (uid_a, uid_b))
    if rows:
        return rows[0]["channel_id"]
    cid = str(uuid.uuid4())
    db.exec(
        "INSERT INTO chat_channels(id,name,type,created_by,created_at) VALUES(?,?,?,?,?)",
        (cid, "dm", "dm", uid_a, _now()))
    db.exec(
        "INSERT OR IGNORE INTO chat_members(channel_id,user_id,joined_at) VALUES(?,?,?)",
        (cid, uid_a, _now()))
    db.exec(
        "INSERT OR IGNORE INTO chat_members(channel_id,user_id,joined_at) VALUES(?,?,?)",
        (cid, uid_b, _now()))
    return cid

def _chat_channel_display(ch: dict, current_uid: str) -> dict:
    """Enrich a channel dict with display name for DMs."""
    if ch.get("type") == "dm":
        other = db.one(
            "SELECT u.username FROM chat_members m "
            "JOIN users u ON u.id=m.user_id "
            "WHERE m.channel_id=? AND m.user_id!=?",
            (ch["id"], current_uid))
        ch["display_name"] = other["username"] if other else "Unknown"
    else:
        ch["display_name"] = ch.get("name", "")
    return ch

@app.route("/chat")
@require_login
def chat_page():
    uid  = flask_session.get("uid","")
    user = flask_session.get("username","")
    # Ensure user is in General channel
    gen = db.one("SELECT id FROM chat_channels WHERE name='General' AND type='group'")
    if gen:
        _chat_ensure_member(gen["id"], uid)
    # Build channel list for sidebar
    channels = db.rows(
        "SELECT c.* FROM chat_channels c "
        "JOIN chat_members m ON c.id=m.channel_id "
        "WHERE m.user_id=? ORDER BY c.type, c.name",
        (uid,))
    channels = [_chat_channel_display(dict(ch), uid) for ch in channels]
    # All users for DM picker
    all_users = db.rows(
        "SELECT id, username FROM users WHERE status='active' AND id!=? ORDER BY username",
        (uid,))
    # All group channels user is NOT in (for join)
    my_channel_ids = [c["id"] for c in channels if c.get("type") == "group"]
    all_groups = db.rows(
        "SELECT * FROM chat_channels WHERE type='group' ORDER BY name")
    joinable = [g for g in all_groups if g["id"] not in my_channel_ids]

    _ch_options = "".join(
        f'<option value="{_html.escape(u["id"])}">{_html.escape(u["username"])}</option>'
        for u in all_users)
    _join_options = "".join(
        f'<option value="{_html.escape(g["id"])}">{_html.escape(g["name"])}</option>'
        for g in joinable)
    _ch_list_html = ""
    for ch in channels:
        icon = "💬" if ch.get("type") == "group" else "👤"
        dname = _html.escape(ch.get("display_name",""))
        cid   = _html.escape(ch["id"])
        _ch_list_html += (
            f'<div class="ch-item" id="chi-{cid}" onclick="selectChannel(\'{cid}\',\'{dname}\')">'
            f'{icon} <span class="ch-name">{dname}</span>'
            f'<span class="ch-unread" id="chub-{cid}" style="display:none"></span>'
            f'</div>')

    content = f"""
<style>
.chat-wrap{{display:flex;height:calc(100vh - 56px);gap:0;overflow:hidden}}
.chat-sidebar{{width:240px;min-width:200px;background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden}}
.chat-sidebar-hdr{{padding:12px 14px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px;
  display:flex;justify-content:space-between;align-items:center}}
.ch-section{{padding:8px 10px 2px;font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}}
.ch-list{{flex:1;overflow-y:auto;padding:4px 6px}}
.ch-item{{padding:7px 10px;border-radius:7px;cursor:pointer;font-size:13px;
  display:flex;align-items:center;gap:7px;transition:background .15s}}
.ch-item:hover{{background:var(--bg3)}}
.ch-item.active{{background:var(--primary);color:#fff}}
.ch-name{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ch-unread{{background:#ef4444;color:#fff;border-radius:10px;padding:1px 6px;font-size:10px;min-width:16px;text-align:center}}
.chat-main{{flex:1;display:flex;flex-direction:column;overflow:hidden}}
.chat-hdr{{padding:12px 18px;border-bottom:1px solid var(--border);font-weight:600;font-size:14px;
  display:flex;align-items:center;gap:8px;background:var(--bg2)}}
.chat-msgs{{flex:1;overflow-y:auto;padding:16px 18px;display:flex;flex-direction:column;gap:10px}}
.msg-row{{display:flex;gap:10px;align-items:flex-start}}
.msg-row-own{{flex-direction:row-reverse}}
.msg-avatar{{width:34px;height:34px;border-radius:50%;background:var(--primary);
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:700;flex-shrink:0;text-transform:uppercase}}
.msg-body{{flex:1}}
.msg-body-own{{text-align:right}}
.msg-meta{{display:flex;gap:8px;align-items:baseline;margin-bottom:2px}}
.msg-meta-own{{flex-direction:row-reverse}}
.msg-user{{font-weight:600;font-size:13px}}
.msg-time{{font-size:10px;color:var(--muted)}}
.msg-text{{font-size:14px;line-height:1.5;word-break:break-word;white-space:pre-wrap;
  display:inline-block;max-width:80%}}
.msg-text-own{{background:rgba(99,102,241,.18);border-radius:14px 14px 4px 14px;
  padding:8px 14px;text-align:left}}
.chat-input-wrap{{padding:12px 18px;border-top:1px solid var(--border);background:var(--bg2)}}
.chat-input-row{{display:flex;gap:8px;align-items:flex-end}}
.chat-input{{flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:10px;
  padding:10px 14px;color:var(--text);font-size:14px;resize:none;max-height:120px;
  min-height:40px;outline:none;font-family:inherit;line-height:1.4}}
.chat-input:focus{{border-color:var(--primary)}}
.chat-send-btn{{background:var(--primary);color:#fff;border:none;border-radius:10px;
  padding:10px 18px;cursor:pointer;font-size:14px;height:40px;flex-shrink:0}}
.emoji-btn{{background:var(--bg3);border:1px solid var(--border);border-radius:10px;
  padding:0 12px;cursor:pointer;font-size:18px;height:40px;flex-shrink:0}}
.emoji-picker{{position:absolute;bottom:68px;right:18px;background:var(--bg2);
  border:1px solid var(--border);border-radius:10px;padding:10px;
  box-shadow:0 8px 24px rgba(0,0,0,.3);z-index:999;display:none;
  width:300px;max-height:200px;overflow-y:auto}}
.emoji-grid{{display:flex;flex-wrap:wrap;gap:4px}}
.emoji-cell{{font-size:20px;cursor:pointer;padding:4px;border-radius:6px;line-height:1}}
.emoji-cell:hover{{background:var(--bg3)}}
.chat-empty{{flex:1;display:flex;align-items:center;justify-content:center;
  color:var(--muted);font-size:15px;flex-direction:column;gap:8px}}
.modal-bg{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;
  align-items:center;justify-content:center}}
.modal-bg.open{{display:flex}}
.modal-box{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:24px;width:360px;box-shadow:0 8px 30px rgba(0,0,0,.4)}}
</style>

<div class="chat-wrap">
  <!-- Sidebar -->
  <div class="chat-sidebar">
    <div class="chat-sidebar-hdr">
      <span>Team Chat</span>
      <div style="display:flex;gap:6px">
        <button class="btn btn-ghost btn-sm" title="New Group" onclick="openNewGroup()" style="font-size:16px;padding:2px 6px">+👥</button>
        <button class="btn btn-ghost btn-sm" title="New DM" onclick="openNewDM()" style="font-size:16px;padding:2px 6px">+👤</button>
        <button class="btn btn-ghost btn-sm" title="Join Channel" onclick="openJoinChannel()" style="font-size:16px;padding:2px 6px">+💬</button>
      </div>
    </div>
    <div class="ch-section">Channels &amp; Messages</div>
    <div class="ch-list" id="ch-list">{_ch_list_html}</div>
  </div>

  <!-- Main -->
  <div class="chat-main">
    <div class="chat-hdr" id="chat-hdr">
      <span style="font-size:20px">💬</span>
      <span id="chat-title" style="color:var(--muted)">Select a channel to start chatting</span>
    </div>
    <div class="chat-msgs" id="chat-msgs">
      <div class="chat-empty" id="chat-empty">
        <span style="font-size:40px">💬</span>
        <span>Pick a channel from the sidebar</span>
      </div>
    </div>
    <div class="chat-input-wrap" id="chat-input-wrap" style="display:none;position:relative">
      <div class="chat-input-row">
        <textarea id="chat-input" class="chat-input" rows="1"
          placeholder="Type a message…"
          onkeydown="chatKeydown(event)"></textarea>
        <button class="emoji-btn" onclick="toggleEmojiPicker(event)" title="Emoji">😊</button>
        <button class="chat-send-btn" onclick="sendMessage()">Send</button>
      </div>
      <div class="emoji-picker" id="emoji-picker">
        <div class="emoji-grid" id="emoji-grid"></div>
      </div>
    </div>
  </div>
</div>

<!-- New Group Modal -->
<div class="modal-bg" id="modal-newgroup">
  <div class="modal-box">
    <h3 style="margin:0 0 16px;font-size:16px">Create Group Channel</h3>
    <input id="ng-name" class="form-control" placeholder="Channel name" style="margin-bottom:14px">
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn btn-ghost" onclick="closeModal('modal-newgroup')">Cancel</button>
      <button class="btn btn-primary" onclick="createGroup()">Create</button>
    </div>
  </div>
</div>

<!-- New DM Modal -->
<div class="modal-bg" id="modal-newdm">
  <div class="modal-box">
    <h3 style="margin:0 0 16px;font-size:16px">Start Direct Message</h3>
    <select id="dm-user" class="form-control" style="margin-bottom:14px">
      <option value="">Select user…</option>
      {_ch_options}
    </select>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn btn-ghost" onclick="closeModal('modal-newdm')">Cancel</button>
      <button class="btn btn-primary" onclick="startDM()">Open DM</button>
    </div>
  </div>
</div>

<!-- Join Channel Modal -->
<div class="modal-bg" id="modal-join">
  <div class="modal-box">
    <h3 style="margin:0 0 16px;font-size:16px">Join Channel</h3>
    <select id="join-cid" class="form-control" style="margin-bottom:14px">
      <option value="">Select channel…</option>
      {_join_options}
    </select>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn btn-ghost" onclick="closeModal('modal-join')">Cancel</button>
      <button class="btn btn-primary" onclick="joinChannel()">Join</button>
    </div>
  </div>
</div>

<script>
var _curCid = null, _curTitle = '', _pollTimer = null, _lastTs = '', _myUid = '{_html.escape(uid)}', _myUser = '{_html.escape(user)}';

var EMOJIS = ['😀','😂','😍','🤔','👍','👎','🔥','💯','❤️','😎','🎉','😢','😡','🤣','😮','👏',
  '🙏','💪','✅','❌','⚠️','🔍','🐛','💡','📊','🚀','🎯','⚡','💬','📝','🔐','🔑',
  '😊','🙂','😐','😳','🤝','👋','💀','🤦','🤷','🎊','🔴','🟢','🟡','🔵','⭕','🔒',
  '📧','📱','💻','🖥️','🌐','📡','🛡️','⚙️','🔧','🗂️','📋','📌','🏠','👤','👥'];

(function initEmojis() {{
  var g = document.getElementById('emoji-grid');
  EMOJIS.forEach(function(e) {{
    var d = document.createElement('span');
    d.className = 'emoji-cell';
    d.textContent = e;
    d.onclick = function() {{ insertEmoji(e); }};
    g.appendChild(d);
  }});
}})();
(function() {{
  var first = document.querySelector('.ch-item');
  if (first) {{ first.click(); }}
}})();

function selectChannel(cid, title) {{
  _curCid = cid; _curTitle = title; _lastTs = '';
  document.getElementById('chat-title').textContent = title;
  document.querySelectorAll('.ch-item').forEach(function(el) {{ el.classList.remove('active'); }});
  var ci = document.getElementById('chi-' + cid);
  if (ci) ci.classList.add('active');
  document.getElementById('chat-msgs').innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  document.getElementById('chat-input-wrap').style.display = 'block';
  loadMessages(true);
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(function() {{ loadMessages(false); }}, 2000);
}}

function loadMessages(full) {{
  if (!_curCid) return;
  var url = '/api/chat/messages/' + _curCid;
  if (!full && _lastTs) url += '?since=' + encodeURIComponent(_lastTs);
  fetch(url).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (!d.ok) return;
    var box = document.getElementById('chat-msgs');
    if (full) {{
      box.innerHTML = '';
      if (!d.messages || !d.messages.length) {{
        box.innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)">No messages yet. Say hello! 👋</div>';
        return;
      }}
    }}
    (d.messages || []).forEach(function(m) {{
      appendMessage(m, box);
      if (!_lastTs || m.created_at > _lastTs) _lastTs = m.created_at;
    }});
    if (full || (d.messages && d.messages.length > 0)) {{
      box.scrollTop = box.scrollHeight;
    }}
  }}).catch(function() {{}});
}}

function appendMessage(m, box) {{
  var isOwn = (m.username === _myUser);
  var initials = (m.username || '?').substring(0,2).toUpperCase();
  var colors = ['#6366f1','#10b981','#f59e0b','#ef4444','#3b82f6','#8b5cf6','#ec4899'];
  var ci = m.user_id ? m.user_id.charCodeAt(0) % colors.length : 0;
  var ts = '';
  try {{
    var dt = new Date(m.created_at);
    ts = dt.toLocaleTimeString([], {{hour:'2-digit',minute:'2-digit'}});
  }} catch(ex) {{}}
  var txt = m.content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  var row = document.createElement('div');
  row.className = isOwn ? 'msg-row msg-row-own' : 'msg-row';
  row.id = 'msg-' + m.id;
  row.innerHTML = '<div class="msg-avatar" style="background:' + colors[ci] + '">' + initials + '</div>'
    + '<div class="msg-body' + (isOwn ? ' msg-body-own' : '') + '">'
    + '<div class="msg-meta' + (isOwn ? ' msg-meta-own' : '') + '"><span class="msg-user">' + escHtml(m.username) + '</span>'
    + '<span class="msg-time">' + ts + '</span></div>'
    + '<div class="msg-text' + (isOwn ? ' msg-text-own' : '') + '">' + txt + '</div></div>';
  box.appendChild(row);
}}

function escHtml(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

function sendMessage() {{
  if (!_curCid) return;
  var inp = document.getElementById('chat-input');
  var content = inp.value.trim();
  if (!content) return;
  inp.value = '';
  inp.style.height = 'auto';
  fetch('/api/chat/send', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{channel_id: _curCid, content: content}})
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (d.ok) loadMessages(false);
  }});
}}

function chatKeydown(e) {{
  if (e.key === 'Enter' && !e.shiftKey) {{
    e.preventDefault();
    sendMessage();
  }}
  setTimeout(function() {{
    var el = document.getElementById('chat-input');
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  }}, 0);
}}

function toggleEmojiPicker(e) {{
  e.stopPropagation();
  var p = document.getElementById('emoji-picker');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
}}
document.addEventListener('click', function() {{
  document.getElementById('emoji-picker').style.display = 'none';
}});

function insertEmoji(em) {{
  var inp = document.getElementById('chat-input');
  var s = inp.selectionStart, end = inp.selectionEnd;
  inp.value = inp.value.substring(0,s) + em + inp.value.substring(end);
  inp.selectionStart = inp.selectionEnd = s + em.length;
  inp.focus();
  document.getElementById('emoji-picker').style.display = 'none';
}}

function openNewGroup() {{ document.getElementById('modal-newgroup').classList.add('open'); document.getElementById('ng-name').value = ''; document.getElementById('ng-name').focus(); }}
function openNewDM()    {{ document.getElementById('modal-newdm').classList.add('open'); }}
function openJoinChannel() {{ document.getElementById('modal-join').classList.add('open'); }}
function closeModal(id)  {{ document.getElementById(id).classList.remove('open'); }}

function createGroup() {{
  var name = document.getElementById('ng-name').value.trim();
  if (!name) return;
  fetch('/api/chat/channels', {{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{name: name}})
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ closeModal('modal-newgroup'); addChannelToSidebar(d.channel_id, name, 'group'); selectChannel(d.channel_id, name); }}
    else alert(d.error || 'Failed to create channel');
  }});
}}

function startDM() {{
  var uid2 = document.getElementById('dm-user').value;
  if (!uid2) return;
  fetch('/api/chat/dm', {{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{user_id: uid2}})
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ closeModal('modal-newdm'); addChannelToSidebar(d.channel_id, d.display_name, 'dm'); selectChannel(d.channel_id, d.display_name); }}
    else alert(d.error || 'Failed to start DM');
  }});
}}

function joinChannel() {{
  var cid = document.getElementById('join-cid').value;
  if (!cid) return;
  fetch('/api/chat/channels/' + cid + '/join', {{method:'POST'}})
    .then(function(r) {{ return r.json(); }}).then(function(d) {{
      if (d.ok) {{ closeModal('modal-join'); addChannelToSidebar(cid, d.name, 'group'); selectChannel(cid, d.name); }}
      else alert(d.error || 'Failed to join channel');
    }});
}}

function addChannelToSidebar(cid, name, type) {{
  if (document.getElementById('chi-' + cid)) return;
  var icon = type === 'group' ? '💬' : '👤';
  var div = document.createElement('div');
  div.className = 'ch-item';
  div.id = 'chi-' + cid;
  var esc = name.replace(/'/g,"&#39;").replace(/"/g,'&quot;');
  div.setAttribute('onclick', "selectChannel('" + cid + "','" + esc + "')");
  div.innerHTML = icon + ' <span class="ch-name">' + escHtml(name) + '</span>'
    + '<span class="ch-unread" id="chub-' + cid + '" style="display:none"></span>';
  document.getElementById('ch-list').appendChild(div);
}}

window.addEventListener('click', function(e) {{
  ['modal-newgroup','modal-newdm','modal-join'].forEach(function(id) {{
    var el = document.getElementById(id);
    if (e.target === el) closeModal(id);
  }});
}});
</script>
"""
    return _base("Chat", content, "chat")

@app.route("/api/chat/channels")
@require_login
def api_chat_channels():
    uid = flask_session.get("uid","")
    _chat_ensure_member(
        (db.one("SELECT id FROM chat_channels WHERE name='General' AND type='group'") or {}).get("id",""),
        uid)
    rows = db.rows(
        "SELECT c.* FROM chat_channels c "
        "JOIN chat_members m ON c.id=m.channel_id "
        "WHERE m.user_id=? ORDER BY c.type, c.name", (uid,))
    result = []
    for ch in rows:
        ch = _chat_channel_display(dict(ch), uid)
        result.append(ch)
    return jsonify({"ok": True, "channels": result})

@app.route("/api/chat/messages/<channel_id>")
@require_login
def api_chat_messages(channel_id):
    uid = flask_session.get("uid","")
    member = db.one(
        "SELECT 1 FROM chat_members WHERE channel_id=? AND user_id=?",
        (channel_id, uid))
    if not member:
        return jsonify({"ok": False, "error": "Not a member"}), 403
    since = request.args.get("since","")
    if since:
        msgs = db.rows(
            "SELECT * FROM chat_messages WHERE channel_id=? AND created_at>? "
            "ORDER BY created_at ASC LIMIT 100",
            (channel_id, since))
    else:
        msgs = db.rows(
            "SELECT * FROM chat_messages WHERE channel_id=? "
            "ORDER BY created_at ASC LIMIT 200",
            (channel_id,))
    return jsonify({"ok": True, "messages": [dict(m) for m in msgs]})

@app.route("/api/chat/send", methods=["POST"])
@require_login
def api_chat_send():
    uid      = flask_session.get("uid","")
    username = flask_session.get("username","")
    data     = request.get_json(force=True) or {}
    cid      = data.get("channel_id","").strip()
    content  = data.get("content","").strip()
    if not cid or not content:
        return jsonify({"ok": False, "error": "Missing channel_id or content"}), 400
    member = db.one(
        "SELECT 1 FROM chat_members WHERE channel_id=? AND user_id=?", (cid, uid))
    if not member:
        return jsonify({"ok": False, "error": "Not a member"}), 403
    mid = str(uuid.uuid4())
    db.exec(
        "INSERT INTO chat_messages(id,channel_id,user_id,username,content,created_at) "
        "VALUES(?,?,?,?,?,?)",
        (mid, cid, uid, username, content[:2000], _now()))
    return jsonify({"ok": True, "id": mid})

@app.route("/api/chat/channels", methods=["POST"])
@require_login
def api_chat_create_channel():
    uid  = flask_session.get("uid","")
    data = request.get_json(force=True) or {}
    name = data.get("name","").strip()[:50]
    if not name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    existing = db.one("SELECT id FROM chat_channels WHERE name=? AND type='group'", (name,))
    if existing:
        _chat_ensure_member(existing["id"], uid)
        return jsonify({"ok": True, "channel_id": existing["id"], "existed": True})
    cid = str(uuid.uuid4())
    db.exec(
        "INSERT INTO chat_channels(id,name,type,created_by,created_at) VALUES(?,?,?,?,?)",
        (cid, name, "group", uid, _now()))
    _chat_ensure_member(cid, uid)
    return jsonify({"ok": True, "channel_id": cid})

@app.route("/api/chat/channels/<channel_id>/join", methods=["POST"])
@require_login
def api_chat_join_channel(channel_id):
    uid = flask_session.get("uid","")
    ch = db.one("SELECT * FROM chat_channels WHERE id=? AND type='group'", (channel_id,))
    if not ch:
        return jsonify({"ok": False, "error": "Channel not found"}), 404
    _chat_ensure_member(channel_id, uid)
    return jsonify({"ok": True, "name": ch["name"]})

@app.route("/api/chat/dm", methods=["POST"])
@require_login
def api_chat_create_dm():
    uid  = flask_session.get("uid","")
    data = request.get_json(force=True) or {}
    uid2 = data.get("user_id","").strip()
    if not uid2:
        tname = data.get("target_username","").strip()
        if tname:
            row = db.one("SELECT id FROM users WHERE username=?", (tname,))
            uid2 = row["id"] if row else ""
    if not uid2:
        return jsonify({"ok": False, "error": "user_id or target_username required"}), 400
    other = db.one("SELECT id, username FROM users WHERE id=?", (uid2,))
    if not other:
        return jsonify({"ok": False, "error": "User not found"}), 404
    cid = _chat_get_or_create_dm(uid, uid2)
    return jsonify({"ok": True, "channel_id": cid, "display_name": other["username"]})

# ═════════════════════════════════════════════════════════════════════════════
# TOR API ROUTES
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/api/tor/status")
def api_tor_status():
    import socket as _sock
    tor_host = _get_setting("tor_socks_host","127.0.0.1")
    tor_port = int(_get_setting("tor_socks_port","9050") or 9050)

    # User explicitly stopped/panicked → honour their intent regardless of socket state
    user_disabled = _get_setting("tor_user_disabled","0") == "1"
    if user_disabled:
        return jsonify({"enabled": False, "status": "disabled",
                        "note": "Stopped by user"})

    def _probe_socks():
        try:
            s = _sock.create_connection((tor_host, tor_port), timeout=2)
            s.close()
            return True
        except Exception:
            return False

    try:
        from feroxsei_tor import get_tor_manager
        mgr = get_tor_manager()
        d = mgr.get_status_dict()
        if not d.get("enabled") and _probe_socks():
            d["enabled"] = True
            d["status"]  = "connected"
            d["note"]    = "TOR detected via SOCKS5 probe"
        # Always inject current source IP from engine HTTP client
        d["source_ip"] = engine.http._local_ip or ""
        return jsonify(d)
    except (ImportError, Exception):
        alive = _probe_socks()
        if alive:
            return jsonify({"enabled": True, "status": "connected",
                            "source_ip": engine.http._local_ip or "",
                            "exit_ip": "", "hop_count": 3,
                            "note": "External TOR - SOCKS5 live"})
        db_on = _get_setting("tor_enabled","0") == "1"
        return jsonify({"enabled": db_on,
                        "source_ip": engine.http._local_ip or "",
                        "status": "disconnected" if db_on else "disabled"})

@app.route("/api/tor/start", methods=["POST"])
@require_api_auth
def api_tor_start():
    try:
        return _api_tor_start_impl()
    except Exception as _e:
        import traceback
        _log(f"[TOR] /api/tor/start unhandled error: {_e}\n{traceback.format_exc()}")
        return jsonify({"ok": False, "status": "error",
                        "message": f"Internal error: {_e}"}), 500

def _api_tor_start_impl():
    try:
        _can_tor = _analyst_can("tor")
    except Exception:
        _can_tor = False
    if not _can_tor:
        return jsonify({"ok": False, "error": "TOR access not permitted for your role"}), 403

    _save_setting("tor_user_disabled", "0")
    socks_host = _get_setting("tor_socks_host", "127.0.0.1")
    socks_port = int(_get_setting("tor_socks_port", "9050") or 9050)

    # ── 1. Dependency check first ─────────────────────────────────────────────
    deps_ok, deps_msg = engine.http.tor_deps_ok()
    if not deps_ok:
        # Try auto-installing missing deps
        _log(f"[TOR] Dependency check failed: {deps_msg} - attempting auto-install")
        try:
            from feroxsei_tor import install_tor_deps
            install_results = install_tor_deps()
            _log(f"[TOR] Auto-install results: {install_results}")
        except Exception as _inst_err:
            _log(f"[TOR] Auto-install error: {_inst_err}")
        # Re-check after attempted install
        deps_ok, deps_msg = engine.http.tor_deps_ok()
        if not deps_ok:
            install_guide = (
                "TOR dependencies are missing. Run these commands in your terminal:\n\n"
                "  # 1. Install TOR daemon:\n"
                "  sudo apt update && sudo apt install -y tor proxychains4\n\n"
                "  # 2. Install Python SOCKS5 library:\n"
                "  pip install PySocks stem --break-system-packages\n\n"
                "  # 3. Start TOR service:\n"
                "  sudo systemctl start tor\n"
                "  sudo systemctl enable tor\n\n"
                "  # 4. Verify TOR is running:\n"
                "  sudo systemctl status tor\n"
                "  curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip\n\n"
                "  # 5. (Optional) Enable control port - add to /etc/tor/torrc:\n"
                "  ControlPort 9051\n"
                "  CookieAuthentication 0\n"
                "  Then: sudo systemctl reload tor"
            )
            return jsonify({
                "ok":           False,
                "status":       "error",
                "message":      deps_msg,
                "install_guide": install_guide,
                "auto_install": "attempted"
            })

    # ── 2. Check if TOR SOCKS is already running ──────────────────────────────
    if engine.http.probe_socks():
        _log("[TOR] SOCKS5 port already listening - using existing TOR")
        ok, msg, status = True, "TOR SOCKS5 port already active", "connected"
    else:
        # ── 3. Start TOR daemon via feroxsei_tor manager ─────────────────────────
        ok, msg, status = False, "", "error"
        try:
            from feroxsei_tor import get_tor_manager
            mgr = get_tor_manager()
            ok, msg = mgr.start()
            status  = mgr.status
        except Exception as e:
            msg = str(e)
            _log(f"[TOR] Start error: {e}")

        if not ok:
            # Try starting tor directly via systemctl / service
            import subprocess as _sp
            for cmd in [
                ["sudo", "systemctl", "start", "tor"],
                ["sudo", "service", "tor", "start"],
                ["tor", "--quiet"],
            ]:
                try:
                    _sp.run(cmd, capture_output=True, timeout=5)
                    import time as _t; _t.sleep(3)
                    if engine.http.probe_socks():
                        ok, msg, status = True, f"TOR started via: {' '.join(cmd)}", "connected"
                        break
                except Exception:
                    pass

        if not ok:
            # Final check - maybe tor is up but we couldn't control it
            if engine.http.probe_socks():
                ok, msg, status = True, "TOR SOCKS5 detected (external process)", "connected"
            else:
                return jsonify({
                    "ok":     False,
                    "status": "error",
                    "message": (
                        f"Could not start TOR: {msg}\n\n"
                        "Manual fix - run in terminal:\n"
                        "  sudo systemctl start tor\n"
                        "  sudo apt install tor proxychains4  # if not installed\n"
                        "  pip install PySocks stem --break-system-packages"
                    )
                })

    _save_setting("tor_enabled", "1")

    # ── 4. Enable TOR on the global engine HTTP client ───────────────────────
    try:
        import threading as _th
        def _bg_enable():
            engine.http.enable_tor(socks_host=socks_host, socks_port=socks_port)
        _th.Thread(target=_bg_enable, daemon=True, name="tor-enable").start()
    except Exception as swap_err:
        _log(f"[TOR] Enable warning: {swap_err}")

    return jsonify({"ok": ok, "message": msg, "status": status})

@app.route("/api/tor/stop", methods=["POST"])
@require_api_auth
def api_tor_stop():
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    import subprocess as _sp
    msgs = []
    # 1. Stop via feroxsei_tor manager
    try:
        from feroxsei_tor import get_tor_manager
        mgr = get_tor_manager()
        mgr.stop()
        msgs.append("feroxsei_tor stopped")
    except Exception as e:
        msgs.append(f"feroxsei_tor: {e}")
    # 2. Kill any OS-level tor process (best-effort)
    try:
        _sp.run(["pkill", "-TERM", "tor"], capture_output=True, timeout=5)
        msgs.append("OS tor process signalled")
    except Exception as e:
        msgs.append(f"pkill: {e}")
    # 3. Set user-disabled flag so badge shows Disabled even if socket lingers
    _save_setting("tor_enabled", "0")
    _save_setting("tor_user_disabled", "1")
    # 4. Disable TOR on the global engine HTTP client
    try:
        engine.http.disable_tor()
    except Exception:
        pass
    return jsonify({"ok": True, "message": " | ".join(msgs), "status": "disabled"})

@app.route("/api/tor/newnym", methods=["POST"])
@require_api_auth
def api_tor_newnym():
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    import threading
    def _rotate_bg():
        """Run rotate_identity in background - it sleeps 4s waiting for new TOR circuit."""
        try:
            engine.http.rotate_identity()
        except Exception:
            pass

    try:
        from feroxsei_tor import get_tor_manager
        mgr = get_tor_manager()
        ok, msg = mgr.new_identity()
        if ok:
            # Send NEWNYM then rebuild session in background (4s delay for circuit build)
            threading.Thread(target=_rotate_bg, daemon=True).start()
        return jsonify({"ok": ok, "message": msg + " - new circuit building (4s)…"})
    except Exception as e:
        # Fallback: send NEWNYM directly via control port if feroxsei_tor unavailable
        try:
            import socket as _s
            tor_host = _get_setting("tor_socks_host", "127.0.0.1")
            ctrl_port = 9051
            with _s.create_connection((tor_host, ctrl_port), timeout=3) as sock:
                sock.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
                sock.recv(256)
            threading.Thread(target=_rotate_bg, daemon=True).start()
            return jsonify({"ok": True, "message": "NEWNYM sent - new circuit building (4s)…"})
        except Exception as e2:
            return jsonify({"ok": False, "error": str(e), "fallback_error": str(e2)})

@app.route("/api/tor/circuit")
def api_tor_circuit():
    try:
        from feroxsei_tor import get_tor_manager, CircuitMonitor
        mgr = get_tor_manager()
        nodes = CircuitMonitor.get_active_circuit(mgr.control_port, mgr.control_password)
        return jsonify({"ok": True, "nodes": nodes,
                        "exit_ip": getattr(mgr, "_exit_ip", None),
                        "exit_country": getattr(mgr, "_exit_country", None)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "nodes": []})

@app.route("/api/tor/refresh_ip", methods=["POST"])
@require_api_auth
def api_tor_refresh_ip():
    """Force-refresh source IP and TOR exit IP for traffic logs."""
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    import threading as _th
    def _do_refresh():
        engine.http.refresh_source_ip()
        if engine.http.use_tor:
            engine.http.refresh_tor_exit_ip()
    _th.Thread(target=_do_refresh, daemon=True, name="ip-refresh-manual").start()
    return jsonify({
        "ok": True,
        "message": "IP refresh started (takes 3-8s)",
        "current_source_ip": engine.http._local_ip,
        "current_exit_ip":   engine.http._tor_exit_ip if engine.http.use_tor else ""
    })

@app.route("/api/tor/check_deps")
@require_api_auth
def api_tor_check_deps():
    """Check TOR dependency status and return install guide if anything is missing."""
    import shutil
    deps = {}
    # TOR binary
    deps["tor_binary"] = {
        "installed": bool(shutil.which("tor")),
        "install": "sudo apt install tor"
    }
    # PySocks
    try:
        import socks; deps["PySocks"] = {"installed": True, "install": ""}  # noqa
    except ImportError:
        deps["PySocks"] = {"installed": False, "install": "pip install PySocks --break-system-packages"}
    # stem
    try:
        import stem; deps["stem"] = {"installed": True, "install": ""}  # noqa
    except ImportError:
        deps["stem"] = {"installed": False, "install": "pip install stem --break-system-packages"}
    # proxychains
    deps["proxychains"] = {
        "installed": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "install": "sudo apt install proxychains4"
    }
    # SOCKS port alive
    deps["socks_port"] = {
        "installed": engine.http.probe_socks(),
        "install": "sudo systemctl start tor"
    }

    all_ok = all(v["installed"] for v in deps.values())
    missing = [k for k, v in deps.items() if not v["installed"]]

    install_guide = ""
    if not all_ok:
        install_guide = (
            "Run these commands to set up TOR anonymous mode:\n\n"
            "# Step 1: Install TOR + proxychains\n"
            "sudo apt update && sudo apt install -y tor proxychains4\n\n"
            "# Step 2: Install Python TOR libraries\n"
            "pip install PySocks stem --break-system-packages\n\n"
            "# Step 3: Start TOR service\n"
            "sudo systemctl start tor\n"
            "sudo systemctl enable tor\n\n"
            "# Step 4: Enable TOR control port (for circuit info + NEWNYM)\n"
            "echo -e 'ControlPort 9051\\nCookieAuthentication 0' | sudo tee -a /etc/tor/torrc\n"
            "sudo systemctl reload tor\n\n"
            "# Step 5: Verify TOR is working\n"
            "curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip\n"
        )

    return jsonify({
        "ok":            all_ok,
        "deps":          deps,
        "missing":       missing,
        "install_guide": install_guide,
        "socks_host":    engine.http._socks_host,
        "socks_port":    engine.http._socks_port,
    })

@app.route("/api/tor/install", methods=["POST"])
@require_api_auth
def api_tor_install():
    """Attempt auto-installation of TOR dependencies."""
    if not _analyst_can("tor"):
        return jsonify({"ok": False, "error": "Not permitted"}), 403
    try:
        from feroxsei_tor import install_tor_deps
        results = install_tor_deps()
        # Re-check after install
        deps_ok, deps_msg = engine.http.tor_deps_ok()
        return jsonify({
            "ok":      deps_ok,
            "results": results,
            "message": "Installation complete - all deps ok" if deps_ok else deps_msg
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/tor/panic", methods=["POST"])
@require_api_auth
def api_tor_panic():
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    import subprocess as _sp
    msgs = []
    # 1. feroxsei_tor panic
    try:
        from feroxsei_tor import panic_stop
        result = panic_stop()
        msgs.append(result.get("message","panic_stop ok"))
    except Exception as e:
        msgs.append(f"feroxsei_tor panic: {e}")
    # 2. Hard-kill tor process
    try:
        _sp.run(["pkill", "-KILL", "tor"], capture_output=True, timeout=5)
        msgs.append("tor process killed")
    except Exception as e:
        msgs.append(f"pkill -KILL: {e}")
    # 3. Force-disable at DB level + badge
    _save_setting("tor_enabled", "0")
    _save_setting("tor_user_disabled", "1")
    # 4. Rebuild engine session without TOR
    try:
        engine.http.use_tor = False
        engine.http.rotate_identity()
    except Exception:
        pass
    return jsonify({"ok": True, "message": "🚨 PANIC - " + " | ".join(msgs),
                    "status": "disabled"})

# ═════════════════════════════════════════════════════════════════════════════
# USERNAME HUNT SITE MANAGER
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/settings/userhunt")
@require_login
def userhunt_settings():
    sites    = db.get_userhunt_sites(enabled_only=False)
    total    = len(sites)
    enabled  = sum(1 for s in sites if s["enabled"])
    custom   = sum(1 for s in sites if s["is_custom"])

    rows_html    = ""
    site_data_map = {}   # id -> dict; serialised to JS with json.dumps (safe escaping)
    for s in sites:
        sid      = s["id"]
        # HTML-safe values for display only
        name_disp = s["name"].replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
        url_disp  = s["url"].replace("{u}", "$$username$$").replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
        chk       = s["check_type"]
        tags_raw  = s["tags"] or "[]"
        try:
            tags_list = json.loads(tags_raw)
            tags_txt  = ", ".join(tags_list)
        except Exception:
            tags_txt = tags_raw
        is_en    = s["enabled"]
        is_cust  = s["is_custom"]
        tog_col  = "#4ade80" if is_en else "var(--muted)"
        tog_lbl  = "✓" if is_en else "✗"
        cust_badge = '<span style="font-size:10px;background:rgba(129,140,248,.18);color:#818cf8;border:1px solid #818cf8;border-radius:4px;padding:1px 5px;margin-left:4px">custom</span>' if is_cust else ""
        # Store raw values in JS data store - json.dumps handles all escaping safely
        site_data_map[sid] = {
            "name":          s["name"],
            "url":           s["url"].replace("{u}", "$$username$$"),
            "check":         chk,
            "found_str":     s.get("found_str") or "",
            "error_str":     s.get("error_str") or "",
            "json_path":     s.get("json_path") or "",
            "tags":          tags_txt,
            "secondary_url": s.get("secondary_url") or "",
            "id_pattern":    s.get("id_pattern") or "",
        }
        rows_html += f"""
    <tr id="site-row-{sid}">
      <td style="text-align:center;width:44px">
        <button onclick="toggleSite({sid},{1 if is_en else 0})"
                id="tog-{sid}"
                style="background:none;border:none;cursor:pointer;font-size:18px;
                       color:{tog_col};font-weight:700;line-height:1"
                title="{'Disable' if is_en else 'Enable'}">{tog_lbl}</button>
      </td>
      <td style="font-weight:500">{name_disp}{cust_badge}</td>
      <td style="font-family:monospace;font-size:11px;color:var(--muted);max-width:300px;
                 overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="{url_disp}">{url_disp}</td>
      <td><span style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;
                       padding:1px 7px;font-size:11px;font-family:monospace">{chk}</span></td>
      <td style="font-size:11px;color:var(--muted)">{tags_txt[:50]}</td>
      <td style="white-space:nowrap;text-align:right">
        <button onclick="editSite({sid})"
                style="background:none;border:1px solid var(--border);border-radius:4px;
                       padding:2px 10px;font-size:11px;cursor:pointer;color:var(--text);
                       margin-right:4px">✏️ Edit</button>
        <button onclick="deleteSite({sid})"
                style="background:none;border:1px solid var(--danger);border-radius:4px;
                       padding:2px 10px;font-size:11px;cursor:pointer;color:var(--danger)">🗑 Del</button>
      </td>
    </tr>"""
    # Serialise site data for injection into the <script> block (json.dumps is XSS-safe here)
    site_data_js = json.dumps(site_data_map).replace("</", "<\\/").replace("<!--", "<\\!--")

    _uh_content = f"""
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
  <h2 style="margin:0;font-size:18px">👤 Username Hunt - Site Manager</h2>
  <span style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;
               padding:3px 12px;font-size:12px;color:var(--muted)">{enabled}/{total} enabled · {custom} custom</span>
  <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
    <button onclick="bulkToggle(1)"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid #4ade80;background:rgba(74,222,128,.08);color:#4ade80">
      ✓ Enable All</button>
    <button onclick="bulkToggle(0)"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--muted);background:var(--bg3);color:var(--muted)">
      ✗ Disable All</button>
    <button onclick="showAddForm()"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--primary);background:rgba(0,212,255,.08);color:var(--primary)">
      ➕ Add Custom Site</button>
    <a href="/settings" style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--text);
                   text-decoration:none">← Back to Settings</a>
  </div>
</div>

<div id="msg-bar" style="display:none;padding:8px 14px;border-radius:6px;margin-bottom:12px;
                          font-size:13px;font-weight:500"></div>

<div id="add-form" style="display:none;background:var(--bg2);border:1px solid var(--border);
                           border-radius:8px;padding:16px;margin-bottom:14px">
  <h3 style="margin:0 0 12px;font-size:14px" id="form-title">➕ Add Custom Site</h3>
  <input type="hidden" id="edit-id" value="">
  <div style="display:grid;grid-template-columns:1fr 2fr;gap:10px;margin-bottom:10px">
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Site Name</label>
      <input id="f-name" type="text" placeholder="e.g. Instagram"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-size:13px">
    </div>
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">
        URL - use <code style="color:var(--primary)">$$username$$</code> as placeholder
      </label>
      <input id="f-url" type="text" placeholder="https://example.com/$$username$$/"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:12px">
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin-bottom:10px">
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Check Type</label>
      <select id="f-check" onchange="toggleCheckFields()"
              style="width:100%;background:var(--bg3);border:1px solid var(--border);
                     border-radius:5px;padding:6px 10px;color:var(--text);font-size:13px">
        <option value="status_code">status_code</option>
        <option value="message">message</option>
        <option value="json_key">json_key</option>
        <option value="response_url">response_url</option>
      </select>
    </div>
    <div id="ff-json-path">
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">JSON Path (json_key)</label>
      <input id="f-json-path" type="text" placeholder="data.username"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-size:12px">
    </div>
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Tags (comma-separated)</label>
      <input id="f-tags" type="text" placeholder="social, photo"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-size:12px">
    </div>
    <div></div>
  </div>
  <!-- Found / Error strings - shown for ALL check types -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
    <div>
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <label style="font-size:12px;color:var(--muted);flex:1">Found String(s) - any of these in body = profile exists</label>
        <button type="button" onclick="addStrRow('found')"
                style="font-size:11px;padding:1px 7px;border-radius:4px;cursor:pointer;
                       border:1px solid #4ade80;background:rgba(74,222,128,.08);color:#4ade80">+ Add</button>
      </div>
      <div id="found-str-list"></div>
    </div>
    <div>
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <label style="font-size:12px;color:var(--muted);flex:1">Error String(s) - any of these in body = not found</label>
        <button type="button" onclick="addStrRow('error')"
                style="font-size:11px;padding:1px 7px;border-radius:4px;cursor:pointer;
                       border:1px solid #ef4444;background:rgba(239,68,68,.08);color:#ef4444">+ Add</button>
      </div>
      <div id="error-str-list"></div>
    </div>
  </div>
  <!-- Sequential search -->
  <div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.15);border-radius:6px;
              padding:10px 12px;margin-bottom:12px">
    <div style="font-size:12px;font-weight:600;color:var(--primary);margin-bottom:8px">
      🔗 Sequential / Dynamic Search (optional)
    </div>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px;line-height:1.6">
      If the first URL returns multiple results (e.g. Flickr search page), extract a user ID and follow-up
      with a second URL. Use <code>$$username$$</code> and <code>$$id$$</code> as placeholders.
      <br>Example ID Pattern: <code>flickr\\.com/photos/([^/"]+)/</code>
      &nbsp;·&nbsp; Secondary URL: <code>https://www.flickr.com/photos/$$id$$</code>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div>
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">ID Extraction Regex</label>
        <input id="f-id-pattern" type="text" placeholder="e.g. flickr\\.com/photos/([^/]+)"
               style="width:100%;background:var(--bg3);border:1px solid var(--border);
                      border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:12px">
      </div>
      <div>
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Secondary URL (uses $$id$$)</label>
        <input id="f-secondary-url" type="text" placeholder="https://site.com/users/$$id$$"
               style="width:100%;background:var(--bg3);border:1px solid var(--border);
                      border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:12px">
      </div>
    </div>
  </div>
  <div style="display:flex;gap:8px">
    <button onclick="saveSite()"
            style="padding:7px 20px;border-radius:6px;cursor:pointer;border:none;
                   background:var(--primary);color:#000;font-weight:600;font-size:13px">
      💾 Save</button>
    <button onclick="closeForm()"
            style="padding:7px 16px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px">
      Cancel</button>
  </div>
</div>

<div style="margin-bottom:10px">
  <input id="search-sites" type="text" placeholder="🔍 Filter sites by name, URL, or tags…"
         oninput="filterSites()"
         style="width:100%;max-width:400px;background:var(--bg2);border:1px solid var(--border);
                border-radius:6px;padding:7px 12px;color:var(--text);font-size:13px">
</div>

<div style="overflow-x:auto">
<table id="sites-table" style="width:100%;border-collapse:collapse;font-size:13px">
  <thead>
    <tr style="border-bottom:2px solid var(--border)">
      <th style="padding:8px;text-align:center;width:44px;color:var(--muted)">On</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Site Name</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">URL Template</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Check</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Tags</th>
      <th style="padding:8px;text-align:right;color:var(--muted)">Actions</th>
    </tr>
  </thead>
  <tbody id="sites-tbody">
{rows_html}
  </tbody>
</table>
</div>


<script>
const SITE_DATA = {site_data_js};

function _msg(txt, ok) {{
  var b = document.getElementById('msg-bar');
  b.textContent = txt;
  b.style.display = 'block';
  b.style.background = ok ? 'rgba(74,222,128,.12)' : 'rgba(239,68,68,.12)';
  b.style.color = ok ? '#4ade80' : '#ef4444';
  b.style.border = '1px solid ' + (ok ? '#4ade80' : '#ef4444');
  setTimeout(function(){{ b.style.display='none'; }}, 4000);
}}

function toggleSite(id, cur) {{
  fetch('/api/userhunt/sites/' + id + '/toggle', {{method:'POST'}})
    .then(function(r){{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) {{
        var btn = document.getElementById('tog-' + id);
        var en  = d.enabled;
        btn.textContent   = en ? '✓' : '✗';
        btn.style.color   = en ? '#4ade80' : 'var(--muted)';
        btn.title         = en ? 'Disable' : 'Enable';
        btn.onclick       = function(){{ toggleSite(id, en ? 1 : 0); }};
      }} else {{ _msg(d.error || 'Error', false); }}
    }});
}}

function bulkToggle(val) {{
  fetch('/api/userhunt/sites/bulk-toggle', {{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{enabled: val}})
  }}).then(function(r){{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ location.reload(); }}
    else {{ _msg(d.error || 'Error', false); }}
  }});
}}

function _setStrRows(type, combined) {{
  var list = document.getElementById(type + '-str-list');
  list.innerHTML = '';
  var vals = combined ? combined.split('|').map(function(v){{return v.trim();}}).filter(Boolean) : [];
  if (!vals.length) vals = [''];
  vals.forEach(function(v) {{ _appendStrRow(type, v); }});
}}

function addStrRow(type) {{
  _appendStrRow(type, '');
}}

function _appendStrRow(type, val) {{
  var list = document.getElementById(type + '-str-list');
  var row  = document.createElement('div');
  row.style.cssText = 'display:flex;gap:4px;margin-bottom:4px';
  var color = type === 'found' ? '#4ade80' : '#ef4444';
  row.innerHTML = '<input type="text" value="' + val.replace(/"/g,'&quot;') + '" placeholder="text in body…"'
    + ' style="flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:5px;'
    + 'padding:5px 8px;color:var(--text);font-size:12px">'
    + '<button type="button" onclick="this.parentElement.remove()"'
    + ' style="padding:4px 8px;border-radius:4px;cursor:pointer;border:1px solid '
    + color + ';background:transparent;color:' + color + ';font-size:13px;line-height:1">✕</button>';
  list.appendChild(row);
}}

function _getStrRows(type) {{
  var list  = document.getElementById(type + '-str-list');
  var inputs = list.querySelectorAll('input');
  var vals   = [];
  inputs.forEach(function(inp) {{
    var v = inp.value.trim();
    if (v) vals.push(v);
  }});
  return vals.join('|');
}}

function showAddForm() {{
  document.getElementById('edit-id').value = '';
  document.getElementById('form-title').textContent = '➕ Add Custom Site';
  document.getElementById('f-name').value = '';
  document.getElementById('f-url').value  = '';
  document.getElementById('f-check').value = 'status_code';
  document.getElementById('f-json-path').value = '';
  document.getElementById('f-tags').value = '';
  document.getElementById('f-id-pattern').value = '';
  document.getElementById('f-secondary-url').value = '';
  _setStrRows('found', '');
  _setStrRows('error', '');
  toggleCheckFields();
  document.getElementById('add-form').style.display = 'block';
  document.getElementById('f-name').focus();
}}

function editSite(id) {{
  var s = SITE_DATA[id];
  if (!s) {{ _msg('Site data not found', false); return; }}
  document.getElementById('edit-id').value  = id;
  document.getElementById('form-title').textContent = '✏️ Edit Site';
  document.getElementById('f-name').value      = s.name;
  document.getElementById('f-url').value       = s.url;
  document.getElementById('f-check').value     = s.check;
  document.getElementById('f-json-path').value = s.json_path;
  document.getElementById('f-tags').value      = s.tags;
  document.getElementById('f-id-pattern').value    = s.id_pattern || '';
  document.getElementById('f-secondary-url').value = s.secondary_url || '';
  _setStrRows('found', s.found_str);
  _setStrRows('error', s.error_str);
  toggleCheckFields();
  document.getElementById('add-form').style.display = 'block';
  document.getElementById('add-form').scrollIntoView({{behavior:'smooth'}});
}}

function closeForm() {{
  document.getElementById('add-form').style.display = 'none';
}}

function toggleCheckFields() {{
  var chk  = document.getElementById('f-check').value;
  document.getElementById('ff-json-path').style.display = (chk === 'json_key') ? '' : 'none';
}}

function saveSite() {{
  var id   = document.getElementById('edit-id').value;
  var data = {{
    name:          document.getElementById('f-name').value.trim(),
    url:           document.getElementById('f-url').value.trim(),
    check_type:    document.getElementById('f-check').value,
    found_str:     _getStrRows('found'),
    error_str:     _getStrRows('error'),
    json_path:     document.getElementById('f-json-path').value.trim(),
    tags:          document.getElementById('f-tags').value.split(',').map(function(t){{return t.trim();}}).filter(Boolean),
    id_pattern:    document.getElementById('f-id-pattern').value.trim(),
    secondary_url: document.getElementById('f-secondary-url').value.trim()
  }};
  if (!data.name || !data.url) {{ _msg('Name and URL are required', false); return; }}
  var url    = id ? '/api/userhunt/sites/' + id : '/api/userhunt/sites';
  var method = id ? 'PUT' : 'POST';
  fetch(url, {{
    method: method,
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify(data)
  }}).then(function(r){{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ location.reload(); }}
    else {{ _msg(d.error || 'Save failed', false); }}
  }});
}}

function deleteSite(id) {{
  var name = (SITE_DATA[id] && SITE_DATA[id].name) ? SITE_DATA[id].name : 'this site';
  if (!confirm('Delete "' + name + '"?')) return;
  fetch('/api/userhunt/sites/' + id, {{method:'DELETE'}})
    .then(function(r){{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) {{ document.getElementById('site-row-' + id).remove(); _msg('Deleted', true); }}
      else {{ _msg(d.error || 'Error', false); }}
    }});
}}

function filterSites() {{
  var q = document.getElementById('search-sites').value.toLowerCase();
  document.querySelectorAll('#sites-tbody tr').forEach(function(tr) {{
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}


toggleCheckFields();
_setStrRows('found', '');
_setStrRows('error', '');
</script>
"""
    return _base("Username Hunt Sites", _uh_content, "settings_osint")


@app.route("/api/userhunt/sites", methods=["GET"])
@require_login
def api_uh_list():
    return jsonify(db.get_userhunt_sites(enabled_only=False))


@app.route("/api/userhunt/sites", methods=["POST"])
@require_login
def api_uh_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    url  = (data.get("url") or "").strip()
    if not name or not url:
        return jsonify({"ok": False, "error": "name and url required"})
    url_internal = url.replace("$$username$$", "{u}")
    try:
        db.exec(
            "INSERT INTO userhunt_sites "
            "(name,url,check_type,found_status,miss_status,found_str,error_str,"
            "expect_url,json_path,tags,secondary_url,id_pattern,enabled,is_custom,created_at) "
            "VALUES (?,?,?,200,404,?,?,?,?,?,?,?,1,1,?)",
            (name, url_internal,
             data.get("check_type","status_code"),
             data.get("found_str","") or "",
             data.get("error_str","") or "",
             data.get("expect_url","") or "",
             data.get("json_path","") or "",
             json.dumps(data.get("tags",[]) or []),
             data.get("secondary_url","") or "",
             data.get("id_pattern","") or "",
             _now())
        )
        _audit("userhunt_add", name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/userhunt/sites/<int:sid>", methods=["PUT"])
@require_login
def api_uh_update(sid):
    data = request.get_json(silent=True) or {}
    url_internal = (data.get("url","") or "").replace("$$username$$", "{u}")
    try:
        db.exec(
            "UPDATE userhunt_sites SET name=?,url=?,check_type=?,found_str=?,"
            "error_str=?,json_path=?,tags=?,secondary_url=?,id_pattern=? WHERE id=?",
            ((data.get("name") or "").strip(),
             url_internal,
             data.get("check_type","status_code"),
             data.get("found_str","") or "",
             data.get("error_str","") or "",
             data.get("json_path","") or "",
             json.dumps(data.get("tags",[]) or []),
             data.get("secondary_url","") or "",
             data.get("id_pattern","") or "",
             sid)
        )
        _audit("userhunt_edit", str(sid))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/userhunt/sites/<int:sid>/toggle", methods=["POST"])
@require_login
def api_uh_toggle(sid):
    row = db.one("SELECT enabled FROM userhunt_sites WHERE id=?", (sid,))
    if not row:
        return jsonify({"ok": False, "error": "not found"})
    new_val = 0 if row["enabled"] else 1
    db.exec("UPDATE userhunt_sites SET enabled=? WHERE id=?", (new_val, sid))
    return jsonify({"ok": True, "enabled": bool(new_val)})


@app.route("/api/userhunt/sites/<int:sid>", methods=["DELETE"])
@require_login
def api_uh_delete(sid):
    db.exec("DELETE FROM userhunt_sites WHERE id=?", (sid,))
    _audit("userhunt_delete", str(sid))
    return jsonify({"ok": True})


@app.route("/api/userhunt/sites/bulk-toggle", methods=["POST"])
@require_login
def api_uh_bulk_toggle():
    data = request.get_json(silent=True) or {}
    val  = 1 if data.get("enabled") else 0
    db.exec("UPDATE userhunt_sites SET enabled=?", (val,))
    return jsonify({"ok": True})


# ═════════════════════════════════════════════════════════════════════════════
# USERNAME / EMAIL PATTERN GENERATOR - Settings page + API
# ═════════════════════════════════════════════════════════════════════════════

def _apply_pattern(pattern: str, first: str, middle: str, last: str) -> str | None:
    """Expand a pattern template against name parts. Returns None if a required
    placeholder cannot be filled (e.g. pattern needs {middle} but no middle name)."""
    first  = (first  or "").strip().lower()
    middle = (middle or "").strip().lower()
    last   = (last   or "").strip().lower()
    f = first[0]  if first  else ""
    m = middle[0] if middle else ""
    l = last[0]   if last   else ""

    needs_middle = "{middle}" in pattern or "{m}" in pattern
    needs_first  = "{first}"  in pattern or "{f}" in pattern
    needs_last   = "{last}"   in pattern or "{l}" in pattern

    if needs_first  and not first:  return None
    if needs_last   and not last:   return None
    if needs_middle and not middle: return None

    result = (pattern
        .replace("{first}",  first)
        .replace("{last}",   last)
        .replace("{middle}", middle)
        .replace("{f}", f)
        .replace("{m}", m)
        .replace("{l}", l))
    return result if "{" not in result else None


def expand_name_to_usernames(first: str, middle: str, last: str, patterns: list) -> list:
    """Return a deduplicated list of usernames from all enabled pattern rows."""
    seen, out = set(), []
    for p in patterns:
        u = _apply_pattern(p["pattern"], first, middle, last)
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


@app.route("/settings/username-patterns")
@require_login
def username_pattern_settings():
    patterns = db.get_username_patterns(enabled_only=False)
    total    = len(patterns)
    enabled  = sum(1 for p in patterns if p["enabled"])
    custom   = sum(1 for p in patterns if p["is_custom"])

    rows_html    = ""
    pattern_data = {}
    for p in patterns:
        pid     = p["id"]
        pat_esc = p["pattern"].replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
        desc_e  = (p["description"] or "").replace("&", "&amp;").replace("<", "&lt;")
        ex_e    = (p["example"]     or "").replace("&", "&amp;").replace("<", "&lt;")
        is_en   = p["enabled"]
        is_cust = p["is_custom"]
        tog_col = "#4ade80" if is_en else "var(--muted)"
        tog_lbl = "✓" if is_en else "✗"
        cust_badge = '<span style="font-size:10px;background:rgba(129,140,248,.18);color:#818cf8;border:1px solid #818cf8;border-radius:4px;padding:1px 5px;margin-left:4px">custom</span>' if is_cust else ""
        pattern_data[pid] = {
            "pattern":     p["pattern"],
            "description": p["description"] or "",
            "example":     p["example"]     or "",
        }
        rows_html += f"""
    <tr id="pat-row-{pid}">
      <td style="text-align:center;width:44px">
        <button onclick="togglePat({pid},{1 if is_en else 0})"
                id="pat-tog-{pid}"
                style="background:none;border:none;cursor:pointer;font-size:18px;
                       color:{tog_col};font-weight:700;line-height:1"
                title="{'Disable' if is_en else 'Enable'}">{tog_lbl}</button>
      </td>
      <td style="font-family:monospace;font-size:13px;color:var(--primary)">{pat_esc}{cust_badge}</td>
      <td style="font-size:12px;color:var(--muted)">{desc_e}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--text2)">{ex_e}</td>
      <td style="white-space:nowrap;text-align:right">
        <button onclick="editPat({pid})"
                style="background:none;border:1px solid var(--border);border-radius:4px;
                       padding:2px 10px;font-size:11px;cursor:pointer;color:var(--text);
                       margin-right:4px">✏️ Edit</button>
        <button onclick="deletePat({pid})"
                style="background:none;border:1px solid var(--danger);border-radius:4px;
                       padding:2px 10px;font-size:11px;cursor:pointer;color:var(--danger)">🗑 Del</button>
      </td>
    </tr>"""

    pat_data_js = json.dumps(pattern_data).replace("</", "<\\/").replace("<!--", "<\\!--")

    _content = f"""
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
  <h2 style="margin:0;font-size:18px">🔤 Username / Email Pattern Generator</h2>
  <span style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;
               padding:3px 12px;font-size:12px;color:var(--muted)">{enabled}/{total} enabled · {custom} custom</span>
  <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
    <button onclick="patBulk(1)"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid #4ade80;background:rgba(74,222,128,.08);color:#4ade80">✓ Enable All</button>
    <button onclick="patBulk(0)"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--muted);background:var(--bg3);color:var(--muted)">✗ Disable All</button>
    <button onclick="showPatForm()"
            style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--primary);background:rgba(0,212,255,.08);color:var(--primary)">➕ Add Pattern</button>
    <a href="/settings" style="font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--text);
                   text-decoration:none">← Back to Settings</a>
  </div>
</div>

<div style="background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);border-radius:8px;
            padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--muted)">
  <strong style="color:var(--primary)">Placeholders:</strong>
  &nbsp;<code style="color:var(--text)">{{first}}</code> full first name &nbsp;·&nbsp;
  <code style="color:var(--text)">{{last}}</code> full last name &nbsp;·&nbsp;
  <code style="color:var(--text)">{{middle}}</code> full middle name &nbsp;·&nbsp;
  <code style="color:var(--text)">{{f}}</code> 1st letter of first &nbsp;·&nbsp;
  <code style="color:var(--text)">{{m}}</code> 1st letter of middle &nbsp;·&nbsp;
  <code style="color:var(--text)">{{l}}</code> 1st letter of last
</div>

<div id="pat-msg" style="display:none;padding:8px 14px;border-radius:6px;margin-bottom:12px;font-size:13px;font-weight:500"></div>

<div id="pat-form" style="display:none;background:var(--bg2);border:1px solid var(--border);
                           border-radius:8px;padding:16px;margin-bottom:14px">
  <h3 style="margin:0 0 12px;font-size:14px" id="pat-form-title">➕ Add Pattern</h3>
  <input type="hidden" id="pat-edit-id" value="">
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">
        Pattern <span style="color:var(--danger)">*</span>
      </label>
      <input id="pat-f-pattern" type="text" placeholder="{{first}}.{{last}}"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:13px">
    </div>
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Description</label>
      <input id="pat-f-desc" type="text" placeholder="First.Last format"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-size:13px">
    </div>
    <div>
      <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Example output</label>
      <input id="pat-f-example" type="text" placeholder="john.doe"
             style="width:100%;background:var(--bg3);border:1px solid var(--border);
                    border-radius:5px;padding:6px 10px;color:var(--text);font-family:monospace;font-size:13px">
    </div>
  </div>
  <div style="display:flex;gap:8px">
    <button onclick="savePat()"
            style="padding:7px 20px;border-radius:6px;cursor:pointer;border:none;
                   background:var(--primary);color:#000;font-weight:600;font-size:13px">💾 Save</button>
    <button onclick="closePatForm()"
            style="padding:7px 16px;border-radius:6px;cursor:pointer;
                   border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px">Cancel</button>
  </div>
</div>

<div style="overflow-x:auto">
<table style="width:100%;border-collapse:collapse;font-size:13px">
  <thead>
    <tr style="border-bottom:2px solid var(--border)">
      <th style="padding:8px;text-align:center;width:44px;color:var(--muted)">On</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Pattern</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Description</th>
      <th style="padding:8px;text-align:left;color:var(--muted)">Example</th>
      <th style="padding:8px;text-align:right;color:var(--muted)">Actions</th>
    </tr>
  </thead>
  <tbody id="pat-tbody">
{rows_html}
  </tbody>
</table>
</div>

<script>
const PAT_DATA = {pat_data_js};

function _pmsg(txt, ok) {{
  var b = document.getElementById('pat-msg');
  b.textContent = txt;
  b.style.display = 'block';
  b.style.background = ok ? 'rgba(74,222,128,.12)' : 'rgba(239,68,68,.12)';
  b.style.color = ok ? '#4ade80' : '#ef4444';
  b.style.border = '1px solid ' + (ok ? '#4ade80' : '#ef4444');
  setTimeout(function(){{ b.style.display='none'; }}, 4000);
}}

function togglePat(id, cur) {{
  fetch('/api/username-patterns/' + id + '/toggle', {{method:'POST'}})
    .then(function(r){{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) {{
        var btn = document.getElementById('pat-tog-' + id);
        var en  = d.enabled;
        btn.textContent = en ? '✓' : '✗';
        btn.style.color = en ? '#4ade80' : 'var(--muted)';
        btn.title       = en ? 'Disable' : 'Enable';
        btn.onclick     = function(){{ togglePat(id, en ? 1 : 0); }};
      }} else {{ _pmsg(d.error || 'Error', false); }}
    }});
}}

function patBulk(val) {{
  fetch('/api/username-patterns/bulk-toggle', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{enabled: val}})
  }}).then(function(r){{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ location.reload(); }}
    else {{ _pmsg(d.error || 'Error', false); }}
  }});
}}

function showPatForm() {{
  document.getElementById('pat-edit-id').value = '';
  document.getElementById('pat-form-title').textContent = '➕ Add Pattern';
  document.getElementById('pat-f-pattern').value = '';
  document.getElementById('pat-f-desc').value    = '';
  document.getElementById('pat-f-example').value = '';
  document.getElementById('pat-form').style.display = 'block';
  document.getElementById('pat-f-pattern').focus();
}}

function editPat(id) {{
  var s = PAT_DATA[id];
  if (!s) {{ _pmsg('Pattern data not found', false); return; }}
  document.getElementById('pat-edit-id').value       = id;
  document.getElementById('pat-form-title').textContent = '✏️ Edit Pattern';
  document.getElementById('pat-f-pattern').value     = s.pattern;
  document.getElementById('pat-f-desc').value        = s.description;
  document.getElementById('pat-f-example').value     = s.example;
  document.getElementById('pat-form').style.display  = 'block';
  document.getElementById('pat-form').scrollIntoView({{behavior:'smooth'}});
}}

function closePatForm() {{
  document.getElementById('pat-form').style.display = 'none';
}}

function savePat() {{
  var id   = document.getElementById('pat-edit-id').value;
  var data = {{
    pattern:     document.getElementById('pat-f-pattern').value.trim(),
    description: document.getElementById('pat-f-desc').value.trim(),
    example:     document.getElementById('pat-f-example').value.trim(),
  }};
  if (!data.pattern) {{ _pmsg('Pattern is required', false); return; }}
  var url    = id ? '/api/username-patterns/' + id : '/api/username-patterns';
  var method = id ? 'PUT' : 'POST';
  fetch(url, {{
    method: method, headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify(data)
  }}).then(function(r){{ return r.json(); }}).then(function(d) {{
    if (d.ok) {{ location.reload(); }}
    else {{ _pmsg(d.error || 'Save failed', false); }}
  }});
}}

function deletePat(id) {{
  var name = (PAT_DATA[id] && PAT_DATA[id].pattern) ? PAT_DATA[id].pattern : 'this pattern';
  if (!confirm('Delete pattern "' + name + '"?')) return;
  fetch('/api/username-patterns/' + id, {{method:'DELETE'}})
    .then(function(r){{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) {{ document.getElementById('pat-row-' + id).remove(); _pmsg('Deleted', true); }}
      else {{ _pmsg(d.error || 'Error', false); }}
    }});
}}
</script>
"""
    return _base("Username Patterns", _content, "settings_osint")


# ── Pattern CRUD API ──────────────────────────────────────────────────────────

@app.route("/api/username-patterns", methods=["GET"])
@require_login
def api_up_list():
    return jsonify(db.get_username_patterns(enabled_only=False))


@app.route("/api/username-patterns", methods=["POST"])
@require_login
def api_up_create():
    data = request.get_json(silent=True) or {}
    pattern = (data.get("pattern") or "").strip()
    if not pattern:
        return jsonify({"ok": False, "error": "pattern required"})
    try:
        db.exec(
            "INSERT INTO username_patterns (pattern,description,example,enabled,is_custom,created_at) "
            "VALUES (?,?,?,1,1,?)",
            (pattern, (data.get("description") or "").strip(),
             (data.get("example") or "").strip(), _now())
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/username-patterns/<int:pid>", methods=["PUT"])
@require_login
def api_up_update(pid):
    data = request.get_json(silent=True) or {}
    pattern = (data.get("pattern") or "").strip()
    if not pattern:
        return jsonify({"ok": False, "error": "pattern required"})
    try:
        db.exec(
            "UPDATE username_patterns SET pattern=?,description=?,example=? WHERE id=?",
            (pattern, (data.get("description") or "").strip(),
             (data.get("example") or "").strip(), pid)
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/username-patterns/<int:pid>", methods=["DELETE"])
@require_login
def api_up_delete(pid):
    db.exec("DELETE FROM username_patterns WHERE id=?", (pid,))
    return jsonify({"ok": True})


@app.route("/api/username-patterns/<int:pid>/toggle", methods=["POST"])
@require_login
def api_up_toggle(pid):
    row = db.one("SELECT enabled FROM username_patterns WHERE id=?", (pid,))
    if not row:
        return jsonify({"ok": False, "error": "not found"})
    new_val = 0 if row["enabled"] else 1
    db.exec("UPDATE username_patterns SET enabled=? WHERE id=?", (new_val, pid))
    return jsonify({"ok": True, "enabled": bool(new_val)})


@app.route("/api/username-patterns/bulk-toggle", methods=["POST"])
@require_login
def api_up_bulk_toggle():
    data = request.get_json(silent=True) or {}
    val  = 1 if data.get("enabled") else 0
    db.exec("UPDATE username_patterns SET enabled=?", (val,))
    return jsonify({"ok": True})


# ── Public helper used by username_hunt module ────────────────────────────────
def get_enabled_patterns():
    return db.get_username_patterns(enabled_only=True)


# ═════════════════════════════════════════════════════════════════════════════
# SETTINGS - OSINT
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/settings/osint", methods=["GET","POST"])
@require_login
def settings_osint():
    if not (_is_admin() or _analyst_can("settings")):
        return redirect("/investigations")
    msg = ""
    if request.method == "POST":
        # Crawl depth
        depth = request.form.get("default_crawl_depth","").strip()
        if depth:
            _save_setting("default_crawl_depth", depth)
        # Default modules
        mods_sel = request.form.getlist("default_modules")
        _save_setting("default_modules", json.dumps(mods_sel))
        # Sub-sources
        all_subsrc = {}
        for mid, subsrcs in _MODULE_SUBSOURCES.items():
            mod_subsrc = {}
            for src_key, _label, _default in subsrcs:
                form_key = f"subsrc_{mid}_{src_key}"
                mod_subsrc[src_key] = "1" if request.form.get(form_key) else "0"
            all_subsrc[mid] = mod_subsrc
        _save_setting("module_subsources", json.dumps(all_subsrc))
        # Image search engines - full JSON from hidden field (includes custom engines)
        _img_engs_json = request.form.get("img_engines_json","").strip()
        if _img_engs_json:
            try:
                _parsed_engs = json.loads(_img_engs_json)
                if isinstance(_parsed_engs, list):
                    _save_setting("image_search_engines", json.dumps(_parsed_engs))
            except Exception:
                pass
        _audit("save_osint_settings")
        msg = "OSINT settings saved."

    crawl_depth  = _get_setting("default_crawl_depth","2")
    default_mods = json.loads(_get_setting("default_modules","[]") or "[]")
    saved_subsrc = json.loads(_get_setting("module_subsources","{}") or "{}")

    # ── Build module rows (with expandable sub-sources) ──────────────────
    _pt_total   = db.one("SELECT COUNT(*) as c FROM username_patterns")
    _pt_enabled = db.one("SELECT COUNT(*) as c FROM username_patterns WHERE enabled=1")
    _pt_tc = (_pt_total   or {}).get("c", 0)
    _pt_ec = (_pt_enabled or {}).get("c", 0)
    _pat_link = f'<a href="/settings/username-patterns" style="font-size:11px;padding:3px 10px;border-radius:5px;border:1px solid #a78bfa;color:#a78bfa;text-decoration:none;white-space:nowrap;margin-left:4px" title="Edit name patterns">🔤 {_pt_ec}/{_pt_tc} patterns</a>'

    def_mod_html = ""
    for mid, icon, name, desc in _MODULES_META:
        ck        = "checked" if mid in default_mods else ""
        subsrcs   = _MODULE_SUBSOURCES.get(mid, [])
        mod_saved = saved_subsrc.get(mid, {})
        has_subs  = len(subsrcs) > 0

        sub_rows = ""
        for src_key, src_label, src_default in subsrcs:
            src_enabled = mod_saved.get(src_key, "1" if src_default else "0")
            sub_ck  = "checked" if src_enabled == "1" else ""
            form_key = f"subsrc_{mid}_{src_key}"
            sub_rows += f'<label style="display:flex;align-items:center;gap:7px;padding:4px 0;font-size:12px;color:var(--text-secondary);cursor:pointer"><input type="checkbox" name="{form_key}" value="1" {sub_ck} style="accent-color:#818cf8;width:13px;height:13px"><span>{src_label}</span></label>'

        expand_btn = ""
        sub_panel  = ""
        if has_subs:
            expand_btn = f'<button type="button" onclick="toggleSubsrc(\'{mid}\')" id="expand-{mid}" style="background:none;border:none;cursor:pointer;color:var(--muted);font-size:14px;padding:2px 4px;line-height:1;margin-left:auto" title="Show/hide data sources">▶</button>'
            sub_panel  = f'<div id="subsrc-{mid}" style="display:none;margin-top:6px;padding:8px 10px;background:var(--bg1);border-radius:6px;border:1px solid var(--border)"><div style="font-size:11px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px">Data sources</div>{sub_rows}</div>'

        manage_btn = ""
        if mid == "username":
            uh_total   = db.one("SELECT COUNT(*) as c FROM userhunt_sites")
            uh_enabled = db.one("SELECT COUNT(*) as c FROM userhunt_sites WHERE enabled=1")
            uh_tc = (uh_total   or {}).get("c", 0)
            uh_ec = (uh_enabled or {}).get("c", 0)
            manage_btn = f'<a href="/settings/userhunt" style="font-size:11px;padding:3px 10px;border-radius:5px;border:1px solid var(--primary);color:var(--primary);text-decoration:none;white-space:nowrap;margin-left:4px" title="Manage username hunt sites">⚙️ {uh_ec}/{uh_tc} sites</a>{_pat_link}'
        elif mid in ("emailHarvest", "identity"):
            manage_btn = _pat_link

        def_mod_html += f'''
      <div style="border:1px solid var(--border);border-radius:7px;margin-bottom:6px;background:var(--bg2)">
        <div style="display:flex;align-items:center;gap:8px;padding:8px 10px">
          <input type="checkbox" name="default_modules" value="{mid}" {ck} style="accent-color:#818cf8;flex-shrink:0">
          <span style="font-size:16px">{icon}</span>
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;font-size:13px">{name}</div>
            <div style="font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{desc}</div>
          </div>
          {manage_btn}{expand_btn}
        </div>
        {sub_panel}
      </div>'''

    msg_html = f'<div class="alert alert-success">{msg}</div>' if msg else ""

    # Image search engines - load saved list, merge with hardcoded defaults
    _img_eng_defaults = [
        {"id": "yandex",  "name": "Yandex Images",      "enabled": True,  "is_default": True,  "note": "Upload → full match + pHash similarity (recommended)", "url": ""},
        {"id": "bing",    "name": "Bing Visual Search",  "enabled": True,  "is_default": True,  "note": "Upload → returns search results URL (React SPA)", "url": ""},
        {"id": "tineye",  "name": "TinEye",              "enabled": False, "is_default": True,  "note": "Exact/near-exact match - may return 403 from some IPs", "url": ""},
        {"id": "google",  "name": "Google Lens",         "enabled": False, "is_default": True,  "note": "Upload → experimental, may require CAPTCHA from some IPs", "url": ""},
        {"id": "flickr",  "name": "Flickr Photo Search", "enabled": False, "is_default": True,  "note": "Public photo feed search by context tags + pHash thumbnail similarity", "url": ""},
    ]
    _saved_img_engs = []
    try:
        _saved_img_engs = json.loads(_get_setting("image_search_engines","[]") or "[]")
    except Exception:
        pass
    _saved_map = {e["id"]: e for e in _saved_img_engs}
    _merged_engines = []
    for _def in _img_eng_defaults:
        _sv = _saved_map.get(_def["id"], {})
        _merged_engines.append({
            "id":         _def["id"],
            "name":       _sv.get("name", _def["name"]),
            "enabled":    _sv.get("enabled", _def["enabled"]),
            "is_default": True,
            "note":       _sv.get("note", _def["note"]),
            "url":        "",
        })
    for _sv in _saved_img_engs:
        if not _sv.get("is_default", True) and _sv.get("id","").startswith("custom_"):
            _merged_engines.append({
                "id":         _sv["id"],
                "name":       _sv.get("name","Custom Engine"),
                "enabled":    _sv.get("enabled", True),
                "is_default": False,
                "note":       _sv.get("note",""),
                "url":        _sv.get("url",""),
            })

    _img_eng_rows_html = ""
    for _ie in _merged_engines:
        _ie_chk = "checked" if _ie["enabled"] else ""
        _ie_is_def = _ie["is_default"]
        _ie_id = _ie["id"]
        _ie_name = _html.escape(_ie["name"])
        _ie_note = _html.escape(_ie["note"])
        _ie_url  = _html.escape(_ie["url"])
        _ie_badge = '<span style="font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(99,102,241,.15);color:#818cf8;white-space:nowrap">Built-in</span>' if _ie_is_def else '<span style="font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(74,222,128,.15);color:#4ade80;white-space:nowrap">Custom</span>'
        _ie_del_btn = "" if _ie_is_def else f'<button type="button" onclick="deleteEngine(\'{_ie_id}\')" style="background:none;border:none;cursor:pointer;color:var(--danger);font-size:15px;padding:2px 6px;flex-shrink:0" title="Delete engine">🗑️</button>'
        _ie_url_row = "" if _ie_is_def else (
            f'<input type="text" id="engurl-{_ie_id}" value="{_ie_url}" placeholder="https://example.com/search?url={{image_url}}" '
            f'style="width:100%;background:var(--bg1);border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-size:11px;color:var(--text);margin-top:4px">'
        )
        _img_eng_rows_html += f'''<div class="eng-row" id="eng-row-{_ie_id}" style="border:1px solid var(--border);border-radius:7px;margin-bottom:6px;background:var(--bg2);padding:8px 10px">
  <div style="display:flex;align-items:center;gap:8px">
    <input type="checkbox" id="engtog-{_ie_id}" {'checked' if _ie["enabled"] else ''} style="accent-color:#818cf8;width:14px;height:14px;flex-shrink:0">
    <div style="flex:1;min-width:0">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">
        <input type="text" id="engname-{_ie_id}" value="{_ie_name}" style="background:transparent;border:none;border-bottom:1px solid transparent;font-weight:600;font-size:13px;color:var(--text);padding:1px 3px;flex:1;min-width:0" onfocus="this.style.borderBottomColor='var(--primary)'" onblur="this.style.borderBottomColor='transparent'">
        {_ie_badge}
      </div>
      <input type="text" id="engnote-{_ie_id}" value="{_ie_note}" placeholder="Notes..." style="background:transparent;border:none;border-bottom:1px solid transparent;font-size:11px;color:var(--muted);padding:1px 3px;width:100%" onfocus="this.style.borderBottomColor='var(--primary)'" onblur="this.style.borderBottomColor='transparent'">
      {_ie_url_row}
    </div>
    {_ie_del_btn}
  </div>
</div>'''

    _all_det_pats  = db.rows("SELECT category, COUNT(*) as c FROM osint_patterns GROUP BY category ORDER BY category")
    _det_total     = db.one("SELECT COUNT(*) as c FROM osint_patterns") or {}
    _det_enabled   = db.one("SELECT COUNT(*) as c FROM osint_patterns WHERE enabled=1") or {}
    _det_tc        = _det_total.get("c", 0)
    _det_ec        = _det_enabled.get("c", 0)
    _det_cat_pills = "".join(
        f'<span style="display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:2px 9px;font-size:11px;color:var(--muted);margin:2px">{row["category"]} <strong style="color:var(--text)">{row["c"]}</strong></span>'
        for row in _all_det_pats
    )

    html = f"""
{msg_html}
<form method="POST">
  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <span class="card-title">⚙️ Scan Defaults</span>
    </div>
    <div class="card-body">
      <div class="form-group" style="max-width:200px">
        <label>Default Crawl Depth</label>
        <select name="default_crawl_depth">
          {"".join(f'<option value="{d}" {"selected" if crawl_depth==str(d) else ""}>{d}</option>' for d in range(1,6))}
        </select>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <span class="card-title">🧩 Default Enabled Modules</span>
      <div style="display:flex;gap:6px">
        <button type="button" onclick="modSelectAll(true)" style="font-size:11px;padding:2px 9px;border-radius:5px;cursor:pointer;border:1px solid #4ade80;background:rgba(74,222,128,.08);color:#4ade80">✓ All</button>
        <button type="button" onclick="modSelectAll(false)" style="font-size:11px;padding:2px 9px;border-radius:5px;cursor:pointer;border:1px solid var(--muted);background:var(--bg3);color:var(--muted)">✗ None</button>
      </div>
    </div>
    <div class="card-body">
      <div style="font-size:11px;color:var(--muted);margin-bottom:10px;padding:6px 10px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);border-radius:6px">
        💡 Only <strong>checked</strong> modules are pre-selected when creating a new OSINT scan. Click ▶ on a row to configure sub-sources.
      </div>
      <div style="max-height:600px;overflow-y:auto;padding-right:2px">
        {def_mod_html}
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
      <span class="card-title">🖼️ Image Search Engines (Image OSINT)</span>
      <button type="button" onclick="showAddEngine()" id="add-eng-btn" style="font-size:12px;padding:4px 12px;border-radius:6px;cursor:pointer;border:1px solid #4ade80;background:rgba(74,222,128,.08);color:#4ade80">+ Add Engine</button>
    </div>
    <div class="card-body">
      <div style="font-size:11px;color:var(--muted);margin-bottom:12px;padding:6px 10px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);border-radius:6px">
        💡 <strong>Built-in</strong> engines use automated upload + pHash similarity scoring. <strong>Custom</strong> engines are URL templates (use <code>{{image_url}}</code> placeholder) shown as reference links in findings. Click engine names or notes to edit inline.
      </div>
      <div id="img-eng-list">
        {_img_eng_rows_html}
      </div>
      <div id="add-eng-panel" style="display:none;border:1px solid #4ade80;border-radius:7px;padding:12px;margin-top:8px;background:rgba(74,222,128,.04)">
        <div style="font-size:12px;font-weight:600;color:#4ade80;margin-bottom:8px">➕ New Custom Engine</div>
        <div style="display:flex;flex-direction:column;gap:6px">
          <input type="text" id="new-eng-name" placeholder="Engine name (e.g. SauceNAO)" style="background:var(--bg1);border:1px solid var(--border);border-radius:5px;padding:6px 10px;font-size:13px;color:var(--text)">
          <input type="text" id="new-eng-url" placeholder="Search URL - use {{image_url}} as placeholder" style="background:var(--bg1);border:1px solid var(--border);border-radius:5px;padding:6px 10px;font-size:13px;color:var(--text)">
          <input type="text" id="new-eng-note" placeholder="Optional note / description" style="background:var(--bg1);border:1px solid var(--border);border-radius:5px;padding:6px 10px;font-size:13px;color:var(--text)">
          <div style="display:flex;gap:8px;margin-top:4px">
            <button type="button" onclick="addEngine()" style="padding:5px 14px;border-radius:6px;cursor:pointer;border:1px solid #4ade80;background:rgba(74,222,128,.15);color:#4ade80;font-size:13px">✓ Add</button>
            <button type="button" onclick="hideAddEngine()" style="padding:5px 14px;border-radius:6px;cursor:pointer;border:1px solid var(--muted);background:var(--bg3);color:var(--muted);font-size:13px">✗ Cancel</button>
          </div>
        </div>
      </div>
      <input type="hidden" name="img_engines_json" id="img-engines-json">
    </div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <div class="card-header" style="display:flex;align-items:center;justify-content:space-between">
      <span class="card-title">🔍 Detection Patterns (jsRecon / JS Analysis)</span>
      <a href="/patterns" style="font-size:12px;padding:4px 12px;border-radius:6px;border:1px solid var(--primary);color:var(--primary);text-decoration:none">⚙️ Manage Patterns →</a>
    </div>
    <div class="card-body">
      <div style="font-size:11px;color:var(--muted);margin-bottom:10px;padding:6px 10px;background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.2);border-radius:6px">
        💡 These <strong>{_det_ec}</strong> of <strong>{_det_tc}</strong> enabled regex patterns are applied by the <strong>🔬 jsRecon</strong> module when scanning JavaScript files - detecting leaked secrets, API keys, cloud credentials, and recon signals.
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">
        {_det_cat_pills}
      </div>
    </div>
  </div>

  <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
    <button class="btn btn-primary">💾 Save OSINT Settings</button>
    <a href="/settings/userhunt" class="btn btn-ghost">🎯 Username Hunt Sites →</a>
    <a href="/settings/username-patterns" class="btn btn-ghost">🔤 Name Patterns →</a>
    <a href="/patterns" class="btn btn-ghost">🔍 Detection Patterns →</a>
  </div>
</form>
<script>
function modSelectAll(enable) {{
  document.querySelectorAll('input[name="default_modules"]').forEach(function(cb) {{ cb.checked = enable; }});
  document.querySelectorAll('input[name^="subsrc_"]').forEach(function(cb) {{ cb.checked = enable; }});
}}
function toggleSubsrc(mid) {{
  var panel = document.getElementById('subsrc-' + mid);
  var btn   = document.getElementById('expand-' + mid);
  if (!panel) return;
  var open = panel.style.display !== 'none';
  panel.style.display = open ? 'none' : 'block';
  if (btn) btn.textContent = open ? '▶' : '▼';
}}
function collectEngines() {{
  var engines = [];
  document.querySelectorAll('#img-eng-list .eng-row').forEach(function(row) {{
    var id = row.id.replace('eng-row-','');
    var nameEl = document.getElementById('engname-' + id);
    var noteEl = document.getElementById('engnote-' + id);
    var urlEl  = document.getElementById('engurl-' + id);
    var togEl  = document.getElementById('engtog-' + id);
    var isDef  = !id.startsWith('custom_');
    engines.push({{
      id:         id,
      name:       nameEl ? nameEl.value : id,
      enabled:    togEl  ? togEl.checked : false,
      is_default: isDef,
      note:       noteEl ? noteEl.value : '',
      url:        urlEl  ? urlEl.value : ''
    }});
  }});
  document.getElementById('img-engines-json').value = JSON.stringify(engines);
}}
document.querySelector('form').addEventListener('submit', collectEngines);
function showAddEngine() {{
  document.getElementById('add-eng-panel').style.display = 'block';
  document.getElementById('add-eng-btn').style.display = 'none';
}}
function hideAddEngine() {{
  document.getElementById('add-eng-panel').style.display = 'none';
  document.getElementById('add-eng-btn').style.display = '';
  document.getElementById('new-eng-name').value = '';
  document.getElementById('new-eng-url').value  = '';
  document.getElementById('new-eng-note').value = '';
}}
function addEngine() {{
  var name = document.getElementById('new-eng-name').value.trim();
  var url  = document.getElementById('new-eng-url').value.trim();
  var note = document.getElementById('new-eng-note').value.trim();
  if (!name) {{ alert('Engine name is required'); return; }}
  var eid = 'custom_' + Date.now();
  var row = document.createElement('div');
  row.className = 'eng-row';
  row.id = 'eng-row-' + eid;
  row.style.cssText = 'border:1px solid var(--border);border-radius:7px;margin-bottom:6px;background:var(--bg2);padding:8px 10px';
  var inner = document.createElement('div');
  inner.style.cssText = 'display:flex;align-items:center;gap:8px';
  var tog = document.createElement('input');
  tog.type = 'checkbox'; tog.id = 'engtog-'+eid; tog.checked = true;
  tog.style.cssText = 'accent-color:#818cf8;width:14px;height:14px;flex-shrink:0';
  var mid = document.createElement('div');
  mid.style.cssText = 'flex:1;min-width:0';
  var topRow = document.createElement('div');
  topRow.style.cssText = 'display:flex;align-items:center;gap:6px;margin-bottom:3px';
  var nameInp = document.createElement('input');
  nameInp.type='text'; nameInp.id='engname-'+eid; nameInp.value=name;
  nameInp.style.cssText='background:transparent;border:none;border-bottom:1px solid transparent;font-weight:600;font-size:13px;color:var(--text);padding:1px 3px;flex:1;min-width:0';
  var badge = document.createElement('span');
  badge.textContent='Custom';
  badge.style.cssText='font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(74,222,128,.15);color:#4ade80;white-space:nowrap';
  topRow.appendChild(nameInp); topRow.appendChild(badge);
  var noteInp = document.createElement('input');
  noteInp.type='text'; noteInp.id='engnote-'+eid; noteInp.value=note;
  noteInp.placeholder='Notes...';
  noteInp.style.cssText='background:transparent;border:none;border-bottom:1px solid transparent;font-size:11px;color:var(--muted);padding:1px 3px;width:100%';
  var urlInp = document.createElement('input');
  urlInp.type='text'; urlInp.id='engurl-'+eid; urlInp.value=url;
  urlInp.placeholder='https://example.com/search?url={{image_url}}';
  urlInp.style.cssText='width:100%;background:var(--bg1);border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-size:11px;color:var(--text);margin-top:4px';
  mid.appendChild(topRow); mid.appendChild(noteInp); mid.appendChild(urlInp);
  var delBtn = document.createElement('button');
  delBtn.type='button'; delBtn.textContent='🗑️';
  delBtn.style.cssText='background:none;border:none;cursor:pointer;color:var(--danger);font-size:15px;padding:2px 6px;flex-shrink:0';
  delBtn.setAttribute('onclick','deleteEngine(this.closest(".eng-row").id.replace("eng-row-",""))');
  inner.appendChild(tog); inner.appendChild(mid); inner.appendChild(delBtn);
  row.appendChild(inner);
  document.getElementById('img-eng-list').appendChild(row);
  hideAddEngine();
}}
function deleteEngine(id) {{
  var row = document.getElementById('eng-row-' + id);
  if (row) row.remove();
}}
</script>"""
    return _base("Settings - OSINT", html, "settings_osint")


# ═════════════════════════════════════════════════════════════════════════════
# SETTINGS - LEAKS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/settings/leaks", methods=["GET","POST"])
@require_admin
def settings_leaks():
    import os as _os
    msg      = ""
    msg_type = "success"
    if request.method == "POST":
        action = request.form.get("action","")

        if action == "save_server":
            _save_setting("leaks_server_url", request.form.get("srv_url","").strip())
            _save_setting("leaks_server_key", request.form.get("srv_key","").strip())
            _audit("save_leaks_server_config")
            msg = "Leaks server configuration saved."

        elif action == "clear_server":
            _save_setting("leaks_server_url", "")
            _save_setting("leaks_server_key", "")
            _audit("clear_leaks_server_config")
            msg = "Leaks server configuration cleared."

        elif action == "add_remote_dir":
            rdir = request.form.get("remote_dir","").strip()
            if rdir:
                resp, st = _leaks_server_call("POST", "/api/dirs", {"path": rdir})
                if resp and resp.get("ok"):
                    _audit("add_remote_leak_dir", detail=rdir)
                    msg = f"Remote directory added: {rdir}"
                else:
                    err = (resp or {}).get("error","Connection failed")
                    msg = f"Error: {err}"
                    msg_type = "danger"
            else:
                msg = "No path provided."
                msg_type = "danger"

        elif action == "remove_remote_dir":
            rdir = request.form.get("remote_dir","").strip()
            if rdir:
                resp, st = _leaks_server_call("DELETE", "/api/dirs", {"path": rdir})
                _audit("remove_remote_leak_dir", detail=rdir)
                msg = f"Remote directory removed."

        elif action == "add":
            dirs    = json.loads(_get_setting("leak_directories","[]") or "[]")
            new_dir = request.form.get("new_dir","").strip()
            if new_dir and new_dir not in dirs:
                dirs.append(new_dir)
                _save_setting("leak_directories", json.dumps(dirs))
                _audit("add_leak_directory", detail=new_dir)
                msg = "Local directory added."
            elif new_dir in dirs:
                msg = "Directory already in list."
            else:
                msg = "No directory path provided."

        elif action == "remove":
            dirs = json.loads(_get_setting("leak_directories","[]") or "[]")
            rm   = request.form.get("dir","")
            dirs = [d for d in dirs if d != rm]
            _save_setting("leak_directories", json.dumps(dirs))
            _audit("remove_leak_directory", detail=rm)
            msg  = "Directory removed."

        elif action == "save_dehashed":
            dh_key     = request.form.get("dh_key","").strip()
            dh_enabled = bool(request.form.get("dh_enabled"))
            payload    = {"enabled": dh_enabled}
            if dh_key:
                payload["api_key"] = dh_key
            resp, st = _leaks_server_call("POST", "/api/dehashed/config", payload)
            if resp and resp.get("ok"):
                _audit("save_dehashed_config")
                msg = "DeHashed configuration saved."
            else:
                err = (resp or {}).get("error","Could not reach leaks server")
                msg = f"Error: {err}"
                msg_type = "danger"

        elif action == "test_dehashed":
            dh_key  = request.form.get("dh_key","").strip()
            payload = {}
            if dh_key:
                payload["api_key"] = dh_key
            resp, st = _leaks_server_call("POST", "/api/dehashed/test", payload)
            if resp and resp.get("ok"):
                bal = resp.get("balance","?")
                msg = f"DeHashed connected. Balance: {bal} credits"
            else:
                err = (resp or {}).get("error","Connection failed")
                msg = f"DeHashed error: {err}"
                msg_type = "danger"

    # ── Read current state ─────────────────────────────────────────────────
    _script_dir  = _os.path.dirname(_os.path.abspath(__file__))
    _builtin_dir = _os.path.join(_script_dir, "leaks", "data")
    _extra_dirs  = json.loads(_get_setting("leak_directories","[]") or "[]")
    _srv_url     = (_get_setting("leaks_server_url","") or "").strip()
    _srv_key     = (_get_setting("leaks_server_key","") or "").strip()

    def _dir_stats(d):
        if not _os.path.isdir(d):
            return "⚠️ not found"
        count = 0
        files = 0
        for fn in _os.listdir(d):
            if fn.endswith(".txt"):
                files += 1
                try:
                    with open(_os.path.join(d, fn), encoding="utf-8", errors="ignore") as fh:
                        count += sum(1 for _ in fh)
                except Exception:
                    pass
        return f"{count:,} records in {files} file(s)"

    # ── Remote server health ───────────────────────────────────────────────
    _srv_health_html = ""
    _remote_rows     = ""
    _dh_cfg          = {}
    if _srv_url and _srv_key:
        try:
            import urllib.request as _ureq2
            _hr  = _ureq2.Request(_srv_url.rstrip("/") + "/health", method="GET")
            _hr.add_header("X-Leaks-Key", _srv_key)
            with _ureq2.urlopen(_hr, timeout=5) as _r2:
                _hdata = json.loads(_r2.read())
            _srv_health_html = (
                '<span style="color:#4ade80;font-weight:700">● Online</span>'
                f' &nbsp;<span style="color:var(--muted);font-size:12px">'
                f'{_hdata.get("dirs",0)} director(ies) configured</span>'
            )
            dr, _ = _leaks_server_call("GET", "/api/dirs")
            _dhr, _ = _leaks_server_call("GET", "/api/dehashed/config")
            if _dhr and _dhr.get("ok"):
                _dh_cfg = _dhr
            for _rd in (dr or {}).get("dirs", []):
                _rde = _html.escape(_rd.get("path",""))
                _rfi = _rd.get("files",0)
                _rre = _rd.get("records",0)
                _rexists = _rd.get("exists", True)
                _rstat = f"{_rre:,} records in {_rfi} file(s)" if _rexists else "⚠️ not found"
                _remote_rows += (
                    f'<tr>'
                    f'<td style="font-family:monospace;font-size:13px">{_rde}</td>'
                    f'<td style="color:var(--muted);font-size:12px">{_rstat}</td>'
                    f'<td>'
                    f'<form method="post" style="display:inline">'
                    f'<input type="hidden" name="action" value="remove_remote_dir">'
                    f'<input type="hidden" name="remote_dir" value="{_rde}">'
                    f'<button class="btn btn-danger btn-sm">Remove</button>'
                    f'</form></td></tr>'
                )
        except Exception as _he:
            _srv_health_html = f'<span style="color:#f87171;font-weight:700">● Offline</span> <span style="color:var(--muted);font-size:12px">{_html.escape(str(_he))}</span>'
    elif _srv_url:
        _srv_health_html = '<span style="color:#fbbf24">● Key not set</span>'

    if not _remote_rows:
        _remote_rows = '<tr><td colspan="3" style="color:var(--muted);font-style:italic">No remote directories configured.</td></tr>'

    _builtin_stat = _dir_stats(_builtin_dir)
    _msg_html     = (f'<div class="alert alert-{msg_type}" style="margin-bottom:14px">{_html.escape(msg)}</div>'
                     if msg else "")
    _srv_url_esc  = _html.escape(_srv_url)
    _srv_key_esc  = _html.escape(_srv_key)
    _health_block = (
        f'<div style="margin-bottom:12px"><strong>Status: </strong>{_srv_health_html}</div>'
        if _srv_url else ""
    )
    _remote_card  = ""
    if _srv_url and _srv_key:
        _remote_card = f"""
<div class="card" style="margin-bottom:16px">
  <div class="card-header"><span class="card-title">🗂️ Remote Server Directories</span></div>
  <div class="card-body">
    <table class="table" style="margin-bottom:16px">
      <thead><tr><th>Path on Leaks Server</th><th>Stats</th><th></th></tr></thead>
      <tbody>{_remote_rows}</tbody>
    </table>
    <form method="post" style="display:flex;gap:10px;align-items:center">
      <input type="hidden" name="action" value="add_remote_dir">
      <input type="text" name="remote_dir" class="form-control" placeholder="/absolute/path/on/leaks/server" style="flex:1">
      <button class="btn btn-primary">+ Add Remote Dir</button>
    </form>
    <p style="color:var(--muted);font-size:12px;margin-top:8px">
      The path must exist on the machine running the Leaks Server. The server validates it before adding.
    </p>
  </div>
</div>"""

    _dh_card = ""
    if _srv_url and _srv_key and _dh_cfg:
        _dh_enabled = "checked" if _dh_cfg.get("dehashed_enabled") else ""
        _dh_key_ph  = "API key set - leave blank to keep" if _dh_cfg.get("has_key") else "Paste your DeHashed v2 API key"
        _dh_card = f"""
<div class="card" style="margin-bottom:16px;border:1px solid rgba(251,191,36,0.3)">
  <div class="card-header" style="background:rgba(251,191,36,0.06)">
    <span class="card-title">&#128273; DeHashed Integration</span>
    <span style="color:var(--muted);font-size:12px;margin-left:8px">Cloud credential search &mdash;
      <a href="https://dehashed.com" target="_blank" style="color:var(--accent)">dehashed.com</a></span>
  </div>
  <div class="card-body">
    <form method="post">
      <input type="hidden" name="action" value="save_dehashed">
      <div style="margin-bottom:12px">
        <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">API Key</label>
        <input type="text" name="dh_key" class="form-control"
          placeholder="{_dh_key_ph}" style="font-family:monospace;max-width:520px">
      </div>
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:14px">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px">
          <input type="checkbox" name="dh_enabled" value="1" {_dh_enabled}
            style="width:16px;height:16px">
          Enable DeHashed in searches
        </label>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary">Save</button>
        <button type="submit" formaction="/settings/leaks" name="action" value="test_dehashed"
          class="btn btn-ghost">Test Connection</button>
      </div>
    </form>
    <p style="color:var(--muted);font-size:12px;margin-top:10px">
      Uses <strong>DeHashed API v2</strong> &mdash; POST with <code>DeHashed-Api-Key</code> header.
      Get your key at <a href="https://dehashed.com/profile" target="_blank"
        style="color:var(--accent)">dehashed.com/profile</a>.
      Results merge with local file results and are tagged with their source database.
    </p>
  </div>
</div>"""

    _extra_rows = ""
    for _d in _extra_dirs:
        _stat = _dir_stats(_d)
        _de   = _html.escape(_d)
        _extra_rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-size:13px">{_de}</td>'
            f'<td style="color:var(--muted);font-size:12px">{_stat}</td>'
            f'<td>'
            f'<form method="post" style="display:inline">'
            f'<input type="hidden" name="action" value="remove">'
            f'<input type="hidden" name="dir" value="{_de}">'
            f'<button class="btn btn-danger btn-sm">Remove</button>'
            f'</form>'
            f'</td>'
            f'</tr>'
        )
    if not _extra_rows:
        _extra_rows = '<tr><td colspan="3" style="color:var(--muted);font-style:italic">No additional local directories configured.</td></tr>'

    html = f"""
{_msg_html}
<h2 style="font-size:20px;font-weight:700;color:var(--text);margin-bottom:16px">⚙️ Config Leaks</h2>
<p style="color:var(--muted);font-size:13px;margin-bottom:20px">
  Configure credential exposure data sources. Searches run against the remote Leaks Server (if configured)
  or fall back to local directories.
  <a href="/leaks" style="color:var(--accent)">→ Go to Search Leaks</a>
</p>

<div class="card" style="margin-bottom:16px;border:1px solid var(--border)">
  <div class="card-header" style="background:rgba(139,92,246,0.08)">
    <span class="card-title">🔌 Remote Leaks Server</span>
    <span style="color:var(--muted);font-size:12px;margin-left:8px">Run <code>leaks_server/start.sh</code> on the data host</span>
  </div>
  <div class="card-body">
    {_health_block}
    <form method="post">
      <input type="hidden" name="action" value="save_server">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div>
          <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Server URL</label>
          <input type="text" name="srv_url" class="form-control" value="{_srv_url_esc}"
            placeholder="http://127.0.0.1:5002">
        </div>
        <div>
          <label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">API Key</label>
          <input type="text" name="srv_key" class="form-control" value="{_srv_key_esc}"
            placeholder="Paste key from leaks server startup output" style="font-family:monospace">
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary">Save Server Config</button>
        <button class="btn btn-ghost" formaction="/settings/leaks" name="action" value="clear_server"
          onclick="return confirm('Clear server config?')">Clear</button>
      </div>
    </form>
    <p style="color:var(--muted);font-size:12px;margin-top:10px">
      When a server is configured, <strong>all searches proxy to it</strong> - local directories below are ignored.
      Leave blank to use local-only mode.
    </p>
  </div>
</div>

{_remote_card}

{_dh_card}

<div class="card" style="margin-bottom:16px">
  <div class="card-header"><span class="card-title">&#128193; Built-in Local Data Directory</span></div>
  <div class="card-body">
    <div style="display:flex;align-items:center;gap:16px">
      <code style="font-size:13px;color:var(--text)">{_html.escape(_builtin_dir)}</code>
      <span style="color:var(--muted);font-size:12px">{_builtin_stat}</span>
    </div>
    <p style="color:var(--muted);font-size:12px;margin-top:8px">
      Sample data for testing. Place your own <code>.txt</code> files here or add external directories below.
      Used only in <strong>local mode</strong> (no remote server configured).
    </p>
  </div>
</div>

<div class="card" style="margin-bottom:16px">
  <div class="card-header"><span class="card-title">📂 Additional Local Directories</span></div>
  <div class="card-body">
    <table class="table" style="margin-bottom:16px">
      <thead><tr><th>Path</th><th>Stats</th><th></th></tr></thead>
      <tbody>{_extra_rows}</tbody>
    </table>
    <form method="post" style="display:flex;gap:10px;align-items:center">
      <input type="hidden" name="action" value="add">
      <input type="text" name="new_dir" class="form-control" placeholder="/path/to/leak/data" style="flex:1">
      <button class="btn btn-primary">+ Add Local Directory</button>
    </form>
    <p style="color:var(--muted);font-size:12px;margin-top:8px">
      Absolute path accessible by the FEROXSEI process. Used only in local mode.
    </p>
  </div>
</div>

<div style="display:flex;gap:10px">
  <a href="/settings" class="btn btn-ghost">← General Settings</a>
  <a href="/leaks" class="btn btn-ghost">🔐 Search Leaks</a>
</div>"""
    return _base("Settings - Leaks", html, "settings_leaks")


# ═════════════════════════════════════════════════════════════════════════════
# PHISHING TEMPLATES API
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/api/phishing/templates", methods=["GET"])
@require_login
def api_phishing_templates_list():
    rows = db.rows("SELECT * FROM phishing_templates ORDER BY name")
    return jsonify({"ok": True, "templates": [dict(r) for r in rows]})

@app.route("/api/phishing/templates", methods=["POST"])
@require_login
def api_phishing_template_create():
    data     = request.get_json(silent=True) or request.form
    name     = (data.get("name") or "").strip()
    subject  = (data.get("subject") or "").strip()
    html_body = data.get("html_body") or ""
    text_body = data.get("text_body") or ""
    if not name or not subject:
        return jsonify({"ok": False, "error": "name and subject required"}), 400
    tid = str(uuid.uuid4())
    uid = flask_session.get("uid", "system")
    db.exec(
        "INSERT INTO phishing_templates (id,user_id,name,subject,html_body,text_body,category,is_default,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?,?,0,?,?)",
        (tid, uid, name, subject, html_body, text_body, "custom", _now(), _now())
    )
    return jsonify({"ok": True, "id": tid})

@app.route("/api/phishing/templates/<tid>", methods=["DELETE"])
@require_login
def api_phishing_template_delete(tid):
    row = db.one("SELECT is_default FROM phishing_templates WHERE id=?", (tid,))
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    if row["is_default"]:
        return jsonify({"ok": False, "error": "cannot delete built-in template"}), 400
    db.exec("DELETE FROM phishing_templates WHERE id=?", (tid,))
    return jsonify({"ok": True})

# PHISHING SENDING PROFILES API
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/api/phishing/profiles", methods=["GET"])
@require_admin
def api_phishing_profiles_list():
    rows = db.rows("SELECT * FROM phishing_sending_profiles ORDER BY name")
    return jsonify({"ok": True, "profiles": [dict(r) for r in rows]})

@app.route("/api/phishing/profiles", methods=["POST"])
@require_admin
def api_phishing_profile_create():
    f = request.form
    pid = str(uuid.uuid4())
    db.exec("""INSERT INTO phishing_sending_profiles(id,user_id,name,from_name,from_address,from_email,
        smtp_host,smtp_port,smtp_user,smtp_password,use_tls,use_ssl,reply_to,send_delay,use_tor,
        auth_type,oauth_client_id,oauth_client_secret,oauth_tenant_id,oauth_refresh_token,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, flask_session["uid"],
         f.get("name","Unnamed"), f.get("from_name",""), f.get("from_address",""), f.get("from_address",""),
         f.get("smtp_host","localhost"), int(f.get("smtp_port",587) or 587),
         f.get("smtp_user",""), f.get("smtp_password",""),
         1 if str(f.get("use_tls","0")).lower() in ("1","true","on","yes") else 0,
         1 if str(f.get("use_ssl","0")).lower() in ("1","true","on","yes") else 0,
         f.get("reply_to",""), float(f.get("send_delay",2.0) or 2.0),
         1 if str(f.get("use_tor","0")).lower() in ("1","true","on","yes") else 0,
         f.get("auth_type","basic"),
         f.get("oauth_client_id",""), f.get("oauth_client_secret",""),
         f.get("oauth_tenant_id","common"), f.get("oauth_refresh_token",""),
         _now()))
    _audit("create_sending_profile", "profile", pid, f.get("name",""))
    return jsonify({"ok": True, "id": pid})

@app.route("/api/phishing/profiles/<pid>", methods=["PUT"])
@require_admin
def api_phishing_profile_update(pid):
    f = request.form or request.get_json(silent=True) or {}
    if isinstance(f, dict):
        get = f.get
    else:
        get = f.get
    row = db.one("SELECT id FROM phishing_sending_profiles WHERE id=?", (pid,))
    if not row:
        return jsonify({"ok": False, "error": "Profile not found"}), 404
    db.exec("""UPDATE phishing_sending_profiles SET
        name=?,from_name=?,from_address=?,from_email=?,
        smtp_host=?,smtp_port=?,smtp_user=?,smtp_password=?,
        use_tls=?,use_ssl=?,reply_to=?,send_delay=?,use_tor=?,
        auth_type=?,oauth_client_id=?,oauth_client_secret=?,
        oauth_tenant_id=?,oauth_refresh_token=?
        WHERE id=?""",
        (get("name","Unnamed"), get("from_name",""), get("from_address",""), get("from_address",""),
         get("smtp_host","localhost"), int(get("smtp_port",587) or 587),
         get("smtp_user",""), get("smtp_password",""),
         1 if str(get("use_tls","0")).lower() in ("1","true","on","yes") else 0,
         1 if str(get("use_ssl","0")).lower() in ("1","true","on","yes") else 0,
         get("reply_to",""), float(get("send_delay",2.0) or 2.0),
         1 if str(get("use_tor","0")).lower() in ("1","true","on","yes") else 0,
         get("auth_type","basic"),
         get("oauth_client_id",""), get("oauth_client_secret",""),
         get("oauth_tenant_id","common"), get("oauth_refresh_token",""),
         pid))
    _audit("edit_sending_profile", "profile", pid, get("name",""))
    return jsonify({"ok": True})

@app.route("/api/phishing/profiles/<pid>", methods=["DELETE"])
@require_admin
def api_phishing_profile_delete(pid):
    db.exec("DELETE FROM phishing_sending_profiles WHERE id=?", (pid,))
    _audit("delete_sending_profile", "profile", pid, "")
    return jsonify({"ok": True})

@app.route("/api/phishing/profiles/<pid>/test", methods=["POST"])
@require_admin
def api_phishing_profile_test(pid):
    import smtplib as _smtplib, ssl as _ssl_mod, email.policy as _epol3
    import email.mime.text as _mime_text, email.mime.multipart as _mime_multi
    from email.utils import formatdate as _fmtdate3
    row = db.one("SELECT * FROM phishing_sending_profiles WHERE id=?", (pid,))
    if not row:
        return jsonify({"ok": False, "error": "Profile not found"}), 404
    data    = request.get_json(silent=True) or {}
    test_to = (data.get("test_to", "") or "").strip()
    if not test_to:
        return jsonify({"ok": False, "error": "Provide a recipient address (test_to)."}), 400
    try:
        host      = row.get("smtp_host", "localhost")
        port      = int(row.get("smtp_port", 587))
        user      = row.get("smtp_user", "")
        pwd       = row.get("smtp_password", "")
        use_tls   = bool(row.get("use_tls", True))
        use_ssl   = bool(row.get("use_ssl", False))
        from_addr = row.get("from_address","") or row.get("from_email","") or "feroxsei@localhost"
        global_mode = ""
        prof_name = row.get("name", "")
        # Build a simple plain verification email (no phishing content)
        msg = _mime_multi.MIMEMultipart("alternative")
        msg["Date"]    = _fmtdate3(localtime=True)
        msg["Subject"] = "FEROXSEI OSINT - SMTP Profile Test"
        msg["From"]    = from_addr
        msg["To"]      = test_to
        plain = (f"FEROXSEI OSINT SMTP configuration test.\n"
                 f"Profile: {prof_name}\nServer: {host}:{port}\n\n"
                 f"This is an automated verification email. No action needed.")
        _esc_prof = _html.escape(prof_name)
        _esc_host = _html.escape(host)
        html_body = (
            '<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '</head>'
            '<body style="margin:0;padding:0;background:#f0f4f8;font-family:Arial,Helvetica,sans-serif">'
            '<table width="100%" cellpadding="0" cellspacing="0"><tr>'
            '<td align="center" style="padding:40px 20px">'
            '<table width="560" cellpadding="0" cellspacing="0" '
            'style="background:#ffffff;border-radius:8px;border:1px solid #dde3ed;overflow:hidden">'
            '<tr><td style="background:#0f172a;padding:28px 32px">'
            '<p style="margin:0;font-size:20px;font-weight:700;color:#38bdf8;letter-spacing:.5px">'
            '&#9670; FEROXSEI OSINT</p>'
            '<p style="margin:6px 0 0;font-size:12px;color:#64748b">SMTP Profile Verification</p>'
            '</td></tr>'
            '<tr><td style="padding:32px">'
            '<p style="margin:0 0 6px;font-size:22px">&#9989; Delivery confirmed</p>'
            f'<p style="color:#475569;margin:12px 0">Profile <strong>{_esc_prof}</strong> '
            f'successfully reached <code style="background:#f1f5f9;padding:2px 7px;'
            f'border-radius:4px;font-size:13px">{_esc_host}:{port}</code>.</p>'
            '<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">'
            '<p style="color:#94a3b8;font-size:12px;margin:0">'
            'This is an automated SMTP configuration test from FEROXSEI OSINT. '
            'No action is required.</p>'
            '</td></tr>'
            '</table></td></tr></table>'
            '</body></html>'
        )
        msg.attach(_mime_text.MIMEText(plain, "plain", "utf-8"))
        msg.attach(_mime_text.MIMEText(html_body, "html", "utf-8"))
        # Connect and send using smtplib directly
        if use_ssl:
            ctx  = _ssl_mod.create_default_context()
            smtp = _smtplib.SMTP_SSL(host, port, timeout=15, context=ctx)
        else:
            smtp = _smtplib.SMTP(host, port, timeout=15)
        if use_tls and not use_ssl:
            smtp.starttls()
        if user and pwd:
            smtp.login(user, pwd)
        smtp.sendmail(from_addr, [test_to], msg.as_bytes(policy=_epol3.SMTP))
        smtp.quit()
        success_msg = f"Test email delivered to {test_to} via {host}:{port}"
        if host in ("mailhog", "localhost", "127.0.0.1") and port == 1025:
            success_msg += " - check MailHog inbox at http://localhost:8025"
        _audit("test_phishing_smtp", detail=f"profile={pid} to={test_to}")
        return jsonify({"ok": True, "message": success_msg})
    except Exception as e:
        err = str(e)
        host = row.get("smtp_host","localhost")
        port = int(row.get("smtp_port", 587))
        if ("111" in err or "refused" in err.lower()) and (port == 1025 or host in ("mailhog","localhost","127.0.0.1")):
            err = (f"Connection refused on {host}:{port}. "
                   "MailHog is not running. "
                   "Local: run 'mailhog' in a terminal. "
                   "Docker: start with docker compose up -d.")
        return jsonify({"ok": False, "error": err})


@app.route("/api/phishing/campaign/<campaign_id>/results", methods=["GET"])
@require_login
def api_phishing_campaign_results(campaign_id):
    """Return phishing_results rows for a campaign (RIDs + tracking status)."""
    rows = db.rows(
        "SELECT id, target_email, target_first, target_last, status, "
        "opened_at, clicked_at, submitted_at, ip_address, last_error "
        "FROM phishing_results WHERE campaign_id=? ORDER BY rowid",
        (campaign_id,)
    )
    results = [
        {
            "id":           r.get("id",""),
            "target_email": r.get("target_email",""),
            "target_first": r.get("target_first",""),
            "target_last":  r.get("target_last",""),
            "status":       r.get("status",""),
            "opened_at":    r.get("opened_at",""),
            "clicked_at":   r.get("clicked_at",""),
            "submitted_at": r.get("submitted_at",""),
            "ip_address":   r.get("ip_address",""),
            "last_error":   r.get("last_error",""),
        }
        for r in rows
    ]
    return jsonify({"ok": True, "results": results})


# ═════════════════════════════════════════════════════════════════════════════
# SETTINGS - PHISHING TEMPLATES
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/settings/phishing", methods=["GET","POST"])
@require_login
def settings_phishing():
    uid      = flask_session["uid"]
    is_admin = _is_admin()
    msg = ""

    if request.method == "POST":
        action = request.form.get("action","")
        if action == "create":
            tid = str(uuid.uuid4())
            db.exec("""INSERT INTO phishing_templates(id,user_id,name,subject,html_body,category,is_default,created_at,updated_at)
                VALUES(?,?,?,?,?,?,0,?,?)""",
                (tid, uid,
                 request.form.get("name","Untitled Template"),
                 request.form.get("subject",""),
                 request.form.get("html_body",""),
                 request.form.get("category","general"),
                 _now(), _now()))
            msg = "Template created."
        elif action == "edit":
            tid = request.form.get("tid","")
            tpl = db.one("SELECT * FROM phishing_templates WHERE id=?", (tid,))
            if tpl and (is_admin or tpl["user_id"] == uid):
                db.upd("phishing_templates", {
                    "name":     request.form.get("name",""),
                    "subject":  request.form.get("subject",""),
                    "html_body":request.form.get("html_body",""),
                    "category": request.form.get("category","general"),
                    "updated_at":_now()
                }, "id=?", (tid,))
                msg = "Template updated."
        elif action == "delete":
            tid = request.form.get("tid","")
            tpl = db.one("SELECT * FROM phishing_templates WHERE id=?", (tid,))
            if tpl and not tpl.get("is_default") and (is_admin or tpl["user_id"] == uid):
                db.exec("DELETE FROM phishing_templates WHERE id=?", (tid,))
                msg = "Template deleted."
        elif action == "save_infra":
            _save_setting("phishing_public_url", request.form.get("phishing_public_url","").strip())
            _audit("save_phishing_infra")
            msg = "Infrastructure settings saved."

    # Fetch templates: system defaults + user's own
    if is_admin:
        templates = db.rows("SELECT * FROM phishing_templates ORDER BY is_default DESC, category, name")
    else:
        templates = db.rows("SELECT * FROM phishing_templates WHERE is_default=1 OR user_id=? ORDER BY is_default DESC, category, name", (uid,))

    cats = sorted(set(t.get("category","general") for t in templates))
    tpl_js_map = json.dumps({t["id"]: {"name":t["name"],"subject":t["subject"],"html_body":t["html_body"],"category":t.get("category","general")} for t in templates}).replace("</","<\\/").replace("<!--","<\\!--")

    tpl_rows = ""
    for t in templates:
        lock = "🔒 " if t.get("is_default") else ""
        del_btn = (f'<button onclick="deleteTemplate(\'{t["id"]}\')" class="btn btn-danger btn-sm" title="Delete">🗑</button>'
                   if not t.get("is_default") else
                   '<span class="badge badge-blue btn-sm">Default</span>')
        tpl_rows += f"""<tr>
          <td><strong style="color:var(--text)">{lock}{_html.escape(t.get('name',''))}</strong></td>
          <td><span class="badge badge-info" style="font-size:10px">{_html.escape(t.get('category',''))}</span></td>
          <td class="text-sm text-muted">{_html.escape(t.get('subject','')[:60])}</td>
          <td>
            <div class="flex gap-2">
              <button onclick="previewTemplate('{t['id']}')" class="btn btn-ghost btn-sm">👁 Preview</button>
              <button onclick="editTemplate('{t['id']}')" class="btn btn-ghost btn-sm">✏️ Edit</button>
              {del_btn}
            </div>
          </td>
        </tr>"""
    if not tpl_rows:
        tpl_rows = '<tr><td colspan=4 style="text-align:center;padding:20px;color:var(--muted)">No templates yet</td></tr>'

    profiles   = db.rows("SELECT * FROM phishing_sending_profiles ORDER BY name")
    public_url = _get_setting("phishing_public_url", "")
    auto_url   = request.host_url.rstrip("/")

    # ── Build sending profiles list HTML ─────────────────────────────────
    _prof_js_map = {}
    if profiles:
        profiles_html = '<table><thead><tr><th>Name</th><th>From</th><th>SMTP</th><th>Auth</th><th>Actions</th></tr></thead><tbody>'
        for p in profiles:
            tls_badge  = '<span style="color:#4ade80;font-size:11px">TLS</span>' if p.get("use_tls") else ''
            ssl_badge  = '<span style="color:#4ade80;font-size:11px">SSL</span>' if p.get("use_ssl") else ''
            tor_badge  = '<span style="color:#c084fc;font-size:11px">TOR</span>' if p.get("use_tor") else ''
            auth_type  = p.get("auth_type","basic")
            oauth_badge = '<span style="color:#818cf8;font-size:11px;background:rgba(129,140,248,.12);border-radius:4px;padding:1px 5px">OAuth2</span>' if auth_type == "oauth2" else ''
            auth_tag   = (oauth_badge or ('<span style="color:#4ade80;font-size:11px">✓ Basic</span>' if p.get("smtp_user") else '<span style="color:var(--muted);font-size:11px">No Auth</span>'))
            pid_esc    = _html.escape(p["id"])
            _prof_js_map[p["id"]] = {
                "name":       p.get("name",""),
                "from_name":  p.get("from_name",""),
                "from_addr":  p.get("from_address","") or p.get("from_email",""),
                "reply_to":   p.get("reply_to",""),
                "smtp_host":  p.get("smtp_host",""),
                "smtp_port":  p.get("smtp_port",587),
                "smtp_user":  p.get("smtp_user",""),
                "use_tls":    bool(p.get("use_tls",1)),
                "use_ssl":    bool(p.get("use_ssl",0)),
                "use_tor":    bool(p.get("use_tor",0)),
                "send_delay": p.get("send_delay",2.0),
                "auth_type":  auth_type,
                "oauth_client_id":     p.get("oauth_client_id",""),
                "oauth_client_secret": p.get("oauth_client_secret",""),
                "oauth_tenant_id":     p.get("oauth_tenant_id","common"),
                "oauth_refresh_token": p.get("oauth_refresh_token",""),
            }
            profiles_html += f"""<tr>
              <td style="font-weight:600">{_html.escape(p.get("name",""))}</td>
              <td class="text-sm mono">{_html.escape(p.get("from_name",""))} &lt;{_html.escape(p.get("from_address","") or p.get("from_email",""))}&gt;</td>
              <td class="text-sm mono">{_html.escape(p.get("smtp_host",""))}:{p.get("smtp_port",587)} {tls_badge}{ssl_badge}{tor_badge}</td>
              <td>{auth_tag}</td>
              <td><div class="flex gap-2">
                <button onclick="editProfile('{pid_esc}')" class="btn btn-ghost btn-sm">✏️ Edit</button>
                <button onclick="testProfile('{pid_esc}')" class="btn btn-ghost btn-sm">🔌 Test</button>
                <button onclick="deleteProfile('{pid_esc}',this)" class="btn btn-danger btn-sm">🗑</button>
              </div></td>
            </tr>"""
        profiles_html += '</tbody></table>'
    else:
        profiles_html = '<div style="text-align:center;padding:20px;color:var(--muted);font-size:13px">No sending profiles yet. Create one below or use a preset.</div>'
    _prof_js_map_json = json.dumps(_prof_js_map).replace("</","<\\/").replace("<!--","<\\!--")

    msg_html = f'<div class="alert alert-success" style="margin-bottom:16px">{msg}</div>' if msg else ""
    var_help = """<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px 16px;font-size:12px;color:var(--text2)">
      <strong style="color:var(--text)">Available Variables:</strong>&nbsp;
      <code>{{.FirstName}}</code> <code>{{.LastName}}</code> <code>{{.Email}}</code>
      <code>{{.Company}}</code> <code>{{.Position}}</code>
      <code>{{.URL}}</code> – phishing link &nbsp;
      <code>{{.TrackingURL}}</code> – tracking pixel &nbsp;
      <code>{{.Date}}</code> <code>{{.CEO}}</code> <code>{{.TrackID}}</code> <code>{{.TicketID}}</code>
    </div>"""

    html = f"""
{msg_html}
<div style="max-width:1100px">

<!-- ── 1. Server Infrastructure ─────────────────────────────────────── -->
<form method="POST" style="margin-bottom:20px">
  <input type="hidden" name="action" value="save_infra">
  <div class="card">
    <div class="card-header">
      <span class="card-title">🌐 Server Configuration</span>
    </div>
    <div class="card-body">
      <div style="font-size:12px;color:var(--muted);margin-bottom:14px;padding:8px 12px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);border-radius:6px;line-height:1.6">
        <strong>Public Base URL</strong> - the URL embedded in phishing emails for tracking links.<br>
        Must be reachable by targets (use ngrok/Cloudflare tunnel/VPS - not localhost).
      </div>
      <div class="form-group" style="max-width:600px">
        <label>Public Base URL</label>
        <input type="url" name="phishing_public_url" value="{public_url}"
          placeholder="https://argus.yourdomain.com"
          style="font-family:monospace">
        <div class="text-sm text-muted mt-1">
          Auto-detected local URL: <code style="color:var(--primary)">{auto_url}</code>
          (used if Public URL is blank)
        </div>
      </div>

      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
        <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:10px">📡 Expose Your FEROXSEI Server</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">

          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px">
            <div style="font-weight:600;font-size:13px;margin-bottom:6px">🔮 Ngrok (Recommended for testing)</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Free HTTPS tunnel - targets get a *.ngrok-free.app URL.</div>
            <pre style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:8px;font-size:11px;color:#69f0ae;margin:0;overflow-x:auto">pip install ngrok
ngrok http 5000</pre>
            <div style="font-size:11px;color:var(--muted);margin-top:6px">Copy the https:// URL shown and paste it above.</div>
          </div>

          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px">
            <div style="font-weight:600;font-size:13px;margin-bottom:6px">⚡ Cloudflare Tunnel (Free, persistent)</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">No account needed for quick tunnels.</div>
            <pre style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:8px;font-size:11px;color:#69f0ae;margin:0;overflow-x:auto"># Install cloudflared
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64 && mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
# Run tunnel
cloudflared tunnel --url http://localhost:5000</pre>
          </div>

          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px">
            <div style="font-weight:600;font-size:13px;margin-bottom:6px">🖥️ VPS / Public IP</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Run FEROXSEI on a cloud VM with a public IP or domain.</div>
            <pre style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:8px;font-size:11px;color:#69f0ae;margin:0;overflow-x:auto"># On your VPS
python3 feroxsei_osint.py --host 0.0.0.0 --port 5000
# Then set URL above to:
# http://YOUR_VPS_IP:5000</pre>
          </div>

          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px">
            <div style="font-weight:600;font-size:13px;margin-bottom:6px">🧅 TOR Hidden Service</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Anonymous .onion address. Enable TOR in General Settings first.</div>
            <pre style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:8px;font-size:11px;color:#69f0ae;margin:0;overflow-x:auto"># /etc/tor/torrc - add:
HiddenServiceDir /var/lib/tor/argus/
HiddenServicePort 80 127.0.0.1:5000
# Restart TOR, then:
cat /var/lib/tor/argus/hostname</pre>
          </div>
        </div>
      </div>
      <button class="btn btn-primary" style="margin-top:14px">💾 Save Server Config</button>
    </div>
  </div>
</form>

<!-- ── 2. Sending Profiles ───────────────────────────────────────────── -->
<div class="card" style="margin-bottom:16px">
  <div class="card-header">
    <span class="card-title">📨 Sending Profiles (SMTP)</span>
    <button type="button" onclick="showProfileForm(true)" class="btn btn-sm" style="background:#ff6b35;border-color:#ff6b35;color:#fff">+ New Profile</button>
  </div>
  <div class="card-body">
    <!-- MailHog local testing info -->
    <div style="background:rgba(251,188,5,.06);border:1px solid rgba(251,188,5,.3);border-radius:7px;padding:12px 14px;margin-bottom:16px">
      <div style="font-size:12px;font-weight:700;color:#fbbc05;margin-bottom:6px">🐦 MailHog - Local Email Testing (No real emails sent)</div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Captures all sent emails locally. Perfect for testing campaigns before going live.</div>
      <pre style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:8px;font-size:11px;color:#69f0ae;margin:0 0 8px;overflow-x:auto"># Install MailHog (Go binary - runs anywhere)
wget -q https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64 -O /usr/local/bin/mailhog
chmod +x /usr/local/bin/mailhog
mailhog   # starts SMTP on :1025, Web UI on :8025</pre>
      <button type="button" onclick="prefillMailhog()"
        style="font-size:12px;padding:4px 12px;border-radius:5px;cursor:pointer;border:1px solid #fbbc05;background:rgba(251,188,5,.1);color:#fbbc05">
        ⚡ Quick-create MailHog Profile
      </button>
      <span style="font-size:11px;color:var(--muted);margin-left:10px">Then open <code>http://localhost:8025</code> to see captured emails</span>
    </div>

    <!-- Profile list -->
    <div id="profile-list">
      {profiles_html}
    </div>

    <!-- Create / Edit form (hidden by default) -->
    <div id="profile-form" style="display:none;margin-top:16px;padding:16px;background:var(--bg3);border:1px solid var(--border);border-radius:8px">
      <input type="hidden" id="pf-edit-id" value="">
      <div style="font-weight:600;font-size:14px;margin-bottom:4px;color:var(--text)" id="pf-form-title">New Sending Profile</div>
      <div style="margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap">
        <span style="color:var(--muted);font-size:12px;line-height:28px">Presets:</span>
        <button type="button" onclick="prefillMailhog()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #fbbc05;background:rgba(251,188,5,.08);color:#fbbc05">🐦 MailHog</button>
        <button type="button" onclick="prefillGmail()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #ea4335;background:rgba(234,67,53,.08);color:#ea4335">📧 Gmail (App Password)</button>
        <button type="button" onclick="prefillOutlookBasic()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #0078d4;background:rgba(0,120,212,.08);color:#0078d4">🪟 Outlook.com</button>
        <button type="button" onclick="prefillO365()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #0078d4;background:rgba(0,120,212,.06);color:#0078d4">🏢 Office 365</button>
        <button type="button" onclick="prefillOutlookOAuth()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #818cf8;background:rgba(129,140,248,.08);color:#818cf8">🔑 Outlook OAuth2</button>
        <button type="button" onclick="prefillSendGrid()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #1a82e2;background:rgba(26,130,226,.08);color:#1a82e2">✉ SendGrid</button>
        <button type="button" onclick="prefillBrevo()" style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;border:1px solid #0b996e;background:rgba(11,153,110,.08);color:#0b996e">📨 Brevo (free)</button>
      </div>
      <div class="grid2" style="gap:12px">
        <div class="form-group"><label>Profile Name *</label>
          <input type="text" id="pf-name" placeholder="Acme Corp SMTP"></div>
        <div class="form-group"><label>Auth Method</label>
          <select id="pf-auth-type" onchange="toggleAuthFields()" style="width:100%;background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:7px 10px;color:var(--text)">
            <option value="basic">Basic (Username + Password)</option>
            <option value="oauth2">OAuth2 / Modern Auth (Microsoft)</option>
            <option value="none">No Auth (open relay / MailHog)</option>
          </select></div>
        <div class="form-group"><label>From Name</label>
          <input type="text" id="pf-from-name" placeholder="IT Department"></div>
        <div class="form-group"><label>From Email *</label>
          <input type="email" id="pf-from-addr" placeholder="noreply@acme.com"></div>
        <div class="form-group"><label>Reply-To</label>
          <input type="email" id="pf-reply-to" placeholder="(optional)"></div>
        <div class="form-group"><label>Send Delay (seconds)</label>
          <input type="number" id="pf-delay" value="2" step="0.5" min="0"></div>
        <div class="form-group"><label>SMTP Host</label>
          <input type="text" id="pf-smtp-host" placeholder="localhost"></div>
        <div class="form-group"><label>SMTP Port</label>
          <input type="number" id="pf-smtp-port" value="587"></div>
      </div>
      <!-- Basic auth fields -->
      <div id="pf-basic-fields" class="grid2" style="gap:12px;margin-top:8px">
        <div class="form-group"><label>SMTP Username</label>
          <input type="text" id="pf-smtp-user" placeholder="(leave blank if not required)"></div>
        <div class="form-group"><label>SMTP Password</label>
          <input type="password" id="pf-smtp-pass" placeholder="(leave blank if not required)"></div>
      </div>
      <!-- OAuth2 fields -->
      <div id="pf-oauth2-fields" style="display:none;margin-top:8px;padding:12px;background:rgba(129,140,248,.06);border:1px solid rgba(129,140,248,.2);border-radius:7px">
        <div style="font-size:12px;color:#818cf8;font-weight:600;margin-bottom:10px">🔑 Microsoft OAuth2 / Modern Auth</div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:10px;line-height:1.6">
          Requires an Azure App Registration with <code>SMTP.Send</code> permission.
          Get your refresh_token once via the OAuth2 flow, then FEROXSEI renews it automatically.
          <a href="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app" target="_blank" style="color:#818cf8">Azure App Registration →</a>
        </div>
        <div class="grid2" style="gap:10px">
          <div class="form-group"><label>Email (SMTP User) *</label>
            <input type="text" id="pf-smtp-user-oauth" placeholder="you@outlook.com"></div>
          <div class="form-group"><label>Tenant ID</label>
            <input type="text" id="pf-oauth-tenant" placeholder="common (or your tenant UUID)"></div>
          <div class="form-group"><label>Client ID (App ID)</label>
            <input type="text" id="pf-oauth-client-id" placeholder="Azure Application (client) ID"></div>
          <div class="form-group"><label>Client Secret</label>
            <input type="password" id="pf-oauth-client-secret" placeholder="Azure Client Secret Value"></div>
        </div>
        <div class="form-group" style="margin-top:6px"><label>Refresh Token *</label>
          <input type="password" id="pf-oauth-refresh" placeholder="OAuth2 refresh_token - obtain once via interactive browser login">
          <div style="font-size:11px;color:var(--muted);margin-top:4px">
            To get a refresh token, run:
            <code style="background:var(--bg);padding:1px 6px;border-radius:3px;font-size:10px">python3 argus_get_token.py</code>
            (generated helper script) or use the Microsoft Graph Explorer.
          </div></div>
      </div>
      <div style="margin-top:12px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
          <input type="checkbox" id="pf-tls" checked> STARTTLS
        </label>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
          <input type="checkbox" id="pf-ssl"> SSL/TLS (port 465)
        </label>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
          <input type="checkbox" id="pf-tor"> Route via TOR
        </label>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px">
        <button type="button" onclick="saveProfile()" class="btn btn-primary" style="background:#ff6b35;border-color:#ff6b35">💾 Save Profile</button>
        <button type="button" onclick="hideProfileForm()" class="btn btn-ghost">Cancel</button>
      </div>
    </div>
  </div>
</div>

  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <span class="card-title" style="color:#ff6b35">🎣 Phishing Email Templates</span>
      <button onclick="showCreateForm()" class="btn btn-sm" style="background:#ff6b35;color:#fff">+ New Template</button>
    </div>
    <table>
      <thead><tr><th>Template Name</th><th>Category</th><th>Subject</th><th>Actions</th></tr></thead>
      <tbody id="tpl-tbody">{tpl_rows}</tbody>
    </table>
  </div>

  <!-- Create / Edit Form -->
  <div id="tpl-form-card" class="card" style="display:none;margin-top:16px">
    <div class="card-header">
      <span class="card-title" id="tpl-form-title">New Template</span>
      <button onclick="hideForm()" class="btn btn-ghost btn-sm">✕ Cancel</button>
    </div>
    <div class="card-body">
      {var_help}
      <form method="POST" id="tpl-form" style="margin-top:16px">
        <input type="hidden" name="action" id="form-action" value="create">
        <input type="hidden" name="tid" id="form-tid" value="">
        <div class="form-row">
          <div class="form-group"><label>Template Name *</label>
            <input type="text" name="name" id="form-name" required placeholder="IT Security Alert"></div>
          <div class="form-group"><label>Category</label>
            <select name="category" id="form-category">
              <option value="IT">IT</option><option value="HR">HR</option>
              <option value="Executive">Executive</option><option value="Cloud">Cloud</option>
              <option value="Delivery">Delivery</option><option value="Finance">Finance</option>
              <option value="general">General</option>
            </select>
          </div>
        </div>
        <div class="form-group"><label>Email Subject *</label>
          <input type="text" name="subject" id="form-subject" required placeholder="Action Required: Your password expires in 24 hours"></div>
        <div class="form-group">
          <div class="flex justify-between items-center mb-2">
            <label style="margin:0">HTML Body *</label>
            <div class="flex gap-2">
              <button type="button" onclick="togglePreviewPane()" class="btn btn-ghost btn-sm">👁 Live Preview</button>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px" id="editor-grid">
            <textarea name="html_body" id="form-html" rows="20" placeholder="&lt;!DOCTYPE html&gt;&lt;html&gt;..." oninput="updatePreview()" style="font-family:var(--mono);font-size:12px"></textarea>
            <div id="preview-pane" style="display:none;border:1px solid var(--border);border-radius:6px;overflow:hidden">
              <div style="background:var(--bg4);padding:6px 10px;font-size:11px;color:var(--muted)">Preview (sample data)</div>
              <iframe id="preview-iframe" style="width:100%;height:420px;border:none;background:#fff"></iframe>
            </div>
          </div>
        </div>
        <div class="flex gap-2">
          <button class="btn btn-primary" style="background:#ff6b35;border-color:#ff6b35">Save Template</button>
          <button type="button" onclick="hideForm()" class="btn btn-ghost">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Preview Modal -->
<div id="preview-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center">
  <div style="background:#fff;width:700px;max-height:90vh;border-radius:8px;overflow:hidden;display:flex;flex-direction:column">
    <div style="background:#1a1a2e;color:#00d4ff;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;font-family:monospace">
      <span id="modal-title" style="font-size:13px">Template Preview</span>
      <button onclick="closePreviewModal()" style="background:none;border:none;color:#fff;font-size:18px;cursor:pointer">✕</button>
    </div>
    <div style="flex:1;overflow:auto">
      <iframe id="preview-modal-iframe" style="width:100%;height:100%;min-height:500px;border:none"></iframe>
    </div>
  </div>
</div>

<script>
const TPL_DATA  = {tpl_js_map};
const PROF_DATA = {_prof_js_map_json};
const SAMPLE = {{FirstName:'John',LastName:'Doe',Email:'john.doe@acme.com',Company:'Acme Corp',Position:'Staff Engineer',URL:'https://acme-portal.example.com/login',TrackingURL:'https://t.example.com/px.gif',Date:'June 13 2026',CEO:'Jane Smith',TrackID:'TRACK-8472',TicketID:'INC-4521'}};

function fillSample(html) {{
  var keys = Object.keys(SAMPLE);
  for (var i=0; i<keys.length; i++) {{
    var k = keys[i];
    html = html.split('{{{{.' + k + '}}}}').join(SAMPLE[k]);
  }}
  return html;
}}
function updatePreview() {{
  var raw = document.getElementById('form-html').value;
  var pane = document.getElementById('preview-pane');
  if (pane.style.display !== 'none') {{
    var iframe = document.getElementById('preview-iframe');
    iframe.srcdoc = fillSample(raw);
  }}
}}
function togglePreviewPane() {{
  var pane = document.getElementById('preview-pane');
  var grid = document.getElementById('editor-grid');
  if (pane.style.display === 'none') {{
    pane.style.display = 'block';
    grid.style.gridTemplateColumns = '1fr 1fr';
    updatePreview();
  }} else {{
    pane.style.display = 'none';
    grid.style.gridTemplateColumns = '1fr';
  }}
}}
function previewTemplate(tid) {{
  var t = TPL_DATA[tid];
  if (!t) return;
  document.getElementById('modal-title').textContent = t.name + ' - ' + t.subject;
  document.getElementById('preview-modal-iframe').srcdoc = fillSample(t.html_body);
  var m = document.getElementById('preview-modal');
  m.style.display = 'flex';
}}
function closePreviewModal() {{ document.getElementById('preview-modal').style.display='none'; }}
function editTemplate(tid) {{
  var t = TPL_DATA[tid];
  if (!t) return;
  document.getElementById('tpl-form-title').textContent = 'Edit Template';
  document.getElementById('form-action').value = 'edit';
  document.getElementById('form-tid').value = tid;
  document.getElementById('form-name').value = t.name;
  document.getElementById('form-subject').value = t.subject;
  document.getElementById('form-html').value = t.html_body;
  document.getElementById('form-category').value = t.category || 'general';
  document.getElementById('tpl-form-card').style.display = '';
  document.getElementById('tpl-form-card').scrollIntoView({{behavior:'smooth'}});
}}
function showCreateForm() {{
  document.getElementById('tpl-form-title').textContent = 'New Template';
  document.getElementById('form-action').value = 'create';
  document.getElementById('form-tid').value = '';
  document.getElementById('form-name').value = '';
  document.getElementById('form-subject').value = '';
  document.getElementById('form-html').value = '';
  document.getElementById('tpl-form-card').style.display = '';
  document.getElementById('tpl-form-card').scrollIntoView({{behavior:'smooth'}});
}}
function hideForm() {{ document.getElementById('tpl-form-card').style.display='none'; }}
function deleteTemplate(tid) {{
  if (!confirm('Delete this template? This cannot be undone.')) return;
  var f = document.createElement('form');
  f.method = 'POST';
  f.innerHTML = '<input name="action" value="delete"><input name="tid" value="'+tid+'">';
  document.body.appendChild(f);
  f.submit();
}}
window.addEventListener('click', function(e) {{
  if (e.target === document.getElementById('preview-modal')) closePreviewModal();
}});

/* ── Sending profile management ─────────────────────────────────────── */
function showProfileForm(isNew) {{
  if (isNew) {{
    document.getElementById('pf-edit-id').value = '';
    document.getElementById('pf-form-title').textContent = 'New Sending Profile';
    document.getElementById('pf-name').value = '';
    document.getElementById('pf-from-name').value = '';
    document.getElementById('pf-from-addr').value = '';
    document.getElementById('pf-reply-to').value = '';
    document.getElementById('pf-smtp-host').value = '';
    document.getElementById('pf-smtp-port').value = '587';
    document.getElementById('pf-smtp-user').value = '';
    document.getElementById('pf-smtp-pass').value = '';
    document.getElementById('pf-delay').value = '2';
    document.getElementById('pf-tls').checked = true;
    document.getElementById('pf-ssl').checked = false;
    document.getElementById('pf-tor').checked = false;
    document.getElementById('pf-auth-type').value = 'basic';
    document.getElementById('pf-smtp-user-oauth').value = '';
    document.getElementById('pf-oauth-tenant').value = 'common';
    document.getElementById('pf-oauth-client-id').value = '';
    document.getElementById('pf-oauth-client-secret').value = '';
    document.getElementById('pf-oauth-refresh').value = '';
    toggleAuthFields();
  }}
  document.getElementById('profile-form').style.display = '';
  document.getElementById('profile-form').scrollIntoView({{behavior:'smooth'}});
}}
function hideProfileForm() {{ document.getElementById('profile-form').style.display='none'; }}

function toggleAuthFields() {{
  var at = document.getElementById('pf-auth-type').value;
  document.getElementById('pf-basic-fields').style.display  = (at === 'basic')  ? '' : 'none';
  document.getElementById('pf-oauth2-fields').style.display = (at === 'oauth2') ? '' : 'none';
}}

function editProfile(pid) {{
  var p = PROF_DATA[pid];
  if (!p) {{ alert('Profile data not found'); return; }}
  document.getElementById('pf-edit-id').value = pid;
  document.getElementById('pf-form-title').textContent = 'Edit Profile: ' + p.name;
  document.getElementById('pf-name').value      = p.name;
  document.getElementById('pf-from-name').value = p.from_name;
  document.getElementById('pf-from-addr').value = p.from_addr;
  document.getElementById('pf-reply-to').value  = p.reply_to;
  document.getElementById('pf-smtp-host').value = p.smtp_host;
  document.getElementById('pf-smtp-port').value = p.smtp_port;
  document.getElementById('pf-smtp-user').value = p.smtp_user;
  document.getElementById('pf-smtp-pass').value = '';
  document.getElementById('pf-delay').value     = p.send_delay;
  document.getElementById('pf-tls').checked     = p.use_tls;
  document.getElementById('pf-ssl').checked     = p.use_ssl;
  document.getElementById('pf-tor').checked     = p.use_tor;
  document.getElementById('pf-auth-type').value = p.auth_type || 'basic';
  document.getElementById('pf-smtp-user-oauth').value    = p.smtp_user;
  document.getElementById('pf-oauth-tenant').value       = p.oauth_tenant_id || 'common';
  document.getElementById('pf-oauth-client-id').value    = p.oauth_client_id;
  document.getElementById('pf-oauth-client-secret').value = '';
  document.getElementById('pf-oauth-refresh').value      = '';
  toggleAuthFields();
  document.getElementById('profile-form').style.display = '';
  document.getElementById('profile-form').scrollIntoView({{behavior:'smooth'}});
}}

function saveProfile() {{
  var pid  = document.getElementById('pf-edit-id').value;
  var at   = document.getElementById('pf-auth-type').value;
  var fd   = new FormData();
  fd.append('name',         document.getElementById('pf-name').value);
  fd.append('from_name',    document.getElementById('pf-from-name').value);
  fd.append('from_address', document.getElementById('pf-from-addr').value);
  fd.append('reply_to',     document.getElementById('pf-reply-to').value);
  fd.append('smtp_host',    document.getElementById('pf-smtp-host').value);
  fd.append('smtp_port',    document.getElementById('pf-smtp-port').value);
  fd.append('send_delay',   document.getElementById('pf-delay').value);
  fd.append('auth_type',    at);
  if (document.getElementById('pf-tls').checked) fd.append('use_tls','1');
  if (document.getElementById('pf-ssl').checked) fd.append('use_ssl','1');
  if (document.getElementById('pf-tor').checked) fd.append('use_tor','1');
  if (at === 'oauth2') {{
    fd.append('smtp_user',            document.getElementById('pf-smtp-user-oauth').value);
    fd.append('oauth_tenant_id',      document.getElementById('pf-oauth-tenant').value);
    fd.append('oauth_client_id',      document.getElementById('pf-oauth-client-id').value);
    var cs = document.getElementById('pf-oauth-client-secret').value;
    if (cs) fd.append('oauth_client_secret', cs);
    var rt = document.getElementById('pf-oauth-refresh').value;
    if (rt) fd.append('oauth_refresh_token', rt);
  }} else {{
    fd.append('smtp_user',     document.getElementById('pf-smtp-user').value);
    var pw = document.getElementById('pf-smtp-pass').value;
    if (pw) fd.append('smtp_password', pw);
  }}
  var url    = pid ? '/api/phishing/profiles/' + pid : '/api/phishing/profiles';
  var method = pid ? 'PUT' : 'POST';
  fetch(url, {{method: method, body: fd}})
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (d.ok) location.reload();
      else alert('Error: ' + (d.error || 'unknown'));
    }});
}}

function deleteProfile(pid, btn) {{
  if (!confirm('Delete this sending profile?')) return;
  fetch('/api/phishing/profiles/' + pid, {{method:'DELETE'}})
    .then(function(r) {{ return r.json(); }}).then(function(d) {{ if (d.ok) location.reload(); }});
}}

function testProfile(pid) {{
  var to = prompt('Send SMTP test email to:');
  if (!to || !to.trim()) return;
  var btn = event.target;
  btn.disabled = true; btn.textContent = 'Sending…';
  fetch('/api/phishing/profiles/' + pid + '/test', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{test_to: to.trim()}})
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    btn.disabled = false; btn.textContent = '🔌 Test';
    if (d.ok) alert('✅ ' + (d.message || 'Test email sent!'));
    else alert('❌ ' + (d.error || 'unknown error'));
  }}).catch(function() {{ btn.disabled = false; btn.textContent = '🔌 Test'; alert('Network error'); }});
}}

/* ── Preset fillers ─────────────────────────────────────────────────── */
function _fillProfile(name, fromN, fromA, host, port, user, tls, ssl, delay, authType) {{
  showProfileForm(true);
  document.getElementById('pf-name').value      = name;
  document.getElementById('pf-from-name').value = fromN;
  document.getElementById('pf-from-addr').value = fromA;
  document.getElementById('pf-smtp-host').value = host;
  document.getElementById('pf-smtp-port').value = port;
  document.getElementById('pf-smtp-user').value = user;
  document.getElementById('pf-tls').checked     = tls;
  document.getElementById('pf-ssl').checked     = ssl;
  document.getElementById('pf-delay').value     = delay || '2';
  if (authType) document.getElementById('pf-auth-type').value = authType;
  toggleAuthFields();
}}
function prefillMailhog()       {{ _fillProfile('MailHog (Local Testing) set host as localhost. for docker set host as mailhog','FEROXSEI Test','argus@localhost','mailhog',1025,'',false,false,'0','none'); }}
function prefillGmail()         {{ _fillProfile('Gmail','','your@gmail.com','smtp.gmail.com',587,'your@gmail.com',true,false,'2','basic'); alert('Gmail requires an App Password (not your account password).\\nEnable 2FA, then go to myaccount.google.com/apppasswords and create one.'); }}
function prefillOutlookBasic()  {{ _fillProfile('Outlook Personal','','you@outlook.com','smtp-mail.outlook.com',587,'you@outlook.com',true,false,'2','basic'); alert('Personal Outlook.com: go to Outlook Settings > Mail > Sync email > enable POP/SMTP first.\\nUse your account password or App Password if 2FA is on.'); }}
function prefillO365()          {{ _fillProfile('Office 365','','you@company.com','smtp.office365.com',587,'you@company.com',true,false,'2','basic'); }}
function prefillOutlookOAuth()  {{
  showProfileForm(true);
  document.getElementById('pf-name').value      = 'Outlook OAuth2';
  document.getElementById('pf-smtp-host').value = 'smtp.office365.com';
  document.getElementById('pf-smtp-port').value = '587';
  document.getElementById('pf-tls').checked     = true;
  document.getElementById('pf-auth-type').value = 'oauth2';
  document.getElementById('pf-oauth-tenant').value = 'common';
  toggleAuthFields();
  alert('OAuth2 for Microsoft:\\n1. Register an app at portal.azure.com\\n2. Add SMTP.Send permission + Grant admin consent\\n3. Get a refresh_token via browser OAuth2 flow\\n4. Fill in Client ID, Tenant ID, and the refresh_token below.');
}}
function prefillSendGrid()      {{ _fillProfile('SendGrid','','noreply@yourdomain.com','smtp.sendgrid.net',587,'apikey',true,false,'2','basic'); alert('SendGrid: username is literally "apikey". Set password to your SendGrid API key.'); }}
function prefillBrevo()         {{ _fillProfile('Brevo (Sendinblue)','','noreply@yourdomain.com','smtp-relay.brevo.com',587,'your@email.com',true,false,'2','basic'); alert('Brevo: free plan = 300 emails/day. Get SMTP key at app.brevo.com > SMTP & API > SMTP Key. Username = your login email, password = SMTP key.'); }}

toggleAuthFields();
</script>"""
    return _base("Settings - Phishing", html, "settings_phishing")


# ═════════════════════════════════════════════════════════════════════════════
# PHISHING CAMPAIGNS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/investigation/<inv_id>/campaign/new", methods=["GET","POST"])
@require_login
def new_phishing_campaign(inv_id):
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    if not inv or (not _is_admin() and inv["user_id"] != uid):
        return redirect("/investigations")
    if not _is_admin() and not _analyst_can("phishing"):
        return redirect("/investigations")

    if request.method == "POST":
        cid = str(uuid.uuid4())
        # Parse target CSV (email,first,last,position per line)
        targets = []
        raw_targets = request.form.get("targets_csv","").strip()
        for line in raw_targets.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if parts and "@" in parts[0]:
                targets.append({"email":parts[0],"first":parts[1] if len(parts)>1 else "","last":parts[2] if len(parts)>2 else "","position":parts[3] if len(parts)>3 else ""})

        # Create target group
        gid = ""
        if targets:
            gid = str(uuid.uuid4())
            db.exec("""INSERT INTO phishing_target_groups(id,user_id,investigation_id,name,targets,created_at)
                VALUES(?,?,?,?,?,?)""",
                (gid, uid, inv_id,
                 request.form.get("name","") + " - Targets",
                 json.dumps(targets), _now()))

        # Create campaign - resolve template name/subject for denormalised columns
        _new_tpl_name    = ""
        _new_tpl_subject = ""
        _new_tid = request.form.get("template_id","").strip()
        if _new_tid:
            _new_tpl = db.one("SELECT name,subject FROM phishing_templates WHERE id=?", (_new_tid,))
            if _new_tpl:
                _new_tpl_name    = _new_tpl["name"]
                _new_tpl_subject = _new_tpl["subject"]
        db.exec("""INSERT INTO phishing_campaigns(id,user_id,investigation_id,name,status,template_id,
            template_name,template_subject,
            target_group_id,sending_profile_id,phishing_url,landing_url,launch_date,scheduled_end,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cid, uid, inv_id,
             request.form.get("name","New Campaign"),
             "draft",
             _new_tid,
             _new_tpl_name, _new_tpl_subject,
             gid,
             request.form.get("sending_profile_id",""),
             request.form.get("phishing_url",""),
             request.form.get("landing_url",""),
             request.form.get("launch_date",""),
             request.form.get("scheduled_end",""),
             _now(), _now()))

        # Seed phishing_results for each target
        for t in targets:
            rid = str(uuid.uuid4())
            db.exec("""INSERT INTO phishing_results(id,campaign_id,target_email,target_first,target_last,target_position,status)
                VALUES(?,?,?,?,?,?,'pending')""",
                (rid, cid, t["email"], t.get("first",""), t.get("last",""), t.get("position","")))

        _audit("create_phishing_campaign","campaign",cid, request.form.get("name",""))
        return redirect(f"/investigation/{inv_id}/campaign/{cid}")

    # GET - show form
    tpls = db.rows("SELECT * FROM phishing_templates ORDER BY is_default DESC, category, name") if _is_admin() else \
           db.rows("SELECT * FROM phishing_templates WHERE is_default=1 OR user_id=? ORDER BY is_default DESC, category, name", (uid,))
    tpl_opts = "".join(
        f'<option value="{t["id"]}">[{t.get("category","")}] {_html.escape(t["name"])}</option>'
        for t in tpls)
    profiles = db.rows("SELECT * FROM phishing_sending_profiles ORDER BY name")
    profile_opts = '<option value="">- None (dry-run mode) -</option>' + "".join(
        f'<option value="{p["id"]}">{_html.escape(p["name"])} ({_html.escape(p.get("smtp_host",""))})</option>'
        for p in profiles)

    # Built-in landing page templates (web clone pages)
    from pathlib import Path as _PthN
    _tpl_dir_n = _PthN(__file__).parent / "investigations" / "phishing" / "templates"
    _avail_landings = sorted([f.stem for f in _tpl_dir_n.glob("*.html")]) if _tpl_dir_n.exists() else []
    _base_url_n = (_get_setting("phishing_public_url","") or request.host_url).rstrip("/")
    # Pre-compute dropdown options for landing page presets
    _landing_preset_opts_n = "".join(
        f'<option value="{_base_url_n}/phish/landing/{n}">{n.replace("_"," ").title()}</option>'
        for n in _avail_landings
    )
    _tor_checked = 'checked' if _get_setting('tor_enabled','0') == '1' else ''

    html = f"""
<div style="max-width:820px;margin:0 auto">
<div class="card">
  <div class="card-header">
    <span class="card-title" style="color:#ff6b35">🎣 New Phishing Campaign</span>
    <a href="/investigation/{inv_id}" class="btn btn-ghost btn-sm">← Back</a>
  </div>
  <div class="card-body">
  <form method="POST">

    <div class="form-group"><label>Campaign Name *</label>
      <input type="text" name="name" placeholder="Acme Corp Q2 2025 Phishing Assessment" required></div>

    <!-- ── 1. Email Template ─────────────────────────────────────── -->
    <div style="margin:20px 0 8px;padding:10px 14px;background:rgba(0,212,255,.05);
                border-left:3px solid var(--primary);border-radius:0 6px 6px 0">
      <div style="font-size:12px;font-weight:700;color:var(--primary);text-transform:uppercase;
                  letter-spacing:.06em;margin-bottom:2px">📧 Email Template</div>
      <div style="font-size:11px;color:var(--muted)">The HTML email body delivered to each target's inbox.</div>
    </div>

    <div class="form-group">
      <label>Email Template *
        <a href="/settings/phishing" target="_blank"
           style="font-size:11px;font-weight:400;color:var(--primary);text-decoration:none;margin-left:8px">
          + Manage templates</a>
      </label>
      <select name="template_id" required>
        <option value="">- Select email template -</option>
        {tpl_opts}
      </select>
      <div class="text-sm text-muted mt-1">
        Use <code>{{{{.FirstName}}}}</code> <code>{{{{.Email}}}}</code> <code>{{{{.URL}}}}</code>
        (auto-becomes the click-tracking link) in your template body.
      </div>
    </div>

    <div class="form-group">
      <label>Sending Profile (SMTP)
        <a href="/settings/phishing" target="_blank"
           style="font-size:11px;font-weight:400;color:var(--primary);text-decoration:none;margin-left:8px">
          + Manage profiles</a>
      </label>
      <select name="sending_profile_id">
        {profile_opts}
      </select>
      <div class="text-sm text-muted mt-1">No profile = dry-run (records results, sends no real emails).</div>
    </div>

    <!-- ── 2. Landing Page (Web Clone) ──────────────────────────── -->
    <div style="margin:20px 0 8px;padding:10px 14px;background:rgba(255,107,53,.05);
                border-left:3px solid #ff6b35;border-radius:0 6px 6px 0">
      <div style="font-size:12px;font-weight:700;color:#ff6b35;text-transform:uppercase;
                  letter-spacing:.06em;margin-bottom:2px">🌐 Landing Page (Fake Login)</div>
      <div style="font-size:11px;color:var(--muted)">
        The web page targets see <em>after</em> clicking the link in the email.
        Choose a built-in clone or enter your own URL.
      </div>
    </div>

    <div class="form-group">
      <label>Landing Page (Fake Login Web Page)</label>
      <select id="new-landing-select" onchange="newLandingSelectChange(this)"
              style="margin-bottom:6px">
        <option value="">- None (targets get awareness page only) -</option>
        {_landing_preset_opts_n}
        <option value="__custom__">🔗 Custom URL…</option>
      </select>
      <input type="hidden" name="landing_url" id="new-landing-url-hidden">
      <div id="new-landing-custom-div" style="display:none;margin-top:6px">
        <input type="text" id="new-landing-custom-input"
               placeholder="https://your-clone.example.com/login"
               oninput="document.getElementById('new-landing-url-hidden').value=this.value">
      </div>
      <div id="new-landing-preview-bar" style="margin-top:6px;display:none">
        <a id="new-landing-preview" href="#" target="_blank"
           style="font-size:11px;padding:3px 10px;border:1px solid #4ade80;border-radius:4px;
                  color:#4ade80;text-decoration:none">👁 Preview Page</a>
      </div>
      <div class="text-sm text-muted mt-1">
        The web page targets land on after clicking the email link.
        Credentials are <strong>not stored</strong> - only the click event is logged.
      </div>
    </div>

    <!-- ── 3. Targets ───────────────────────────────────────────── -->
    <div style="margin:20px 0 8px;padding:10px 14px;background:rgba(74,222,128,.05);
                border-left:3px solid #4ade80;border-radius:0 6px 6px 0">
      <div style="font-size:12px;font-weight:700;color:#4ade80;text-transform:uppercase;
                  letter-spacing:.06em;margin-bottom:2px">👥 Target List</div>
      <div style="font-size:11px;color:var(--muted)">CSV of targets who will receive the email.</div>
    </div>

    <div class="form-group">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
        <label style="margin:0">Targets (CSV) *</label>
        <a href="/api/download-template?type=phishing" download="phishing_targets_template.csv"
          style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);text-decoration:none">⬇ Template</a>
        <label style="font-size:11px;padding:3px 10px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text2);cursor:pointer">
          ⬆ Import CSV
          <input type="file" accept=".csv" style="display:none" id="phish-csv-import" onchange="importPhishCsv(this)">
        </label>
      </div>
      <textarea name="targets_csv" id="phish-targets-csv" rows="7"
        placeholder="email,first,last,position&#10;john.doe@acme.com,John,Doe,Engineer&#10;jane.smith@acme.com,Jane,Smith,Manager"
        required></textarea>
      <div class="text-sm text-muted mt-1">Columns: <code>email, first, last, position</code> - first/last/position optional.</div>
    </div>

    <!-- ── 4. Options ───────────────────────────────────────────── -->
    <div class="form-group">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div><label>Launch Date <span style="color:var(--muted);font-weight:400">(optional)</span></label>
          <input type="datetime-local" name="launch_date"></div>
        <div><label>End Date / Auto-Stop <span style="color:var(--muted);font-weight:400">(optional)</span></label>
          <input type="datetime-local" name="scheduled_end">
          <div style="font-size:11px;color:var(--muted);margin-top:3px">Campaign stops automatically at this time.</div>
        </div>
      </div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 14px">
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2);cursor:pointer">
          <input type="checkbox" name="use_tor" {_tor_checked}>
          Route delivery through TOR (changes circuit per target)
        </label>
      </div>
    </div>

    <div class="flex gap-2 mt-3">
      <button class="btn btn-primary" style="background:#ff6b35;border-color:#ff6b35">Create Campaign →</button>
      <a href="/investigation/{inv_id}" class="btn btn-ghost">Cancel</a>
    </div>
  </form>
  </div>
</div>
</div>
<script>
function importPhishCsv(input) {{
  var file = input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {{
    var lines = e.target.result.split('\\n');
    var out = [];
    lines.forEach(function(line, i) {{
      line = line.trim();
      if (!line) return;
      if (i===0 && line.toLowerCase().startsWith('email')) return;
      out.push(line);
    }});
    document.getElementById('phish-targets-csv').value = out.join('\\n');
    input.value='';
  }};
  reader.readAsText(file);
}}
function newLandingSelectChange(sel) {{
  var val = sel.value;
  var hidden = document.getElementById('new-landing-url-hidden');
  var customDiv = document.getElementById('new-landing-custom-div');
  var prevBar = document.getElementById('new-landing-preview-bar');
  var prev = document.getElementById('new-landing-preview');
  if (val === '__custom__') {{
    customDiv.style.display = '';
    var customInp = document.getElementById('new-landing-custom-input');
    hidden.value = customInp ? customInp.value : '';
    prevBar.style.display = hidden.value ? '' : 'none';
    if (prev && hidden.value) prev.href = hidden.value;
  }} else {{
    customDiv.style.display = 'none';
    hidden.value = val;
    if (val) {{
      prevBar.style.display = '';
      if (prev) prev.href = val;
    }} else {{
      prevBar.style.display = 'none';
    }}
  }}
}}
</script>"""
    return _base("New Phishing Campaign", html, "investigations")


@app.route("/investigation/<inv_id>/campaign/<campaign_id>")
@require_login
def view_phishing_campaign(inv_id, campaign_id):
    uid = flask_session["uid"]
    inv = db.one("SELECT * FROM investigations WHERE id=?", (inv_id,))
    if not inv or (not _is_admin() and inv["user_id"] != uid):
        return redirect("/investigations")
    camp = db.one("SELECT c.*,COALESCE(t.name, c.template_name) as template_name,COALESCE(t.subject, c.template_subject) as template_subject FROM phishing_campaigns c LEFT JOIN phishing_templates t ON c.template_id=t.id AND c.template_id!='' WHERE c.id=?", (campaign_id,))
    if not camp:
        return redirect(f"/investigation/{inv_id}")
    results = db.rows("SELECT * FROM phishing_results WHERE campaign_id=? ORDER BY target_email", (campaign_id,))

    # Stats
    total   = len(results)
    sent    = sum(1 for r in results if r.get("sent_at"))
    opened  = sum(1 for r in results if r.get("opened_at"))
    clicked = sum(1 for r in results if r.get("clicked_at"))
    submitted = sum(1 for r in results if r.get("submitted_at"))

    def pct(n): return f"{round(n/total*100)}%" if total else "0%"

    result_rows = ""
    for r in results:
        _rstatus = r.get("status","pending")
        status_icon = {"pending":"⏳","sent":"📧","opened":"👁","clicked":"🖱️","submitted":"🎯","failed":"❌"}.get(_rstatus,"⏳")
        _err = _html.escape(r.get("last_error","") or "")
        if _rstatus == "failed":
            _badge_cls = "badge-high"
            _badge_title = f' title="{_err}"' if _err else ' title="Send failed"'
            _err_cell = f'<td class="text-sm" style="color:var(--danger);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{_err}">{_err[:80] if _err else "Send failed"}</td>'
        else:
            _badge_cls = "info" if r.get("sent_at") else "blue"
            _badge_title = ""
            _err_cell = '<td class="text-sm text-muted">-</td>'
        result_rows += f"""<tr>
          <td class="mono text-sm">{_html.escape(r.get('target_email',''))}</td>
          <td class="text-sm">{_html.escape(r.get('target_first',''))} {_html.escape(r.get('target_last',''))}</td>
          <td class="text-sm text-muted">{_html.escape(r.get('target_position',''))}</td>
          <td><span class="badge badge-{_badge_cls}"{_badge_title}>{status_icon} {_rstatus.upper()}</span></td>
          <td class="text-sm text-muted">{str(r.get('sent_at',''))[:16] or '-'}</td>
          <td class="text-sm text-muted">{str(r.get('opened_at',''))[:16] or '-'}</td>
          <td class="text-sm text-muted">{str(r.get('clicked_at',''))[:16] or '-'}</td>
          <td class="text-sm {'badge-high' if r.get('submitted_at') else ''}">{'⚠ '+str(r.get('submitted_at',''))[:16] if r.get('submitted_at') else '-'}</td>
          {_err_cell}
        </tr>"""
    if not result_rows:
        result_rows = '<tr><td colspan=8 style="text-align:center;padding:20px;color:var(--muted)">No targets in this campaign</td></tr>'

    status_badge_map = {"draft":"badge-blue","approved":"badge-info","sending":"badge-info","active":"badge-info","completed":"badge-low","paused":"badge-medium","suspended":"badge-high","pending_approval":"badge-medium","error":"badge-high"}
    sb = status_badge_map.get(camp.get("status","draft"),"badge-blue")

    # Build active URL info
    base_url = (_get_setting("phishing_public_url","") or request.host_url).rstrip("/")
    tracking_pixel_example = f"{base_url}/phish/track/open/{campaign_id}/[rid].png"
    click_track_example    = f"{base_url}/phish/track/click/{campaign_id}/[rid]"
    awareness_example      = f"{base_url}/phish/awareness/{campaign_id}/[rid]"
    # Email link - what {{.URL}} in templates resolves to (per recipient)
    email_link_example = base_url + "/phish/track/click/" + campaign_id + "/[rid]"

    # Landing page - scan templates dir, default if campaign has none set
    from pathlib import Path as _PthC
    _tpl_dir = _PthC(__file__).parent / "investigations" / "phishing" / "templates"
    available_landings = sorted([f.stem for f in _tpl_dir.glob("*.html")]) if _tpl_dir.exists() else []
    landing_url = (camp.get("landing_url","") or camp.get("phishing_url","")).strip()
    landing_url_esc = _html.escape(landing_url)

    # Edit form data
    edit_templates = db.rows("SELECT id,name FROM phishing_templates ORDER BY name")
    edit_profiles  = db.rows("SELECT id,name FROM phishing_sending_profiles ORDER BY name")
    camp_name_esc  = _html.escape(camp.get("name",""))

    approved_by_esc = _html.escape(camp.get("approved_by","") or "")
    is_approved = bool(camp.get("approved_by"))
    camp_status = camp.get("status","draft")
    can_edit = camp_status not in ("sending","completed")

    admin_controls = ""
    if _is_admin():
        if camp_status not in ("sending","completed","suspended"):
            admin_controls = (
                f'<button onclick="testSendCampaign()" class="btn btn-sm" '
                f'style="border:1px solid #60a5fa;color:#60a5fa;background:rgba(96,165,250,.08)">'
                f'📧 Test Send</button> '
                f'<button onclick="launchCampaign()" class="btn btn-sm" '
                f'style="background:#16a34a;color:#fff;border-color:#16a34a">🚀 Launch Campaign</button>'
            )
        elif camp_status == "sending":
            admin_controls = f'<button onclick="suspendCampaign()" class="btn btn-sm btn-danger">🛑 Suspend</button>'
    if can_edit:
        admin_controls += f' <button onclick="toggleEdit()" class="btn btn-ghost btn-sm">✏️ Edit</button>'

    # Pre-compute strings that cannot use backslash inside f-string expressions
    _em_not_set = '<em style="font-family:var(--sans);color:var(--muted)">Not set - click Edit to configure</em>'
    _landing_color = '#4ade80' if landing_url else 'var(--muted)'
    _preview_btn = (
        f'<a href="{landing_url_esc}" target="_blank" style="font-size:10px;padding:2px 8px;'
        f'border:1px solid var(--border);background:var(--bg4);border-radius:4px;'
        f'cursor:pointer;color:var(--muted);text-decoration:none">Preview</a>'
        if landing_url else ''
    )
    # Pre-compute template/profile option lists for edit panel (avoids backslash-in-fstring)
    _tpl_opts = "".join(
        f'<option value="{t["id"]}" {"selected" if t["id"] == camp.get("template_id","") else ""}>'
        f'{_html.escape(t["name"])}</option>'
        for t in edit_templates
    )
    _prof_opts = "".join(
        f'<option value="{p["id"]}" {"selected" if p["id"] == camp.get("sending_profile_id","") else ""}>'
        f'{_html.escape(p["name"])}</option>'
        for p in edit_profiles
    )
    # Detect if current landing_url matches a built-in preset
    import re as _re_lnd
    _lnd_stem_match = _re_lnd.search(r'/phish/landing/([a-zA-Z0-9_-]+)$', landing_url) if landing_url else None
    _lnd_current_stem = _lnd_stem_match.group(1) if _lnd_stem_match else ""
    _lnd_is_custom = bool(landing_url and not _lnd_current_stem)

    _edit_landing_opts = '<option value="">- None (awareness page only) -</option>'
    for n in available_landings:
        _sel_attr = 'selected' if n == _lnd_current_stem else ''
        _edit_landing_opts += (
            f'<option value="{base_url}/phish/landing/{n}" {_sel_attr}>'
            f'{n.replace("_"," ").title()}</option>'
        )
    _custom_sel_attr = 'selected' if _lnd_is_custom else ''
    _edit_landing_opts += f'<option value="__custom__" {_custom_sel_attr}>🔗 Custom URL…</option>'
    _edit_custom_disp = '' if _lnd_is_custom else 'none'
    _edit_custom_val = _html.escape(landing_url) if _lnd_is_custom else ''
    _edit_prev_disp = '' if landing_url else 'none'
    _edit_panel = (
        f'<div id="edit-panel" style="display:none;margin-bottom:16px">'
        f'<div class="card" style="border-color:#ff6b35"><div class="card-header" style="background:rgba(255,107,53,.06)">'
        f'<span class="card-title" style="color:#ff6b35">✏️ Edit Campaign</span>'
        f'<button onclick="toggleEdit()" class="btn btn-ghost btn-sm">✕ Cancel</button>'
        f'</div><div class="card-body">'
        f'<form method="POST" action="/investigation/{inv_id}/campaign/{campaign_id}/edit">'

        # Campaign name
        f'<div class="form-group" style="margin-bottom:16px">'
        f'<label style="font-weight:600">Campaign Name</label>'
        f'<input type="text" name="name" value="{camp_name_esc}" required></div>'

        # ── Email section header
        f'<div style="margin:16px 0 10px;padding:8px 12px;background:rgba(0,212,255,.05);'
        f'border-left:3px solid var(--primary);border-radius:0 5px 5px 0">'
        f'<div style="font-size:11px;font-weight:700;color:var(--primary);text-transform:uppercase;'
        f'letter-spacing:.06em">📧 Email Template</div></div>'
        f'<div class="grid2" style="gap:12px;margin-bottom:4px">'
        f'<div class="form-group"><label>Email Template</label>'
        f'<select name="template_id"><option value="">- none -</option>{_tpl_opts}</select>'
        f'<div style="font-size:11px;color:var(--muted);margin-top:4px">'
        f'HTML email body sent to each target. <a href="/settings/phishing" target="_blank" '
        f'style="color:var(--primary)">Manage →</a></div></div>'
        f'<div class="form-group"><label>Sending Profile (SMTP)</label>'
        f'<select name="sending_profile_id"><option value="">- none (dry-run) -</option>{_prof_opts}</select>'
        f'<div style="font-size:11px;color:var(--muted);margin-top:4px">'
        f'No profile = records results only, no real emails sent.</div></div>'
        f'</div>'

        # ── Landing page section header
        f'<div style="margin:16px 0 10px;padding:8px 12px;background:rgba(255,107,53,.05);'
        f'border-left:3px solid #ff6b35;border-radius:0 5px 5px 0">'
        f'<div style="font-size:11px;font-weight:700;color:#ff6b35;text-transform:uppercase;'
        f'letter-spacing:.06em">🌐 Landing Page (Fake Login Web Page)</div></div>'
        f'<div class="form-group">'
        f'<label>Landing Page</label>'
        f'<select id="edit-landing-select" onchange="editLandingSelectChange(this)" style="margin-bottom:6px">'
        f'{_edit_landing_opts}'
        f'</select>'
        f'<input type="hidden" name="landing_url" id="edit-landing" value="{landing_url_esc}">'
        f'<div id="edit-landing-custom-div" style="display:{_edit_custom_disp};margin-top:6px">'
        f'<input type="text" id="edit-landing-custom-input" value="{_edit_custom_val}" '
        f'placeholder="https://your-clone.example.com/login" '
        f'oninput="document.getElementById(\'edit-landing\').value=this.value">'
        f'</div>'
        f'<div id="edit-preview-bar" style="margin-top:6px;display:{_edit_prev_disp}">'
        f'<a id="preview-landing-btn" href="{landing_url_esc}" target="_blank" '
        f'style="font-size:11px;padding:2px 8px;border:1px solid #4ade80;border-radius:4px;'
        f'color:#4ade80;text-decoration:none">👁 Preview Page</a>'
        f'</div>'
        f'<div style="font-size:11px;color:var(--muted);margin-top:4px">'
        f'The web page targets arrive at after clicking the email link.</div>'
        f'</div>'

        # Buttons
        f'<div class="flex gap-2" style="margin-top:16px">'
        f'<button type="submit" class="btn btn-primary" style="background:#ff6b35;border-color:#ff6b35">'
        f'💾 Save Changes</button>'
        f'<button type="button" onclick="toggleEdit()" class="btn btn-ghost">Cancel</button>'
        f'</div></form></div></div></div>'
    ) if can_edit else ''

    _sched_end_val = camp.get("scheduled_end","") or ""
    _sched_end_html = (
        f' · <span style="color:#f59e0b">⏱ Auto-stops: {_html.escape(_sched_end_val.replace("T"," "))}</span>'
        if _sched_end_val else ""
    )

    html = f"""
<div class="flex justify-between items-center mb-3">
  <div>
    <div style="display:flex;align-items:center;gap:10px">
      <h2 style="font-size:18px;font-weight:700;color:var(--text)">{_html.escape(camp.get('name',''))}</h2>
      <span class="badge {sb}">{camp_status.upper().replace('_',' ')}</span>
      {'<span style="font-size:11px;color:#4ade80">✅ Approved by '+approved_by_esc+'</span>' if approved_by_esc else ('<span style="font-size:11px;color:#4ade80">✅ Admin - auto-approved on launch</span>' if _is_admin() else '<span style="font-size:11px;color:#f59e0b">⚠ Awaiting admin approval</span>')}
    </div>
    <div class="text-sm text-muted">Template: {_html.escape(camp.get('template_name',''))} · Subject: {_html.escape(camp.get('template_subject',''))}{_sched_end_html}</div>
  </div>
  <div class="flex gap-2">
    {admin_controls}
    <a href="/investigation/{inv_id}" class="btn btn-ghost btn-sm">← Back</a>
  </div>
</div>

<!-- Active URL Info Card -->
<div class="card" style="margin-bottom:16px;border-color:{'#ff6b35' if camp_status=='sending' else 'var(--border)'}">
  <div class="card-header" style="background:{'rgba(255,107,53,0.08)' if camp_status=='sending' else 'var(--bg2)'}">
    <span class="card-title">🌐 Campaign URLs</span>
    {'<span class="badge badge-info" style="animation:pulse 2s infinite">● LIVE</span>' if camp_status=='sending' else ''}
  </div>
  <div class="card-body" style="font-family:var(--mono);font-size:12px;display:grid;gap:8px">

    <div style="background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.2);border-radius:6px;padding:10px 12px;font-family:var(--sans);font-size:12px;color:var(--text2);line-height:1.6">
      <strong style="color:var(--primary)">How it works:</strong>
      Put <code style="background:var(--bg3);padding:1px 5px;border-radius:3px">{{{{.URL}}}}</code> in your email template - it auto-becomes the click-tracking link per recipient.
      Targets are redirected to the <strong>Landing Page</strong> below after click tracking is recorded.
    </div>

    <div style="display:grid;grid-template-columns:150px 1fr auto;align-items:center;gap:8px;padding:8px;background:var(--bg3);border-radius:5px">
      <span style="color:var(--muted);font-family:var(--sans);font-size:11px;font-weight:600;text-transform:uppercase">📧 Email Link</span>
      <span style="color:var(--primary)">{email_link_example}</span>
      <button onclick="copyToClip('{email_link_example}')" style="font-size:10px;padding:2px 8px;border:1px solid var(--border);background:var(--bg4);border-radius:4px;cursor:pointer;color:var(--muted)">Copy</button>
    </div>

    <div style="display:grid;grid-template-columns:150px 1fr auto;align-items:center;gap:8px;padding:8px;background:var(--bg3);border-radius:5px">
      <span style="color:var(--muted);font-family:var(--sans);font-size:11px;font-weight:600;text-transform:uppercase">🖥 Landing Page</span>
      <span style="color:{_landing_color}">{landing_url_esc or _em_not_set}</span>
      {_preview_btn}
    </div>

    <div style="display:grid;grid-template-columns:150px 1fr;align-items:center;gap:8px;padding:8px;background:var(--bg3);border-radius:5px">
      <span style="color:var(--muted);font-family:var(--sans);font-size:11px;font-weight:600;text-transform:uppercase">📷 Open Pixel</span>
      <span style="color:var(--text2)">{tracking_pixel_example}</span>
    </div>
    <div style="display:grid;grid-template-columns:150px 1fr;align-items:center;gap:8px;padding:8px;background:var(--bg3);border-radius:5px">
      <span style="color:var(--muted);font-family:var(--sans);font-size:11px;font-weight:600;text-transform:uppercase">📚 Awareness Page</span>
      <span style="color:var(--text2)">{awareness_example}</span>
    </div>
  </div>
</div>

<!-- Edit Campaign Panel -->
{_edit_panel}

<div class="grid3" style="margin-bottom:20px;gap:12px">
  <div class="stat-card"><div class="stat-icon">📧</div><div class="stat-value">{total}</div><div class="stat-label">Total Targets</div></div>
  <div class="stat-card"><div class="stat-icon">👁</div><div class="stat-value">{opened} <small style="font-size:14px;color:var(--muted)">({pct(opened)})</small></div><div class="stat-label">Opened</div></div>
  <div class="stat-card"><div class="stat-icon">🖱️</div><div class="stat-value">{clicked} <small style="font-size:14px;color:var(--muted)">({pct(clicked)})</small></div><div class="stat-label">Clicked</div></div>
  <div class="stat-card"><div class="stat-icon">⚠️</div><div class="stat-value" style="color:var(--danger)">{submitted} <small style="font-size:14px;color:var(--muted)">({pct(submitted)})</small></div><div class="stat-label">Credentials Submitted</div></div>
  <div class="stat-card"><div class="stat-icon">📤</div><div class="stat-value">{sent}</div><div class="stat-label">Sent</div></div>
  <div class="stat-card"><div class="stat-icon">🎣</div><div class="stat-value" style="color:#ff6b35">{pct(clicked)}</div><div class="stat-label">Click Rate</div></div>
</div>

<div class="card">
  <div class="card-header">
    <span class="card-title">📋 Target Results</span>
    <span class="text-sm text-muted">{total} targets</span>
  </div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Email</th><th>Name</th><th>Position</th><th>Status</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Error</th></tr></thead>
    <tbody>{result_rows}</tbody>
  </table>
  </div>
</div>

<!-- ── Captured Mail / MailHog inbox ──────────────────────────── -->
<div class="card" style="margin-top:16px">
  <div class="card-header">
    <span class="card-title">📥 Captured Mail
      <span style="font-size:11px;color:var(--muted);font-weight:400">&nbsp;via MailHog</span>
    </span>
    <button onclick="loadMhInbox()" class="btn btn-ghost btn-sm">🔄 Refresh</button>
  </div>
  <div id="mh-list" style="max-height:300px;overflow-y:auto">
    <div style="color:var(--muted);padding:20px;text-align:center;font-size:13px">Loading…</div>
  </div>
  <div id="mh-preview" style="display:none;border-top:1px solid var(--border)">
    <div style="display:flex;justify-content:space-between;align-items:center;
                padding:8px 14px;background:var(--bg2)">
      <span id="mh-preview-subj"
            style="font-size:13px;font-weight:600;color:var(--text);max-width:80%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>
      <button onclick="closeMhPreview()" class="btn btn-ghost btn-sm">✕ Close</button>
    </div>
    <iframe id="mh-preview-frame" src=""
            style="width:100%;height:500px;border:none;background:#fff"></iframe>
  </div>
</div>

<script>
function approveCampaign() {{
  if (!confirm('Approve this campaign for delivery? Ensure you have documented authorisation.')) return;
  fetch('/api/phishing/campaign/{campaign_id}/approve', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{ if(d.ok) location.reload(); else alert(d.error||'Error'); }});
}}
function launchCampaign() {{
  if (!confirm('Launch campaign and begin sending emails to all targets?')) return;
  fetch('/api/phishing/campaign/{campaign_id}/launch', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{ if(d.ok) {{ alert('Campaign launched!'); location.reload(); }} else alert(d.error||'Error'); }});
}}
function suspendCampaign() {{
  if (!confirm('EMERGENCY STOP: Immediately suspend this campaign?')) return;
  fetch('/api/phishing/campaign/{campaign_id}/suspend', {{method:'POST'}})
    .then(r=>r.json()).then(d=>{{ if(d.ok) location.reload(); else alert(d.error||'Error'); }});
}}
function toggleEdit() {{
  var p = document.getElementById('edit-panel');
  if (p) p.style.display = (p.style.display === 'none' || p.style.display === '') ? 'block' : 'none';
}}
function copyToClip(txt) {{
  var btn = event && event.target ? event.target : null;
  navigator.clipboard.writeText(txt).then(function() {{
    if (btn) {{ var old = btn.textContent; btn.textContent = '✓ Copied'; setTimeout(function(){{ btn.textContent = old; }}, 1500); }}
  }}).catch(function() {{ prompt('Copy this URL:', txt); }});
}}
function editLandingSelectChange(sel) {{
  var val = sel.value;
  var hidden = document.getElementById('edit-landing');
  var customDiv = document.getElementById('edit-landing-custom-div');
  var prevBar = document.getElementById('edit-preview-bar');
  var prev = document.getElementById('preview-landing-btn');
  if (val === '__custom__') {{
    customDiv.style.display = '';
    var ci = document.getElementById('edit-landing-custom-input');
    hidden.value = ci ? ci.value : '';
    if (prev && hidden.value) {{ prev.href = hidden.value; prevBar.style.display = ''; }}
    else {{ prevBar.style.display = 'none'; }}
  }} else {{
    customDiv.style.display = 'none';
    hidden.value = val;
    if (val) {{ prevBar.style.display = ''; if (prev) prev.href = val; }}
    else {{ prevBar.style.display = 'none'; }}
  }}
}}
function testSendCampaign() {{
  var to = prompt('Send test phishing email to (your email):');
  if (!to) return;
  var btn = event && event.target ? event.target : null;
  if (btn) btn.disabled = true;
  fetch('/api/phishing/campaign/{campaign_id}/test', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{to_email: to}})
  }}).then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (btn) btn.disabled = false;
      if (d.ok) alert('Test email sent to ' + to + '!\\n\\n' + (d.note || ''));
      else alert('Test send failed: ' + (d.error || 'Unknown error'));
    }}).catch(function(e) {{
      if (btn) btn.disabled = false;
      alert('Error: ' + e);
    }});
}}

/* ── MailHog inbox ─────────────────────────────────────────────── */
var _MH_MSGS = [];
function _mhEsc(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}
function loadMhInbox() {{
  var box = document.getElementById('mh-list');
  if (!box) return;
  box.innerHTML = '<div style="color:var(--muted);padding:16px;text-align:center;font-size:13px">Loading…</div>';
  fetch('/api/phishing/mailhog/messages')
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (!d.ok) {{
        box.innerHTML = '<div style="color:var(--danger);padding:14px;font-size:13px">' +
          _mhEsc(d.error || 'MailHog not reachable') + '</div>';
        return;
      }}
      _MH_MSGS = d.messages || [];
      if (!_MH_MSGS.length) {{
        box.innerHTML = '<div style="color:var(--muted);padding:20px;text-align:center;font-size:13px">' +
          'No messages captured yet - send a test email to populate the inbox.</div>';
        return;
      }}
      var rows = _MH_MSGS.map(function(m, i) {{
        return '<tr style="cursor:pointer" onclick="showMhPreview(' + i + ')">' +
          '<td class="text-sm">' + _mhEsc(m.from) + '</td>' +
          '<td class="text-sm">' + _mhEsc((m.to || []).join(', ')) + '</td>' +
          '<td class="text-sm">' + _mhEsc(m.subject || '(no subject)') + '</td>' +
          '<td class="text-sm text-muted" style="white-space:nowrap">' + _mhEsc(m.date) + '</td>' +
          '<td><button class="btn btn-ghost btn-sm" style="font-size:11px;padding:2px 8px">View</button></td>' +
          '</tr>';
      }}).join('');
      box.innerHTML =
        '<table style="width:100%"><thead><tr>' +
        '<th style="font-size:11px">From</th>' +
        '<th style="font-size:11px">To</th>' +
        '<th style="font-size:11px">Subject</th>' +
        '<th style="font-size:11px">Date</th>' +
        '<th></th></tr></thead><tbody>' + rows + '</tbody></table>';
    }})
    .catch(function(e) {{
      box.innerHTML = '<div style="color:var(--danger);padding:14px;font-size:13px">Error: ' + e + '</div>';
    }});
}}
function showMhPreview(idx) {{
  var m = _MH_MSGS[idx];
  if (!m) return;
  document.getElementById('mh-preview').style.display = 'block';
  document.getElementById('mh-preview-subj').textContent = m.subject || '(no subject)';
  document.getElementById('mh-preview-frame').src =
    '/api/phishing/mailhog/message/' + encodeURIComponent(m.id) + '/html';
}}
function closeMhPreview() {{
  document.getElementById('mh-preview').style.display = 'none';
  document.getElementById('mh-preview-frame').src = '';
}}
document.addEventListener('DOMContentLoaded', function() {{ loadMhInbox(); }});
</script>"""
    return _base(f"Campaign: {camp.get('name','')}", html, "investigations")


@app.route("/investigation/<inv_id>/campaign/<campaign_id>/edit", methods=["POST"])
@require_login
def edit_phishing_campaign(inv_id, campaign_id):
    """Save edits to a phishing campaign (name, template, sending profile, landing URL)."""
    uid = flask_session["uid"]
    camp = db.one("SELECT * FROM phishing_campaigns WHERE id=? AND investigation_id=?",
                  (campaign_id, inv_id))
    if not camp:
        return "Campaign not found", 404
    # Only owner or admin may edit
    if not _is_admin() and camp["user_id"] != uid:
        return "Forbidden", 403
    # Cannot edit while actively sending
    if camp.get("status") in ("sending", "completed"):
        flask_session["flash"] = "Cannot edit a campaign that is sending or completed."
        return redirect(f"/investigation/{inv_id}/campaign/{campaign_id}")

    name              = request.form.get("name", "").strip() or camp["name"]
    template_id       = request.form.get("template_id", "").strip() or None
    sending_profile_id = request.form.get("sending_profile_id", "").strip() or None
    landing_url       = request.form.get("landing_url", "").strip() or None

    # Resolve template display name + subject for denormalised columns
    tpl_name    = camp.get("template_name", "")
    tpl_subject = camp.get("template_subject", "")
    if template_id:
        tpl = db.one("SELECT * FROM phishing_templates WHERE id=?", (template_id,))
        if tpl:
            tpl_name    = tpl["name"]
            tpl_subject = tpl["subject"]

    db.exec(
        """UPDATE phishing_campaigns
           SET name=?, template_id=?, sending_profile_id=?, landing_url=?,
               template_name=?, template_subject=?, updated_at=?
           WHERE id=?""",
        (name, template_id, sending_profile_id, landing_url,
         tpl_name, tpl_subject, _now(), campaign_id)
    )
    _audit("edit_phishing_campaign", "campaign", campaign_id,
           f"name={name} landing={landing_url}")
    flask_session["flash"] = f"Campaign '{name}' updated."
    return redirect(f"/investigation/{inv_id}/campaign/{campaign_id}")


@app.route("/api/phishing/campaign/<campaign_id>/delete", methods=["POST"])
@require_api_auth
def api_phishing_campaign_delete(campaign_id):
    uid = flask_session["uid"]
    c   = db.one("SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,))
    if not c or (not _is_admin() and c["user_id"] != uid):
        return jsonify({"ok":False,"error":"not found"}), 404
    db.exec("DELETE FROM phishing_results WHERE campaign_id=?", (campaign_id,))
    db.exec("DELETE FROM phishing_campaigns WHERE id=?", (campaign_id,))
    _audit("delete_phishing_campaign", "campaign", campaign_id, "")
    return jsonify({"ok":True})


@app.route("/api/phishing/campaign/<campaign_id>/approve", methods=["POST"])
@require_admin
def api_phishing_campaign_approve(campaign_id):
    """Admin-only: approve a campaign so the engine will allow delivery."""
    c = db.one("SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,))
    if not c:
        return jsonify({"ok": False, "error": "not found"}), 404
    approver = flask_session.get("username", "admin")
    db.exec(
        "UPDATE phishing_campaigns SET approved_by=?, approved_at=?, status='approved', updated_at=? WHERE id=?",
        (approver, _now(), _now(), campaign_id)
    )
    _audit("approve_phishing_campaign", "campaign", campaign_id, approver)
    return jsonify({"ok": True, "approved_by": approver})


@app.route("/api/phishing/campaign/<campaign_id>/suspend", methods=["POST"])
@require_admin
def api_phishing_campaign_suspend(campaign_id):
    """Admin-only: immediately suspend a running campaign (emergency stop)."""
    c = db.one("SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,))
    if not c:
        return jsonify({"ok": False, "error": "not found"}), 404
    from investigations.phishing.engine import PhishingEngine as _PhEng
    _PhEng(db).stop_campaign(campaign_id)
    db.exec(
        "UPDATE phishing_campaigns SET status='suspended', updated_at=? WHERE id=?",
        (_now(), campaign_id)
    )
    _audit("suspend_phishing_campaign", "campaign", campaign_id, flask_session.get("username",""))
    return jsonify({"ok": True})


@app.route("/api/phishing/campaign/<campaign_id>/test", methods=["POST"])
@require_login
def api_phishing_campaign_test(campaign_id):
    """
    Send a single test phishing email.
    Priority: global MailHog mode → campaign Sending Profile → system SMTP fallback.
    """
    if not _is_admin():
        return jsonify({"ok": False, "error": "Admin only"}), 403
    data = request.get_json(silent=True) or {}
    to_email = (data.get("to_email","") or "").strip()
    if not to_email:
        return jsonify({"ok": False, "error": "to_email required"}), 400
    camp = db.one("SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,))
    if not camp:
        return jsonify({"ok": False, "error": "Campaign not found"}), 404
    # Load email template
    tpl = (db.one("SELECT * FROM phishing_templates WHERE id=?", (camp.get("template_id",""),))
           if camp.get("template_id") else None)
    if not tpl:
        return jsonify({"ok": False, "error": "No email template assigned to this campaign. Edit it first."}), 400
    # Render with dummy target data
    base_url = (_get_setting("phishing_public_url","") or request.host_url).rstrip("/")
    test_click_url = base_url + "/phish/track/click/" + campaign_id + "/TEST"
    subject = (tpl.get("subject","") or "Test Phishing Email")
    for k, v in [("{{.FirstName}}","Test"),("{{.LastName}}","User"),
                 ("{{.Email}}",to_email),("{{.Position}}","Tester")]:
        subject = subject.replace(k, v)
    body_html = (tpl.get("html_body","") or "")
    for k, v in [("{{.FirstName}}","Test"),("{{.LastName}}","User"),
                 ("{{.Email}}",to_email),("{{.Position}}","Tester"),("{{.URL}}",test_click_url)]:
        body_html = body_html.replace(k, v)
    test_banner = (
        '<div style="background:#b91c1c;color:#fff;text-align:center;padding:8px 16px;'
        'font-family:Arial,sans-serif;font-size:13px;font-weight:700;letter-spacing:.05em">'
        '⚠ THIS IS A TEST EMAIL - Not a real campaign send</div>'
    )
    body_html = test_banner + body_html

    ok, err, note = False, "", ""
    smtp_mode = _get_setting("sys_smtp_mode", "mailhog")

    # ── Priority: campaign Sending Profile → global MailHog/SMTP ────────────
    prof_row = (db.one("SELECT * FROM phishing_sending_profiles WHERE id=?",
                       (camp.get("sending_profile_id",""),))
               if camp.get("sending_profile_id") else None)

    if prof_row:
        # ── Use the campaign's assigned Sending Profile (whatever SMTP it has) ──
        prof_name = prof_row.get("name","")
        try:
            from investigations.phishing.sender import PhishingSender as _PS
            _prof = {
                "smtp_host":  prof_row.get("smtp_host","localhost"),
                "smtp_port":  int(prof_row.get("smtp_port", 587)),
                "smtp_user":  prof_row.get("smtp_user",""),
                "smtp_pass":  prof_row.get("smtp_password","") or prof_row.get("smtp_pass",""),
                "smtp_tls":   bool(prof_row.get("use_tls", True)),
                "smtp_ssl":   bool(prof_row.get("use_ssl", False)),
                "from_name":  prof_row.get("from_name","FEROXSEI Phishing [TEST]"),
                "from_email": prof_row.get("from_address","") or prof_row.get("from_email",""),
                "send_delay": 0,
            }
            res = _PS(_prof).send({"email": to_email}, body_html, f"[TEST] {subject}")
            ok, err = res.get("ok", False), res.get("error","")
            mh_port_hint = int(prof_row.get("smtp_port", 587))
            if prof_row.get("smtp_host","") in ("localhost","mailhog","127.0.0.1") and mh_port_hint == 1025:
                note = (f"Sent via profile \"{prof_name}\" (MailHog) → "
                        f"check http://localhost:8025 - click the HTML tab to see rendered email.")
            else:
                note = f"Sent via Sending Profile \"{prof_name}\" → {to_email}"
        except Exception as e:
            ok, err = False, str(e)

    elif smtp_mode == "mailhog":
        # ── No profile: fall back to global MailHog mode ─────────────────────
        sys_cfg  = _sys_smtp_cfg()
        mh_host  = sys_cfg.get("host","localhost")
        mh_port  = int(sys_cfg.get("port", 1025))
        mh_from  = sys_cfg.get("from") or "argus-phishing@localhost"
        try:
            from investigations.phishing.sender import PhishingSender as _PS
            _prof = {"smtp_host": mh_host, "smtp_port": mh_port,
                     "smtp_user": "", "smtp_pass": "",
                     "smtp_tls": False, "smtp_ssl": False,
                     "from_name": "FEROXSEI Phishing [TEST]",
                     "from_email": mh_from, "send_delay": 0}
            res = _PS(_prof).send({"email": to_email}, body_html, f"[TEST] {subject}")
            ok, err = res.get("ok", False), res.get("error","")
            note = ("MailHog (global) - check http://localhost:8025 - "
                    "click the HTML tab to see rendered email. "
                    "Assign a Sending Profile in Edit Campaign to use custom SMTP.")
        except Exception as e:
            ok, err = False, str(e)

    else:
        # ── No profile, custom SMTP global mode: use system SMTP ─────────────
        ok, err = _send_system_email(to_email, f"[TEST] {subject}", body_html, f"TEST: {subject}")
        note = ("No Sending Profile assigned to this campaign - used system SMTP. "
                "Assign a Sending Profile in Edit Campaign to use campaign-specific SMTP.")

    _audit("test_send_phishing", "campaign", campaign_id,
           f"to={to_email} profile={prof_row.get('name','none') if prof_row else 'none'}")
    if not ok:
        return jsonify({"ok": False, "error": err or "Send failed"})
    return jsonify({"ok": True, "note": note})


@app.route("/api/phishing/mailhog/messages")
@require_login
def api_phishing_mailhog_messages():
    """Proxy MailHog /api/v2/messages → simplified JSON for the FEROXSEI inbox widget."""
    try:
        import urllib.request as _ur
        mh_host = (_get_setting("sys_smtp_mailhog_host", "").strip()
                   or _mailhog_default_host())
        url = f"http://{mh_host}:8025/api/v2/messages?limit=50"
        with _ur.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())

        messages = []
        for item in (data.get("items") or []):
            frm = item.get("From") or {}
            from_str = (f'{frm.get("Mailbox","")}@{frm.get("Domain","")}'
                        if frm else "")
            to_list = [
                f'{t.get("Mailbox","")}@{t.get("Domain","")}'
                for t in (item.get("To") or [])
            ]
            content = item.get("Content") or {}
            hdrs    = content.get("Headers") or {}
            subject  = (hdrs.get("Subject") or [""])[0]
            date_str = (hdrs.get("Date") or [""])[0][:30]
            messages.append({
                "id":      item.get("ID", ""),
                "from":    from_str,
                "to":      to_list,
                "subject": subject,
                "date":    date_str,
            })
        return jsonify({"ok": True, "messages": messages,
                        "total": data.get("total", 0)})
    except Exception as e:
        return jsonify({"ok": False, "error":
            f"MailHog not reachable at {mh_host if 'mh_host' in dir() else 'localhost'}:8025 - "
            f"is MailHog running? ({e})"})


@app.route("/api/phishing/mailhog/message/<path:msg_id>/html")
@require_login
def api_phishing_mailhog_message_html(msg_id):
    """Return the HTML body of a MailHog message for iframe preview."""
    import re as _re2, urllib.request as _ur2, urllib.parse as _up2
    if not _re2.match(r'^[A-Za-z0-9@._+\-]+$', msg_id):
        return "Invalid ID", 400
    try:
        mh_host = (_get_setting("sys_smtp_mailhog_host", "").strip()
                   or _mailhog_default_host())
        url = f"http://{mh_host}:8025/api/v1/messages/{_up2.quote(msg_id, safe='')}"
        with _ur2.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())

        def _find_html(part):
            if not part:
                return None
            hdrs = part.get("Headers") or {}
            ct   = (hdrs.get("Content-Type") or hdrs.get("content-type") or [""])[0]
            if "text/html" in ct:
                return part.get("Body") or ""
            for sub in ((part.get("MIME") or {}).get("Parts") or []):
                r = _find_html(sub)
                if r is not None:
                    return r
            return None

        html_body = None
        content = data.get("Content") or {}
        for p in ((content.get("MIME") or {}).get("Parts") or []):
            html_body = _find_html(p)
            if html_body is not None:
                break
        if html_body is None:
            for p in ((data.get("MIME") or {}).get("Parts") or []):
                html_body = _find_html(p)
                if html_body is not None:
                    break
        if html_body is None:
            html_body = content.get("Body") or ""

        if not html_body:
            html_body = "<p style='font-family:sans-serif;padding:20px;color:#666'>No HTML content in this message.</p>"
        return html_body, 200, {
            "Content-Type": "text/html; charset=utf-8",
            "X-Frame-Options": "SAMEORIGIN",
        }
    except Exception as e:
        return (
            f"<p style='font-family:sans-serif;padding:20px;color:red'>Error: {e}</p>",
            500, {"Content-Type": "text/html"},
        )


@app.route("/api/phishing/campaign/<campaign_id>/launch", methods=["POST"])
@require_login
def api_phishing_campaign_launch(campaign_id):
    """Launch an approved campaign in the background."""
    uid = flask_session["uid"]
    c   = db.one("SELECT * FROM phishing_campaigns WHERE id=?", (campaign_id,))
    if not c or (not _is_admin() and c["user_id"] != uid):
        return jsonify({"ok": False, "error": "not found"}), 404
    if not c.get("approved_by"):
        if _is_admin():
            # Admin implicitly self-approves on launch
            approver = flask_session.get("username", "admin")
            db.exec(
                "UPDATE phishing_campaigns SET approved_by=?, approved_at=?, status='approved', updated_at=? WHERE id=?",
                (approver, _now(), _now(), campaign_id)
            )
            _audit("auto_approve_phishing_campaign", "campaign", campaign_id, approver)
        else:
            return jsonify({"ok": False, "error": "Campaign must be approved by an administrator first."}), 403
    from investigations.phishing.engine import PhishingEngine as _PhEng
    base_url = (_get_setting("phishing_public_url","") or request.host_url).rstrip("/")
    # Pass global SMTP config so phishing engine can honour MailHog/Custom mode
    _sys_cfg = _sys_smtp_cfg()
    _PhEng(db, base_url, system_smtp=_sys_cfg).start_campaign(campaign_id)
    _audit("launch_phishing_campaign", "campaign", campaign_id, flask_session.get("username",""))
    return jsonify({"ok": True})


@app.route("/phish/landing/<name>")
def phish_landing_page(name):
    """
    Serve a phishing landing page template by name.
    Files live in investigations/phishing/templates/<name>.html
    The click-tracker appends ?cid=<campaign_id>&rid=<rid> so the
    page JS can POST credentials to /phish/track/submit/<cid>/<rid>.
    No login required - targets are external email recipients.
    """
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_-]+$', name):
        return "Not found", 404
    tpl_path = Path(__file__).parent / "investigations" / "phishing" / "templates" / f"{name}.html"
    if not tpl_path.exists():
        return "Not found", 404
    return tpl_path.read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/phish/awareness/<campaign_id>/<rid>")
def phish_awareness(campaign_id, rid):
    """
    Educational awareness page shown to participants after they click/submit.
    No login required - participants are external email recipients.
    """
    result = db.one(
        "SELECT r.*, c.name as campaign_name, t.name as template_name "
        "FROM phishing_results r "
        "LEFT JOIN phishing_campaigns c ON r.campaign_id=c.id "
        "LEFT JOIN phishing_templates t ON c.template_id=t.id "
        "WHERE r.campaign_id=? AND r.id=?",
        (campaign_id, rid)
    )
    campaign_name = _html.escape(result.get("campaign_name","Security Awareness Training") if result else "Security Awareness Training")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Awareness Training</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f4f8;color:#2d3748;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
    .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.12);max-width:680px;width:100%;overflow:hidden}}
    .header{{background:linear-gradient(135deg,#e53e3e,#c53030);color:#fff;padding:32px;text-align:center}}
    .header h1{{font-size:24px;margin-bottom:8px}}
    .header p{{opacity:.9;font-size:15px}}
    .body{{padding:32px}}
    .alert{{background:#fff5f5;border:2px solid #fc8181;border-radius:8px;padding:16px;margin-bottom:24px;display:flex;gap:12px;align-items:flex-start}}
    .alert-icon{{font-size:24px;flex-shrink:0}}
    h2{{font-size:18px;color:#2d3748;margin-bottom:12px;margin-top:24px}}
    h2:first-child{{margin-top:0}}
    ul{{padding-left:20px;line-height:1.8;color:#4a5568}}
    .indicator{{background:#f7fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:8px 0}}
    .indicator strong{{color:#c53030}}
    .footer{{background:#f7fafc;border-top:1px solid #e2e8f0;padding:20px 32px;font-size:13px;color:#718096;text-align:center}}
    .btn{{display:inline-block;background:#3182ce;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin-top:16px}}
  </style>
</head>
<body>
<div class="card">
  <div class="header">
    <div style="font-size:48px;margin-bottom:12px">🎣</div>
    <h1>This was a Security Awareness Test</h1>
    <p>{campaign_name}</p>
  </div>
  <div class="body">
    <div class="alert">
      <span class="alert-icon">⚠️</span>
      <div>
        <strong>You clicked a simulated phishing link.</strong><br>
        This was a controlled exercise run by your security team. No real harm has occurred -
        but a real attacker could have stolen your credentials or installed malware.
      </div>
    </div>

    <h2>🔍 Red flags you may have missed</h2>
    <div class="indicator"><strong>Sender address:</strong> Look carefully - real company emails never use free providers or misspelled domains.</div>
    <div class="indicator"><strong>Urgency &amp; pressure:</strong> Phrases like "Act now", "Your account will be suspended", or "Immediate action required" are classic manipulation tactics.</div>
    <div class="indicator"><strong>Hover before clicking:</strong> Always hover over links to see where they actually lead before clicking.</div>
    <div class="indicator"><strong>Unexpected requests:</strong> Legitimate IT teams will never ask for your password via email.</div>

    <h2>✅ What to do when you spot a real phishing email</h2>
    <ul>
      <li>Do <strong>not</strong> click any links or open attachments</li>
      <li>Report it to your security team using the "Report Phishing" button in your email client</li>
      <li>Delete the email from your inbox</li>
      <li>If you already clicked - change your password immediately and contact IT</li>
    </ul>

    <h2>📚 Learn more</h2>
    <ul>
      <li>Complete the assigned phishing awareness training module in your LMS</li>
      <li>Review your organisation's acceptable use and email security policies</li>
      <li>Enable multi-factor authentication (MFA) on all your accounts</li>
    </ul>
  </div>
  <div class="footer">
    This simulation was conducted under your organisation's security awareness programme.
    Your participation data is used only to improve security training - no personal data is stored.
  </div>
</div>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


# ═════════════════════════════════════════════════════════════════════════════
# PHISHING TRACKER ROUTES - open pixel / click redirect / submit capture
# ═════════════════════════════════════════════════════════════════════════════
try:
    from investigations.phishing.tracker import register_tracker_routes as _reg_tracker
    _base_url_for_tracker = (
        os.environ.get("PHISHING_PUBLIC_URL","") or
        _get_setting("phishing_public_url","") or
        "http://127.0.0.1:5001"
    )
    _reg_tracker(app, db, _base_url_for_tracker)
except Exception as _e:
    print(f"[WARNING] Could not register phishing tracker routes: {_e}")


# ═════════════════════════════════════════════════════════════════════════════
# LICENSE
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/license")
def license_page():
    html = """
<div style="max-width:760px;margin:0 auto">
  <div class="card">
    <div class="card-header">
      <span class="card-title">⚖️ License &amp; Legal Disclaimer</span>
    </div>
    <div class="card-body">

      <div style="background:rgba(255,56,96,.08);border:1px solid rgba(255,56,96,.3);border-radius:8px;padding:16px;margin-bottom:24px">
        <p style="font-weight:700;color:#ff3860;margin-bottom:8px;font-size:13px">⚠️ AUTHORIZED USE ONLY - LEGAL DISCLAIMER</p>
        <p style="font-size:13px;line-height:1.7;color:var(--text)">
          This software is intended <strong>exclusively for authorized security testing, research, and educational purposes</strong>.
          You must have explicit written permission from the owner of any system, network, or data before using this tool against it.
          Unauthorized use against systems you do not own or have permission to test is <strong>illegal</strong> and may violate
          computer fraud laws including but not limited to the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act,
          and equivalent legislation in your jurisdiction.
        </p>
        <p style="font-size:13px;line-height:1.7;color:var(--text);margin-top:10px">
          <strong>The author(s) accept no responsibility or liability</strong> for any misuse, damage, legal consequences,
          or harm caused directly or indirectly by the use of this software.
          <strong>You use this software entirely at your own risk.</strong>
        </p>
      </div>

      <p style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px">MIT License</p>
      <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Copyright (c) 2026 PentestRox</p>
      <pre style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:16px;font-size:12px;color:var(--text2);white-space:pre-wrap;line-height:1.7">Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.</pre>

      <p style="font-size:12px;color:var(--muted);margin-top:20px;text-align:center">
        FEROXSEI OSINT &nbsp;·&nbsp; by PentestRox &nbsp;·&nbsp;
        <a href="/" style="color:var(--muted)">Back to Dashboard</a>
      </p>
    </div>
  </div>
</div>"""
    return _base("License", html, "")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    _host = os.environ.get("FEROXSEI_HOST", "0.0.0.0")
    _port = int(os.environ.get("FEROXSEI_PORT", str(PORT)))
    _in_docker = os.path.exists("/.dockerenv")
    import pathlib as _pl
    _run_dir = str(_pl.Path(__file__).parent.resolve())
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   FEROXSEI OSINT - Ultimate Intelligence Platform           ║
║   http://{_host}:{_port}{"  [Docker]" if _in_docker else ""}
╚══════════════════════════════════════════════════════════╝
📂 Running from: {_run_dir}
{"🐳 Running inside Docker container" if _in_docker else "First run: register at http://127.0.0.1:"+str(_port)+"/register"}
""")
    app.run(host=_host, port=_port, debug=False, threaded=True)
