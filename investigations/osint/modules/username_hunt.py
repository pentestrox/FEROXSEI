"""
FEROXSEI OSINT - Username Hunt Module

Check types:
  status_code   - HTTP 200=found, 404=not-found (reliable for most APIs)
  message       - body contains found_str XOR error_str
  response_url  - redirect target differs from expected (no-JS check)
  json_key      - JSON response contains key at path

Rules:
  • Only save a finding when there is CONFIRMED evidence (url reachable + content validated)
  • Never save "not found" findings
  • Extract profile data (name, bio, followers) when available via JSON API
"""
from __future__ import annotations
import json
import re
from concurrent.futures import as_completed

from .base import BaseOSINTModule, _log, _extract_username, _thread_pool

try:
    from ddgs import DDGS as _DDGS
    _HAS_DDGS = True
except ImportError:
    try:
        from duckduckgo_search import DDGS as _DDGS
        _HAS_DDGS = True
    except ImportError:
        _HAS_DDGS = False

_DDG_BLOCKED_SITES = {
    "Twitter/X":  ("site:twitter.com/{u} OR site:x.com/{u}", "twitter.com/{u}", "x.com/{u}"),
    "Instagram":  ("site:instagram.com/{u}",                  "instagram.com/{u}", ""),
    "LinkedIn":   ('site:linkedin.com/in/{u}',                "linkedin.com/in/{u}", ""),
    "Facebook":   ("site:facebook.com/{u}",                   "facebook.com/{u}", ""),
    "YouTube":    ("site:youtube.com/@{u}",                   "youtube.com/@{u}", ""),
    "TikTok":     ("site:tiktok.com/@{u}",                    "tiktok.com/@{u}", ""),
}

# ─────────────────────────────────────────────────────────────────────────────
# Content-verification helpers
# ─────────────────────────────────────────────────────────────────────────────

# Phrases that appear in "user not found" pages even when HTTP status is 200.
# If any of these are detected in the response body, the finding is rejected.
_NOT_FOUND_PATTERNS: tuple[str, ...] = (
    "user not found",
    "page not found",
    "profile not found",
    "account not found",
    "user does not exist",
    "account does not exist",
    "doesn't exist",
    "does not exist",
    "no user found",
    "user has been removed",
    "no such user",
    "account suspended",
    "this account has been",
    "sorry, we couldn't find",
    "we can't find that user",
    "we couldn&#39;t find",
    "whoops, that page is gone",
    "there's nothing here",
    "there&#8217;s nothing here",
    "nobody here by that screen name",
    "is not a gravatar user",
    "that page doesn't exist",
    "that page doesn&#39;t exist",
    "account doesn't exist",
    "user deleted",
    "account deleted",
    "profile not available",
    "this user has been banned",
    "no results found",
    "404 not found",
    "this content isn't available",
)

# ─────────────────────────────────────────────────────────────────────────────
# Site registry
# Each entry: name → dict with:
#   url          str   URL template - {u} replaced with username
#   check        str   "status_code" | "message" | "response_url" | "json_key"
#   found_status int   HTTP status that means EXISTS        (default 200)
#   miss_status  int   HTTP status that means MISSING       (default 404)
#   found_str    str   substring in body that confirms user EXISTS
#   error_str    str   substring in body that means NOT found
#   expect_url   str   partial URL expected in final r.url  (response_url check)
#   json_path    str   dot-path in JSON that must be truthy (json_key check)
#   api_url      str   extra URL to fetch richer profile data (optional)
#   tags         list  extra tags on finding
# ─────────────────────────────────────────────────────────────────────────────
SITES: dict[str, dict] = {

    # ── Developer / Code ─────────────────────────────────────────────────────
    "GitHub": {
        "url": "https://api.github.com/users/{u}",
        "check": "json_key",
        "json_path": "login",
        "tags": ["dev", "code"],
    },
    "GitLab": {
        "url": "https://gitlab.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Sorry, we couldn&#39;t find",
        "tags": ["dev", "code"],
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "code"],
    },
    "Replit": {
        "url": "https://replit.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "404 Not Found",
        "tags": ["dev", "code"],
    },
    "CodePen": {
        "url": "https://codepen.io/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "code"],
    },
    "Dev.to": {
        "url": "https://dev.to/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "blog"],
    },
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "check": "json_key",
        "json_path": "id",
        "tags": ["dev", "community"],
    },
    "DockerHub": {
        "url": "https://hub.docker.com/v2/users/{u}/",
        "check": "json_key",
        "json_path": "username",
        "tags": ["dev", "infrastructure"],
    },
    "npm": {
        "url": "https://www.npmjs.com/~{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "user not found",
        "tags": ["dev", "nodejs"],
    },
    "PyPI": {
        "url": "https://pypi.org/user/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "python"],
    },
    "SourceForge": {
        "url": "https://sourceforge.net/u/{u}/profile/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "code"],
    },
    "Gitea (codeberg)": {
        "url": "https://codeberg.org/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "user does not exist",
        "tags": ["dev", "code"],
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{u}",
        "check": "message",
        "found_str": "reputation",
        "error_str": "Page Not Found",
        "tags": ["dev", "community"],
    },
    "Hugging Face": {
        "url": "https://huggingface.co/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "ai"],
    },
    "Kaggle": {
        "url": "https://www.kaggle.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "ai", "data"],
    },
    "LeetCode": {
        "url": "https://leetcode.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page Not Found",
        "tags": ["dev", "competitive"],
    },
    "HackerRank": {
        "url": "https://www.hackerrank.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "competitive"],
    },
    "Codeforces": {
        "url": "https://codeforces.com/profile/{u}",
        "check": "message",
        "found_str": "userbox",
        "error_str": "not found",
        "tags": ["dev", "competitive"],
    },
    "HackerEarth": {
        "url": "https://www.hackerearth.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "competitive"],
    },
    "Exercism": {
        "url": "https://exercism.org/profiles/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "learning"],
    },
    "OpenHub": {
        "url": "https://www.openhub.net/accounts/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Account Not Found",
        "tags": ["dev", "code"],
    },
    "JSFiddle": {
        "url": "https://jsfiddle.net/user/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "web"],
    },

    # ── Bug Bounty / Security ─────────────────────────────────────────────────
    "HackerOne": {
        "url": "https://hackerone.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "bugbounty"],
    },
    "Bugcrowd": {
        "url": "https://bugcrowd.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "bugbounty"],
    },
    "Intigriti": {
        "url": "https://app.intigriti.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "bugbounty"],
    },
    "Keybase": {
        "url": "https://keybase.io/_/api/1.0/user/lookup.json?username={u}",
        "check": "json_key",
        "json_path": "them.0.id",
        "tags": ["security", "crypto"],
    },
    "PentesterLab": {
        "url": "https://pentesterlab.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "ctf"],
    },
    "CyberDefenders": {
        "url": "https://cyberdefenders.org/p/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "ctf"],
    },

    # ── Social Media ──────────────────────────────────────────────────────────
    "Reddit": {
        "url": "https://www.reddit.com/user/{u}/about.json",
        "check": "json_key",
        "json_path": "data.name",
        "tags": ["social"],
    },
    "Twitter/X": {
        "url": "https://twitter.com/{u}",
        "check": "message",
        "found_str": "@{u}",
        "error_str": "This account doesn",
        "tags": ["social"],
    },
    "Instagram": {
        "url": "https://www.instagram.com/{u}/",
        "check": "message",
        "found_str": '"username":"{u}"',
        "error_str": "Sorry, this page isn",
        "tags": ["social"],
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{u}",
        "check": "message",
        "found_str": '"uniqueId":"{u}"',
        "error_str": "Couldn&#x27;t find this account",
        "tags": ["social"],
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Sorry! We couldn't find that page.",
        "tags": ["social"],
    },
    "Telegram": {
        "url": "https://t.me/{u}",
        "check": "message",
        "found_str": "tgme_page_title",
        "error_str": "tgme_page_additional",
        "tags": ["social", "messaging"],
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{u}",
        "check": "message",
        "found_str": "public-profile-name",
        "error_str": "Page Not Found",
        "tags": ["social", "professional"],
    },
    "Facebook": {
        "url": "https://www.facebook.com/{u}",
        "check": "message",
        "found_str": 'content="https://www.facebook.com/{u}"',
        "error_str": "This page isn",
        "tags": ["social"],
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "fediverse"],
    },
    "Bluesky": {
        "url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
        "check": "json_key",
        "json_path": "did",
        "tags": ["social", "fediverse"],
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Sorry, couldn",
        "tags": ["social"],
    },
    "VK": {
        "url": "https://vk.com/{u}",
        "check": "message",
        "found_str": 'og:url" content="https://vk.com/{u}"',
        "error_str": "This page was removed",
        "tags": ["social"],
    },
    "Tumblr": {
        "url": "https://www.tumblr.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "There's nothing here",
        "tags": ["social", "blog"],
    },
    "Threads": {
        "url": "https://www.threads.net/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social"],
    },
    "BeReal": {
        "url": "https://bere.al/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social"],
    },
    "Clubhouse": {
        "url": "https://www.clubhouse.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "audio"],
    },
    "VSCO": {
        "url": "https://vsco.co/{u}/gallery",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "photo"],
    },
    "Poshmark": {
        "url": "https://poshmark.com/closet/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "shopping"],
    },
    "Depop": {
        "url": "https://www.depop.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "shopping"],
    },
    "Xing": {
        "url": "https://www.xing.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["professional", "social"],
    },

    # ── Creative / Portfolio ───────────────────────────────────────────────────
    "Dribbble": {
        "url": "https://dribbble.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Whoops, that page is gone",
        "tags": ["creative", "design"],
    },
    "Behance": {
        "url": "https://www.behance.net/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["creative", "design"],
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Nobody here by that screen name",
        "id_pattern": r"(\d{5,15}@N\d{2,3})",
        "secondary_url": "https://www.flickr.com/photos/$$id$$",
        "tags": ["creative", "photo"],
    },
    "Flickr People Search": {
        "url": "https://www.flickr.com/search/people/?username={u}",
        "check": "message",
        "found_str": "pathAlias",
        "error_str": "0 people found|no people found",
        "id_pattern": r"(\d{5,15}@N\d{2,3})",
        "secondary_url": "https://www.flickr.com/photos/$$id$$",
        "tags": ["creative", "photo"],
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page Not Found",
        "tags": ["creative", "art"],
    },
    "ArtStation": {
        "url": "https://www.artstation.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["creative", "art"],
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "is not a Gravatar user",
        "tags": ["identity"],
    },
    "500px": {
        "url": "https://500px.com/p/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Sorry, that page",
        "tags": ["creative", "photo"],
    },
    "Unsplash": {
        "url": "https://unsplash.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["creative", "photo"],
    },
    "Imgur": {
        "url": "https://imgur.com/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "user not found",
        "tags": ["creative", "image"],
    },
    "Giphy": {
        "url": "https://giphy.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["creative", "social"],
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "404 Not Found",
        "tags": ["writing", "fiction"],
    },
    "Redbubble": {
        "url": "https://www.redbubble.com/people/{u}/shop",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["creative", "shopping"],
    },

    # ── Gaming ────────────────────────────────────────────────────────────────
    "Twitch": {
        "url": "https://www.twitch.tv/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Sorry. Unless you",
        "tags": ["gaming", "streaming"],
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "check": "message",
        "found_str": "persona_name",
        "error_str": "The specified profile could not be found",
        "tags": ["gaming"],
    },
    "Xbox": {
        "url": "https://xboxgamertag.com/search/{u}",
        "check": "message",
        "found_str": "Gamertag Found",
        "error_str": "Gamertag Not Found",
        "tags": ["gaming"],
    },
    "PSN": {
        "url": "https://psnprofiles.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "User Not Found",
        "tags": ["gaming"],
    },
    "Lichess": {
        "url": "https://lichess.org/api/user/{u}",
        "check": "json_key",
        "json_path": "id",
        "tags": ["gaming", "chess"],
    },
    "Chess.com": {
        "url": "https://api.chess.com/pub/player/{u}",
        "check": "json_key",
        "json_path": "username",
        "tags": ["gaming", "chess"],
    },
    "Kongregate": {
        "url": "https://www.kongregate.com/accounts/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["gaming"],
    },
    "Speedrun.com": {
        "url": "https://www.speedrun.com/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "does not exist",
        "tags": ["gaming"],
    },
    "Itch.io": {
        "url": "https://{u}.itch.io",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "page not found",
        "tags": ["gaming", "creative"],
    },
    "Newgrounds": {
        "url": "https://{u}.newgrounds.com",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["gaming", "creative"],
    },
    "Roblox": {
        "url": "https://www.roblox.com/users/profile?username={u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "User not found",
        "tags": ["gaming"],
    },
    "Minecraft": {
        "url": "https://api.mojang.com/users/profiles/minecraft/{u}",
        "check": "json_key",
        "json_path": "id",
        "tags": ["gaming"],
    },

    # ── Music / Audio ─────────────────────────────────────────────────────────
    "SoundCloud": {
        "url": "https://soundcloud.com/{u}",
        "check": "message",
        "found_str": '"@type":"MusicGroup"',
        "error_str": "We can&#39;t find that user",
        "tags": ["music"],
    },
    "Spotify": {
        "url": "https://open.spotify.com/user/{u}",
        "check": "message",
        "found_str": '"@type":"MusicGroup"',
        "error_str": "Page not found",
        "tags": ["music"],
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "User not found",
        "tags": ["music"],
    },
    "Bandcamp": {
        "url": "https://bandcamp.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["music"],
    },
    "Mixcloud": {
        "url": "https://www.mixcloud.com/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page Not Found",
        "tags": ["music"],
    },

    # ── Video ──────────────────────────────────────────────────────────────────
    "YouTube": {
        "url": "https://www.youtube.com/@{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "This channel doesn",
        "tags": ["video"],
    },
    "Vimeo": {
        "url": "https://vimeo.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page not found",
        "tags": ["video"],
    },
    "Dailymotion": {
        "url": "https://www.dailymotion.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["video"],
    },
    "Rumble": {
        "url": "https://rumble.com/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "404 Not Found",
        "tags": ["video"],
    },
    "Odysee": {
        "url": "https://odysee.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["video"],
    },
    "BitChute": {
        "url": "https://www.bitchute.com/profile/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Channel not found",
        "tags": ["video"],
    },

    # ── Writing / Blog ────────────────────────────────────────────────────────
    "Medium": {
        "url": "https://medium.com/@{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Page not found",
        "tags": ["blog", "writing"],
    },
    "Substack": {
        "url": "https://{u}.substack.com",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "not found",
        "tags": ["blog", "newsletter"],
    },
    "Ghost": {
        "url": "https://{u}.ghost.io",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["blog"],
    },
    "WordPress": {
        "url": "https://{u}.wordpress.com",
        "check": "message",
        "found_str": '<link rel="profile"',
        "error_str": "doesn&#8217;t exist",
        "tags": ["blog"],
    },
    "Hashnode": {
        "url": "https://hashnode.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["blog", "dev"],
    },
    "Mirror.xyz": {
        "url": "https://mirror.xyz/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["writing", "crypto"],
    },
    "Vocal.media": {
        "url": "https://vocal.media/authors/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["writing", "blog"],
    },

    # ── Professional / Business ────────────────────────────────────────────────
    "AngelList": {
        "url": "https://angel.co/u/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["professional", "startup"],
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page not found",
        "tags": ["professional", "startup"],
    },
    "Crunchbase": {
        "url": "https://www.crunchbase.com/person/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Page Not Found",
        "tags": ["professional", "business"],
    },
    "About.me": {
        "url": "https://about.me/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "That page doesn",
        "tags": ["professional", "identity"],
    },
    "ResearchGate": {
        "url": "https://www.researchgate.net/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["academic", "professional"],
    },
    "Academia.edu": {
        "url": "https://independent.academia.edu/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["academic"],
    },
    "SlideShare": {
        "url": "https://www.slideshare.net/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["professional", "presentations"],
    },
    "Scribd": {
        "url": "https://www.scribd.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["writing", "documents"],
    },

    # ── Link Aggregators / Bio Pages ──────────────────────────────────────────
    "Linktree": {
        "url": "https://linktr.ee/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Sorry, this page isn",
        "tags": ["identity", "link"],
    },
    "Carrd": {
        "url": "https://{u}.carrd.co",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["identity", "link"],
    },
    "Bio.link": {
        "url": "https://bio.link/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["identity", "link"],
    },

    # ── Freelance / Marketplace ────────────────────────────────────────────────
    "Fiverr": {
        "url": "https://www.fiverr.com/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "Sorry, this page",
        "tags": ["freelance"],
    },
    "Freelancer": {
        "url": "https://www.freelancer.com/u/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["freelance"],
    },
    "Toptal": {
        "url": "https://www.toptal.com/resume/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["freelance", "professional"],
    },

    # ── Finance / Crypto ──────────────────────────────────────────────────────
    "Coinbase": {
        "url": "https://www.coinbase.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["crypto", "finance"],
    },
    "Patreon": {
        "url": "https://www.patreon.com/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "become a creator",
        "tags": ["creator", "finance"],
    },
    "Ko-fi": {
        "url": "https://ko-fi.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page not found",
        "tags": ["creator", "finance"],
    },
    "Buy Me A Coffee": {
        "url": "https://www.buymeacoffee.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Not Found",
        "tags": ["creator", "finance"],
    },
    "Etsy": {
        "url": "https://www.etsy.com/shop/{u}",
        "check": "message",
        "found_str": '"@type":"Store"',
        "error_str": "Sorry, this shop",
        "tags": ["shopping", "creative"],
    },

    # ── Paste / Text ──────────────────────────────────────────────────────────
    "Pastebin": {
        "url": "https://pastebin.com/u/{u}",
        "check": "message",
        "found_str": "Public Pastes",
        "error_str": "Not Found",
        "tags": ["paste"],
    },

    # ── Q&A / Community ───────────────────────────────────────────────────────
    "Quora": {
        "url": "https://www.quora.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["community", "qa"],
    },
    "Disqus": {
        "url": "https://disqus.com/by/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page Not Found",
        "tags": ["community"],
    },
    "Instructables": {
        "url": "https://www.instructables.com/member/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["community", "diy"],
    },
    "Letterboxd": {
        "url": "https://letterboxd.com/{u}",
        "check": "message",
        "found_str": "profile-summary",
        "error_str": "Sorry, we can",
        "tags": ["entertainment", "movies"],
    },
    "Goodreads": {
        "url": "https://www.goodreads.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["entertainment", "books"],
    },
    "MyAnimeList": {
        "url": "https://myanimelist.net/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Invalid Username",
        "tags": ["entertainment", "anime"],
    },
    "AniList": {
        "url": "https://anilist.co/user/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["entertainment", "anime"],
    },
    "Duolingo": {
        "url": "https://www.duolingo.com/profile/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["education"],
    },

    # ── Travel ────────────────────────────────────────────────────────────────
    "Couchsurfing": {
        "url": "https://www.couchsurfing.com/people/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["travel"],
    },
    "TripAdvisor": {
        "url": "https://www.tripadvisor.com/members/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["travel"],
    },

    # ── Forums / Niche ────────────────────────────────────────────────────────
    "Lobsters": {
        "url": "https://lobste.rs/~{u}.json",
        "check": "json_key",
        "json_path": "username",
        "tags": ["dev", "community"],
    },
    "Gitea": {
        "url": "https://gitea.com/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["dev", "code"],
    },
    "Launchpad": {
        "url": "https://launchpad.net/~{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "does not exist",
        "tags": ["dev", "linux"],
    },
    "Phoronix": {
        "url": "https://www.phoronix.com/forums/member/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["community", "tech"],
    },
    "Fosstodon": {
        "url": "https://fosstodon.org/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social", "fediverse", "dev"],
    },

    # ── CTF / Hacking ─────────────────────────────────────────────────────────
    "HackTheBox": {
        "url": "https://app.hackthebox.com/profile/overview",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "ctf"],
    },
    "TryHackMe": {
        "url": "https://tryhackme.com/p/{u}",
        "check": "message",
        "found_str": "Joined",
        "error_str": "404",
        "tags": ["security", "ctf"],
    },
    "Root-Me": {
        "url": "https://www.root-me.org/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "not found",
        "tags": ["security", "ctf"],
    },
    "PicoCTF": {
        "url": "https://play.picoctf.org/users/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["security", "ctf"],
    },

    # ── Dating / Personal ─────────────────────────────────────────────────────
    "OkCupid": {
        "url": "https://www.okcupid.com/profile/{u}",
        "check": "message",
        "found_str": '"userDisplayName"',
        "error_str": "Hmm, we can",
        "tags": ["dating", "personal"],
    },

    # ── Other ─────────────────────────────────────────────────────────────────
    "Wikipedia": {
        "url": "https://en.wikipedia.org/wiki/User:{u}",
        "check": "message",
        "found_str": "User contributions",
        "error_str": "There is currently no text in this page",
        "tags": ["encyclopedia"],
    },
    "Archive.org": {
        "url": "https://archive.org/details/@{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "error_str": "Page cannot be found",
        "tags": ["archive"],
    },
    "Internet Archive Forums": {
        "url": "https://archive.org/about/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["archive"],
    },
    "Ello": {
        "url": "https://ello.co/{u}",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social"],
    },
    "Minds": {
        "url": "https://www.minds.com/{u}/",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social"],
    },
    "Gab": {
        "url": "https://gab.com/{u}",
        "check": "message",
        "found_str": '"@type":"Person"',
        "error_str": "User not found",
        "tags": ["social"],
    },
    "Parler": {
        "url": "https://parler.com/profile/{u}/posts",
        "check": "status_code",
        "found_status": 200,
        "miss_status": 404,
        "tags": ["social"],
    },
}


try:
    from .userhunt_extra import SITES_EXTRA as _SITES_EXTRA
    SITES.update(_SITES_EXTRA)
except Exception:
    pass


def _extract_json_path(data: dict, path: str):
    """Navigate dot-path like 'data.name' or 'them.0.id' in JSON."""
    parts = path.split(".")
    cur = data
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, list):
            try:
                cur = cur[int(p)]
            except (IndexError, ValueError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _load_db_sites(db) -> dict:
    try:
        rows = db.get_userhunt_sites(enabled_only=True)
        if not rows:
            return {}
        sites = {}
        for r in rows:
            url = r["url"].replace("$$username$$", "{u}")
            sites[r["name"]] = {
                "url":           url,
                "check":         r["check_type"],
                "found_status":  r["found_status"],
                "miss_status":   r["miss_status"],
                "found_str":     r["found_str"] or "",
                "error_str":     r["error_str"] or "",
                "expect_url":    r["expect_url"] or "",
                "json_path":     r["json_path"] or "",
                "tags":          json.loads(r["tags"] or "[]"),
                "secondary_url": r.get("secondary_url") or "",
                "id_pattern":    r.get("id_pattern") or "",
            }
        return sites
    except Exception:
        return {}


class UsernameHuntModule(BaseOSINTModule):
    """Username enumeration across 137+ built-in platforms (DB-driven, fully configurable)."""
    NAME  = "username"
    LABEL = "Username Hunt"
    ICON  = "👤"
    ORDER = 40
    TARGET_TYPES: list = ['username']

    def _expand_name_usernames(self, config: dict) -> list[str]:
        """Generate username list from name parts + DB patterns (advanced mode)."""
        first  = (config.get("name_first")  or "").strip()
        middle = (config.get("name_middle") or "").strip()
        last   = (config.get("name_last")   or "").strip()
        if not first or not last:
            return []
        try:
            patterns = self.db.get_username_patterns(enabled_only=True)
        except Exception:
            patterns = []
        if not patterns:
            return []
        seen, out = set(), []
        for p in patterns:
            pat    = p.get("pattern","")
            f      = first[0].lower()  if first  else ""
            m      = middle[0].lower() if middle else ""
            l      = last[0].lower()   if last   else ""
            needs_mid = "{middle}" in pat or "{m}" in pat
            if needs_mid and not middle:
                continue
            result = (pat
                .replace("{first}",  first.lower())
                .replace("{last}",   last.lower())
                .replace("{middle}", middle.lower())
                .replace("{f}", f)
                .replace("{m}", m)
                .replace("{l}", l))
            if "{" not in result and result not in seen:
                seen.add(result)
                out.append(result)
        return out

    def _expand_email_addresses(self, config: dict) -> list[str]:
        """Generate email list from name parts + domain (advanced email mode)."""
        first  = (config.get("email_first")  or "").strip()
        middle = (config.get("email_middle") or "").strip()
        last   = (config.get("email_last")   or "").strip()
        domain = (config.get("email_domain") or "").strip().lstrip("@")
        if not first or not last or not domain:
            return []
        # Re-use username patterns but append domain
        tmp_cfg = {"name_first": first, "name_middle": middle, "name_last": last}
        usernames = self._expand_name_usernames(tmp_cfg)
        return [f"{u}@{domain}" for u in usernames]

    def run(self, scan_id: str, target: str, config: dict) -> None:
        # ── Advanced name-builder mode ────────────────────────────────────────
        if config.get("adv_username"):
            usernames = self._expand_name_usernames(config)
            if not usernames:
                _log(f"[{self.LABEL}] Advanced mode: no patterns produced usernames - skipping")
                return
            first = config.get("name_first","")
            last  = config.get("name_last","")
            _log(f"[{self.LABEL}] Advanced mode: {len(usernames)} username variants for {first} {last}")
            self.emit_task(scan_id,
                           f"Advanced hunt: {len(usernames)} variants for {first} {last}",
                           detail=", ".join(usernames[:8]) + ("…" if len(usernames) > 8 else ""))
            for uname in usernames:
                if self.should_skip(scan_id):
                    break
                self._run_for_username(scan_id, uname, config)
            return

        username = config.get("username") or _extract_username(target)
        if not username:
            _log(f"[{self.LABEL}] No username found in target - skipping")
            return

        username = username.strip().lstrip("@")
        self._run_for_username(scan_id, username, config)

    def _run_for_username(self, scan_id: str, username: str, config: dict) -> None:
        """Core hunt for a single username across all enabled sites."""
        active_sites = _load_db_sites(self.db) or SITES
        total = len(active_sites)

        _log(f"[{self.LABEL}] Hunting: @{username} across {total} platforms")
        self.emit_task(scan_id, f"Checking @{username} across {total} platforms",
                       detail="Content-validated - no false positives")

        found: list[dict] = []
        errors: list[str] = []

        def _check_site(name: str, cfg: dict) -> dict | None:
            if self.should_skip(scan_id):
                return None
            raw_url = cfg["url"].replace("{u}", username)
            check   = cfg.get("check", "status_code")
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            }
            if "api.github.com" in raw_url or "firebaseio" in raw_url \
                    or "bsky.app" in raw_url or "hub.docker.com" in raw_url \
                    or "chess.com" in raw_url or "lichess.org" in raw_url:
                headers["Accept"] = "application/json"

            try:
                r = self.http.get(
                    raw_url, scan_id, self.NAME,
                    add_delay=False,
                    allow_redirects=True,
                    timeout=10,
                    headers=headers,
                )
            except Exception:
                return None

            if not r:
                return None

            found_status = cfg.get("found_status", 200)
            miss_status  = cfg.get("miss_status",  404)
            # Support pipe-separated multi-value found/error strings
            _fs_raw = (cfg.get("found_str", "") or "").replace("{u}", username)
            _es_raw = (cfg.get("error_str", "") or "").replace("{u}", username)
            found_strs = [s.strip() for s in _fs_raw.split("|") if s.strip()]
            error_strs = [s.strip() for s in _es_raw.split("|") if s.strip()]
            found_str  = found_strs[0] if found_strs else ""
            error_str  = error_strs[0] if error_strs else ""

            body = ""
            if hasattr(r, "text") and r.text:
                body = r.text[:500_000]

            confirmed = False
            evidence_detail = ""

            if check == "status_code":
                if r.status_code == miss_status:
                    return None
                if r.status_code != found_status:
                    return None
                if error_strs and any(e.lower() in body.lower() for e in error_strs):
                    return None
                # ── Redirect-to-root / listing page detection ────────────────
                # If allow_redirects=True took us to the site homepage or a
                # listing page (path is "/" or doesn't contain the username),
                # it's a redirect-to-homepage FP.
                final_url = getattr(r, "url", raw_url) or raw_url
                try:
                    from urllib.parse import urlparse as _up2
                    _fp = _up2(final_url).path.rstrip("/")
                    if _fp in ("", "/", "/home", "/index.html", "/index.php", "/models") \
                            or username.lower() not in final_url.lower():
                        if not body or username.lower() not in body.lower():
                            return None
                except Exception:
                    pass
                # ── Content safety-net ────────────────────────────────────────
                # Many platforms return HTTP 200 for "not found" pages. Verify:
                #   1. The username actually appears somewhere in the body
                #   2. The page doesn't contain "user not found"-style language
                # Lower threshold to 50 to catch short redirect pages.
                if body and len(body) > 50:
                    body_l = body.lower()
                    if username.lower() not in body_l:
                        return None          # username absent → not a real profile
                    if any(pat in body_l for pat in _NOT_FOUND_PATTERNS):
                        return None          # "not found" page despite HTTP 200
                # ─────────────────────────────────────────────────────────────
                confirmed = True
                evidence_detail = f"HTTP {r.status_code}"

            elif check == "message":
                if error_strs and any(e.lower() in body.lower() for e in error_strs):
                    return None
                if found_strs:
                    if not any(fs.lower() in body.lower() for fs in found_strs):
                        return None
                elif r.status_code not in (200, 201):
                    return None
                confirmed = True
                _matched_fs = next((fs for fs in found_strs if fs.lower() in body.lower()), found_str)
                evidence_detail = f"Content match: '{_matched_fs[:60]}'" if _matched_fs else f"HTTP {r.status_code}"

            elif check == "response_url":
                expect = cfg.get("expect_url", "")
                if expect and expect not in r.url:
                    return None
                if error_strs and any(e.lower() in body.lower() for e in error_strs):
                    return None
                # Not-found pattern safety-net
                if body and len(body) > 200:
                    body_l = body.lower()
                    if any(pat in body_l for pat in _NOT_FOUND_PATTERNS):
                        return None
                confirmed = True
                evidence_detail = f"Final URL: {r.url}"

            elif check == "json_key":
                if r.status_code == miss_status or r.status_code not in (200, 201):
                    return None
                try:
                    jdata = r.json()
                except Exception:
                    return None
                val = _extract_json_path(jdata, cfg.get("json_path", ""))
                if not val:
                    return None
                confirmed = True
                evidence_detail = f"API confirmed: {cfg['json_path']} = {str(val)[:80]}"

            if not confirmed:
                return None

            profile_extra = _extract_profile_data(name, r, body, username)
            # ── Sequential search: extract ID → verify secondary URL via HTTP ─
            secondary_results = []
            sec_url_tmpl = cfg.get("secondary_url", "")
            id_pattern   = cfg.get("id_pattern", "")
            if sec_url_tmpl and id_pattern and body:
                try:
                    import re as _re
                    id_matches = _re.findall(id_pattern.replace("{u}", username), body)
                    seen_ids   = set()
                    candidates = []
                    for extracted_id in id_matches[:10]:
                        if extracted_id and extracted_id != username and extracted_id not in seen_ids:
                            seen_ids.add(extracted_id)
                            sec_url = (sec_url_tmpl
                                       .replace("$$username$$", username)
                                       .replace("$$id$$", extracted_id)
                                       .replace("{u}", username))
                            candidates.append({"id": extracted_id, "url": sec_url})
                    # HTTP-verify each candidate URL
                    for cand in candidates:
                        if self.should_skip(scan_id):
                            break
                        try:
                            sec_r = self.http.get(
                                cand["url"], scan_id, self.NAME,
                                add_delay=False,
                                allow_redirects=True,
                                timeout=8,
                                headers=headers,
                            )
                            if sec_r and sec_r.status_code == 200:
                                sec_body = sec_r.text[:10_000] if hasattr(sec_r, "text") else ""
                                sec_profile = _extract_profile_data(name, sec_r, sec_body, cand["id"])
                                cand["verified"]  = True
                                cand["profile"]   = sec_profile
                                cand["final_url"] = getattr(sec_r, "url", cand["url"])
                                secondary_results.append(cand)
                        except Exception:
                            pass
                except Exception:
                    pass
            return {
                "platform":   name,
                "url":        r.url,
                "check":      check,
                "evidence":   evidence_detail,
                "profile":    profile_extra,
                "tags":       cfg.get("tags", []),
                "secondary":  secondary_results,
            }

        with _thread_pool(max_workers=10) as pool:
            futs = {pool.submit(_check_site, name, cfg): name
                    for name, cfg in active_sites.items()}
            done = 0
            for fut in as_completed(futs):
                done += 1
                try:
                    result = fut.result(timeout=15)
                    if result:
                        found.append(result)
                        _log(f"[{self.LABEL}] ✅ FOUND @{username} on {result['platform']}")
                        prof = result["profile"]
                        prof_lines = []
                        if prof.get("display_name"):
                            prof_lines.append(f"Name: {prof['display_name']}")
                        if prof.get("bio"):
                            prof_lines.append(f"Bio: {prof['bio'][:200]}")
                        if prof.get("followers") is not None:
                            prof_lines.append(f"Followers: {prof['followers']}")
                        if prof.get("location"):
                            prof_lines.append(f"Location: {prof['location']}")
                        evidence_block = "\n".join([
                            f"URL: {result['url']}",
                            f"Check: {result['evidence']}",
                        ] + prof_lines)
                        self.db.save_finding(
                            scan_id, self.NAME, "info",
                            f"👤 @{username} on {result['platform']}",
                            f"Username active on {result['platform']}",
                            url=result["url"],
                            evidence=evidence_block,
                            tags=["username", "identity", "osint"] + result["tags"],
                            raw_data={"platform": result["platform"],
                                      "url": result["url"],
                                      "profile": prof},
                        )
                        # ── Save secondary profiles (sequential search, HTTP-verified) ─
                        for sec in result.get("secondary", []):
                            sec_prof  = sec.get("profile", {})
                            sec_lines = [
                                f"URL: {sec.get('final_url', sec['url'])}",
                                f"Source: Sequential search from @{username} on {result['platform']}",
                                f"Extracted ID: {sec['id']} (HTTP 200 verified)",
                            ]
                            if sec_prof.get("display_name"):
                                sec_lines.append(f"Name: {sec_prof['display_name']}")
                            if sec_prof.get("bio"):
                                sec_lines.append(f"Bio: {sec_prof['bio'][:200]}")
                            if sec_prof.get("followers") is not None:
                                sec_lines.append(f"Followers: {sec_prof['followers']}")
                            if sec_prof.get("location"):
                                sec_lines.append(f"Location: {sec_prof['location']}")
                            sec_evidence = "\\n".join(sec_lines)
                            self.db.save_finding(
                                scan_id, self.NAME, "low",
                                f"👤 @{username} → ID:{sec['id']} on {result['platform']} (verified)",
                                f"Sequential search confirmed user ID {sec['id']} on {result['platform']} - profile page returns HTTP 200",
                                url=sec.get("final_url", sec["url"]),
                                evidence=sec_evidence,
                                tags=["username", "identity", "osint", "sequential", "verified"] + result["tags"],
                                raw_data={"platform": result["platform"],
                                          "url": sec.get("final_url", sec["url"]),
                                          "extracted_id": sec["id"],
                                          "source_username": username,
                                          "profile": sec_prof},
                            )
                            # Add to entity graph (with scan_id so per-scan filter works)
                            try:
                                scan_row = self.db.one("SELECT investigation_id FROM osint_scans WHERE id=?", (scan_id,))
                                if scan_row and scan_row.get("investigation_id"):
                                    inv_id = scan_row["investigation_id"]
                                    self.db.ensure_entity(inv_id, "username", sec["url"],
                                                          label=f"{result['platform']}:{sec['id']}",
                                                          confidence=80,
                                                          source_module=self.NAME,
                                                          scan_id=scan_id)
                                    self.db.ensure_entity(inv_id, "flickr_id", sec["id"],
                                                          label=sec["id"],
                                                          confidence=85,
                                                          source_module=self.NAME,
                                                          scan_id=scan_id)
                            except Exception:
                                pass
                except Exception:
                    pass
                if done % 20 == 0:
                    self.emit_task(scan_id,
                                   f"Checked {done}/{total} - {len(found)} found",
                                   detail=f"@{username}")

        if _HAS_DDGS and not self.should_skip(scan_id):
            ddg_found = set(r["platform"] for r in found)
            self.emit_task(scan_id, "DDG search: blocked social platforms",
                           detail="Twitter/X, Instagram, LinkedIn, Facebook, YouTube, TikTok")
            for platform, (query_tmpl, url_hint, url_hint2) in _DDG_BLOCKED_SITES.items():
                if platform in ddg_found or self.should_skip(scan_id):
                    continue
                query = query_tmpl.replace("{u}", username)
                hint1 = url_hint.replace("{u}", username).lower()
                hint2 = url_hint2.replace("{u}", username).lower()
                try:
                    hits = _DDGS().text(query, max_results=5) or []
                except Exception as exc:
                    _log(f"[{self.LABEL}] DDG error for {platform}: {exc}")
                    hits = []
                for h in hits:
                    href = (h.get("href") or h.get("url") or "").lower()
                    if hint1 in href or (hint2 and hint2 in href):
                        real_url = h.get("href") or h.get("url") or ""
                        evidence_block = "\n".join([
                            f"URL: {real_url}",
                            f"Check: DDG search-indexed (direct HTTP blocked)",
                            f"Title: {h.get('title', '')[:100]}",
                            f"Snippet: {h.get('body', '')[:200]}",
                        ])
                        self.db.save_finding(
                            scan_id, self.NAME, "info",
                            f"👤 @{username} on {platform} (search-indexed)",
                            f"Username found via DDG search index on {platform}. "
                            "Direct HTTP check was blocked by platform bot-protection.",
                            url=real_url,
                            evidence=evidence_block,
                            tags=["username", "identity", "osint", "social", "ddg"],
                            raw_data={"platform": platform, "url": real_url,
                                      "source": "ddg_search"},
                        )
                        _log(f"[{self.LABEL}] DDG found @{username} on {platform}: {real_url}")
                        found.append({"platform": platform, "url": real_url,
                                      "tags": ["social"], "profile": {},
                                      "evidence": "DDG search-indexed"})
                        break

        if not found:
            _log(f"[{self.LABEL}] No confirmed profiles for @{username}")
            return

        tag_groups: dict[str, list[str]] = {}
        for r in found:
            for t in r["tags"]:
                tag_groups.setdefault(t, []).append(r["platform"])

        summary_lines = [f"  {r['platform']}: {r['url']}" for r in found]
        self.db.save_finding(
            scan_id, self.NAME, "medium",
            f"👤 Username Intelligence: @{username} - {len(found)} Platform(s)",
            f"Confirmed @{username} active on {len(found)} platforms across "
            f"{len(tag_groups)} categories.",
            evidence="\n".join(summary_lines),
            tags=["username", "identity", "osint", "summary"],
            raw_data={
                "username": username,
                "total_found": len(found),
                "platforms": [r["platform"] for r in found],
                "categories": tag_groups,
            },
        )
        _log(f"[{self.LABEL}] Done - {len(found)}/{total} confirmed for @{username}")


def _extract_profile_data(platform: str, r, body: str, username: str) -> dict:
    """Best-effort profile data extraction from API JSON responses."""
    out: dict = {}
    try:
        if platform in ("GitHub",):
            j = r.json()
            out["display_name"] = j.get("name") or ""
            out["bio"]          = j.get("bio") or ""
            out["followers"]    = j.get("followers")
            out["location"]     = j.get("location") or ""
            out["public_repos"] = j.get("public_repos")
            out["company"]      = j.get("company") or ""
            out["blog"]         = j.get("blog") or ""
            out["avatar"]       = j.get("avatar_url") or ""
            out["created"]      = j.get("created_at") or ""
            return out

        if platform in ("HackerNews",):
            j = r.json()
            out["karma"]    = j.get("karma")
            out["created"]  = j.get("created")
            return out

        if platform == "DockerHub":
            j = r.json()
            out["display_name"] = j.get("full_name") or ""
            out["bio"]          = j.get("company") or ""
            out["followers"]    = j.get("followers")
            return out

        if platform in ("Lichess", "Chess.com"):
            j = r.json()
            out["display_name"] = (j.get("username") or j.get("name") or "")
            rating = j.get("perfs") or j.get("stats") or {}
            if rating:
                out["rating"] = str(rating)[:100]
            return out

        if platform == "Bluesky":
            j = r.json()
            out["display_name"] = j.get("displayName") or ""
            out["bio"]          = j.get("description") or ""
            out["followers"]    = j.get("followersCount")
            out["avatar"]       = j.get("avatar") or ""
            return out

        if platform == "Reddit":
            j = r.json()
            d = j.get("data", {})
            out["display_name"] = d.get("name") or ""
            out["karma"]        = d.get("total_karma") or d.get("link_karma")
            out["created"]      = str(d.get("created_utc") or "")
            out["verified"]     = d.get("verified", False)
            return out

        if platform == "Keybase":
            j = r.json()
            them = (j.get("them") or [{}])[0]
            prof = them.get("profile") or {}
            out["display_name"] = prof.get("full_name") or ""
            out["bio"]          = prof.get("bio") or ""
            out["location"]     = prof.get("location") or ""
            return out

        if platform == "Lobsters":
            j = r.json()
            out["display_name"] = j.get("username") or ""
            out["karma"]        = j.get("karma")
            out["created"]      = j.get("created_at") or ""
            return out

    except Exception:
        pass

    try:
        og_title = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', body, re.I)
        og_desc  = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if og_title:
            out["display_name"] = og_title.group(1).strip()
        if og_desc:
            out["bio"] = og_desc.group(1).strip()[:300]
    except Exception:
        pass

    return out
