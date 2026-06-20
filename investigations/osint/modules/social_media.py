"""
FEROXSEI OSINT - Social Media OSINT (Advanced)
Inspired by: twscrape, Osintgram, GHunt, SpiderFoot

Covers:
  • GitHub - org repos, member list, contributor emails, tech stack, secret leaks in commits
  • Twitter/X - profile data via Nitter public instances (no API key)
  • LinkedIn - company page, employee count, tech stack from job posts
  • Instagram - public profile metadata (bio, follower count, posts)
  • Facebook - public page info
  • Google Account (GHunt-style) - Google profile, services linked to email/ID
  • Reddit - subreddit + user presence for brand/org
  • YouTube - channel search for brand presence
  • Job post intelligence - tech stack reverse-engineering from LinkedIn/Indeed

No findings saved without confirmed evidence.
"""
from __future__ import annotations
import re
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain

_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')

_NITTER_INSTANCES = [
    "https://nitter.net",
    "https://nitter.it",
    "https://nitter.nl",
    "https://nitter.1d4.us",
    "https://nitter.kavin.rocks",
]

_TECH_IN_JOB_POSTS = [
    "React", "Vue", "Angular", "Next.js", "Node.js", "Django", "Flask",
    "Ruby on Rails", "Laravel", "Spring Boot", "FastAPI", "Express",
    "PostgreSQL", "MySQL", "MongoDB", "Redis", "Elasticsearch", "Cassandra",
    "AWS", "Azure", "GCP", "Kubernetes", "Docker", "Terraform", "Ansible",
    "GraphQL", "gRPC", "Kafka", "RabbitMQ", "Nginx", "Apache",
    "Python", "Go", "Rust", "Java", "Kotlin", "Swift", "TypeScript",
    "Splunk", "Datadog", "Prometheus", "Grafana", "Sentry",
    "Okta", "Auth0", "Vault", "CyberArk",
]


class SocialMediaModule(BaseOSINTModule):
    """Comprehensive social media OSINT - GitHub, Twitter, LinkedIn, Instagram, GHunt."""
    NAME  = "socialMedia"
    LABEL = "Social Media OSINT"
    ICON  = "📱"
    ORDER = 65
    TARGET_TYPES: list = ['username', 'domain', 'email', 'string']

    def run(self, scan_id: str, target: str, config: dict) -> None:
        target_type = self._target_type or config.get("target_type", "domain")
        gh_token    = config.get("github_token", "")

        if target_type == "username":
            username = target.strip().lstrip("@")
            _log(f"[{self.LABEL}] Username mode: '{username}'")
            self._run_username_mode(scan_id, username, gh_token)
            return

        # ── Domain / org / string mode (original behaviour) ───────────────
        domain   = _extract_domain(target)
        org      = domain.split(".")[0]

        _log(f"[{self.LABEL}] Social media intelligence for {org} / {domain}")

        gh_hdrs = {"Accept": "application/vnd.github+json"}
        if gh_token:
            gh_hdrs["Authorization"] = f"Bearer {gh_token}"

        self.emit_task(scan_id, "GitHub organisation deep dive", detail=f"org: {org}")
        self._github_org(scan_id, org, gh_hdrs)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Twitter/X public profile search",
                       detail="via Nitter public instances")
        self._twitter_search(scan_id, org, domain)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "LinkedIn company + job post intelligence")
        self._linkedin(scan_id, org, domain)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Instagram public presence")
        self._instagram(scan_id, org)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Reddit brand/org presence")
        self._reddit(scan_id, org, domain)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "YouTube channel search")
        self._youtube(scan_id, org, domain)

        if self.should_skip(scan_id): return

        self.emit_task(scan_id, "Job post tech stack reverse-engineering",
                       detail="DuckDuckGo → extract technologies from job ads")
        self._job_post_intel(scan_id, org, domain)

        _log(f"[{self.LABEL}] Social media intelligence complete for {org}")

    # ── Username mode ─────────────────────────────────────────────────────────

    def _run_username_mode(self, scan_id: str, username: str, gh_token: str) -> None:
        """
        Search for a username across all major social platforms.
        Strategy per platform:
          1. Direct API / profile URL check (reliable where possible)
          2. DuckDuckGo 'site:platform.com/username' fallback (catches
             platforms that block direct scraping - Instagram, Facebook, etc.)
        """
        gh_hdrs = {"Accept": "application/vnd.github+json"}
        if gh_token:
            gh_hdrs["Authorization"] = f"Bearer {gh_token}"

        platforms = [
            # (label, direct_url, site_dork, profile_url_fmt)
            ("GitHub",    f"https://api.github.com/users/{quote(username)}",
             f"site:github.com/{username}",
             f"https://github.com/{username}"),
            ("Twitter/X", f"https://nitter.net/{username}",
             f"site:twitter.com/{username} OR site:x.com/{username}",
             f"https://twitter.com/{username}"),
            ("Instagram", f"https://www.instagram.com/{username}/",
             f"site:instagram.com/{username}",
             f"https://www.instagram.com/{username}/"),
            ("Reddit",    f"https://www.reddit.com/user/{username}/about.json",
             f"site:reddit.com/user/{username}",
             f"https://reddit.com/user/{username}"),
            ("LinkedIn",  None,
             f"site:linkedin.com/in/{username}",
             f"https://linkedin.com/in/{username}"),
            ("Facebook",  None,
             f"site:facebook.com/{username}",
             f"https://facebook.com/{username}"),
            ("YouTube",   None,
             f"site:youtube.com/@{username} OR site:youtube.com/user/{username}",
             f"https://youtube.com/@{username}"),
            ("TikTok",    None,
             f"site:tiktok.com/@{username}",
             f"https://tiktok.com/@{username}"),
            ("Pinterest", None,
             f"site:pinterest.com/{username}",
             f"https://pinterest.com/{username}"),
            ("Keybase",   f"https://keybase.io/{username}",
             f"site:keybase.io/{username}",
             f"https://keybase.io/{username}"),
        ]

        found_platforms: list[str] = []

        for label, direct_url, dork, profile_url in platforms:
            if self.should_skip(scan_id):
                break
            self.emit_task(scan_id, f"Checking {label}: @{username}")
            confirmed = False
            evidence  = ""
            found_url = profile_url

            # ── 1. Direct API / profile fetch ─────────────────────────────
            if direct_url:
                confirmed, evidence = self._direct_check(
                    scan_id, username, label, direct_url, gh_hdrs)

            # ── 2. DuckDuckGo fallback ────────────────────────────────────
            if not confirmed:
                confirmed, evidence, found_url = self._ddg_check(
                    scan_id, username, label, dork, profile_url)

            if confirmed:
                found_platforms.append(label)
                sev = "medium" if label in ("GitHub","LinkedIn") else "info"
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"📱 {label}: @{username} profile found",
                    f"Username '{username}' confirmed on {label}.",
                    url=found_url,
                    evidence=evidence or f"Profile URL: {found_url}",
                    tags=["social", label.lower().replace("/","").replace(" ",""),
                          "username", "presence"],
                )

        # GitHub deep-dive (API gives much more data)
        if self.should_skip(scan_id): return
        self.emit_task(scan_id, f"GitHub deep-dive: @{username}")
        self._github_org(scan_id, username, gh_hdrs)

        if found_platforms:
            _log(f"[{self.LABEL}] Found '{username}' on: {', '.join(found_platforms)}")
        else:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"📱 No Social Profiles Found for @{username}",
                f"Checked GitHub, Twitter/X, Instagram, Reddit, LinkedIn, Facebook, "
                f"YouTube, TikTok, Pinterest, and Keybase - no confirmed profiles.",
                tags=["social", "username", "not-found"]
            )

    def _direct_check(self, scan_id: str, username: str, label: str,
                      url: str, gh_hdrs: dict) -> tuple[bool, str]:
        """Try a direct HTTP/API check. Returns (confirmed, evidence)."""
        try:
            hdrs = gh_hdrs if "api.github.com" in url else {}
            ua   = "Mozilla/5.0 (compatible; FEROXSEI-OSINT)"
            r    = self.http.get(url, scan_id, self.NAME,
                                 headers={**hdrs, "User-Agent": ua},
                                 add_delay=False, timeout=10)
            if not r or r.status_code not in (200, 301, 302):
                return False, ""

            body = (r.text or "").lower()

            # GitHub JSON API
            if "api.github.com" in url and r.status_code == 200:
                try:
                    d = r.json()
                    if d.get("login"):
                        return True, (
                            f"Login:     {d.get('login','')}\n"
                            f"Name:      {d.get('name','')}\n"
                            f"Bio:       {(d.get('bio','') or '')[:200]}\n"
                            f"Repos:     {d.get('public_repos',0)}\n"
                            f"Followers: {d.get('followers',0)}\n"
                            f"Profile:   {d.get('html_url','')}"
                        )
                except Exception:
                    pass
                return False, ""

            # Reddit JSON API
            if "reddit.com/user/" in url and r.status_code == 200:
                try:
                    d = r.json().get("data", {})
                    if d.get("name"):
                        return True, (
                            f"Name:    {d.get('name','')}\n"
                            f"Karma:   {d.get('link_karma',0) + d.get('comment_karma',0)}\n"
                            f"Created: {d.get('created_utc','')}"
                        )
                except Exception:
                    pass
                return False, ""

            # Keybase / Nitter / Instagram - check username in body
            NOT_FOUND = ("this page isn't available", "not found", "does not exist",
                         "no user", "account suspended", "something went wrong",
                         "404", "page not found")
            if any(p in body for p in NOT_FOUND):
                return False, ""
            if username.lower() in body:
                return True, f"Direct profile page confirmed username in body.\nURL: {url}"

        except Exception as exc:
            _log(f"[{self.LABEL}] {label} direct check error: {exc}")
        return False, ""

    def _ddg_check(self, scan_id: str, username: str, label: str,
                   dork: str, fallback_url: str) -> tuple[bool, str, str]:
        """
        DuckDuckGo search fallback. Returns (confirmed, evidence, confirmed_url).
        A result is confirmed if the exact username appears in the result URL.
        """
        import re as _re
        try:
            search_url = f"https://html.duckduckgo.com/html/?q={quote(dork)}"
            r = self.http.get(search_url, scan_id, self.NAME,
                              headers={"User-Agent":
                                       "Mozilla/5.0 (compatible; FEROXSEI-OSINT)"},
                              add_delay=True, timeout=12)
            if not r or r.status_code != 200:
                return False, "", fallback_url

            try:
                from bs4 import BeautifulSoup as _BS
                soup    = _BS(r.text, "html.parser")
                results = soup.select(".result__body")[:8]
            except ImportError:
                # Fallback: regex URL extraction
                results = []
                hits    = _re.findall(r'class="result__url"[^>]*>([^<]+)<', r.text)
                for h in hits[:5]:
                    url_clean = _re.sub(r'\s+', '', h).lower()
                    if username.lower() in url_clean:
                        return True, f"DuckDuckGo: {label} result URL confirmed username.\nURL: {h.strip()}", h.strip()
                return False, "", fallback_url

            for res in results:
                url_el   = res.select_one(".result__url")
                title_el = res.select_one(".result__title")
                snip_el  = res.select_one(".result__snippet")
                url_text = _re.sub(r'\s+', '', (url_el.get_text() if url_el else ""))
                if username.lower() in url_text.lower():
                    title = title_el.get_text(strip=True)[:120] if title_el else ""
                    snip  = snip_el.get_text(strip=True)[:200]  if snip_el else ""
                    # Normalise to https://
                    found_url = url_text if url_text.startswith("http") else "https://" + url_text
                    return True, (
                        f"DuckDuckGo confirmed {label} profile.\n"
                        f"URL:     {found_url}\n"
                        f"Title:   {title}\n"
                        f"Snippet: {snip}"
                    ), found_url

        except Exception as exc:
            _log(f"[{self.LABEL}] {label} DDG check error: {exc}")
        return False, "", fallback_url

    def _github_org(self, scan_id: str, org: str, hdrs: dict) -> None:
        r = self.http.get(f"https://api.github.com/orgs/{org}",
                          scan_id, self.NAME, headers=hdrs)
        if not (r and r.status_code == 200):
            r = self.http.get(f"https://api.github.com/users/{org}",
                              scan_id, self.NAME, headers=hdrs)
        if not (r and r.status_code == 200):
            return

        data = r.json()
        name = data.get("name") or org
        self.db.save_finding(
            scan_id, self.NAME, "info",
            f"GitHub: {name} ({data.get('type','Org')})",
            f"GitHub presence confirmed for '{org}'.",
            url=data.get("html_url", ""),
            evidence=(f"Name: {name}\n"
                      f"Bio: {data.get('bio','') or data.get('description','')}\n"
                      f"Public repos: {data.get('public_repos', 0)}\n"
                      f"Followers: {data.get('followers', 0)}\n"
                      f"Members (public): {data.get('public_members_url','')}\n"
                      f"Blog: {data.get('blog','')}\n"
                      f"Email: {data.get('email','')}\n"
                      f"Location: {data.get('location','')}"),
            tags=["github", "org", "social"],
            raw_data=data
        )

        r2 = self.http.get(
            f"https://api.github.com/orgs/{org}/repos?per_page=50&sort=updated&type=public",
            scan_id, self.NAME, headers=hdrs)
        if not (r2 and r2.status_code == 200):
            r2 = self.http.get(
                f"https://api.github.com/users/{org}/repos?per_page=50&sort=updated",
                scan_id, self.NAME, headers=hdrs)

        if r2 and r2.status_code == 200:
            repos = r2.json()
            langs: dict[str, int] = {}
            topics_all: list[str] = []
            for repo in repos:
                lang = repo.get("language")
                if lang:
                    langs[lang] = langs.get(lang, 0) + 1
                topics_all.extend(repo.get("topics", []))

            if repos:
                sorted_langs = sorted(langs.items(), key=lambda x: -x[1])
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"GitHub Tech Stack: {org} uses {', '.join(l for l, _ in sorted_langs[:5])}",
                    f"Language distribution inferred from {len(repos)} public repos.",
                    evidence=(f"Languages: {dict(sorted_langs[:10])}\n"
                              f"Common topics: {', '.join(list(set(topics_all))[:20])}\n"
                              f"Repos analysed: {len(repos)}"),
                    tags=["github", "tech-stack", "recon"],
                    raw_data={"languages": dict(sorted_langs), "topics": list(set(topics_all))}
                )

            secret_repos = [r for r in repos if any(
                kw in (r.get("name","") + r.get("description","")).lower()
                for kw in ("secret","config","internal","private","infra","k8s","helm","deploy")
            )]
            if secret_repos:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"⚠️ GitHub: {len(secret_repos)} Potentially Sensitive Repo Name(s)",
                    "Public repos with names suggesting internal/infra/config content.",
                    evidence="\n".join(
                        f"{r.get('full_name','')} - {r.get('description','')}"
                        for r in secret_repos[:10]
                    ),
                    tags=["github", "sensitive", "config", "exposure"]
                )

        r3 = self.http.get(
            f"https://api.github.com/orgs/{org}/members?per_page=30",
            scan_id, self.NAME, headers=hdrs)
        if r3 and r3.status_code == 200:
            members = r3.json()
            if members:
                logins = [m.get("login","") for m in members]
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"GitHub Members: {len(members)} Public Employee(s) for {org}",
                    "Public GitHub org members - potential targets for phishing or credential attacks.",
                    evidence="\n".join(f"  @{l}" for l in logins[:30]),
                    tags=["github", "members", "employees", "recon"],
                    raw_data={"members": logins}
                )

        r4 = self.http.get(
            f"https://api.github.com/search/commits?q=org:{org}&per_page=20&sort=author-date",
            scan_id, self.NAME, headers={**hdrs, "Accept": "application/vnd.github.cloak-preview+json"})
        if r4 and r4.status_code == 200:
            emails_found: set[str] = set()
            try:
                for item in r4.json().get("items", []):
                    commit = item.get("commit", {})
                    for role in ("author", "committer"):
                        em = commit.get(role, {}).get("email", "")
                        if em and "noreply" not in em and "@" in em:
                            emails_found.add(em.lower())
            except Exception:
                pass
            if emails_found:
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"GitHub Commit Emails: {len(emails_found)} Developer Email(s) Exposed",
                    "Real developer emails leaked via public commit metadata.",
                    evidence="\n".join(sorted(emails_found)[:30]),
                    tags=["github", "email", "developer", "exposure"],
                    raw_data={"emails": list(emails_found)}
                )

    def _twitter_search(self, scan_id: str, org: str, domain: str) -> None:
        for base in _NITTER_INSTANCES:
            if self.should_skip(scan_id):
                return
            r = self.http.get(f"{base}/{org}",
                              scan_id, self.NAME, add_delay=False, timeout=8)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if "profile-card" not in body.lower() and "tweet-content" not in body.lower():
                continue

            name_m   = re.search(r'class="profile-card-fullname"[^>]*>([^<]+)<', body)
            bio_m    = re.search(r'class="profile-bio"[^>]*>([^<]+)<', body)
            stats_m  = re.findall(r'class="profile-stat-num"[^>]*>([^<]+)<', body)
            verified = "icon-ok-circled" in body

            name = name_m.group(1).strip() if name_m else org
            bio  = bio_m.group(1).strip() if bio_m else ""
            followers = stats_m[1] if len(stats_m) > 1 else "?"
            tweets    = stats_m[0] if stats_m else "?"

            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"Twitter/X: @{org} - {followers} followers",
                f"Twitter profile found for @{org}.",
                url=f"https://twitter.com/{org}",
                evidence=(f"Name: {name}\n"
                          f"Bio: {bio}\n"
                          f"Tweets: {tweets}\n"
                          f"Followers: {followers}\n"
                          f"Verified: {verified}\n"
                          f"Source: {base}"),
                tags=["twitter", "social", "presence", "recon"]
            )

            recent_tweets = re.findall(r'class="tweet-content[^"]*"[^>]*>([^<]{10,280})<', body)
            if recent_tweets:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"Twitter Recent Activity: @{org} - {len(recent_tweets)} Visible Tweets",
                    "Recent tweet content from public timeline.",
                    evidence="\n\n".join(f"• {t[:200]}" for t in recent_tweets[:10]),
                    tags=["twitter", "content", "social"]
                )
            return

    def _linkedin(self, scan_id: str, org: str, domain: str) -> None:
        li_url = f"https://www.linkedin.com/company/{org}"
        r = self.http.get(li_url, scan_id, self.NAME, add_delay=False, timeout=10)
        if r and r.status_code == 200 and "linkedin" in r.url:
            body = r.text or ""
            employees_m = re.search(r'([\d,]+)\s+employee', body, re.I)
            employees   = employees_m.group(1) if employees_m else "?"
            industry_m  = re.search(r'"industry":"([^"]+)"', body)
            industry    = industry_m.group(1) if industry_m else ""
            desc_m      = re.search(r'"description":"([^"]{20,500})"', body)
            desc        = desc_m.group(1) if desc_m else ""

            self.db.save_finding(
                scan_id, self.NAME, "info",
                f"LinkedIn: {org} - {employees} employees",
                f"LinkedIn company page found for '{org}'.",
                url=li_url,
                evidence=(f"Company: {org}\n"
                          f"Employees: {employees}\n"
                          f"Industry: {industry}\n"
                          f"Description: {desc[:300]}"),
                tags=["linkedin", "social", "corporate", "recon"]
            )

        for q in [f'site:linkedin.com/in "{org}"', f'site:linkedin.com/in "@{domain}"']:
            if self.should_skip(scan_id):
                break
            dq_url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
            r2 = self.http.get(dq_url, scan_id, self.NAME, add_delay=True, timeout=10)
            if not r2 or r2.status_code != 200:
                continue
            profiles = re.findall(r'linkedin\.com/in/([\w\-]+)', r2.text)
            if profiles:
                self.db.save_finding(
                    scan_id, self.NAME, "medium",
                    f"LinkedIn Employees: {len(set(profiles))} Profile(s) Found for {org}",
                    "LinkedIn employee profiles discovered via search engine.",
                    evidence="\n".join(
                        f"  https://linkedin.com/in/{p}" for p in list(set(profiles))[:20]
                    ),
                    tags=["linkedin", "employees", "recon", "social"]
                )
                break

    def _instagram(self, scan_id: str, org: str) -> None:
        r = self.http.get(f"https://www.instagram.com/{org}/?__a=1&__d=dis",
                          scan_id, self.NAME, add_delay=False, timeout=8)
        found = False
        if r and r.status_code == 200:
            try:
                data   = r.json()
                user   = data.get("graphql", {}).get("user") or data.get("data", {}).get("user", {})
                if user:
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"Instagram: @{org} - {user.get('edge_followed_by',{}).get('count','?')} followers",
                        "Instagram public profile found.",
                        url=f"https://www.instagram.com/{org}/",
                        evidence=(f"Full name: {user.get('full_name','')}\n"
                                  f"Bio: {user.get('biography','')[:200]}\n"
                                  f"Followers: {user.get('edge_followed_by',{}).get('count','?')}\n"
                                  f"Posts: {user.get('edge_owner_to_timeline_media',{}).get('count','?')}\n"
                                  f"Verified: {user.get('is_verified', False)}\n"
                                  f"Business: {user.get('is_business_account', False)}\n"
                                  f"Category: {user.get('category_name','')}"),
                        tags=["instagram", "social", "presence"]
                    )
                    found = True
            except Exception:
                pass

        if not found:
            r2 = self.http.get(f"https://www.instagram.com/{org}/",
                               scan_id, self.NAME, add_delay=False, timeout=8)
            if r2 and r2.status_code == 200 and '"username"' in (r2.text or ""):
                bio_m = re.search(r'"biography":"([^"]{3,300})"', r2.text)
                fol_m = re.search(r'"edge_followed_by":\{"count":(\d+)', r2.text)
                name_m = re.search(r'"full_name":"([^"]+)"', r2.text)
                if name_m or fol_m:
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"Instagram: @{org} - {fol_m.group(1) if fol_m else '?'} followers",
                        "Instagram public profile found via page scrape.",
                        url=f"https://www.instagram.com/{org}/",
                        evidence=(f"Name: {name_m.group(1) if name_m else ''}\n"
                                  f"Followers: {fol_m.group(1) if fol_m else '?'}\n"
                                  f"Bio: {bio_m.group(1) if bio_m else ''}"),
                        tags=["instagram", "social", "presence"]
                    )

    def _reddit(self, scan_id: str, org: str, domain: str) -> None:
        for target in (f"r/{org}", f"u/{org}"):
            r = self.http.get(
                f"https://www.reddit.com/{target}/about.json",
                scan_id, self.NAME, add_delay=False, timeout=8,
                headers={"User-Agent": "FEROXSEI-OSINT/1.0"})
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json().get("data", {})
                if not data:
                    continue
                kind = "Subreddit" if target.startswith("r/") else "User"
                subs = data.get("subscribers") or data.get("comment_karma")
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"Reddit {kind}: {target} - {subs} {'subscribers' if kind=='Subreddit' else 'karma'}",
                    f"Reddit {kind.lower()} presence confirmed.",
                    url=f"https://reddit.com/{target}",
                    evidence=(f"Name: {data.get('display_name','') or data.get('name','')}\n"
                              f"Title: {data.get('title','') or data.get('subreddit','')}\n"
                              f"Description: {(data.get('public_description','') or data.get('subreddit',''))[:200]}\n"
                              f"{'Subscribers' if kind=='Subreddit' else 'Karma'}: {subs}"),
                    tags=["reddit", "social", "community", "recon"]
                )
            except Exception:
                pass

    def _youtube(self, scan_id: str, org: str, domain: str) -> None:
        search_url = (f"https://www.youtube.com/results?search_query={quote(org)}"
                      f"&sp=EgIQAg%253D%253D")
        r = self.http.get(search_url, scan_id, self.NAME, add_delay=False, timeout=10)
        if not r or r.status_code != 200:
            return
        body = r.text or ""
        channels = re.findall(r'"channelId":"([^"]+)".*?"title":\{"runs":\[\{"text":"([^"]+)"', body)
        if channels:
            for cid, cname in channels[:3]:
                if org.lower() in cname.lower() or cname.lower() in org.lower():
                    self.db.save_finding(
                        scan_id, self.NAME, "info",
                        f"YouTube Channel: {cname}",
                        "YouTube channel presence found for the organisation.",
                        url=f"https://www.youtube.com/channel/{cid}",
                        evidence=f"Channel ID: {cid}\nChannel name: {cname}",
                        tags=["youtube", "social", "presence"]
                    )

    def _job_post_intel(self, scan_id: str, org: str, domain: str) -> None:
        queries = [
            f'site:linkedin.com/jobs "{org}" engineer developer',
            f'site:indeed.com "{org}" "{domain}"',
            f'"{org}" jobs "we use" OR "our stack" OR "tech stack"',
        ]
        detected_techs: set[str] = set()
        for q in queries:
            if self.should_skip(scan_id):
                break
            r = self.http.get(
                f"https://html.duckduckgo.com/html/?q={quote(q)}",
                scan_id, self.NAME, add_delay=True, timeout=10)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            for tech in _TECH_IN_JOB_POSTS:
                if re.search(r'\b' + re.escape(tech) + r'\b', body, re.I):
                    detected_techs.add(tech)

        if detected_techs:
            self.db.save_finding(
                scan_id, self.NAME, "medium",
                f"Tech Stack from Job Posts: {len(detected_techs)} Technology/ies Identified",
                f"Technologies inferred from {org}'s job postings - reveals attack surface.",
                evidence="Detected technologies:\n" + "\n".join(f"  • {t}" for t in sorted(detected_techs)),
                tags=["job-posts", "tech-stack", "recon", "social"],
                raw_data={"technologies": sorted(detected_techs)}
            )
