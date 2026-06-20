"""FEROXSEI OSINT - Git Leaks module."""
from __future__ import annotations
import json
import time
from urllib.parse import quote

from .base import BaseOSINTModule, _log, _extract_domain


class GitLeaksModule(BaseOSINTModule):
    """GitHub API search + exposed .git directory detection."""
    NAME  = "gitLeaks"
    LABEL = "Git Leaks"
    ICON  = "🔓"
    ORDER = 30
    TARGET_TYPES: list = ['domain', 'string']

    DORKS = [
        'filename:.env "{domain}"',
        'filename:config.php "{domain}"',
        'filename:.npmrc "{domain}"',
        'filename:credentials "{domain}"',
        'filename:secrets.yml "{domain}"',
        'filename:docker-compose.yml "{domain}"',
        '"{domain}" password OR secret OR api_key',
        '"{domain}" DB_PASSWORD OR DATABASE_URL',
        'org:{org} filename:.env',
        'org:{org} filename:secrets',
    ]

    def run(self, scan_id, target, config):
        domain   = _extract_domain(target)
        org      = domain.split(".")[0]
        gh_token = config.get("github_token","")
        _log(f"[{self.LABEL}] Checking {domain} for git leaks")

        headers = {"Accept": "application/vnd.github.v3+json"}
        if gh_token:
            headers["Authorization"] = f"token {gh_token}"

        if target.startswith("http"):
            base = target
        else:
            _probe = self.http.get(f"https://{target}", scan_id, self.NAME, add_delay=False)
            base = f"https://{target}" if (_probe and _probe.status_code in (200,301,302,403)) else f"http://{target}"

        # Check exposed .git directory
        self._check_exposed_git(scan_id, base)

        # GitHub code search
        if gh_token:
            for dork_tmpl in self.DORKS:
                dork = dork_tmpl.replace("{domain}", domain).replace("{org}", org)
                self._github_search(scan_id, dork, headers)
                time.sleep(1.5)

        # Check common git-exposed files
        git_files = [
            "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
            "/.gitignore", "/.git-credentials", "/.gitlab-ci.yml",
            "/.github/workflows/", "/Makefile", "/Dockerfile",
        ]
        for gf in git_files:
            url = base.rstrip("/") + gf
            r = self.http.get(url, scan_id, self.NAME, add_delay=False,
                              allow_redirects=False)
            if r and r.status_code == 200:
                sev = "critical" if ".git/config" in gf or "credentials" in gf else "medium"
                hits = self.patterns.scan_text(r.text, url)
                self.db.save_finding(
                    scan_id, self.NAME, sev,
                    f"Exposed Git File: {gf}",
                    f"Git file accessible at {url}",
                    url=url, evidence=r.text[:500],
                    tags=["git","exposure","critical"]
                )
                for hit in hits:
                    self.db.save_finding(
                        scan_id, self.NAME, hit["severity"],
                        f"Git Leak Pattern: {hit['pattern_name']}",
                        f"Pattern '{hit['pattern_name']}' found in exposed git file",
                        url=url, evidence=hit["evidence"],
                        pattern_id=hit["pattern_id"],
                        tags=["git","pattern","leak"]
                    )

        _log(f"[{self.LABEL}] Done")

    def _check_exposed_git(self, scan_id, target):
        base = target if target.startswith("http") else f"http://{target}"
        url  = base.rstrip("/") + "/.git/HEAD"
        r = self.http.get(url, scan_id, self.NAME, add_delay=False,
                          allow_redirects=False)
        if r and r.status_code == 200 and "ref:" in r.text:
            self.db.save_finding(
                scan_id, self.NAME, "critical",
                "⚠️ CRITICAL: Exposed .git Repository",
                f".git directory is publicly accessible at {base}/.git/\n"
                f"Entire source code and commit history may be downloadable!",
                url=url, evidence=r.text[:200],
                tags=["git","exposure","critical","source-code"]
            )

    def _github_search(self, scan_id, query, headers):
        url = f"https://api.github.com/search/code?q={quote(query)}&per_page=5"
        r = self.http.get(url, scan_id, self.NAME, headers=headers)
        if not r or r.status_code != 200:
            return
        try:
            data  = r.json()
            items = data.get("items", [])
            for item in items:
                repo  = item.get("repository",{}).get("full_name","")
                fpath = item.get("path","")
                furl  = item.get("html_url","")
                self.db.save_finding(
                    scan_id, self.NAME, "high",
                    f"GitHub Code Match: {fpath}",
                    f"Target-related code found in {repo}: {fpath}\nQuery: {query}",
                    url=furl, evidence=json.dumps(item.get("text_matches",[])),
                    tags=["github","code-search","leak"]
                )
        except Exception:
            pass
