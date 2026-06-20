"""FEROXSEI OSINT - AI Analysis module.

Three-phase approach:
  Phase 1 - Directed clearnet OSINT research (AI generates queries → module executes)
  Phase 2 - Dark web research: clearnet indexes always; .onion engines + fetch only when TOR on
  Phase 3 - Synthesis: correlate Phase 1+2 results + existing findings → comprehensive report

Target-type aware throughout: domain / username / email / phone / ip / string each
get their own research focus and analysis lens.
"""
from __future__ import annotations
import json
import re
import time

from urllib.parse import quote

from .base import BaseOSINTModule, _log

# ── Dark web search engines (clearnet only for Phase 2 without TOR) ──────────
_DW_ENGINES_CLEARNET = [
    ("Ahmia",      "https://ahmia.fi/search/?q={q}"),
    ("DarkSearch", "https://darksearch.io/api/search?query={q}&page=1"),
    ("OnionLand",  "https://onionlandsearchengine.com/search?q={q}"),
]
_DW_ENGINES_ONION = [
    ("Ahmia.onion",
     "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}"),
    ("Haystack.onion",
     "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}"),
    ("Torch.onion",
     "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/?q={q}&action=search"),
]

_ONION_URL_RE = re.compile(r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*', re.I)
_EMAIL_RE     = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def _extract_json(text: str) -> dict:
    """Extract and parse the first JSON object from an AI response."""
    if not text:
        raise ValueError("Empty response")
    fence = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', text, re.I)
    if fence:
        return json.loads(fence.group(1))
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found")
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("Unbalanced braces")


def _visible_text(html: str, max_chars: int = 1000) -> str:
    text = re.sub(r'<[^>]+>', ' ', html)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:max_chars]


class AIAnalysisModule(BaseOSINTModule):
    """
    Claude/GPT-powered OSINT analysis with active clearnet + dark web research.

    Phase 1 - Directed clearnet research:
        AI generates OSINT-specific search queries for the target type.
        Module executes them via DDG/Bing and returns results.

    Phase 2 - Dark web research:
        Clearnet dark web indexes (Ahmia, DarkSearch) always run.
        .onion search engines + page fetching only when TOR is on.

    Phase 3 - Synthesis:
        AI receives: existing findings + Phase 1 results + Phase 2 dark web hits.
        Returns: executive summary, risks, correlations, suggested queries, new patterns.
    """
    NAME  = "aiOsint"
    LABEL = "AI Analysis"
    ICON  = "🤖"
    ORDER = 90
    TARGET_TYPES: list = ['domain', 'username', 'email', 'phone', 'ip', 'string']

    # ── System prompt (type-aware, injected with target_type) ────────────────
    _RESEARCH_SYSTEM = """You are FEROXSEI AI, an elite OSINT analyst performing active intelligence research.
Given a target and target type, produce a JSON object with:
{
  "clearnet_queries": ["query1", "query2", ...],   // 5-8 targeted search queries for clearnet OSINT
  "darkweb_queries":  ["query1", "query2", ...],   // 3-5 targeted queries for dark web search indexes
  "focus_notes": "Brief note on what to look for given this target type"
}

Guidelines per target type:
- domain:   subdomains, exposed files, tech stack, breaches, leaked credentials, GitHub mentions
- username:  social profiles, forum posts, breaches, leaked databases, pastebin, dark web mentions
- email:     breach databases, leaked credentials, associated accounts, haveibeenpwned, phishing
- phone:     spam reports, carrier info, reverse lookup, leaked databases, fraud forums
- ip:        geolocation, ASN, abuse reports, CVE exploits, botnet membership, dark web forums
- string:    data breach dumps, paste sites, dark web markets, Telegram leaks, GitHub secrets

Respond ONLY with valid JSON (no markdown, no prose)."""

    _SYNTHESIS_SYSTEM = """You are FEROXSEI AI, an elite OSINT analyst. Synthesize intelligence from multiple sources:
- Existing module findings (DNS, crawler, email harvest, etc.)
- Clearnet research results (search engine results for targeted queries)
- Dark web intelligence (search results from dark web indexes)

Produce a comprehensive JSON report:
{
  "executive_summary": "3-5 sentence summary of what was found and what it means",
  "critical_risks":    ["risk1", "risk2"],
  "correlations":      ["correlation1", "correlation2"],
  "clearnet_findings": ["notable finding from clearnet research"],
  "darkweb_findings":  ["notable finding from dark web research"],
  "suggested_queries": ["follow-up query 1", "follow-up query 2", "follow-up query 3"],
  "new_patterns": [
    {"name": "...", "pattern": "regex...", "category": "...", "severity": "...", "description": "..."}
  ],
  "attack_surface_score": 0
}

Be precise. Only report what evidence supports. Score 0-100."""

    # ─────────────────────────────────────────────────────────────────────────

    def run(self, scan_id, target, config):
        from feroxsei_osint import _get_setting
        anthropic_key = (config.get("anthropic_key", "") or _get_setting("anthropic_key", "")).strip()
        openai_key    = (config.get("openai_key",    "") or _get_setting("openai_key",    "")).strip()
        api_key       = anthropic_key or openai_key

        if not api_key:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                "🤖 AI Analysis: API Key Required",
                "No Anthropic or OpenAI API key found.\n"
                "Go to Settings → API Keys and add your key, then re-run the scan.",
                tags=["ai", "setup"]
            )
            return

        target_type = self._target_type or config.get("target_type", "domain")
        tor_on      = self.http.use_tor
        _log(f"[{self.LABEL}] target_type={target_type} | TOR={'ON' if tor_on else 'OFF'}")

        if tor_on:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                "⚠️ AI Analysis: TOR Mode Active - Synthesis May Fail",
                "Anonymous Mode (TOR) is currently enabled. AI API providers "
                "(Anthropic, OpenAI) block requests from TOR exit nodes, so the "
                "synthesis phase may fail.\n\n"
                "To get a full AI report:\n"
                "1. Disable Anonymous Mode using the TOR badge in the header\n"
                "2. Re-run this scan\n\n"
                "Phase 1 (research queries) and Phase 2 (dark web) will still run below.",
                tags=["ai", "tor", "warning"]
            )

        # ── Phase 1: AI-directed clearnet research ────────────────────────────
        self.emit_task(scan_id, "Phase 1: Generating targeted OSINT research queries",
                       detail=f"target_type={target_type}")

        research_prompt = (
            f"Target type: {target_type}\n"
            f"Target: {target}\n\n"
            f"Generate precise OSINT queries for this {target_type} target."
        )
        queries_json = self._call_ai(
            scan_id, anthropic_key, openai_key,
            self._RESEARCH_SYSTEM, research_prompt,
            max_tokens=800, label="query generation"
        )

        clearnet_queries = []
        darkweb_queries  = []
        if queries_json:
            clearnet_queries = queries_json.get("clearnet_queries", [])[:8]
            darkweb_queries  = queries_json.get("darkweb_queries",  [])[:5]
            focus_note       = queries_json.get("focus_notes", "")
            _log(f"[{self.LABEL}] AI generated {len(clearnet_queries)} clearnet + "
                 f"{len(darkweb_queries)} darkweb queries")
            if focus_note:
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"🤖 AI Research Strategy for {target_type.upper()}: {target[:60]}",
                    focus_note,
                    tags=["ai", "strategy", target_type]
                )

        # Execute clearnet queries
        clearnet_results: list[dict] = []
        if clearnet_queries:
            self.emit_task(scan_id, "Phase 1: Executing clearnet OSINT searches",
                           detail=f"{len(clearnet_queries)} queries via DDG + Bing")
            for q in clearnet_queries:
                if self.should_skip(scan_id):
                    break
                result = self._clearnet_search(scan_id, q)
                if result:
                    clearnet_results.append({"query": q, "result": result})

        _log(f"[{self.LABEL}] Phase 1 done - {len(clearnet_results)} clearnet results")

        if self.should_skip(scan_id):
            return

        # ── Phase 2: Dark web research ────────────────────────────────────────
        # Clearnet dark web indexes (Ahmia.fi etc.) always run.
        # .onion search engines + content fetch only when TOR is ON.
        self.emit_task(
            scan_id, "Phase 2: Dark web research",
            detail=f"TOR={'ON - .onion engines included' if tor_on else 'OFF - clearnet DW indexes only'}"
        )

        dw_results: list[dict] = []
        dw_queries = darkweb_queries or [target, f'"{target}"']   # fallback if AI query failed

        _DW_ERROR_PHRASES = [
            "not deployd non-javascript", "no-javascript version",
            "enable javascript", "javascript is required",
            "unfortunately we have not", "no results found",
            "did not match any documents",
        ]

        def _is_empty_dw_page(body_text: str) -> bool:
            low = body_text.lower()
            return any(ph in low for ph in _DW_ERROR_PHRASES)

        # Clearnet dark web indexes (always)
        for q in dw_queries[:4]:
            if self.should_skip(scan_id):
                break
            for eng_name, url_tpl in _DW_ENGINES_CLEARNET:
                r = self.http.get(
                    url_tpl.format(q=quote(q)),
                    scan_id, self.NAME, add_delay=False, timeout=15
                )
                if not r or r.status_code != 200:
                    continue
                body = r.text or ""
                if _is_empty_dw_page(body):
                    continue
                onion_urls = _ONION_URL_RE.findall(body)[:10]
                snippet    = _visible_text(body, 500)
                if onion_urls or target.lower() in body.lower():
                    dw_results.append({
                        "engine":    eng_name,
                        "query":     q,
                        "onion_urls": onion_urls,
                        "snippet":   snippet[:300],
                    })

        # .onion search engines + content fetch (TOR only)
        if tor_on:
            self.emit_task(scan_id, "Phase 2: Searching .onion engines via TOR",
                           detail=f"{len(_DW_ENGINES_ONION)} engines × {len(dw_queries[:3])} queries")
            for q in dw_queries[:3]:
                if self.should_skip(scan_id):
                    break
                for eng_name, url_tpl in _DW_ENGINES_ONION:
                    r = self.http.get(
                        url_tpl.format(q=quote(q)),
                        scan_id, self.NAME, add_delay=True, timeout=35
                    )
                    if not r or r.status_code != 200:
                        continue
                    body      = r.text or ""
                    onion_urls = _ONION_URL_RE.findall(body)[:10]
                    snippet    = _visible_text(body, 400)
                    if onion_urls or target.lower() in body.lower():
                        dw_results.append({
                            "engine":    eng_name,
                            "query":     q,
                            "onion_urls": onion_urls,
                            "snippet":   snippet[:300],
                        })

            # Fetch top discovered .onion pages for content
            seen_onions: set[str] = set()
            for r_item in dw_results:
                for onion_url in r_item.get("onion_urls", [])[:2]:
                    if onion_url in seen_onions:
                        continue
                    seen_onions.add(onion_url)
                    if self.should_skip(scan_id):
                        break
                    self.emit_task(scan_id, f"Fetching .onion: {onion_url[:55]}…")
                    page_r = self.http.get(onion_url, scan_id, self.NAME,
                                           add_delay=True, timeout=35)
                    if page_r and page_r.status_code == 200 and page_r.text:
                        body = page_r.text[:20000]
                        text = _visible_text(body, 1500)
                        if target.lower() in text.lower():
                            emails = _EMAIL_RE.findall(body)[:5]
                            self.db.save_finding(
                                scan_id, self.NAME, "high",
                                f"🕳️ AI Dark Web: .onion Page References '{target[:50]}'",
                                f"Fetched .onion page contains references to the target.",
                                url=onion_url,
                                evidence=(
                                    f"URL: {onion_url}\n"
                                    f"Content excerpt:\n{text[:600]}"
                                    + (f"\nEmails found: {', '.join(emails)}" if emails else "")
                                ),
                                tags=["ai", "darkweb", "onion", target_type]
                            )
                    if len(seen_onions) >= 5:
                        break

        # Save a dark web research summary finding if hits found
        if dw_results:
            all_onions = list({u for r in dw_results for u in r.get("onion_urls", [])})
            self.db.save_finding(
                scan_id, self.NAME,
                "high" if len(all_onions) > 3 else "medium",
                f"🤖 AI Dark Web Research: {len(all_onions)} .onion URL(s) for '{target[:60]}'",
                f"AI-directed dark web searches found {len(dw_results)} engine result(s) "
                f"containing {len(all_onions)} unique .onion URL(s) related to the target.",
                evidence="\n".join(
                    f"[{r['engine']}] Query: {r['query']}\n  Snippet: {r['snippet'][:150]}"
                    for r in dw_results[:8]
                ),
                tags=["ai", "darkweb", "research", target_type],
                raw_data={"onion_urls": all_onions[:30]}
            )

        elif not tor_on:
            self.db.save_finding(
                scan_id, self.NAME, "info",
                "🧅 AI Dark Web: Enable TOR for Full .onion Coverage",
                "TOR is OFF. Clearnet dark web indexes were searched.\n"
                "Enable TOR to search .onion engines and fetch page content.",
                tags=["ai", "darkweb", "tor", "info"]
            )

        _log(f"[{self.LABEL}] Phase 2 done - {len(dw_results)} DW result sets")

        if self.should_skip(scan_id):
            return

        # ── Phase 3: Synthesis - correlate everything ─────────────────────────
        self.emit_task(scan_id, "Phase 3: AI synthesis - correlating all intelligence",
                       detail="Existing findings + clearnet + dark web → report")

        # Gather existing findings (from all modules that ran before AI)
        findings = self.db.get_findings(scan_id, limit=300)
        findings = [f for f in findings
                    if not (f.get("module") == self.NAME and f.get("severity") == "info")]

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings,
                                 key=lambda x: sev_order.get(x.get("severity", "info"), 4))
        findings_summary = [
            {
                "module":      f.get("module", ""),
                "severity":    f.get("severity", "info"),
                "title":       f.get("title", "")[:120],
                "description": (f.get("description", "") or "")[:200],
            }
            for f in sorted_findings[:80]
        ]

        # Build synthesis prompt
        sev_counts = ", ".join(
            f"{s}={sum(1 for x in findings if x.get('severity') == s)}"
            for s in ['critical', 'high', 'medium', 'low', 'info']
        )
        clearnet_summary = "\n".join(
            f"Query: {r['query']}\nResult: {r['result'][:300]}"
            for r in clearnet_results[:10]
        ) or "No clearnet results retrieved."
        dw_summary = "\n".join(
            f"[{r['engine']}] {r['query']}: {r['snippet'][:200]}"
            f"{' | .onions: ' + str(r['onion_urls'][:3]) if r.get('onion_urls') else ''}"
            for r in dw_results[:8]
        ) or "No dark web results retrieved."

        synthesis_prompt = (
            f"Target: {target}\n"
            f"Target type: {target_type}\n"
            f"TOR enabled: {tor_on}\n\n"
            f"=== EXISTING MODULE FINDINGS ({len(findings)} total) ===\n"
            f"Severity: {sev_counts}\n"
            f"{json.dumps(findings_summary, indent=2)}\n\n"
            f"=== CLEARNET OSINT RESEARCH ===\n{clearnet_summary}\n\n"
            f"=== DARK WEB RESEARCH ===\n{dw_summary}"
        )

        _log(f"[{self.LABEL}] Sending synthesis prompt ({len(synthesis_prompt)} chars)")
        analysis = self._call_ai(
            scan_id, anthropic_key, openai_key,
            self._SYNTHESIS_SYSTEM, synthesis_prompt,
            max_tokens=3500, label="synthesis"
        )

        if analysis:
            self._process_analysis(scan_id, target, target_type, analysis,
                                   "Claude" if anthropic_key else "GPT-4o")
        else:
            _ai_err_detail = getattr(self, "_last_ai_error", "").strip()
            _tor_hint = (
                "\n\n⚠️ TOR is enabled - Anthropic/OpenAI block TOR exit nodes. "
                "Disable Anonymous Mode and re-run."
            ) if tor_on else ""
            self.db.save_finding(
                scan_id, self.NAME, "info",
                "🤖 AI Analysis: Synthesis Call Failed",
                "API call(s) failed for the synthesis phase. "
                "Phase 1 (clearnet) and Phase 2 (dark web) results are still saved above."
                + (_tor_hint)
                + (f"\n\nError details:\n{_ai_err_detail}" if _ai_err_detail else ""),
                tags=["ai", "error"]
            )

    # ── AI call helper ────────────────────────────────────────────────────────

    def _call_ai(self, scan_id: str, anthropic_key: str, openai_key: str,
                 system: str, user_prompt: str,
                 max_tokens: int = 2000, label: str = "AI call") -> dict | None:
        """Call Anthropic Claude first, fall back to OpenAI. Returns parsed dict or None."""
        self._last_ai_error = ""

        if anthropic_key:
            try:
                r = self.http.post(
                    "https://api.anthropic.com/v1/messages",
                    scan_id, self.NAME,
                    json={
                        "model":      "claude-sonnet-4-6",
                        "max_tokens": max_tokens,
                        "system":     system,
                        "messages":   [{"role": "user", "content": user_prompt}],
                    },
                    headers={
                        "x-api-key":         anthropic_key,
                        "anthropic-version": "2023-06-01",
                        "content-type":      "application/json",
                    },
                    add_delay=False,
                    timeout=90
                )
                if r and r.status_code == 200:
                    text = r.json()["content"][0]["text"]
                    _log(f"[{self.LABEL}] Claude {label}: {len(text)} chars")
                    return _extract_json(text)
                if r:
                    err = f"Anthropic HTTP {r.status_code}: {r.text[:300]}"
                    _log(f"[{self.LABEL}] Claude {label} error {r.status_code}: {r.text[:200]}")
                    self._last_ai_error += err + "\n"
                else:
                    self._last_ai_error += "Anthropic: no response (timeout or connection error)\n"
            except Exception as ex:
                _log(f"[{self.LABEL}] Claude {label} exception: {ex}")
                self._last_ai_error += f"Anthropic exception: {ex}\n"

        if openai_key:
            try:
                r2 = self.http.post(
                    "https://api.openai.com/v1/chat/completions",
                    scan_id, self.NAME,
                    json={
                        "model":           "gpt-4o",
                        "max_tokens":      max_tokens,
                        "response_format": {"type": "json_object"},
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user",   "content": user_prompt},
                        ],
                    },
                    headers={
                        "Authorization": f"Bearer {openai_key}",
                        "Content-Type":  "application/json",
                    },
                    add_delay=False,
                    timeout=90
                )
                if r2 and r2.status_code == 200:
                    text = r2.json()["choices"][0]["message"]["content"]
                    _log(f"[{self.LABEL}] GPT-4o {label}: {len(text)} chars")
                    return _extract_json(text)
                if r2:
                    err2 = f"OpenAI HTTP {r2.status_code}: {r2.text[:300]}"
                    _log(f"[{self.LABEL}] GPT-4o {label} error {r2.status_code}: {r2.text[:200]}")
                    self._last_ai_error += err2 + "\n"
                else:
                    self._last_ai_error += "OpenAI: no response (timeout or connection error)\n"
            except Exception as ex:
                _log(f"[{self.LABEL}] GPT-4o {label} exception: {ex}")
                self._last_ai_error += f"OpenAI exception: {ex}\n"

        return None

    # ── Clearnet search helper ────────────────────────────────────────────────

    def _clearnet_search(self, scan_id: str, query: str) -> str:
        """Run one query on DDG + Bing, return combined visible text snippet."""
        snippets: list[str] = []
        for url in [
            f"https://duckduckgo.com/html/?q={quote(query)}",
            f"https://www.bing.com/search?q={quote(query)}",
        ]:
            r = self.http.get(url, scan_id, self.NAME, add_delay=True, timeout=12)
            if r and r.status_code == 200 and r.text:
                text = _visible_text(r.text, 600)
                if text:
                    snippets.append(text)
            if snippets:
                break   # one result is enough per query

        return " | ".join(snippets)[:800] if snippets else ""

    # ── Analysis processor ────────────────────────────────────────────────────

    def _process_analysis(self, scan_id: str, target: str, target_type: str,
                          analysis: dict, provider: str = "AI") -> None:
        score   = analysis.get("attack_surface_score", 0)
        summary = analysis.get("executive_summary", "No summary provided.")
        risks   = analysis.get("critical_risks",    [])
        corrs   = analysis.get("correlations",      [])
        queries = analysis.get("suggested_queries", [])
        cl_hits = analysis.get("clearnet_findings", [])
        dw_hits = analysis.get("darkweb_findings",  [])

        ev_parts = []
        if risks:
            ev_parts.append("CRITICAL RISKS:\n" + "\n".join(f"• {r}" for r in risks))
        if corrs:
            ev_parts.append("CORRELATIONS:\n" + "\n".join(f"• {c}" for c in corrs))
        if cl_hits:
            ev_parts.append("CLEARNET FINDINGS:\n" + "\n".join(f"• {h}" for h in cl_hits))
        if dw_hits:
            ev_parts.append("DARK WEB FINDINGS:\n" + "\n".join(f"• {h}" for h in dw_hits))
        if queries:
            ev_parts.append("SUGGESTED FOLLOW-UP QUERIES:\n" + "\n".join(f"• {q}" for q in queries))

        sev = "critical" if score >= 70 else ("high" if score >= 40 else "medium")
        self.db.save_finding(
            scan_id, self.NAME, sev,
            f"🤖 [{provider}] {target_type.upper()} Intelligence Report - Score: {score}/100",
            summary,
            evidence="\n\n".join(ev_parts),
            tags=["ai", "analysis", "intelligence", provider.lower(), target_type]
        )

        # Add AI-generated detection patterns
        added = 0
        for pat in analysis.get("new_patterns", []):
            name    = pat.get("name", "AI Pattern")
            pattern = pat.get("pattern", "")
            if not pattern:
                continue
            try:
                import re as _re
                _re.compile(pattern)
            except Exception:
                continue
            if self.patterns.add_pattern(
                name=name, pattern=pattern,
                category=pat.get("category", "ai-generated"),
                severity=pat.get("severity", "medium"),
                description=pat.get("description", ""),
                tags=["ai-generated"], source="ai"
            ):
                added += 1
                self.db.save_finding(
                    scan_id, self.NAME, "info",
                    f"🤖 New Pattern Created: {name}",
                    pat.get("description", ""),
                    evidence=f"Regex: {pattern}",
                    tags=["ai", "pattern", "new"]
                )

        _log(f"[{self.LABEL}] Complete - score={score}, {added} patterns added")
