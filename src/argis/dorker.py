from __future__ import annotations

import asyncio
import re
from typing import Any

from argis.utils.network import RateLimiter, build_client

_DORK_QUERIES: list[tuple[str, str]] = [
    ("username_google", '"{}"'),
    ("username_github", '"{}" site:github.com'),
    ("username_twitter", '"{}" site:x.com OR site:twitter.com'),
    ("username_linkedin", '"{}" site:linkedin.com/in'),
    ("username_reddit", '"{}" site:reddit.com'),
    ("username_archives", '"{}" site:web.archive.org'),
    ("username_pastebin", '"{}" site:pastebin.com OR site:ghostbin.com'),
    ("username_google_drive", '"{}" site:docs.google.com'),
]

_EMAIL_DORKS: list[tuple[str, str]] = [
    ("email_google", '"{}"'),
    ("email_pastebin", '"{}" site:pastebin.com OR site:ghostbin.com'),
]

_RESULT_LINK_RE = re.compile(r'<a\s+rel="nofollow"\s+class="result__a"\s+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
_RESULT_SNIPPET_RE = re.compile(r'<a\s+rel="nofollow"\s+class="result__snippet"[^>]*>(.*?)</a>', re.DOTALL)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', re.IGNORECASE)
_STRIP_TAGS = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    return _STRIP_TAGS.sub("", html).strip()


class Dorker:
    def __init__(self, rate_limiter: RateLimiter | None = None):
        self.rate_limiter = rate_limiter or RateLimiter(default_rps=3.0)

    async def search(self, query: str, client: "httpx.AsyncClient") -> list[dict[str, str]]:
        """Execute a single dork query and return structured results."""
        from urllib.parse import quote as url_quote
        from argis.utils.network import random_user_agent

        url = f"https://html.duckduckgo.com/html/?q={url_quote(query)}"
        await self.rate_limiter.acquire(url)
        headers = {"User-Agent": random_user_agent()}
        try:
            resp = await client.get(url, headers=headers, timeout=10.0)
            if resp.status_code != 200:
                return []
        except Exception:
            return []

        results: list[dict[str, str]] = []
        html = resp.text
        title_match = _TITLE_RE.search(html)
        page_title = _strip_html(title_match.group(1)).strip() if title_match else ""

        for link_match, snippet_match in zip(
            _RESULT_LINK_RE.finditer(html),
            _RESULT_SNIPPET_RE.finditer(html),
        ):
            href = link_match.group(1)
            title_raw = link_match.group(2)
            title = _strip_html(title_raw).strip() or page_title or href
            snippet = _strip_html(snippet_match.group(1)).strip() if snippet_match else ""
            if href and title:
                results.append({"url": href, "title": title, "snippet": snippet[:300]})

        return results

    async def run(self, target_username: str, target_emails: list[str], client: "httpx.AsyncClient") -> dict[str, list[dict[str, str]]]:
        """Run all dork queries for a target and return structured findings."""
        from argis.utils.extract_utils import clean_emails

        all_results: dict[str, list[dict[str, str]]] = {}

        username_queries = [q.format(target_username) for _, q in _DORK_QUERIES]
        for name, query in zip([n for n, _ in _DORK_QUERIES], username_queries):
            results = await self.search(query, client)
            if results:
                all_results[name] = results
            await asyncio.sleep(0.5)

        for email in target_emails:
            if not email or "@" not in email:
                continue
            email_queries = [q.format(email) for _, q in _EMAIL_DORKS]
            for name, query in zip([n for n, _ in _EMAIL_DORKS], email_queries):
                results = await self.search(query, client)
                if results:
                    key = f"{name}_{email}"
                    all_results[key] = results
                await asyncio.sleep(0.5)

        return all_results

    def to_findings(self, dork_results: dict[str, list[dict[str, str]]], target_username: str) -> list[dict[str, Any]]:
        """Convert dork results into finding dicts compatible with the investigation engine."""
        findings: list[dict[str, Any]] = []
        agent_id = 90
        for query_name, results in dork_results.items():
            category = "deep_web" if "pastebin" in query_name or "ghostbin" in query_name else "social"
            for i, r in enumerate(results[:5]):
                agent_id += 1
                findings.append({
                    "agent_id": agent_id,
                    "agent_name": f"Dork [{query_name}]",
                    "category": category,
                    "title": r.get("title", target_username),
                    "description": r.get("snippet", "")[:300],
                    "evidence": [r.get("url", "")],
                    "confidence": 0.65,
                    "platform": query_name.replace("_google", "").replace("_", " ").title(),
                })
        return findings