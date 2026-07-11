"""Scan for mentions of a handle/email in public paste sites, GitHub code,
and Google dork patterns.

Sources (all public, no auth needed for basic search):
  * GitHub Code Search API (public)
  * Various paste search engines
  * Generates Google dork queries for the user to open

Ethics: searches only public, already-indexed content. Does not access
private repos, unlisted pastes, or authenticated endpoints.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx


@dataclass
class Mention:
    source: str
    title: str
    url: str
    snippet: str = ""
    date: str = ""


@dataclass
class MentionReport:
    query: str
    mentions: list[Mention] = field(default_factory=list)
    dorks: list[str] = field(default_factory=list)


_GITHUB_SEARCH = "https://api.github.com/search/code?q={query}&per_page=10"


async def _github_code(client: httpx.AsyncClient, query: str) -> list[Mention]:
    url = _GITHUB_SEARCH.format(query=query)
    try:
        r = await client.get(url, headers={"Accept": "application/vnd.github.v3.text-match+json"})
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    out = []
    for item in r.json().get("items", [])[:10]:
        snippet = ""
        for tm in item.get("text_matches", []):
            snippet = tm.get("fragment", "")[:120]
            break
        out.append(Mention(
            source="github", title=item.get("repository", {}).get("full_name", ""),
            url=item.get("html_url", ""), snippet=snippet,
        ))
    return out


def _generate_dorks(handle: str, emails: list[str]) -> list[str]:
    """Google dork queries the user can paste into a browser."""
    dorks = [
        f'"{handle}" site:pastebin.com',
        f'"{handle}" site:ghostbin.co OR site:rentry.co',
        f'"{handle}" site:paste.ee OR site:dpaste.org',
        f'"{handle}" inurl:paste OR inurl:bin',
        f'"{handle}" filetype:txt OR filetype:csv OR filetype:log',
        f'"{handle}" site:gist.github.com',
    ]
    for email in emails[:3]:
        dorks.append(f'"{email}" -site:{email.split("@")[1]}')
    return dorks


async def scan_mentions(
    handle: str, emails: list[str] | None = None, *, timeout: float = 15.0,
) -> MentionReport:
    report = MentionReport(query=handle)
    report.dorks = _generate_dorks(handle, emails or [])

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        gh = await _github_code(client, handle)
        report.mentions.extend(gh)

    return report
