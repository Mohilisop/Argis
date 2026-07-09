"""Temporal identity reconstruction for argis.

For each found account, derive the earliest possible first-seen date from:
  1. Wayback Machine CDX API snapshots
  2. On-page "joined" / "member since" metadata (regex extraction)

Then render a chronological timeline and flag creation bursts.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime

import httpx

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
CDX_CONCURRENCY = 8

_JOINED_RX = re.compile(
    r"(?:joined|member\s+since|registered|created|since)\s*[:\s]*(\d{4}[\-\/]\d{1,2}[\-\/]\d{1,2})",
    re.I,
)


@dataclass
class Dated:
    platform: str
    url: str
    cdx_earliest: str | None = None
    page_joined: str | None = None
    first_seen: str | None = None
    snapshots: int = 0


@dataclass
class TimelineReport:
    username: str
    accounts: list[Dated] = field(default_factory=list)
    anomalies: list[dict] = field(default_factory=list)


async def _cdx_one(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, platform: str, url: str,
) -> Dated:
    async with sem:
        params = {
            "url": url,
            "output": "json",
            "fl": "timestamp,original",
            "limit": 500,
            "collapse": "urlkey",
        }
        d = Dated(platform=platform, url=url)
        try:
            resp = await client.get(WAYBACK_CDX, params=params, timeout=httpx.Timeout(15.0))
            if resp.status_code != 200:
                return d
            data = resp.json()
            if not data or len(data) < 2:
                return d
            timestamps = [row[0] for row in data[1:]]
            if timestamps:
                timestamps.sort()
                d.cdx_earliest = timestamps[0]
                d.snapshots = len(timestamps)
        except Exception:
            pass
        return d


async def _fetch_page_date(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, d: Dated,
) -> Dated:
    async with sem:
        try:
            resp = await client.get(d.url, timeout=httpx.Timeout(10.0))
            if resp.status_code == 200:
                m = _JOINED_RX.search(resp.text)
                if m:
                    d.page_joined = m.group(1)
        except Exception:
            pass
        return d


def _resolve_first(d: Dated) -> str | None:
    candidates: list[str] = []
    if d.cdx_earliest:
        ts = d.cdx_earliest.strip()
        if len(ts) >= 8:
            candidates.append(f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}")
    if d.page_joined:
        candidates.append(d.page_joined)
    if not candidates:
        return None
    parsed = []
    for c in candidates:
        normalized = c.replace("/", "-")
        try:
            parsed.append(datetime.strptime(normalized, "%Y-%m-%d"))
        except ValueError:
            continue
    if not parsed:
        return candidates[0]
    return min(parsed).strftime("%Y-%m-%d")


def _detect_bursts(accounts: list[Dated], window_days: int = 7) -> list[dict]:
    dated = [a for a in accounts if a.first_seen]
    if len(dated) < 2:
        return []
    pairs: list[tuple[datetime, str]] = []
    for a in dated:
        try:
            pairs.append((datetime.strptime(a.first_seen, "%Y-%m-%d"), a.platform))
        except (ValueError, TypeError):
            continue
    pairs.sort(key=lambda x: x[0])
    bursts: list[dict] = []
    i = 0
    while i < len(pairs):
        cluster: list[str] = [pairs[i][1]]
        j = i + 1
        while j < len(pairs) and (pairs[j][0] - pairs[i][0]).days <= window_days:
            cluster.append(pairs[j][1])
            j += 1
        if len(cluster) >= 3:
            bursts.append({
                "date": pairs[i][0].strftime("%Y-%m-%d"),
                "window_days": window_days,
                "count": len(cluster),
                "platforms": cluster,
            })
        i = j
    return bursts


async def build_timeline(
    username: str,
    found: dict[str, dict],
    *,
    fetch_page_dates: bool = True,
) -> TimelineReport:
    targets = {p: r["url"] for p, r in found.items()
               if r.get("status") == "FOUND" and r.get("url")}
    if not targets:
        return TimelineReport(username=username)

    sem = asyncio.Semaphore(CDX_CONCURRENCY)
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        dated = await asyncio.gather(*(
            _cdx_one(client, sem, p, u) for p, u in targets.items()
        ))

        if fetch_page_dates:
            sem2 = asyncio.Semaphore(CDX_CONCURRENCY)
            dated = await asyncio.gather(*(
                _fetch_page_date(client, sem2, d) for d in dated
            ))

    for d in dated:
        d.first_seen = _resolve_first(d)

    dated.sort(key=lambda d: d.first_seen or "9999-99-99")

    bursts = _detect_bursts(dated)

    return TimelineReport(
        username=username,
        accounts=dated,
        anomalies=bursts,
    )


def format_timeline(report: TimelineReport) -> str:
    lines = [f"Timeline for @{report.username}", ""]
    for a in report.accounts:
        first = a.first_seen or "\u2014"
        line = f"  {first}  {a.platform}  {a.url}"
        extra = []
        if a.cdx_earliest:
            extra.append(f"CDX: {a.cdx_earliest[:10]}")
        if a.page_joined:
            extra.append(f"page: {a.page_joined}")
        if extra:
            line += f"  ({'; '.join(extra)})"
        lines.append(line)

    if report.anomalies:
        lines.append("")
        lines.append(f"Creation bursts ({len(report.anomalies)} detected):")
        for b in report.anomalies:
            lines.append(
                f"  {b['date']}: {b['count']} accounts in {b['window_days']}d "
                f"\u2014 {', '.join(b['platforms'])}"
            )

    return "\n".join(lines)