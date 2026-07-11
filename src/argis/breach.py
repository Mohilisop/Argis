"""Breach intelligence: check extracted emails against Have I Been Pwned.

Uses the public HIBP API (no key needed for the breach-check endpoint).
Rate-limited to 1 req/1.6s per HIBP's fair-use policy. Ethical: this tells
the OPERATOR which of their own emails are compromised, not a third party.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field

import httpx

_HIBP = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
_HEADERS = {"User-Agent": "argis-osint-scanner", "Accept": "application/json"}
_RATE = 1.6  # seconds between requests (HIBP fair-use)


@dataclass
class Breach:
    name: str
    domain: str
    date: str
    data_classes: list[str]
    pwn_count: int
    is_verified: bool


@dataclass
class BreachReport:
    email: str
    breaches: list[Breach] = field(default_factory=list)
    error: str | None = None

    @property
    def compromised(self) -> bool:
        return len(self.breaches) > 0

    @property
    def worst(self) -> list[str]:
        """Data classes that appear most (passwords, emails, IPs, etc.)."""
        all_classes = [c for b in self.breaches for c in b.data_classes]
        return [c for c, _ in Counter(all_classes).most_common(8)]


async def check_email(client: httpx.AsyncClient, email: str) -> BreachReport:
    url = _HIBP.format(email=email)
    try:
        r = await client.get(url, headers=_HEADERS)
    except httpx.HTTPError as exc:
        return BreachReport(email, error=type(exc).__name__)
    if r.status_code == 404:
        return BreachReport(email)
    if r.status_code == 429:
        return BreachReport(email, error="rate-limited")
    if r.status_code != 200:
        return BreachReport(email, error=f"HTTP {r.status_code}")
    breaches = []
    for b in r.json():
        breaches.append(Breach(
            name=b.get("Name", ""), domain=b.get("Domain", ""),
            date=b.get("BreachDate", ""),
            data_classes=b.get("DataClasses", []),
            pwn_count=b.get("PwnCount", 0),
            is_verified=b.get("IsVerified", False),
        ))
    return BreachReport(email, breaches)


async def check_all(emails: list[str]) -> list[BreachReport]:
    """Check a list of emails, rate-limited per HIBP policy."""
    reports: list[BreachReport] = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for email in emails:
            reports.append(await check_email(client, email))
            await asyncio.sleep(_RATE)
    return reports
