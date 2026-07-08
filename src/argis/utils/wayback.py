from __future__ import annotations

from dataclasses import dataclass, field

import httpx

WAYBACK_CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_AVAILABLE_API = "https://archive.org/wayback/available"


@dataclass
class WaybackSnapshot:
    timestamp: str
    url: str
    status_code: str | None = None


@dataclass
class WaybackResult:
    username: str
    snapshots: list[WaybackSnapshot] = field(default_factory=list)
    total: int = 0
    error: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


async def check_wayback(
    username: str,
    *,
    limit: int = 20,
    timeout: float = 10.0,
) -> WaybackResult:
    query = f"*/{username}*"
    params = {
        "url": query,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "limit": limit,
        "collapse": "urlkey",
    }

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        try:
            resp = await client.get(WAYBACK_CDX_API, params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.RequestError as exc:
            return WaybackResult(username=username, error=f"Request failed: {exc}")
        except Exception as exc:
            return WaybackResult(username=username, error=str(exc))

    if not data or len(data) < 2:
        return WaybackResult(username=username, snapshots=[], total=0)

    snapshots = []
    for row in data[1:]:
        ts = row[0]
        url = row[1]
        sc = row[2] if len(row) > 2 else None
        snapshots.append(WaybackSnapshot(timestamp=ts, url=url, status_code=sc))

    first_seen = snapshots[0].timestamp if snapshots else None
    last_seen = snapshots[-1].timestamp if snapshots else None

    return WaybackResult(
        username=username,
        snapshots=snapshots,
        total=len(snapshots),
        first_seen=first_seen,
        last_seen=last_seen,
    )


async def check_wayback_url(url: str, timeout: float = 10.0) -> str | None:
    params = {"url": url}
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        try:
            resp = await client.get(WAYBACK_AVAILABLE_API, params=params)
            data = resp.json()
            archived_snapshots = data.get("archived_snapshots", {})
            closest = archived_snapshots.get("closest", {})
            if closest and closest.get("available"):
                return closest["url"]
        except Exception:
            pass
    return None
