"""Cross-platform identity correlation for Argis.

After a scan finds a handle on N platforms, this decides which of those
accounts plausibly belong to the SAME person and which are namesakes or
impersonators. It is deliberately disambiguation, not deanonymization: every
input already shares one public username.

Signals per profile:
  * avatar perceptual hash (dHash, 64-bit) -- robust to resize/re-encode
  * display name (from <title> / og:site_name / og:title)
  * bio / description (meta description / og:description)
  * outbound links + emails found on the page

Scoring is a weighted blend; clustering is union-find over a similarity
threshold. Everything degrades gracefully when a signal is missing.
"""

from __future__ import annotations

import asyncio
import io
import re
from dataclasses import dataclass, field

import httpx

from argis.utils.network import build_client, random_user_agent

try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

_OG_IMAGE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_OG_TITLE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_OG_SITE = re.compile(
    r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_OG_DESC = re.compile(
    r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_META_DESC = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LINK = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.I)
_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_WORD = re.compile(r"[a-z0-9]+")

_STOP_DOMAINS = {
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "google.com", "apple.com", "microsoft.com", "github.com", "linkedin.com",
    "t.co", "bit.ly", "cdn.jsdelivr.net", "gravatar.com", "gstatic.com",
}


@dataclass
class Signals:
    platform: str
    url: str
    display_name: str = ""
    bio: str = ""
    avatar_hash: int | None = None
    links: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    error: str | None = None


def _dhash(data: bytes, size: int = 8) -> int | None:
    """64-bit difference hash. Robust to resize and re-encode."""
    if not _HAS_PIL:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("L").resize(
            (size + 1, size), Image.LANCZOS
        )
    except Exception:
        return None
    px = list(img.getdata())
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            left = px[base + col]
            right = px[base + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _reg_domain(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    if not m:
        return ""
    host = m.group(1).lower().split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _clean_name(raw: str, platform: str, handle: str) -> str:
    name = re.split(r"[|\u2013\u2014\-]", raw)[0].strip()
    name = re.sub(r"\(@?" + re.escape(handle) + r"\)", "", name, flags=re.I).strip()
    name = re.sub(r"@" + re.escape(handle), "", name, flags=re.I).strip()
    return name


async def _fetch_signals(
    client: httpx.AsyncClient, platform: str, url: str, handle: str,
    fetch_avatar: bool,
) -> Signals:
    headers = {"User-Agent": random_user_agent()}
    try:
        r = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return Signals(platform, url, error=type(exc).__name__)

    html = r.text[:60000]
    sig = Signals(platform, url)

    name = ""
    m = _OG_TITLE.search(html) or _OG_SITE.search(html)
    if m:
        name = m.group(1)
    elif (mt := _TITLE.search(html)):
        name = mt.group(1)
    sig.display_name = _clean_name(name, platform, handle)

    d = _OG_DESC.search(html) or _META_DESC.search(html)
    if d:
        sig.bio = d.group(1).strip()

    for lm in _LINK.finditer(html):
        dom = _reg_domain(lm.group(1))
        if dom and dom not in _STOP_DOMAINS and dom != _reg_domain(url):
            sig.links.add(dom)
    sig.emails = set(_EMAIL.findall(html))

    if fetch_avatar and _HAS_PIL:
        im = _OG_IMAGE.search(html)
        if im:
            try:
                ir = await client.get(im.group(1), headers=headers)
                if ir.status_code == 200:
                    sig.avatar_hash = _dhash(ir.content)
            except httpx.HTTPError:
                pass
    return sig


_WEIGHTS = {"avatar": 0.45, "name": 0.25, "bio": 0.15, "links": 0.10, "email": 0.05}


def similarity(a: Signals, b: Signals) -> tuple[float, dict]:
    parts: dict[str, float] = {}
    if a.avatar_hash is not None and b.avatar_hash is not None:
        dist = _hamming(a.avatar_hash, b.avatar_hash)
        parts["avatar"] = max(0.0, 1.0 - dist / 32.0)
    if a.display_name and b.display_name:
        na, nb = a.display_name.lower(), b.display_name.lower()
        exact = 1.0 if na == nb else _jaccard(_tokens(na), _tokens(nb))
        parts["name"] = exact
    if a.bio and b.bio:
        parts["bio"] = _jaccard(_tokens(a.bio), _tokens(b.bio))
    if a.links and b.links:
        parts["links"] = _jaccard(a.links, b.links)
    if a.emails and b.emails:
        parts["email"] = 1.0 if (a.emails & b.emails) else 0.0

    if not parts:
        return 0.0, parts
    wsum = sum(_WEIGHTS[k] for k in parts)
    score = sum(_WEIGHTS[k] * v for k, v in parts.items()) / wsum
    return score, parts


class _UF:
    def __init__(self, items: list[str]):
        self.p = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.p[self.find(a)] = self.find(b)


@dataclass
class Cluster:
    members: list[str]
    confidence: float
    label: str


@dataclass
class LinkReport:
    handle: str
    signals: dict[str, Signals]
    clusters: list[Cluster]
    edges: list[tuple[str, str, float]]
    pillow: bool

    @property
    def primary(self) -> Cluster | None:
        ident = [c for c in self.clusters if c.label == "identity"]
        return max(ident, key=lambda c: len(c.members)) if ident else None

    @property
    def impersonators(self) -> list[str]:
        p = self.primary
        if not p:
            return []
        inside = set(p.members)
        return [s for s in self.signals if s not in inside]


async def correlate(
    handle: str,
    found: dict[str, dict],
    *,
    threshold: float = 0.62,
    fetch_avatar: bool = True,
    timeout: float = 12.0,
    concurrency: int = 12,
    proxy: str | None = None,
    use_tor: bool = False,
) -> LinkReport:
    targets = {p: info["url"] for p, info in found.items()
               if info.get("status") == "FOUND" and info.get("url")}
    sem = asyncio.Semaphore(concurrency)

    async with build_client(
        proxy=proxy, use_tor=use_tor, timeout=timeout,
    ) as client:
        async def one(p: str, u: str) -> Signals:
            async with sem:
                return await _fetch_signals(client, p, u, handle, fetch_avatar)
        sigs = await asyncio.gather(*(one(p, u) for p, u in targets.items()))

    signals = {s.platform: s for s in sigs if s.error is None}

    names = list(signals)
    uf = _UF(names)
    edges: list[tuple[str, str, float]] = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            score, _ = similarity(signals[names[i]], signals[names[j]])
            if score > 0:
                edges.append((names[i], names[j], round(score, 3)))
            if score >= threshold:
                uf.union(names[i], names[j])

    groups: dict[str, list[str]] = {}
    for n in names:
        groups.setdefault(uf.find(n), []).append(n)

    clusters: list[Cluster] = []
    for members in groups.values():
        if len(members) > 1:
            pair_scores = [
                s for a, b, s in edges
                if a in members and b in members and s >= threshold
            ]
            conf = round(sum(pair_scores) / len(pair_scores), 3) if pair_scores else 0.0
            clusters.append(Cluster(sorted(members), conf, "identity"))
        else:
            clusters.append(Cluster(members, 0.0, "singleton"))
    clusters.sort(key=lambda c: (c.label != "identity", -len(c.members)))

    return LinkReport(handle, signals, clusters, sorted(
        edges, key=lambda e: -e[2]), _HAS_PIL)