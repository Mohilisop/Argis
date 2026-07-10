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

from argis.intel_http import AsyncFetcher

from argis.utils.network import random_user_agent

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
_STRIP_TAGS_RE = re.compile(r"<(script|style|noscript|template)\b[^>]*>.*?</\1>",
                            re.I | re.S)

_STOP_DOMAINS = {
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "google.com", "apple.com", "microsoft.com", "github.com", "linkedin.com",
    "t.co", "bit.ly", "cdn.jsdelivr.net", "gravatar.com", "gstatic.com",
}

_EMAIL_BLOCK_DOMAINS = {
    "sentry.io", "ingest.us.sentry.io", "ingest.sentry.io",
    "automattic.com", "wordpress.com", "gravatar.com",
    "sentry-next.wixpress.com", "wixpress.com", "example.com",
    "domain.com", "email.com", "yourdomain.com",
    "test.com", "testing.com", "gg.com", "techaro.lol",
    "example.org",
}
_EMAIL_BLOCK_LOCAL = {
    "noreply", "no-reply", "donotreply", "support", "hello", "info",
    "admin", "webmaster", "postmaster", "privacy", "privacypolicyupdates",
    "abuse", "security", "sentry", "root", "mailer-daemon",
}
_EMAIL_JUNK_RE = re.compile(r"\.(?:jpg|jpeg|png|gif|webp|svg|css|js|woff2?)\b", re.I)
_HEXish_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)

_NOTFOUND_TITLES = {
    "profile not found", "user not found", "page not found", "not found",
    "sign up", "log in", "login", "undefined", "page isn't available",
    "this page isn't available", "error", "404", "whoops",
}


def visible_html(html: str) -> str:
    """Remove script/style/etc so extractors only see rendered content."""
    return _STRIP_TAGS_RE.sub(" ", html)


def _valid_email(addr: str) -> bool:
    addr = addr.strip().strip(".").lower()
    if "@" not in addr:
        return False
    local, _, domain = addr.partition("@")
    if not local or not domain or "." not in domain:
        return False
    if _EMAIL_JUNK_RE.search(addr):
        return False
    if _HEXish_RE.match(local) or len(local) > 40:
        return False
    if any(domain == d or domain.endswith("." + d) for d in _EMAIL_BLOCK_DOMAINS):
        return False
    if any(local.startswith(p + "+") or local == p for p in _EMAIL_BLOCK_LOCAL):
        return False
    return True


def clean_emails(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in raw:
        e2 = e.strip().strip(".")
        key = e2.lower()
        if key in seen:
            continue
        if _valid_email(e2):
            seen.add(key)
            out.append(e2)
    return out


@dataclass
class Signals:
    platform: str
    url: str
    display_name: str = ""
    bio: str = ""
    avatar_hash: int | None = None
    avatar_url: str = ""
    links: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    labels: dict | None = None
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


def _clean_display_name(raw: str, platform: str, handle: str) -> str:
    name = re.split(r"[·|–—\-]", raw)[0].strip()
    name = re.sub(r"\(@?" + re.escape(handle) + r"\)", "", name, flags=re.I).strip()
    name = re.sub(r"@" + re.escape(handle), "", name, flags=re.I).strip()
    low = name.lower()
    if low in (platform.lower(), handle.lower()):
        return ""
    if low in _NOTFOUND_TITLES:
        return ""
    return name


async def _fetch_signals(
    fetcher, platform: str, url: str, handle: str,
    fetch_avatar: bool,
) -> Signals:
    res = await fetcher.get(url)
    if res.error or not res.text:
        return Signals(platform, url, error=res.error or "empty")

    html = res.text[:80000]
    text = visible_html(html)
    sig = Signals(platform, url)

    from argis.extract import extract_labels, labels_to_dict
    raw_labels = extract_labels(platform, html)
    if raw_labels:
        sig.labels = labels_to_dict(raw_labels)

    name = ""
    m = _OG_TITLE.search(html) or _OG_SITE.search(html)
    if m:
        name = m.group(1)
    elif (mt := _TITLE.search(html)):
        name = mt.group(1)
    sig.display_name = _clean_display_name(name, platform, handle)

    d = _OG_DESC.search(html) or _META_DESC.search(html)
    if d:
        sig.bio = d.group(1).strip()

    for lm in _LINK.finditer(text):
        dom = _reg_domain(lm.group(1))
        if dom and dom not in _STOP_DOMAINS and dom != _reg_domain(url):
            sig.links.add(dom)
    sig.emails = set(clean_emails(_EMAIL.findall(text)))

    if fetch_avatar:
        im = _OG_IMAGE.search(html)
        if im:
            sig.avatar_url = im.group(1)
            if _HAS_PIL:
                data = await fetcher.get_bytes(sig.avatar_url)
                if data:
                    sig.avatar_hash = _dhash(data)
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
    render: bool = False,
) -> LinkReport:
    targets = {p: info["url"] for p, info in found.items()
               if info.get("status") == "FOUND" and info.get("url")}
    sem = asyncio.Semaphore(concurrency)

    async with AsyncFetcher(
        timeout=timeout, concurrency=concurrency, proxy=proxy,
        use_tor=use_tor, render=render,
    ) as fetcher:
        async def one(p: str, u: str) -> Signals:
            async with sem:
                return await _fetch_signals(fetcher, p, u, handle, fetch_avatar)
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