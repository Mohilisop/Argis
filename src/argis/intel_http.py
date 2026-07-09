"""Shared HTTP layer for the Argis Intelligence suite.

One AsyncFetcher, used by every intel command, gives you:
  * in-process + on-disk response caching (a URL is fetched once per TTL)
  * per-host rate limiting (polite, avoids self-inflicted WAF bans)
  * bounded concurrency and exponential-backoff retries
  * a single place to later swap in the render fallback
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from argis.utils.network import random_user_agent

_CACHE_DIR = Path.home() / ".argis" / "http-cache"


@dataclass
class Fetched:
    url: str
    status: int
    text: str
    from_cache: bool = False
    rendered: bool = False
    error: str | None = None


class AsyncFetcher:
    def __init__(
        self,
        *,
        timeout: float = 12.0,
        concurrency: int = 15,
        per_host_delay: float = 0.4,
        cache_ttl: float = 86_400.0,
        proxy: str | None = None,
        use_tor: bool = False,
        http2: bool = False,
        max_retries: int = 3,
        render: bool = False,
    ):
        self.timeout = timeout
        self.per_host_delay = per_host_delay
        self.cache_ttl = cache_ttl
        self.max_retries = max_retries
        self.render = render
        self._sem = asyncio.Semaphore(concurrency)
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._host_last: dict[str, float] = {}
        self._mem: dict[str, Fetched] = {}
        self._proxy = proxy or (("socks5://127.0.0.1:9050") if use_tor else None)
        self._http2 = http2
        self._client: httpx.AsyncClient | None = None
        if cache_ttl > 0:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self) -> "AsyncFetcher":
        kwargs: dict = {
            "http2": self._http2,
            "timeout": httpx.Timeout(self.timeout),
            "follow_redirects": True,
        }
        if self._proxy:
            kwargs["proxy"] = self._proxy
        self._client = httpx.AsyncClient(**kwargs)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    def _key(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def _cache_path(self, url: str) -> Path:
        return _CACHE_DIR / f"{self._key(url)}.json"

    def _read_cache(self, url: str) -> Fetched | None:
        if self.cache_ttl <= 0:
            return None
        if url in self._mem:
            return self._mem[url]
        p = self._cache_path(url)
        if not p.exists():
            return None
        if time.time() - p.stat().st_mtime > self.cache_ttl:
            return None
        try:
            d = json.loads(p.read_text("utf-8"))
        except Exception:
            return None
        f = Fetched(url=url, status=d["status"], text=d["text"],
                    from_cache=True, rendered=d.get("rendered", False))
        self._mem[url] = f
        return f

    def _write_cache(self, f: Fetched) -> None:
        if self.cache_ttl <= 0 or f.error:
            return
        self._mem[f.url] = f
        try:
            self._cache_path(f.url).write_text(json.dumps(
                {"status": f.status, "text": f.text, "rendered": f.rendered}),
                encoding="utf-8")
        except Exception:
            pass

    async def _throttle(self, host: str) -> None:
        async with self._host_locks[host]:
            last = self._host_last.get(host, 0.0)
            wait = self.per_host_delay - (time.time() - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._host_last[host] = time.time()

    async def get(self, url: str, *, want_render: bool | None = None) -> Fetched:
        cached = self._read_cache(url)
        if cached is not None:
            return cached

        host = urlparse(url).netloc
        assert self._client is not None, "use AsyncFetcher as an async context manager"

        async with self._sem:
            await self._throttle(host)
            attempt = 0
            while True:
                attempt += 1
                try:
                    r = await self._client.get(
                        url, headers={"User-Agent": random_user_agent()})
                    f = Fetched(url=url, status=r.status_code, text=r.text)
                    break
                except httpx.HTTPError as exc:
                    if attempt >= self.max_retries:
                        return Fetched(url=url, status=0, text="",
                                       error=type(exc).__name__)
                    await asyncio.sleep(2 ** attempt)

        do_render = self.render if want_render is None else want_render
        if do_render and _looks_gated(f.text):
            from argis.render import render_page
            rendered = await render_page(url, timeout=self.timeout,
                                         proxy=self._proxy)
            if rendered is not None:
                f = Fetched(url=url, status=f.status or 200, text=rendered,
                            rendered=True)

        self._write_cache(f)
        return f

    async def get_bytes(self, url: str) -> bytes | None:
        cached = self._read_cache(url)
        if cached is not None:
            return cached.text.encode("utf-8") if not cached.error else None

        host = urlparse(url).netloc
        assert self._client is not None

        async with self._sem:
            await self._throttle(host)
            try:
                r = await self._client.get(
                    url, headers={"User-Agent": random_user_agent()})
                if r.status_code == 200:
                    return r.content
            except httpx.HTTPError:
                pass
        return None


_GATE_MARKERS = (
    "enable javascript", "please enable js", "loading...",
    "you need to enable javascript", "__next_data__", "window.__initial",
)


def _looks_gated(text: str) -> bool:
    if len(text.strip()) < 1200:
        return True
    low = text[:6000].lower()
    if "og:image" in low or "og:description" in low:
        return False
    return any(m in low for m in _GATE_MARKERS)