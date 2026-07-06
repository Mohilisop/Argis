"""HTTP client construction, user-agent rotation, and proxy/Tor routing."""

from __future__ import annotations

import random

import httpx

# A small rotation pool. Real browser UAs reduce the odds of a WAF (e.g.
# Cloudflare) flagging the scan as bot traffic.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
    "Safari/604.1",
]

TOR_PROXY_URL = "socks5://127.0.0.1:9050"


def random_user_agent() -> str:
    """Return a random desktop/mobile User-Agent string."""
    return random.choice(USER_AGENTS)


def build_client(
    *,
    proxy: str | None = None,
    use_tor: bool = False,
    timeout: float = 7.0,
    http2: bool = False,
) -> httpx.AsyncClient:
    """Construct a configured httpx.AsyncClient.

    Args:
        proxy: Explicit proxy URL (e.g. "socks5://127.0.0.1:9050" or
            "http://user:pass@host:port"). Takes precedence over use_tor.
        use_tor: If True and no explicit proxy given, route through a local
            Tor SOCKS5 proxy (assumes Tor is running on the default port).
        timeout: Per-request timeout in seconds.
        http2: Enable HTTP/2 multiplexing support.
    """
    proxy_url = proxy or (TOR_PROXY_URL if use_tor else None)

    kwargs: dict = {
        "http2": http2,
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": True,
    }
    if proxy_url:
        kwargs["proxy"] = proxy_url

    return httpx.AsyncClient(**kwargs)
