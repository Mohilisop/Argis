"""Headless-render fallback for JS-gated profiles.

Optional: only used when ``--render`` is set AND the server HTML looks gated.
Requires ``playwright`` plus a one-time ``playwright install chromium``.
Absent -> returns None and the caller keeps the server HTML.
"""

from __future__ import annotations

_PW_AVAILABLE: bool | None = None


def playwright_available() -> bool:
    global _PW_AVAILABLE
    if _PW_AVAILABLE is None:
        try:
            import playwright
            _PW_AVAILABLE = True
        except Exception:
            _PW_AVAILABLE = False
    return _PW_AVAILABLE


async def render_page(
    url: str, *, timeout: float = 12.0, proxy: str | None = None,
) -> str | None:
    if not playwright_available():
        return None
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None

    launch_kwargs: dict = {"headless": True}
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            try:
                page = await browser.new_page(
                    user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/124.0.0.0 Safari/537.36"))
                await page.goto(url, timeout=int(timeout * 1000),
                                wait_until="domcontentloaded")
                await page.wait_for_timeout(1200)
                return await page.content()
            finally:
                await browser.close()
    except Exception:
        return None