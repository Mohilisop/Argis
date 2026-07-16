from __future__ import annotations

_PW_AVAILABLE: bool | None = None

_LOGIN_WALL_KEYWORDS = (
    "log in", "sign in", "sign up", "create account", "join now",
    "continue with google", "continue with apple", "continue with facebook",
    "continue with github", "forgot password", "reset password",
    "log in to see", "sign in to see", "log in to view",
    "create new account", "don't have an account",
)


def playwright_available() -> bool:
    global _PW_AVAILABLE
    if _PW_AVAILABLE is None:
        try:
            import playwright  # noqa: F401
            _PW_AVAILABLE = True
        except Exception:
            _PW_AVAILABLE = False
    return _PW_AVAILABLE


class BrowserChecker:
    def __init__(self, *, proxy: str | None = None):
        self._proxy = proxy
        self._browser = None
        self._playwright = None

    async def start(self) -> bool:
        if not playwright_available():
            return False
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        launch_kwargs: dict = {"headless": True}
        if self._proxy:
            launch_kwargs["proxy"] = {"server": self._proxy}
        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        return True

    async def check(self, url: str, *, timeout: float = 15.0, username: str = "") -> dict:
        result: dict = {
            "html": "", "title": "", "final_url": url,
            "error": None, "is_login_wall": False,
        }
        if not self._browser:
            result["error"] = "browser not started"
            return result
        try:
            page = await self._browser.new_page(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            )
            resp = await page.goto(url, timeout=int(timeout * 1000),
                                   wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)
            result["html"] = await page.content()
            result["title"] = (await page.title()).strip()
            result["final_url"] = page.url

            text = result["html"][:8000].lower()
            count = 0
            for kw in _LOGIN_WALL_KEYWORDS:
                if kw in text:
                    count += 1
            result["is_login_wall"] = count >= 2

            if resp and resp.status:
                result["status"] = resp.status
            else:
                result["status"] = 200

            await page.close()
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def close(self):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
