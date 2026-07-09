"""Screenshot profiles using Playwright (optional dependency)."""

import asyncio
from io import BytesIO
from typing import Optional

try:
    from rich.console import Console
    from rich.text import Text
    _rich = True
except ImportError:
    _rich = False


async def screenshot_profile(
    url: str,
    platform: str,
    username: str,
    timeout: float = 15.0,
) -> Optional[bytes]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            await page.wait_for_timeout(2000)
            data = await page.screenshot(full_page=False)
            await browser.close()
        return data
    except Exception:
        return None


def render_screenshot_to_terminal(image_data: bytes, max_width: int = 80) -> Optional[str]:
    try:
        from PIL import Image
    except ImportError:
        return None

    try:
        img = Image.open(BytesIO(image_data))
        aspect = img.height / img.width
        term_w = min(max_width, 120)
        w = term_w
        h = int(w * aspect * 0.45)
        img = img.resize((w, h), Image.LANCZOS)

        lines = []
        ch = " "
        for y in range(h):
            row = ""
            for x in range(w):
                px = img.getpixel((x, y))
                r, g, b = px[:3]
                row += f"\033[48;2;{r};{g};{b}m{ch}\033[0m"
            lines.append(row)
        return "\n".join(lines)
    except Exception:
        return None


def print_terminal_screenshots(screenshots: dict[str, bytes], max_width: int = 80) -> None:
    if not _rich:
        return
    console = Console()
    for platform_name, data in screenshots.items():
        art = render_screenshot_to_terminal(data, max_width)
        if art:
            console.print(f"\n[bold cyan]{platform_name}[/bold cyan]")
            console.print(art)


async def take_screenshots(
    results: dict,
    username: str,
    timeout: float = 15.0,
    max_concurrent: int = 3,
) -> dict[str, bytes]:
    found = {
        name: r["url"]
        for name, r in results.items()
        if r.get("status") == "FOUND" and r.get("url")
    }
    if not found:
        return {}

    sem = asyncio.Semaphore(max_concurrent)

    async def _one(name: str, url: str) -> tuple[str, Optional[bytes]]:
        async with sem:
            data = await screenshot_profile(url, name, username, timeout)
            return name, data

    tasks = [_one(name, url) for name, url in found.items()]
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    return {name: data for name, data in outcomes if isinstance(data, bytes)}
