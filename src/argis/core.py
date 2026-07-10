from __future__ import annotations

import asyncio
import json
import pathlib
import re
from collections import defaultdict

import httpx

from argis.exceptions import SiteConfigError
from argis.utils.display import console, make_progress, print_found
from argis.utils.network import build_client, random_user_agent

_CHALLENGE_MARKERS = (
    "client challenge", "checking your browser", "attention required",
    "verify you are human", "just a moment...", "captcha",
    "making sure you're not a bot", "making sure you\u2019re not a bot",
    "enable javascript and cookies", "ddos-guard", "cf-browser-verification",
    "please verify you are a human", "__cf_chl",
    "making sure you&#39;re not a bot", "&#39;re not a bot",
    "please wait", "please stand by", "verify your browser",
)

_SOFT_404_TITLES = (
    "not found", "page not found", "user not found", "profile not found",
    "doesn't exist", "doesn\u2019t exist", "error 404", "404", "general error",
    "log in", "login", "sign up", "signup", "sign in", "join ",
    "official site", "contact", "for web", " \u2022 log in",
    "get your very own", "create your", "welcome to",
    "learn to code", "the magic of the internet",
    "undefined", "whoops", "page isn't available",
    "messenger", "my indeed",
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_DESC_RE = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_STRIP_TAGS_RE = re.compile(r"<(script|style|noscript|template)\b[^>]*>.*?</\1>",
                            re.I | re.S)


def visible_html(html: str) -> str:
    """Remove script/style/etc so extractors only see rendered content."""
    return _STRIP_TAGS_RE.sub(" ", html)


def _looks_generic(title: str, platform: str) -> bool:
    low = title.strip().lower()
    if not low:
        return True
    plat_low = platform.lower()
    if low in (plat_low, plat_low + " social", plat_low + ".com"):
        return True
    if low.startswith(plat_low + " -") or low.startswith(plat_low + " \u2022"):
        return True
    return any(s in low for s in _SOFT_404_TITLES)


def _categorize_error(exc: BaseException) -> str:
    if isinstance(exc, httpx.ConnectTimeout):
        return "CONNECT_TIMEOUT"
    if isinstance(exc, httpx.ReadTimeout):
        return "READ_TIMEOUT"
    if isinstance(exc, httpx.TimeoutException):
        return "TIMEOUT"
    if isinstance(exc, httpx.ConnectError):
        msg = str(exc).lower()
        if "errno 11001" in msg or "getaddrinfo" in msg or "nodename" in msg:
            return "DNS_ERROR"
        if "connection refused" in msg or "connectionreset" in msg or "10061" in msg:
            return "CONNECTION_REFUSED"
        if "connection reset" in msg:
            return "CONNECTION_RESET"
        if "ssl" in msg or "certificate" in msg or "handshake" in msg:
            return "SSL_ERROR"
        if "timed out" in msg:
            return "CONNECT_TIMEOUT"
        return "CONNECT_ERROR"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "PROTOCOL_ERROR"
    if isinstance(exc, httpx.TooManyRedirects):
        return "TOO_MANY_REDIRECTS"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP_{exc.response.status_code}"
    return "UNKNOWN_ERROR"


class ArgisEngine:
    def __init__(
        self,
        username: str,
        *,
        proxy: str | None = None,
        use_tor: bool = False,
        timeout: float = 7.0,
        concurrency: int = 30,
        sites_path: pathlib.Path | None = None,
        http2: bool = False,
        categories: tuple[str, ...] | None = None,
        retry_blocked: bool = True,
        retry_max_attempts: int = 3,
        exclude: set[str] | None = None,
        include: set[str] | None = None,
    ):
        self.username = username
        self.proxy = proxy
        self.use_tor = use_tor
        self.timeout = timeout
        self.http2 = http2
        self.categories = set(categories) if categories else None
        self.retry_blocked = retry_blocked
        self.retry_max_attempts = retry_max_attempts
        self.exclude = set(e.lower() for e in exclude) if exclude else None
        self.include = set(i.lower() for i in include) if include else None
        self.sites = self._load_sites(sites_path)
        self._semaphore = asyncio.Semaphore(concurrency)

    def _load_sites(self, sites_path: pathlib.Path | None) -> dict:
        path = sites_path or (pathlib.Path(__file__).parent / "sites.json")
        if not path.exists():
            raise SiteConfigError(f"sites.json not found at {path}")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                sites = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SiteConfigError(f"sites.json is not valid JSON: {exc}") from exc

        for name, rules in sites.items():
            if "url" not in rules or "error_type" not in rules:
                raise SiteConfigError(
                    f"Site '{name}' is missing required 'url' or 'error_type' key"
                )
        return sites

    def _filter_sites(self) -> dict:
        sites = self.sites

        if self.include is not None:
            sites = {
                name: rules
                for name, rules in sites.items()
                if name.lower() in self.include
            }
            return sites

        if self.categories is not None:
            cats_lower = {c.lower() for c in self.categories}
            sites = {
                name: rules
                for name, rules in sites.items()
                if rules.get("category", "").lower() in cats_lower
            }
        if self.exclude is not None:
            sites = {
                name: rules
                for name, rules in sites.items()
                if name.lower() not in self.exclude
            }
        return sites

    async def check_platform(
        self, client: httpx.AsyncClient, name: str, rules: dict, attempt: int = 1
    ) -> dict:
        target_url = rules["url"].format(self.username)
        headers = {"User-Agent": random_user_agent()}

        async with self._semaphore:
            try:
                response = await client.get(target_url, headers=headers)
            except httpx.TimeoutException as exc:
                err_type = _categorize_error(exc)
                return {"status": "TIMEOUT", "url": target_url, "error": err_type}
            except httpx.RequestError as exc:
                err_type = _categorize_error(exc)
                if self.retry_blocked and attempt < self.retry_max_attempts:
                    if err_type in (
                        "CONNECTION_RESET", "CONNECT_TIMEOUT", "PROTOCOL_ERROR",
                    ):
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                        return await self.check_platform(
                            client, name, rules, attempt=attempt + 1
                        )
                return {"status": "UNKNOWN", "url": target_url, "error": err_type}
            except Exception as exc:
                err_type = _categorize_error(exc)
                return {"status": "UNKNOWN", "url": target_url, "error": err_type}

        if response.status_code in (403, 429, 503):
            if self.retry_blocked and attempt < self.retry_max_attempts:
                wait = 2 ** attempt
                await asyncio.sleep(wait)
                return await self.check_platform(
                    client, name, rules, attempt=attempt + 1
                )
            return {"status": "BLOCKED", "url": target_url}

        if response.status_code >= 500:
            if self.retry_blocked and attempt < self.retry_max_attempts:
                wait = 2 ** attempt
                await asyncio.sleep(wait)
                return await self.check_platform(
                    client, name, rules, attempt=attempt + 1
                )

        lowered_text = response.text[:2000].lower()
        if any(marker in lowered_text for marker in _CHALLENGE_MARKERS):
            return {"status": "BLOCKED", "url": target_url}

        text = visible_html(response.text)
        error_type = rules["error_type"]
        error_criteria = rules.get("error_criteria")

        not_found = False
        if error_type == "status_code":
            if response.status_code == int(error_criteria):
                not_found = True
        elif error_type == "message":
            if error_criteria and error_criteria in text:
                not_found = True
        elif error_type == "response_url":
            if error_criteria and str(response.url).rstrip("/") == error_criteria.rstrip("/"):
                not_found = True

        if not_found:
            return {"status": "NOT_FOUND", "url": target_url}

        if response.status_code == 200:
            from argis.correlate import clean_emails
            emails = clean_emails(_EMAIL_RE.findall(text))
            title_match = _TITLE_RE.search(response.text[:5000])
            title = title_match.group(1).strip() if title_match else ""
            if not title or _looks_generic(title, name):
                return {"status": "NOT_FOUND", "url": target_url}
            desc_match = _META_DESC_RE.search(response.text[:5000])
            description = desc_match.group(1).strip() if desc_match else None
            return {
                "status": "FOUND",
                "url": target_url,
                "title": title,
                "description": description,
                "emails": emails,
            }

        return {"status": "UNKNOWN", "url": target_url, "error": f"HTTP_{response.status_code}"}

    async def run_scan(
        self, *, quiet: bool = False, stats: dict | None = None
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}
        sites = self._filter_sites()

        if not sites:
            console.print("[bold yellow]No sites match the given filters.[/bold yellow]")
            return results

        async with build_client(
            proxy=self.proxy,
            use_tor=self.use_tor,
            timeout=self.timeout,
            http2=self.http2,
        ) as client:
            if quiet:
                tasks = [
                    self.check_platform(client, name, rules)
                    for name, rules in sites.items()
                ]
                outcomes = await asyncio.gather(*tasks)
                for (name, _), outcome in zip(sites.items(), outcomes):
                    results[name] = outcome
                return results

            with make_progress() as progress:
                task_id = progress.add_task(
                    "[cyan]Scanning...", total=len(sites)
                )

                async def run_one(name: str, rules: dict) -> None:
                    outcome = await self.check_platform(client, name, rules)
                    results[name] = outcome
                    if outcome["status"] == "FOUND":
                        progress.console.print(
                            f"  [bold green]\u2713[/bold green] [white]{name}:[/white] "
                            f"[underline cyan]{outcome['url']}[/underline cyan]"
                        )
                    if stats is not None:
                        st = outcome["status"]
                        stats["by_status"][st] = stats["by_status"].get(st, 0) + 1
                        stats["done"] += 1
                        stats["total"] = len(sites)
                        err = outcome.get("error")
                        if err and st in ("UNKNOWN", "TIMEOUT"):
                            stats["by_error"][err] = stats["by_error"].get(err, 0) + 1
                    progress.advance(task_id)

                await asyncio.gather(
                    *(run_one(name, rules) for name, rules in sites.items())
                )

        return results


def extract_categories(sites_path: pathlib.Path | None = None) -> list[str]:
    path = sites_path or (pathlib.Path(__file__).parent / "sites.json")
    with open(path, "r", encoding="utf-8") as fh:
        sites = json.load(fh)
    cats = set()
    for rules in sites.values():
        cat = rules.get("category", "uncategorized")
        cats.add(cat.lower())
    return sorted(cats)


def build_email_map(all_results: dict[str, dict]) -> dict[str, list[str]]:
    email_map: dict[str, list[str]] = {}
    for platform, info in all_results.items():
        if info.get("status") == "FOUND" and info.get("emails"):
            email_map[platform] = info["emails"]
    return email_map
