from __future__ import annotations

import asyncio
import json
import pathlib
import re
from collections import defaultdict
from pathlib import Path

import httpx

from argis.exceptions import SiteConfigError
from argis.utils.display import console, make_progress, print_found
from argis.utils.extract_utils import clean_emails, visible_html
from argis.utils.network import build_client, random_user_agent
from argis.browser import BrowserChecker, playwright_available

_STRIP_NON_ENCODABLE = re.compile(r"[^\x20-\x7E\xA0-\xFF\u0100-\u024F\u0300-\u03FF\u2000-\u206F\u2100-\u214F\u2150-\u218F\u2200-\u22FF\u2500-\u257F]+")

_CHALLENGE_MARKERS = (
    "client challenge", "checking your browser", "attention required",
    "verify you are human", "just a moment...", "captcha",
    "making sure you're not a bot", "making sure you\u2019re not a bot",
    "enable javascript and cookies", "ddos-guard", "cf-browser-verification",
    "please verify you are a human", "__cf_chl", "px-captcha",
    "incapsula", "perimeterx", "are you a robot",
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
    "profile isn't available",
    "messenger", "my indeed",
)

_LOGIN_WALL_CONFIRM_PATTERNS = (
    "see photos, videos and more from",
    "never miss a post from",
    "sign up and never miss a post",
    "log in to see photos and videos",
    "follow to see their posts",
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_DESC_RE = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)


def _looks_generic(title: str, platform: str) -> bool:
    low = title.strip().lower()
    if not low:
        return True
    plat_low = platform.lower()
    if low == plat_low:
        return True
    if low in (plat_low + " social", plat_low + ".com"):
        return True
    if low.startswith(plat_low + " -") or low.startswith(plat_low + " \u2022"):
        return True
    return any(s in low for s in _SOFT_404_TITLES)


def _confidence_score(text: str, rules: dict, has_username_in_title: bool = False) -> int:
    """Score 0-100 for how confident we are this is a real profile."""
    score = 0
    low = text.lower()[:8000]

    et = rules.get("error_type")
    if et in ("message", "response_url"):
        score += 40
    elif et == "status_code" and rules.get("error_criteria") != 404:
        score += 35
    else:
        score += 20

    if has_username_in_title:
        score += 25

    if len(text) > 3000:
        score += 15
    elif len(text) > 1500:
        score += 8

    if "og:image" in low and "default" not in low:
        score += 10

    if "og:description" in low or 'name="description"' in low:
        score += 10

    return min(score, 100)


def _login_wall_confirms_user(text: str, username: str) -> bool:
    """Check if a login-walled page still confirms the profile exists."""
    low = text.lower()
    user_low = username.lower()
    if user_low not in low:
        return False
    for pattern in _LOGIN_WALL_CONFIRM_PATTERNS:
        if pattern in low:
            return True
    return False


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
        render: bool = False,
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
        self.render = render
        self._browser: BrowserChecker | None = None
        self.sites = self._load_sites(sites_path)
        self._semaphore = asyncio.Semaphore(concurrency)

    def _load_sites(self, sites_path: pathlib.Path | None) -> dict:
        if sites_path:
            path = sites_path
        else:
            user_path = Path.home() / ".argis" / "sites.json"
            path = user_path if user_path.exists() else (pathlib.Path(__file__).parent / "sites.json")
        if not path.exists():
            raise SiteConfigError(f"sites.json not found at {path}")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SiteConfigError(f"sites.json is not valid JSON: {exc}") from exc

        if isinstance(raw, list):
            sites = {}
            for item in raw:
                name = item.get("name", "unknown")
                url = item["url"].replace("{username}", "{}").replace("{user}", "{}").replace("{0}", "{}")
                rules = {"url": url, "category": item.get("category", "uncategorized")}
                check = item.get("check", "status_code")
                valid = item.get("valid", 200)
                if check == "status_code":
                    rules["error_type"] = "status_code"
                    rules["error_criteria"] = "404"
                elif check == "response_body":
                    rules["error_type"] = "message"
                    rules["error_criteria"] = item.get("error_msg", "")
                if "headers" in item:
                    rules["headers"] = item["headers"]
                if "regex" in item:
                    rules["regex"] = item["regex"]
                elif "username_validator" in item:
                    rules["username_validator"] = item["username_validator"]
                if item.get("browser"):
                    rules["use_browser"] = True
                sites[name] = rules
        else:
            sites = raw
            for name, rules in sites.items():
                if "url" not in rules or "error_type" not in rules:
                    raise SiteConfigError(
                        f"Site '{name}' is missing required 'url' or 'error_type' key"
                    )
        return sites

    def _filter_sites(self) -> dict:
        sites = self.sites

        if self.include is not None:
            include_lower = {i.lower() for i in self.include}
            sites = {
                name: rules
                for name, rules in sites.items()
                if name.lower() in include_lower
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
        sites = {
            name: rules
            for name, rules in sites.items()
            if not self._skip_by_username_validator(name, rules)
        }
        return sites

    def _skip_by_username_validator(self, name: str, rules: dict) -> bool:
        pattern = rules.get("regex") or rules.get("username_validator")
        if not pattern:
            return False
        try:
            return not re.match(pattern, self.username)
        except re.error:
            return False

    async def _ensure_browser(self) -> bool:
        if self._browser is not None:
            return True
        if not self.render or not playwright_available():
            return False
        self._browser = BrowserChecker(proxy=self.proxy)
        ok = await self._browser.start()
        if not ok:
            self._browser = None
        return ok

    async def check_platform_browser(self, name: str, rules: dict) -> dict:
        target_url = rules["url"].format(self.username)
        ok = await self._ensure_browser()
        if not ok:
            return {"status": "UNKNOWN", "url": target_url, "error": "BROWSER_UNAVAILABLE"}
        async with self._semaphore:
            result = await self._browser.check(target_url, timeout=self.timeout, username=self.username)
        if result["error"]:
            return {"status": "UNKNOWN", "url": target_url, "error": result["error"]}
        if result["is_login_wall"]:
            return {"status": "LOGIN_WALL", "url": result["final_url"]}
        html = result["html"]
        title = result["title"]
        if not title:
            return {"status": "NOT_FOUND", "url": result["final_url"]}
        if _looks_generic(title, name):
            return {"status": "NOT_FOUND", "url": result["final_url"]}
        if name.lower() == "instagram":
            pat = f"(@{self.username.lower()}) • instagram photos and videos"
            if title.lower().strip() == pat:
                return {"status": "NOT_FOUND", "url": result["final_url"]}
        final_url = result["final_url"]
        status_code = result.get("status", 200)
        has_user = self.username.lower() in title.lower()
        conf = _confidence_score(html[:50000], rules, has_user)
        return {
            "status": "FOUND",
            "url": final_url,
            "title": title,
            "browser_rendered": True,
            "confidence": conf,
        }

    async def check_platform(
        self, client: httpx.AsyncClient, name: str, rules: dict, attempt: int = 1
    ) -> dict:
        target_url = rules["url"].format(self.username)
        headers = {"User-Agent": random_user_agent()}
        if "headers" in rules:
            headers.update(rules["headers"])

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

        if response.status_code in (403, 429, 503, 999):
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
            emails = clean_emails(_EMAIL_RE.findall(text))
            title_match = _TITLE_RE.search(response.text)
            title = title_match.group(1).strip() if title_match else ""
            title = _STRIP_NON_ENCODABLE.sub("", title).strip()
            if not title or _looks_generic(title, name):
                if name.lower() == "instagram":
                    try:
                        oembed_url = f"https://api.instagram.com/oembed?url={target_url}"
                        oresp = await client.get(oembed_url)
                        if oresp.status_code == 200:
                            odata = oresp.json()
                            thumb = odata.get("thumbnail_url")
                            if thumb:
                                return {"status": "FOUND", "url": target_url, "title": odata.get("title", title), "emails": emails, "confidence": 85}
                    except Exception:
                        pass
                if _login_wall_confirms_user(text, self.username):
                    return {"status": "FOUND", "url": target_url, "title": title or name, "login_wall": True, "emails": emails, "confidence": 60}
                return {"status": "NOT_FOUND", "url": target_url}
            desc_match = _META_DESC_RE.search(response.text[:200000])
            description = desc_match.group(1).strip() if desc_match else None
            if description:
                description = _STRIP_NON_ENCODABLE.sub("", description).strip() or None
            has_user = self.username.lower() in title.lower()
            conf = _confidence_score(response.text[:50000], rules, has_user)
            return {
                "status": "FOUND",
                "url": target_url,
                "title": title,
                "description": description,
                "emails": emails,
                "confidence": conf,
            }

        return {"status": "UNKNOWN", "url": target_url, "error": f"HTTP_{response.status_code}"}

    def _build_url_reverse_map(self) -> list[tuple[re.Pattern, str]]:
        patterns = []
        for name, rules in self.sites.items():
            tmpl = rules["url"]
            if "{}" in tmpl:
                escaped = re.escape(tmpl.replace("{}", "__U__"))
                prefix = escaped.replace("__U__", "(?P<user>[^/?#]+)")
                try:
                    patterns.append((re.compile(prefix), name))
                except re.error:
                    pass
                if "://www." in tmpl:
                    no_www_tmpl = tmpl.replace("://www.", "://", 1)
                    no_www_escaped = re.escape(no_www_tmpl.replace("{}", "__U__"))
                    no_www_prefix = no_www_escaped.replace("__U__", "(?P<user>[^/?#]+)")
                    try:
                        patterns.append((re.compile(no_www_prefix), name))
                    except re.error:
                        pass
        return patterns

    @staticmethod
    def _extract_profile_links(html: str, patterns: list[tuple[re.Pattern, str]], current_user: str) -> dict[str, set[str]]:
        discovered: dict[str, set[str]] = {}
        for link in re.findall(r'href=["\'](https?://[^"\' ]+)["\']', html):
            for pat, plat in patterns:
                m = pat.search(link)
                if m:
                    user = m.group("user").lower()
                    if user and user != current_user.lower():
                        discovered.setdefault(plat, set()).add(user)
        return discovered

    async def recursive_scan(self, max_depth: int = 2, quiet: bool = False) -> dict[str, dict]:
        original_username = self.username
        all_results: dict[str, dict] = {}
        scanned: set[str] = set()
        patterns = self._build_url_reverse_map()

        queue: list[tuple[str, str | None, str | None]] = [(self.username, None, None)]

        for depth in range(max_depth):
            if not queue:
                break
            batch = queue
            queue = []
            for handle, src_plat, src_handle in batch:
                if handle in scanned:
                    continue
                scanned.add(handle)
                if not quiet and handle != original_username:
                    console.print(f"  [cyan]Recursive[/cyan] [white]{handle}[/white] "
                                  f"(from [bold]{src_plat}[/bold] by [dim]{src_handle}[/dim])")
                self.username = handle
                results = await self.run_scan(quiet=quiet)
                for plat, info in results.items():
                    uid = f"{handle}|{plat}"
                    info["_handle"] = handle
                    info["_source_plat"] = src_plat
                    info["_source_handle"] = src_handle
                    all_results[uid] = info
                if depth + 1 < max_depth:
                    found_plats = {p for p, r in results.items() if r.get("status") == "FOUND" and r.get("url")}
                    if found_plats:
                        async with build_client(proxy=self.proxy, use_tor=self.use_tor, timeout=self.timeout, http2=self.http2) as client:
                            for plat in found_plats:
                                html = await self._fetch_page(results[plat]["url"], client, retries=1)
                                if html:
                                    for p, users in self._extract_profile_links(html, patterns, handle).items():
                                        for u in users:
                                            if u not in scanned:
                                                queue.append((u, p, handle))

        self.username = original_username
        return all_results

    @staticmethod
    async def _fetch_page(url: str, client: httpx.AsyncClient, retries: int = 1) -> str | None:
        for _ in range(retries + 1):
            try:
                resp = await client.get(url, headers={"User-Agent": random_user_agent()})
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                pass
        return None

    async def run_scan(
        self, *, quiet: bool = False, stats: dict | None = None
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}
        sites = self._filter_sites()

        if not sites:
            console.print("[bold yellow]No sites match the given filters.[/bold yellow]")
            return results

        browser_sites = {n: r for n, r in sites.items() if r.get("use_browser")}
        http_sites = {n: r for n, r in sites.items() if not r.get("use_browser")}

        async def run_http_sites():
            nonlocal results
            if not http_sites:
                return
            async with build_client(
                proxy=self.proxy,
                use_tor=self.use_tor,
                timeout=self.timeout,
                http2=self.http2,
            ) as client:
                if quiet:
                    tasks = [self.check_platform(client, n, r) for n, r in http_sites.items()]
                    outcomes = await asyncio.gather(*tasks)
                    for (name, _), outcome in zip(http_sites.items(), outcomes):
                        results[name] = outcome
                else:
                    with make_progress() as progress:
                        task_id = progress.add_task(
                            "[cyan]Scanning (HTTP)...", total=len(http_sites)
                        )
                        async def run_one(name: str, rules: dict) -> None:
                            outcome = await self.check_platform(client, name, rules)
                            results[name] = outcome
                            _print_found(progress, outcome, stats, name, len(http_sites))
                            progress.advance(task_id)
                        await asyncio.gather(
                            *(run_one(n, r) for n, r in http_sites.items())
                        )

        async def run_browser_sites():
            nonlocal results
            if not browser_sites:
                return
            if not await self._ensure_browser():
                if not quiet:
                    console.print("[yellow]Browser unavailable — skipping browser-required sites.[/yellow]")
                    console.print("[yellow]  Install: pip install \"argis[render]\" && playwright install chromium[/yellow]")
                    console.print("[yellow]  Then re-run: argis scan ... --render[/yellow]")
                for name in browser_sites:
                    results[name] = {"status": "SKIPPED", "url": browser_sites[name]["url"].format(self.username)}
                return
            try:
                if quiet:
                    tasks = [self.check_platform_browser(n, r) for n, r in browser_sites.items()]
                    outcomes = await asyncio.gather(*tasks)
                    for (name, _), outcome in zip(browser_sites.items(), outcomes):
                        results[name] = outcome
                else:
                    with make_progress() as progress:
                        task_id = progress.add_task(
                            "[cyan]Scanning (Browser)...", total=len(browser_sites)
                        )
                        async def run_one_browser(name: str, rules: dict) -> None:
                            outcome = await self.check_platform_browser(name, rules)
                            results[name] = outcome
                            _print_found(progress, outcome, stats, name, len(browser_sites))
                            progress.advance(task_id)
                        await asyncio.gather(
                            *(run_one_browser(n, r) for n, r in browser_sites.items())
                        )
            finally:
                if self._browser:
                    await self._browser.close()

        await asyncio.gather(run_http_sites(), run_browser_sites())

        return results


def extract_categories(sites_path: pathlib.Path | None = None) -> list[str]:
    path = sites_path or (pathlib.Path(__file__).parent / "sites.json")
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    cats = set()
    data = raw if isinstance(raw, list) else raw.values()
    for entry in data:
        cat = entry.get("category", "uncategorized") if isinstance(entry, dict) else "uncategorized"
        cats.add(cat.lower())
    return sorted(cats)


def build_email_map(all_results: dict[str, dict]) -> dict[str, list[str]]:
    email_map: dict[str, list[str]] = {}
    for platform, info in all_results.items():
        if info.get("status") == "FOUND" and info.get("emails"):
            email_map[platform] = info["emails"]
    return email_map


def _print_found(progress, outcome: dict, stats, name: str, total: int) -> None:
    if outcome["status"] == "FOUND":
        progress.console.print(
            f"  [bold green]\u2713[/bold green] [white]{name}:[/white] "
            f"[underline cyan]{outcome['url']}[/underline cyan]"
        )
    if stats is not None:
        st = outcome["status"]
        stats["by_status"][st] = stats["by_status"].get(st, 0) + 1
        stats["done"] += 1
        stats["total"] = total
        err = outcome.get("error")
        if err and st in ("UNKNOWN", "TIMEOUT"):
            stats["by_error"][err] = stats["by_error"].get(err, 0) + 1


SITES_RAW_URL = "https://raw.githubusercontent.com/Mohilisop/argis/main/src/argis/sites.json"


def update_sites_file() -> Path:
    """Fetch the latest sites.json from GitHub and save to ~/.argis/sites.json."""
    import httpx as _httpx
    dest = Path.home() / ".argis" / "sites.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        resp = _httpx.get(SITES_RAW_URL, follow_redirects=True, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
        dest.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        console.print(f"[green]Sites updated from GitHub ({len(raw)} platforms)[/green]")
    except Exception as exc:
        if dest.exists():
            console.print(f"[yellow]Update failed ({exc}), using cached ~/.argis/sites.json[/yellow]")
        else:
            console.print(f"[red]Update failed ({exc})[/red]")
            raise SiteConfigError("Could not fetch sites.json from GitHub") from exc
    return dest
