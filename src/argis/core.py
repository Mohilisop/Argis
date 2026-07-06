"""The operational heart of Argis: loads site rules, runs concurrent async
HTTP checks, and applies detection rules to filter out false positives."""

from __future__ import annotations

import asyncio
import json
import pathlib

import httpx

from argis.exceptions import SiteConfigError
from argis.utils.display import console, make_progress, print_found
from argis.utils.network import build_client, random_user_agent

# Generic markers that indicate a WAF/bot-challenge page rather than a real
# answer about account existence (e.g. Cloudflare's "Client Challenge",
# reCAPTCHA walls). These can return HTTP 200, so status-code rules alone
# would misread them as FOUND. Checked before any per-site rule runs.
_CHALLENGE_MARKERS = (
    "client challenge",
    "checking your browser",
    "attention required",
    "verify you are human",
    "just a moment...",
    "captcha",
)


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
    ):
        self.username = username
        self.proxy = proxy
        self.use_tor = use_tor
        self.timeout = timeout
        self.sites = self._load_sites(sites_path)
        self._semaphore = asyncio.Semaphore(concurrency)

    def _load_sites(self, sites_path: pathlib.Path | None) -> dict:
        """Locate and load target site config relative to the package path."""
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

    async def check_platform(
        self, client: httpx.AsyncClient, name: str, rules: dict
    ) -> dict:
        """Evaluate a single site against its detection rule. Never raises."""
        target_url = rules["url"].format(self.username)
        headers = {"User-Agent": random_user_agent()}

        async with self._semaphore:
            try:
                response = await client.get(target_url, headers=headers)
            except httpx.TooManyRedirects:
                return {"status": "UNKNOWN", "url": target_url}
            except httpx.TimeoutException:
                return {"status": "TIMEOUT", "url": target_url}
            except httpx.RequestError:
                return {"status": "UNKNOWN", "url": target_url}
            except Exception:
                # Catches low-level transport/protocol errors that escape
                # httpx's own exception hierarchy (e.g. a raw h2.ProtocolError
                # from a connection torn down mid-handshake under high
                # concurrency). A single misbehaving connection should never
                # take down the whole scan's asyncio.gather.
                return {"status": "UNKNOWN", "url": target_url}

        # 429 / 403 usually mean a WAF or rate limiter intervened, not a
        # legitimate answer about account existence.
        if response.status_code in (403, 429):
            return {"status": "BLOCKED", "url": target_url}

        # Some WAFs (e.g. Cloudflare) serve a challenge page with a 200,
        # which would otherwise be misread as a legitimate FOUND result.
        lowered_text = response.text[:2000].lower()
        if any(marker in lowered_text for marker in _CHALLENGE_MARKERS):
            return {"status": "BLOCKED", "url": target_url}

        error_type = rules["error_type"]
        error_criteria = rules.get("error_criteria")

        if error_type == "status_code":
            if response.status_code == int(error_criteria):
                return {"status": "NOT_FOUND", "url": target_url}
        elif error_type == "message":
            if error_criteria and error_criteria in response.text:
                return {"status": "NOT_FOUND", "url": target_url}
        elif error_type == "response_url":
            if error_criteria and str(response.url).rstrip("/") == error_criteria.rstrip("/"):
                return {"status": "NOT_FOUND", "url": target_url}

        if response.status_code == 200:
            return {"status": "FOUND", "url": target_url}

        return {"status": "UNKNOWN", "url": target_url}

    async def run_scan(self, *, quiet: bool = False) -> dict[str, dict]:
        """Run all site checks concurrently with a live progress bar."""
        results: dict[str, dict] = {}

        async with build_client(
            proxy=self.proxy, use_tor=self.use_tor, timeout=self.timeout
        ) as client:
            if quiet:
                tasks = [
                    self.check_platform(client, name, rules)
                    for name, rules in self.sites.items()
                ]
                outcomes = await asyncio.gather(*tasks)
                for (name, _), outcome in zip(self.sites.items(), outcomes):
                    results[name] = outcome
                return results

            with make_progress() as progress:
                task_id = progress.add_task(
                    "[yellow]Probing networks...", total=len(self.sites)
                )

                async def run_one(name: str, rules: dict) -> None:
                    outcome = await self.check_platform(client, name, rules)
                    results[name] = outcome
                    if outcome["status"] == "FOUND":
                        progress.console.print(
                            f"[bold green][+][/bold green] [white]{name}:[/white] "
                            f"[underline cyan]{outcome['url']}[/underline cyan]"
                        )
                    progress.advance(task_id)

                await asyncio.gather(
                    *(run_one(name, rules) for name, rules in self.sites.items())
                )

        return results
