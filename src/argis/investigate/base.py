import asyncio
import hashlib
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import httpx


class FindingCategory(str, Enum):
    IDENTITY = "identity"
    SOCIAL = "social"
    PROFESSIONAL = "professional"
    DEEP_WEB = "deep_web"
    SPECIALIST = "specialist"


@dataclass
class Finding:
    agent_name: str
    agent_id: int
    category: FindingCategory
    title: str
    description: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    source_urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InvestigationTarget:
    username: str
    aliases: list[str] = field(default_factory=list)
    known_emails: list[str] = field(default_factory=list)
    known_platforms: list[str] = field(default_factory=list)
    known_domains: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


_FETCH_CACHE_TTL = 300.0

@dataclass
class _CacheEntry:
    status: int
    text: str
    headers: dict
    fetched_at: float


@dataclass
class AgentContext:
    target: InvestigationTarget
    client: httpx.AsyncClient
    findings: dict[int, list[Finding]] = field(default_factory=dict)
    shared_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    _http_cache: dict[str, _CacheEntry] = field(default_factory=dict)

    def add_finding(self, agent_id: int, finding: Finding) -> None:
        self.findings.setdefault(agent_id, []).append(finding)
        self.shared_data.setdefault("all_findings", []).append(finding)

    def add_error(self, agent_id: int, message: str) -> None:
        self.errors.append(f"[Agent {agent_id}] {message}")

    def get_findings(self, category: Optional[FindingCategory] = None) -> list[Finding]:
        results = self.shared_data.get("all_findings", [])
        if category:
            return [f for f in results if f.category == category]
        return results

    def get_evidence_urls(self) -> list[str]:
        seen: set[str] = set()
        urls: list[str] = []
        for f in self.get_findings():
            for u in f.source_urls:
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        return urls

    def get_known_emails(self) -> list[str]:
        return list(set(self.target.known_emails))

    def get_known_aliases(self) -> list[str]:
        return list(set(a for a in (self.target.aliases or []) if a))

    def cached_fetch(self, url: str) -> _CacheEntry | None:
        entry = self._http_cache.get(url)
        if entry is None:
            return None
        if time.monotonic() - entry.fetched_at > _FETCH_CACHE_TTL:
            del self._http_cache[url]
            return None
        return entry

    def cache_put(self, url: str, status: int, text: str, headers: dict) -> None:
        self._http_cache[url] = _CacheEntry(status=status, text=text, headers=headers, fetched_at=time.monotonic())

    def to_dict(self) -> dict:
        all_f = self.get_findings()
        return {
            "target": asdict(self.target),
            "findings": {str(aid): [f.to_dict() for f in flist] for aid, flist in self.findings.items()},
            "summary": {
                "total_findings": len(all_f),
                "high_confidence": len([f for f in all_f if f.confidence >= 0.8]),
                "medium_confidence": len([f for f in all_f if 0.5 <= f.confidence < 0.8]),
                "low_confidence": len([f for f in all_f if f.confidence < 0.5]),
                "categories": {cat.value: len([f for f in all_f if f.category == cat]) for cat in FindingCategory},
            },
            "errors": self.errors,
            "elapsed_seconds": round(time.time() - self.start_time, 2),
        }


class BaseAgent:
    MAX_RETRIES = 3
    BASE_RETRY_DELAY = 1.0
    MAX_RETRY_DELAY = 8.0

    def __init__(self, agent_id: int, name: str, category: FindingCategory, description: str = ""):
        self.agent_id = agent_id
        self.name = name
        self.category = category
        self.description = description
        self._max_retries = self.MAX_RETRIES
        self._base_retry_delay = self.BASE_RETRY_DELAY

    def _retry_delay_for(self, attempt: int) -> float:
        delay = self._base_retry_delay * (2 ** attempt)
        return min(delay, self.MAX_RETRY_DELAY)

    async def investigate(self, ctx: AgentContext) -> None:
        last_error = ""
        for attempt in range(self._max_retries + 1):
            try:
                await self._run(ctx)
                return
            except asyncio.CancelledError:
                return
            except httpx.TimeoutException as exc:
                last_error = f"Timeout: {exc}"
            except httpx.ConnectError as exc:
                last_error = f"Connection error: {exc}"
            except httpx.TooManyRedirects as exc:
                last_error = f"Redirect loop: {exc}"
            except httpx.HTTPStatusError as exc:
                last_error = f"HTTP {exc.response.status_code}"
                if exc.response.status_code in (403, 429):
                    delay = self._retry_delay_for(attempt) * 3
                    if attempt < self._max_retries:
                        await asyncio.sleep(delay)
                        continue
            except Exception as exc:
                last_error = str(exc)

            if attempt < self._max_retries:
                delay = self._retry_delay_for(attempt)
                await asyncio.sleep(delay)
                continue

        ctx.add_error(self.agent_id, f"{self.name}: {last_error}")

    async def _run(self, ctx: AgentContext) -> None:
        raise NotImplementedError

    def _emit(self, ctx: AgentContext, title: str, description: str, confidence: float,
              evidence: list[str] | None = None, urls: list[str] | None = None,
              metadata: dict | None = None) -> None:
        ctx.add_finding(self.agent_id, Finding(
            agent_name=self.name, agent_id=self.agent_id, category=self.category,
            title=title, description=description, confidence=confidence,
            evidence=evidence or [], source_urls=urls or [], metadata=metadata or {},
        ))

    def _read_shared(self, ctx: AgentContext, key: str, default: Any = None) -> Any:
        return ctx.shared_data.get(key, default)

    def _write_shared(self, ctx: AgentContext, key: str, value: Any) -> None:
        ctx.shared_data[key] = value

    async def _fetch(self, ctx: AgentContext, url: str, timeout: float = 10.0) -> tuple[int, str, dict]:
        cached = ctx.cached_fetch(url)
        if cached is not None:
            return cached.status, cached.text, cached.headers
        try:
            r = await ctx.client.get(url, timeout=timeout, follow_redirects=True)
            ctx.cache_put(url, r.status_code, r.text, dict(r.headers))
            return r.status_code, r.text, dict(r.headers)
        except httpx.TimeoutException:
            return 0, "", {}
        except httpx.ConnectError:
            return 0, "", {}
        except Exception:
            return 0, "", {}

    async def _fetch_json(self, ctx: AgentContext, url: str, timeout: float = 12.0) -> tuple[bool, dict]:
        status, text, _ = await self._fetch(ctx, url, timeout)
        if status != 200 or not text:
            return False, {}
        import json as _json
        try:
            return True, _json.loads(text)
        except (_json.JSONDecodeError, ValueError):
            return False, {}

    def _findings_for_category(self, ctx: AgentContext, category: FindingCategory | str) -> list[Finding]:
        if isinstance(category, FindingCategory):
            return ctx.get_findings(category)
        return [f for f in ctx.get_findings() if f.category.value == category]

    def _agent_has_finding(self, ctx: AgentContext, agent_name_fragment: str) -> bool:
        return any(agent_name_fragment.lower() in f.agent_name.lower() for f in ctx.get_findings())

    async def _extract_text(self, ctx: AgentContext, url: str) -> str:
        status, html, _ = await self._fetch(ctx, url)
        if not html or status != 200:
            return ""
        from argis.utils.extract_utils import visible_html
        return visible_html(html)

    async def _post(self, ctx: AgentContext, url: str, json_data: dict | None = None,
                    data: dict | None = None, timeout: float = 10.0) -> tuple[int, str]:
        try:
            kwargs: dict = {"timeout": timeout, "follow_redirects": True}
            if json_data is not None:
                r = await ctx.client.post(url, json=json_data, **kwargs)
            elif data is not None:
                r = await ctx.client.post(url, data=data, **kwargs)
            else:
                return 0, ""
            return r.status_code, r.text
        except Exception:
            return 0, ""
