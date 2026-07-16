import asyncio
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


@dataclass
class AgentContext:
    target: InvestigationTarget
    client: httpx.AsyncClient
    findings: dict[int, list[Finding]] = field(default_factory=dict)
    shared_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)

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
    def __init__(self, agent_id: int, name: str, category: FindingCategory, description: str = ""):
        self.agent_id = agent_id
        self.name = name
        self.category = category
        self.description = description
        self._max_retries = 1
        self._retry_delay = 1.0

    async def investigate(self, ctx: AgentContext) -> None:
        for attempt in range(self._max_retries + 1):
            try:
                await self._run(ctx)
                return
            except asyncio.CancelledError:
                return
            except Exception as e:
                if attempt < self._max_retries:
                    await asyncio.sleep(self._retry_delay)
                    continue
                ctx.add_error(self.agent_id, f"{self.name}: {e}")

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
        try:
            r = await ctx.client.get(url, timeout=timeout, follow_redirects=True)
            return r.status_code, r.text, dict(r.headers)
        except httpx.TimeoutException:
            return 0, "", {}
        except Exception:
            return 0, "", {}
