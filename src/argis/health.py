"""Self-healing site-rule health checks.

Every OSINT username scanner shares the same silent failure mode: a platform
changes its markup or its 404 behaviour, the rule in ``sites.json`` rots, and
nobody notices until a user reports a false result months later.

This module re-runs every rule against a *known-real* and a *known-fake*
username and reports which rules still behave correctly.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import secrets
import string
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from argis.core import ArgisEngine
from argis.utils.network import build_client

# Statuses that let us draw no conclusion about a rule's health.
INCONCLUSIVE_STATUSES = {"BLOCKED", "TIMEOUT", "UNKNOWN"}

# Known-real, stable accounts for the positive pass. A rule is positive-checked
# only if it appears here OR carries a "test_account" key in sites.json (the
# sites.json value wins). Keep these long-lived and obviously public so the
# check never cries wolf. Extend freely.
KNOWN_ACCOUNTS: dict[str, str] = {
    "GitHub": "torvalds",
    "GitLab": "gitlab-org",
    "Docker Hub": "library",
    "PyPI": "dstufft",
    "Reddit": "spez",
    "Instagram": "instagram",
    "YouTube": "youtube",
    "Twitch": "twitch",
    "TikTok": "tiktok",
    "SoundCloud": "soundcloud",
    "Steam": "gabelogannewell",
    "Chess.com": "hikaru",
    "Telegram": "telegram",
    "Patreon": "patreon",
    "Dribbble": "dribbble",
    "Behance": "behance",
    "Medium": "medium",
    "Dev.to": "ben",
    "Keybase": "max",
    "Hacker News": "pg",
}


@dataclass
class Check:
    site: str
    kind: str
    username: str
    expected: str
    got: str
    verdict: str
    url: str = ""
    note: str = ""


@dataclass
class HealthReport:
    checks: list[Check] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def broken(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == "BROKEN"]

    @property
    def inconclusive(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == "INCONCLUSIVE"]

    @property
    def passed(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == "PASS"]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "summary": {
                "total": len(self.checks),
                "passed": len(self.passed),
                "broken": len(self.broken),
                "inconclusive": len(self.inconclusive),
                "duplicate_rules": len(self.duplicates),
            },
            "duplicates": self.duplicates,
            "checks": [asdict(c) for c in self.checks],
        }

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append("# \U0001FA7A Argis site-rule health report")
        lines.append("")
        lines.append(f"_Generated {self.generated_at} (UTC)._")
        lines.append("")
        lines.append(
            f"**{len(self.passed)} healthy \u00b7 {len(self.broken)} broken \u00b7 "
            f"{len(self.inconclusive)} inconclusive** across {len(self.checks)} checks."
        )
        lines.append("")
        if self.broken:
            lines.append("## \u274c Broken rules")
            lines.append("")
            lines.append("| Platform | Check | Username | Expected | Got | Why |")
            lines.append("|---|---|---|---|---|---|")
            for c in self.broken:
                lines.append(
                    f"| {c.site} | {c.kind} | `{c.username}` | {c.expected} | "
                    f"{c.got} | {c.note} |"
                )
            lines.append("")
        else:
            lines.append("## \u2705 No broken rules detected")
            lines.append("")
        if self.duplicates:
            lines.append("## \u26a0\ufe0f Duplicate rule names in sites.json")
            lines.append("")
            lines.append(
                "These platform names appear more than once. JSON keeps only the "
                "last definition, so the earlier rules are silently dead:"
            )
            lines.append("")
            for name in self.duplicates:
                lines.append(f"- `{name}`")
            lines.append("")
        if self.inconclusive:
            lines.append(
                f"<details><summary>\u2139\ufe0f {len(self.inconclusive)} inconclusive "
                "(blocked / timeout / network) \u2014 no action needed</summary>"
            )
            lines.append("")
            for c in self.inconclusive:
                lines.append(f"- {c.site} ({c.kind}): {c.got}")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        return "\n".join(lines)


def _improbable_username(length: int = 24) -> str:
    """A username that is virtually guaranteed not to exist anywhere."""
    alphabet = string.ascii_lowercase + string.digits
    return "argisdoctor" + "".join(secrets.choice(alphabet) for _ in range(length))


def _detect_duplicates(sites_path: pathlib.Path) -> list[str]:
    """Return platform names defined more than once in sites.json."""
    seen: dict[str, int] = defaultdict(int)

    def _hook(pairs):
        for key, _ in pairs:
            seen[key] += 1
        return dict(pairs)

    with open(sites_path, "r", encoding="utf-8") as fh:
        json.load(fh, object_pairs_hook=_hook)
    # Filter out JSON meta-keys that appear as top-level keys of every rule
    meta = {"category", "error_criteria", "error_type", "url"}
    return sorted(
        name for name, count in seen.items() if count > 1 and name not in meta
    )


class HealthChecker:
    def __init__(
        self,
        sites_path: pathlib.Path | None = None,
        *,
        timeout: float = 12.0,
        concurrency: int = 15,
        proxy: str | None = None,
        use_tor: bool = False,
        http2: bool = False,
        only: set[str] | None = None,
    ):
        self.sites_path = (
            pathlib.Path(sites_path)
            if sites_path
            else (pathlib.Path(__file__).parent / "sites.json")
        )
        with open(self.sites_path, "r", encoding="utf-8") as fh:
            sites = json.load(fh)
        if only:
            only_l = {o.lower() for o in only}
            sites = {n: r for n, r in sites.items() if n.lower() in only_l}
        self.sites = sites
        self.timeout = timeout
        self.concurrency = concurrency
        self.proxy = proxy
        self.use_tor = use_tor
        self.http2 = http2

    def _engine(self, username: str) -> ArgisEngine:
        return ArgisEngine(
            username,
            proxy=self.proxy,
            use_tor=self.use_tor,
            timeout=self.timeout,
            concurrency=self.concurrency,
            http2=self.http2,
            sites_path=self.sites_path,
            retry_blocked=False,
        )

    async def run(self) -> HealthReport:
        report = HealthReport()
        report.duplicates = _detect_duplicates(self.sites_path)
        report.checks.extend(await self._negative_pass())
        report.checks.extend(await self._positive_pass())
        return report

    async def _negative_pass(self) -> list[Check]:
        fake = _improbable_username()
        engine = self._engine(fake)
        async with build_client(
            proxy=self.proxy, use_tor=self.use_tor,
            timeout=self.timeout, http2=self.http2,
        ) as client:

            async def one(name: str, rules: dict) -> Check:
                out = await engine.check_platform(client, name, rules)
                got = out["status"]
                if got == "NOT_FOUND":
                    verdict, note = "PASS", ""
                elif got == "FOUND":
                    verdict = "BROKEN"
                    note = (
                        "rule reports FOUND for a username that cannot exist "
                        "(false-positive / detection too loose)"
                    )
                else:
                    verdict, note = "INCONCLUSIVE", got
                return Check(
                    site=name, kind="negative", username=fake,
                    expected="NOT_FOUND", got=got, verdict=verdict,
                    url=out.get("url", ""), note=note,
                )

            return list(
                await asyncio.gather(*(one(n, r) for n, r in self.sites.items()))
            )

    def _positive_targets(self) -> dict[str, dict]:
        """Map account -> {site: rules} for every positive-checkable site."""
        groups: dict[str, dict] = defaultdict(dict)
        for name, rules in self.sites.items():
            account = rules.get("test_account") or KNOWN_ACCOUNTS.get(name)
            if account:
                groups[account][name] = rules
        return groups

    async def _positive_pass(self) -> list[Check]:
        checks: list[Check] = []
        for account, subsites in self._positive_targets().items():
            engine = self._engine(account)
            async with build_client(
                proxy=self.proxy, use_tor=self.use_tor,
                timeout=self.timeout, http2=self.http2,
            ) as client:

                async def one(name: str, rules: dict, account: str = account) -> Check:
                    out = await engine.check_platform(client, name, rules)
                    got = out["status"]
                    if got == "FOUND":
                        verdict, note = "PASS", ""
                    elif got == "NOT_FOUND":
                        verdict = "BROKEN"
                        note = (
                            f"known-real account '{account}' reported NOT_FOUND "
                            "(rule signature likely changed / detection too strict)"
                        )
                    else:
                        verdict, note = "INCONCLUSIVE", got
                    return Check(
                        site=name, kind="positive", username=account,
                        expected="FOUND", got=got, verdict=verdict,
                        url=out.get("url", ""), note=note,
                    )

                checks.extend(
                    await asyncio.gather(*(one(n, r) for n, r in subsites.items()))
                )
        return checks