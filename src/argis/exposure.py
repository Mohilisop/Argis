"""Privacy exposure scoring for Argis.

After a scan, assess how much of the target's identity is exposed online.
Score 0 (ghost) -> 100 (fully doxxed). A shrink plan suggests concrete
take-down actions ranked by impact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

_EMAIL_RX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_SENSITIVITY: dict[str, float] = {
    "social": 1.0,
    "dating": 1.0,
    "messaging": 0.9,
    "professional": 0.8,
    "coding": 0.6,
    "gaming": 0.5,
    "media": 0.4,
    "shopping": 0.7,
    "transport": 0.7,
    "finance": 0.9,
    "health": 0.9,
    "adult": 1.0,
    "forums": 0.6,
    "email": 0.8,
    "blog": 0.5,
    "news": 0.3,
    "education": 0.5,
    "government": 0.7,
    "entertainment": 0.4,
    "cloud": 0.6,
    "devtools": 0.5,
    "photo": 0.6,
    "music": 0.4,
    "video": 0.5,
    "crowdfunding": 0.6,
    "review": 0.4,
    "anonymous": 0.1,
}


@dataclass
class Factor:
    name: str
    score: float
    weight: float
    detail: str = ""


@dataclass
class Action:
    platform: str
    url: str
    impact: float
    reason: str


@dataclass
class ExposureReport:
    username: str
    overall: float
    grade: str
    factors: list[Factor] = field(default_factory=list)
    shrink_plan: list[Action] = field(default_factory=list)
    category_breakdown: dict[str, int] = field(default_factory=dict)
    found: int = 0
    emails_leaked: list[str] = field(default_factory=list)
    real_name_consistency: float = 0.0


def _name_similarity(names: list[str], handle: str) -> float:
    if not names:
        return 0.0
    tokens = handle.lower()
    scores = []
    for n in names:
        n = n.lower().strip()
        if not n:
            continue
        if n == tokens:
            scores.append(1.0)
        elif n in tokens or tokens in n:
            scores.append(0.7)
        else:
            scores.append(SequenceMatcher(None, n, tokens).ratio())
    return sum(scores) / len(scores) if scores else 0.0


def assess(
    username: str,
    found: dict[str, dict],
    emails: list[str] | None = None,
    display_names: dict[str, str] | None = None,
    categories: dict[str, str] | None = None,
) -> ExposureReport:
    cats = categories or {}
    names = display_names or {}
    email_list = emails or []
    platforms = {p: r for p, r in found.items() if r.get("status") == "FOUND"}
    n = len(platforms)
    if n == 0:
        return ExposureReport(
            username=username, overall=0.0, grade="A",
            factors=[Factor("No accounts found", 0.0, 1.0)],
        )

    factors: list[Factor] = []

    factor_footprint = min(1.0, n / 20)
    factors.append(Factor("Footprint breadth", factor_footprint, 0.25,
                          f"{n} platforms"))

    sensitivity_total = 0.0
    cat_buckets: dict[str, int] = {}
    for p in platforms:
        c = cats.get(p, "forums")
        sensitivity_total += _SENSITIVITY.get(c, 0.5)
        cat_buckets[c] = cat_buckets.get(c, 0) + 1
    avg_sens = sensitivity_total / n
    factors.append(Factor("Category sensitivity", avg_sens, 0.20,
                          f"avg {avg_sens:.2f} across {len(cat_buckets)} categories"))

    email_score = 0.0
    leaked: list[str] = []
    for e in email_list:
        if _EMAIL_RX.match(e):
            leaked.append(e)
    if leaked:
        email_score = min(1.0, len(leaked) * 0.25)
    factors.append(Factor("Email leakage", email_score, 0.20,
                          f"{len(leaked)} email(s) exposed"))

    name_sim = _name_similarity(list(names.values()), username)
    factors.append(Factor("Real-name consistency", name_sim, 0.15,
                          f"similarity {name_sim:.2f}"))

    avatar_factor = 0.0
    with_avatar = sum(1 for r in platforms.values() if r.get("has_avatar"))
    if n > 0:
        avatar_factor = with_avatar / n
    factors.append(Factor("Avatar reuse", avatar_factor, 0.10,
                          f"{with_avatar}/{n} profiles have avatars"))

    interlink = 0.0
    all_links: list[str] = []
    for r in platforms.values():
        links = r.get("links_domains") or []
        all_links.extend(links)
    unique = len(set(all_links))
    if unique > 1:
        interlink = min(1.0, unique / 5)
    factors.append(Factor("Cross-platform interlinking", interlink, 0.10,
                          f"{unique} unique domain(s) referenced"))

    wsum = sum(f.weight for f in factors)
    overall = sum(f.score * f.weight for f in factors) / wsum
    score = round(overall * 100, 1)

    if score <= 15:
        grade = "A"
    elif score <= 35:
        grade = "B"
    elif score <= 55:
        grade = "C"
    elif score <= 75:
        grade = "D"
    else:
        grade = "F"

    shrink: list[Action] = []
    for p, r in sorted(platforms.items()):
        impact = _SENSITIVITY.get(cats.get(p, "forums"), 0.5)
        if email_list and any(e in str(r) for e in email_list):
            impact += 0.2
        if cats.get(p) in ("dating", "adult"):
            impact += 0.3
        impact = min(1.0, impact)
        shrink.append(Action(p, r["url"], round(impact, 2),
                              f"category={cats.get(p, 'unknown')}"))

    shrink.sort(key=lambda a: (-a.impact, a.platform))

    return ExposureReport(
        username=username,
        overall=score,
        grade=grade,
        factors=factors,
        shrink_plan=shrink,
        category_breakdown=cat_buckets,
        found=n,
        emails_leaked=leaked,
        real_name_consistency=round(name_sim, 3),
    )