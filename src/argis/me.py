"""argis me: unified self-assessment.

Runs the full intelligence stack on YOUR handle and produces a single
threat report: what's exposed, what's leaked, who's impersonating you,
and a ranked fix-list.

This is the product. Everything else is infrastructure for this.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class FixAction:
    priority: int = 0
    points_saved: float = 0.0
    what: str = ""
    where: list[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    handle: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    accounts_found: int = 0
    platforms_scanned: int = 0
    accounts: dict = field(default_factory=dict)

    exposure_score: float = 0.0
    exposure_grade: str = "?"
    exposure_factors: list = field(default_factory=list)

    emails_checked: int = 0
    emails_breached: int = 0
    breaches: list = field(default_factory=list)

    lookalikes_scanned: int = 0
    impersonators_found: int = 0
    impersonators: list = field(default_factory=list)

    geo_signals: list = field(default_factory=list)

    code_mentions: int = 0
    dorks: list = field(default_factory=list)

    actions: list[FixAction] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.exposure_score >= 70 or self.emails_breached >= 2 or self.impersonators_found >= 1:
            return "HIGH"
        if self.exposure_score >= 40 or self.emails_breached >= 1:
            return "MEDIUM"
        return "LOW"


async def run_me(
    handle: str,
    *,
    timeout: float = 12.0,
    concurrency: int = 20,
    proxy: str | None = None,
    use_tor: bool = False,
    skip_impersonation: bool = False,
    max_variants: int = 60,
) -> ThreatReport:
    from argis.utils.display import console

    report = ThreatReport(handle=handle)

    # === PHASE 1: scan ===
    console.print("[bold green][1/6][/bold green] [white]Scanning handle...[/white]")
    from argis.core import ArgisEngine
    engine = ArgisEngine(
        handle, timeout=timeout, concurrency=concurrency,
        proxy=proxy, use_tor=use_tor,
    )
    results = await engine.run_scan(quiet=True)
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    report.accounts = found
    report.accounts_found = len(found)
    report.platforms_scanned = len(results)

    emails = sorted({e for r in found.values() for e in r.get("emails", [])})
    display_names = {p: r["display_name"] for p, r in found.items() if r.get("display_name")}
    sites = engine._filter_sites()
    cats_map = {p: rules.get("category", "forums") for p, rules in sites.items()}

    # === PHASE 2: exposure score ===
    console.print("[bold green][2/6][/bold green] [white]Scoring exposure...[/white]")
    try:
        from argis.exposure import assess
        exp = assess(handle, found, emails=emails, display_names=display_names,
                     categories=cats_map)
        report.exposure_score = exp.overall
        report.exposure_grade = exp.grade
        report.exposure_factors = exp.factors
        for a in exp.shrink_plan:
            pts = round(a.impact * 15, 1)
            report.actions.append(FixAction(
                points_saved=pts, what=f"Close or lock {a.platform}",
                where=[a.url]))
    except Exception:
        pass

    # === PHASE 3: breach check ===
    console.print("[bold green][3/6][/bold green] [white]Checking breaches...[/white]")
    if emails:
        try:
            from argis.breach import check_all
            breach_reports = await check_all(emails)
            report.emails_checked = len(emails)
            report.emails_breached = sum(1 for b in breach_reports if b.compromised)
            report.breaches = breach_reports
            if report.emails_breached > 0:
                breached_emails = [b.email for b in breach_reports if b.compromised]
                report.actions.insert(0, FixAction(
                    points_saved=20.0,
                    what=f"Change passwords for {report.emails_breached} breached email(s) and enable 2FA everywhere",
                    where=breached_emails,
                ))
        except Exception:
            pass

    # === PHASE 4: impersonation check ===
    if not skip_impersonation:
        console.print("[bold green][4/6][/bold green] [white]Checking for impersonators...[/white]")
        try:
            from argis.impersonate import guard
            g = await guard(
                handle, max_variants=max_variants, warn_threshold=0.55,
                timeout=timeout, concurrency=concurrency // 2,
                proxy=proxy, use_tor=use_tor,
            )
            report.lookalikes_scanned = g.variants_scanned
            report.impersonators_found = len(g.impersonators)
            report.impersonators = g.impersonators
            if g.impersonators:
                report.actions.insert(0, FixAction(
                    points_saved=25.0,
                    what=f"Report {len(g.impersonators)} likely impersonator(s)",
                    where=[f"{m.variant} on {m.platform}" for m in g.impersonators[:5]],
                ))
        except Exception:
            pass
    else:
        console.print("[bold green][4/6][/bold green] [dim]Impersonation check skipped[/dim]")

    # === PHASE 5: geo inference ===
    console.print("[bold green][5/6][/bold green] [white]Inferring location...[/white]")
    try:
        from argis.geo_infer import infer_geo
        bios = [r.get("description", "") for r in found.values() if r.get("description")]
        titles = [r.get("title", "") for r in found.values() if r.get("title")]
        report.geo_signals = infer_geo(bios, titles, list(found.keys()))
    except Exception:
        pass

    # === PHASE 6: mentions ===
    console.print("[bold green][6/6][/bold green] [white]Searching public mentions...[/white]")
    try:
        from argis.mentions import scan_mentions
        m = await scan_mentions(handle, emails)
        report.code_mentions = len(m.mentions)
        report.dorks = m.dorks
        if m.mentions:
            report.actions.append(FixAction(
                points_saved=10.0,
                what=f"Review {len(m.mentions)} public code/paste mention(s) of your handle",
                where=[mt.url for mt in m.mentions[:5]],
            ))
    except Exception:
        pass

    report.actions.sort(key=lambda a: -a.points_saved)
    for i, a in enumerate(report.actions, 1):
        a.priority = i

    return report
