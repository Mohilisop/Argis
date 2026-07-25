"""Argis console entry point with extension commands."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from argis.cli import app
from argis.diff import load_history
from argis.dossier_runtime import install_dossier_repair
from argis.echo import analyze_echo
from argis.exceptions import HistoryError
from argis.media_decisions import register_media_decision_commands
from argis.media_review import register_media_review_command
from argis.media_runtime import install_media_capture
from argis.utils.display import console
from argis.investigate import InvestigationOrchestrator, InvestigationTarget
from argis.email_gen import EmailPatternGenerator
from argis.password_check import PasswordLeakChecker

install_media_capture()
install_dossier_repair()
register_media_review_command(app)
register_media_decision_commands(app)


@app.command("echo", rich_help_panel="TRACKING")
def echo_command(
    username: str = typer.Argument(..., help="Username whose saved scan history should be analyzed."),
    window: int = typer.Option(72, "--window", "-w", min=1, help="Hours in which changes count as coordinated."),
    min_confidence: int = typer.Option(45, "--min-confidence", "-mc", min=0, max=100, help="Hide Echo events below this confidence."),
    json_output: bool = typer.Option(False, "--json", help="Print the complete Echo report as JSON."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the complete Echo report to a JSON file."),
) -> None:
    """Detect coordinated identity drift across saved scans."""
    try:
        history = load_history(username)
    except HistoryError as exc:
        console.print(f"[bold red]History error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if len(history) < 2:
        console.print(
            f"[yellow]Echo needs at least two saved scans for @{username}.[/yellow]\n"
            f"[dim]Run [green]argis scan {username}[/green] now, then scan again later.[/dim]"
        )
        raise typer.Exit(code=1)

    report = analyze_echo(history, username, coordination_window_hours=window, minimum_confidence=min_confidence)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if output is not None:
        output_path = output.expanduser().resolve()
        if output_path.suffix.lower() != ".json":
            output_path = output_path.with_suffix(".json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
        console.print(f"[green]Echo report written -> [underline]{output_path}[/underline][/green]")
    if json_output:
        console.print_json(payload)
        return
    _print_echo_report(report, username, window)


def _print_echo_report(report: dict, username: str, window: int) -> None:
    score = int(report.get("stability_score", 100))
    if score >= 80:
        stability_style, stability_label = "green", "STABLE"
    elif score >= 55:
        stability_style, stability_label = "yellow", "DRIFTING"
    else:
        stability_style, stability_label = "red", "VOLATILE"
    events = report.get("events", [])
    summary = (
        f"[bold]@{username}[/bold]\n"
        f"[dim]{report.get('snapshots_analyzed', 0)} snapshots, "
        f"{len(report.get('platforms_seen', []))} platforms, {window}h coordination window[/dim]\n\n"
        f"Identity stability: [{stability_style}][bold]{score}/100 ({stability_label})[/bold][/{stability_style}]\n"
        f"Identity epochs: [cyan]{report.get('identity_epochs', 0)}[/cyan]  Echo events: [cyan]{len(events)}[/cyan]"
    )
    console.print(Panel(summary, title="[bold green]ARGIS ECHO[/bold green]", border_style="green"))
    for warning in report.get("warnings", []):
        console.print(f"[yellow]! {warning}[/yellow]")
    if not events:
        console.print("[dim]No coordinated identity drift crossed the confidence threshold.[/dim]")
        return
    table = Table(show_header=True, header_style="bold dim", expand=True)
    table.add_column("When", no_wrap=True, width=19)
    table.add_column("Event", no_wrap=True)
    table.add_column("Conf.", justify="right", no_wrap=True)
    table.add_column("Platforms")
    table.add_column("Evidence")
    for event in events:
        confidence = int(event.get("confidence", 0))
        style = "red" if confidence >= 85 else "yellow" if confidence >= 65 else "cyan"
        table.add_row(
            str(event.get("observed_at", ""))[:19].replace("T", " "),
            str(event.get("event_type", "account_change")).replace("_", " "),
            f"[{style}]{confidence}%[/{style}]",
            ", ".join(event.get("platforms", [])),
            ", ".join(str(value).replace("_", " ") for value in event.get("fields", [])),
        )
    console.print(table)
    console.print("[dim]Use --json or -o FILE for full before/after evidence.[/dim]")


@app.command("investigate", rich_help_panel="INTELLIGENCE")
def investigate_command(
    username: str = typer.Argument(..., help="Username to deeply investigate."),
    aliases: Optional[str] = typer.Option(None, "--alias", "-a", help="Comma-separated known aliases."),
    emails: Optional[str] = typer.Option(None, "--email", "-e", help="Comma-separated known emails."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to JSON file."),
    markdown: Optional[Path] = typer.Option(None, "--markdown", "-m", help="Write report as Markdown."),
    html: Optional[Path] = typer.Option(None, "--html", "-h", help="Write report as HTML (advanced report)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-agent findings."),
    resume: bool = typer.Option(False, "--resume", "-r", help="Resume from previous scan checkpoint (skips re-scanning)."),
    generate_emails: bool = typer.Option(False, "--generate-emails", help="Generate and rank email address candidates."),
    check_passwords: bool = typer.Option(False, "--check-passwords", help="Analyze password patterns against breach data."),
) -> None:
    """Deep multi-agent investigation across 50 specialized AI agents (5 squads)."""
    import time

    alias_list = [a.strip() for a in aliases.split(",") if a.strip()] if aliases else []
    email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else []

    target = InvestigationTarget(username=username, aliases=alias_list, known_emails=email_list)
    orchestrator = InvestigationOrchestrator()

    console.print(f"[bold cyan]Argis Deep Investigation[/bold cyan]")
    console.print(f"[dim]Target: @{username} | Agents: 50 | Squads: 5[/dim]")
    if generate_emails:
        console.print(f"[dim]Email generation enabled[/dim]")
    if check_passwords:
        console.print(f"[dim]Password leak check enabled[/dim]")

    if resume:
        console.print("[dim]Resume mode enabled — scan will be skipped if checkpoint exists[/dim]")
    console.print()

    start = time.time()
    ctx = orchestrator.investigate_sync(target, resume=resume, generate_emails=generate_emails, check_passwords=check_passwords)
    elapsed = time.time() - start

    report = orchestrator.generate_report(ctx)
    data = report.to_dict()["report"]
    s = data["summary"]

    console.print(Panel(
        f"[bold]@{username}[/bold]\n"
        f"[dim]{s['total_findings']} findings • {s['high_confidence']} high-confidence • "
        f"{elapsed:.1f}s[/dim]",
        title="[bold green]INVESTIGATION COMPLETE[/bold green]",
    ))

    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Squad")
    table.add_column("Category")
    table.add_column("Findings")
    table.add_column("Top Agent")
    for squad_name, cat_enum, squad_label in [
        ("Alpha", "identity", "Core Identity"),
        ("Beta", "social", "Social Intel"),
        ("Gamma", "professional", "Professional"),
        ("Delta", "deep_web", "Deep Web"),
        ("Epsilon", "specialist", "Specialists"),
    ]:
        count = s.get("by_category", {}).get(cat_enum, 0)
        top = ""
        for f in data["findings"]:
            if f["category"] == cat_enum:
                top = f["agent_name"]
                break
        table.add_row(f"[cyan]{squad_name}[/cyan]", squad_label, str(count), top or "-")
    console.print(table)

    for score_name, score_val in data.get("scores", {}).items():
        label = score_name.replace("_", " ").title()
        color = "green" if score_val < 40 else "yellow" if score_val < 70 else "red"
        console.print(f"  [{color}]{label}: {score_val}/100[/{color}]")

    email_candidates = data.get("email_candidates", [])
    if email_candidates:
        console.print(f"\n[bold cyan]Email Candidates:[/bold cyan] {len(email_candidates)} generated")
        for c in email_candidates[:5]:
            pct = int(c["confidence"] * 100)
            badge = "green" if pct >= 80 else "yellow"
            breach_tag = " [red][BREACHED][/red]" if c.get("in_breach") else ""
            console.print(f"  [{badge}]{c['email']}[/{badge}] ({int(c['confidence']*100)}%){breach_tag}")
        if len(email_candidates) > 5:
            console.print(f"  [dim]... and {len(email_candidates) - 5} more[/dim]")

    pw_findings = data.get("password_check_findings", [])
    if pw_findings:
        console.print(f"\n[bold cyan]Password Leak Check:[/bold cyan]")
        pw_analysis = data.get("password_analysis", {})
        risk = pw_analysis.get("risk_assessment", {})
        grade = risk.get("grade", "N/A")
        score = risk.get("overall_score", 0)
        grade_color = "red" if score >= 70 else "yellow" if score >= 40 else "green"
        console.print(f"  Risk: [{grade_color}]{grade}[/{grade_color}] ({score}/100)")
        for rec in risk.get("recommendations", [])[:3]:
            console.print(f"  [dim]→ {rec}[/dim]")

    if verbose:
        console.print("\n[bold]Detailed Findings:[/bold]")
        for f in data["findings"]:
            pct = int(f["confidence"] * 100)
            color = "green" if pct >= 80 else "yellow" if pct >= 50 else "dim"
            console.print(f"  [{color}][{f'#{f["agent_id"]:02d}'}] {f['title']} ({pct}%)[/{color}]")
            console.print(f"    [dim]{f['description']}[/dim]")

    if output:
        p = output.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.to_json(), encoding="utf-8")
        console.print(f"[green]JSON report -> {p}[/green]")

    if markdown:
        p = markdown.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.to_markdown(), encoding="utf-8")
        console.print(f"[green]Markdown report -> {p}[/green]")

    if html:
        p = html.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.to_html(), encoding="utf-8")
        console.print(f"[green]HTML report -> {p}[/green]")


@app.command("emails", rich_help_panel="INTELLIGENCE")
def emails_command(
    username: str = typer.Argument(..., help="Username to generate emails for."),
    aliases: Optional[str] = typer.Option(None, "--alias", "-a", help="Comma-separated known aliases."),
    emails: Optional[str] = typer.Option(None, "--email", "-e", help="Comma-separated known emails."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to JSON file."),
) -> None:
    """Generate plausible email address patterns for a target username."""
    alias_list = [a.strip() for a in aliases.split(",") if a.strip()] if aliases else []
    email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else []

    gen = EmailPatternGenerator()
    candidates = gen.generate(
        username=username,
        aliases=alias_list,
        known_emails=email_list,
    )

    console.print(f"[bold cyan]Email Pattern Generator[/bold cyan]")
    console.print(f"[dim]Target: @{username} | Generated {len(candidates)} candidates[/dim]\n")

    from rich.table import Table
    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Email", width=40)
    table.add_column("Pattern")
    table.add_column("Confidence")
    for c in candidates[:20]:
        pct = int(c["confidence"] * 100)
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "dim"
        table.add_row(
            c["email"],
            c["pattern"],
            f"[{color}]{pct}%[/{color}]",
        )
    console.print(table)

    if len(candidates) > 20:
        console.print(f"[dim]... and {len(candidates) - 20} more candidates[/dim]")

    if output:
        p = output.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        import json
        result = {
            "target": username,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "candidates": candidates[:50],
            "stats": {"total_candidates": len(candidates)},
        }
        p.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]Output -> {p}[/green]")


@app.command("check-passwords", rich_help_panel="INTELLIGENCE")
def check_passwords_command(
    username: str = typer.Argument(..., help="Username to check password patterns for."),
    aliases: Optional[str] = typer.Option(None, "--alias", "-a", help="Comma-separated known aliases."),
    emails: Optional[str] = typer.Option(None, "--email", "-e", help="Comma-separated known emails."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to JSON file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all password patterns."),
) -> None:
    """Analyze password pattern exposure from breach data and username patterns."""
    alias_list = [a.strip() for a in aliases.split(",") if a.strip()] if aliases else []
    email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else []

    import asyncio
    from argis.breach import check_all as breach_check_all
    from argis.utils.network import build_client

    checker = PasswordLeakChecker()
    breach_reports = []
    if email_list:
        console.print("[dim]Checking emails against breach databases...[/dim]")
        breach_reports = asyncio.run(breach_check_all(email_list))

    analysis = checker.analyze(
        username=username,
        aliases=alias_list,
        known_emails=email_list,
        breach_reports=breach_reports,
    )

    risk = analysis["risk_assessment"]
    patterns = analysis["password_patterns"]
    found = [p for p in patterns if p["found_in_breaches"]]

    console.print(f"[bold cyan]Password Leak Check[/bold cyan]")
    console.print(f"[dim]Target: @{username} | Patterns tested: {len(patterns)} | Found in breaches: {len(found)}[/dim]\n")

    from rich.panel import Panel
    from rich.table import Table

    grade_color = "red" if risk["overall_score"] >= 70 else "yellow" if risk["overall_score"] >= 40 else "green"
    console.print(Panel(
        f"[bold]Risk Assessment: [{'red' if risk['overall_score'] >= 70 else 'yellow' if risk['overall_score'] >= 40 else 'green'}]{risk['grade']}[/{'red' if risk['overall_score'] >= 70 else 'yellow' if risk['overall_score'] >= 40 else 'green'}][/bold]\n"
        f"Score: [bold]{risk['overall_score']}/100[/bold]\n"
        f"Reuse Risk: [bold]{analysis.get('reuse_risk', 'N/A')}[/bold]",
        title="[bold green]PASSWORD EXPOSURE REPORT[/bold green]",
    ))

    if found:
        table = Table(show_header=True, header_style="bold dim")
        table.add_column("Pattern")
        table.add_column("Example")
        table.add_column("Breaches")
        table.add_column("Risk")
        for p in found[:10]:
            risk_color = "red" if p["reuse_risk"] == "HIGH" else "yellow" if p["reuse_risk"] == "MEDIUM" else "green"
            table.add_row(
                p["pattern"],
                p["example"],
                str(p["breach_count"]),
                f"[{risk_color}]{p['reuse_risk']}[/{risk_color}]",
            )
        console.print("\n[bold]Compromised Patterns:[/bold]")
        console.print(table)

    console.print("\n[bold]Recommendations:[/bold]")
    for rec in risk["recommendations"]:
        console.print(f"  • {rec}")

    if output:
        p = output.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        import json
        p.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]Output -> {p}[/green]")
