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
from argis.echo import analyze_echo
from argis.exceptions import HistoryError
from argis.media_runtime import install_media_capture
from argis.utils.display import console

# Preserve validated avatar URLs/hashes in normal scan results before dossier
# normalization runs. Installation is idempotent.
install_media_capture()


@app.command("echo", rich_help_panel="History & Tracking")
def echo_command(
    username: str = typer.Argument(..., help="Username whose saved scan history should be analyzed."),
    window: int = typer.Option(72, "--window", "-w", min=1, help="Hours in which changes count as coordinated."),
    min_confidence: int = typer.Option(45, "--min-confidence", "-mc", min=0, max=100, help="Hide Echo events below this confidence."),
    json_output: bool = typer.Option(False, "--json", help="Print the complete Echo report as JSON."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the complete Echo report to a JSON file."),
) -> None:
    """Detect coordinated identity drift across saved scans.

    Examples:
        argis echo johndoe
        argis echo johndoe --window 24 --min-confidence 70
        argis echo johndoe --json
        argis echo johndoe -o johndoe-echo.json
    """
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
