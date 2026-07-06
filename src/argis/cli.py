"""Command-line interface for Argis. Parses flags and delegates to core.py
and diff.py — this module should stay free of scanning/HTTP logic."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from argis import diff as diffmod
from argis.core import ArgisEngine
from argis.exceptions import ArgisError
from argis.utils import display
from argis.utils.display import console
from argis.utils.export import export_results

app = typer.Typer(
    help="Argis: the all-seeing username scanner. Hunt down accounts across "
    "dozens of platforms and track how a username's footprint changes over time."
)


@app.command()
def scan(
    username: str = typer.Argument(..., help="The target username to hunt down."),
    diff: bool = typer.Option(
        False, "--diff", "-d", help="Compare this scan against the last saved scan."
    ),
    save: bool = typer.Option(
        True, "--save/--no-save", help="Save this scan to history for future --diff runs."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Route requests through a proxy, e.g. socks5://127.0.0.1:9050"
    ),
    tor: bool = typer.Option(
        False, "--tor", help="Route requests through a local Tor SOCKS5 proxy."
    ),
    timeout: float = typer.Option(7.0, "--timeout", help="Per-request timeout in seconds."),
    concurrency: int = typer.Option(
        30, "--concurrency", help="Maximum number of simultaneous requests."
    ),
    export: Optional[str] = typer.Option(
        None, "--export", help="Export format: csv, json, or markdown."
    ),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="Output file path for --export (default: <username>.<ext>)."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress the progress bar and live [+] hits."
    ),
):
    """Search for a target username across all configured platforms."""
    if not quiet:
        display.print_banner(username)

    try:
        engine = ArgisEngine(
            username,
            proxy=proxy,
            use_tor=tor,
            timeout=timeout,
            concurrency=concurrency,
        )
        results = asyncio.run(engine.run_scan(quiet=quiet))
    except ArgisError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if not quiet:
        console.print()
        display.print_results_table(results, username)
        display.print_summary(results)

    if diff:
        previous = diffmod.get_last_scan(username)
        console.print()
        if previous is None:
            console.print(
                "[dim]No previous scan found for this username — nothing to diff "
                "against. This scan will become the baseline.[/dim]"
            )
        else:
            delta = diffmod.compute_diff(previous["results"], results)
            display.print_diff(delta)

    if save:
        diffmod.save_scan(username, results)

    if export:
        fmt = export.lower()
        ext = {"json": "json", "csv": "csv", "markdown": "md"}.get(fmt)
        if ext is None:
            console.print(f"[bold red]Unsupported export format:[/bold red] {export}")
            raise typer.Exit(code=1)
        out_path = output or Path(f"{username}.{ext}")
        export_results(results, username, fmt, out_path)
        console.print(f"[dim]Exported results to {out_path}[/dim]")


@app.command()
def history(
    username: str = typer.Argument(..., help="Username whose scan history to display."),
    limit: int = typer.Option(10, "--limit", help="Maximum number of past scans to show."),
):
    """Show past scan timestamps and found-profile counts for a username."""
    records = diffmod.load_history(username)
    if not records:
        console.print(f"[dim]No history found for '{username}'.[/dim]")
        return

    table = Table(title=f"Scan history for @{username}")
    table.add_column("#")
    table.add_column("Timestamp")
    table.add_column("Found")
    table.add_column("Total sites")

    for i, record in enumerate(records[-limit:], start=1):
        found = sum(1 for r in record["results"].values() if r["status"] == "FOUND")
        table.add_row(str(i), record["timestamp"], str(found), str(len(record["results"])))

    console.print(table)


@app.command("clear-history")
def clear_history(
    username: str = typer.Argument(..., help="Username whose history should be deleted."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
):
    """Delete all saved scan history for a username."""
    if not yes:
        confirmed = typer.confirm(f"Delete all saved history for '{username}'?")
        if not confirmed:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit()

    removed = diffmod.clear_history(username)
    if removed:
        console.print(f"[green]History cleared for '{username}'.[/green]")
    else:
        console.print(f"[dim]No history existed for '{username}'.[/dim]")


if __name__ == "__main__":
    app()
