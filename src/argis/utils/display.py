"""Rich-based terminal UI components: progress bars, tables, diff views."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)
from rich.table import Table

console = Console()

STATUS_STYLES = {
    "FOUND": "bold green",
    "NOT_FOUND": "dim red",
    "UNKNOWN": "yellow",
    "TIMEOUT": "yellow",
    "BLOCKED": "bold magenta",
}


def make_progress() -> Progress:
    """Build the live progress bar used while scanning platforms."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    )


def print_banner(username: str) -> None:
    console.print(f"[bold white]\U0001f441\ufe0f  Argis Engine[/bold white] initializing...")
    console.print(f"Targeting handle: [bold cyan]@{username}[/bold cyan]\n")


def print_found(name: str, url: str) -> None:
    console.print(f"[bold green][+][/bold green] [white]{name}:[/white] "
                  f"[underline cyan]{url}[/underline cyan]")


def print_results_table(results: dict[str, dict], username: str) -> None:
    """Render a full results table (name, status, url)."""
    table = Table(title=f"Argis scan results for @{username}", show_lines=False)
    table.add_column("Platform", style="white")
    table.add_column("Status")
    table.add_column("URL", style="cyan", overflow="fold")

    for name, info in sorted(results.items()):
        status = info["status"]
        style = STATUS_STYLES.get(status, "white")
        table.add_row(name, f"[{style}]{status}[/{style}]", info["url"])

    console.print(table)


def print_summary(results: dict[str, dict]) -> None:
    found = sum(1 for r in results.values() if r["status"] == "FOUND")
    total = len(results)
    console.print(
        Panel.fit(
            f"[bold green]{found}[/bold green] / {total} platforms show an "
            f"active profile",
            title="Summary",
        )
    )


def print_diff(diff: dict) -> None:
    """Render a diff report: newly found, newly gone, unchanged counts."""
    table = Table(title="Diff since last scan")
    table.add_column("Change", style="white")
    table.add_column("Platform")
    table.add_column("URL", style="cyan", overflow="fold")

    for name, url in diff.get("added", []):
        table.add_row("[bold green][+] REGISTERED[/bold green]", name, url)
    for name, url in diff.get("removed", []):
        table.add_row("[bold red][-] DELETED[/bold red]", name, url)

    if not diff.get("added") and not diff.get("removed"):
        console.print("[dim]No changes detected since the last scan.[/dim]")
    else:
        console.print(table)

    unchanged = diff.get("unchanged_count", 0)
    console.print(f"[dim]{unchanged} platform(s) unchanged.[/dim]")
