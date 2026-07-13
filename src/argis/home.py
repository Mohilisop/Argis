"""ARGIS home screen: banner + command index shown for a bare `argis`.

Self-contained and Rich-based. From the CLI no-subcommand callback:

    from argis.home import render_home
    render_home(console)
    raise typer.Exit()
"""
from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ANSI Shadow logo, drawn with a cyan -> teal -> green vertical gradient.
_LOGO_LINES = [
    r" █████╗ ██████╗  ██████╗ ██╗███████╗",
    r"██╔══██╗██╔══██╗██╔════╝ ██║██╔════╝",
    r"███████║██████╔╝██║  ███╗██║███████╗",
    r"██╔══██║██╔══██╗██║   ██║██║╚════██║",
    r"██║  ██║██║  ██║╚██████╔╝██║███████║",
    r"╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝",
]
_LOGO_GRADIENT = [
    "#22d3ee", "#22d3ee", "#2dd4bf", "#2dd4bf", "#4ade80", "#4ade80",
]

_SECTIONS: list[tuple[str, str, list[tuple[str, str, str]]]] = [
    ("◉", "SURVEILLANCE", [
        ("scan", "<username>", "Crawl 509 platforms with media + dossier output"),
        ("scan --dossier", "<path>", "Add --dossier <file.html> to generate the HTML report"),
        ("scan-image", "<img>", "OCR a screenshot for embedded usernames and URLs"),
        ("scan-face", "<img>", "Reverse-image search a face across the open web"),
        ("setup-celebrity-db", "", "Download DeepFace celebrity reference images"),
    ]),
    ("◆", "INTELLIGENCE", [
        ("me", "<username>", "Full self-assessment: scan + breach + geo + impersonation"),
        ("breach", "<username>", "Correlate emails against known breach records"),
        ("mentions", "<username>", "Dredge handles from pastes, code repos, and dorks"),
        ("locate", "<username>", "Infer region from timezone and language metadata"),
        ("link", "<username>", "Cluster accounts into real identities vs impersonators"),
        ("guard", "<username>", "Proactive sweep for lookalike impersonator handles"),
        ("doctor", "", "Health-check every site rule and flag rot"),
    ]),
    ("▲", "RECONNAISSANCE", [
        ("recon", "<host>", "Port scan, OS fingerprint, traceroute, DNS, WHOIS, geo"),
        ("domain", "<domain>", "DNS chain, WHOIS, port scan, geo-IP"),
        ("discover", "<cidr>", "Sweep a subnet for live hosts"),
        ("myip", "", "Show your public IP, ASN, and geolocation"),
    ]),
    ("◷", "TRACKING", [
        ("history", "<user>", "Review scan timestamps and diffs"),
        ("clear-history", "<user>", "Purge scan history for a target"),
        ("monitor", "<user>", "Continuous surveillance with change alerts"),
    ]),
    ("▤", "ANALYSIS", [
        ("compare", "<u1> <u2>", "Side-by-side platform overlap and divergence"),
        ("exposure", "<username>", "Risk score (0-100) plus a footprint shrink plan"),
        ("timeline", "<username>", "Account-creation chronology across platforms"),
        ("graph", "<username>", "Interactive pivot graph of accounts and links"),
        ("media-review", "<user>", "Interactive media confidence dashboard"),
        ("media-apply", "<json>", "Save reviewed media decisions for future dossiers"),
        ("media-clear", "", "Reset all media decisions to automatic mode"),
        ("wayback", "<username>", "Historical profile snapshots via Archive.org"),
    ]),
    ("⚙", "UTILITIES", [
        ("mcp", "", "Run as an MCP server (Claude, Cursor, etc.)"),
        ("categories", "", "List all platform categories with counts"),
        ("search", "", "Full-text search across scan history"),
        ("stats", "", "Aggregate scan statistics and hit rates"),
        ("web", "", "Launch the local Argis web UI (live streaming results)"),
        ("import-sites", "<src>", "Import Sherlock/Maigret site definitions"),
    ]),
]

_SECTION_COLOR = {
    "SURVEILLANCE": "#22d3ee",
    "INTELLIGENCE": "#4ade80",
    "RECONNAISSANCE": "#fbbf24",
    "TRACKING": "#c77dff",
    "ANALYSIS": "#38bdf8",
    "UTILITIES": "#94a3b8",
}


def _logo() -> Text:
    logo = Text(justify="left")
    for line, color in zip(_LOGO_LINES, _LOGO_GRADIENT):
        logo.append(line + "\n", style=f"bold {color}")
    return logo


def _section_block(glyph: str, name: str, rows: list[tuple[str, str, str]]) -> Group:
    color = _SECTION_COLOR.get(name, "#22d3ee")
    header = Text()
    header.append(f" {glyph}  ", style=f"bold {color}")
    header.append(name, style=f"bold {color}")

    table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    table.add_column("cmd", style="bold #e8e8f0", no_wrap=True)
    table.add_column("arg", style="#6a7a8a", no_wrap=True)
    table.add_column("desc", style="#8a94a6")
    for cmd, arg, desc in rows:
        table.add_row(f"  {cmd}", arg, desc)
    return Group(header, table, Text(""))


def render_home(console: Console, version: str = "0.8.0") -> None:
    """Render the ARGIS home screen for a bare `argis` invocation."""
    tagline = Text(justify="left")
    tagline.append("  the all-seeing OSINT collector", style="italic #6a7a8a")
    tagline.append("   ·   ", style="#3a4452")
    tagline.append(f"v{version}", style="bold #4ade80")

    console.print()
    console.print(_logo())
    console.print(tagline)
    console.print()

    usage = Text()
    usage.append("  usage  ", style="reverse bold #22d3ee")
    usage.append("  argis ", style="bold #e8e8f0")
    usage.append("<command> ", style="#4ade80")
    usage.append("[options]", style="#6a7a8a")
    console.print(usage)
    console.print()

    blocks = [_section_block(glyph, name, rows) for glyph, name, rows in _SECTIONS]
    console.print(Panel(
        Group(*blocks),
        border_style="#1f2a37",
        padding=(1, 1),
        title="[bold #22d3ee]COMMAND INDEX[/bold #22d3ee]",
        title_align="left",
    ))

    examples = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    examples.add_column(style="#4ade80", no_wrap=True)
    examples.add_column(style="#6a7a8a")
    examples.add_row("argis scan johndoe", "surface every account")
    examples.add_row("argis scan johndoe --dossier report.html", "build the HTML dossier")
    examples.add_row("argis me johndoe", "full self-assessment")
    examples.add_row("argis recon -tr -os example.com", "traceroute + OS fingerprint")
    examples.add_row("argis web", "launch the browser UI")

    console.print()
    console.print(Text("  examples", style="bold #94a3b8"))
    console.print(examples)

    footer = Text(justify="left")
    footer.append("  --help ", style="bold #22d3ee")
    footer.append("per-command help", style="#6a7a8a")
    footer.append("     --version ", style="bold #22d3ee")
    footer.append("build version", style="#6a7a8a")
    footer.append("     defensive / self-OSINT only", style="italic #3a4452")
    console.print()
    console.print(footer)
    console.print()
