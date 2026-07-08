from __future__ import annotations

import time

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.live import Live
from rich.rule import Rule
from rich.table import Table
from rich.style import Style
from rich import box
from rich.align import Align

console = Console()

LOGO_SUB = "[cyan]the all-seeing OSINT scanner[/cyan]"

# Blocky ASCII wordmark for "ARGIS", one string per row.
_ARGIS_ART = [
    " █    ██    ██   ███   ██ ",
    "█ █   █ █   █     █   █   ",
    "███   ██    █ █   █    █  ",
    "█ █   █ █   █ █   █     █ ",
    "█ █   █ █    ██   ███  ██ ",
]

# Gradient endpoints (cyan -> blue), matching the eye logo's palette.
_GRAD_START = (110, 231, 255)
_GRAD_END = (58, 120, 235)


def _lerp_rgb(t: float) -> tuple[int, int, int]:
    r = round(_GRAD_START[0] + (_GRAD_END[0] - _GRAD_START[0]) * t)
    g = round(_GRAD_START[1] + (_GRAD_END[1] - _GRAD_START[1]) * t)
    b = round(_GRAD_START[2] + (_GRAD_END[2] - _GRAD_START[2]) * t)
    return r, g, b


def _lerp_color(t: float) -> str:
    r, g, b = _lerp_rgb(t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _gradient_line(line: str, revealed: int | None = None, shimmer_center: float | None = None) -> Text:
    """Render one row of the wordmark with a cyan->blue gradient.

    ``revealed`` limits how many characters (left to right) are drawn, letting
    callers build a typewriter-style reveal. ``shimmer_center`` brightens
    characters near that column index, used for the sweeping highlight pass.
    """
    text = Text()
    width = max(len(line) - 1, 1)
    limit = len(line) if revealed is None else max(0, min(revealed, len(line)))
    for i, ch in enumerate(line):
        if i >= limit or ch == " ":
            text.append(" ")
            continue
        r, g, b = _lerp_rgb(i / width)
        if shimmer_center is not None:
            dist = abs(i - shimmer_center)
            if dist < 2.2:
                boost = max(0.0, 1 - dist / 2.2) * 0.85
                r = round(r + (255 - r) * boost)
                g = round(g + (255 - g) * boost)
                b = round(b + (255 - b) * boost)
        text.append(ch, style=Style(color=f"#{r:02x}{g:02x}{b:02x}", bold=True))
    return text


def _logo_panel(revealed: list[int] | None = None, shimmer_center: float | None = None) -> Panel:
    art = Text()
    for i, row in enumerate(_ARGIS_ART):
        row_revealed = None if revealed is None else revealed[i]
        art.append_text(_gradient_line(row, row_revealed, shimmer_center))
        if i != len(_ARGIS_ART) - 1:
            art.append("\n")

    body = Align.center(art)
    return Panel(
        body,
        subtitle=LOGO_SUB,
        subtitle_align="center",
        border_style="cyan",
        padding=(1, 2),
    )


def _print_logo() -> None:
    console.print(_logo_panel())


def _animate_logo() -> None:
    """Play a short reveal + shimmer intro before settling on the static logo."""
    lengths = [len(row) for row in _ARGIS_ART]
    total_width = max(lengths)
    revealed = [0] * len(_ARGIS_ART)
    step = 3

    with Live(console=console, auto_refresh=False, transient=True) as live:
        for row_idx, length in enumerate(lengths):
            for chars in range(0, length + step, step):
                revealed[row_idx] = min(chars, length)
                live.update(_logo_panel(revealed), refresh=True)
                time.sleep(0.012)
            revealed[row_idx] = length

        for pos in range(-2, total_width + 3):
            live.update(_logo_panel(lengths, float(pos)), refresh=True)
            time.sleep(0.02)

    # Leave the final, non-transient frame in the scrollback.
    _print_logo()


def _show_logo(animate: bool = True) -> None:
    if animate and console.is_terminal:
        try:
            _animate_logo()
            return
        except Exception:
            pass
    _print_logo()


STATUS_BADGES = {
    "FOUND": "[bold green]\u2713[/bold green]",
    "NOT_FOUND": "[dim]\u2014[/dim]",
    "UNKNOWN": "[yellow]?[/yellow]",
    "TIMEOUT": "[yellow]\u23f3[/yellow]",
    "BLOCKED": "[bold magenta]\u26a0[/bold magenta]",
}

STATUS_STYLES = {
    "FOUND": "bold green",
    "NOT_FOUND": "dim red",
    "UNKNOWN": "yellow",
    "TIMEOUT": "yellow",
    "BLOCKED": "bold magenta",
}


def print_section(title: str, style: str = "bold cyan") -> None:
    console.print(Rule(style=Style(dim=True)))
    console.print(f"[{style}]{title}[/{style}]")


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style=Style(color="grey37"), complete_style=Style(color="cyan")),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )


def print_banner(username: str, animate: bool = True) -> None:
    _show_logo(animate)
    console.print()
    console.print(Panel.fit(
        f"[bold white]Argis Engine[/bold white] initializing\n"
        f"[bold cyan]Target:[/bold cyan] @{username}",
        border_style="cyan",
    ))


def print_found(name: str, url: str) -> None:
    console.print(f"  [bold green]\u2713[/bold green] [white]{name}:[/white] "
                  f"[underline cyan]{url}[/underline cyan]")


def _style_status_cell(status: str) -> str:
    badge = STATUS_BADGES.get(status, "")
    style = STATUS_STYLES.get(status, "white")
    return f"[{style}]{badge} {status}[/{style}]"


def print_results_table(results: dict[str, dict], username: str) -> None:
    table = Table(
        title=f"[bold white]Scan results for @{username}[/bold white]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        title_style="bold",
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("#", style="dim", no_wrap=True, width=3)
    table.add_column("Platform", style="white", no_wrap=True)
    table.add_column("Status")
    table.add_column("URL", style="cyan", overflow="fold")

    for i, (name, info) in enumerate(sorted(results.items()), 1):
        status = info["status"]
        is_found = status == "FOUND"
        table.add_row(
            str(i) if not is_found else f"[bold]{i}[/bold]",
            name if not is_found else f"[bold]{name}[/bold]",
            _style_status_cell(status),
            info["url"],
        )

    console.print(table)


def print_compact_results(results: dict[str, dict], username: str) -> None:
    found = [(n, i) for n, i in results.items() if i["status"] == "FOUND"]
    rest = [(n, i) for n, i in results.items() if i["status"] != "FOUND"]
    rest.sort(key=lambda x: x[1].get("status", ""))

    table = Table(
        title=f"[bold white]Scan results for @{username}[/bold white]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        title_style="bold",
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Platform", style="white", no_wrap=True)
    table.add_column("Status")
    table.add_column("URL", style="cyan", overflow="fold")

    if found:
        for name, info in found:
            table.add_row(
                f"[bold green]{name}[/bold green]",
                _style_status_cell("FOUND"),
                info["url"],
            )
        table.add_section()
    for name, info in rest:
        s = STATUS_STYLES.get(info["status"], "white")
        table.add_row(
            f"[{s}]{name}[/{s}]",
            _style_status_cell(info["status"]),
            f"[{s}]{info['url']}[/{s}]",
        )

    console.print(table)


def print_summary(results: dict[str, dict]) -> None:
    found = sum(1 for r in results.values() if r["status"] == "FOUND")
    total = len(results)
    blocked = sum(1 for r in results.values() if r["status"] == "BLOCKED")
    timed_out = sum(1 for r in results.values() if r["status"] == "TIMEOUT")
    unknown = sum(1 for r in results.values() if r["status"] == "UNKNOWN")

    details = f"[bold green]{found} found[/bold green]"
    if blocked:
        details += f"  [bold magenta]{blocked} blocked[/bold magenta]"
    if timed_out:
        details += f"  [yellow]{timed_out} timeout[/yellow]"
    if unknown:
        details += f"  [yellow]{unknown} unknown[/yellow]"

    console.print(
        Panel.fit(
            f"{details}\n"
            f"[dim]{total} platforms scanned[/dim]",
            title="[bold]Summary[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def print_diff(diff: dict) -> None:
    table = Table(
        title="[bold]Changes since last scan[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
    )
    table.add_column("Change", style="white")
    table.add_column("Platform")
    table.add_column("URL", style="cyan", overflow="fold")

    for name, url in diff.get("added", []):
        table.add_row("[bold green]\u2713 REGISTERED[/bold green]", name, url)
    for name, url in diff.get("removed", []):
        table.add_row("[bold red]\u2717 DELETED[/bold red]", name, url)

    if not diff.get("added") and not diff.get("removed"):
        console.print("[dim]No changes detected since the last scan.[/dim]")
    else:
        console.print(table)

    unchanged = diff.get("unchanged_count", 0)
    console.print(f"[dim]{unchanged} platform(s) unchanged.[/dim]")


def print_email_results(email_map: dict[str, list[str]]) -> None:
    if not email_map:
        return
    print_section("Emails Discovered")
    table = Table(
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Platform", style="white")
    table.add_column("Email(s)", style="yellow")
    for platform, emails in sorted(email_map.items()):
        table.add_row(platform, ", ".join(emails))
    console.print(table)


def print_recon_banner(target: str) -> None:
    _print_logo()
    console.print()
    console.print(Panel.fit(
        f"[bold white]Argis Recon[/bold white] initializing\n"
        f"[bold cyan]Target:[/bold cyan] {target}",
        border_style="cyan",
    ))


def print_port_results(target: str, results: list) -> None:
    open_results = [r for r in results if r.open]
    if not open_results:
        console.print(Panel.fit(
            "[dim]No open ports found[/dim]",
            border_style="grey37",
        ))
    else:
        table = Table(
            title=f"[bold]Open ports on {target}[/bold]",
            box=box.ROUNDED,
            header_style=Style(color="cyan", bold=True),
            border_style="grey37",
            title_style="bold",
            padding=(0, 1),
        )
        table.add_column("Port", style="white", no_wrap=True)
        table.add_column("Service", style="green")
        table.add_column("State", style="dim")
        for r in sorted(open_results, key=lambda x: x.port):
            table.add_row(
                f"[bold]{r.port}[/bold]",
                r.service_guess or "unknown",
                "open",
            )
        console.print(table)

    console.print(
        f"[dim]{len(open_results)} open / {len(results)} ports scanned[/dim]"
    )


def print_udp_results(target: str, results: list) -> None:
    open_results = [r for r in results if r.open]
    if not open_results:
        return

    table = Table(
        title=f"[bold]Open UDP ports on {target}[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Port", style="white")
    table.add_column("Service", style="green")
    for r in sorted(open_results, key=lambda x: x.port):
        table.add_row(str(r.port), r.service_guess or "unknown")
    console.print(table)


def print_web_results(results: list) -> None:
    if not results:
        return

    table = Table(
        title="[bold]Web fingerprint[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Port", style="white", no_wrap=True)
    table.add_column("Scheme")
    table.add_column("Status")
    table.add_column("Server", style="green")
    table.add_column("Title", style="yellow", overflow="fold")
    table.add_column("Tech", style="cyan")

    for r in results:
        if r.error:
            table.add_row(str(r.port), r.scheme, f"[red]{r.error}[/red]", "-", "-", "-")
        else:
            tech = ", ".join(r.tech_stack[:5]) if r.tech_stack else "-"
            code_str = str(r.status_code)
            code_color = "green" if r.status_code and r.status_code < 400 else "yellow" if r.status_code and r.status_code < 500 else "red"
            table.add_row(
                str(r.port),
                r.scheme,
                f"[{code_color}]{code_str}[/{code_color}]",
                r.server or "-",
                r.title or "-",
                tech,
            )

    console.print(table)


def print_banner_results(results: list) -> None:
    shown = [r for r in results if r.banner]
    if not shown:
        return

    table = Table(
        title="[bold]Service banners[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Port", style="white")
    table.add_column("Banner", style="yellow", overflow="fold")
    table.add_column("Version", style="green")

    for r in shown:
        table.add_row(str(r.port), r.banner, r.version or "-")

    console.print(table)


def print_dns_results(dns_result) -> None:
    if dns_result is None:
        return
    if dns_result.error:
        console.print(f"[dim]DNS lookup failed: {dns_result.error}[/dim]")
        return

    table = Table(
        title=f"[bold]DNS records for {dns_result.hostname}[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Type", style="white", no_wrap=True)
    table.add_column("Value", style="cyan", overflow="fold")

    for rec in dns_result.records:
        table.add_row(rec.type, rec.value)

    console.print(table)


def print_whois_results(whois_text: str | None) -> None:
    if not whois_text:
        return
    console.print(Panel(
        whois_text[:1500],
        title="[bold]WHOIS[/bold]",
        border_style="cyan",
    ))


def print_geoip_results(geo) -> None:
    from argis.utils.geoip import GeoIPResult

    if geo.error:
        if "private" in geo.error.lower():
            console.print(f"[dim][yellow]\u26a0 {geo.error}[/yellow][/dim]")
        elif "API key" in geo.error.lower():
            console.print(f"[bold red]\u2716 {geo.error}[/bold red]")
        else:
            console.print(f"[dim]Geolocation failed: {geo.error}[/dim]")
        return

    lines = []
    if geo.country_name:
        flag = ""
        if geo.country_code2:
            flag = chr(ord(geo.country_code2[0]) + 127397) + chr(ord(geo.country_code2[1]) + 127397)
        lines.append(f"[bold cyan]Country:[/bold cyan] {flag} {geo.country_name} ({geo.country_code2})")
    if geo.state_prov:
        lines.append(f"[bold cyan]State/Province:[/bold cyan] {geo.state_prov}")
    if geo.city:
        lines.append(f"[bold cyan]City:[/bold cyan] {geo.city}")
    if geo.zipcode:
        lines.append(f"[bold cyan]ZIP:[/bold cyan] {geo.zipcode}")
    if geo.latitude is not None and geo.longitude is not None:
        map_url = f"https://www.google.com/maps?q={geo.latitude},{geo.longitude}"
        lines.append(f"[bold cyan]Coordinates:[/bold cyan] {geo.latitude}, {geo.longitude}")
        lines.append(f"[dim]Map: {map_url}[/dim]")
    if geo.isp:
        lines.append(f"[bold cyan]ISP:[/bold cyan] {geo.isp}")
    if geo.organization:
        lines.append(f"[bold cyan]Organization:[/bold cyan] {geo.organization}")
    if geo.timezone:
        lines.append(f"[bold cyan]Timezone:[/bold cyan] {geo.timezone}")
    if geo.currency:
        lines.append(f"[bold cyan]Currency:[/bold cyan] {geo.currency}")

    console.print(Panel.fit(
        "\n".join(lines),
        title=f"\U0001f310 Geolocation: {geo.ip}",
        border_style="cyan",
    ))


def print_discovery_results(cidr: str, results: list) -> None:
    alive = [r for r in results if r.alive]

    if alive:
        table = Table(
            title=f"[bold]Live hosts in {cidr}[/bold]",
            box=box.ROUNDED,
            header_style=Style(color="cyan", bold=True),
            border_style="grey37",
            padding=(0, 1),
        )
        table.add_column("#", style="dim", no_wrap=True, width=3)
        table.add_column("IP", style="green")
        for i, r in enumerate(sorted(alive, key=lambda x: tuple(int(p) for p in x.ip.split("."))), 1):
            table.add_row(str(i), r.ip)
        console.print(table)
    else:
        console.print(Panel.fit(
            "[dim]No responsive hosts found[/dim]",
            border_style="grey37",
        ))

    console.print(f"[dim]{len(alive)} alive / {len(results)} hosts probed[/dim]")


def print_batch_summary(results: dict[str, dict[str, dict]]) -> None:
    table = Table(
        title="[bold]Batch scan summary[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Username", style="white", no_wrap=True)
    table.add_column("Found", style="green")
    table.add_column("Total", style="cyan")
    table.add_column("Emails", style="yellow")
    table.add_column("Errors", style="red")

    for username, scan_results in sorted(results.items()):
        found = sum(1 for r in scan_results.values() if r.get("status") == "FOUND")
        total = len(scan_results)
        errors = sum(1 for r in scan_results.values() if r.get("error"))
        emails = set()
        for r in scan_results.values():
            for e in r.get("emails", []):
                emails.add(e)
        table.add_row(username, str(found), str(total), str(len(emails)), str(errors))

    console.print(table)

    found_total = sum(
        1 for res in results.values() for r in res.values() if r["status"] == "FOUND"
    )
    console.print(
        f"[dim]Total found: [bold green]{found_total}[/bold green][/dim]"
    )


def print_os_results(os_guesses: list) -> None:
    if not os_guesses:
        return
    table = Table(
        title="[bold]OS Detection[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Name", style="white")
    table.add_column("Accuracy", style="green")
    table.add_column("Detail", style="dim", overflow="fold")
    for g in os_guesses:
        table.add_row(g.name, f"{g.accuracy}%", g.detail or "-")
    console.print(table)


def print_traceroute_results(hops: list) -> None:
    if not hops:
        return
    table = Table(
        title="[bold]Traceroute[/bold]",
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Hop", style="white", no_wrap=True)
    table.add_column("IP", style="cyan")
    table.add_column("RTT", style="green")
    for h in hops:
        ip = h.ip or "[dim]*[/dim]"
        rtt = f"{h.rtt:.1f}ms" if h.rtt else "-"
        table.add_row(str(h.ttl), ip, rtt)
    console.print(table)
    reachable = sum(1 for h in hops if h.alive)
    console.print(f"[dim]{reachable} hops / {len(hops)} total[/dim]")


def print_monitor_header(username: str, interval: int, animate: bool = True) -> None:
    _show_logo(animate)
    console.print()
    console.print(Panel.fit(
        f"Monitoring [bold cyan]@{username}[/bold cyan]\n"
        f"Interval: [bold yellow]{interval}s[/bold yellow]\n"
        "[dim]Press Ctrl+C to stop[/dim]",
        title="\U0001f6ae Argis Monitor",
        border_style="cyan",
    ))


def print_monitor_diff(prev: dict, curr: dict) -> None:
    from argis.diff import compute_diff

    delta = compute_diff(prev, curr)
    if delta["added"] or delta["removed"]:
        print_diff(delta)
    else:
        console.print("[dim]No changes detected in this cycle.[/dim]")


def print_error_details(errors: dict[str, dict]) -> None:
    if not errors:
        return
    print_section("Error Details")
    table = Table(
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Platform", style="white")
    table.add_column("Error", style="red")
    table.add_column("URL", style="dim", overflow="fold")
    for name, info in sorted(errors.items()):
        table.add_row(name, info.get("error", "?"), info.get("url", ""))
    console.print(table)


def print_error_summary(by_error: dict[str, int]) -> None:
    if not by_error:
        return
    print_section("Error Summary")
    table = Table(
        box=box.ROUNDED,
        header_style=Style(color="cyan", bold=True),
        border_style="grey37",
        padding=(0, 1),
    )
    table.add_column("Error type", style="red")
    table.add_column("Count", style="yellow")
    for err, count in sorted(by_error.items(), key=lambda x: -x[1]):
        table.add_row(err, str(count))
    console.print(table)


def print_completion(elapsed: float, found: int, total: int) -> None:
    rate = f"{total / elapsed:.1f}/s" if elapsed > 0 else "-"
    console.print()
    console.print(Panel.fit(
        f"[bold white]{found}[/bold white] / [bold white]{total}[/bold white] found "
        f"in [bold cyan]{elapsed:.1f}s[/bold cyan] ({rate})\n"
        f"[dim]\u2713 Scan complete[/dim]",
        border_style="green",
    ))
