from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.table import Table
from rich.panel import Panel

from argis import diff as diffmod
from argis.core import ArgisEngine, build_email_map, extract_categories
from argis.exceptions import ArgisError
from argis.recon import (
    ALL_TCP_PORTS,
    DEFAULT_PORTS,
    TIMING_TEMPLATES,
    discover_hosts,
    run_recon,
    udp_port_scan,
)
from argis.utils import display
from argis.utils.config import init_config, load_config
from argis.utils.display import console
from argis.utils.export import export_results, send_webhook, to_json_stream
from argis.utils.notify import send_notification
from argis.utils.wayback import check_wayback

app = typer.Typer(
    rich_markup_mode="rich",
    help="Argis: the all-seeing username scanner. Hunt down accounts across "
    "dozens of platforms and track how a username's footprint changes over time.",
    epilog="[dim]See full docs at [link=https://github.com/Mohilisop/argis]github.com/Mohilisop/argis[/link][/dim]",
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
):
    if version:
        from argis import __version__

        console.print(f"[bold cyan]Argis[/bold cyan] [green]v{__version__}[/green]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        from rich.text import Text
        logo = Text()
        logo.append("  ___   _   _   _   ___   ___   \n")
        logo.append(" / _ \\ /_\\ | |_| | / __| / _ \\  \n", style="cyan")
        logo.append("| (_) |/ _ \\|  _  || (_ || (_) | \n", style="cyan")
        logo.append(" \\___//_/ \\_\\_| |_| \\___| \\___/  \n", style="cyan")
        logo.append("  the all-seeing OSINT scanner    \n", style="dim")
        console.print(logo)
        console.print("[bold]Usage:[/bold] [green]argis[/green] [cyan]<command>[/cyan] [dim][options][/dim]\n")

        from rich.table import Table

        groups = {
            "Username Scanning": [
                ("scan <username>", "Search a username across 133 platforms"),
            ],
            "Reconnaissance": [
                ("recon <host>", "Port scan, OS detection, traceroute, DNS, WHOIS, geo"),
                ("domain <domain>", "DNS resolution, WHOIS, port scan, geo"),
                ("discover <cidr>", "Sweep a subnet for live hosts"),
                ("myip", "Show your public IP and geolocate it"),
            ],
            "History & Tracking": [
                ("history <user>", "View past scan timestamps"),
                ("clear-history <user>", "Delete scan history"),
                ("monitor <user>", "Continuously watch a username for changes"),
            ],
            "Analysis": [
                ("compare <u1> <u2>", "Compare two usernames side by side"),
                ("wayback <user>", "Check historical profile snapshots"),
                ("search <query>", "Search across all scan history"),
                ("stats", "Aggregate statistics across all users"),
            ],
            "Utilities": [
                ("categories", "List all available platform categories"),
            ],
        }

        for group_name, cmds in groups.items():
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Cmd", style="cyan", no_wrap=True)
            table.add_column("Desc", style="dim")
            for cmd, desc in cmds:
                table.add_row(f"  {cmd}", desc)
            console.print(f"[bold]{group_name}[/bold]")
            console.print(table)
            console.print()

        console.print("[dim]Flags:[/dim]")
        console.print("  [cyan]--help[/cyan]    Show help for a specific command")
        console.print("  [cyan]--version[/cyan] Show version number")
        console.print()
        console.print("[dim]Tip:[/dim] [green]argis recon --help[/green] for all recon options (-pt, -sv, -os, -tr, -ag, etc.)")
        console.print()
        console.print("[dim]Examples:[/dim]")
        console.print("  [green]argis scan johndoe[/green]")
        console.print("  [green]argis scan --file users.txt --export html[/green]")
        console.print("  [green]argis recon -pt 22,80,443 -sv example.com[/green]")
        console.print("  [green]argis recon -ag 192.168.1.0/24[/green]")
        console.print("  [green]argis recon -ax -gl github.com[/green]")
        console.print("  [green]argis recon -tr -os example.com[/green]")
        console.print("  [green]argis compare alice bob[/green]")
        console.print("  [green]argis myip[/green]")
        console.print()
        raise typer.Exit()


def _merge_config(cli_args: dict[str, Any]) -> dict[str, Any]:
    cfg = load_config()
    merged = {}
    for key, cli_val in cli_args.items():
        cfg_val = cfg.get(key)
        if cli_val is not None and cli_val is not False:
            if isinstance(cli_val, bool):
                merged[key] = cli_val
            else:
                merged[key] = cli_val
        elif cfg_val is not None:
            merged[key] = cfg_val
        else:
            merged[key] = cli_val
    return merged


VALID_EXPORT_FORMATS = {"csv", "json", "markdown", "html", "md"}


@app.command(rich_help_panel="Username Scanning")
def scan(
    username: str = typer.Argument(..., help="The target username to hunt down."),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Path to a file with one username per line for batch scanning."
    ),
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
    timeout: Optional[float] = typer.Option(
        None, "--timeout", help="Per-request timeout in seconds. (default: 7.0)"
    ),
    concurrency: Optional[int] = typer.Option(
        None, "--concurrency", help="Maximum number of simultaneous requests. (default: 30)"
    ),
    export: Optional[str] = typer.Option(
        None, "--export", help="Export format(s): csv, json, markdown, html (comma-separated for multiple)."
    ),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="Output file path for --export (default: <username>.<ext>)."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress the progress bar and live [+] hits."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show per-platform error details for failed checks."
    ),
    http2: bool = typer.Option(
        False, "--http2", help="Enable HTTP/2 multiplexing support."
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Comma-separated list of categories to filter by."
    ),
    exclude: Optional[str] = typer.Option(
        None, "--exclude", "-x", help="Comma-separated list of platforms to skip."
    ),
    status_filter: Optional[str] = typer.Option(
        None, "--status", "-s", help="Show only platforms with given status(es): FOUND,NOT_FOUND,TIMEOUT,BLOCKED,UNKNOWN."
    ),
    all: bool = typer.Option(
        False, "--all", "-a", help="Show all results (including non-FOUND) in compact view."
    ),
    retry: bool = typer.Option(
        True, "--retry/--no-retry", help="Retry BLOCKED/TIMEOUT responses with exponential backoff."
    ),
    webhook: Optional[str] = typer.Option(
        None, "--webhook", help="Send results to a Slack/Discord webhook URL."
    ),
    webhook_type: str = typer.Option(
        "slack", "--webhook-type", help="Webhook type: slack or discord."
    ),
    json_stream: bool = typer.Option(
        False, "--json-stream", help="Output results as JSON Lines (one JSON object per line)."
    ),
    emails: bool = typer.Option(
        False, "--emails", "-e", help="Extract and display emails from discovered profiles."
    ),
    notify: bool = typer.Option(
        False, "--notify", "-n", help="Send a desktop notification when the scan completes."
    ),
    list_platforms: bool = typer.Option(
        False, "--list", "-l", help="List platforms that would be scanned and exit."
    ),
    config: bool = typer.Option(
        False, "--config", help="Load default settings from ~/.argis/config.json."
    ),
    save_config: bool = typer.Option(
        False, "--save-config", help="Save the current flags as new defaults."
    ),
    geo_key: Optional[str] = typer.Option(
        None, "--geo-key", help="ipgeolocation.io API key (or set ARGIS_GEOIP_KEY env var)."
    ),
):
    """Search for a target username across all configured platforms.

    \b
    Examples:
      argis scan johndoe
      argis scan johndoe --status FOUND
      argis scan johndoe --export json,html
      argis scan johndoe --exclude twitter,facebook
      argis scan johndoe --verbose
      argis scan johndoe --list
      argis scan --file users.txt --export csv
    """
    init_config()

    if save_config:
        from argis.utils.config import save_config as sc

        sc({
            "proxy": proxy,
            "tor": tor,
            "timeout": timeout or 7.0,
            "concurrency": concurrency or 30,
            "http2": http2,
            "retry": retry,
            "export": export,
            "quiet": quiet,
            "notify": notify,
            "geoip_key": geo_key,
        })
        console.print("[green]Settings saved to ~/.argis/config.json[/green]")

    if config:
        cfg = load_config()
        proxy = proxy or cfg.get("proxy")
        tor = tor or cfg.get("tor", False)
        timeout = timeout or cfg.get("timeout", 7.0)
        concurrency = concurrency or cfg.get("concurrency", 30)
        http2 = http2 or cfg.get("http2", False)
        retry = cfg.get("retry", True) if retry else False
        export = export or cfg.get("export")
        quiet = quiet or cfg.get("quiet", False)

    categories = tuple(c.strip().lower() for c in category.split(",")) if category else None
    exclude_set = set(e.strip().lower() for e in exclude.split(",")) if exclude else None

    if file:
        _run_batch_scan(
            file=file,
            proxy=proxy,
            use_tor=tor,
            timeout=timeout or 7.0,
            concurrency=concurrency or 30,
            export=export,
            output=output,
            quiet=quiet,
            verbose=verbose,
            http2=http2,
            category=category,
            exclude=exclude_set,
            status_filter=status_filter,
            retry=retry,
            webhook=webhook,
            webhook_type=webhook_type,
        )
        return

    if not quiet:
        display.print_banner(username)

    engine = ArgisEngine(
        username,
        proxy=proxy,
        use_tor=tor,
        timeout=timeout or 7.0,
        concurrency=concurrency or 30,
        http2=http2,
        categories=categories,
        exclude=exclude_set,
        retry_blocked=retry,
    )

    if list_platforms:
        _show_platform_list(engine, categories)
        return

    scan_start = time.time()
    try:
        results = asyncio.run(engine.run_scan(quiet=quiet))
    except ArgisError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    scan_elapsed = time.time() - scan_start

    if not results:
        return

    if json_stream:
        console.print(to_json_stream(results))
        if save:
            diffmod.save_scan(username, results)
        return

    if not quiet:
        _display_scan_results(results, username, all, verbose, emails, status_filter)

    if not quiet:
        found_count = sum(1 for r in results.values() if r["status"] == "FOUND")
        display.print_completion(scan_elapsed, found_count, len(results))

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

    _handle_scan_export(results, username, export, output)

    if verbose:
        _print_error_summary(results)

    if webhook:
        success = asyncio.run(
            send_webhook(webhook, results, username, webhook_type=webhook_type)
        )
        if success:
            console.print("[dim]Webhook notification sent.[/dim]")
        else:
            console.print("[dim][yellow]Webhook notification failed.[/yellow][/dim]")

    if notify:
        found = sum(1 for r in results.values() if r["status"] == "FOUND")
        total = len(results)
        send_notification(
            "Argis Scan Complete",
            f"@{username}: {found}/{total} platforms found",
        )
        console.print("[dim]Desktop notification sent.[/dim]")


def _show_platform_list(engine: ArgisEngine, categories: tuple | None) -> None:
    sites = engine._filter_sites()
    console.print(f"[bold cyan]Platforms to scan[/bold cyan] ({len(sites)} total)\n")
    by_cat: dict[str, list[str]] = {}
    for name, rules in sorted(sites.items()):
        cat = rules.get("category", "uncategorized")
        by_cat.setdefault(cat, []).append(name)
    for cat, names in sorted(by_cat.items()):
        console.print(f"  [bold]{cat}[/bold] ({len(names)})")
        for n in names:
            console.print(f"    [cyan]{n}[/cyan]")
    console.print(f"\n[dim]Total: {len(sites)} platforms[/dim]")
    raise typer.Exit()


def _display_scan_results(
    results: dict, username: str, show_all: bool, verbose: bool, emails: bool, status_filter: str | None
) -> None:
    filtered = results
    if status_filter:
        allowed = set(s.strip().upper() for s in status_filter.split(","))
        filtered = {n: r for n, r in results.items() if r.get("status") in allowed}

    if not filtered:
        console.print("[dim]No results match the given --status filter.[/dim]")
        return

    console.print()
    if show_all:
        display.print_compact_results(filtered, username)
    else:
        display.print_results_table(filtered, username)
    display.print_summary(filtered)

    if verbose:
        errors = {n: r for n, r in results.items() if r.get("error")}
        if errors:
            console.print()
            display.print_error_details(errors)

    if emails:
        email_map = build_email_map(results)
        if email_map:
            console.print()
            display.print_email_results(email_map)


def _handle_scan_export(
    results: dict, username: str, export: str | None, output: Path | None
) -> None:
    if not export:
        return

    formats = [f.strip().lower() for f in export.split(",")]
    for fmt in formats:
        ext_map = {"json": "json", "csv": "csv", "markdown": "md", "md": "md", "html": "html"}
        ext = ext_map.get(fmt)
        if ext is None:
            console.print(f"[bold red]Unsupported export format:[/bold red] {fmt}")
            continue
        out_path = output or Path(f"{username}.{ext}")
        export_results(results, username, fmt, out_path)
        console.print(f"[dim]Exported results to {out_path}[/dim]")


def _print_error_summary(results: dict) -> None:
    by_error: dict[str, int] = {}
    for r in results.values():
        err = r.get("error")
        if err:
            by_error[err] = by_error.get(err, 0) + 1
    if by_error:
        console.print()
        display.print_error_summary(by_error)


def _run_batch_scan(
    file: Path,
    proxy: str | None,
    use_tor: bool,
    timeout: float,
    concurrency: int,
    export: str | None,
    output: Path | None,
    quiet: bool,
    verbose: bool,
    http2: bool,
    category: str | None,
    exclude: set[str] | None,
    status_filter: str | None,
    retry: bool,
    webhook: str | None,
    webhook_type: str,
) -> None:
    if not file.exists():
        console.print(f"[bold red]File not found:[/bold red] {file}")
        raise typer.Exit(code=1)

    usernames = file.read_text("utf-8").strip().splitlines()
    usernames = [u.strip() for u in usernames if u.strip()]
    if not usernames:
        console.print("[bold red]No usernames found in the file.[/bold red]")
        raise typer.Exit(code=1)

    categories = tuple(c.strip().lower() for c in category.split(",")) if category else None

    console.print(
        f"[bold cyan]Batch scan[/bold cyan] — {len(usernames)} username(s) from {file}\n"
    )

    all_results: dict[str, dict[str, dict]] = {}

    async def _scan_one(u: str) -> tuple[str, dict]:
        engine = ArgisEngine(
            u,
            proxy=proxy,
            use_tor=use_tor,
            timeout=timeout,
            concurrency=concurrency,
            http2=http2,
            categories=categories,
            exclude=exclude,
            retry_blocked=retry,
        )
        try:
            res = await engine.run_scan(quiet=quiet)
        except ArgisError:
            res = {}
        diffmod.save_scan(u, res)
        if not quiet:
            found = sum(1 for r in res.values() if r["status"] == "FOUND")
            console.print(f"  [cyan]@{u}[/cyan]: [green]{found}[/green] found / {len(res)} platforms")
        return u, res

    async def _run_all() -> None:
        sem = asyncio.Semaphore(concurrency // 10 + 1)

        async def _bounded(u: str) -> tuple[str, dict]:
            async with sem:
                return await _scan_one(u)

        tasks = [_bounded(u) for u in usernames]
        for u, res in await asyncio.gather(*tasks):
            all_results[u] = res

    asyncio.run(_run_all())

    if not quiet:
        console.print()
        display.print_batch_summary(all_results)

    _export_batch_results(all_results, export, output)

    if webhook:
        total_found = sum(
            1 for res in all_results.values() for r in res.values() if r["status"] == "FOUND"
        )
        success = asyncio.run(
            send_webhook(
                webhook,
                {"__batch__": {"status": "FOUND" if total_found > 0 else "NOT_FOUND"}},
                f"batch-{len(usernames)}-users",
                webhook_type=webhook_type,
            )
        )
        if success:
            console.print("[dim]Webhook notification sent.[/dim]")


def _export_batch_results(all_results: dict, export: str | None, output: Path | None) -> None:
    if not export:
        return
    formats = [f.strip().lower() for f in export.split(",")]
    for fmt in formats:
        if fmt == "json":
            import json as jsonmod
            out_path = output or Path("batch-results.json")
            out_path.write_text(jsonmod.dumps(all_results, indent=2))
            console.print(f"[dim]Exported batch results to {out_path}[/dim]")
        elif fmt == "csv":
            import csv
            out_path = output or Path("batch-results.csv")
            with open(out_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["username", "platform", "status", "url", "error"])
                for u, res in sorted(all_results.items()):
                    for p, info in sorted(res.items()):
                        writer.writerow([u, p, info["status"], info["url"], info.get("error", "")])
            console.print(f"[dim]Exported batch results to {out_path}[/dim]")
        elif fmt in ("markdown", "md"):
            out_path = output or Path("batch-results.md")
            lines = ["# Argis batch scan results", ""]
            for u, res in sorted(all_results.items()):
                found = sum(1 for r in res.values() if r["status"] == "FOUND")
                lines.append(f"## @{u} — {found} found\n")
                lines.append("| Platform | Status | URL | Error |")
                lines.append("|---|---|---|---|")
                for p, info in sorted(res.items()):
                    lines.append(f"| {p} | {info['status']} | {info['url']} | {info.get('error', '')} |")
                lines.append("")
            out_path.write_text("\n".join(lines))
            console.print(f"[dim]Exported batch results to {out_path}[/dim]")


TIMING_HELP = "Timing template 0-5: " + ", ".join(
    f"{k}={v['label']}" for k, v in sorted(TIMING_TEMPLATES.items())
)

SCRIPT_CHOICES = ["web", "banners", "dns", "whois", "geo", "all"]


@app.command(rich_help_panel="Reconnaissance")
def recon(
    target: str = typer.Argument(..., help="Hostname or IP address to scan (not a URL or CIDR)."),
    # === Scan types ===
    ag: bool = typer.Option(
        False, "-ag", "--ping-scan", help="Alive/ping-sweep — discover live hosts (skip port scan)."
    ),
    tc: bool = typer.Option(
        True, "-tc", "--tcp-connect", help="TCP connect scan (default)."
    ),
    ud: bool = typer.Option(
        False, "-ud", "--udp", help="UDP scan on common ports."
    ),
    sy: bool = typer.Option(
        False, "-sy", "--syn-scan", help="SYN scan — requires admin/raw socket privileges."
    ),
    sv: bool = typer.Option(
        False, "-sv", "--service-version", help="Service version detection on open ports."
    ),
    df: bool = typer.Option(
        False, "-df", "--default-scripts", help="Run default recon scripts (web + banners + DNS + WHOIS + geo)."
    ),
    os_detect: bool = typer.Option(
        False, "-os", "--os-detection", help="Attempt OS detection via TTL and banner analysis."
    ),
    ax: bool = typer.Option(
        False, "-ax", "--aggressive", help="Aggressive scan: -sv + -os + -df + --traceroute."
    ),
    # === Port specification ===
    pt: Optional[str] = typer.Option(
        None, "-pt", "--ports", help="Ports to scan (e.g. 22,80,443). Use '-' or '*' for all 65535 ports."
    ),
    # === Timing ===
    tm: int = typer.Option(
        3, "-tm", "--timing", min=0, max=5, help=TIMING_HELP,
    ),
    # === Script selection ===
    script: Optional[str] = typer.Option(
        None, "-sc", "--script", help="Comma-separated scripts to run: web,banners,dns,whois,geo,all."
    ),
    # === Traceroute ===
    traceroute: bool = typer.Option(
        False, "-tr", "--traceroute", help="Trace network path to the target host."
    ),
    # === Output formats ===
    on: Optional[str] = typer.Option(
        None, "-on", "--output-normal", help="Write normal (text) output to file."
    ),
    ox: Optional[str] = typer.Option(
        None, "-ox", "--output-xml", help="Write XML output to file."
    ),
    og: Optional[str] = typer.Option(
        None, "-og", "--output-grepable", help="Write grepable output to file."
    ),
    oa: Optional[str] = typer.Option(
        None, "-oa", "--output-all", help="Write all output formats (normal+XML+grepable) to base name."
    ),
    # === Geolocation ===
    geo: bool = typer.Option(
        False, "-gl", "--geo", help="Geolocate the target IP (requires ipgeolocation.io API key)."
    ),
    geo_key: Optional[str] = typer.Option(
        None, "--geo-key", help="ipgeolocation.io API key (or ARGIS_GEOIP_KEY env var)."
    ),
    # === General options ===
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress banner and print only final results."
    ),
    # === Legacy (hidden, backward-compat) ===
    web: Optional[bool] = typer.Option(None, "--web/--no-web", hidden=True),
    banners: Optional[bool] = typer.Option(None, "--banners/--no-banners", hidden=True),
    dns: Optional[bool] = typer.Option(None, "--dns", hidden=True),
    whois: Optional[bool] = typer.Option(None, "--whois", hidden=True),
    udp: Optional[bool] = typer.Option(None, "--udp", hidden=True),
    export: Optional[str] = typer.Option(None, "--export", hidden=True),
    output: Optional[Path] = typer.Option(None, "--output", hidden=True),
    timeout: Optional[float] = typer.Option(None, "--timeout", hidden=True),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", hidden=True),
):
    """Scan a target host — ports, services, OS, DNS, WHOIS, geo.

    \b
    Examples:
      argis recon example.com
      argis recon -ag 192.168.1.0/24
      argis recon -pt 22,80,443 -sv example.com
      argis recon -pt - -tm4 10.0.0.1
      argis recon -ax -gl example.com
      argis recon -tr -os github.com
      argis recon -ox scan.xml -on scan.txt example.com
    """
    if not quiet:
        display.print_recon_banner(target)

    # === Detect all-ports mode ===
    all_ports = pt in ("-", "*") if pt else False
    port_list = DEFAULT_PORTS
    if pt and not all_ports:
        try:
            port_list = tuple(int(x.strip()) for x in pt.split(",") if x.strip())
        except ValueError:
            console.print("[bold red]Error:[/bold red] -pt must be comma-separated integers, '-', or '*' for all.")
            raise typer.Exit(code=1)
    elif all_ports:
        port_list = ALL_TCP_PORTS
        console.print("[yellow]Scanning all 65535 TCP ports — this may take a while.[/yellow]")

    # === Aggressive mode (-ax) ===
    if ax:
        sv = True
        os_detect = True
        df = True
        traceroute = True
        geo = True

    # === Resolve script selection ===
    script_modules: set[str] = set()
    if script:
        parts = [s.strip().lower() for s in script.split(",")]
        for part in parts:
            if part == "all":
                script_modules = {"web", "banners", "dns", "whois", "geo"}
                break
            if part in SCRIPT_CHOICES:
                script_modules.add(part)

    do_web = "web" in script_modules or df or (web is not False)
    do_banners = "banners" in script_modules or sv or df or (banners is not False)
    do_dns = "dns" in script_modules or df or dns or False
    do_whois = "whois" in script_modules or df or whois or False
    do_udp = ud or udp or False
    do_os = os_detect
    do_traceroute = traceroute
    do_geo = geo

    # === Ping scan (-ag) ===
    if ag:
        probe_ports = (80, 443, 22)
        if pt and not all_ports:
            probe_ports = port_list
        try:
            results = asyncio.run(
                discover_hosts(target, probe_ports=probe_ports, timeout=1.0, concurrency=100)
            )
        except ArgisError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(code=1)
        display.print_discovery_results(target, results)
        return

    # === Timing ===
    timing_cfg = TIMING_TEMPLATES.get(tm, TIMING_TEMPLATES[3])
    t_out = timeout or timing_cfg["timeout"]
    t_conc = concurrency or timing_cfg["concurrency"]

    if not quiet and ax:
        console.print(f"[bold]Aggressive mode (-ax):[/bold] {timing_cfg['label']} timing\n")

    # === Main recon ===
    try:
        report = asyncio.run(
            run_recon(
                target,
                ports=port_list,
                do_web=do_web,
                do_banners=do_banners,
                do_dns=do_dns,
                do_whois=do_whois,
                do_os_detection=do_os,
                do_traceroute=do_traceroute,
                do_syn_scan=sy,
                timing=tm,
                port_timeout=t_out,
                port_concurrency=t_conc,
            )
        )
    except ArgisError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    display.print_port_results(target, report.open_ports)

    if do_udp:
        console.print()
        udp_results = asyncio.run(
            udp_port_scan(target, timeout=t_out, concurrency=t_conc)
        )
        display.print_udp_results(target, udp_results)

    if do_web and report.web_results:
        console.print()
        display.print_web_results(report.web_results)
    if do_banners and report.banners:
        console.print()
        display.print_banner_results(report.banners)
    if report.os_guesses:
        console.print()
        display.print_os_results(report.os_guesses)
    if report.traceroute_hops:
        console.print()
        display.print_traceroute_results(report.traceroute_hops)
    if do_dns and report.dns:
        console.print()
        display.print_dns_results(report.dns)
    if do_whois and report.whois:
        console.print()
        display.print_whois_results(report.whois)
    if do_geo:
        from argis.utils.geoip import geoip_lookup

        console.print()
        geo_result = asyncio.run(geoip_lookup(target, api_key=geo_key, timeout=t_out))
        display.print_geoip_results(geo_result)

    # === Output handling ===
    base_name = oa or None
    output_files: list[str] = []

    if export:
        _handle_legacy_export(report, export, output)

    if on or base_name:
        path = Path(on or f"{base_name}.txt") if base_name else Path(on)
        _write_normal_output(report, path)
        output_files.append(str(path))

    if ox or base_name:
        path = Path(ox or f"{base_name}.xml") if base_name else Path(ox)
        _write_xml_output(report, path)
        output_files.append(str(path))

    if og or base_name:
        path = Path(og or f"{base_name}.grepable") if base_name else Path(og)
        _write_grepable_output(report, path)
        output_files.append(str(path))

    if output_files:
        for f in output_files:
            console.print(f"[dim]Wrote output to {f}[/dim]")


def _build_recon_dict(report) -> dict:
    d: dict = {
        "target": report.target,
        "open_ports": [
            {"port": r.port, "service_guess": r.service_guess}
            for r in report.open_ports if r.open
        ],
        "web": [
            {
                "port": r.port, "scheme": r.scheme, "status_code": r.status_code,
                "server": r.server, "title": r.title, "error": r.error,
                "tech_stack": r.tech_stack,
            }
            for r in report.web_results
        ],
        "banners": [
            {"port": r.port, "banner": r.banner, "version": r.version, "error": r.error}
            for r in report.banners
        ],
    }
    if report.dns and not report.dns.error:
        d["dns"] = {
            "hostname": report.dns.hostname,
            "records": [{"type": r.type, "value": r.value} for r in report.dns.records],
        }
    if report.whois:
        d["whois"] = report.whois[:1000]
    if report.os_guesses:
        d["os_guesses"] = [
            {"name": g.name, "accuracy": g.accuracy, "detail": g.detail}
            for g in report.os_guesses
        ]
    if report.traceroute_hops:
        d["traceroute"] = [
            {"ttl": h.ttl, "ip": h.ip, "rtt_ms": round(h.rtt, 1) if h.rtt else None}
            for h in report.traceroute_hops
        ]
    return d


def _handle_legacy_export(report, fmt: str, output: Optional[Path]) -> None:
    fmt = fmt.lower()
    ext_map = {"json": "json", "csv": "csv", "markdown": "md", "html": "html"}
    ext = ext_map.get(fmt)
    if ext is None:
        console.print(f"[bold red]Unsupported export format:[/bold red] {fmt}")
        raise typer.Exit(code=1)
    data = _build_recon_dict(report)
    out_path = output or Path(f"{report.target}-recon.{ext}")

    if fmt == "json":
        import json as jsonmod
        out_path.write_text(jsonmod.dumps(data, indent=2))
    elif fmt == "html":
        _write_recon_html(data, out_path)
    elif fmt == "markdown":
        _write_recon_markdown(data, out_path)
    elif fmt == "csv":
        _write_recon_csv(data, out_path)

    console.print(f"[dim]Exported results to {out_path}[/dim]")


def _write_recon_html(data: dict, out_path: Path) -> None:
    target = data["target"]
    rows = ""
    for p in data.get("open_ports", []):
        rows += f"<tr><td>{p['port']}</td><td>tcp</td><td>{p['service_guess'] or 'unknown'}</td></tr>\n"
    for w in data.get("web", []):
        rows += f"<tr><td>{w['port']}</td><td>{w['scheme']}</td><td>{w.get('status_code') or w.get('error') or '-'}</td></tr>\n"

    os_rows = ""
    for g in data.get("os_guesses", []):
        os_rows += f"<tr><td>{g['name']}</td><td>{g['accuracy']}%</td><td>{g.get('detail', '')}</td></tr>\n"

    tr_rows = ""
    for h in data.get("traceroute", []):
        ip = h["ip"] or "*"
        rtt = f"{h['rtt_ms']}ms" if h.get("rtt_ms") else "-"
        tr_rows += f"<tr><td>{h['ttl']}</td><td>{ip}</td><td>{rtt}</td></tr>\n"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon report — {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #0f172a; color: #e2e8f0; }}
  h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e293b; }}
  th {{ background: #1e293b; color: #94a3b8; text-transform: uppercase; font-size: 0.8em; }}
  tr:hover {{ background: #1e293b; }}
  .section {{ margin-top: 30px; }}
  .section h2 {{ color: #f472b6; }}
</style>
</head>
<body>
<h1>Recon report — {target}</h1>
<div class="section">
<h2>Open Ports & Services</h2>
<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th></tr></thead><tbody>{rows}</tbody></table>
</div>
<div class="section">
<h2>Banners</h2>
<table><thead><tr><th>Port</th><th>Banner</th><th>Version</th></tr></thead><tbody>
{"".join(f"<tr><td>{b['port']}</td><td>{b['banner'] or '-'}</td><td>{b.get('version') or '-'}</td></tr>" for b in data.get("banners", []) if b.get("banner"))}
</tbody></table>
</div>
{"<div class='section'><h2>OS Detection</h2><table><thead><tr><th>Name</th><th>Accuracy</th><th>Detail</th></tr></thead><tbody>" + os_rows + "</tbody></table></div>" if os_rows else ""}
{"<div class='section'><h2>Traceroute</h2><table><thead><tr><th>Hop</th><th>IP</th><th>RTT</th></tr></thead><tbody>" + tr_rows + "</tbody></table></div>" if tr_rows else ""}
</body>
</html>"""
    out_path.write_text(html)


def _write_recon_markdown(data: dict, out_path: Path) -> None:
    lines = [f"# Recon report: {data['target']}", "", "## Open ports", ""]
    lines += ["| Port | Service |", "|---|---|"]
    lines += [f"| {p['port']} | {p['service_guess'] or 'unknown'} |" for p in data["open_ports"]]
    lines += ["", "## Web fingerprint", "", "| Port | Scheme | Status | Server | Title |", "|---|---|---|---|---|"]
    lines += [
        f"| {w['port']} | {w['scheme']} | {w.get('status_code') or w.get('error') or '-'} | "
        f"{w.get('server') or '-'} | {w.get('title') or '-'} |"
        for w in data["web"]
    ]
    if data.get("banners"):
        lines += ["", "## Banners", "", "| Port | Banner | Version |", "|---|---|---|"]
        lines += [
            f"| {b['port']} | {b['banner'] or '-'} | {b.get('version') or '-'} |"
            for b in data["banners"]
        ]
    if data.get("dns"):
        lines += ["", "## DNS Records", "", "| Type | Value |", "|---|---|"]
        lines += [f"| {r['type']} | {r['value']} |" for r in data["dns"]["records"]]
    if data.get("os_guesses"):
        lines += ["", "## OS Detection", "", "| Name | Accuracy | Detail |", "|---|---|---|"]
        lines += [f"| {g['name']} | {g['accuracy']}% | {g.get('detail', '')} |" for g in data["os_guesses"]]
    if data.get("traceroute"):
        lines += ["", "## Traceroute", "", "| Hop | IP | RTT |", "|---|---|---|"]
        lines += ["| {} | {} | {} |".format(h['ttl'], h['ip'] or '*', f"{h['rtt_ms']}ms" if h.get('rtt_ms') else '-') for h in data["traceroute"]]
    out_path.write_text("\n".join(lines))


def _write_recon_csv(data: dict, out_path: Path) -> None:
    import csv
    with open(out_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["type", "port", "detail"])
        for p in data["open_ports"]:
            writer.writerow(["port", p["port"], p["service_guess"] or "unknown"])
        for w in data["web"]:
            writer.writerow(["web", w["port"], f"{w.get('status_code')} {w.get('server') or ''} {w.get('title') or ''}"])


def _write_normal_output(report, path: Path) -> None:
    data = _build_recon_dict(report)
    lines = [
        f"# Nmap-like scan report for {report.target}",
        f"# Timestamp: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    if data["open_ports"]:
        lines.append("PORT\tSTATE\tSERVICE")
        for p in data["open_ports"]:
            lines.append(f"{p['port']}/tcp\topen\t{p['service_guess'] or 'unknown'}")
        lines.append("")
    for w in data["web"]:
        lines.append(f"WEB\t{w['port']}\t{w.get('status_code') or w.get('error', '-')}\t{w.get('server', '-')}\t{w.get('title', '-')}")
    if data.get("os_guesses"):
        lines.append("")
        lines.append("OS DETECTION:")
        for g in data["os_guesses"]:
            lines.append(f"  {g['name']} ({g['accuracy']}%)")
    if data.get("traceroute"):
        lines.append("")
        lines.append("TRACEROUTE:")
        for h in data["traceroute"]:
            ip = h["ip"] or "*"
            rtt = f"{h['rtt_ms']}ms" if h.get("rtt_ms") else "-"
            lines.append(f"  {h['ttl']}  {ip}  {rtt}")
    path.write_text("\n".join(lines))


def _write_xml_output(report, path: Path) -> None:
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    root = ET.Element("nmapscan")
    root.set("target", report.target)

    ports_el = ET.SubElement(root, "ports")
    for r in report.open_ports:
        if r.open:
            p = ET.SubElement(ports_el, "port")
            p.set("portid", str(r.port))
            p.set("protocol", "tcp")
            p.set("state", "open")
            s = ET.SubElement(p, "service")
            s.set("name", r.service_guess or "unknown")

    web_el = ET.SubElement(root, "web")
    for r in report.web_results:
        w = ET.SubElement(web_el, "result")
        w.set("port", str(r.port))
        w.set("scheme", r.scheme)
        if r.status_code:
            w.set("status", str(r.status_code))
        if r.server:
            w.set("server", r.server)
        if r.title:
            w.set("title", r.title)

    banners_el = ET.SubElement(root, "banners")
    for r in report.banners:
        if r.banner:
            b = ET.SubElement(banners_el, "banner")
            b.set("port", str(r.port))
            b.text = r.banner[:200]
            if r.version:
                b.set("version", r.version)

    if report.os_guesses:
        os_el = ET.SubElement(root, "os")
        for g in report.os_guesses:
            o = ET.SubElement(os_el, "guess")
            o.set("name", g.name)
            o.set("accuracy", str(g.accuracy))

    if report.traceroute_hops:
        tr_el = ET.SubElement(root, "traceroute")
        for h in report.traceroute_hops:
            hop = ET.SubElement(tr_el, "hop")
            hop.set("ttl", str(h.ttl))
            hop.set("ip", h.ip or "*")
            if h.rtt:
                hop.set("rtt_ms", f"{h.rtt:.1f}")

    rough = ET.tostring(root, encoding="unicode")
    dom = minidom.parseString(rough.encode())
    path.write_text(dom.toprettyxml(indent="  "))


def _write_grepable_output(report, path: Path) -> None:
    lines: list[str] = []
    for r in report.open_ports:
        if r.open:
            svc = r.service_guess or "unknown"
            lines.append(f"Port: {r.port}/tcp\tState: open\tService: {svc}")
    for r in report.web_results:
        status = r.status_code or r.error or "-"
        title = r.title or "-"
        lines.append(f"Web: {r.port}\tStatus: {status}\tTitle: {title}")
    if report.os_guesses:
        best = report.os_guesses[0]
        lines.append(f"OS: {best.name}\tAccuracy: {best.accuracy}%")
    for h in report.traceroute_hops:
        ip = h.ip or "*"
        rtt = f"{h.rtt:.1f}ms" if h.rtt else "-"
        lines.append(f"Hop: {h.ttl}\tIP: {ip}\tRTT: {rtt}")
    path.write_text("\n".join(lines))


@app.command(rich_help_panel="Reconnaissance")
def discover(
    cidr: str = typer.Argument(..., help="Subnet to sweep, e.g. 192.168.1.0/24 (capped at 256 hosts)."),
    ports: Optional[str] = typer.Option(
        None, "--ports", help="Comma-separated probe ports (default: 80,443,22)."
    ),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-probe timeout in seconds."),
    concurrency: int = typer.Option(
        100, "--concurrency", help="Maximum number of simultaneous host probes."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the banner."),
):
    """Sweep a subnet to find which hosts respond (TCP-probe based host discovery)."""
    if not quiet:
        display.print_recon_banner(cidr)

    probe_ports = (80, 443, 22)
    if ports:
        try:
            probe_ports = tuple(int(p.strip()) for p in ports.split(",") if p.strip())
        except ValueError:
            console.print("[bold red]Error:[/bold red] --ports must be a comma-separated list of integers.")
            raise typer.Exit(code=1)

    try:
        results = asyncio.run(
            discover_hosts(cidr, probe_ports=probe_ports, timeout=timeout, concurrency=concurrency)
        )
    except ArgisError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    display.print_discovery_results(cidr, results)


@app.command(rich_help_panel="History & Tracking")
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


@app.command("clear-history", rich_help_panel="History & Tracking")
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


@app.command(rich_help_panel="History & Tracking")
def monitor(
    username: str = typer.Argument(..., help="Username to continuously watch."),
    interval: int = typer.Option(
        300, "--interval", "-i", help="Seconds between scans (default: 300 = 5 min)."
    ),
    diff: bool = typer.Option(
        True, "--diff/--no-diff", help="Show diff against the previous cycle."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress per-cycle output."),
):
    """Continuously watch a username and report changes over time."""
    display.print_monitor_header(username, interval)
    previous_results = None

    try:
        while True:
            engine = ArgisEngine(username)
            results = asyncio.run(engine.run_scan(quiet=quiet))

            if previous_results is not None and diff:
                delta = diffmod.compute_diff(previous_results, results)
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                console.print(f"\n[dim][{ts}] Scan complete — checking for changes...[/dim]")
                if delta["added"] or delta["removed"]:
                    display.print_monitor_diff(previous_results, results)
                else:
                    console.print("[dim]No changes detected.[/dim]")
            elif not quiet:
                display.print_summary(results)

            previous_results = results
            diffmod.save_scan(username, results)

            console.print(
                f"[dim]Next scan in [yellow]{interval}s[/yellow]. "
                f"Press Ctrl+C to stop.[/dim]"
            )
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")


@app.command(rich_help_panel="Analysis")
def search(
    query: str = typer.Argument(..., help="Search term to look for."),
    field: str = typer.Option(
        "platform", "--field", "-f", help="Field to search: platform or url."
    ),
    status: Optional[str] = typer.Option(
        None, "--status", "-s", help="Filter by status: FOUND, NOT_FOUND, BLOCKED, etc."
    ),
    limit: int = typer.Option(20, "--limit", help="Maximum number of results to show."),
):
    """Search across all scanned history for a platform or URL."""
    matches = diffmod.search_history(query, field=field, status_filter=status)
    if not matches:
        console.print(f"[dim]No matches found for '{query}'.[/dim]")
        return

    table = Table(title=f"Search results for '{query}'")
    table.add_column("Username", style="white")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Platform", style="white")
    table.add_column("Status")
    table.add_column("URL", style="cyan", overflow="fold")

    for m in matches[-limit:]:
        style = display.STATUS_STYLES.get(m["status"], "white")
        table.add_row(
            m["username"],
            m["timestamp"],
            m["platform"],
            f"[{style}]{m['status']}[/{style}]",
            m["url"],
        )

    console.print(table)
    console.print(f"[dim]{len(matches)} total match(es), showing last {min(limit, len(matches))}[/dim]")


@app.command(rich_help_panel="Analysis")
def stats(
    top: int = typer.Option(15, "--top", help="Number of top platforms to show."),
):
    """Show aggregate statistics across all tracked users."""
    data = diffmod.aggregate_stats()

    console.print(
        Panel.fit(
            f"[bold cyan]Users tracked:[/bold cyan] {data['total_users']}\n"
            f"[bold cyan]Total scans:[/bold cyan] {data['total_scans']}\n"
            f"[bold cyan]Total found profiles:[/bold cyan] [green]{data['total_found_profiles']}[/green]\n"
            f"[bold cyan]Emails collected:[/bold cyan] {data['total_emails_collected']}",
            title="\U0001f4ca Argis Statistics",
        )
    )

    if data["top_platforms"]:
        table = Table(title=f"Top {min(top, len(data['top_platforms']))} platforms")
        table.add_column("Platform", style="white")
        table.add_column("Times Found", style="green")

        for entry in data["top_platforms"][:top]:
            table.add_row(entry["platform"], str(entry["count"]))

        console.print(table)


@app.command(rich_help_panel="Utilities")
def categories():
    """List all available site categories."""
    cats = extract_categories()
    if not cats:
        console.print("[dim]No categories found.[/dim]")
        return
    console.print("[bold]Available categories:[/bold]")
    for cat in cats:
        console.print(f"  [cyan]{cat}[/cyan]")


@app.command(rich_help_panel="Analysis")
def compare(
    username1: str = typer.Argument(..., help="First username to compare."),
    username2: str = typer.Argument(..., help="Second username to compare."),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Comma-separated list of categories to filter by."
    ),
    timeout: float = typer.Option(7.0, "--timeout", help="Per-request timeout in seconds."),
    concurrency: int = typer.Option(30, "--concurrency", help="Max simultaneous requests."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress."),
):
    """Compare two usernames side by side to find shared and unique profiles."""
    categories = tuple(c.strip().lower() for c in category.split(",")) if category else None

    if not quiet:
        display.print_recon_banner(f"{username1} vs {username2}")

    engine1 = ArgisEngine(username1, timeout=timeout, concurrency=concurrency, categories=categories)
    engine2 = ArgisEngine(username2, timeout=timeout, concurrency=concurrency, categories=categories)

    results1 = asyncio.run(engine1.run_scan(quiet=True))
    results2 = asyncio.run(engine2.run_scan(quiet=True))

    set1 = {p for p, r in results1.items() if r["status"] == "FOUND"}
    set2 = {p for p, r in results2.items() if r["status"] == "FOUND"}

    both = set1 & set2
    only1 = set1 - set2
    only2 = set2 - set1

    table = Table(title=f"Comparison: @{username1} vs @{username2}")
    table.add_column("Category", style="white")
    table.add_column("Count", style="cyan")
    table.add_column("Platforms", style="green", overflow="fold")

    both_sorted = sorted(both)
    only1_sorted = sorted(only1)
    only2_sorted = sorted(only2)

    table.add_row("Both", str(len(both_sorted)), ", ".join(both_sorted) if both_sorted else "-")
    table.add_row(
        f"Only @{username1}", str(len(only1_sorted)), ", ".join(only1_sorted) if only1_sorted else "-"
    )
    table.add_row(
        f"Only @{username2}", str(len(only2_sorted)), ", ".join(only2_sorted) if only2_sorted else "-"
    )

    console.print(table)
    console.print(
        f"[dim]Overlap: {len(both)} shared / {len(set1 | set2)} unique platforms.[/dim]"
    )


@app.command(rich_help_panel="Analysis")
def wayback(
    username: str = typer.Argument(..., help="Username to check on Wayback Machine."),
    limit: int = typer.Option(20, "--limit", help="Max snapshots to show."),
    timeout: float = typer.Option(10.0, "--timeout", help="API request timeout."),
):
    """Check the Wayback Machine for historical snapshots of a username's profiles."""
    display.print_recon_banner(f"{username} (Wayback)")

    result = asyncio.run(check_wayback(username, limit=limit, timeout=timeout))

    if result.error:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        raise typer.Exit(code=1)

    if result.total == 0:
        console.print(f"[dim]No Wayback Machine snapshots found for '{username}'.[/dim]")
        return

    panel_text = (
        f"[bold cyan]Total snapshots:[/bold cyan] {result.total}\n"
        f"[bold cyan]First seen:[/bold cyan] {result.first_seen or 'N/A'}\n"
        f"[bold cyan]Last seen:[/bold cyan] {result.last_seen or 'N/A'}"
    )
    console.print(Panel.fit(panel_text, title="Wayback Summary"))

    table = Table(title=f"Recent snapshots for @{username}")
    table.add_column("Timestamp", style="cyan")
    table.add_column("URL", style="green", overflow="fold")
    table.add_column("Status", style="white")

    for snap in result.snapshots[:limit]:
        table.add_row(snap.timestamp, snap.url, snap.status_code or "-")

    console.print(table)
    console.print(f"[dim]Showing {min(limit, result.total)} of {result.total} snapshots.[/dim]")


@app.command(rich_help_panel="Reconnaissance")
def domain(
    domain_name: str = typer.Argument(..., help="Domain name to investigate (e.g. example.com)."),
    timeout: float = typer.Option(3.0, "--timeout", help="Lookup timeout in seconds."),
    whois: bool = typer.Option(False, "--whois", help="Perform WHOIS lookup."),
    geo: bool = typer.Option(False, "--geo", help="IP geolocation lookup (requires API key)."),
    geo_key: Optional[str] = typer.Option(
        None, "--geo-key", help="ipgeolocation.io API key (or set ARGIS_GEOIP_KEY env var)."
    ),
    scan_ports: bool = typer.Option(
        False, "--scan-ports", help="Scan common ports on the resolved IP."
    ),
):
    """DNS resolution, WHOIS, and optional port scan for a domain."""
    from argis.recon import dns_enum, run_whois, port_scan

    display.print_recon_banner(domain_name)

    dns_result = asyncio.run(dns_enum(domain_name))
    display.print_dns_results(dns_result)

    if whois:
        whois_text = asyncio.run(asyncio.to_thread(run_whois, domain_name))
        display.print_whois_results(whois_text)

    if geo and dns_result and not dns_result.error and dns_result.records:
        from argis.utils.geoip import geoip_lookup

        ip = dns_result.records[0].value
        geo_result = asyncio.run(geoip_lookup(ip, api_key=geo_key, timeout=timeout))
        display.print_geoip_results(geo_result)

    if scan_ports and dns_result and not dns_result.error and dns_result.records:
        ip = dns_result.records[0].value
        console.print(f"\n[bold]Scanning ports on {ip}...[/bold]")
        open_ports = asyncio.run(
            port_scan(ip, timeout=min(timeout, 2.0), concurrency=50)
        )
        display.print_port_results(ip, open_ports)


@app.command(rich_help_panel="Reconnaissance")
def myip(
    geo: bool = typer.Option(True, "--geo/--no-geo", help="Geolocate your public IP."),
    geo_key: Optional[str] = typer.Option(
        None, "--geo-key", help="ipgeolocation.io API key (or set ARGIS_GEOIP_KEY env var)."
    ),
    timeout: float = typer.Option(5.0, "--timeout", help="Lookup timeout in seconds."),
):
    """Show your public IP address and optionally geolocate it."""
    from argis.utils.geoip import geoip_lookup, get_public_ip

    display.print_recon_banner("myip")
    ip = asyncio.run(get_public_ip(timeout=timeout))

    if not ip:
        console.print("[bold red]Could not determine public IP.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]Public IP:[/bold cyan] [green]{ip}[/green]\n")

    if geo:
        result = asyncio.run(geoip_lookup(ip, api_key=geo_key, timeout=timeout))
        display.print_geoip_results(result)


if __name__ == "__main__":
    app()
