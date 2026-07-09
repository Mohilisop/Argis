from __future__ import annotations

import asyncio
import time
import webbrowser
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
                    ("scan-image <img>", "Extract usernames/URLs from a screenshot via OCR"),
                    ("scan-face <img>", "Detect faces and reverse-search them for profiles"),
                ],
                "Intelligence": [
                    ("doctor", "Health-check every site rule and flag rot"),
                    ("link <username>", "Cluster accounts into real identities vs impersonators"),
                    ("guard <username>", "Hunt lookalike handles impersonating you"),
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
                    ("compare <u1> <u2>", "Compare two usernames side-by-side"),
                    ("exposure <username>", "Privacy risk score (0-100) + shrink plan"),
                    ("timeline <username>", "Chronological timeline of account creation"),
                    ("graph <username>", "Interactive pivot graph of accounts & references"),
                    ("wayback <username>", "Check Wayback Machine history for a username"),
                ],
                "Utilities": [
                    ("categories", "List all available platform categories"),
                    ("search", "Search across all scan history"),
                    ("stats", "Aggregate statistics on scan results"),
                    ("import-sites <source> <path>", "Import Sherlock/Maigret sites into Argis"),
                    ("setup-celebrity-db", "Download celebrity face data for offline DeepFace matching"),
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
    animate: bool = typer.Option(
        True, "--animate/--no-animate",
        help="Play the animated startup logo (auto-skipped on non-interactive terminals).",
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
    screenshots: bool = typer.Option(
        False, "--screenshots", help="Capture screenshots of found profile pages via Playwright."
    ),
    show_screenshots: bool = typer.Option(
        False, "--show", help="Show screenshots as ANSI art in the terminal."
    ),
    site: Optional[str] = typer.Option(
        None, "--site", help="Only check specific platform(s). Comma-separated, e.g. 'GitHub,X (Twitter)'."
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
            "animate": animate,
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
        animate = animate and cfg.get("animate", True)

    categories = tuple(c.strip().lower() for c in category.split(",")) if category else None
    exclude_set = set(e.strip().lower() for e in exclude.split(",")) if exclude else None
    include_set = set(s.strip() for s in site.split(",")) if site else None

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
            screenshots=screenshots,
            show_screenshots=show_screenshots,
        )
        return

    if not quiet:
        display.print_banner(username, animate=animate)

    engine = ArgisEngine(
        username,
        proxy=proxy,
        use_tor=tor,
        timeout=timeout or 7.0,
        concurrency=concurrency or 30,
        http2=http2,
        categories=categories,
        exclude=exclude_set,
        include=include_set,
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

    screenshot_data: dict[str, bytes] = {}
    if screenshots:
        try:
            from argis.utils.screenshot import take_screenshots

            screenshot_data = asyncio.run(take_screenshots(results, username))
            if not screenshot_data and not quiet:
                console.print("[dim]No screenshots captured (Playwright may not be installed).[/dim]")
        except Exception as exc:
            if verbose:
                console.print(f"[dim][yellow]Screenshots failed: {exc}[/yellow][/dim]")

    if show_screenshots and screenshot_data:
        try:
            from argis.utils.screenshot import print_terminal_screenshots
            print_terminal_screenshots(screenshot_data)
        except Exception as exc:
            if verbose:
                console.print(f"[dim][yellow]Terminal rendering failed: {exc}[/yellow][/dim]")

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


@app.command(rich_help_panel="Username Scanning")
def scan_image(
    image: Path = typer.Argument(..., help="Path to a screenshot image to OCR."),
    scan: bool = typer.Option(
        False, "--scan", "-s", help="Run argis scan on extracted usernames."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress OCR text output."),
):
    """Extract usernames and URLs from a screenshot image via OCR.

    \b
    Examples:
      argis scan-image screenshot.png
      argis scan-image screenshot.png --scan
    """
    from argis.utils.ocr import extract_text, extract_urls, extract_usernames, extract_potential_usernames

    text = extract_text(str(image))
    if text is None:
        console.print("[yellow]OCR not available. Install Tesseract (https://github.com/UB-Mannheim/tesseract/releases) then: pip install \"argis[screenshots]\"[/yellow]")
        raise typer.Exit(code=1)

    if not quiet:
        from rich.markup import escape
        console.print(f"\n[bold cyan]OCR text:[/bold cyan]\n[dim]{escape(text)}[/dim]")

    urls = extract_urls(text)
    usernames = extract_usernames(text, urls)
    potentials = extract_potential_usernames(text)

    if usernames:
        console.print(f"\n[bold cyan]Usernames found ({len(usernames)}):[/bold cyan]")
        for u in usernames:
            console.print(f"  [green]@{u}[/green]")

    if potentials and potentials != usernames:
        extra = [p for p in potentials if p not in usernames]
        if extra:
            console.print(f"\n[bold yellow]Potential usernames ({len(extra)}):[/bold yellow]")
            for u in extra:
                console.print(f"  [yellow]{u}[/yellow]")
            console.print("[dim]Tip: use argis scan <name> to scan a potential username[/dim]")

    if not usernames and not potentials:
        console.print("\n[dim]No usernames found.[/dim]")

    if urls:
        console.print(f"\n[bold cyan]URLs found ({len(urls)}):[/bold cyan]")
        for u in urls:
            console.print(f"  [link={u}]{u}[/link]")
    else:
        console.print("\n[dim]No URLs found.[/dim]")

    all_targets = usernames + ([p for p in potentials if p not in usernames] if potentials else [])

    if scan and all_targets:
        from argis.core import ArgisEngine

        for u in all_targets:
            print(f"\n--- Scanning @{u} ---")
            engine = ArgisEngine(u)
            try:
                results = asyncio.run(engine.run_scan(quiet=True))
                found = sum(1 for r in results.values() if r["status"] == "FOUND")
                print(f"  @{u}: {found}/{len(results)} platforms found")
                for name, info in sorted(results.items()):
                    if info["status"] == "FOUND":
                        print(f"    + {name}: {info['url']}")
            except Exception as exc:
                print(f"  Scan failed: {exc}")


@app.command(rich_help_panel="Username Scanning")
def scan_face(
    image: Path = typer.Argument(..., help="Path to an image to scan for faces."),
    identify: bool = typer.Option(
        False, "--identify", "-i", help="Identify the person via reverse search and auto-scan for profiles."
    ),
    search: bool = typer.Option(
        False, "--search", "-s", help="Open reverse search in browser (no auto-scan)."
    ),
    engine: str = typer.Option(
        "google", "--engine", "-e",
        help="Reverse search engine: google, tineye, bing, yandex, saucenao, iqdb, imgops"
    ),
    crop: bool = typer.Option(
        False, "--crop", "-c", help="Save face crops to disk."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory for face crops (default: ~/.argis/faces/).",
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Skip online reverse search; use DeepFace offline only."
    ),
    site: Optional[str] = typer.Option(
        None, "--site", help="Only scan specific platforms (comma-separated). e.g. 'X (Twitter),GitHub'."
    ),
):
    """Detect faces, identify the person, and scan for their profiles.

    \b
    Examples:
      argis scan-face photo.jpg
      argis scan-face photo.jpg --search
      argis scan-face photo.jpg --identify
      argis scan-face photo.jpg --engine tineye --search
      argis scan-face photo.jpg --identify --offline         # DeepFace only
    """
    from argis.utils.vision import detect_faces, crop_face, get_face_bytes, upload_to_engine, get_engine_url, ENGINES

    faces = detect_faces(str(image))
    if not faces:
        console.print("[yellow]No faces detected or OpenCV not installed.[/yellow]")
        console.print("[dim]Install: pip install \"argis[vision]\"[/dim]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Faces detected: {len(faces)}[/bold cyan]")
    for i, (x, y, w, h) in enumerate(faces, 1):
        console.print(f"  [green]#{i}[/green] at ({x}, {y}) size {w}x{h}")

    crop_dir = output or (Path.home() / ".argis" / "faces")

    if crop:
        saved = []
        for i, face in enumerate(faces, 1):
            p = crop_face(str(image), face, crop_dir, i)
            saved.append(p)
        console.print(f"\n[green]Saved {len(saved)} face crop(s) to:[/green]")
        for p in saved:
            console.print(f"  [dim]{p}[/dim]")

    if engine not in ENGINES:
        console.print(f"[yellow]Unknown engine '{engine}'. Supported: {', '.join(ENGINES)}[/yellow]")
        raise typer.Exit(code=1)

    if search:
        for i, face in enumerate(faces, 1):
            face_bytes = get_face_bytes(str(image), face)
            if not face_bytes:
                continue
            url = upload_to_engine(face_bytes, engine)
            if url:
                console.print(f"\n[bold cyan]Reverse search for face #{i}:[/bold cyan]")
                console.print(f"  [link={url}]{url}[/link]")
                webbrowser.open(url)
            else:
                crop_path = crop_face(str(image), face, crop_dir, i)
                engine_url = get_engine_url(engine)
                console.print(f"\n[bold cyan]Face #{i}: Could not auto-upload. Open {engine_url} and upload this file:[/bold cyan]")
                console.print(f"  [dim]{crop_path}[/dim]")
                webbrowser.open(engine_url)

    if identify:
        from argis.core import ArgisEngine
        from argis.utils.vision import identify_face, find_celebrity_lookalike, setup_celebrity_db, analyze_face

        for i, face in enumerate(faces, 1):
            console.print(f"\n[bold cyan]Face #{i}: Identifying...[/bold cyan]")
            face_bytes = get_face_bytes(str(image), face)
            if not face_bytes:
                console.print("  [red]Failed to read face crop.[/red]")
                continue

            name = None
            crop_path = None

            # Strategy 0: insightface offline demographic analysis
            if not offline:
                crop_path = crop_path or crop_face(str(image), face, crop_dir, i)
                try:
                    demo = analyze_face(str(crop_path))
                    if demo and demo.get("detected"):
                        parts = []
                        if demo.get("age"):
                            parts.append(f"age ~{int(demo['age'])}")
                        if demo.get("gender"):
                            parts.append(demo["gender"])
                        if parts:
                            console.print(f"  [dim]Demographics: {', '.join(parts)}[/dim]")
                except Exception:
                    pass

            # Strategy 1: insightface offline celebrity lookalike
            crop_path = crop_path or crop_face(str(image), face, crop_dir, i)
            try:
                celeb = find_celebrity_lookalike(str(crop_path))
                if celeb:
                    name = celeb["identity"]
                    console.print(f"  [green]Face match:[/green] {name} ({celeb['similarity']} confidence)")
            except Exception:
                pass

            # Strategy 2: host image + Google reverse search HTML
            if not name and not offline:
                try:
                    name = identify_face(face_bytes)
                    if name:
                        console.print(f"  [green]Google reverse search:[/green] {name}")
                except Exception as e:
                    console.print(f"  [dim]Google reverse search failed: {e}[/dim]")

            # Strategy 3: upload-to-engine + Playwright
            if not name and not offline:
                search_url = upload_to_engine(face_bytes, engine)
                if search_url:
                    try:
                        from argis.utils.vision import identify_from_search
                        import asyncio
                        loop = asyncio.new_event_loop()
                        name = loop.run_until_complete(identify_from_search(search_url))
                        loop.close()
                        if name:
                            console.print(f"  [green]Playwright extraction:[/green] {name}")
                    except Exception as e:
                        console.print(f"  [dim]Playwright extraction failed: {e}[/dim]")

            if name:
                username = name.lower().replace(" ", "").replace(".", "")
                print(f"\n--- Scanning @{username} ---")
                include_set_face = set(s.strip() for s in site.split(",")) if site else None
                eng = ArgisEngine(username, include=include_set_face)
                try:
                    results = asyncio.run(eng.run_scan(quiet=True))
                    found = sum(1 for r in results.values() if r["status"] == "FOUND")
                    print(f"  @{username}: {found}/{len(results)} platforms found")
                    for pname, info in sorted(results.items()):
                        if info["status"] == "FOUND":
                            print(f"    + {pname}: {info['url']}")
                except Exception as exc:
                    print(f"  Scan failed: {exc}")
            else:
                console.print("  [yellow]Auto-identification failed. Open browser to search manually:[/yellow]")
                engine_url = get_engine_url(engine)
                console.print(f"  [dim]Crop saved: {crop_path}[/dim]")
                console.print(f"  [dim]Open: {engine_url}[/dim]")
                webbrowser.open(engine_url)


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
    screenshots: bool = False,
    show_screenshots: bool = False,
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

    all_screenshot_data: dict[str, dict[str, bytes]] = {}
    if screenshots:
        try:
            from argis.utils.screenshot import take_screenshots
            for u, res in all_results.items():
                data = asyncio.run(take_screenshots(res, u))
                if data:
                    all_screenshot_data[u] = data
        except Exception:
            pass

    if show_screenshots and all_screenshot_data:
        try:
            from argis.utils.screenshot import print_terminal_screenshots
            for u, data in all_screenshot_data.items():
                console.print(f"\n[bold cyan]@{u}[/bold cyan]")
                print_terminal_screenshots(data)
        except Exception:
            pass


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
    animate: bool = typer.Option(
        True, "--animate/--no-animate", help="Play the animated startup logo."
    ),
):
    """Continuously watch a username and report changes over time."""
    display.print_monitor_header(username, interval, animate=animate)
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
def exposure(
    username: str = typer.Argument(..., help="Handle to assess for privacy exposure."),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Comma-separated category filter for the pre-scan."
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout."),
    concurrency: int = typer.Option(12, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through local Tor SOCKS5."),
    render: bool = typer.Option(
        False, "--render", help="Use a headless browser for JS-gated profiles (needs playwright)."
    ),
):
    """Privacy risk score (0-100), grade (A-F), and ranked shrink plan.

    Scans the handle, then scores exposure across footprint breadth, category
    sensitivity, email leakage, real-name consistency, avatar reuse, and cross-
    platform interlinking. The shrink plan lists accounts to take down first.

    \b
    Examples:
      argis exposure johndoe
      argis exposure johndoe --category social,coding
      argis exposure johndoe --render
    """
    from argis.core import ArgisEngine
    from argis.exposure import assess

    from argis.utils.display import console

    cats = tuple(c.strip().lower() for c in category.split(",")) if category else None
    console.print(f"[bold cyan]Scanning[/bold cyan] @{username} for exposure assessment\u2026")
    engine = ArgisEngine(
        username, timeout=timeout, concurrency=concurrency,
        categories=cats, proxy=proxy, use_tor=tor,
    )
    results = asyncio.run(engine.run_scan(quiet=True))
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}

    emails: list[str] = []
    for r in found.values():
        if r.get("emails"):
            emails.extend(r["emails"])

    display_names: dict[str, str] = {}
    for p, r in found.items():
        if r.get("display_name"):
            display_names[p] = r["display_name"]

    cats_map = {}
    sites = engine._filter_sites()
    for p, rules in sites.items():
        cats_map[p] = rules.get("category", "forums")

    report = assess(username, found, emails=emails,
                    display_names=display_names, categories=cats_map)

    from rich.table import Table
    from rich.panel import Panel

    color = "green" if report.grade in ("A", "B") else "yellow" if report.grade == "C" else "red"
    panel = Panel.fit(
        f"[bold cyan]Score:[/bold cyan] [bold {color}]{report.overall}/100[/bold {color}]  "
        f"[bold cyan]Grade:[/bold cyan] [{color}]{report.grade}[/{color}]\n"
        f"[bold cyan]Accounts found:[/bold cyan] {report.found}\n"
        f"[bold cyan]Emails leaked:[/bold cyan] {len(report.emails_leaked)}\n"
        f"[bold cyan]Name consistency:[/bold cyan] {report.real_name_consistency:.0%}",
        title=f"Exposure report \u2014 @{username}",
    )
    console.print()
    console.print(panel)

    console.print("\n[bold]Factor breakdown:[/bold]")
    t = Table(show_header=False, box=None)
    t.add_column("Factor", style="cyan")
    t.add_column("Score", justify="right")
    t.add_column("Detail", style="dim")
    for f in report.factors:
        t.add_row(f.name, f"{f.score:.0%}", f.detail)
    console.print(t)

    if report.shrink_plan:
        console.print("\n[bold]Shrink plan (highest impact first):[/bold]")
        st = Table()
        st.add_column("#")
        st.add_column("Platform", style="cyan")
        st.add_column("Impact", justify="right")
        st.add_column("Reason", style="dim")
        for i, a in enumerate(report.shrink_plan, 1):
            st.add_row(str(i), a.platform, f"{a.impact:.0%}", a.reason)
        console.print(st)

    if report.category_breakdown:
        console.print("\n[bold]Category breakdown:[/bold]")
        ct = Table(show_header=True, box=None)
        ct.add_column("Category", style="cyan")
        ct.add_column("Count", justify="right")
        for cat, cnt in sorted(report.category_breakdown.items(),
                                key=lambda x: -x[1]):
            ct.add_row(cat, str(cnt))
        console.print(ct)
    console.print()


@app.command(rich_help_panel="Analysis")
def timeline(
    username: str = typer.Argument(..., help="Handle to build a timeline for."),
    no_page_dates: bool = typer.Option(
        False, "--no-page-dates", help="Skip fetching on-page joined/member-since metadata."
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Comma-separated category filter."
    ),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout."),
    concurrency: int = typer.Option(12, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through local Tor SOCKS5."),
    render: bool = typer.Option(
        False, "--render", help="Use a headless browser for JS-gated profiles (needs playwright)."
    ),
):
    """Chronological timeline of when accounts were created.

    Queries the Wayback Machine CDX API and scrapes on-page "joined" metadata
    to estimate the earliest creation date per platform. Flags creation bursts
    that may indicate impersonation.

    \b
    Examples:
      argis timeline johndoe
      argis timeline johndoe --no-page-dates
      argis timeline johndoe --render
    """
    from argis.core import ArgisEngine
    from argis.timeline import build_timeline, format_timeline

    from argis.utils.display import console

    cats = tuple(c.strip().lower() for c in category.split(",")) if category else None
    console.print(f"[bold cyan]Scanning[/bold cyan] @{username}\u2026")
    engine = ArgisEngine(
        username, timeout=timeout, concurrency=concurrency,
        categories=cats, proxy=proxy, use_tor=tor,
    )
    results = asyncio.run(engine.run_scan(quiet=True))
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    if not found:
        console.print("[yellow]No accounts found.[/yellow]")
        raise typer.Exit()

    console.print(f"[green]{len(found)}[/green] accounts. Querying Wayback CDX and page dates\u2026")
    report = asyncio.run(build_timeline(
        username, found, fetch_page_dates=not no_page_dates,
    ))

    from rich.table import Table
    t = Table(title=f"Timeline \u2014 @{username}")
    t.add_column("First seen", style="cyan", no_wrap=True)
    t.add_column("Platform", style="white")
    t.add_column("URL", style="dim", overflow="fold")
    for a in report.accounts:
        first = a.first_seen or "\u2014"
        t.add_row(first, a.platform, a.url)
    console.print()
    console.print(t)

    if report.anomalies:
        console.print("\n[bold red]Creation bursts detected:[/bold red]")
        for b in report.anomalies:
            console.print(
                f"  {b['date']}: [yellow]{b['count']}[/yellow] accounts in "
                f"{b['window_days']}d \u2014 {', '.join(b['platforms'])}"
            )
        console.print(
            "[dim]Multiple accounts created in quick succession can indicate "
            "impersonation or sockpuppetry.[/dim]"
        )
    else:
        console.print("\n[dim]No anomalous creation bursts detected.[/dim]")
    console.print()


@app.command(rich_help_panel="Analysis")
def graph(
    username: str = typer.Argument(..., help="Seed handle to build a pivot graph from."),
    expand: bool = typer.Option(
        False, "--expand", "-e", help="One-hop expansion: scrape profiles for referenced handles/emails."
    ),
    output: Path = typer.Option(
        Path("pivot-graph.html"), "--output", "-o", help="Output HTML file for interactive graph."
    ),
    graphml_output: Optional[Path] = typer.Option(
        None, "--graphml", help="Optional GraphML export path (for Maltego/Gephi)."
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Comma-separated category filter."
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout."),
    concurrency: int = typer.Option(10, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through local Tor SOCKS5."),
    render: bool = typer.Option(
        False, "--render", help="Use a headless browser for JS-gated profiles (needs playwright)."
    ),
):
    """Build an interactive pivot graph from a seed handle.

    Scans the handle, maps each found account as a node, and optionally
    expands one hop by scraping profiles for referenced handles and emails.
    Exports an interactive HTML graph (vis-network) and optional GraphML.

    \b
    Examples:
      argis graph johndoe
      argis graph johndoe --expand
      argis graph johndoe --expand --graphml pivot.graphml
      argis graph johndoe --expand --render
    """
    from argis.core import ArgisEngine
    from argis.graph import build_graph, to_html, to_graphml
    from rich.tree import Tree

    from argis.utils.display import console

    cats = tuple(c.strip().lower() for c in category.split(",")) if category else None
    console.print(f"[bold cyan]Scanning[/bold cyan] @{username}\u2026")
    engine = ArgisEngine(
        username, timeout=timeout, concurrency=concurrency,
        categories=cats, proxy=proxy, use_tor=tor,
    )
    results = asyncio.run(engine.run_scan(quiet=True))
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    if not found:
        console.print("[yellow]No accounts found.[/yellow]")
        raise typer.Exit()

    console.print(f"[green]{len(found)}[/green] accounts found. Building pivot graph\u2026")
    from argis.render import playwright_available
    if render and not playwright_available():
        console.print("[yellow]--render requested but Playwright isn't installed. "
                      "Run: pip install \"argis[render]\" && playwright install chromium. "
                      "Falling back to server HTML.[/yellow]")
    pg = asyncio.run(build_graph(
        username, expand_hops=1 if expand else 0, max_expand=8,
        category=cats, timeout=timeout, concurrency=concurrency,
        proxy=proxy, use_tor=tor, render=render,
    ))

    html = to_html(pg)
    output.write_text(html, encoding="utf-8")
    console.print(f"[green]Pivot graph written to[/green] {output}")

    if graphml_output:
        graphml = to_graphml(pg)
        graphml_output.write_text(graphml, encoding="utf-8")
        console.print(f"[green]GraphML exported to[/green] {graphml_output}")

    seed_node = pg.nodes.get(username)
    tree = Tree(f"[bold cyan]@{pg.seed}[/bold cyan] (seed)")
    kind_icons = {"account": "\U0001f464", "handle_ref": "\U0001f517", "email": "\u2709\ufe0f", "seed": "\U0001f34e"}
    for nid, n in pg.nodes.items():
        if nid == pg.seed:
            continue
        icon = kind_icons.get(n.kind, "\u2022")
        label = f"{icon} [white]{n.label}[/white]"
        if n.platform:
            label += f" [dim]({n.platform})[/dim]"
        tree.add(label)
    console.print()
    console.print(tree)
    console.print(
        f"\n[dim]Graph: {len(pg.nodes)} node(s), {len(pg.edges)} edge(s)"
        f"{' (one-hop expanded)' if expand else ''}[/dim]"
    )


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


@app.command(name="import-sites", rich_help_panel="Utilities")
def import_sites(
    source: str = typer.Argument(..., help="Source DB: 'sherlock' or 'maigret'."),
    path: Path = typer.Argument(..., help="Path to the source data.json."),
    sites: Path = typer.Option(
        Path("src/argis/sites.json"), "--sites", help="Argis sites.json to merge into."),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="Where to write merged DB (default: overwrite --sites)."),
    overwrite_existing: bool = typer.Option(
        False, "--overwrite-existing",
        help="Let imported rules replace existing ones on name clash "
             "(default: keep yours, rename the import)."),
    verify: bool = typer.Option(
        False, "--verify",
        help="Run doctor on the merged DB immediately after import."),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Report what would be imported without writing."),
):
    """Import Sherlock/Maigret site databases into Argis -- verified breadth.

    Translates an external username-site database into Argis's detection schema,
    protecting your hand-verified core on name clashes. Follow with argis doctor
    (or --verify) so the imported breadth arrives *checked*, not assumed.

    \b
    Examples:
      argis import-sites sherlock sherlock/resources/data.json --dry-run
      argis import-sites maigret maigret/resources/data.json -o merged.json
      argis import-sites sherlock data.json --verify
    """
    from argis.importers import load_and_import
    from argis.utils.display import console

    base = json.loads(sites.read_text("utf-8")) if sites.exists() else {}
    result = load_and_import(
        source, path, base, prefer_existing=not overwrite_existing)

    console.print(
        f"[bold cyan]{source.title()} import[/bold cyan]: "
        f"[green]{result.imported}[/green] translated \u00b7 "
        f"[yellow]{len(result.skipped)}[/yellow] skipped \u00b7 "
        f"[magenta]{len(result.renamed)}[/magenta] renamed to protect your core"
    )
    console.print(
        f"[dim]Merged DB size: {len(result.sites)} platforms "
        f"(was {len(base)}).[/dim]"
    )
    if result.skipped[:12]:
        console.print("[dim]Skipped (first 12, never guessed):[/dim]")
        for name, why in result.skipped[:12]:
            console.print(f"  [dim]\u2022 {name}: {why}[/dim]")

    if dry_run:
        console.print("[yellow]Dry run -- nothing written.[/yellow]")
        raise typer.Exit()

    dest = output or sites
    dest.write_text(
        json.dumps(result.sites, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    console.print(f"[green]Wrote {len(result.sites)} platforms \u2192 {dest}[/green]")

    if verify:
        from argis.health import HealthChecker
        console.print("\n[bold cyan]Verifying imported rules with doctor\u2026[/bold cyan]")
        report = asyncio.run(HealthChecker(sites_path=dest).run())
        console.print(
            f"[green]{len(report.passed)} healthy[/green] \u00b7 "
            f"[bold red]{len(report.broken)} broken[/bold red] \u00b7 "
            f"[yellow]{len(report.inconclusive)} inconclusive[/yellow]"
        )
        console.print("[dim]Broken/unverified imports can be pruned or fixed "
                      "before they ever reach a user.[/dim]")


@app.command(rich_help_panel="Utilities")
def doctor(
    only: Optional[str] = typer.Option(
        None, "--only", help="Comma-separated platforms to health-check (default: all)."
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout in seconds."),
    concurrency: int = typer.Option(15, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through a local Tor SOCKS5 proxy."),
    http2: bool = typer.Option(False, "--http2", help="Enable HTTP/2."),
    report: Optional[Path] = typer.Option(
        None, "--report", help="Write a Markdown health report to this path."
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", help="Write a JSON health report to this path."
    ),
    exit_code: bool = typer.Option(
        False, "--exit-code", help="Exit with code 1 if any rule is BROKEN (for CI)."
    ),
):
    """Check every site rule against a known-real and known-fake username.

    Surfaces rules that have rotted — either matching users that can't exist,
    or failing to see accounts that do — plus duplicate rule names.

    \b
    Examples:
      argis doctor
      argis doctor --only GitHub,Reddit,Steam
      argis doctor --report health.md --json health.json --exit-code
    """
    from argis.health import HealthChecker

    only_set = {o.strip() for o in only.split(",") if o.strip()} if only else None
    checker = HealthChecker(
        timeout=timeout, concurrency=concurrency, proxy=proxy,
        use_tor=tor, http2=http2, only=only_set,
    )

    console.print("[bold cyan]Running site-rule health check\u2026[/bold cyan]")
    report_obj = asyncio.run(checker.run())

    table = Table(title="Argis rule health")
    table.add_column("Platform", style="cyan", no_wrap=True)
    table.add_column("Check")
    table.add_column("Expected")
    table.add_column("Got")
    table.add_column("Verdict")
    styles = {"PASS": "green", "BROKEN": "bold red", "INCONCLUSIVE": "yellow"}
    for c in sorted(report_obj.checks, key=lambda c: (c.verdict != "BROKEN", c.site)):
        table.add_row(
            c.site, c.kind, c.expected, c.got,
            f"[{styles.get(c.verdict, 'white')}]{c.verdict}[/]",
        )
    console.print(table)

    console.print(
        f"\n[green]{len(report_obj.passed)} healthy[/green] \u00b7 "
        f"[bold red]{len(report_obj.broken)} broken[/bold red] \u00b7 "
        f"[yellow]{len(report_obj.inconclusive)} inconclusive[/yellow]"
    )
    if report_obj.duplicates:
        console.print(
            f"[yellow]WARNING: {len(report_obj.duplicates)} duplicate rule name(s):[/yellow] "
            + ", ".join(report_obj.duplicates)
        )

    if report:
        report.write_text(report_obj.to_markdown(), encoding="utf-8")
        console.print(f"[dim]Markdown report written to {report}[/dim]")
    if json_out:
        import json as _json
        json_out.write_text(_json.dumps(report_obj.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {json_out}[/dim]")

    if exit_code and report_obj.broken:
        raise typer.Exit(code=1)


@app.command(rich_help_panel="Utilities")
def setup_celebrity_db(
    force: bool = typer.Option(
        False, "--force", "-f", help="Redownload all celebrity images even if already cached."
    ),
):
    """Download celebrity reference images for offline DeepFace lookalike matching."""
    from argis.utils.vision import setup_celebrity_db as _setup
    count = _setup(force=force)
    db_path = Path.home() / ".argis" / "celebrities"
    console.print(f"[green]Celebrity DB ready:[/green] {count} images in [dim]{db_path}[/dim]")
    console.print("[dim]Now run [cyan]argis scan-face photo.jpg --identify --offline[/cyan] for offline matching.[/dim]")


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
def guard(
    username: str = typer.Argument(..., help="A handle YOU own, to defend."),
    reference: Optional[str] = typer.Option(
        None, "--reference", "-r",
        help="URL of a profile that's definitely you (sets the match fingerprint)."
    ),
    threshold: float = typer.Option(
        0.55, "--threshold", "-t", help="Similarity at/above which a lookalike is flagged."
    ),
    max_variants: int = typer.Option(
        120, "--max-variants", help="Cap on generated lookalike handles."
    ),
    list_variants: bool = typer.Option(
        False, "--list", "-l", help="Print generated variants and exit (no scan)."
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Limit scans to these categories."
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout."),
    concurrency: int = typer.Option(20, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through local Tor SOCKS5."),
    render: bool = typer.Option(
        False, "--render", help="Use a headless browser for JS-gated profiles (needs playwright)."
    ),
):
    """Hunt for accounts impersonating you on lookalike handles.

    Generates confusable variants of your handle (separators, affixes, leet,
    Unicode homoglyphs), scans them all, and scores each registered lookalike
    against your real profile -- so you find the impostor on 'j0hndoe_official'
    before your followers do.

    \b
    Examples:
      argis guard johndoe
      argis guard johndoe --reference https://github.com/johndoe
      argis guard johndoe --list
      argis guard johndoe --threshold 0.65 --category social
    """
    from argis.impersonate import generate_variants, guard as run_guard

    if list_variants:
        variants = generate_variants(username, max_variants=max_variants)
        console.print(f"[bold cyan]{len(variants)} lookalike variants[/bold cyan] "
                      f"for @{username}:\n")
        for v in variants:
            console.print(f"  [dim]\u2022[/dim] {v}")
        raise typer.Exit()

    cats = tuple(c.strip().lower() for c in category.split(",")) if category else None
    console.print(
        f"[bold cyan]Guarding[/bold cyan] @{username} -- generating lookalikes, "
        "scanning, and correlating\u2026 [dim](this fans out, give it a moment)[/dim]"
    )
    report = asyncio.run(run_guard(
        username, reference_url=reference, max_variants=max_variants,
        warn_threshold=threshold, category=cats, timeout=timeout,
        concurrency=concurrency, proxy=proxy, use_tor=tor,
        render=render,
    ))

    if report.reference is None:
        console.print(
            "[yellow]Couldn't build a reference fingerprint (no usable profile "
            "for your own handle, and no --reference given). Showing raw "
            "lookalike hits without similarity scoring.[/yellow]"
        )

    console.print(
        f"[dim]Scanned {report.variants_scanned} variants \u00b7 "
        f"{report.hits} registered lookalike account(s) found.[/dim]\n"
    )

    imps = report.impersonators
    if imps:
        t = Table(title="\U0001F6A8  Likely impersonators", title_style="bold red")
        t.add_column("Variant", style="red")
        t.add_column("Platform", style="cyan")
        t.add_column("Match", justify="right")
        t.add_column("Display name")
        t.add_column("URL", style="dim")
        for m in imps:
            t.add_row(m.variant, m.platform, f"{m.score:.0%}",
                      m.display_name or "\u2014", m.url)
        console.print(t)
    else:
        console.print("[green]No lookalike account crossed the impersonation "
                      "threshold. \U0001F44D[/green]")

    looks = report.lookalikes
    if looks:
        console.print()
        t = Table(title=f"\u2139\ufe0f  Other registered lookalikes "
                        f"(below {report.warn_threshold:.0%})")
        t.add_column("Variant")
        t.add_column("Platform", style="cyan")
        t.add_column("Match", justify="right")
        t.add_column("URL", style="dim")
        for m in looks[:25]:
            t.add_row(m.variant, m.platform, f"{m.score:.0%}", m.url)
        console.print(t)
        if len(looks) > 25:
            console.print(f"[dim]\u2026and {len(looks) - 25} more.[/dim]")

    console.print(
        f"\n[dim]{len(imps)} flagged \u00b7 {len(looks)} benign lookalikes \u00b7 "
        f"threshold {report.warn_threshold:.0%}[/dim]"
    )


@app.command(rich_help_panel="Analysis")
def link(
    username: str = typer.Argument(..., help="Handle to scan and correlate."),
    threshold: float = typer.Option(
        0.62, "--threshold", "-t", help="Similarity cutoff for 'same person' (0-1)."
    ),
    no_avatar: bool = typer.Option(
        False, "--no-avatar", help="Skip avatar hashing (text-only correlation)."
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Limit the pre-scan to these categories."
    ),
    timeout: float = typer.Option(12.0, "--timeout", help="Per-request timeout."),
    concurrency: int = typer.Option(12, "--concurrency", help="Max simultaneous requests."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Route through a proxy."),
    tor: bool = typer.Option(False, "--tor", help="Route through local Tor SOCKS5."),
    render: bool = typer.Option(
        False, "--render", help="Use a headless browser for JS-gated profiles (needs playwright)."
    ),
):
    """Scan a handle, then cluster the hits into real identities vs impersonators.

    Answers the question no other scanner does: of everywhere this handle
    exists, which accounts are the SAME person -- and which are namesakes or
    impostors wearing the handle?

    \b
    Examples:
      argis link johndoe
      argis link johndoe --threshold 0.7
      argis link johndoe --no-avatar --category social,coding
      argis link johndoe --render
    """
    from argis.core import ArgisEngine
    from argis.correlate import correlate

    cats = tuple(c.strip().lower() for c in category.split(",")) if category else None
    from argis.render import playwright_available
    if render and not playwright_available():
        console.print("[yellow]--render requested but Playwright isn't installed. "
                      "Run: pip install \"argis[render]\" && playwright install chromium. "
                      "Falling back to server HTML.[/yellow]")
    console.print(f"[bold cyan]Scanning[/bold cyan] @{username}...")
    engine = ArgisEngine(
        username, timeout=timeout, concurrency=concurrency,
        categories=cats, proxy=proxy, use_tor=tor,
    )
    results = asyncio.run(engine.run_scan(quiet=True))
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    if not found:
        console.print("[yellow]No accounts found -- nothing to correlate.[/yellow]")
        raise typer.Exit()

    console.print(
        f"[green]{len(found)}[/green] accounts found. Correlating identities..."
    )
    report = asyncio.run(correlate(
        username, found, threshold=threshold, fetch_avatar=not no_avatar,
        timeout=timeout, concurrency=concurrency, proxy=proxy, use_tor=tor,
        render=render,
    ))

    if not report.pillow and not no_avatar:
        console.print(
            "[dim yellow]Pillow not installed -- running text-only "
            "(no avatar matching). pip install pillow for full power.[/dim yellow]"
        )

    for i, c in enumerate([c for c in report.clusters if c.label == "identity"], 1):
        t = Table(title=f"\U0001F9EC Identity cluster #{i}  "
                        f"(confidence {c.confidence:.0%})")
        t.add_column("Platform", style="cyan")
        t.add_column("Display name")
        t.add_column("URL", style="dim")
        for m in c.members:
            s = report.signals[m]
            t.add_row(m, s.display_name or "\u2014", s.url)
        console.print(t)

    imp = report.impersonators
    if imp:
        console.print()
        t = Table(title="\u26a0\ufe0f  Possible impersonators / namesakes",
                  title_style="bold red")
        t.add_column("Platform", style="red")
        t.add_column("Display name")
        t.add_column("Why flagged", style="dim")
        primary = report.primary
        for m in imp:
            s = report.signals[m]
            best = max(
                (sc for a, b, sc in report.edges
                 if m in (a, b) and (a in primary.members or b in primary.members)),
                default=0.0,
            )
            t.add_row(m, s.display_name or "\u2014",
                      f"peak similarity to you: {best:.0%} (< {threshold:.0%})")
        console.print(t)
    else:
        console.print("\n[green]No outliers -- every account looks like the same "
                      "person.[/green]")

    console.print(
        f"\n[dim]{len(report.clusters)} cluster(s) from {len(report.signals)} "
        f"profiles \u00b7 threshold {threshold:.0%} \u00b7 "
        f"avatar matching {'on' if report.pillow and not no_avatar else 'off'}[/dim]"
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
    from urllib.parse import urlparse
    from argis.recon import dns_enum, run_whois, port_scan

    parsed = urlparse(domain_name)
    if parsed.scheme and parsed.netloc:
        domain_name = parsed.netloc
    elif parsed.scheme and not parsed.netloc and "/" in domain_name:
        domain_name = domain_name.split("/")[0]
    domain_name = domain_name.split("@")[-1]
    domain_name = domain_name.strip("/").strip()

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
