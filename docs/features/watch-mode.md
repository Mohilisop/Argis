# Argis: Watch Mode — Continuous Username Monitoring & Alerts

# Argis: Watch Mode

Continuous background monitoring of usernames with real-time alerts when accounts appear, disappear, or change. Turn Argis from a one-shot scanner into a persistent surveillance tool.

You already have: `diff.py` for historical comparison, `core.py` for async scanning, `sites.json` for platform definitions. This adds: **a scheduler, watchlist management, notification backends, and a daemon mode.**

* * *

## New CLI subcommand: `watch`

Add a new Typer subgroup:

```python
watch_app = typer.Typer(help="Continuous username monitoring & alerts.")
app.add_typer(watch_app, name="watch")

@watch_app.command("add")
def watch_add(
    username: str = typer.Argument(..., help="Username to monitor."),
    platforms: Optional[str] = typer.Option(None, "-p", "--platforms", help="Comma-separated platforms (default: all)."),
    interval: str = typer.Option("6h", "-i", "--interval", help="Check interval: 30m, 1h, 6h, 12h, 24h."),
    notify: Optional[str] = typer.Option(None, "-n", "--notify", help="Notification backend: discord, telegram, email, webhook, desktop."),
    webhook_url: Optional[str] = typer.Option(None, "--webhook-url", help="Webhook URL for discord/telegram/generic."),
    stealth: bool = typer.Option(False, "--stealth", help="Randomize intervals ±30%%, rotate user agents."),
):
    """Add a username to the watchlist."""
    ...

@watch_app.command("remove")
def watch_remove(
    username: str = typer.Argument(..., help="Username to stop monitoring."),
):
    """Remove a username from the watchlist."""
    ...

@watch_app.command("list")
def watch_list(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show last check time and change count."),
):
    """Show all monitored usernames."""
    ...

@watch_app.command("run")
def watch_run(
    daemon: bool = typer.Option(False, "-d", "--daemon", help="Run as background daemon."),
    once: bool = typer.Option(False, "--once", help="Run one check cycle then exit."),
    pid_file: Optional[Path] = typer.Option(None, "--pid-file", help="PID file for daemon mode."),
):
    """Start the watch daemon."""
    ...

@watch_app.command("status")
def watch_status():
    """Show daemon status and next scheduled checks."""
    ...

@watch_app.command("history")
def watch_history(
    username: str = typer.Argument(..., help="Username to show change history for."),
    limit: int = typer.Option(20, "-l", "--limit", help="Number of events to show."),
):
    """Show change history for a monitored username."""
    ...
```

* * *

## `src/argis/watch.py` — Core watch engine

```python
"""Watch mode: continuous username monitoring with alerts.

Scheduler that periodically re-scans watched usernames,
diffs against previous state, and fires notifications on changes.
"""
from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from argis.core import scan_username
from argis.diff import compute_diff
from argis.notifiers import dispatch_notification


WATCHLIST_PATH = Path.home() / ".argis" / "watchlist.json"
STATE_DB_PATH = Path.home() / ".argis" / "watch_state.json"


@dataclass
class WatchTarget:
    username: str
    platforms: list[str] = field(default_factory=list)  # empty = all
    interval_seconds: int = 21600  # 6h default
    notify_backend: str = "desktop"
    webhook_url: Optional[str] = None
    stealth: bool = False
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_check: Optional[str] = None
    change_count: int = 0


def parse_interval(s: str) -> int:
    """Parse human interval string to seconds."""
    units = {"m": 60, "h": 3600, "d": 86400}
    if s[-1] in units:
        return int(s[:-1]) * units[s[-1]]
    return int(s)


def load_watchlist() -> list[WatchTarget]:
    """Load watchlist from disk."""
    if not WATCHLIST_PATH.exists():
        return []
    data = json.loads(WATCHLIST_PATH.read_text("utf-8"))
    return [WatchTarget(**entry) for entry in data]


def save_watchlist(targets: list[WatchTarget]) -> None:
    """Persist watchlist to disk."""
    WATCHLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    WATCHLIST_PATH.write_text(
        json.dumps([asdict(t) for t in targets], indent=2), encoding="utf-8"
    )


def load_state() -> dict:
    """Load previous scan states."""
    if not STATE_DB_PATH.exists():
        return {}
    return json.loads(STATE_DB_PATH.read_text("utf-8"))


def save_state(state: dict) -> None:
    """Persist scan states."""
    STATE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_DB_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


async def check_target(target: WatchTarget, state: dict) -> list[dict]:
    """Run a scan for one target and diff against previous state."""
    # Apply stealth jitter
    if target.stealth:
        jitter = random.uniform(-0.3, 0.3) * target.interval_seconds
        await asyncio.sleep(max(0, jitter))

    # Scan
    platforms = target.platforms or None  # None = all
    current_results = await scan_username(
        target.username,
        platforms=platforms,
        stealth=target.stealth,
    )

    # Diff
    prev_results = state.get(target.username, {})
    changes = compute_diff(prev_results, current_results)

    # Update state
    state[target.username] = current_results
    target.last_check = datetime.utcnow().isoformat()

    return changes


async def run_watch_loop(*, once: bool = False) -> None:
    """Main watch loop. Checks all targets on their intervals."""
    targets = load_watchlist()
    state = load_state()

    if not targets:
        print("[!] Watchlist is empty. Add targets with: argis watch add <username>")
        return

    print(f"[*] Watching {len(targets)} targets...")

    while True:
        now = time.time()

        for target in targets:
            # Check if it's time
            if target.last_check:
                last = datetime.fromisoformat(target.last_check).timestamp()
                if now - last < target.interval_seconds:
                    continue

            print(f"[~] Checking @{target.username}...")
            changes = await check_target(target, state)

            if changes:
                target.change_count += len(changes)
                print(f"[!] {len(changes)} change(s) for @{target.username}")

                # Fire notifications
                await dispatch_notification(
                    target=target,
                    changes=changes,
                )

        # Persist
        save_watchlist(targets)
        save_state(state)

        if once:
            break

        # Sleep until next check needed
        next_check = min(
            target.interval_seconds for target in targets
        )
        await asyncio.sleep(min(next_check, 60))  # wake every 60s max to recheck
```

* * *

## `src/argis/notifiers/__init__.py` — Notification dispatch

```python
"""Notification backends for watch mode."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def dispatch_notification(target: "WatchTarget", changes: list[dict]) -> None:
    """Route notifications to the configured backend."""
    backend = target.notify_backend.lower()

    if backend == "discord":
        from argis.notifiers.discord import send
        await send(target, changes)
    elif backend == "telegram":
        from argis.notifiers.telegram import send
        await send(target, changes)
    elif backend == "email":
        from argis.notifiers.email import send
        await send(target, changes)
    elif backend == "webhook":
        from argis.notifiers.webhook import send
        await send(target, changes)
    elif backend == "desktop":
        from argis.notifiers.desktop import send
        await send(target, changes)
    else:
        print(f"[!] Unknown notify backend: {backend}")
```

* * *

## `src/argis/notifiers/discord.py`

```python
"""Discord webhook notifications."""
from __future__ import annotations

import httpx
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def send(target: "WatchTarget", changes: list[dict]) -> None:
    """Send change alert to a Discord webhook."""
    if not target.webhook_url:
        print("[!] No webhook URL configured for Discord.")
        return

    embeds = []
    for change in changes[:10]:  # Discord limit
        color = 0x00FF00 if change["type"] == "appeared" else 0xFF0000 if change["type"] == "disappeared" else 0xFFAA00
        embeds.append({
            "title": f"@{target.username} — {change['platform']}",
            "description": _format_change(change),
            "color": color,
            "timestamp": change.get("timestamp"),
        })

    payload = {
        "username": "Argis Watch",
        "embeds": embeds,
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(target.webhook_url, json=payload, timeout=10)
        if r.status_code not in (200, 204):
            print(f"[!] Discord webhook failed: {r.status_code}")


def _format_change(change: dict) -> str:
    if change["type"] == "appeared":
        return f"🟢 New account detected\n{change.get('url', '')}"
    elif change["type"] == "disappeared":
        return f"🔴 Account no longer found\n{change.get('url', '')}"
    else:
        fields = ", ".join(change.get("fields", []))
        return f"🟡 Profile changed: {fields}\n{change.get('url', '')}"
```

* * *

## `src/argis/notifiers/telegram.py`

```python
"""Telegram bot notifications."""
from __future__ import annotations

import os
import httpx
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def send(target: "WatchTarget", changes: list[dict]) -> None:
    """Send change alert via Telegram bot."""
    token = os.environ.get("ARGIS_TELEGRAM_TOKEN")
    chat_id = target.webhook_url  # reuse webhook_url field for chat_id

    if not token or not chat_id:
        print("[!] Set ARGIS_TELEGRAM_TOKEN env and --webhook-url to chat_id.")
        return

    lines = [f"🔍 *Argis Watch* — @{target.username}\n"]
    for change in changes:
        if change["type"] == "appeared":
            lines.append(f"🟢 *{change['platform']}* — new account\n`{change.get('url', '')}`")
        elif change["type"] == "disappeared":
            lines.append(f"🔴 *{change['platform']}* — gone\n`{change.get('url', '')}`")
        else:
            fields = ", ".join(change.get("fields", []))
            lines.append(f"🟡 *{change['platform']}* — changed: {fields}")

    text = "\n".join(lines)

    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
```

* * *

## `src/argis/notifiers/webhook.py`

```python
"""Generic webhook (POST JSON) notifications."""
from __future__ import annotations

import httpx
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def send(target: "WatchTarget", changes: list[dict]) -> None:
    """POST changes as JSON to a generic webhook endpoint."""
    if not target.webhook_url:
        print("[!] No webhook URL configured.")
        return

    payload = {
        "tool": "argis",
        "event": "watch_alert",
        "username": target.username,
        "timestamp": datetime.utcnow().isoformat(),
        "change_count": len(changes),
        "changes": changes,
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(
            target.webhook_url,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Argis-Watch/1.0"},
            timeout=10,
        )
        if r.status_code >= 400:
            print(f"[!] Webhook failed: {r.status_code}")
```

* * *

## `src/argis/notifiers/email.py`

```python
"""Email (SMTP) notifications."""
from __future__ import annotations

import os
import smtplib
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def send(target: "WatchTarget", changes: list[dict]) -> None:
    """Send change alert via SMTP email."""
    smtp_host = os.environ.get("ARGIS_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("ARGIS_SMTP_PORT", "587"))
    smtp_user = os.environ.get("ARGIS_SMTP_USER")
    smtp_pass = os.environ.get("ARGIS_SMTP_PASS")
    to_addr = target.webhook_url  # reuse for email address

    if not all([smtp_user, smtp_pass, to_addr]):
        print("[!] Set ARGIS_SMTP_USER, ARGIS_SMTP_PASS, and --webhook-url to recipient email.")
        return

    subject = f"Argis Alert: {len(changes)} change(s) for @{target.username}"

    body_lines = [f"Argis detected {len(changes)} change(s) for @{target.username}:\n"]
    for change in changes:
        if change["type"] == "appeared":
            body_lines.append(f"+ NEW: {change['platform']} — {change.get('url', '')}")
        elif change["type"] == "disappeared":
            body_lines.append(f"- GONE: {change['platform']} — {change.get('url', '')}")
        else:
            fields = ", ".join(change.get("fields", []))
            body_lines.append(f"~ CHANGED: {change['platform']} — {fields}")

    msg = MIMEText("\n".join(body_lines))
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        print(f"[!] Email send failed: {e}")
```

* * *

## `src/argis/notifiers/desktop.py`

```python
"""Desktop notifications (libnotify on Linux, osascript on macOS, toast on Windows)."""
from __future__ import annotations

import platform
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argis.watch import WatchTarget


async def send(target: "WatchTarget", changes: list[dict]) -> None:
    """Fire a native desktop notification."""
    title = f"Argis: @{target.username}"
    body = f"{len(changes)} change(s) detected"

    # Add first change as detail
    if changes:
        c = changes[0]
        if c["type"] == "appeared":
            body += f"\n🟢 {c['platform']} appeared"
        elif c["type"] == "disappeared":
            body += f"\n🔴 {c['platform']} gone"
        else:
            body += f"\n🟡 {c['platform']} changed"
        if len(changes) > 1:
            body += f"\n...and {len(changes) - 1} more"

    system = platform.system()

    try:
        if system == "Linux":
            subprocess.run(
                ["notify-send", "-a", "Argis", title, body],
                timeout=5, check=False,
            )
        elif system == "Darwin":
            script = f'display notification "{body}" with title "{title}"'
            subprocess.run(
                ["osascript", "-e", script],
                timeout=5, check=False,
            )
        elif system == "Windows":
            # PowerShell toast
            ps = (
                f'[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, '
                f'ContentType = WindowsRuntime] > $null; '
                f'$t = [Windows.UI.Notifications.ToastNotification]::New('
                f'[Windows.Data.Xml.Dom.XmlDocument]::new()); '
                f'$t.Content.LoadXml("<toast><visual><binding template=\'ToastText02\'>'
                f'<text id=\'1\'>{title}</text><text id=\'2\'>{body}</text>'
                f'</binding></visual></toast>"); '
                f'[Windows.UI.Notifications.ToastNotificationManager]::'
                f'CreateToastNotifier("Argis").Show($t)'
            )
            subprocess.run(["powershell", "-Command", ps], timeout=5, check=False)
    except Exception:
        print(f"[!] Desktop notification failed (fallback): {title} — {body}")
```

* * *

## Stealth mode details

When `--stealth` is enabled:

```python
# In watch.py check_target():
if target.stealth:
    # Randomize check interval ±30%
    jitter = random.uniform(-0.3, 0.3) * target.interval_seconds
    await asyncio.sleep(max(0, jitter))

# In core.py scan_username() when stealth=True:
# 1. Random delay between platform checks (0.5-3s)
await asyncio.sleep(random.uniform(0.5, 3.0))
# 2. Rotate user agents from a pool
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ...",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...",
    # ... 20+ real browser UAs
]
headers["User-Agent"] = random.choice(UA_POOL)
# 3. Randomize platform check order
platforms = random.sample(platforms, len(platforms))
```

* * *

## Systemd service file (Linux daemon)

```ini
# ~/.config/systemd/user/argis-watch.service
[Unit]
Description=Argis Watch Daemon
After=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/argis watch run
Restart=on-failure
RestartSec=30
Environment=ARGIS_TELEGRAM_TOKEN=your-token-here

[Install]
WantedBy=default.target
```

Enable with: `systemctl --user enable --now argis-watch`

* * *

## Watchlist file format (`~/.argis/watchlist.json`)

```json
[
  {
    "username": "target_user",
    "platforms": ["github", "twitter", "reddit", "telegram"],
    "interval_seconds": 21600,
    "notify_backend": "discord",
    "webhook_url": "https://discord.com/api/webhooks/...",
    "stealth": true,
    "added_at": "2026-07-11T18:00:00",
    "last_check": "2026-07-11T23:45:00",
    "change_count": 3
  },
  {
    "username": "another_person",
    "platforms": [],
    "interval_seconds": 3600,
    "notify_backend": "desktop",
    "webhook_url": null,
    "stealth": false,
    "added_at": "2026-07-11T20:00:00",
    "last_check": null,
    "change_count": 0
  }
]
```

* * *

## Change event schema

```python
# What compute_diff() returns for watch mode:
{
    "type": "appeared" | "disappeared" | "changed",
    "platform": "github",
    "url": "https://github.com/target_user",
    "timestamp": "2026-07-11T23:45:00Z",
    "fields": ["bio", "display_name"],  # only for "changed" type
    "old_values": {"bio": "old bio"},     # only for "changed" type
    "new_values": {"bio": "new bio"},     # only for "changed" type
}
```

* * *

## Summary: Watch Mode capabilities

| Command | Action | Notes |
| --- | --- | --- |
| `watch add <user>` | Add to watchlist | supports -p, -i, -n, --stealth |
| `watch remove <user>` | Remove from watchlist | stops all monitoring |
| `watch list` | Show all targets | -v for last check + change count |
| `watch run` | Start monitor loop | foreground by default |
| `watch run -d` | Daemon mode | background, use with systemd |
| `watch run --once` | Single pass | cron-friendly |
| `watch status` | Show daemon info | next checks, uptime |
| `watch history <user>` | Change log | last N events for a target |

| Notify Backend | Config | Notes |
| --- | --- | --- |
| `discord` | --webhook-url | Rich embeds with colors |
| `telegram` | ARGIS_TELEGRAM_TOKEN + --webhook-url (chat_id) | Markdown formatted |
| `email` | ARGIS_SMTP_* env vars + --webhook-url (recipient) | Plain text |
| `webhook` | --webhook-url | Generic JSON POST |
| `desktop` | none | Native OS notifications |

| Flag | Purpose |
| --- | --- |
| `--stealth` | Randomize intervals ±30%, rotate UAs, shuffle platform order |
| `-i 30m` | Check every 30 minutes |
| `-i 6h` | Check every 6 hours (default) |
| `-i 24h` | Check once daily |

This turns Argis into a persistent OSINT monitor. The diff engine does the brains, this just adds the heartbeat. Ship it.