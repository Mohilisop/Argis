"""Persist scan history per-username as JSON and compute deltas between runs.

History layout: ~/.argis/history/<username>.json
    [
      {"timestamp": "2026-07-06T10:00:00+00:00", "results": {name: {"status": ..., "url": ...}}},
      ...
    ]

The most recent entry is always last in the list.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from argis.exceptions import HistoryError


def history_dir() -> Path:
    """Return (and create if needed) the directory holding all history files."""
    directory = Path.home() / ".argis" / "history"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _safe_filename(username: str) -> str:
    """Sanitize a username into a filesystem-safe file stem."""
    keep = "-_."
    return "".join(c if c.isalnum() or c in keep else "_" for c in username) + ".json"


def history_file(username: str) -> Path:
    return history_dir() / _safe_filename(username)


def load_history(username: str) -> list[dict]:
    """Load all past scans for a username, oldest first. Empty list if none."""
    path = history_file(username)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("history file is not a list")
        return data
    except (json.JSONDecodeError, ValueError) as exc:
        raise HistoryError(f"Could not read history for '{username}': {exc}") from exc


def get_last_scan(username: str) -> dict | None:
    history = load_history(username)
    return history[-1] if history else None


def save_scan(username: str, results: dict[str, dict], *, max_entries: int = 50) -> None:
    """Append a new scan snapshot to the username's history file.

    Args:
        username: the target username.
        results: mapping of platform name -> {"status": ..., "url": ...}.
        max_entries: cap on retained history entries (oldest are dropped).
    """
    history = load_history(username)
    history.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }
    )
    # Keep history bounded so the file doesn't grow unbounded over years of use.
    history = history[-max_entries:]

    path = history_file(username)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
    except OSError as exc:
        raise HistoryError(f"Could not write history for '{username}': {exc}") from exc


def clear_history(username: str) -> bool:
    """Delete a username's history file. Returns True if a file was removed."""
    path = history_file(username)
    if path.exists():
        path.unlink()
        return True
    return False


def compute_diff(previous: dict[str, dict], current: dict[str, dict]) -> dict:
    """Compare two result snapshots and return added/removed/unchanged info.

    A platform is "added" if it wasn't FOUND before but is FOUND now.
    A platform is "removed" if it was FOUND before but is not FOUND now.
    """
    added: list[tuple[str, str]] = []
    removed: list[tuple[str, str]] = []
    unchanged = 0

    all_names = set(previous) | set(current)
    for name in sorted(all_names):
        prev_status = previous.get(name, {}).get("status")
        curr_status = current.get(name, {}).get("status")
        curr_url = current.get(name, {}).get("url", previous.get(name, {}).get("url", ""))

        was_found = prev_status == "FOUND"
        is_found = curr_status == "FOUND"

        if is_found and not was_found:
            added.append((name, curr_url))
        elif was_found and not is_found:
            removed.append((name, curr_url))
        else:
            unchanged += 1

    return {"added": added, "removed": removed, "unchanged_count": unchanged}
