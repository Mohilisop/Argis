from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argis.exceptions import HistoryError


def history_dir() -> Path:
    directory = Path.home() / ".argis" / "history"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _safe_filename(username: str) -> str:
    keep = "-_."
    return "".join(c if c.isalnum() or c in keep else "_" for c in username) + ".json"


def history_file(username: str) -> Path:
    return history_dir() / _safe_filename(username)


def load_history(username: str) -> list[dict]:
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
    history = load_history(username)
    history.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }
    )
    history = history[-max_entries:]

    path = history_file(username)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
    except OSError as exc:
        raise HistoryError(f"Could not write history for '{username}': {exc}") from exc


def clear_history(username: str) -> bool:
    path = history_file(username)
    if path.exists():
        path.unlink()
        return True
    return False


def compute_diff(previous: dict[str, dict], current: dict[str, dict]) -> dict:
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


def list_all_users() -> list[str]:
    hdir = history_dir()
    if not hdir.exists():
        return []
    users: list[str] = []
    for fname in os.listdir(str(hdir)):
        if fname.endswith(".json"):
            stem = fname[:-5]
            users.append(stem)
    return sorted(users)


def search_history(
    query: str,
    *,
    field: str = "platform",
    status_filter: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for username in list_all_users():
        history = load_history(username)
        for entry in history:
            ts = entry["timestamp"]
            for platform, info in entry["results"].items():
                if status_filter and info.get("status") != status_filter:
                    continue
                if field == "platform" and query.lower() in platform.lower():
                    results.append({
                        "username": username,
                        "timestamp": ts,
                        "platform": platform,
                        "status": info.get("status"),
                        "url": info.get("url"),
                    })
                elif field == "url" and query.lower() in info.get("url", "").lower():
                    results.append({
                        "username": username,
                        "timestamp": ts,
                        "platform": platform,
                        "status": info.get("status"),
                        "url": info.get("url"),
                    })
    return results


def aggregate_stats() -> dict[str, Any]:
    total_scans = 0
    total_found: dict[str, int] = {}
    user_stats: dict[str, dict[str, int]] = {}
    platform_found_count: dict[str, int] = {}
    total_emails_collected = 0

    for username in list_all_users():
        history = load_history(username)
        user_stats[username] = {"scans": len(history), "found": 0}
        most_recent_found = 0

        for entry in history:
            total_scans += 1
            for platform, info in entry["results"].items():
                if info.get("status") == "FOUND":
                    total_found[platform] = total_found.get(platform, 0) + 1
                    platform_found_count[platform] = platform_found_count.get(platform, 0) + 1
                    most_recent_found += 1
                    emails = info.get("emails", [])
                    if emails:
                        total_emails_collected += len(emails)

        user_stats[username]["found"] = most_recent_found

    top_platforms = sorted(platform_found_count.items(), key=lambda x: -x[1])[:15]
    total_users = len(user_stats)
    total_found_all = sum(s["found"] for s in user_stats.values())

    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "total_found_profiles": total_found_all,
        "total_emails_collected": total_emails_collected,
        "top_platforms": [{"platform": p, "count": c} for p, c in top_platforms],
        "users": user_stats,
    }
