"""Persist media-review decisions and apply them to generated dossiers."""
from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import typer

from argis.utils.display import console

_VALID_STATES = {"accepted", "rejected", "review"}


def decisions_dir() -> Path:
    override = os.environ.get("ARGIS_MEDIA_REVIEW_DIR")
    path = Path(override).expanduser() if override else Path.home() / ".argis" / "media-reviews"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(username: str) -> str:
    keep = "-_."
    return "".join(ch if ch.isalnum() or ch in keep else "_" for ch in username)


def decisions_file(username: str) -> Path:
    return decisions_dir() / f"{_safe_name(username)}.json"


def validate_review_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize dashboard-exported review JSON."""
    target = str(payload.get("target") or "").strip()
    media = payload.get("media")
    if not target:
        raise ValueError("review JSON is missing target")
    if not isinstance(media, list):
        raise ValueError("review JSON is missing media list")

    clean_media: list[dict[str, Any]] = []
    for index, raw in enumerate(media, start=1):
        if not isinstance(raw, Mapping):
            raise ValueError(f"media item {index} is not an object")
        platform = str(raw.get("platform") or "").strip()
        image_url = str(raw.get("image_url") or raw.get("image") or "").strip()
        profile_url = str(raw.get("profile_url") or "").strip()
        state = str(raw.get("state") or "review").lower().strip()
        if not platform:
            raise ValueError(f"media item {index} is missing platform")
        if state not in _VALID_STATES:
            raise ValueError(f"media item {index} has invalid state: {state}")
        if state == "accepted" and not image_url.startswith(("http://", "https://", "data:image/")):
            raise ValueError(f"accepted media item {index} has no usable image URL")
        clean_media.append({
            "platform": platform,
            "profile_url": profile_url,
            "image_url": image_url,
            "avatar_hash": str(raw.get("avatar_hash") or ""),
            "confidence": int(raw.get("confidence", raw.get("score", 0)) or 0),
            "source": str(raw.get("source") or "media review"),
            "state": state,
            "signals": [str(value) for value in (raw.get("signals") or raw.get("flags") or [])],
        })

    counts = {state: sum(item["state"] == state for item in clean_media) for state in _VALID_STATES}
    return {
        "schema_version": "1.0",
        "target": target,
        "reviewed_at": str(payload.get("reviewed_at") or datetime.now(timezone.utc).isoformat()),
        "summary": counts,
        "media": clean_media,
    }


def import_review_file(source: Path) -> tuple[Path, dict[str, Any]]:
    """Validate a dashboard export and save it as the active target review."""
    source = source.expanduser().resolve()
    try:
        payload = json.loads(source.read_text("utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read review file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"review file is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("review JSON root must be an object")
    normalized = validate_review_payload(payload)
    destination = decisions_file(normalized["target"])
    destination.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")
    return destination, normalized


def load_decisions(username: str) -> dict[str, Any] | None:
    path = decisions_file(username)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
        return validate_review_payload(value)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _decision_index(review: Mapping[str, Any]) -> tuple[dict[tuple[str, str], dict], dict[str, dict]]:
    exact: dict[tuple[str, str], dict] = {}
    platform_only: dict[str, dict] = {}
    for item in review.get("media", []):
        platform = str(item.get("platform") or "").casefold()
        profile_url = str(item.get("profile_url") or "").rstrip("/").casefold()
        if platform and profile_url:
            exact[(platform, profile_url)] = item
        if platform:
            platform_only[platform] = item
    return exact, platform_only


def apply_decisions_to_records(
    records: Sequence[Mapping[str, Any]],
    username: str,
) -> list[dict[str, Any]]:
    """Return dossier records where only accepted reviewed media is retained.

    If no review exists, records are returned unchanged. Once a review exists,
    accepted images are inserted and rejected/pending candidates are removed.
    """
    review = load_decisions(username)
    copied = [deepcopy(dict(record)) for record in records]
    if review is None:
        return copied

    exact, platform_only = _decision_index(review)
    for record in copied:
        platform = str(record.get("p") or record.get("platform") or "").casefold()
        profile_url = str(record.get("url") or "").rstrip("/").casefold()
        decision = exact.get((platform, profile_url)) or platform_only.get(platform)
        if decision is None:
            continue

        warnings = list(record.get("warnings") or [])
        state = decision["state"]
        record["media_review_state"] = state
        record["media_review_confidence"] = decision.get("confidence", 0)

        if state == "accepted":
            record["img"] = decision["image_url"]
            record["avatar_url"] = decision["image_url"]
            if decision.get("avatar_hash"):
                record["avatar_hash"] = decision["avatar_hash"]
            warnings = [w for w in warnings if not str(w).startswith(("avatar rejected", "avatar unavailable"))]
            warnings.append("media approved by analyst")
        else:
            record["img"] = ""
            record["avatar_url"] = ""
            record["avatar_hash"] = ""
            warnings.append(
                "media rejected by analyst" if state == "rejected" else "media awaiting analyst approval"
            )
        record["warnings"] = list(dict.fromkeys(warnings))
    return copied


def register_media_decision_commands(app: typer.Typer) -> None:
    @app.command("media-apply", rich_help_panel="ANALYSIS")
    def media_apply(
        review_json: Path = typer.Argument(..., exists=True, readable=True, help="JSON exported by the media-review dashboard."),
    ) -> None:
        """Save media approvals so future dossiers use only reviewed images."""
        try:
            destination, payload = import_review_file(review_json)
        except ValueError as exc:
            console.print(f"[bold red]Invalid media review:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        summary = payload["summary"]
        console.print(
            f"[green]Media review applied for @{payload['target']}:[/green] "
            f"{summary['accepted']} accepted, {summary['rejected']} rejected, "
            f"{summary['review']} pending."
        )
        console.print(f"[dim]Saved to {destination}. Regenerate the dossier to use these decisions.[/dim]")

    @app.command("media-clear", rich_help_panel="ANALYSIS")
    def media_clear(
        username: str = typer.Argument(..., help="Target whose saved media decisions should be removed."),
    ) -> None:
        """Remove saved media decisions and return dossiers to automatic media."""
        path = decisions_file(username)
        if path.exists():
            path.unlink()
            console.print(f"[green]Cleared media review for @{username}.[/green]")
        else:
            console.print(f"[dim]No saved media review for @{username}.[/dim]")
