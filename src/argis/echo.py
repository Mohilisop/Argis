"""Argis Echo: cross-platform identity drift analysis.

A normal diff answers "what changed between two scans?" Echo answers a harder
question: "which changes happened together across platforms, and what identity
story do they reveal?"

Echo is intentionally offline and deterministic. It consumes historical Argis
snapshots, normalizes common result schemas, suppresses generic page noise, and
returns coordinated change events with evidence and confidence.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Iterable, Mapping, Sequence


TRACKED_FIELDS = ("display_name", "bio", "avatar_hash", "emails")

_GENERIC_TEXT = {
    "home",
    "profile",
    "user profile",
    "log in",
    "sign up",
    "not found",
    "wayback machine",
}


@dataclass(frozen=True)
class FieldChange:
    platform: str
    field: str
    before: Any
    after: Any
    observed_at: str
    source_url: str = ""


@dataclass
class EchoEvent:
    """A coordinated identity change observed across one or more platforms."""

    event_type: str
    observed_at: str
    platforms: list[str]
    fields: list[str]
    confidence: int
    summary: str
    evidence: list[FieldChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = [asdict(item) for item in self.evidence]
        return value


@dataclass
class EchoReport:
    username: str
    generated_at: str
    snapshots_analyzed: int
    platforms_seen: list[str]
    stability_score: int
    identity_epochs: int
    events: list[EchoEvent]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["events"] = [event.to_dict() for event in self.events]
        return value


def analyze_echo(
    snapshots: Sequence[Mapping[str, Any]],
    username: str,
    *,
    coordination_window_hours: int = 72,
    minimum_confidence: int = 45,
) -> dict[str, Any]:
    """Analyze historical scans for coordinated cross-platform identity drift.

    Each snapshot should contain a timestamp under ``timestamp``, ``scanned_at``,
    ``created_at``, or ``date`` and profiles under ``profiles``, ``results``, or
    ``accounts``. Profile records may use either modern names (``platform``,
    ``category``, ``display_name``) or older Argis aliases (``p``, ``cat``,
    ``name``, ``img`` and ``mail``).

    Returns a JSON-serializable report. No network calls are made.
    """
    if len(snapshots) < 2:
        return EchoReport(
            username=username,
            generated_at=_now_iso(),
            snapshots_analyzed=len(snapshots),
            platforms_seen=[],
            stability_score=100,
            identity_epochs=1 if snapshots else 0,
            events=[],
            warnings=["Echo needs at least two historical snapshots."],
        ).to_dict()

    normalized = sorted(
        (_normalize_snapshot(snapshot, index) for index, snapshot in enumerate(snapshots)),
        key=lambda item: item["timestamp"],
    )

    warnings: list[str] = []
    if any(item["synthetic_timestamp"] for item in normalized):
        warnings.append(
            "One or more snapshots had no timestamp; input order was used instead."
        )

    raw_changes: list[FieldChange] = []
    platforms_seen: set[str] = set()

    for previous, current in zip(normalized, normalized[1:]):
        previous_profiles = previous["profiles"]
        current_profiles = current["profiles"]
        platforms_seen.update(previous_profiles)
        platforms_seen.update(current_profiles)

        for platform in sorted(set(previous_profiles) | set(current_profiles)):
            before = previous_profiles.get(platform)
            after = current_profiles.get(platform)

            if before is None and after is not None:
                raw_changes.append(
                    FieldChange(
                        platform=platform,
                        field="account_presence",
                        before="absent",
                        after="present",
                        observed_at=current["timestamp"].isoformat(),
                        source_url=after.get("url", ""),
                    )
                )
                continue

            if before is not None and after is None:
                raw_changes.append(
                    FieldChange(
                        platform=platform,
                        field="account_presence",
                        before="present",
                        after="absent",
                        observed_at=current["timestamp"].isoformat(),
                        source_url=before.get("url", ""),
                    )
                )
                continue

            if before is None or after is None:
                continue

            for field_name in TRACKED_FIELDS:
                old_value = before.get(field_name)
                new_value = after.get(field_name)
                if _meaningfully_changed(field_name, old_value, new_value):
                    raw_changes.append(
                        FieldChange(
                            platform=platform,
                            field=field_name,
                            before=old_value,
                            after=new_value,
                            observed_at=current["timestamp"].isoformat(),
                            source_url=after.get("url", ""),
                        )
                    )

    events = _cluster_changes(
        raw_changes,
        coordination_window_hours=max(1, coordination_window_hours),
        minimum_confidence=max(0, min(100, minimum_confidence)),
    )

    changed_platforms = {platform for event in events for platform in event.platforms}
    strong_events = sum(event.confidence >= 75 for event in events)
    change_pressure = min(
        100,
        len(changed_platforms) * 6 + len(events) * 5 + strong_events * 8,
    )
    stability_score = max(0, 100 - change_pressure)

    # An epoch is a stable identity period separated by a strong coordinated event.
    identity_epochs = 1 + strong_events if normalized else 0

    return EchoReport(
        username=username,
        generated_at=_now_iso(),
        snapshots_analyzed=len(normalized),
        platforms_seen=sorted(platforms_seen),
        stability_score=stability_score,
        identity_epochs=identity_epochs,
        events=events,
        warnings=warnings,
    ).to_dict()


def _cluster_changes(
    changes: Iterable[FieldChange],
    *,
    coordination_window_hours: int,
    minimum_confidence: int,
) -> list[EchoEvent]:
    ordered = sorted(changes, key=lambda item: _parse_time(item.observed_at))
    if not ordered:
        return []

    groups: list[list[FieldChange]] = []
    current: list[FieldChange] = []
    window_seconds = coordination_window_hours * 3600

    for change in ordered:
        if not current:
            current = [change]
            continue
        first_time = _parse_time(current[0].observed_at)
        this_time = _parse_time(change.observed_at)
        if (this_time - first_time).total_seconds() <= window_seconds:
            current.append(change)
        else:
            groups.append(current)
            current = [change]
    if current:
        groups.append(current)

    events: list[EchoEvent] = []
    for group in groups:
        platforms = sorted({item.platform for item in group})
        fields = sorted({item.field for item in group})
        confidence = _score_group(group)
        if confidence < minimum_confidence:
            continue
        event_type = _classify_group(group)
        events.append(
            EchoEvent(
                event_type=event_type,
                observed_at=max(
                    (_parse_time(item.observed_at) for item in group)
                ).isoformat(),
                platforms=platforms,
                fields=fields,
                confidence=confidence,
                summary=_summarize(event_type, platforms, fields),
                evidence=group,
            )
        )
    return events


def _score_group(group: Sequence[FieldChange]) -> int:
    platforms = {item.platform for item in group}
    fields = {item.field for item in group}

    score = 28
    score += min(35, max(0, len(platforms) - 1) * 14)
    score += min(18, max(0, len(fields) - 1) * 6)

    if "avatar_hash" in fields:
        score += 14
    if "emails" in fields:
        score += 12
    if "account_presence" in fields:
        score += 8
    if "display_name" in fields:
        score += 6

    # A single bio edit is normal platform activity, not an identity event.
    if len(platforms) == 1 and fields == {"bio"}:
        score -= 22

    return max(0, min(100, score))


def _classify_group(group: Sequence[FieldChange]) -> str:
    fields = {item.field for item in group}
    presence = [item for item in group if item.field == "account_presence"]

    appeared = sum(item.after == "present" for item in presence)
    disappeared = sum(item.after == "absent" for item in presence)

    if disappeared >= 2:
        return "coordinated_retreat"
    if appeared >= 2:
        return "coordinated_expansion"
    if "avatar_hash" in fields and "display_name" in fields:
        return "identity_rebrand"
    if "emails" in fields:
        return "contact_pivot"
    if "avatar_hash" in fields:
        return "avatar_migration"
    if "display_name" in fields or "bio" in fields:
        return "profile_drift"
    return "account_change"


def _summarize(event_type: str, platforms: Sequence[str], fields: Sequence[str]) -> str:
    labels = {
        "coordinated_retreat": "Multiple accounts disappeared in the same observation window",
        "coordinated_expansion": "Multiple accounts appeared in the same observation window",
        "identity_rebrand": "Avatar and display-name changes indicate a coordinated rebrand",
        "contact_pivot": "Contact details changed across the observed identity",
        "avatar_migration": "Avatar changes moved across one or more platforms",
        "profile_drift": "Profile identity signals changed",
        "account_change": "Account state changed",
    }
    platform_text = ", ".join(platforms[:4])
    if len(platforms) > 4:
        platform_text += f" +{len(platforms) - 4} more"
    field_text = ", ".join(field.replace("_", " ") for field in fields)
    return f"{labels[event_type]}: {platform_text}. Evidence: {field_text}."


def _normalize_snapshot(snapshot: Mapping[str, Any], index: int) -> dict[str, Any]:
    raw_time = (
        snapshot.get("timestamp")
        or snapshot.get("scanned_at")
        or snapshot.get("created_at")
        or snapshot.get("date")
    )
    synthetic = raw_time is None
    timestamp = _parse_time(raw_time) if raw_time is not None else datetime.fromtimestamp(index, timezone.utc)

    records = (
        snapshot.get("profiles")
        or snapshot.get("results")
        or snapshot.get("accounts")
        or []
    )

    if isinstance(records, Mapping):
        iterable = []
        for platform, value in records.items():
            if isinstance(value, Mapping):
                record = dict(value)
                record.setdefault("platform", str(platform))
                iterable.append(record)
    else:
        iterable = [dict(item) for item in records if isinstance(item, Mapping)]

    profiles: dict[str, dict[str, Any]] = {}
    for record in iterable:
        normalized = _normalize_profile(record)
        platform = normalized["platform"]
        if platform:
            profiles[platform] = normalized

    return {
        "timestamp": timestamp,
        "synthetic_timestamp": synthetic,
        "profiles": profiles,
    }


def _normalize_profile(record: Mapping[str, Any]) -> dict[str, Any]:
    platform = str(
        record.get("platform")
        or record.get("p")
        or record.get("site")
        or record.get("name")
        or ""
    ).strip()

    title = _clean_text(record.get("title"))
    display_name = _clean_text(record.get("display_name") or record.get("name"))
    if display_name and display_name.lower() == platform.lower():
        display_name = None
    if not display_name and title and len(title) <= 64 and title.lower() not in _GENERIC_TEXT:
        display_name = title

    emails_value = record.get("emails", record.get("mail", []))
    if isinstance(emails_value, str):
        emails = sorted({part.strip().lower() for part in emails_value.split(",") if "@" in part})
    elif isinstance(emails_value, Sequence):
        emails = sorted({str(part).strip().lower() for part in emails_value if "@" in str(part)})
    else:
        emails = []

    return {
        "platform": platform,
        "category": str(record.get("category") or record.get("cat") or "uncategorized"),
        "url": str(record.get("url") or ""),
        "display_name": display_name,
        "bio": _clean_text(record.get("bio") or record.get("description")),
        "avatar_hash": record.get("avatar_hash") or record.get("phash"),
        "emails": emails,
    }


def _meaningfully_changed(field_name: str, before: Any, after: Any) -> bool:
    if before == after:
        return False
    if not before and not after:
        return False

    if field_name in {"display_name", "bio"}:
        old_text = _clean_text(before) or ""
        new_text = _clean_text(after) or ""
        if old_text.lower() in _GENERIC_TEXT and new_text.lower() in _GENERIC_TEXT:
            return False
        similarity = SequenceMatcher(None, old_text.lower(), new_text.lower()).ratio()
        threshold = 0.82 if field_name == "bio" else 0.9
        return similarity < threshold

    if field_name == "emails":
        return set(before or []) != set(after or [])

    return before != after


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split()).strip()
    return text or None


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), timezone.utc)
    else:
        raw = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            parsed = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
