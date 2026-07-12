from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from argis.models import MediaEvidence


@dataclass
class AdapterResult:
    found: bool
    profile_url: str
    display_name: str | None = None
    bio: str | None = None
    media: list[MediaEvidence] = field(default_factory=list)
    diagnostic: dict | None = None


class MediaAdapter(Protocol):
    platforms: set[str]

    async def resolve(
        self, client, username: str, profile_url: str
    ) -> AdapterResult:
        ...
