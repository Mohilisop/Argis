from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EvidenceItem:
    """A single piece of extracted evidence with provenance."""

    field: str
    value: str
    source: str
    confidence: int
    category: str = "identity"


@dataclass
class ProfileEvidence:
    """Canonical model for one platform profile found during scanning."""

    platform: str
    category: str
    username: str
    url: str
    status: str
    confidence: int = 0
    title: str | None = None
    display_name: str | None = None
    bio: str | None = None
    emails: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    avatar_url: str | None = None
    avatar_hash: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)
    verification: str = "UNVERIFIED"
    warnings: list[str] = field(default_factory=list)
