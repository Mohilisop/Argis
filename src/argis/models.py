"""Canonical Argis data models.

ProfileEvidence is the single schema every scanner, adapter, and exporter
shares. MediaEvidence is the canonical media record: classification, confidence,
provenance, and offline caching fields all live here so no renderer has to guess
whether an image is a real avatar or a platform logo.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Media classifications ──────────────────────────────────────────
PROFILE_AVATAR = "PROFILE_AVATAR"
PROFILE_BANNER = "PROFILE_BANNER"
PLATFORM_LOGO = "PLATFORM_LOGO"
GENERIC_THUMBNAIL = "GENERIC_THUMBNAIL"
DEFAULT_AVATAR = "DEFAULT_AVATAR"
UNKNOWN_MEDIA = "UNKNOWN_MEDIA"
REJECTED = "REJECTED"

MEDIA_CLASSIFICATIONS = frozenset({
    PROFILE_AVATAR, PROFILE_BANNER, PLATFORM_LOGO, GENERIC_THUMBNAIL,
    DEFAULT_AVATAR, UNKNOWN_MEDIA, REJECTED,
})


@dataclass
class EvidenceItem:
    """A single piece of extracted evidence with provenance."""

    field: str
    value: str
    source: str
    confidence: int
    category: str = "identity"


@dataclass
class MediaEvidence:
    """One captured image with classification and provenance.

    Only a validated PROFILE_AVATAR may be used as an avatar, feed avatar
    correlation, or affect risk scoring. Everything else is page media.
    """

    url: str
    classification: str = UNKNOWN_MEDIA
    confidence: int = 0
    source: str = ""
    width: int | None = None
    height: int | None = None
    content_type: str | None = None
    perceptual_hash: str | None = None
    local_path: str | None = None
    embedded_uri: str | None = None
    validated: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def is_profile_avatar(self) -> bool:
        return self.classification == PROFILE_AVATAR and self.validated

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "classification": self.classification,
            "confidence": self.confidence,
            "source": self.source,
            "width": self.width,
            "height": self.height,
            "content_type": self.content_type,
            "perceptual_hash": self.perceptual_hash,
            "local_path": self.local_path,
            "embedded_uri": self.embedded_uri,
            "validated": self.validated,
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MediaEvidence":
        return cls(
            url=str(data.get("url", "")),
            classification=str(data.get("classification", UNKNOWN_MEDIA)),
            confidence=int(data.get("confidence", 0) or 0),
            source=str(data.get("source", "")),
            width=data.get("width"),
            height=data.get("height"),
            content_type=data.get("content_type"),
            perceptual_hash=data.get("perceptual_hash"),
            local_path=data.get("local_path"),
            embedded_uri=data.get("embedded_uri"),
            validated=bool(data.get("validated", False)),
            warnings=list(data.get("warnings", []) or []),
        )


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
    media: list[MediaEvidence] = field(default_factory=list)
    media_diagnostics: list[dict] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    verification: str = "UNVERIFIED"
    warnings: list[str] = field(default_factory=list)

    def best_avatar(self) -> MediaEvidence | None:
        """Return the highest-confidence validated profile avatar, if any."""
        avatars = [m for m in self.media if m.is_profile_avatar]
        if not avatars:
            return None
        return max(avatars, key=lambda m: m.confidence)
