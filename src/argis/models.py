from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


MEDIA_CLASSIFICATIONS = {
    "PROFILE_AVATAR", "PROFILE_BANNER", "PLATFORM_LOGO",
    "GENERIC_THUMBNAIL", "DEFAULT_AVATAR", "UNKNOWN_MEDIA", "REJECTED",
}

DIAGNOSTIC_CODES = {
    "ACCOUNT_NOT_FOUND", "PRIVATE_ACCOUNT", "AUTH_REQUIRED", "BLOCKED",
    "RATE_LIMITED", "HTTP_ERROR", "INVALID_RESPONSE", "NO_PUBLIC_MEDIA",
    "USERNAME_MISMATCH", "IMAGE_DOWNLOAD_FAILED", "IMAGE_VALIDATION_FAILED",
}


@dataclass
class EvidenceItem:
    field: str
    value: str
    source: str
    confidence: int
    category: str = "identity"


@dataclass
class MediaEvidence:
    url: str
    classification: str
    confidence: int
    source: str
    width: int | None = None
    height: int | None = None
    content_type: str | None = None
    perceptual_hash: str | None = None
    local_path: str | None = None
    embedded_uri: str | None = None
    validated: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class ProfileEvidence:
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
    media: list[MediaEvidence] = field(default_factory=list)
    media_diagnostics: list[dict] = field(default_factory=list)
    verification: str = "UNVERIFIED"
    warnings: list[str] = field(default_factory=list)
