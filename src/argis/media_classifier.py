"""Evidence-based media classifier.

Decides whether a captured image is a real profile avatar or platform noise
(logo, favicon, marketing preview, default avatar). This is the piece that
stops the dossier from labelling every og:image as PROFILE_AVATAR 90%.

The classifier is pure and deterministic so it is trivially testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from argis.models import (
    DEFAULT_AVATAR,
    GENERIC_THUMBNAIL,
    PLATFORM_LOGO,
    PROFILE_AVATAR,
    PROFILE_BANNER,
    REJECTED,
    UNKNOWN_MEDIA,
)

# Path/filename fragments that mark an image as site chrome, not a person.
_LOGO_PATTERN = re.compile(
    r"(?i)(?:^|[/_.\-])"
    r"(logo|favicon|sprite|banner|cover|brand|product|thumbnail|"
    r"default|placeholder|og[-_]?image|ogimage|share|social|preview|"
    r"apple-touch|android-chrome|meta-image|meta-default|letterbox)"
    r"(?:[/_.?&=\-]|$)"
)
_PROFILE_HINT = re.compile(
    r"(?i)(avatar|profile[_-]?pic|profile[_-]?image|userpic|headshot|portrait)"
)
_STABLE_ID = re.compile(
    r"(?i)(?:/u/|/user/|/users/|/avatars?/)?(?:\D|^)(\d{5,})(?:\D|$)"
)

_AMBIGUOUS_STATES = {"AMBIGUOUS", "NOT_FOUND", "ERROR", "UNVERIFIED"}
_PREVIEW_MIN_WIDTH = 600


@dataclass
class ClassifierContext:
    platform: str
    profile_url: str
    image_url: str
    source: str = ""
    username: str = ""
    verification: str = "PROBABLE"
    width: int | None = None
    height: int | None = None
    content_type: str | None = None
    api_declared_avatar: bool = False
    jsonld_person: bool = False
    username_in_page: bool = False
    host_duplicate: bool = False
    known_default_hash: bool = False
    known_logo_hash: bool = False
    is_banner_field: bool = False
    decodable_image: bool = True


def _looks_like_preview(width: int | None, height: int | None) -> bool:
    if not width or not height:
        return False
    if width < _PREVIEW_MIN_WIDTH:
        return False
    ratio = width / height
    return 1.7 <= ratio <= 2.1


def _looks_square(width: int | None, height: int | None) -> bool:
    if not width or not height:
        return False
    ratio = width / height
    return 0.8 <= ratio <= 1.25


def classify_media(ctx: ClassifierContext) -> tuple[str, int, list[str]]:
    """Return (classification, confidence 0-100, warnings)."""
    warnings: list[str] = []
    low_url = ctx.image_url.lower()
    source_low = (ctx.source or "").lower()

    # Hard, unambiguous outcomes first.
    if not ctx.decodable_image:
        return REJECTED, 0, ["response is not a decodable image"]
    if ctx.known_logo_hash:
        return PLATFORM_LOGO, 0, ["matches a known platform logo"]
    if ctx.known_default_hash:
        return DEFAULT_AVATAR, 0, ["matches a known default avatar"]

    image_host = urlparse(ctx.image_url).netloc.lower()
    profile_host = urlparse(ctx.profile_url).netloc.lower()

    score = 45

    if ctx.api_declared_avatar:
        score += 45
        warnings.append("API-declared avatar field")
    if ctx.jsonld_person:
        score += 35
    if "profile" in source_low or "avatar" in source_low:
        score += 30
    if _PROFILE_HINT.search(low_url):
        score += 18
    if _STABLE_ID.search(low_url):
        score += 20
    if ctx.username and ctx.username.lower() in low_url:
        score += 20
    if ctx.username_in_page:
        score += 18
    if image_host and profile_host and (
        image_host == profile_host or image_host.endswith("." + profile_host)
    ):
        score += 8
    if _looks_square(ctx.width, ctx.height):
        score += 8

    logo_hit = bool(_LOGO_PATTERN.search(low_url))
    if logo_hit:
        score -= 70
        warnings.append("URL path looks like a site asset")
    if _looks_like_preview(ctx.width, ctx.height):
        score -= 45
        warnings.append("dimensions resemble a social preview image")
    if "og" in source_low and not ctx.username_in_page and (
        not ctx.username or ctx.username.lower() not in low_url
    ):
        score -= 40
        warnings.append("generic Open Graph image without username evidence")
    if ctx.host_duplicate:
        score -= 60
        warnings.append("image reused across unrelated profiles on this host")

    ambiguous = ctx.verification.upper() in _AMBIGUOUS_STATES
    if ambiguous:
        score = min(score, 35)
        warnings.append("source account is not verified")

    score = max(0, min(100, score))

    # Banner detection: explicit banner field or wide profile-header art that
    # is not a logo.
    if ctx.is_banner_field or (_looks_like_preview(ctx.width, ctx.height) and not logo_hit and score >= 40):
        return PROFILE_BANNER, score, warnings

    if score >= 80:
        return PROFILE_AVATAR, score, warnings
    if logo_hit:
        return PLATFORM_LOGO, score, warnings
    if "og" in source_low or _looks_like_preview(ctx.width, ctx.height):
        return GENERIC_THUMBNAIL, score, warnings
    return UNKNOWN_MEDIA, score, warnings
