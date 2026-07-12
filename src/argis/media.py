from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Optional

from argis.models import EvidenceItem, ProfileEvidence

try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False


_LOGO_PATTERNS = re.compile(
    r"(?i)(logo|sprite|banner|cover|icon|default|placeholder|ogimage|brand|avatar_default|1x1|pixel)"
)

# Known platform default avatar perceptual hashes (64-bit dhash)
# Will be populated on first encounter
_KNOWN_DEFAULT_HASHES: set[int] = set()

_MIN_AVATAR_SIZE = 80
_MAX_AVATAR_SIZE = 1024 * 1024 * 2  # 2 MB
_MIN_ASPECT = 0.65
_MAX_ASPECT = 1.5


def _dhash(data: bytes, size: int = 8) -> int | None:
    """64-bit difference hash."""
    if not _HAS_PIL:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("L").resize(
            (size + 1, size), Image.LANCZOS
        )
    except Exception:
        return None
    px = list(img.getdata())
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            left = px[base + col]
            right = px[base + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def _is_valid_avatar(data: bytes, url: str) -> tuple[bool, str]:
    """Validate an avatar image candidate. Returns (is_valid, reason)."""
    if not data:
        return False, "empty response"
    if len(data) > _MAX_AVATAR_SIZE:
        return False, f"exceeds size limit ({len(data)} bytes)"
    if _LOGO_PATTERNS.search(url):
        return False, f"logo/default pattern in URL"
    if not _HAS_PIL:
        return True, ""
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return False, "not a valid image"
    w, h = img.size
    if w < _MIN_AVATAR_SIZE or h < _MIN_AVATAR_SIZE:
        return False, f"too small ({w}x{h})"
    aspect = w / h
    if aspect < _MIN_ASPECT or aspect > _MAX_ASPECT:
        return False, f"bad aspect ratio ({aspect:.2f})"
    phash = _dhash(data)
    if phash is not None and phash in _KNOWN_DEFAULT_HASHES:
        return False, "matches known default avatar"
    return True, ""


_OG_IMAGE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_TWITTER_IMAGE = re.compile(
    r'<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_JSONLD_IMAGE = re.compile(
    r'"image"\s*:\s*"([^"]+)"', re.I
)


def extract_avatar_candidates(html: str, page_url: str) -> list[str]:
    """Extract avatar URL candidates from page HTML, ordered by priority."""
    candidates: list[str] = []

    # 1. JSON-LD image
    for m in _JSONLD_IMAGE.finditer(html):
        candidates.append(m.group(1))

    # 2. Open Graph image
    m = _OG_IMAGE.search(html)
    if m:
        candidates.append(m.group(1))

    # 3. Twitter card image
    m = _TWITTER_IMAGE.search(html)
    if m:
        candidates.append(m.group(1))

    # Resolve relative URLs
    from urllib.parse import urljoin
    resolved = []
    for c in candidates:
        if c.startswith("/"):
            c = urljoin(page_url, c)
        resolved.append(c)
    return resolved


async def enrich_avatar(
    profile: ProfileEvidence,
    html: str | None = None,
    fetcher=None,
) -> ProfileEvidence:
    """Attempt to find and validate an avatar for this profile."""
    if profile.avatar_url:
        # Already has one from an API or structured source
        return profile

    if not html:
        return profile

    candidates = extract_avatar_candidates(html, profile.url)
    if not candidates:
        return profile

    if fetcher is None:
        return profile

    for url in candidates:
        data = await fetcher.get_bytes(url)
        valid, reason = _is_valid_avatar(data, url)
        if valid:
            profile.avatar_url = url
            h = _dhash(data)
            if h is not None:
                profile.avatar_hash = hex(h)
            profile.evidence.append(
                EvidenceItem(
                    field="avatar", value=url,
                    source="enrich.og_image", confidence=70,
                )
            )
            return profile

    return profile
