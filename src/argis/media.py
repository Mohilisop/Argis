from __future__ import annotations

import io
import json
import re
from html import unescape
from urllib.parse import urljoin

from argis.models import EvidenceItem, ProfileEvidence

try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

_LOGO_PATTERNS = re.compile(
    r"(?i)(?:^|[/_.-])(logo|sprite|banner|cover|brand|placeholder|avatar[_-]?default|default[_-]?avatar|1x1|pixel)(?:[/_.?&=-]|$)"
)
_MIN_AVATAR_SIZE = 48
_MAX_AVATAR_SIZE = 8 * 1024 * 1024
_MIN_ASPECT = 0.55
_MAX_ASPECT = 1.8

# Known reliable public avatar endpoints. These are attempted before page metadata.
def platform_avatar_candidates(profile: ProfileEvidence) -> list[str]:
    user = profile.username.strip()
    platform = profile.platform.lower().strip()
    if not user:
        return []
    if platform in {"github", "gist", "github sponsors"}:
        return [f"https://github.com/{user}.png?size=460"]
    if platform == "gitlab":
        return [f"https://gitlab.com/uploads/-/system/user/avatar/{user}/avatar.png"]
    if platform == "codeberg":
        return [f"https://codeberg.org/avatars/{user}"]
    return []


def _dhash(data: bytes, size: int = 8) -> int | None:
    if not _HAS_PIL:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("L").resize(
            (size + 1, size), Image.Resampling.LANCZOS
        )
    except Exception:
        return None
    get_pixels = getattr(img, "get_flattened_data", None) or getattr(img, "getdata")
    pixels = list(get_pixels())
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            bits = (bits << 1) | (
                1 if pixels[base + col] > pixels[base + col + 1] else 0
            )
    return bits


def _is_valid_avatar(data: bytes | None, url: str) -> tuple[bool, str]:
    if not data:
        return False, "empty image response"
    if len(data) > _MAX_AVATAR_SIZE:
        return False, f"image exceeds {_MAX_AVATAR_SIZE} bytes"
    if _LOGO_PATTERNS.search(url):
        return False, "URL looks like a logo/default asset"
    if not _HAS_PIL:
        # Keep media functional without the optional Pillow dependency.
        return True, "validation limited because Pillow is not installed"
    try:
        image = Image.open(io.BytesIO(data))
        image.verify()
        image = Image.open(io.BytesIO(data))
    except Exception:
        return False, "response is not a decodable image"
    width, height = image.size
    if width < _MIN_AVATAR_SIZE or height < _MIN_AVATAR_SIZE:
        return False, f"image too small ({width}x{height})"
    aspect = width / height
    if not _MIN_ASPECT <= aspect <= _MAX_ASPECT:
        return False, f"avatar aspect ratio rejected ({aspect:.2f})"
    return True, ""


_META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(
    r"([:\w-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
    re.I,
)
_JSONLD = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S,
)
_IMG_TAG = re.compile(r"<img\b[^>]*>", re.I)


def _attrs(tag: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in _ATTR.finditer(tag):
        values[match.group(1).lower()] = unescape(
            match.group(2) or match.group(3) or match.group(4) or ""
        )
    return values


def _json_images(value) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in {"image", "avatar", "thumbnailurl", "contenturl"}:
                if isinstance(child, str):
                    found.append(child)
                elif isinstance(child, dict) and isinstance(child.get("url"), str):
                    found.append(child["url"])
            found.extend(_json_images(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_json_images(child))
    return found


def extract_avatar_candidates(page_html: str, page_url: str) -> list[str]:
    """Extract likely profile images regardless of HTML attribute order."""
    candidates: list[str] = []

    # Structured data is strongest when the page describes a Person/ProfilePage.
    for block in _JSONLD.findall(page_html):
        try:
            candidates.extend(_json_images(json.loads(unescape(block.strip()))))
        except (json.JSONDecodeError, TypeError):
            continue

    # Open Graph and Twitter metadata. Parsing attributes avoids the old bug where
    # content="..." appearing before property="og:image" was silently missed.
    for tag in _META_TAG.findall(page_html):
        attrs = _attrs(tag)
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in {
            "og:image", "og:image:url", "og:image:secure_url",
            "twitter:image", "twitter:image:src",
        }:
            candidates.append(attrs.get("content", ""))

    # Profile-specific image tags are a final fallback, not every image on page.
    for tag in _IMG_TAG.findall(page_html):
        attrs = _attrs(tag)
        marker = " ".join(
            [attrs.get("class", ""), attrs.get("id", ""), attrs.get("alt", "")]
        ).lower()
        if any(word in marker for word in ("avatar", "profile", "userpic", "photo")):
            candidates.append(attrs.get("src") or attrs.get("data-src") or "")

    resolved: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate = unescape(str(candidate)).strip()
        if not candidate or candidate.startswith(("data:", "blob:")):
            continue
        if candidate.startswith("//"):
            candidate = "https:" + candidate
        candidate = urljoin(page_url, candidate)
        if candidate.startswith(("http://", "https://")) and candidate not in seen:
            seen.add(candidate)
            resolved.append(candidate)
    return resolved


async def enrich_avatar(
    profile: ProfileEvidence,
    html: str | None = None,
    fetcher=None,
) -> ProfileEvidence:
    """Fetch, validate, and attach a profile avatar.

    Unlike the previous implementation, this fetches the profile page itself
    when the caller does not pass HTML. That was the reason dossier media stayed
    empty: normalized scan results do not preserve response HTML.
    """
    if profile.avatar_url:
        return profile
    if fetcher is None:
        profile.warnings.append("avatar unavailable: no media fetcher")
        return profile

    page_html = html
    if not page_html and profile.url:
        fetched = await fetcher.get(profile.url, want_render=None)
        if fetched and fetched.status == 200:
            page_html = fetched.text
        else:
            profile.warnings.append("avatar unavailable: profile page fetch failed")

    candidates = platform_avatar_candidates(profile)
    if page_html:
        candidates.extend(extract_avatar_candidates(page_html, profile.url))

    # Preserve order and remove duplicates.
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        profile.warnings.append("avatar unavailable: no profile-image candidate")
        return profile

    rejection_reasons: list[str] = []
    for url in candidates[:12]:
        data = await fetcher.get_bytes(url)
        valid, reason = _is_valid_avatar(data, url)
        if not valid:
            rejection_reasons.append(reason)
            continue
        profile.avatar_url = url
        digest = _dhash(data or b"")
        if digest is not None:
            profile.avatar_hash = f"{digest:016x}"
        profile.evidence.append(
            EvidenceItem(
                field="avatar",
                value=url,
                source="media.validated_profile_image",
                confidence=90 if platform_avatar_candidates(profile) else 76,
            )
        )
        return profile

    reason = rejection_reasons[0] if rejection_reasons else "all candidates failed"
    profile.warnings.append(f"avatar rejected: {reason}")
    return profile
