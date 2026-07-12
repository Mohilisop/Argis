"""Image capture, validation, and MediaEvidence construction.

Downloads a candidate image, measures it (dimensions, MIME type, perceptual
hash), then hands the facts to the classifier. Back-compatible helpers
(_dhash, _is_valid_avatar, extract_avatar_candidates) are retained so existing
call sites keep working.
"""
from __future__ import annotations

import io
import json
import re
from html import unescape
from urllib.parse import urljoin

from argis.media_classifier import ClassifierContext, classify_media
from argis.models import MediaEvidence, PROFILE_AVATAR

try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

_MAX_IMAGE_BYTES = 8 * 1024 * 1024
_MIN_DIM = 48
_IMAGE_MIME_PREFIXES = ("image/",)

_LOGO_PATTERNS = re.compile(
    r"(?i)(logo|sprite|banner|cover|icon|default|placeholder|ogimage|brand|"
    r"avatar_default|1x1|pixel)"
)


def _dhash(data: bytes, size: int = 8) -> int | None:
    """64-bit difference hash. Returns None without Pillow or on failure."""
    if not _HAS_PIL:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("L").resize(
            (size + 1, size), Image.Resampling.LANCZOS
        )
    except Exception:
        return None
    px = list(img.getdata())
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            bits = (bits << 1) | (1 if px[base + col] > px[base + col + 1] else 0)
    return bits


def _measure(data: bytes) -> tuple[int | None, int | None, bool]:
    """Return (width, height, decodable)."""
    if not _HAS_PIL:
        return None, None, True
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
        return img.size[0], img.size[1], True
    except Exception:
        return None, None, False


def _is_valid_avatar(data: bytes | None, url: str) -> tuple[bool, str]:
    """Legacy boolean gate kept for existing callers."""
    if not data:
        return False, "empty response"
    if len(data) > _MAX_IMAGE_BYTES:
        return False, f"exceeds size limit ({len(data)} bytes)"
    if _LOGO_PATTERNS.search(url):
        return False, "logo/default pattern in URL"
    width, height, decodable = _measure(data)
    if not decodable:
        return False, "not a valid image"
    if width is not None and (width < _MIN_DIM or height < _MIN_DIM):
        return False, f"too small ({width}x{height})"
    return True, ""


_META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(
    r"([:\w-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I
)
_JSONLD = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S
)
_IMG_TAG = re.compile(r"<img\b[^>]*>", re.I)


def _attrs(tag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR.finditer(tag):
        out[m.group(1).lower()] = unescape(m.group(2) or m.group(3) or m.group(4) or "")
    return out


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
    """Extract likely profile-image URLs, ordered strongest first."""
    candidates: list[tuple[str, str]] = []  # (url, source)

    for block in _JSONLD.findall(page_html):
        try:
            for u in _json_images(json.loads(unescape(block.strip()))):
                candidates.append((u, "jsonld.image"))
        except (json.JSONDecodeError, TypeError):
            continue

    for tag in _META_TAG.findall(page_html):
        attrs = _attrs(tag)
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in {"og:image", "og:image:url", "og:image:secure_url"}:
            candidates.append((attrs.get("content", ""), "html.og_image"))
        elif key in {"twitter:image", "twitter:image:src"}:
            candidates.append((attrs.get("content", ""), "html.twitter_image"))

    for tag in _IMG_TAG.findall(page_html):
        attrs = _attrs(tag)
        marker = " ".join([attrs.get("class", ""), attrs.get("id", ""), attrs.get("alt", "")]).lower()
        if any(w in marker for w in ("avatar", "profile", "userpic", "photo")):
            candidates.append((attrs.get("src") or attrs.get("data-src") or "", "html.avatar_section_img"))

    resolved: list[str] = []
    seen: set[str] = set()
    for url, _source in candidates:
        url = unescape(str(url)).strip()
        if not url or url.startswith(("data:", "blob:")):
            continue
        if url.startswith("//"):
            url = "https:" + url
        url = urljoin(page_url, url)
        if url.startswith(("http://", "https://")) and url not in seen:
            seen.add(url)
            resolved.append(url)
    return resolved


def extract_avatar_candidate_sources(page_html: str, page_url: str) -> list[tuple[str, str]]:
    """Like extract_avatar_candidates but keeps the (url, source) provenance."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(raw: str, source: str) -> None:
        raw = unescape(str(raw)).strip()
        if not raw or raw.startswith(("data:", "blob:")):
            return
        if raw.startswith("//"):
            raw = "https:" + raw
        raw = urljoin(page_url, raw)
        if raw.startswith(("http://", "https://")) and raw not in seen:
            seen.add(raw)
            pairs.append((raw, source))

    for block in _JSONLD.findall(page_html):
        try:
            for u in _json_images(json.loads(unescape(block.strip()))):
                add(u, "jsonld.image")
        except (json.JSONDecodeError, TypeError):
            continue
    for tag in _META_TAG.findall(page_html):
        attrs = _attrs(tag)
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in {"og:image", "og:image:url", "og:image:secure_url"}:
            add(attrs.get("content", ""), "html.og_image")
        elif key in {"twitter:image", "twitter:image:src"}:
            add(attrs.get("content", ""), "html.twitter_image")
    for tag in _IMG_TAG.findall(page_html):
        attrs = _attrs(tag)
        marker = " ".join([attrs.get("class", ""), attrs.get("id", ""), attrs.get("alt", "")]).lower()
        if any(w in marker for w in ("avatar", "profile", "userpic", "photo")):
            add(attrs.get("src") or attrs.get("data-src") or "", "html.avatar_section_img")
    return pairs


def build_media_evidence(
    *,
    image_url: str,
    image_bytes: bytes | None,
    platform: str,
    profile_url: str,
    username: str,
    source: str,
    verification: str = "PROBABLE",
    content_type: str | None = None,
    api_declared_avatar: bool = False,
    jsonld_person: bool = False,
    username_in_page: bool = False,
    is_banner_field: bool = False,
    known_default_hash: bool = False,
    known_logo_hash: bool = False,
) -> MediaEvidence:
    """Measure, hash, classify a candidate image into a MediaEvidence."""
    width = height = None
    decodable = True
    phash_hex: str | None = None

    too_big = bool(image_bytes) and len(image_bytes) > _MAX_IMAGE_BYTES
    mime_ok = not content_type or content_type.split(";")[0].strip().startswith(_IMAGE_MIME_PREFIXES)

    if image_bytes and not too_big and mime_ok:
        width, height, decodable = _measure(image_bytes)
        digest = _dhash(image_bytes)
        if digest is not None:
            phash_hex = f"{digest:016x}"
    elif image_bytes is None:
        decodable = True  # no bytes fetched; classify on URL signals only
    else:
        decodable = False

    ctx = ClassifierContext(
        platform=platform,
        profile_url=profile_url,
        image_url=image_url,
        source=source,
        username=username,
        verification=verification,
        width=width,
        height=height,
        content_type=content_type,
        api_declared_avatar=api_declared_avatar,
        jsonld_person=jsonld_person,
        username_in_page=username_in_page,
        known_default_hash=known_default_hash,
        known_logo_hash=known_logo_hash,
        is_banner_field=is_banner_field,
        decodable_image=decodable if image_bytes is not None else True,
    )
    classification, confidence, warnings = classify_media(ctx)

    if too_big:
        warnings = [*warnings, "image exceeds size limit"]
    if not mime_ok:
        warnings = [*warnings, f"unexpected content type: {content_type}"]

    validated = (
        classification == PROFILE_AVATAR
        and confidence >= 80
        and (image_bytes is None or decodable)
    )

    return MediaEvidence(
        url=image_url,
        classification=classification,
        confidence=confidence,
        source=source,
        width=width,
        height=height,
        content_type=content_type,
        perceptual_hash=phash_hex,
        validated=validated,
        warnings=warnings,
    )
