from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Optional

from argis import cache as argis_cache
from argis.decisions import MediaDecisions
from argis.defaults import PLATFORM_DEFAULTS
from argis.media_adapters import registered_adapters, adapter_for_platform
from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence, ProfileEvidence
from argis.resolve_url import detect_platform, extract_username, profile_url_for


import re as _re

_OG_IMAGE = _re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', _re.I
)
_AVATAR_CLASS = _re.compile(
    r'<[^>]*(?:class|id)\s*=\s*["\'][^"\']*(?:avatar|profile|user-avatar|userpic|pfp)[^"\']*["\'][^>]*>',
    _re.I
)
_IMG_TAG = _re.compile(
    r'<img[^>]+(?:src|data-src|data-original)=["\']([^"\']+)["\']', _re.I
)


def _norm(v: Any) -> str:
    return (v or "").strip().lower()


def _is_default_avatar(evidence: MediaEvidence, diagnostic: dict | None = None) -> bool:
    if evidence.classification == "DEFAULT_AVATAR":
        return True
    if evidence.confidence == 0:
        return True
    if diagnostic and "default" in str(diagnostic).lower():
        return True
    return False


async def _resolve_media(
    client: Any,
    platform: str,
    username: str,
    profile_url: str,
) -> AdapterResult:
    adapter = adapter_for_platform(platform)
    if adapter is None:
        return AdapterResult(found=False, profile_url=profile_url, diagnostic={
            "code": "NO_ADAPTER", "platform": platform,
            "message": f"No adapter for {platform}",
        })
    try:
        return await adapter.resolve(client, username, profile_url)
    except Exception as exc:
        return AdapterResult(found=False, profile_url=profile_url, diagnostic={
            "code": "ADAPTER_ERROR", "platform": platform,
            "message": str(exc),
        })


async def search_url(
    client: Any,
    url: str,
    username: str | None = None,
    platform: str | None = None,
    use_cache: bool = True,
    **kwargs,
) -> ProfileEvidence | None:
    if platform is None:
        platform = detect_platform(url)
    if not platform:
        return None
    if username is None:
        username = extract_username(url, platform)
    if not username:
        return None
    if use_cache:
        cache_key = f"media_{platform}_{username}".lower().replace("@", "")
        cached = argis_cache.get(cache_key)
        if cached is not None:
            pe = ProfileEvidence(**cached)
            if pe.media:
                pe.media = [MediaEvidence(**m) for m in cached.get("media", [])]
            return pe
    profile_url = profile_url_for(platform, username) or url
    result = await _resolve_media(client, platform, username, profile_url)
    found = result.found
    media = result.media or []
    diag = result.diagnostic

    pe = ProfileEvidence(
        platform=platform,
        category=PLATFORM_DEFAULTS.get(platform, {}).get("category", "unknown"),
        username=username,
        url=profile_url,
        status="FOUND" if found else "NOT_FOUND",
        display_name=result.display_name,
        bio=result.bio,
        avatar_url=result.profile_url if result.profile_url != profile_url else None,
        media=media,
        media_diagnostics=[diag] if diag else [],
    )
    if not found:
        pe.status = "NOT_FOUND"
    if use_cache:
        argis_cache.set(cache_key, pe.__dict__)
    return pe


async def search_profile(
    client: Any,
    username: str,
    platforms: list[str] | None = None,
    use_cache: bool = True,
    concurrency: int = 5,
    **kwargs,
) -> dict[str, ProfileEvidence]:
    if platforms is None:
        platforms = list(PLATFORM_DEFAULTS.keys())
    sem = asyncio.Semaphore(concurrency)

    async def search_one(platform: str) -> tuple[str, ProfileEvidence | None]:
        url = profile_url_for(platform, username)
        if not url:
            return platform, None
        async with sem:
            pe = await search_url(client, url, username=username, platform=platform, use_cache=use_cache)
            return platform, pe

    tasks = [search_one(p) for p in platforms]
    results = await asyncio.gather(*tasks)
    return {p: pe for p, pe in results if pe is not None}


def collect_media(
    profiles: dict[str, ProfileEvidence],
    min_confidence: int | None = None,
    classify: bool = True,
    include_defaults: bool = False,
) -> list[MediaEvidence]:
    collected = []
    for platform, profile in profiles.items():
        for evidence in profile.media:
            if not include_defaults and _is_default_avatar(evidence, None):
                continue
            if min_confidence is not None and evidence.confidence < min_confidence:
                continue
            collected.append(evidence)
    collected.sort(key=lambda m: m.confidence, reverse=True)
    return collected[:MediaDecisions.RECOMMENDED_MAX_MEDIA]


def rank_media_candidates(profiles: dict[str, ProfileEvidence]) -> list[dict]:
    candidates = []
    for platform, profile in profiles.items():
        if not profile.media:
            continue
        for evidence in profile.media:
            chosen = MediaDecisions.decide(profile)
            candidates.append({
                "platform": platform,
                "username": profile.username,
                "url": evidence.url,
                "classification": evidence.classification,
                "confidence": evidence.confidence,
                "source": evidence.source,
                "validated": evidence.validated,
                "chosen": chosen == evidence.url,
                "ascension": MediaDecisions.ascension_class(evidence.classification),
            })
    return sorted(candidates, key=lambda c: c["confidence"], reverse=True)


def extract_avatar_candidates(html: str, profile_url: str | None = None) -> list[MediaEvidence]:
    candidates: list[MediaEvidence] = []
    seen: set[str] = set()

    for m in _OG_IMAGE.finditer(html):
        url = m.group(1)
        if url and url not in seen:
            seen.add(url)
            candidates.append(MediaEvidence(
                url=url, classification="PROFILE_AVATAR", confidence=70,
                source="html.og_image",
            ))

    avatar_sections = set()
    for m in _AVATAR_CLASS.finditer(html):
        start = max(0, m.start() - 500)
        end = min(len(html), m.end() + 500)
        avatar_sections.add(html[start:end])

    for section in avatar_sections:
        for m in _IMG_TAG.finditer(section):
            url = m.group(1)
            if url and url not in seen:
                seen.add(url)
                candidates.append(MediaEvidence(
                    url=url, classification="PROFILE_AVATAR", confidence=65,
                    source="html.avatar_section_img",
                ))

    return candidates


async def enrich_avatar(
    pe: ProfileEvidence,
    html: str,
    fetcher: Any = None,
) -> ProfileEvidence:
    candidates = extract_avatar_candidates(html, pe.url)
    if not candidates:
        return pe
    if fetcher is not None:
        from urllib.parse import urlparse
        base = urlparse(pe.url)
        valid = []
        for c in candidates:
            try:
                resp = await fetcher.get(c.url)
                if resp.status == 200 and not resp.error:
                    c.validated = True
                    c.confidence = min(c.confidence + 20, 100)
                    valid.append(c)
            except Exception:
                valid.append(c)
        candidates = valid
    existing_urls = {m.url for m in pe.media}
    for c in candidates:
        if c.url not in existing_urls:
            pe.media.append(c)
            existing_urls.add(c.url)
    return pe
