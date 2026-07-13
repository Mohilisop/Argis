from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from argis.media import search_url, search_profile, collect_media, rank_media_candidates
from argis.models import ProfileEvidence
from argis.resolve_url import detect_platform, extract_username
from argis.intel_http import IntelHTTP

_GITHUB_NAMES = {"github", "gist", "github sponsors"}
_INSTAGRAM_NAMES = {"instagram"}
_INSTAGRAM_APP_ID = "936619743392459"


def _format_profile(pe: ProfileEvidence, detailed: bool = False) -> dict:
    d = {
        "platform": pe.platform,
        "username": pe.username,
        "url": pe.url,
        "status": pe.status,
        "display_name": pe.display_name,
        "bio": pe.bio,
        "media_count": len(pe.media),
        "avatar_url": pe.avatar_url,
    }
    if detailed:
        d["media"] = [
            {
                "url": m.url,
                "classification": m.classification,
                "confidence": m.confidence,
                "source": m.source,
                "validated": m.validated,
                "warnings": m.warnings,
                "width": m.width,
                "height": m.height,
                "content_type": m.content_type,
                "perceptual_hash": m.perceptual_hash,
            }
            for m in pe.media
        ]
        d["diagnostics"] = pe.media_diagnostics
        d["warnings"] = pe.warnings
    return d


def _collect_summary(profiles: dict[str, ProfileEvidence]) -> list[dict]:
    results = []
    for platform, pe in sorted(profiles.items()):
        results.append(_format_profile(pe, detailed=False))
    return results


async def _run_media_search(
    client: IntelHTTP,
    targets: list[str],
    platforms: list[str] | None = None,
    _format: str = "text",
    detailed: bool = False,
    **kwargs,
) -> str:
    all_profiles: dict[str, ProfileEvidence] = {}

    for target in targets:
        platform = detect_platform(target)
        if platform:
            username = extract_username(target, platform)
            if username:
                pe = await search_url(client, target, username=username, platform=platform, **kwargs)
                if pe:
                    all_profiles[platform] = pe
        else:
            results = await search_profile(client, target, platforms=platforms, **kwargs)
            all_profiles.update(results)

    if _format == "json":
        output = {
            "profiles": {p: _format_profile(pe, detailed=detailed) for p, pe in all_profiles.items()},
            "media_candidates": rank_media_candidates(all_profiles),
        }
        return json.dumps(output, indent=2, default=str)
    else:
        lines = [f"Media Search Results ({len(all_profiles)} platforms found)\n"]
        for platform, pe in sorted(all_profiles.items()):
            status_icon = "\u2713" if pe.status == "FOUND" else "\u2717"
            lines.append(f"  [{status_icon}] {platform}: {pe.username}")
            lines.append(f"         URL: {pe.url}")
            if pe.display_name:
                lines.append(f"         Name: {pe.display_name}")
            if pe.media:
                best = max(pe.media, key=lambda m: m.confidence)
                lines.append(f"         Best media: {best.url} ({best.classification}, {best.confidence}%)")
            if pe.media_diagnostics:
                for diag in pe.media_diagnostics:
                    code = diag.get("code", "UNKNOWN")
                    msg = diag.get("message", "")
                    lines.append(f"         [{code}] {msg}")
        if not all_profiles:
            lines.append("  No profiles found.")
        return "\n".join(lines)


async def media_runtime(args: Any) -> str:
    async with IntelHTTP() as client:
        return await _run_media_search(
            client=client,
            targets=args.targets,
            platforms=args.platforms,
            _format=args.format,
            detailed=args.detailed,
            use_cache=not args.no_cache,
            concurrency=args.concurrency,
        )


def install_media_capture():
    pass
