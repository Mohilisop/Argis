"""Runtime bridge that preserves profile media in normal scan results.

The scanner previously discarded response HTML before dossier enrichment ran.
This hook reuses the active HTTP client for FOUND profiles, extracts image
metadata, validates candidates, and stores avatar_url/avatar_hash in the result.
"""
from __future__ import annotations

from argis.core import ArgisEngine
from argis.media import _dhash, _is_valid_avatar, extract_avatar_candidates
from argis.utils.network import random_user_agent

_INSTALLED = False
_ORIGINAL_CHECK = ArgisEngine.check_platform


def install_media_capture() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    ArgisEngine.check_platform = _check_platform_with_media
    _INSTALLED = True


async def _check_platform_with_media(self, client, name: str, rules: dict, attempt: int = 1):
    result = await _ORIGINAL_CHECK(self, client, name, rules, attempt=attempt)
    if result.get("status") != "FOUND" or result.get("avatar_url"):
        return result

    # Refetch only confirmed hits. This fixes the lost-response problem without
    # changing the scanner's public result contract or guessing image URLs.
    try:
        response = await client.get(
            result["url"],
            headers={"User-Agent": random_user_agent()},
            follow_redirects=True,
        )
        if response.status_code != 200:
            result["media_warning"] = f"profile media fetch returned HTTP {response.status_code}"
            return result

        candidates = extract_avatar_candidates(response.text, str(response.url))
        for image_url in candidates[:10]:
            try:
                image_response = await client.get(
                    image_url,
                    headers={
                        "User-Agent": random_user_agent(),
                        "Referer": str(response.url),
                        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                    },
                    follow_redirects=True,
                )
            except Exception:
                continue
            if image_response.status_code != 200:
                continue
            valid, _ = _is_valid_avatar(image_response.content, image_url)
            if not valid:
                continue
            result["avatar_url"] = str(image_response.url)
            digest = _dhash(image_response.content)
            if digest is not None:
                result["avatar_hash"] = f"{digest:016x}"
            result["media_source"] = "validated profile metadata"
            break

        if not result.get("avatar_url"):
            result["media_warning"] = "no validated profile image found"
    except Exception as exc:
        result["media_warning"] = f"media capture failed: {type(exc).__name__}"
    return result
