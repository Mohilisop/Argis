"""Runtime media capture for scan results.

GitHub and Instagram resolve through first-party profile APIs. Every other
platform falls back to validated JSON-LD, Open Graph, Twitter card, and
profile-image metadata extracted from the confirmed profile page.

This module monkey-patches ArgisEngine.check_platform so normal scans preserve
validated avatar_url/avatar_hash before dossier generation runs.
"""
from __future__ import annotations

from typing import Any

from argis.core import ArgisEngine
from argis.media import _dhash, _is_valid_avatar, extract_avatar_candidates
from argis.utils.network import random_user_agent

_INSTALLED = False
_ORIGINAL_CHECK = ArgisEngine.check_platform

_GITHUB_NAMES = {"github", "gist", "github sponsors"}
_INSTAGRAM_NAMES = {"instagram"}
_INSTAGRAM_APP_ID = "936619743392459"


def install_media_capture() -> None:
    """Install the media-capture wrapper on the scan engine (idempotent)."""
    global _INSTALLED
    if _INSTALLED:
        return
    ArgisEngine.check_platform = _check_platform_with_media
    _INSTALLED = True


def _json_response(response) -> dict[str, Any] | None:
    try:
        value = response.json()
    except Exception:
        return None
    return value if isinstance(value, dict) else None


async def _github_profile(client, username: str) -> dict[str, Any] | None:
    """Resolve a GitHub profile through GitHub's public user API."""
    try:
        response = await client.get(
            f"https://api.github.com/users/{username}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Argis-OSINT",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            follow_redirects=True,
        )
    except Exception:
        return None
    if response.status_code != 200:
        return None
    data = _json_response(response)
    if not data or str(data.get("login", "")).casefold() != username.casefold():
        return None
    avatar = str(data.get("avatar_url") or "")
    if not avatar.startswith("https://"):
        return None
    return {
        "status": "FOUND",
        "url": str(data.get("html_url") or f"https://github.com/{username}"),
        "title": str(data.get("name") or data.get("login") or username),
        "display_name": str(data.get("name") or ""),
        "description": str(data.get("bio") or ""),
        "avatar_url": avatar,
        "confidence": 100,
        "media_source": "GitHub public user API",
        "profile_source": "api.github.com/users",
    }


async def _instagram_profile(client, username: str) -> dict[str, Any] | None:
    """Resolve public Instagram profile metadata used by the web client."""
    endpoint = "https://www.instagram.com/api/v1/users/web_profile_info/"
    try:
        response = await client.get(
            endpoint,
            params={"username": username},
            headers={
                "User-Agent": random_user_agent(),
                "X-IG-App-ID": _INSTAGRAM_APP_ID,
                "Accept": "*/*",
                "Referer": f"https://www.instagram.com/{username}/",
            },
            follow_redirects=True,
        )
    except Exception:
        return None
    if response.status_code != 200:
        return None
    payload = _json_response(response)
    user = (payload or {}).get("data", {}).get("user")
    if not isinstance(user, dict):
        return None
    if str(user.get("username", "")).casefold() != username.casefold():
        return None
    avatar = str(user.get("profile_pic_url_hd") or user.get("profile_pic_url") or "")
    if not avatar.startswith("http"):
        return None
    full_name = str(user.get("full_name") or "")
    return {
        "status": "FOUND",
        "url": f"https://www.instagram.com/{username}/",
        "title": full_name or f"@{username}",
        "display_name": full_name,
        "description": str(user.get("biography") or ""),
        "avatar_url": avatar,
        "confidence": 100,
        "media_source": "Instagram web profile API",
        "profile_source": "instagram web_profile_info",
        "is_private": bool(user.get("is_private", False)),
        "is_verified": bool(user.get("is_verified", False)),
    }


async def _profile_api_result(client, platform: str, username: str) -> dict[str, Any] | None:
    name = platform.casefold().strip()
    if name in _GITHUB_NAMES:
        return await _github_profile(client, username)
    if name in _INSTAGRAM_NAMES:
        return await _instagram_profile(client, username)
    return None


async def _attach_validated_image(client, result: dict[str, Any]) -> dict[str, Any]:
    image_url = str(result.get("avatar_url") or "")
    if not image_url:
        return result
    try:
        response = await client.get(
            image_url,
            headers={
                "User-Agent": random_user_agent(),
                "Referer": str(result.get("url") or ""),
                "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            },
            follow_redirects=True,
        )
    except Exception as exc:
        result["media_warning"] = f"avatar download failed: {type(exc).__name__}"
        return result
    if response.status_code != 200:
        result["media_warning"] = f"avatar download returned HTTP {response.status_code}"
        return result
    valid, reason = _is_valid_avatar(response.content, image_url)
    if not valid:
        result["media_warning"] = f"avatar validation failed: {reason}"
        result.pop("avatar_url", None)
        return result
    result["avatar_url"] = str(response.url)
    digest = _dhash(response.content)
    if digest is not None:
        result["avatar_hash"] = f"{digest:016x}"
    result["media_validated"] = True
    return result


async def _check_platform_with_media(self, client, name: str, rules: dict, attempt: int = 1):
    # First-party profile data wins even when the generic HTML scanner is blocked
    # or mistakes a login page for NOT_FOUND.
    api_result = await _profile_api_result(client, name, self.username)
    if api_result is not None:
        return await _attach_validated_image(client, api_result)

    result = await _ORIGINAL_CHECK(self, client, name, rules, attempt=attempt)
    if result.get("status") != "FOUND" or result.get("avatar_url"):
        return result

    try:
        response = await client.get(
            result["url"],
            headers={"User-Agent": random_user_agent()},
            follow_redirects=True,
        )
        if response.status_code != 200:
            result["media_warning"] = f"profile media fetch returned HTTP {response.status_code}"
            return result

        for image_url in extract_avatar_candidates(response.text, str(response.url))[:10]:
            candidate = dict(result)
            candidate["avatar_url"] = image_url
            candidate["media_source"] = "validated profile metadata"
            candidate = await _attach_validated_image(client, candidate)
            if candidate.get("avatar_url"):
                return candidate

        result["media_warning"] = "no validated profile image found"
    except Exception as exc:
        result["media_warning"] = f"media capture failed: {type(exc).__name__}"
    return result
