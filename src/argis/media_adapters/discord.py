from __future__ import annotations

from html import unescape

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence


class DiscordAdapter:
    platforms = {"discord"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Discord", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Discord", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Discord", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text
        import re as _re
        avatar_match = _re.search(
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', text, _re.I
        )
        if avatar_match:
            url = unescape(avatar_match.group(1))
            if "discord" in url.lower() or "cdn.discord" in url.lower():
                return AdapterResult(found=True, profile_url=profile_url, media=[
                    MediaEvidence(url=url, classification="PROFILE_AVATAR",
                                  confidence=90, source="discord.og_image",
                                  validated=True),
                ])
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "Discord", "code": "NO_PUBLIC_MEDIA",
        })
