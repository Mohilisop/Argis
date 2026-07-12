from __future__ import annotations

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence


class SnapchatAdapter:
    platforms = {"snapchat"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,*/*;q=0.9",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Snapchat", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Snapchat", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Snapchat", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text
        if "We couldn" in text and ("doesn" in text.lower() or "found" in text.lower()):
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Snapchat", "code": "ACCOUNT_NOT_FOUND",
                "message": "Snapchat returned user-not-found page",
            })
        import re as _re
        avatar_match = _re.search(
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', text, _re.I
        )
        if avatar_match:
            url = avatar_match.group(1)
            if "snapchat" in url.lower() or "bitmoji" in url.lower():
                return AdapterResult(found=True, profile_url=profile_url, media=[
                    MediaEvidence(url=url, classification="PROFILE_AVATAR",
                                  confidence=85, source="snapchat.og_image",
                                  validated=True),
                ])
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "Snapchat", "code": "NO_PUBLIC_MEDIA",
        })
