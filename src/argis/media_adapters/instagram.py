from __future__ import annotations

import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_USERNAME_RE = re.compile(r'"username"\s*:\s*"([^"]+)"', re.I)
_HD_PIC_RE = re.compile(r'"profile_pic_url_hd"\s*:\s*"([^"]+)"', re.I)
_PIC_RE = re.compile(r'"profile_pic_url"\s*:\s*"([^"]+)"', re.I)
_OG_IMAGE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.I
)


class InstagramAdapter:
    platforms = {"instagram", "instagram web profile"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        from urllib.parse import unquote
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Instagram", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Instagram", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status in (429, 403):
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Instagram", "code": "BLOCKED", "http_status": resp.status,
                "message": "Instagram blocked the public profile request",
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Instagram", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text
        username_match = _USERNAME_RE.search(text)
        if username_match:
            found_user = unquote(username_match.group(1))
            if found_user.lower() != username.lower():
                return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                    "platform": "Instagram", "code": "USERNAME_MISMATCH",
                    "message": f"Page returned username '{found_user}'",
                })
        if "This Account is Private" in text or "private" in text.lower():
            hd = _HD_PIC_RE.search(text) or _PIC_RE.search(text)
            if hd:
                avatar = unquote(hd.group(1)).replace("\\u0026", "&")
                return AdapterResult(found=True, profile_url=profile_url, media=[
                    MediaEvidence(url=avatar, classification="PROFILE_AVATAR", confidence=90,
                                  source="instagram.private_profile_pic", validated=True),
                ], diagnostic={
                    "platform": "Instagram", "code": "PRIVATE_ACCOUNT",
                    "message": "Account is private, but profile pic is visible",
                })
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Instagram", "code": "PRIVATE_ACCOUNT",
                "message": "Account is private, no public media",
            })
        hd = _HD_PIC_RE.search(text) or _PIC_RE.search(text)
        if hd:
            avatar = unquote(hd.group(1)).replace("\\u0026", "&")
            return AdapterResult(found=True, profile_url=profile_url, media=[
                MediaEvidence(url=avatar, classification="PROFILE_AVATAR", confidence=98,
                              source="instagram.profile_pic_hd", validated=True),
            ])
        og = _OG_IMAGE.search(text)
        if og:
            return AdapterResult(found=True, profile_url=profile_url, media=[
                MediaEvidence(url=og.group(1), classification="PROFILE_AVATAR", confidence=70,
                              source="instagram.og_image"),
            ])
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "Instagram", "code": "NO_PUBLIC_MEDIA",
            "message": "Page loaded but no profile picture found",
        })
