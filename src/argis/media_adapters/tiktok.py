from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_SIGI_STATE = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)


class TikTokAdapter:
    platforms = {"tiktok"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "TikTok", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status in (429, 403):
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "TikTok", "code": "BLOCKED", "http_status": resp.status,
                "message": "TikTok blocked the request (bot challenge or rate limit)",
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "TikTok", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "TikTok", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        m = _SIGI_STATE.search(resp.text)
        if not m:
            return AdapterResult(found=True, profile_url=profile_url, diagnostic={
                "platform": "TikTok", "code": "NO_PUBLIC_MEDIA",
                "message": "No __NEXT_DATA__ state found",
            })
        try:
            data = json.loads(m.group(1))
            props = data.get("props", {}).get("pageProps", {})
            user_info = props.get("userData", {}) or props.get("userInfo", {}) or {}
            unique_id = user_info.get("uniqueId", "") or user_info.get("user", {}).get("uniqueId", "")
            if unique_id.lower() != username.lower():
                return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                    "platform": "TikTok", "code": "USERNAME_MISMATCH",
                    "message": f"Page returned uniqueId '{unique_id}'",
                })
            avatar = (user_info.get("avatarLarger") or user_info.get("avatarMedium")
                      or user_info.get("avatarThumb") or user_info.get("user", {}).get("avatarLarger", ""))
            if avatar:
                return AdapterResult(found=True, profile_url=profile_url, media=[
                    MediaEvidence(url=avatar, classification="PROFILE_AVATAR",
                                  confidence=96, source="tiktok.next_data",
                                  validated=True),
                ])
        except Exception:
            pass
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "TikTok", "code": "NO_PUBLIC_MEDIA",
        })
