from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_TWITCH_APOLLO = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)


class TwitchAdapter:
    platforms = {"twitch"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
            "Client-ID": "kimne78kx3ncx6brgo4mv6wki5h1ko",
        }
        gql = {
            "query": "query($login:String){user(login:$login){id login displayName profileImageURL(width:300) biography}}",
            "variables": {"login": username},
        }
        try:
            resp = await client.post("https://gql.twitch.tv/gql",
                                     headers=headers, json=gql)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitch", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 400:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitch", "code": "BLOCKED", "http_status": 400,
                "message": "Twitch GQL rejected the request",
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitch", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        data = resp.json()
        user = data.get("data", {}).get("user")
        if user is None:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitch", "code": "ACCOUNT_NOT_FOUND",
                "message": "GQL returned null user",
            })
        display = user.get("login", "")
        if display.lower() != username.lower():
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitch", "code": "USERNAME_MISMATCH",
                "message": f"GQL returned login '{display}'",
            })
        avatar = user.get("profileImageURL", "")
        media = []
        if avatar:
            media.append(MediaEvidence(
                url=avatar, classification="PROFILE_AVATAR",
                confidence=98, source="twitch.gql", validated=True,
            ))
        return AdapterResult(
            found=True, profile_url=profile_url,
            display_name=user.get("displayName"),
            bio=user.get("biography"),
            media=media,
        )
