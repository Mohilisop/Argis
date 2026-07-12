from __future__ import annotations

import re
from html import unescape

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_AVATAR_FULL = re.compile(r"<avatarFull>\s*<(?:\!\[CDATA\[)?([^<>\]]+)(?:\]\]>)?\s*</avatarFull>", re.I)
_AVATAR_ICON = re.compile(r"<avatarIcon>\s*<(?:\!\[CDATA\[)?([^<>\]]+)(?:\]\]>)?\s*</avatarIcon>", re.I)
_STEAM_ID = re.compile(r"<steamID>\s*<(?:\!\[CDATA\[)?([^<>\]]+)(?:\]\]>)?\s*</steamID>", re.I)
_CUSTOM_URL = re.compile(r"<customURL>\s*<(?:\!\[CDATA\[)?([^<>\]]+)(?:\]\]>)?\s*</customURL>", re.I)

_STEAM_DEFAULTS = {
    "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb",
    "fef49e7fa7e1997310d705b2a6158ff8dc1cdfba",
}


class SteamAdapter:
    platforms = {"steam", "steam group"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        xml_url = profile_url.rstrip("/") + "/?xml=1"
        try:
            resp = await client.get(xml_url, headers={"User-Agent": "Argis/1.0"})
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Steam", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Steam", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Steam", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text
        sid = _STEAM_ID.search(text)
        custom = _CUSTOM_URL.search(text)
        steam_name = (custom.group(1) if custom else sid.group(1) if sid else "").strip()
        if steam_name.lower() not in (username.lower(), f"[{username.lower()}]"):
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Steam", "code": "USERNAME_MISMATCH",
                "message": f"XML returned '{steam_name}'",
            })
        avatar = unescape(_AVATAR_FULL.search(text).group(1).strip()) if _AVATAR_FULL.search(text) else ""
        if not avatar:
            avatar = unescape(_AVATAR_ICON.search(text).group(1).strip()) if _AVATAR_ICON.search(text) else ""
        if avatar:
            import hashlib
            if hashlib.sha1(avatar.encode()).hexdigest() in _STEAM_DEFAULTS:
                return AdapterResult(found=True, profile_url=profile_url, media=[
                    MediaEvidence(url=avatar, classification="DEFAULT_AVATAR",
                                  confidence=0, source="steam.xml"),
                ], diagnostic={
                    "platform": "Steam", "code": "NO_PUBLIC_MEDIA",
                    "message": "Steam default avatar detected",
                })
            return AdapterResult(found=True, profile_url=profile_url, media=[
                MediaEvidence(url=avatar, classification="PROFILE_AVATAR",
                              confidence=97, source="steam.xml_avatar_full",
                              validated=True),
            ])
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "Steam", "code": "NO_PUBLIC_MEDIA",
        })
