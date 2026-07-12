from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_HYDRATION = re.compile(r'window\.__sc_hydration\s*=\s*(\[.*?\]);', re.DOTALL)


class SoundCloudAdapter:
    platforms = {"soundcloud"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,*/*;q=0.9",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "SoundCloud", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "SoundCloud", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "SoundCloud", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        m = _HYDRATION.search(resp.text)
        if not m:
            return AdapterResult(found=True, profile_url=profile_url, diagnostic={
                "platform": "SoundCloud", "code": "NO_PUBLIC_MEDIA",
                "message": "No hydration state found",
            })
        try:
            hydration = json.loads(m.group(1))
        except Exception:
            return AdapterResult(found=True, profile_url=profile_url, diagnostic={
                "platform": "SoundCloud", "code": "INVALID_RESPONSE",
            })
        for entry in hydration:
            if entry.get("hydratable") == "user":
                data = entry.get("data", {}) or entry.get("data", {})
                permalink = data.get("permalink", "")
                if permalink.lower() != username.lower():
                    return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                        "platform": "SoundCloud", "code": "USERNAME_MISMATCH",
                        "message": f"Profile returned permalink '{permalink}'",
                    })
                avatar = data.get("avatar_url", "")
                if avatar:
                    avatar = avatar.replace("-large.", "-t500x500.").replace("-small.", "-t500x500.")
                    return AdapterResult(found=True, profile_url=profile_url, media=[
                        MediaEvidence(url=avatar, classification="PROFILE_AVATAR",
                                      confidence=96, source="soundcloud.hydration_avatar_url",
                                      validated=True),
                    ])
                return AdapterResult(found=True, profile_url=profile_url, diagnostic={
                    "platform": "SoundCloud", "code": "NO_PUBLIC_MEDIA",
                })
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "SoundCloud", "code": "NO_PUBLIC_MEDIA",
        })
