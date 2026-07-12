from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence


class ActivityPubAdapter:
    platforms = {"mastodon", "pleroma", "misskey", "lemmy", "peertube", "activitypub", "fedi",
                 "f channel", "threads"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "Accept": "application/activity+json, application/json",
            "User-Agent": "Argis/1.0",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 410:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "ACCOUNT_SUSPENDED",
                "http_status": 410, "message": "Account suspended (Gone)",
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        content_type = resp.headers.get("Content-Type", "")
        if "json" not in content_type and "activity+json" not in content_type:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "NOT_ACTIVITYPUB",
                "message": "Does not return ActivityPub JSON",
            })
        try:
            data = resp.json()
        except Exception:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "INVALID_JSON",
            })
        preferred = data.get("preferredUsername", "")
        if preferred.lower() != username.lower():
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "ActivityPub", "code": "USERNAME_MISMATCH",
                "message": f"ActivityPub returned preferredUsername '{preferred}'",
            })
        icon = data.get("icon", {})
        if isinstance(icon, dict):
            avatar = icon.get("url", "") or (icon.get("type") == "Image" and icon.get("url", "")) or ""
        elif isinstance(icon, str):
            avatar = icon
        else:
            avatar = ""
        media = []
        if avatar:
            media.append(MediaEvidence(
                url=avatar, classification="PROFILE_AVATAR",
                confidence=95, source="activitypub.icon", validated=True,
            ))
        return AdapterResult(
            found=True, profile_url=profile_url,
            display_name=data.get("name"),
            bio=data.get("summary"),
            media=media,
        )
