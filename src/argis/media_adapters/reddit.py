from __future__ import annotations

from html import unescape

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence


class RedditAdapter:
    platforms = {"reddit"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        api_url = f"https://www.reddit.com/user/{username}/about.json"
        headers = {"User-Agent": "Argis/1.0 (by /u/argis_osint)"}
        try:
            resp = await client.get(api_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Reddit", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 429:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Reddit", "code": "RATE_LIMITED", "http_status": 429,
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Reddit", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Reddit", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        data = resp.json()
        redditor = data.get("data", {})
        name = redditor.get("name", "")
        if name.lower() != username.lower():
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Reddit", "code": "USERNAME_MISMATCH",
                "message": f"API returned name '{name}'",
            })
        icon = redditor.get("icon_img", "") or redditor.get("subreddit", {}).get("icon_img", "")
        if icon:
            icon = unescape(icon).split("?")[0]
        media = []
        if icon and "default" not in icon.lower():
            media.append(MediaEvidence(
                url=icon, classification="PROFILE_AVATAR", confidence=95,
                source="reddit_api.icon_img", validated=True,
            ))
        return AdapterResult(
            found=True, profile_url=f"https://www.reddit.com/user/{username}",
            display_name=redditor.get("subreddit", {}).get("title"),
            media=media,
        )
