from __future__ import annotations

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence


class GitHubAdapter:
    platforms = {"github", "gist", "github sponsors"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        api_url = f"https://api.github.com/users/{username}"
        try:
            resp = await client.get(api_url, headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "Argis"})
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "GitHub", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 403:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "GitHub", "code": "RATE_LIMITED", "http_status": 403,
                "message": "GitHub API rate limit exceeded",
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "GitHub", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
                "message": "GitHub user not found",
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "GitHub", "code": "HTTP_ERROR", "http_status": resp.status,
                "message": f"GitHub API returned {resp.status}",
            })
        data = resp.json()
        api_login = data.get("login", "")
        if api_login.lower() != username.lower():
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "GitHub", "code": "USERNAME_MISMATCH",
                "message": f"API returned login '{api_login}' instead of '{username}'",
            })
        avatar = data.get("avatar_url", "")
        media_list = []
        if avatar:
            media_list.append(MediaEvidence(
                url=avatar, classification="PROFILE_AVATAR", confidence=100,
                source="github_api.avatar_url", validated=True,
            ))
        return AdapterResult(
            found=True, profile_url=data.get("html_url", profile_url),
            display_name=data.get("name"), bio=data.get("bio"),
            media=media_list,
        )
