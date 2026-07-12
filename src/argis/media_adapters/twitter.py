from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_NEXT_DATA = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)


class TwitterAdapter:
    platforms = {"twitter", "x.com", "x"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,*/*;q=0.9",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitter", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitter", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitter", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text
        if "this account doesn" in text.lower() or "account suspended" in text.lower():
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "Twitter", "code": "ACCOUNT_NOT_FOUND",
                "message": "Account suspended or does not exist",
            })
        m = _NEXT_DATA.search(text)
        if m:
            try:
                data = json.loads(m.group(1))
                props = data.get("props", {}).get("pageProps", {})
                user_result = (
                    props.get("user", {}) or
                    props.get("userData", {}) or
                    props.get("data", {}).get("userResult", {}).get("result", {}) or
                    {}
                )
                legacy = user_result.get("legacy", {}) or user_result.get("user", {}).get("legacy", {})
                screen_name = legacy.get("screen_name", "").lower()
                if screen_name and screen_name != username.lower():
                    return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                        "platform": "Twitter", "code": "USERNAME_MISMATCH",
                        "message": f"Page returned screen_name '{screen_name}'",
                    })
                avatar = (legacy.get("profile_image_url_https", "").replace("_normal.", "_400x400.")
                          if legacy.get("profile_image_url_https") else "")
                if avatar and "default_profile" not in str(legacy):
                    return AdapterResult(found=True, profile_url=profile_url, media=[
                        MediaEvidence(url=avatar, classification="PROFILE_AVATAR",
                                      confidence=98, source="twitter.next_data",
                                      validated=True),
                    ])
            except Exception:
                pass
        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "Twitter", "code": "NO_PUBLIC_MEDIA",
        })
