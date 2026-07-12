from __future__ import annotations

import json
import re

from argis.media_adapters.base import AdapterResult
from argis.models import MediaEvidence

_YT_INITIAL = re.compile(r"ytInitialData\s*=\s*(\{.*?\});", re.DOTALL)
_JSONLD = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S)


class YouTubeAdapter:
    platforms = {"youtube", "youtube music"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            resp = await client.get(profile_url, headers=headers, follow_redirects=True)
        except Exception as exc:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "YouTube", "code": "HTTP_ERROR", "message": str(exc),
            })
        if resp.status == 404:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "YouTube", "code": "ACCOUNT_NOT_FOUND", "http_status": 404,
            })
        if resp.status != 200:
            return AdapterResult(found=False, profile_url=profile_url, diagnostic={
                "platform": "YouTube", "code": "HTTP_ERROR", "http_status": resp.status,
            })
        text = resp.text

        for m in _JSONLD.finditer(text):
            try:
                ld = json.loads(m.group(1))
                if isinstance(ld, dict):
                    image = ld.get("image", "")
                    if isinstance(image, dict):
                        image = image.get("url", "")
                    if isinstance(image, str) and image:
                        return AdapterResult(found=True, profile_url=profile_url, media=[
                            MediaEvidence(url=image, classification="PROFILE_AVATAR",
                                          confidence=95, source="youtube.jsonld", validated=True),
                        ])
            except Exception:
                pass

        m = _YT_INITIAL.search(text)
        if m:
            try:
                data = json.loads(m.group(1))
                tabs = (
                    data.get("contents", {}).get("twoColumnBrowseResultsRenderer", {})
                    .get("tabs", [])
                )
                for tab in tabs:
                    section = (
                        tab.get("tabRenderer", {}).get("content", {})
                        .get("sectionListRenderer", {}).get("contents", [])
                    )
                    for item in section:
                        shelf = item.get("itemSectionRenderer", {}).get("contents", [])
                        for entry in shelf:
                            channel = entry.get("channelFeaturedContentRenderer", {})
                            avatar = channel.get("avatar", {}).get("thumbnails", [])
                            if avatar:
                                url = avatar[-1].get("url", "")
                                if url:
                                    return AdapterResult(found=True, profile_url=profile_url, media=[
                                        MediaEvidence(url=url, classification="PROFILE_AVATAR",
                                                      confidence=92, source="youtube.initial_data",
                                                      validated=True),
                                    ])
            except Exception:
                pass

        return AdapterResult(found=True, profile_url=profile_url, diagnostic={
            "platform": "YouTube", "code": "NO_PUBLIC_MEDIA",
            "message": "Channel page loaded but no avatar found in structured data",
        })
