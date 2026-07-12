from __future__ import annotations

import re
from urllib.parse import urlparse

from argis.models import ProfileEvidence

_PLATFORM_PATTERNS: dict[str, list[re.Pattern]] = {}
_PROFILE_URL_PATTERNS: dict[str, str] = {}


def _compile_patterns():
    if _PLATFORM_PATTERNS:
        return
    entries = [
        ("github", r"github\.com", "https://github.com/{}"),
        ("gist", r"gist\.github\.com", "https://gist.github.com/{}"),
        ("instagram", r"(?:www\.)?instagram\.com", "https://www.instagram.com/{}/"),
        ("reddit", r"(?:www\.)?reddit\.com", "https://www.reddit.com/user/{}"),
        ("youtube", r"(?:www\.)?youtube\.com", "https://www.youtube.com/@{}"),
        ("twitter", r"(?:www\.)?(?:twitter|x)\.com", "https://twitter.com/{}"),
        ("tiktok", r"(?:www\.)?tiktok\.com", "https://www.tiktok.com/@{}"),
        ("soundcloud", r"(?:www\.)?soundcloud\.com", "https://soundcloud.com/{}"),
        ("steam", r"steamcommunity\.com", "https://steamcommunity.com/id/{}"),
        ("snapchat", r"(?:www\.)?snapchat\.com", "https://www.snapchat.com/add/{}"),
        ("discord", r"(?:www\.)?discord(?:app)?\.com", "https://discord.com/users/{}"),
        ("twitch", r"(?:www\.)?twitch\.tv", "https://www.twitch.tv/{}"),
        ("threads", r"(?:www\.)?threads\.net", "https://www.threads.net/@{}"),
        ("mastodon", r"(?:www\.)?([a-z0-9-]+\.(?:social|online|world|space|cloud|xyz|app))", None),
    ]
    for platform, domain_re, url_template in entries:
        _PLATFORM_PATTERNS[platform] = [re.compile(domain_re, re.I)]
        if url_template is not None:
            _PROFILE_URL_PATTERNS[platform] = url_template


def detect_platform(url: str) -> str | None:
    _compile_patterns()
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    for platform, patterns in _PLATFORM_PATTERNS.items():
        for pat in patterns:
            if pat.search(hostname):
                return platform
    return None


def extract_username(url: str, platform: str | None = None) -> str | None:
    _compile_patterns()
    if platform is None:
        platform = detect_platform(url)
    if platform is None:
        return None
    path = urlparse(url).path.strip("/")
    if platform in ("threads", "tiktok", "instagram", "youtube", "twitter"):
        return path.split("/")[0].lstrip("@")
    if platform == "reddit":
        parts = path.split("/")
        if "user" in parts:
            idx = parts.index("user")
            return parts[idx + 1] if idx + 1 < len(parts) else parts[0]
        return parts[0] if parts else None
    if platform in ("github", "soundcloud"):
        return path.split("/")[0]
    if platform == "steam":
        parts = path.split("/")
        for i, p in enumerate(parts):
            if p in ("id", "profiles") and i + 1 < len(parts):
                return parts[i + 1]
        return None
    if platform in ("snapchat",):
        parts = path.split("/")
        if "add" in path:
            idx = parts.index("add")
            return parts[idx + 1] if idx + 1 < len(parts) else None
        return parts[0] if parts else None
    if platform in ("mastodon",):
        parts = path.split("/")
        return parts[0].lstrip("@") if parts else None
    if platform in ("discord",):
        parts = path.split("/")
        return parts[-1] if parts else None
    if platform in ("twitch",):
        return path.split("/")[0]
    return path.split("/")[0] if path else None


def profile_url_for(platform: str, username: str) -> str | None:
    _compile_patterns()
    template = _PROFILE_URL_PATTERNS.get(platform)
    if template:
        try:
            return template.format(username)
        except (IndexError, KeyError):
            pass
    return None
