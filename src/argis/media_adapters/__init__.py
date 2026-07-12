from argis.media_adapters.github import GitHubAdapter
from argis.media_adapters.instagram import InstagramAdapter
from argis.media_adapters.reddit import RedditAdapter
from argis.media_adapters.youtube import YouTubeAdapter
from argis.media_adapters.soundcloud import SoundCloudAdapter
from argis.media_adapters.steam import SteamAdapter
from argis.media_adapters.tiktok import TikTokAdapter
from argis.media_adapters.twitter import TwitterAdapter
from argis.media_adapters.snapchat import SnapchatAdapter
from argis.media_adapters.discord import DiscordAdapter
from argis.media_adapters.activitypub import ActivityPubAdapter
from argis.media_adapters.twitch import TwitchAdapter
from argis.media_adapters.mastodon import MastodonAdapter

_ADAPTERS: list = []


def registered_adapters() -> list:
    global _ADAPTERS
    if not _ADAPTERS:
        _ADAPTERS = [
            GitHubAdapter(), InstagramAdapter(), RedditAdapter(),
            YouTubeAdapter(), SoundCloudAdapter(), SteamAdapter(),
            TikTokAdapter(), TwitterAdapter(), SnapchatAdapter(),
            DiscordAdapter(), ActivityPubAdapter(), TwitchAdapter(),
            MastodonAdapter(),
        ]
    return _ADAPTERS


def adapter_for_platform(platform: str):
    plat = platform.lower().strip()
    for a in registered_adapters():
        if plat in {p.lower() for p in a.platforms}:
            return a
    return None
