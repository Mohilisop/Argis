from __future__ import annotations

from argis.media_adapters.activitypub import ActivityPubAdapter
from argis.media_adapters.base import AdapterResult


class MastodonAdapter:
    platforms = {"mastodon"}

    async def resolve(self, client, username: str, profile_url: str) -> AdapterResult:
        return await ActivityPubAdapter().resolve(client, username, profile_url)
