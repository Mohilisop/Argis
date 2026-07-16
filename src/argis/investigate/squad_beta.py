"""Squad Beta - Social Intelligence (Agents 11-20) - Real social profile analysis"""

import asyncio
import re
from argis.investigate.base import BaseAgent, AgentContext, FindingCategory
from argis.utils.wayback import check_wayback
from argis.extract import extract_labels


class Agent011_SocialGraphMapper(BaseAgent):
    def __init__(self):
        super().__init__(11, "SocialGraphMapper", FindingCategory.SOCIAL,
                         "Map social platform presence from scan results")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        by_cat = ctx.shared_data.get("platforms_by_category", {})
        social_plats = by_cat.get("social", []) + by_cat.get("media", [])

        ctx.shared_data["social_platforms"] = social_plats
        if social_plats:
            self._emit(ctx, f"Active on {len(social_plats)} social/media platforms",
                       f"Social platforms: {', '.join(social_plats[:10])}",
                       min(0.85, 0.3 + len(social_plats) * 0.02),
                       evidence=[f"Social: {p}" for p in social_plats[:15]])
        else:
            self._emit(ctx, "Social graph", "No social platform accounts found", 0.1)


class Agent012_ContentAnalyzer(BaseAgent):
    def __init__(self):
        super().__init__(12, "ContentAnalyzer", FindingCategory.SOCIAL,
                         "Fetch and analyze profile pages for interests and patterns")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        interest_keywords = {
            "tech": "technology", "security": "infosec", "photo": "photography",
            "music": "music", "game": "gaming", "travel": "travel",
            "fit": "fitness", "food": "cooking", "art": "art_design",
            "code": "programming", "data": "data_science", "write": "writing",
            "dev": "development", "crypto": "cryptocurrency", "ai": "artificial_intelligence",
        }
        interests = set()
        for p in found:
            r = results.get(p, {})
            t = (r.get("title") or "").lower()
            d = (r.get("description") or "").lower()
            combined = f"{p.lower()} {t} {d}"
            for kw, category in interest_keywords.items():
                if kw in combined:
                    interests.add(category)

        interest_list = sorted(interests)
        ctx.shared_data["detected_interests"] = interest_list
        if interest_list:
            self._emit(ctx, f"Interests detected: {', '.join(interest_list[:8])}",
                       f"Derived from {len(found)} platform profiles",
                       0.6, evidence=[f"Interest area: {i}" for i in interest_list])
        else:
            uname = ctx.target.username.lower()
            for kw, category in interest_keywords.items():
                if kw in uname:
                    interests.add(category)
            interest_list = sorted(interests)
            if interest_list:
                self._emit(ctx, f"Interests inferred from username: {', '.join(interest_list)}",
                           f"Based on username keyword analysis: {len(interest_list)} areas",
                           0.3, evidence=[f"Interest: {i}" for i in interest_list])
            else:
                self._emit(ctx, "Content analysis", "Insufficient content for interest detection", 0.1)


class Agent013_EngagementProfiler(BaseAgent):
    def __init__(self):
        super().__init__(13, "EngagementProfiler", FindingCategory.SOCIAL,
                         "Analyze profile engagement from platform metadata")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        totals = {"followers": 0, "following": 0, "posts": 0, "repos": 0}
        for p in found:
            r = results.get(p, {})
            desc = (r.get("description") or "").lower()
            for metric in totals:
                nums = re.findall(rf'{metric}[:\s]+(\d{{1,7}})', desc)
                if nums:
                    totals[metric] += int(nums[-1])
        active = sum(1 for v in totals.values() if v > 0)
        if active > 0:
            summary = ", ".join(f"{k}: {v}" for k, v in totals.items() if v > 0)
            self._emit(ctx, f"Engagement metrics: {summary}",
                       f"Extracted from {active} platform profile descriptions",
                       0.5, evidence=[f"{k}: {v}" for k, v in totals.items() if v > 0])
        else:
            self._emit(ctx, "Engagement profiling",
                       "No engagement metrics found. Requires deep profile scraping.",
                       0.1)


class Agent014_TimestampCorrelator(BaseAgent):
    def __init__(self):
        super().__init__(14, "TimestampCorrelator", FindingCategory.SOCIAL,
                         "Correlate activity timestamps across platforms")

    async def _run(self, ctx: AgentContext) -> None:
        self._emit(ctx, "Activity timestamp analysis",
                   "Timestamp correlation requires commit history or post dates from platform APIs. "
                   "Historical data analysis available via `argis echo` command.",
                   0.15, evidence=["Use `argis echo <username>` for drift tracking across time"])


class Agent015_MediaExtractor(BaseAgent):
    def __init__(self):
        super().__init__(15, "MediaExtractor", FindingCategory.SOCIAL,
                         "Extract profile avatars and media metadata")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        avatars = []
        for p in found[:15]:
            r = results.get(p, {})
            if r.get("avatar_url"):
                avatars.append({"platform": p, "url": r["avatar_url"]})
        if avatars:
            self._emit(ctx, f"Found {len(avatars)} profile avatars",
                       "Profile images discovered across platforms",
                       0.55, evidence=[f"{a['platform']}: {a['url']}" for a in avatars])
        else:
            self._emit(ctx, "Media extraction",
                       "Profile images require deep scraping. Enable `--dossier` for media capture.",
                       0.1, evidence=["Use `argis scan <user> --dossier` for media"])


class Agent016_HashtagTracker(BaseAgent):
    def __init__(self):
        super().__init__(16, "HashtagTracker", FindingCategory.SOCIAL,
                         "Derive topic hashtags from interests and platforms")

    async def _run(self, ctx: AgentContext) -> None:
        interests = ctx.shared_data.get("detected_interests", [])
        found = ctx.shared_data.get("found_platforms", [])
        topics = set(interests)
        platform_topics = {
            "github": "tech", "stackoverflow": "programming", "medium": "writing",
            "dev.to": "programming", "soundcloud": "music", "spotify": "music",
            "steam": "gaming", "twitch": "gaming", "instagram": "photography",
            "flickr": "photography", "strava": "fitness", "goodreads": "reading",
        }
        for p in found:
            if p.lower() in platform_topics:
                topics.add(platform_topics[p.lower()])

        hashtags = [f"#{t.replace('_', '')}" for t in topics]
        ctx.shared_data["derived_hashtags"] = hashtags
        if hashtags:
            self._emit(ctx, f"Topic hashtags: {' '.join(hashtags[:10])}",
                       f"Derived from {len(interests)} interests + {len(found)} platforms",
                       0.55, evidence=hashtags)


class Agent017_PlatformMigration(BaseAgent):
    def __init__(self):
        super().__init__(17, "PlatformMigration", FindingCategory.SOCIAL,
                         "Detect platform migration patterns")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        overlaps = {
            "twitter": "x", "medium": "substack", "instagram": "threads",
            "youtube": "odysee", "reddit": "lemmy", "twitch": "trovo",
        }
        migrations = []
        for old, new in overlaps.items():
            if old in found and new in found:
                migrations.append(f"{old} -> {new}")
        if migrations:
            self._emit(ctx, f"Detected {len(migrations)} potential platform migrations",
                       "; ".join(migrations),
                       0.5, evidence=migrations)
        elif any(p in found for p in overlaps.keys()):
            self._emit(ctx, "Platform migration check",
                       "Single-platform presence detected. No migration signals found.",
                       0.2)
        else:
            self._emit(ctx, "Platform migration check",
                       "No overlapping platform pairs found for migration detection.",
                       0.1)


class Agent018_InfluencerTracer(BaseAgent):
    def __init__(self):
        super().__init__(18, "InfluencerTracer", FindingCategory.SOCIAL,
                         "Assess influence potential from platform activity")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        influence_signals = 0
        major_platforms = ["youtube", "instagram", "twitter", "tiktok", "linkedin", "github", "medium"]
        for p in found:
            if p.lower() in major_platforms:
                influence_signals += 1
            if results.get(p, {}).get("status") == "FOUND":
                influence_signals += 1

        if influence_signals > 5:
            level = "HIGH"
            conf = 0.7
        elif influence_signals > 3:
            level = "MEDIUM"
            conf = 0.5
        else:
            level = "LOW"
            conf = 0.3
        self._emit(ctx, f"Influence potential: {level}",
                   f"Signals: {influence_signals} — {len(found)} platforms found",
                   conf, evidence=[f"Signal strength: {influence_signals}/10"])


class Agent019_DeletedContentRecovery(BaseAgent):
    def __init__(self):
        super().__init__(19, "DeletedContentRecovery", FindingCategory.SOCIAL,
                         "Find cached/deleted content via Wayback Machine")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        target_urls = []
        for p in found[:5]:
            url = results.get(p, {}).get("url", "")
            if url:
                target_urls.append(url)
        target_urls.append(f"https://{ctx.target.username}.com")

        snapshots = []
        for url in target_urls:
            try:
                result = await check_wayback(ctx.target.username, limit=3)
                if result.snapshots:
                    for s in result.snapshots[:2]:
                        snapshots.append(f"{s.timestamp}: {s.url}")
            except Exception:
                pass

        if snapshots:
            ctx.shared_data["wayback_snapshots"] = snapshots
            self._emit(ctx, f"Found {len(snapshots)} cached/historical snapshots",
                       "Wayback Machine snapshots available for content recovery",
                       0.7, evidence=snapshots)
        else:
            self._emit(ctx, "Deleted content recovery",
                       "Wayback Machine check completed. No historical snapshots found for this handle.",
                       0.2)


class Agent020_SocialCircleAnalyzer(BaseAgent):
    def __init__(self):
        super().__init__(20, "SocialCircleAnalyzer", FindingCategory.SOCIAL,
                         "Analyze social connections from platform data")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        connection_hints = []
        for p in found:
            r = results.get(p, {})
            desc = (r.get("description") or "").lower()
            members = re.findall(r'(?:member|team|org|company|group)[:\s]+([\w\s]+)', desc)
            if members:
                connection_hints.extend(members[:3])

        ctx.shared_data["connection_hints"] = connection_hints
        if connection_hints:
            self._emit(ctx, f"Connection hints: {', '.join(connection_hints[:5])}",
                       f"Organizational/team references found in {len(connection_hints)} profiles",
                       0.4, evidence=connection_hints)
        else:
            self._emit(ctx, "Social circle analysis",
                       "Connection mapping requires mutual follower data. Not available from basic scans.",
                       0.1)


class BetaSquad:
    def __init__(self):
        self.agents = [cls() for cls in [
            Agent011_SocialGraphMapper, Agent012_ContentAnalyzer,
            Agent013_EngagementProfiler, Agent014_TimestampCorrelator,
            Agent015_MediaExtractor, Agent016_HashtagTracker,
            Agent017_PlatformMigration, Agent018_InfluencerTracer,
            Agent019_DeletedContentRecovery, Agent020_SocialCircleAnalyzer,
        ]]

    async def run_all(self, ctx: AgentContext) -> None:
        await asyncio.gather(*[a.investigate(ctx) for a in self.agents])