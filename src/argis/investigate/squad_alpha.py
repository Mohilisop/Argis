"""Squad Alpha - Core Identity (Agents 1-10) - Real identity scanning"""

import asyncio
import re
from argis.investigate.base import BaseAgent, AgentContext, FindingCategory
from argis.utils.extract_utils import clean_display_name, clean_emails, visible_html
from argis.geo_infer import infer_geo

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class Agent001_IdentityAggregator(BaseAgent):
    def __init__(self):
        super().__init__(1, "IdentityAggregator", FindingCategory.IDENTITY,
                         "Run full platform scan and build unified identity profile")

    async def _run(self, ctx: AgentContext) -> None:
        profile = ctx.shared_data.get("unified_profile", {})
        results = ctx.shared_data.get("scan_results", {})
        found_plats = ctx.shared_data.get("found_platforms", [])
        clean = ctx.shared_data.get("discovered_emails", [])
        dork = ctx.shared_data.get("dork_findings", [])
        correlation = ctx.shared_data.get("correlation_findings", [])

        evidence = [f"Found on {p}: {results.get(p, {}).get('url', '')}" for p in found_plats[:15]]
        if dork:
            evidence.append(f"Dork coverage: {len(dork)} surface exposure signals")
        if correlation:
            evidence.append(f"Correlation: {len(correlation)} cross-username matches")
        total = ctx.shared_data.get("scan_total_count", 0)
        conf = min(0.95, 0.3 + len(found_plats) * 0.01 + (0.05 if dork else 0) + (0.05 if correlation else 0))
        self._emit(ctx, f"Identity profile: {len(found_plats)} platforms found",
                   f"Scanned {total} platforms, found {len(found_plats)} accounts, "
                   f"{len(clean)} emails discovered",
                   conf,
                   evidence=evidence, urls=[results.get(p, {}).get("url", "") for p in found_plats[:10]])


class Agent002_UsernameCrossReferencer(BaseAgent):
    def __init__(self):
        super().__init__(2, "UsernameCrossReferencer", FindingCategory.IDENTITY,
                         "Cross-reference username across all discovered platforms")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        dork = ctx.shared_data.get("dork_findings", [])
        correlation = ctx.shared_data.get("correlation_findings", [])
        if not found:
            self._emit(ctx, "Username cross-reference", "No platforms scanned yet", 0.1)
            return

        by_category: dict[str, list[str]] = {}
        for p in found:
            cat = results[p].get("category", "uncategorized")
            by_category.setdefault(cat, []).append(p)

        ctx.shared_data["platforms_by_category"] = by_category
        total_cats = len(by_category)
        evidence = [f"{cat}: {len(plats)} platforms" for cat, plats in sorted(by_category.items())]

        conf = min(0.95, 0.4 + len(found) * 0.003)
        if correlation:
            evidence.append(f"Correlation found: {len(correlation)} cross-username matches")
            conf = min(conf + 0.05, 0.95)
        if dork:
            evidence.append(f"Dork coverage: {len(dork)} surface exposure signals")
            conf = min(conf + 0.03, 0.95)

        self._emit(ctx, f"Username active on {len(found)} platforms across {total_cats} categories",
                    f"Categories: {', '.join(sorted(by_category.keys()))}",
                    conf, evidence=evidence)


class Agent003_NameResolver(BaseAgent):
    def __init__(self):
        super().__init__(3, "NameResolver", FindingCategory.IDENTITY,
                         "Extract real names from platform profiles")

    async def _run(self, ctx: AgentContext) -> None:
        titles = ctx.shared_data.get("profile_titles", [])
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})

        name_candidates = set()
        for t in titles:
            if t and len(t) < 80 and not t.startswith("http"):
                cleaned = re.sub(r'\s+', ' ', t).strip()
                if cleaned and cleaned.lower() != ctx.target.username.lower():
                    name_candidates.add(cleaned)

        for p in found:
            r = results.get(p, {})
            desc = r.get("description", "") or ""
            display = clean_display_name(desc[:100], p, ctx.target.username)
            if display and display.lower() != ctx.target.username.lower():
                name_candidates.add(display)

        ctx.shared_data["real_names"] = list(name_candidates)
        if name_candidates:
            top = list(name_candidates)[:5]
            self._emit(ctx, f"Potential real names: {' | '.join(top)}",
                       f"Extracted from {len(name_candidates)} profile name signals across platforms",
                       0.5 + min(0.4, len(name_candidates) * 0.05),
                       evidence=[f"Platform signal: {n}" for n in top])
        else:
            self._emit(ctx, "Real name resolution",
                       "No display names found across discovered platforms",
                       0.1)


class Agent004_EmailDiscovery(BaseAgent):
    def __init__(self):
        super().__init__(4, "EmailDiscovery", FindingCategory.IDENTITY,
                         "Discover emails from scan results and pattern generation")

    async def _run(self, ctx: AgentContext) -> None:
        discovered = ctx.shared_data.get("discovered_emails", [])
        known = ctx.target.known_emails
        all_emails = set(known) | set(discovered)

        dork = ctx.shared_data.get("dork_findings", [])
        dork_urls = []
        for dk in dork:
            for url in dk.get("evidence", []):
                if url and url not in dork_urls:
                    dork_urls.append(url)
            if len(dork_urls) >= 5:
                break

        for d in ["gmail.com", "outlook.com", "protonmail.com", "yahoo.com", "icloud.com"]:
            candidate = f"{ctx.target.username}@{d}"
            all_emails.add(candidate)

        for alias in ctx.target.aliases:
            for d in ["gmail.com", "protonmail.com"]:
                all_emails.add(f"{alias}@{d}")

        if dork_urls:
            for url in dork_urls[:10]:
                status, text, _ = await self._fetch(ctx, url, timeout=8.0)
                if status == 200 and text:
                    from argis.utils.extract_utils import clean_emails as _clean
                    found = _clean(_EMAIL_RE.findall(text))
                    for e in found:
                        all_emails.add(e)

        ctx.shared_data["all_email_candidates"] = list(all_emails)
        real = discovered or []
        conf = 0.85
        if dork_urls:
            conf = min(conf + 0.05, 0.95)
        if real:
            self._emit(ctx, f"{len(real)} emails discovered from platform scans",
                        f"Emails: {', '.join(real[:5])}{'...' if len(real) > 5 else ''}",
                        conf, evidence=[f"Email: {e}" for e in real])
        else:
            self._emit(ctx, f"Generated {len(all_emails)} email candidates",
                        f"Based on username + aliases across common domains",
                        0.35, evidence=[f"Candidate: {e}" for e in list(all_emails)[:8]])


class Agent005_PhoneMapper(BaseAgent):
    def __init__(self):
        super().__init__(5, "PhoneMapper", FindingCategory.IDENTITY,
                         "Search for phone numbers in profile data")

    async def _run(self, ctx: AgentContext) -> None:
        descs = ctx.shared_data.get("profile_descriptions", [])
        phone_pattern = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
        phones = set()
        for d in descs:
            matches = phone_pattern.findall(d or "")
            for m in matches:
                if m.strip():
                    phones.add(m.strip())
        if phones:
            self._emit(ctx, f"Found {len(phones)} phone number patterns",
                       f"Phone numbers extracted from profile descriptions",
                       0.4, evidence=list(phones))
        else:
            self._emit(ctx, "Phone number search",
                       "No phone numbers found in public profile data. Phone data typically requires private sources.",
                       0.1)


class Agent006_LocationPinner(BaseAgent):
    def __init__(self):
        super().__init__(6, "LocationPinner", FindingCategory.IDENTITY,
                         "Triangulate geographic locations from profile signals")

    async def _run(self, ctx: AgentContext) -> None:
        bios = ctx.shared_data.get("profile_descriptions", [])
        titles = ctx.shared_data.get("profile_titles", [])
        found = ctx.shared_data.get("found_platforms", [])
        geo_signals = infer_geo(bios, titles, found)
        ctx.shared_data["geo_signals"] = geo_signals

        if geo_signals:
            best = geo_signals[0]
            evidence = [f"{s.country} (confidence: {s.confidence:.0%})" for s in geo_signals]
            self._emit(ctx, f"Location inferred: {best.country}",
                       f"Top signal: {best.evidence} — {len(geo_signals)} location indicators total",
                       best.confidence, evidence=evidence)
        else:
            self._emit(ctx, "Geolocation analysis",
                       "No location signals found in profile data. Run recon with an IP address for geo-IP lookup.",
                       0.1)


class Agent007_AgeEstimator(BaseAgent):
    def __init__(self):
        super().__init__(7, "AgeEstimator", FindingCategory.IDENTITY,
                         "Estimate age range from profile data")

    async def _run(self, ctx: AgentContext) -> None:
        titles = ctx.shared_data.get("profile_titles", [])
        descs = ctx.shared_data.get("profile_descriptions", [])
        all_text = " ".join(titles + descs).lower()
        age_hints = []

        for pattern, label in [(r'\b(\d{2})\s*years?\s*old\b', "explicit_age"),
                                (r'\b(?:born|b\.)\s*(\d{4})\b', "birth_year"),
                                (r'\bclass\s*of\s*(\d{4})\b', "graduation_year")]:
            m = re.search(pattern, all_text)
            if m:
                age_hints.append(f"{label}: {m.group(0)}")

        year_patterns = re.findall(r'\b(19[4-9]\d|20[0-2]\d)\b', all_text)
        if year_patterns:
            years = sorted(set(year_patterns))
            age_hints.append(f"mentioned_years: {', '.join(years[:5])}")

        if age_hints:
            self._emit(ctx, f"Age indicators: {len(age_hints)} hints found",
                       "; ".join(age_hints[:5]),
                       0.45, evidence=age_hints)
        else:
            self._emit(ctx, "Age estimation",
                       "No age signals found in profile data. Requires biographical info or platform-specific age fields.",
                       0.1)


class Agent008_GenderAnalyzer(BaseAgent):
    def __init__(self):
        super().__init__(8, "GenderAnalyzer", FindingCategory.IDENTITY,
                         "Analyze gender indicators from profile data")

    async def _run(self, ctx: AgentContext) -> None:
        all_text = " ".join(ctx.shared_data.get("profile_titles", []) +
                            ctx.shared_data.get("profile_descriptions", []))
        pronouns = re.findall(r'\b(he/him|she/her|they/them|him|her|his|hers)\b', all_text.lower())
        unique = list(set(pronouns))
        if unique:
            self._emit(ctx, f"Pronoun indicators: {', '.join(unique)}",
                       "Gender indicators found in profile bios",
                       0.6, evidence=[f"Pronoun: {p}" for p in unique])
        else:
            self._emit(ctx, "Gender analysis",
                       "No explicit gender indicators in profile data. Requires pronoun fields or name-based inference.",
                       0.1)


class Agent009_LanguageDetector(BaseAgent):
    def __init__(self):
        super().__init__(9, "LanguageDetector", FindingCategory.IDENTITY,
                         "Detect languages from profile content")

    async def _run(self, ctx: AgentContext) -> None:
        all_text = " ".join(ctx.shared_data.get("profile_titles", []) +
                            ctx.shared_data.get("profile_descriptions", []))
        lang_hints = []
        unicode_ranges = {
            "Cyrillic": (r'[\u0400-\u04FF]', "ru"),
            "Arabic": (r'[\u0600-\u06FF]', "ar"),
            "CJK": (r'[\u4E00-\u9FFF]', "zh"),
            "Devanagari": (r'[\u0900-\u097F]', "hi"),
            "Korean": (r'[\uAC00-\uD7AF]', "ko"),
            "Japanese": (r'[\u3040-\u309F\u30A0-\u30FF]', "ja"),
        }
        for name, (pattern, code) in unicode_ranges.items():
            if re.search(pattern, all_text):
                lang_hints.append(f"{name} ({code})")

        western_keywords = re.findall(r'\b(the|a|an|is|are|was|were|have|has|this|that)\b', all_text.lower())
        if len(western_keywords) > 3:
            lang_hints.append("English (en)")

        ctx.shared_data["language_hints"] = lang_hints
        if lang_hints:
            self._emit(ctx, f"Language indicators: {', '.join(lang_hints)}",
                       f"Detected {len(lang_hints)} language signals from profile content",
                       0.5, evidence=lang_hints)
        else:
            self._emit(ctx, "Language detection",
                       "Insufficient text content for language detection",
                       0.1)


class Agent010_TimeZoneProfiler(BaseAgent):
    def __init__(self):
        super().__init__(10, "TimeZoneProfiler", FindingCategory.IDENTITY,
                         "Infer timezone from geographic signals")

    async def _run(self, ctx: AgentContext) -> None:
        geo = ctx.shared_data.get("geo_signals", [])
        tz_zones = {
            "US": "America/New_York", "GB": "Europe/London", "DE": "Europe/Berlin",
            "FR": "Europe/Paris", "IN": "Asia/Kolkata", "JP": "Asia/Tokyo",
            "AU": "Australia/Sydney", "BR": "America/Sao_Paulo", "CA": "America/Toronto",
            "RU": "Europe/Moscow", "CN": "Asia/Shanghai", "KR": "Asia/Seoul",
        }
        hints = []
        for g in geo:
            if g.country in tz_zones:
                hints.append(tz_zones[g.country])
        if hints:
            self._emit(ctx, f"Timezone inferred: {hints[0]}",
                       f"Based on geographic signals: {', '.join(set(hints))}",
                       0.5, evidence=hints)
        else:
            self._emit(ctx, "Timezone analysis",
                       "No timezone data available. Geographic signals needed for timezone inference.",
                       0.1)


class AlphaSquad:
    def __init__(self):
        self.agents = [cls() for cls in [
            Agent001_IdentityAggregator, Agent002_UsernameCrossReferencer,
            Agent003_NameResolver, Agent004_EmailDiscovery, Agent005_PhoneMapper,
            Agent006_LocationPinner, Agent007_AgeEstimator, Agent008_GenderAnalyzer,
            Agent009_LanguageDetector,
            Agent010_TimeZoneProfiler,
        ]]

    async def run_all(self, ctx: AgentContext) -> None:
        await asyncio.gather(*[a.investigate(ctx) for a in self.agents])