"""Squad Epsilon - Specialists (Agents 41-50) - Expert analysis and scoring"""

import asyncio
import re
from argis.investigate.base import BaseAgent, AgentContext, FindingCategory
from argis.exposure import assess as exposure_assess
from argis.geo_infer import infer_geo
from argis.utils.geoip import geoip_lookup


class Agent041_CryptocurrencyTracer(BaseAgent):
    def __init__(self):
        super().__init__(41, "CryptocurrencyTracer", FindingCategory.SPECIALIST,
                         "Check for crypto wallet addresses in profile data")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        all_text = ""
        for p in found:
            r = results.get(p, {})
            all_text += f"{r.get('title', '')} {r.get('description', '')} {p} "

        btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
        wallets = []
        for m in btc_pattern.findall(all_text):
            wallets.append(f"BTC: {m}")
        for m in eth_pattern.findall(all_text):
            wallets.append(f"ETH: {m}")

        ctx.shared_data["crypto_wallets"] = wallets
        if wallets:
            self._emit(ctx, f"Found {len(wallets)} cryptocurrency wallet addresses",
                       "Wallet addresses detected in profile data",
                       0.6, evidence=wallets)
        else:
            self._emit(ctx, "Cryptocurrency tracing",
                       "No wallet addresses found in public profile data. Requires blockchain explorer queries.",
                       0.1)


class Agent042_GeolocationDeepDive(BaseAgent):
    def __init__(self):
        super().__init__(42, "GeolocationDeepDive", FindingCategory.SPECIALIST,
                         "Deep geolocation with IP-based lookups")

    async def _run(self, ctx: AgentContext) -> None:
        try:
            geo_signals = list(ctx.shared_data.get("geo_signals") or [])
            domain_info = list(ctx.shared_data.get("domain_info") or [])
        except Exception:
            geo_signals, domain_info = [], []
        try:
            all_ips = set()
            for d in domain_info:
                if not isinstance(d, dict):
                    continue
                dns = d.get("dns") or []
                for record in dns:
                    import re as _re
                    ip_match = _re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(record))
                    if ip_match:
                        all_ips.add(ip_match.group())
        except Exception:
            all_ips = set()

        ip_locations = []
        for ip in list(all_ips)[:3]:
            try:
                geo = await geoip_lookup(ip)
                if geo is not None:
                    city = getattr(geo, 'city', '') or ''
                    country = getattr(geo, 'country_name', '') or getattr(geo, 'country', '') or ''
                    err = getattr(geo, 'error', None)
                    if not err and (city or country):
                        ip_locations.append(f"{ip}: {city}, {country}")
            except Exception:
                pass

        combined = []
        try:
            for g in geo_signals:
                country = getattr(g, 'country', str(g)) if not isinstance(g, str) else g
                evidence = getattr(g, 'evidence', '') if not isinstance(g, str) else ''
                combined.append(f"Profile signal: {country} ({evidence})")
        except Exception:
            pass
        combined.extend(ip_locations)

        if combined:
            self._emit(ctx, f"Geolocation: {len(combined)} signals",
                       f"Profile-based + IP-based location signals",
                       0.5, evidence=combined)
        else:
            self._emit(ctx, "Geolocation deep dive",
                   "No IP addresses available for geo-IP lookup. Run domain recon for IP sources.",
                    0.1)


class Agent043_ImageForensics(BaseAgent):
    def __init__(self):
        super().__init__(43, "ImageForensics", FindingCategory.SPECIALIST,
                         "Analyze profile images for forensic signals")

    async def _run(self, ctx: AgentContext) -> None:
        avatars = []
        results = ctx.shared_data.get("scan_results", {})
        for p, r in results.items():
            if r.get("status") == "FOUND" and r.get("avatar_url"):
                avatars.append({"platform": p, "url": r["avatar_url"]})
        if avatars:
            self._emit(ctx, f"Found {len(avatars)} profile images for forensic analysis",
                       "Images available for reverse search. Use `argis scan-face` for automated reverse image search.",
                       0.4, evidence=[f"{a['platform']}: {a['url']}" for a in avatars[:8]])
        else:
            self._emit(ctx, "Image forensics",
                       "No profile images captured. Use `argis scan <user> --dossier` for media capture.",
                       0.1)


class Agent044_LinguisticProfiler(BaseAgent):
    def __init__(self):
        super().__init__(44, "LinguisticProfiler", FindingCategory.SPECIALIST,
                         "Analyze writing style from available text")

    async def _run(self, ctx: AgentContext) -> None:
        all_text = " ".join(ctx.shared_data.get("profile_descriptions", []) +
                            ctx.shared_data.get("profile_titles", []))
        if len(all_text) < 50:
            self._emit(ctx, "Linguistic profiling",
                       "Insufficient text for stylometric analysis. Need 200+ words from posts or comments.",
                       0.1)
            return

        word_count = len(all_text.split())
        sentences = re.split(r'[.!?]+', all_text)
        avg_sentence_len = word_count / max(len([s for s in sentences if s.strip()]), 1)
        caps_ratio = sum(1 for c in all_text if c.isupper()) / max(len(all_text), 1)
        num_ratio = sum(1 for c in all_text if c.isdigit()) / max(len(all_text), 1)

        profile = {
            "word_count": word_count,
            "avg_sentence_length": round(avg_sentence_len, 1),
            "uppercase_ratio": round(caps_ratio, 3),
            "numeric_ratio": round(num_ratio, 3),
        }
        ctx.shared_data["linguistic_profile"] = profile

        observations = []
        if avg_sentence_len > 20:
            observations.append("Long-form writing style (complex sentences)")
        elif avg_sentence_len > 12:
            observations.append("Moderate sentence length (balanced style)")
        else:
            observations.append("Short/concise writing style")
        if caps_ratio < 0.02:
            observations.append("Standard capitalization (minimal emphasis)")
        elif caps_ratio > 0.1:
            observations.append("High capitalization frequency (possible emphasis style)")

        self._emit(ctx, f"Linguistic profile: {observations[0]}",
                   f"Analysis based on {word_count} words. {observations[1] if len(observations) > 1 else ''}",
                   0.45, evidence=observations + [f"{k}: {v}" for k, v in profile.items()])


class Agent045_PsychologicalProfiler(BaseAgent):
    def __init__(self):
        super().__init__(45, "PsychologicalProfiler", FindingCategory.SPECIALIST,
                         "Personality trait inference from interests and activity")

    async def _run(self, ctx: AgentContext) -> None:
        interests = ctx.shared_data.get("detected_interests", [])
        skills = ctx.shared_data.get("detected_skills", [])
        platforms = ctx.shared_data.get("found_platforms", [])

        trait_map = {
            "technology": ["analytical", "systematic"], "programming": ["logical", "precise"],
            "security": ["vigilant", "meticulous"], "gaming": ["competitive", "strategic"],
            "music": ["creative", "sensitive"], "art": ["creative", "expressive"],
            "photography": ["observant", "aesthetic"], "fitness": ["disciplined", "goal_oriented"],
            "travel": ["curious", "adventurous"], "writing": ["introspective", "articulate"],
            "data_science": ["analytical", "curious"], "cryptocurrency": ["risk_tolerant", "innovative"],
        }

        traits = set()
        for i in interests:
            if i in trait_map:
                for t in trait_map[i]:
                    traits.add(t)

        platform_traits = {
            "github": "collaborative", "stackoverflow": "helpful", "medium": "thoughtful",
            "reddit": "community_driven", "linkedin": "professional", "twitter": "conversational",
            "instagram": "visual", "youtube": "educational",
        }
        for p in platforms:
            if p.lower() in platform_traits:
                traits.add(platform_traits[p.lower()])

        ctx.shared_data["personality_traits"] = sorted(traits)
        if traits:
            self._emit(ctx, f"Traits: {', '.join(sorted(traits)[:8])}",
                       f"Derived from {len(interests)} interests, {len(skills)} skills, {len(platforms)} platforms",
                       0.4, evidence=[f"Trait: {t}" for t in sorted(traits)])
        else:
            self._emit(ctx, "Psychological profiling",
                       "Insufficient data for trait inference. More content/interests needed.",
                       0.1)


class Agent046_ThreatAssessor(BaseAgent):
    def __init__(self):
        super().__init__(46, "ThreatAssessor", FindingCategory.SPECIALIST,
                         "Comprehensive threat and exposure assessment")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        emails = ctx.shared_data.get("discovered_emails", [])
        breach_data = ctx.shared_data.get("breach_reports", [])

        try:
            exposure = exposure_assess(ctx.target.username, results,
                                       emails=emails if emails else None)
            ctx.shared_data["exposure_report"] = exposure
            score = exposure.overall
            grade = exposure.grade or "N/A"

            risk_factors = []
            if breach_data:
                total_breaches = sum(len(r.breaches) for r in breach_data)
                if total_breaches > 0:
                    risk_factors.append(f"{total_breaches} data breaches detected")
            if score > 60:
                risk_factors.append(f"Exposure score: {score}/100 (grade {grade})")
            if len(found) > 50:
                risk_factors.append(f"Large digital footprint: {len(found)} platforms")

            risk_level = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"
            self._emit(ctx, f"Threat assessment: {risk_level} risk (grade {grade})",
                       f"Exposure score: {score}/100. {' | '.join(risk_factors[:5])}",
                       max(0.5, score / 100),
                       evidence=risk_factors if risk_factors else ["No significant risk factors detected"],
                       metadata={"exposure_score": score, "grade": grade, "risk_level": risk_level})
        except Exception as e:
            self._emit(ctx, "Threat assessment",
                       f"Exposure scoring: {e}", 0.2)


class Agent047_MisinformationDetector(BaseAgent):
    def __init__(self):
        super().__init__(47, "MisinformationDetector", FindingCategory.SPECIALIST,
                         "Analyze profile data for authenticity signals")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})

        red_flags = 0
        reasons = []
        for p in found[:20]:
            r = results.get(p, {})
            status = r.get("status", "")
            if status == "BLOCKED":
                red_flags += 1
                reasons.append(f"{p}: blocked/restricted access")

        all_text = " ".join(ctx.shared_data.get("profile_descriptions", []))
        spam_signals = ["buy followers", "click here", "free money", "crypto giveaway",
                        "limited offer", "act now"]
        for signal in spam_signals:
            if signal in all_text.lower():
                red_flags += 1
                reasons.append(f"Spam signal: '{signal}'")

        authenticity = "LOW" if red_flags > 3 else "MEDIUM" if red_flags > 1 else "HIGH"
        self._emit(ctx, f"Profile authenticity: {authenticity}",
                   f"Red flags detected: {red_flags}. {' '.join(reasons[:5])}" if reasons
                   else "No authenticity concerns detected across platforms",
                   0.4 if red_flags > 0 else 0.7,
                   evidence=reasons if reasons else ["No spam or bot signals detected"])


class Agent048_PoliticalAffiliationMapper(BaseAgent):
    def __init__(self):
        super().__init__(48, "PoliticalAffiliationMapper", FindingCategory.SPECIALIST,
                         "Map political leaning indicators from platform data")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])

        pol_keywords = {
            "democrat": "left", "republican": "right", "liberal": "left",
            "conservative": "right", "progressive": "left", "libertarian": "libertarian",
            "socialist": "left", "green": "left", "independent": "independent",
            "trump": "right", "biden": "left", "bernie": "left",
        }
        signals = []
        for p in found:
            desc = (results.get(p, {}).get("description") or "").lower()
            for kw, leaning in pol_keywords.items():
                if kw in desc:
                    signals.append(f"{p}: {kw} -> {leaning}")

        ctx.shared_data["political_signals"] = signals
        if signals:
            leanings = [s.split("->")[-1].strip() for s in signals]
            from collections import Counter
            dominant = Counter(leanings).most_common(1)
            if dominant:
                self._emit(ctx, f"Political leaning: {dominant[0][0]}",
                           f"Based on {len(signals)} signals from profile content",
                           0.35, evidence=signals)
        else:
            self._emit(ctx, "Political affiliation analysis",
                       "No political signals detected. Requires content analysis of posts.",
                       0.1)


class Agent049_HobbyCommunityFinder(BaseAgent):
    def __init__(self):
        super().__init__(49, "HobbyCommunityFinder", FindingCategory.SPECIALIST,
                         "Map niche community memberships from platform activity")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        interests = ctx.shared_data.get("detected_interests", [])
        results = ctx.shared_data.get("scan_results", {})

        community_map = {
            "github": ["Open Source", "Developer Community"],
            "reddit": ["Interest-based Communities"],
            "stackoverflow": ["Programming Community"],
            "steam": ["Gaming Community"],
            "twitch": ["Live Streaming", "Gaming"],
            "medium": ["Writers Community"],
            "dev.to": ["Developer Blogging"],
            "soundcloud": ["Music Production"],
            "strava": ["Running/Cycling Community"],
            "goodreads": ["Book Community"],
            "letterboxd": ["Film Community"],
            "myanimelist": ["Anime Community"],
        }

        communities = set()
        for p in found:
            if p.lower() in community_map:
                for c in community_map[p.lower()]:
                    communities.add(c)

        interest_community = {
            "technology": "Tech Enthusiasts", "gaming": "Gamers",
            "music": "Music Enthusiasts", "photography": "Photographers",
            "fitness": "Fitness Community", "security": "InfoSec Community",
            "programming": "Developer Community", "writing": "Writing Community",
        }
        for i in interests:
            if i in interest_community:
                communities.add(interest_community[i])
            elif i != "general":
                communities.add(f"{i.title()} Enthusiasts")

        ctx.shared_data["detected_communities"] = sorted(communities)
        if communities:
            self._emit(ctx, f"Communities: {len(communities)} groups identified",
                       f"Niche communities: {', '.join(sorted(communities)[:10])}",
                       0.6, evidence=[f"Community: {c}" for c in sorted(communities)])
        else:
            self._emit(ctx, "Community discovery",
                       "No community affiliations detectable from current data.",
                       0.1)


class Agent050_PredictiveAnalyzer(BaseAgent):
    def __init__(self):
        super().__init__(50, "PredictiveAnalyzer", FindingCategory.SPECIALIST,
                         "Synthesize all findings into behavioral predictions")

    async def _run(self, ctx: AgentContext) -> None:
        findings = ctx.shared_data.get("all_findings", [])
        found = ctx.shared_data.get("found_platforms", [])
        interests = ctx.shared_data.get("detected_interests", [])
        skills = ctx.shared_data.get("detected_skills", [])
        threat = ctx.shared_data.get("exposure_report", None)

        predictions = []
        confidence_sum = sum(f.confidence for f in findings)
        avg_confidence = confidence_sum / max(len(findings), 1)
        data_quality = "HIGH" if avg_confidence > 0.5 else "MEDIUM" if avg_confidence > 0.3 else "LOW"

        if any(i in interests for i in ["programming", "development", "technology"]):
            predictions.append("Likely to maintain active coding profiles (GitHub, GitLab, Stack Overflow)")
        if "gaming" in interests:
            predictions.append("Probable participation in gaming communities and platforms")
        if any(p in found for p in ["linkedin", "crunchbase", "wellfound"]):
            predictions.append("Actively managing professional presence — likely open to opportunities")
        if len(found) > 30:
            predictions.append("Large digital footprint suggests long-term active internet presence")
        if len(found) < 5:
            predictions.append("Limited digital footprint — possible privacy-conscious user")
        if "security" in interests or "infosec" in interests:
            predictions.append("Security awareness may indicate technical/security professional")

        if threat:
            score = getattr(threat, "overall", 50)
            if score > 60:
                predictions.append("HIGH priority monitoring recommended due to exposure level")

        if predictions:
            self._emit(ctx, f"Behavioral predictions ({data_quality} confidence data)",
                       f"Based on {len(findings)} findings across {len(found)} platforms. "
                       f"Average finding confidence: {avg_confidence:.0%}",
                       0.35 + min(0.4, avg_confidence),
                       evidence=predictions,
                       metadata={"data_quality": data_quality,
                                 "findings_analyzed": len(findings),
                                 "predictions_count": len(predictions)})
        else:
            self._emit(ctx, "Predictive analysis",
                       "Insufficient signals for behavioral prediction. More data required.",
                       0.1)


class EpsilonSquad:
    def __init__(self):
        self.agents = [cls() for cls in [
            Agent041_CryptocurrencyTracer, Agent042_GeolocationDeepDive,
            Agent043_ImageForensics, Agent044_LinguisticProfiler,
            Agent045_PsychologicalProfiler, Agent046_ThreatAssessor,
            Agent047_MisinformationDetector, Agent048_PoliticalAffiliationMapper,
            Agent049_HobbyCommunityFinder, Agent050_PredictiveAnalyzer,
        ]]

    async def run_all(self, ctx: AgentContext) -> None:
        await asyncio.gather(*[a.investigate(ctx) for a in self.agents])