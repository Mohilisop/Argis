from __future__ import annotations

from argis.models import ProfileEvidence


class MediaDecisions:
    MEDIA_WEIGHTS: dict[str, int] = {
        "PROFILE_AVATAR": 100,
        "PROFILE_BANNER": 60,
        "PLATFORM_LOGO": 30,
        "GENERIC_THUMBNAIL": 15,
        "DEFAULT_AVATAR": 0,
        "UNKNOWN_MEDIA": 5,
        "REJECTED": -50,
    }

    CONFIDENCE_THRESHOLD = 50
    MAX_MEDIA_PER_PROFILE = 25
    RECOMMENDED_MAX_MEDIA = 10

    ASCENSION_CLASSES: dict[str, str] = {
        "PROFILE_AVATAR": "HIGH",
        "PROFILE_BANNER": "MEDIUM",
        "PLATFORM_LOGO": "LOW",
        "GENERIC_THUMBNAIL": "LOW",
        "DEFAULT_AVATAR": "REJECT",
        "UNKNOWN_MEDIA": "LOW",
        "REJECTED": "REJECT",
    }

    @staticmethod
    def decide(profile: ProfileEvidence) -> str | None:
        if not profile.media:
            return None
        best = max(profile.media, key=lambda m: m.confidence)
        cls = best.classification
        weight = MediaDecisions.MEDIA_WEIGHTS.get(cls, 0)
        if weight <= 0:
            return None
        if best.confidence < MediaDecisions.CONFIDENCE_THRESHOLD:
            return None
        return best.url

    @staticmethod
    def pick_best_url(media_list: list) -> str | None:
        if not media_list:
            return None
        best = max(media_list, key=lambda m: m.confidence)
        if best.confidence >= MediaDecisions.CONFIDENCE_THRESHOLD:
            return best.url
        return None

    @staticmethod
    def ascension_class(classification: str) -> str:
        return MediaDecisions.ASCENSION_CLASSES.get(classification, "LOW")

    @staticmethod
    def filter_by_confidence(media_list: list, threshold: int | None = None) -> list:
        t = threshold if threshold is not None else MediaDecisions.CONFIDENCE_THRESHOLD
        return [m for m in media_list if m.confidence >= t and MediaDecisions.MEDIA_WEIGHTS.get(m.classification, 0) > 0]

    @staticmethod
    def filter_warnings(media_list: list) -> list:
        return [m for m in media_list if not m.warnings]
