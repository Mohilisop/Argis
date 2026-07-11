from __future__ import annotations

import re
from typing import Optional


# Pages that don't represent a real user profile
_GENERIC_MARKERS = re.compile(
    r"(?i)(sign up|log in|join for free|create (your )?account|"
    r"welcome to|powered by|this (page|site) (doesn't|does not) exist|"
    r"page not found|user not found|profile not found|"
    r"are you looking for|search results|"
    r"this service has been discontinued|"
    r"this content is no longer available|"
    r"we can't find that user|"
    r"this page is not available|"
    r"the requested resource was not found)"
)

_AMBIGUOUS_TITLE_MARKERS = re.compile(
    r"(?i)^(home|index|about|contact|terms|privacy|help|faq|"
    r"challenges?|programming|platform|community|technology|"
    r"talent|solutions?|services?|products?)$"
)


def determine_verification(
    status: str,
    title: str | None,
    description: str | None,
    html_sample: str | None = None,
    url: str = "",
    platform: str = "",
    username: str = "",
) -> tuple[str, list[str]]:
    """Determine verification state for a profile.

    Returns (state, warnings_list).
    States: VERIFIED, PROBABLE, AMBIGUOUS, NOT_FOUND, ERROR
    """
    warnings: list[str] = []

    if status != "FOUND":
        if status in ("NOT_FOUND", "TIMEOUT"):
            return ("NOT_FOUND", warnings)
        if status in ("BLOCKED", "UNKNOWN"):
            return ("AMBIGUOUS", [f"scan status: {status}"])

    if not title and not description:
        return ("AMBIGUOUS", ["no title or description extracted"])

    username_in_title = username.lower() in (title or "").lower() if title else False
    username_in_desc = username.lower() in (description or "").lower() if description else False

    if username_in_title:
        # Best signal: title contains the target username
        return ("VERIFIED", warnings)

    # Check for generic page markers
    if title and _GENERIC_MARKERS.search(title):
        if username_in_desc:
            return ("PROBABLE", ["title appears generic but username in description"])
        return ("AMBIGUOUS", [f"generic page title: {title[:60]}"])

    if description and _GENERIC_MARKERS.search(description):
        return ("AMBIGUOUS", ["generic page description"])

    if title and _AMBIGUOUS_TITLE_MARKERS.match(title.strip()):
        return ("AMBIGUOUS", [f"ambiguous title: {title.strip()[:40]}"])

    # Title is specific but doesn't contain the username
    if title and len(title) > 10:
        return ("PROBABLE", ["username not confirmed in page title"])

    return ("AMBIGUOUS", ["no verification signals available"])
