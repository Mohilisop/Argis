"""Geographic inference from public profile metadata.

Signals (all public, already extracted):
  * Explicit location fields (JSON-LD, bio "based in", og:locale)
  * Language of profile content / script detection
  * Time-zone clues (posting patterns if available, timezone in page meta)
  * Region-specific platforms (VK = Russia, Line = Japan/Thailand, Snapchatहिन्दी = India)
  * Currency symbols in bios

Output: ranked list of (country, confidence, evidence) tuples.
Ethics: purely from public profile metadata the person published. No IP lookup,
no tracking, no geofencing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class GeoSignal:
    country: str
    confidence: float
    evidence: str


_LOCATION_RE = re.compile(
    r"(?:based in|located in|from|\U0001F4CD|\U0001F30D|\U0001F1EE\U0001F1F3|\U0001F1FA\U0001F1F8)"
    r"\s*([A-Za-z\s,]+)", re.I)

_SCRIPT_HINTS = {
    "devanagari": ("India", 0.8),
    "arabic": ("Middle East / North Africa", 0.6),
    "hangul": ("South Korea", 0.85),
    "kanji": ("Japan", 0.8),
    "cyrillic": ("Russia / Eastern Europe", 0.6),
    "thai": ("Thailand", 0.85),
}

_PLATFORM_HINTS = {
    "VK": ("Russia", 0.7, "VK is predominantly Russian"),
    "Xing": ("Germany / DACH", 0.65, "Xing is primarily used in German-speaking countries"),
    "Line": ("Japan / Thailand", 0.6, "Line is dominant in Japan and Thailand"),
    "Ravelry": ("USA / UK", 0.4, "Ravelry skews English-speaking"),
}

_CURRENCY = {
    "\u20b9": ("India", 0.85), "\u20ac": ("Europe", 0.5), "\u00a3": ("UK", 0.7),
    "\u00a5": ("Japan / China", 0.6), "\u20a9": ("South Korea", 0.8),
    "R$": ("Brazil", 0.8),
}

_DEVANAGARI = re.compile(r"[\u0900-\u097f]")
_ARABIC = re.compile(r"[\u0600-\u06ff]")
_HANGUL = re.compile(r"[\uac00-\ud7af]")
_KANJI = re.compile(r"[\u4e00-\u9fff]")
_CYRILLIC = re.compile(r"[\u0400-\u04ff]")
_THAI = re.compile(r"[\u0e00-\u0e7f]")

_SCRIPTS = [
    ("devanagari", _DEVANAGARI), ("arabic", _ARABIC), ("hangul", _HANGUL),
    ("kanji", _KANJI), ("cyrillic", _CYRILLIC), ("thai", _THAI),
]

_KNOWN_LOCATIONS = {
    "india": "India", "mumbai": "India", "delhi": "India", "bangalore": "India",
    "bengaluru": "India", "hyderabad": "India", "pune": "India", "chennai": "India",
    "kolkata": "India", "usa": "USA", "united states": "USA",
    "new york": "USA", "san francisco": "USA", "los angeles": "USA",
    "london": "UK", "united kingdom": "UK", "uk": "UK",
    "germany": "Germany", "berlin": "Germany", "munich": "Germany",
    "france": "France", "paris": "France", "japan": "Japan", "tokyo": "Japan",
    "canada": "Canada", "toronto": "Canada", "australia": "Australia",
    "sydney": "Australia", "brazil": "Brazil", "s\u00e3o paulo": "Brazil",
}


def infer_geo(
    bios: list[str],
    titles: list[str],
    platforms_found: list[str],
    all_text: str = "",
) -> list[GeoSignal]:
    """Return ranked geo signals from profile metadata."""
    signals: list[GeoSignal] = []
    combined = " ".join(bios + titles) + " " + all_text

    for bio in bios:
        m = _LOCATION_RE.search(bio)
        if m:
            loc = m.group(1).strip().rstrip(",.").lower()
            country = _KNOWN_LOCATIONS.get(loc)
            if country:
                signals.append(GeoSignal(country, 0.9, f"explicit location: '{m.group(1).strip()}'"))

    for name, pat in _SCRIPTS:
        if pat.search(combined):
            country, conf = _SCRIPT_HINTS[name]
            signals.append(GeoSignal(country, conf, f"{name} script detected in profile text"))

    for plat in platforms_found:
        if plat in _PLATFORM_HINTS:
            country, conf, reason = _PLATFORM_HINTS[plat]
            signals.append(GeoSignal(country, conf, reason))

    for sym, (country, conf) in _CURRENCY.items():
        if sym in combined:
            signals.append(GeoSignal(country, conf, f"currency symbol '{sym}' in profile"))

    low = combined.lower()
    for key, country in _KNOWN_LOCATIONS.items():
        if key in low and not any(s.country == country and s.confidence >= 0.9 for s in signals):
            signals.append(GeoSignal(country, 0.5, f"location name '{key}' mentioned"))
            break

    merged: dict[str, GeoSignal] = {}
    for s in signals:
        if s.country not in merged or s.confidence > merged[s.country].confidence:
            merged[s.country] = s
    return sorted(merged.values(), key=lambda s: -s.confidence)
