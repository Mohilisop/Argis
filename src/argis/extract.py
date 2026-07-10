"""Structured, typed-label extraction from profile pages — Maigret-style.

Turns a profile's HTML into a dict of typed labels:
  full_name, username, bio, location, follower_count, following_count,
  post_count, created_at, verified, avatar_url, external_url, gender(hint)

Strategy, most-reliable first:
  1. JSON-LD  (<script type="application/ld+json">)  — schema.org Person/ProfilePage
  2. OpenGraph / Twitter card meta
  3. Generic meta (description, etc.)
  4. A small registry of per-platform regexes for the high-value counts

Each label carries (value, type, source) so downstream code can trust/rank it.
Nothing is fabricated: an extractor that doesn't match emits nothing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class Label:
    key: str
    value: object
    type: str      # "str" | "int" | "date" | "bool" | "url"
    source: str    # "json-ld" | "opengraph" | "meta" | "platform:<name>"


_JSONLD = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S)
_META = lambda prop: re.compile(
    rf'<meta[^>]+(?:property|name)=["\']{prop}["\'][^>]+content=["\']([^"\']*)["\']',
    re.I)
_OG_IMAGE = _META("og:image")
_OG_DESC = _META("og:description")
_OG_TITLE = _META("og:title")
_TW_TITLE = _META("twitter:title")

_COUNT = re.compile(r"([\d.,]+)\s*([KkMmBb]?)")


def _to_int(txt: str) -> int | None:
    m = _COUNT.search(txt.replace("\u00a0", " "))
    if not m:
        return None
    num, suf = m.group(1).replace(",", ""), m.group(2).lower()
    try:
        val = float(num)
    except ValueError:
        return None
    mult = {"": 1, "k": 1_000, "m": 1_000_000, "b": 1_000_000_000}[suf]
    return int(val * mult)


def _parse_jsonld(html_text: str) -> dict:
    out: dict = {}
    for block in _JSONLD.findall(html_text):
        try:
            data = json.loads(block)
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for it in items:
            if not isinstance(it, dict):
                continue
            graph = it.get("@graph") if isinstance(it.get("@graph"), list) else [it]
            for node in graph:
                if not isinstance(node, dict):
                    continue
                t = node.get("@type", "")
                t = " ".join(t) if isinstance(t, list) else str(t)
                if any(k in t for k in ("Person", "ProfilePage", "Organization")):
                    out.setdefault("full_name", node.get("name"))
                    out.setdefault("bio", node.get("description"))
                    out.setdefault("avatar_url", node.get("image") if isinstance(
                        node.get("image"), str) else None)
                    if isinstance(node.get("address"), dict):
                        out.setdefault("location",
                                       node["address"].get("addressLocality"))
                    if node.get("sameAs"):
                        sa = node["sameAs"]
                        out.setdefault("external_url",
                                       sa[0] if isinstance(sa, list) and sa else sa)
                    if node.get("dateCreated") or node.get("foundingDate"):
                        out.setdefault("created_at",
                                       node.get("dateCreated") or node.get("foundingDate"))
    return {k: v for k, v in out.items() if v}


_PLATFORM_RULES: dict[str, list[tuple[str, re.Pattern]]] = {
    "GitHub": [
        ("follower_count", re.compile(r'(\d[\d,]*)\s*</span>\s*followers?', re.I)),
        ("following_count", re.compile(r'(\d[\d,]*)\s*</span>\s*following', re.I)),
    ],
    "Instagram": [
        ("follower_count", re.compile(r'"edge_followed_by":\{"count":(\d+)')),
        ("following_count", re.compile(r'"edge_follow":\{"count":(\d+)')),
        ("post_count", re.compile(r'"edge_owner_to_timeline_media":\{"count":(\d+)')),
        ("verified", re.compile(r'"is_verified":(true|false)')),
    ],
    "Twitter/X": [
        ("follower_count", re.compile(r'([\d.,KMB]+)\s+Followers', re.I)),
    ],
    "Reddit": [
        ("post_count", re.compile(r'([\d.,kmb]+)\s*(?:post )?karma', re.I)),
    ],
}


def extract_labels(platform: str, html_text: str) -> dict[str, Label]:
    labels: dict[str, Label] = {}

    def put(key, value, typ, source):
        if value in (None, "", []):
            return
        labels.setdefault(key, Label(key, value, typ, source))

    for k, v in _parse_jsonld(html_text).items():
        typ = "url" if k.endswith("url") else ("date" if k == "created_at" else "str")
        put(k, v, typ, "json-ld")

    if (m := _OG_TITLE.search(html_text)) or (m := _TW_TITLE.search(html_text)):
        put("full_name", m.group(1).split("(")[0].strip(), "str", "opengraph")
    if (m := _OG_DESC.search(html_text)):
        put("bio", m.group(1).strip(), "str", "opengraph")
    if (m := _OG_IMAGE.search(html_text)):
        put("avatar_url", m.group(1), "url", "opengraph")

    for key, pat in _PLATFORM_RULES.get(platform, []):
        m = pat.search(html_text)
        if not m:
            continue
        raw = m.group(1)
        if key == "verified":
            put(key, raw.lower() == "true", "bool", f"platform:{platform}")
        elif key.endswith("_count"):
            n = _to_int(raw)
            if n is not None:
                put(key, n, "int", f"platform:{platform}")
        else:
            put(key, raw, "str", f"platform:{platform}")

    return labels


def labels_to_dict(labels: dict[str, Label]) -> dict:
    return {k: l.value for k, l in labels.items()}
