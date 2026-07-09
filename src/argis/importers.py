"""Import external username-site databases into Argis's sites.json schema.

Supports:
  * Sherlock  (data.json)            -- https://github.com/sherlock-project/sherlock
  * Maigret   (data.json)            -- https://github.com/soxoj/maigret

Both are ISC/MIT-licensed open data. We translate their detection rules into
Argis's {url, error_type, error_criteria, category} format, tag provenance,
and let `argis doctor` verify the result -- so imported breadth arrives
*checked*, not assumed.

Design: pure translation + de-dupe. No network here; verification is doctor's
job. Anything we can't translate faithfully is skipped with a reason, never
guessed -- a wrong rule is worse than a missing one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class ImportResult:
    sites: dict = field(default_factory=dict)
    imported: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)
    renamed: list[str] = field(default_factory=list)


def _category_from_url(url: str) -> str:
    host = urlparse(url).netloc.lower()
    table = {
        "coding": ("github", "gitlab", "bitbucket", "codepen", "replit",
                   "stackoverflow", "leetcode", "codeforces", "kaggle", "npm",
                   "pypi", "dockerhub", "sourceforge"),
        "social": ("twitter", "x.com", "facebook", "instagram", "tiktok",
                   "reddit", "tumblr", "vk.com", "threads", "bsky", "mastodon"),
        "gaming": ("steam", "twitch", "xbox", "playstation", "epicgames",
                   "chess.com", "osu", "kongregate", "newgrounds"),
        "media": ("youtube", "vimeo", "soundcloud", "spotify", "flickr",
                  "bandcamp", "mixcloud", "dailymotion", "last.fm"),
        "professional": ("linkedin", "xing", "indeed", "glassdoor", "wellfound",
                         "angel.co", "crunchbase"),
        "creative": ("behance", "dribbble", "artstation", "deviantart", "vsco"),
        "blogging": ("medium", "substack", "wordpress", "blogspot", "dev.to",
                     "hashnode", "wattpad"),
        "finance": ("paypal", "venmo", "cash.app", "patreon", "ko-fi"),
    }
    for cat, needles in table.items():
        if any(nd in host for nd in needles):
            return cat
    return "uncategorized"


def from_sherlock(data: dict) -> ImportResult:
    res = ImportResult()
    for name, e in data.items():
        if name.startswith("$"):
            continue
        url = e.get("url")
        if not url or "{}" not in url:
            res.skipped.append((name, "no usable url template"))
            continue
        et = e.get("errorType")
        if et == "status_code":
            rule = {"error_type": "status_code",
                    "error_criteria": int(e.get("errorCode", 404))}
        elif et == "message":
            msg = e.get("errorMsg")
            if not msg:
                res.skipped.append((name, "message type without errorMsg"))
                continue
            if isinstance(msg, list):
                msg = next((m for m in msg if m), None)
            if not msg:
                res.skipped.append((name, "empty errorMsg list"))
                continue
            rule = {"error_type": "message", "error_criteria": msg}
        elif et == "response_url":
            eu = e.get("errorUrl")
            if not eu:
                res.skipped.append((name, "response_url type without errorUrl"))
                continue
            rule = {"error_type": "response_url", "error_criteria": eu}
        else:
            res.skipped.append((name, f"unsupported errorType={et!r}"))
            continue
        rule["url"] = url
        rule["category"] = _category_from_url(url)
        rule["source"] = "sherlock"
        res.sites[name] = rule
        res.imported += 1
    return res


def from_maigret(data: dict) -> ImportResult:
    res = ImportResult()
    sites = data.get("sites", data)
    for name, e in sites.items():
        if not isinstance(e, dict):
            continue
        url = e.get("url")
        if not url or "{}" not in url and "{username}" not in url:
            res.skipped.append((name, "no usable url template"))
            continue
        url = url.replace("{username}", "{}")
        if e.get("checkType") == "status_code" or (
            not e.get("errors") and not e.get("absenceStrs")
        ):
            rule = {"error_type": "status_code", "error_criteria": 404}
        elif e.get("absenceStrs"):
            phrase = e["absenceStrs"]
            phrase = phrase[0] if isinstance(phrase, list) else phrase
            rule = {"error_type": "message", "error_criteria": phrase}
        elif e.get("errors"):
            phrase = next(iter(e["errors"].keys()), None)
            if not phrase:
                res.skipped.append((name, "errors map empty"))
                continue
            rule = {"error_type": "message", "error_criteria": phrase}
        else:
            res.skipped.append((name, "no translatable detection rule"))
            continue
        tags = e.get("tags") or []
        cat = next((t for t in tags if t in {
            "coding", "social", "gaming", "media", "professional",
            "creative", "blogging", "finance", "lifestyle"}), None)
        rule["url"] = url
        rule["category"] = cat or _category_from_url(url)
        rule["source"] = "maigret"
        res.sites[name] = rule
        res.imported += 1
    return res


def merge(
    base: dict, incoming: ImportResult, *, prefer_existing: bool = True,
) -> ImportResult:
    out = ImportResult(sites=dict(base))
    out.imported = incoming.imported
    out.skipped = list(incoming.skipped)
    for name, rule in incoming.sites.items():
        if name in out.sites:
            if prefer_existing:
                alt = f"{name} ({rule.get('source', 'import')})"
                out.sites[alt] = rule
                out.renamed.append(alt)
            else:
                out.sites[name] = rule
        else:
            out.sites[name] = rule
    return out


def load_and_import(
    source: str, path: Path, base_sites: dict, *, prefer_existing: bool = True,
) -> ImportResult:
    data = json.loads(path.read_text("utf-8"))
    if source == "sherlock":
        incoming = from_sherlock(data)
    elif source == "maigret":
        incoming = from_maigret(data)
    else:
        raise ValueError(f"unknown source: {source!r}")
    return merge(base_sites, incoming, prefer_existing=prefer_existing)