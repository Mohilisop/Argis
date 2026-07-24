from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse, unquote


_SNAKE_RE = re.compile(r"[-_\.]")
_USERNAME_SPLIT_RE = re.compile(r"[-_\.]+")
_MIN_OVERLAP_WORDS = 3
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def _normalize_handle(handle: str) -> str:
    return _SNAKE_RE.sub("", handle).lower().strip()


def _extract_handles_from_url(url: str) -> list[str]:
    path = urlparse(url).path.rstrip("/")
    parts = [unquote(p) for p in path.split("/") if p and not p.startswith(".")]
    handles = []
    for p in parts:
        if any(c in p for c in ("@", "/", ":")):
            continue
        if len(p) >= 3:
            handles.append(p)
    return handles


def _tokenize(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z0-9._%+\-]{4,}", text.lower())
    return set(tokens)


def _shared_tokens(a: str, b: str) -> set[str]:
    return _tokenize(a) & _tokenize(b)


def _extract_emails_from_text(text: str) -> list[str]:
    return list(set(_EMAIL_RE.findall(text)))


class CrossUsernameCorrelator:
    """Detect if the same person uses different usernames across platforms."""

    def __init__(self):
        self._findings: list[dict] = []
        self._agent_id = 95

    def correlate(
        self,
        target_username: str,
        known_aliases: list[str],
        known_emails: list[str],
        scan_results: dict,
        profile_descriptions: list[str],
        profile_titles: list[str],
    ) -> list[dict]:
        found = [(p, r) for p, r in scan_results.items() if r.get("status") == "FOUND"]
        target_handles = {_normalize_handle(target_username)}
        for alias in known_aliases:
            target_handles.add(_normalize_handle(alias))

        # Collect all candidate usernames with their platform + URLs
        platform_profiles: list[dict] = []
        for plat, info in found:
            url = info.get("url", "")
            handles = _extract_handles_from_url(url)
            title = info.get("title", "") or ""
            desc = info.get("description", "") or ""
            handles.append(target_username)
            platform_profiles.append({
                "platform": plat,
                "url": url,
                "handles": handles,
                "title": title,
                "description": desc,
                "normalized_handles": {_normalize_handle(h) for h in handles},
            })

        # Strategy 1: Same username variant across platforms
        variant_groups: dict[str, list[str]] = defaultdict(list)
        for prof in platform_profiles:
            for h in prof["normalized_handles"]:
                if h and h != _normalize_handle(target_username):
                    variant_groups[h].append(prof["platform"])

        for handle, plats in variant_groups.items():
            if len(plats) >= 2:
                self._agent_id += 1
                self._findings.append({
                    "agent_id": self._agent_id,
                    "agent_name": "Cross-Username Correlator",
                    "category": "identity",
                    "title": f"Same username variant across platforms",
                    "description": f"Handle @{handle} found on {', '.join(plats)} — possible shared identity",
                    "evidence": [f"@{handle} on {p}" for p in plats],
                    "confidence": 0.75,
                    "platform": "cross-platform",
                })

        # Strategy 2: Email pattern match across platforms
        email_tokens: dict[str, set[str]] = defaultdict(set)
        prof_texts: list[dict] = []
        for prof in platform_profiles:
            text = f"{prof['title']} {prof['description']}"
            emails = _extract_emails_from_text(text)
            for email in emails:
                local = email.split("@")[0]
                email_tokens[email].update(_tokenize(local))
                email_tokens[email].update(_tokenize(prof["platform"]))
            prof_texts.append({"platform": prof["platform"], "text": text, "url": prof["url"]})

        for plat_a, prof_a in enumerate(prof_texts):
            for plat_b, prof_b in enumerate(prof_texts):
                if plat_a >= plat_b:
                    continue
                shared = _shared_tokens(prof_a["text"], prof_b["text"])
                if len(shared) >= _MIN_OVERLAP_WORDS:
                    # Filter out common generic words
                    generic = {"the", "and", "for", "with", "this", "that", "from", "have", "been", "they", "user", "profile", "page"}
                    sig = shared - generic
                    if len(sig) >= 2:
                        self._agent_id += 1
                        self._findings.append({
                            "agent_id": self._agent_id,
                            "agent_name": "Cross-Username Correlator",
                            "category": "identity",
                            "title": "Profile description overlap detected",
                            "description": f"Shared keywords ({', '.join(list(sig)[:5])}) found across {prof_a['platform']} and {prof_b['platform']}",
                            "evidence": [prof_a["url"], prof_b["url"]],
                            "confidence": min(0.90, 0.5 + len(sig) * 0.08),
                            "platform": f"{prof_a['platform']} ↔ {prof_b['platform']}",
                        })

        # Strategy 3: Known aliases/emails match found platform data
        known_emails_set = {e.strip().lower() for e in known_emails if "@" in e}
        for prof in platform_profiles:
            text = f"{prof['title']} {prof['description']}"
            found_emails = _extract_emails_from_text(text)
            found_normalized = {e.strip().lower() for e in found_emails}
            overlap = found_normalized & known_emails_set
            if overlap:
                self._agent_id += 1
                self._findings.append({
                    "agent_id": self._agent_id,
                    "agent_name": "Cross-Username Correlator",
                    "category": "deep_web",
                    "title": f"Known email found on {prof['platform']}",
                    "description": f"Email address linked to target appears in {prof['platform']} profile data",
                    "evidence": [prof["url"]] + list(overlap),
                    "confidence": 0.95,
                    "platform": prof["platform"],
                })

        known_aliases_lower = {_normalize_handle(a) for a in known_aliases}
        for prof in platform_profiles:
            for handle in prof["normalized_handles"]:
                if handle in known_aliases_lower and handle != _normalize_handle(target_username):
                    self._agent_id += 1
                    self._findings.append({
                        "agent_id": self._agent_id,
                        "agent_name": "Cross-Username Correlator",
                        "category": "identity",
                        "title": f"Known alias @{handle} found on {prof['platform']}",
                        "description": f"Alias from investigation target matches a profile on {prof['platform']}",
                        "evidence": [prof["url"]],
                        "confidence": 0.90,
                        "platform": prof["platform"],
                    })

        return self._findings
