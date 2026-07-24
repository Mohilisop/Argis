"""Shared extraction utilities: email cleaning, name cleaning, visible HTML."""

from __future__ import annotations

import re

_STRIP_TAGS_RE = re.compile(
    r"<(script|style|noscript|template)\b[^>]*>.*?</\1>", re.I | re.S)


def visible_html(html: str) -> str:
    """Strip script/style tags so extractors only see rendered content."""
    return _STRIP_TAGS_RE.sub(" ", html)


_EMAIL_BLOCK_DOMAINS = (
    "sentry.io", "ingest.us.sentry.io", "ingest.sentry.io", "wixpress.com",
    "automattic.com", "wordpress.com", "gravatar.com", "example.com",
    "test.com", "testing.com", "gg.com", "techaro.lol", "email.com",
    "domain.com", "yourdomain.com", "example.org", "noreply.github.com",
)
_EMAIL_BLOCK_LOCAL = (
    "noreply", "no-reply", "donotreply", "support", "hello", "info",
    "admin", "webmaster", "postmaster", "privacy", "privacypolicyupdates",
    "abuse", "security", "sentry", "root", "mailer-daemon",
    "free-marketing", "controlpricing", "freetieredpricing",
    "freetieredpricing23", "monthly-marketing", "multicoupon-marketing",
    "yearly-marketing",
)
_EMAIL_JUNK_RE = re.compile(r"\.(?:jpg|jpeg|png|gif|webp|svg|css|js|woff2?|avif|ico|bmp|tiff?|heic|heif|raw|psd|ai|eps)\b", re.I)
_HEXish_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)


def _valid_email(addr: str) -> bool:
    addr = addr.strip().strip(".").lower()
    if "@" not in addr:
        return False
    local, _, domain = addr.partition("@")
    if not local or not domain or "." not in domain:
        return False
    if _EMAIL_JUNK_RE.search(addr):
        return False
    if _HEXish_RE.match(local) or len(local) > 40:
        return False
    if any(domain == d or domain.endswith("." + d) for d in _EMAIL_BLOCK_DOMAINS):
        return False
    if local in _EMAIL_BLOCK_LOCAL:
        return False
    if any(local.startswith(p + "+") for p in _EMAIL_BLOCK_LOCAL):
        return False
    return True


def clean_emails(raw: list[str]) -> list[str]:
    """Filter a raw email list to only genuine personal addresses."""
    seen, out = set(), []
    for e in raw:
        e2 = e.strip().strip(".")
        if e2.lower() in seen:
            continue
        if _valid_email(e2):
            seen.add(e2.lower())
            out.append(e2)
    return out


_NOTFOUND_TITLES = {
    "profile not found", "user not found", "page not found", "not found",
    "sign up", "log in", "login", "undefined", "page isn't available",
    "this page isn't available", "error", "404", "whoops",
    "wordpress.com", "my indeed profile", "threads",
}


def clean_display_name(raw: str, platform: str, handle: str) -> str:
    """Extract a real name from a title, rejecting platform noise."""
    name = re.split(r"[\u00b7|\u2013\u2014\-]", raw)[0].strip()
    name = re.sub(r"\(@?" + re.escape(handle) + r"\)", "", name, flags=re.I).strip()
    name = re.sub(r"@" + re.escape(handle), "", name, flags=re.I).strip()
    name = re.sub(r"&#x?[0-9a-fA-F]+;", "", name).strip()
    name = re.sub(r"\s*\u2022\s*.*", "", name).strip()
    low = name.lower()
    if low in (platform.lower(), handle.lower()) or low in _NOTFOUND_TITLES:
        return ""
    if len(name) > 60:
        return ""
    return name
