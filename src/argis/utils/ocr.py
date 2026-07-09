"""OCR screenshot images and extract usernames + URLs."""

import re
from pathlib import Path
from typing import Optional

try:
    import pytesseract
    from PIL import Image

    _has_ocr = True
except ImportError:
    _has_ocr = False

if _has_ocr:
    import shutil
    if not shutil.which("tesseract"):
        for _path in [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]:
            import os as _os
            if _os.path.exists(_path):
                pytesseract.pytesseract.tesseract_cmd = _path
                break

URL_RE = re.compile(r"https?://[^\s)\]}>\"'']+")
USERNAME_RE = re.compile(r"@(\w+)")
WORD_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_.]{2,29}\b")

_STOPWORDS = {
    "the", "this", "that", "with", "from", "have", "been", "were", "they",
    "their", "them", "your", "have", "what", "when", "where", "which",
    "there", "here", "about", "would", "could", "should", "after", "before",
    "between", "through", "during", "without", "within", "along", "following",
    "follow", "followers", "following", "posts", "follower", "people",
    "photos", "videos", "photo", "video", "profile", "private", "public",
    "view", "edit", "share", "save", "report", "block", "message", "switch",
    "remove", "account", "settings", "help", "support", "privacy", "terms",
    "about", "contact", "search", "explore", "create", "upload",
    "instagram", "facebook", "twitter", "tiktok", "snapchat", "youtube",
    "threads", "thread", "reply", "comment", "comments", "like", "likes",
    "posts", "post", "story", "stories", "reel", "reels", "igtv", "guide",
    "see", "and", "the", "for", "not", "are", "but", "all", "can", "has",
    "had", "was", "got", "get", "its", "let", "may", "new", "now", "old",
    "one", "out", "own", "per", "say", "see", "set", "she", "too", "try",
    "use", "way", "who", "also", "any", "did", "done", "down", "each",
    "else", "even", "ever", "fact", "far", "few", "got", "yet", "just",
    "keep", "kind", "know", "last", "life", "like", "long", "made", "make",
    "many", "more", "most", "much", "must", "name", "need", "next", "note",
    "once", "only", "open", "over", "part", "past", "said", "same", "some",
    "such", "take", "tell", "than", "them", "then", "time", "true", "well",
    "went", "very", "year", "years", "zero", "first", "second",
}


def extract_text(image_path: str | Path) -> Optional[str]:
    if not _has_ocr:
        return None
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text.strip() or None
    except Exception:
        return None


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(URL_RE.findall(text)))


def extract_usernames(text: str, urls: list[str] | None = None) -> list[str]:
    seen: set[str] = set()
    for m in USERNAME_RE.finditer(text):
        u = m.group(1).strip().lower()
        if u and len(u) >= 2:
            seen.add(u)
    if urls:
        for url in urls:
            parts = url.rstrip("/").split("/")
            if len(parts) >= 2:
                candidate = parts[-1].split("?")[0].split("#")[0]
                if candidate and re.match(r"^[a-zA-Z0-9_.-]{2,}$", candidate):
                    seen.add(candidate.lower())
    return sorted(seen)


def extract_potential_usernames(text: str) -> list[str]:
    seen: set[str] = set()
    lines = text.splitlines()
    for line in lines:
        stripped = line.strip()
        word_count = len(stripped.split())
        for m in WORD_RE.finditer(stripped):
            w = m.group(0).lower()
            if w not in _STOPWORDS and len(w) >= 3 and word_count <= 2:
                seen.add(w)
    return sorted(seen)
