from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

CACHE_DIR: Path | None = None
CACHE_TTL = 3600


def configure(cache_dir: str | Path | None = None, ttl: int = 3600):
    global CACHE_DIR, CACHE_TTL
    if cache_dir:
        CACHE_DIR = Path(cache_dir)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_TTL = ttl


def _cache_path(key: str) -> Path:
    assert CACHE_DIR is not None
    return CACHE_DIR / f"{key}.json"


def get(key: str) -> dict | None:
    if CACHE_DIR is None:
        return None
    p = _cache_path(key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if time.time() - data.get("_cached_at", 0) > CACHE_TTL:
            p.unlink(missing_ok=True)
            return None
        return data.get("result")
    except Exception:
        p.unlink(missing_ok=True)
        return None


def set(key: str, result: Any):
    if CACHE_DIR is None:
        return
    p = _cache_path(key)
    p.write_text(
        json.dumps({"_cached_at": time.time(), "result": result}),
        encoding="utf-8",
    )


def clear():
    if CACHE_DIR is None:
        return
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
