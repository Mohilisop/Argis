"""Compatibility repair for generated dossier HTML.

The report already contains avatar URLs, but one malformed nested quote in the
account image fallback makes the browser reject the entire script. As a result,
both Captured Avatars and Verified Accounts remain visually empty.
"""
from __future__ import annotations

from functools import wraps

_INSTALLED = False

# Exact malformed fragment present in generated HTML.
_BROKEN = '''onerror="this.outerHTML='<div class=pfp-ph>' + d.p[0].toUpperCase() + '</div>'">'''
_SAFE = '''onerror="this.style.display='none'">'''


def repair_dossier_html(value: str) -> str:
    """Return HTML with valid JavaScript image error handling."""
    if not isinstance(value, str):
        return value
    return value.replace(_BROKEN, _SAFE)


def install_dossier_repair() -> None:
    """Wrap public dossier renderers so every CLI path receives valid HTML."""
    global _INSTALLED
    if _INSTALLED:
        return

    import argis.dossier as dossier

    for name in ("to_html_report", "generate_dossier_html"):
        original = getattr(dossier, name, None)
        if original is None or getattr(original, "_argis_repaired", False):
            continue

        @wraps(original)
        def wrapped(*args, __original=original, **kwargs):
            return repair_dossier_html(__original(*args, **kwargs))

        wrapped._argis_repaired = True
        setattr(dossier, name, wrapped)

    _INSTALLED = True
