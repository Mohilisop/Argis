"""Runtime dossier repairs and analyst-approved media injection."""
from __future__ import annotations

from functools import wraps
from typing import Any

from argis.media_decisions import apply_decisions_to_records

_INSTALLED = False

# Both fragments are valid HTML intentions but invalid JavaScript: the inner
# single quotes terminate the surrounding single-quoted JS string literal, which
# is a parse-time error that disables the ENTIRE dossier <script>. When that
# happens, the avatar wall, media evidence grid, and account groups all render
# empty. HTML-encoding the inner quotes keeps the DOM behavior identical while
# making the JS string valid.
_REPLACEMENTS = (
    (
        '''onerror="this.outerHTML='<div class=pfp-ph>' + d.p[0].toUpperCase() + '</div>'">''',
        '''onerror="this.style.display=&#39;none&#39;">''',
    ),
    (
        '''onerror="this.style.display='none'">''',
        '''onerror="this.style.display=&#39;none&#39;">''',
    ),
)


def repair_dossier_html(value: str) -> str:
    if not isinstance(value, str):
        return value
    for broken, safe in _REPLACEMENTS:
        value = value.replace(broken, safe)
    return value


def _apply_review(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Apply saved decisions when renderer arguments are records + username."""
    mutable_args = list(args)
    records = mutable_args[0] if mutable_args else kwargs.get("results")
    username = mutable_args[1] if len(mutable_args) > 1 else kwargs.get("username")
    if isinstance(records, list) and isinstance(username, str):
        reviewed = apply_decisions_to_records(records, username)
        if mutable_args:
            mutable_args[0] = reviewed
        else:
            kwargs = dict(kwargs)
            kwargs["results"] = reviewed
    return tuple(mutable_args), kwargs


def install_dossier_repair() -> None:
    """Wrap renderers so reviewed media is applied before HTML generation."""
    global _INSTALLED
    if _INSTALLED:
        return

    import argis.dossier as dossier

    original_generate = getattr(dossier, "generate_dossier_html", None)
    if original_generate is not None and not getattr(original_generate, "_argis_repaired", False):
        @wraps(original_generate)
        def generate_wrapper(*args, **kwargs):
            reviewed_args, reviewed_kwargs = _apply_review(args, kwargs)
            return repair_dossier_html(original_generate(*reviewed_args, **reviewed_kwargs))
        generate_wrapper._argis_repaired = True
        dossier.generate_dossier_html = generate_wrapper

    original_report = getattr(dossier, "to_html_report", None)
    if original_report is not None and not getattr(original_report, "_argis_repaired", False):
        @wraps(original_report)
        def report_wrapper(*args, **kwargs):
            reviewed_args, reviewed_kwargs = _apply_review(args, kwargs)
            return repair_dossier_html(original_report(*reviewed_args, **reviewed_kwargs))
        report_wrapper._argis_repaired = True
        dossier.to_html_report = report_wrapper

    _INSTALLED = True
