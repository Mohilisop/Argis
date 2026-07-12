"""Runtime dossier repairs and analyst-approved media injection."""
from __future__ import annotations

from functools import wraps
from typing import Any

from argis.media_decisions import apply_decisions_to_records

_INSTALLED = False
_BROKEN = '''onerror="this.outerHTML='<div class=pfp-ph>' + d.p[0].toUpperCase() + '</div>'">'''
_SAFE = '''onerror="this.style.display='none'">'''


def repair_dossier_html(value: str) -> str:
    if not isinstance(value, str):
        return value
    return value.replace(_BROKEN, _SAFE)


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

    # Some versions expose to_html_report as a separate renderer. Apply review
    # data when it has the same records/username signature; otherwise only repair.
    original_report = getattr(dossier, "to_html_report", None)
    if original_report is not None and not getattr(original_report, "_argis_repaired", False):
        @wraps(original_report)
        def report_wrapper(*args, **kwargs):
            reviewed_args, reviewed_kwargs = _apply_review(args, kwargs)
            return repair_dossier_html(original_report(*reviewed_args, **reviewed_kwargs))
        report_wrapper._argis_repaired = True
        dossier.to_html_report = report_wrapper

    _INSTALLED = True
