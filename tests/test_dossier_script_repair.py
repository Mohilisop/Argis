from __future__ import annotations

from argis.dossier_runtime import repair_dossier_html


def test_repairs_style_display_handler():
    broken = '''<img class="pfp" src="x" loading="lazy" onerror="this.style.display='none'">'''
    fixed = repair_dossier_html(broken)
    assert "='none'\"" not in fixed
    assert "&#39;none&#39;" in fixed


def test_repairs_outerhtml_handler():
    broken = '''onerror="this.outerHTML='<div class=pfp-ph>' + d.p[0].toUpperCase() + '</div>'">'''
    fixed = repair_dossier_html(broken)
    assert "this.outerHTML='" not in fixed
    assert "this.style.display=&#39;none&#39;" in fixed


def test_repair_leaves_valid_html_untouched():
    clean = '<div class="faces"></div><script>const DATA=[];</script>'
    assert repair_dossier_html(clean) == clean


def test_repaired_script_has_no_unbalanced_single_quote_break():
    # A minimal reproduction of the generated account-row snippet.
    snippet = (
        "const img = d.img ? '<img class=\"pfp\" src=\"' + d.img + "
        "'\" loading=\"lazy\" onerror=\"this.style.display='none'\">' : '';"
    )
    fixed = repair_dossier_html(snippet)
    # The dangerous inner single-quoted literal must be gone.
    assert "display='none'" not in fixed
