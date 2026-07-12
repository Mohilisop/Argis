from __future__ import annotations

import json

from typer.testing import CliRunner

from argis.entrypoint import app
from argis.media_review import (
    collect_media_candidates,
    render_media_review_dashboard,
    score_media,
)


runner = CliRunner()


def sample_history():
    return [{
        "timestamp": "2026-07-12T04:50:00+00:00",
        "results": {
            "GitHub": {
                "status": "FOUND",
                "url": "https://github.com/alice",
                "avatar_url": "https://github.com/alice.png?size=460",
                "avatar_hash": "abc123",
                "media_source": "validated API endpoint",
                "category": "development",
            },
            "Podcast Index": {
                "status": "FOUND",
                "url": "https://podcastindex.org/podcaster/alice",
                "avatar_url": "https://podcastindex.org/android-chrome-256x256.png",
                "avatar_hash": "def456",
                "media_source": "og:image",
                "category": "entertainment",
            },
            "Missing": {
                "status": "NOT_FOUND",
                "url": "https://example.com/alice",
                "avatar_url": "https://example.com/logo.png",
            },
        },
    }]


def test_score_media_rewards_username_specific_avatar():
    score, signals = score_media(
        "GitHub",
        "https://github.com/alice",
        "https://github.com/alice.png?size=460",
        "validated API endpoint",
    )
    assert score >= 90
    assert any("GitHub" in signal for signal in signals)


def test_score_media_rejects_favicon_assets():
    score, signals = score_media(
        "Podcast Index",
        "https://podcastindex.org/podcaster/alice",
        "https://podcastindex.org/android-chrome-256x256.png",
        "og:image",
    )
    assert score < 50
    assert any("site asset" in signal for signal in signals)


def test_collect_media_candidates_only_keeps_found_media():
    candidates = collect_media_candidates(sample_history()[0]["results"])
    assert [candidate.platform for candidate in candidates] == ["Podcast Index", "GitHub"]
    assert candidates[0].suspicious is True
    assert candidates[1].confidence >= 90


def test_dashboard_contains_safe_interactive_payload():
    candidates = collect_media_candidates(sample_history()[0]["results"])
    dashboard = render_media_review_dashboard(
        "alice", candidates, scanned_at="2026-07-12T04:50:00Z"
    )
    assert "Media confidence" in dashboard
    assert "Accept PFP" in dashboard
    assert "Export JSON" in dashboard
    assert "github.com/alice.png" in dashboard
    assert "this.outerHTML='<div" not in dashboard
    assert "const target=\"alice\"" in dashboard


def test_media_review_cli_writes_html(monkeypatch, tmp_path):
    monkeypatch.setattr("argis.media_review.load_history", lambda username: sample_history())
    destination = tmp_path / "review.html"

    result = runner.invoke(app, ["media-review", "alice", "-o", str(destination)])

    assert result.exit_code == 0
    assert "2 candidates" in result.stdout
    text = destination.read_text("utf-8")
    assert "Podcast Index" in text
    assert "GitHub" in text


def test_media_review_cli_handles_missing_history(monkeypatch, tmp_path):
    monkeypatch.setattr("argis.media_review.load_history", lambda username: [])
    result = runner.invoke(app, ["media-review", "alice", "-o", str(tmp_path)])
    assert result.exit_code == 1
    assert "No saved scan" in result.stdout


def test_export_payload_fields_are_json_serializable():
    candidates = collect_media_candidates(sample_history()[0]["results"])
    payload = json.dumps([candidate.__dict__ for candidate in candidates])
    decoded = json.loads(payload)
    assert decoded[0]["state"] == "review"
    assert isinstance(decoded[0]["signals"], list)
