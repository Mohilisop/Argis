from __future__ import annotations

import json

from typer.testing import CliRunner

from argis.dossier import generate_dossier_html
from argis.entrypoint import app
from argis.media_decisions import (
    apply_decisions_to_records,
    decisions_file,
    import_review_file,
    load_decisions,
    validate_review_payload,
)


runner = CliRunner()


def review_payload():
    return {
        "target": "alice",
        "reviewed_at": "2026-07-12T06:00:00Z",
        "media": [
            {
                "platform": "GitHub",
                "profile_url": "https://github.com/alice",
                "image_url": "https://github.com/alice.png?size=460",
                "avatar_hash": "approved-hash",
                "confidence": 96,
                "source": "validated API endpoint",
                "state": "accepted",
                "signals": ["Username-specific endpoint"],
            },
            {
                "platform": "Podcast Index",
                "profile_url": "https://podcastindex.org/podcaster/alice",
                "image_url": "https://podcastindex.org/android-chrome-256x256.png",
                "avatar_hash": "favicon-hash",
                "confidence": 4,
                "source": "og:image",
                "state": "rejected",
                "signals": ["Filename looks like a site asset"],
            },
            {
                "platform": "DeBank",
                "profile_url": "https://debank.com/profile/alice",
                "image_url": "https://static-assets.debank.com/user.png",
                "confidence": 62,
                "state": "review",
            },
        ],
    }


def records():
    return [
        {
            "p": "GitHub", "url": "https://github.com/alice",
            "img": "", "avatar_hash": "", "warnings": [],
            "cat": "development", "name": "", "mail": "", "bio": "",
            "links": [], "status": "FOUND", "confidence": 95,
            "verification": "VERIFIED",
        },
        {
            "p": "Podcast Index", "url": "https://podcastindex.org/podcaster/alice",
            "img": "https://podcastindex.org/android-chrome-256x256.png",
            "avatar_hash": "favicon-hash", "warnings": [],
            "cat": "entertainment", "name": "", "mail": "", "bio": "",
            "links": [], "status": "FOUND", "confidence": 70,
            "verification": "PROBABLE",
        },
        {
            "p": "DeBank", "url": "https://debank.com/profile/alice",
            "img": "https://static-assets.debank.com/user.png",
            "avatar_hash": "pending-hash", "warnings": [],
            "cat": "crypto", "name": "", "mail": "", "bio": "",
            "links": [], "status": "FOUND", "confidence": 70,
            "verification": "PROBABLE",
        },
    ]


def test_validate_review_counts_states():
    value = validate_review_payload(review_payload())
    assert value["summary"] == {"accepted": 1, "rejected": 1, "review": 1}


def test_import_and_load_review(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path / "reviews"))
    source = tmp_path / "export.json"
    source.write_text(json.dumps(review_payload()), "utf-8")
    destination, value = import_review_file(source)
    assert destination.exists()
    assert destination == decisions_file("alice")
    assert load_decisions("alice")["media"][0]["state"] == "accepted"


def test_apply_accepts_rejects_and_hides_pending(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path))
    decisions_file("alice").write_text(json.dumps(review_payload()), "utf-8")
    reviewed = apply_decisions_to_records(records(), "alice")
    github, podcast, debank = reviewed
    assert github["img"].endswith("alice.png?size=460")
    assert github["avatar_hash"] == "approved-hash"
    assert "media approved by analyst" in github["warnings"]
    assert podcast["img"] == ""
    assert "media rejected by analyst" in podcast["warnings"]
    assert debank["img"] == ""
    assert "media awaiting analyst approval" in debank["warnings"]


def test_no_review_keeps_automatic_media(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path))
    original = records()
    reviewed = apply_decisions_to_records(original, "alice")
    assert reviewed[1]["img"] == original[1]["img"]


def test_dossier_runtime_includes_only_approved_media(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path))
    decisions_file("alice").write_text(json.dumps(review_payload()), "utf-8")
    html = generate_dossier_html(records(), "alice")
    assert "github.com/alice.png?size=460" in html
    assert "android-chrome-256x256.png" not in html
    assert "static-assets.debank.com/user.png" not in html


def test_media_apply_cli_persists_export(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path / "reviews"))
    source = tmp_path / "alice-media-review.json"
    source.write_text(json.dumps(review_payload()), "utf-8")
    result = runner.invoke(app, ["media-apply", str(source)])
    assert result.exit_code == 0
    assert "1 accepted" in result.stdout
    assert decisions_file("alice").exists()


def test_media_clear_cli_removes_saved_review(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGIS_MEDIA_REVIEW_DIR", str(tmp_path))
    decisions_file("alice").write_text(json.dumps(review_payload()), "utf-8")
    result = runner.invoke(app, ["media-clear", "alice"])
    assert result.exit_code == 0
    assert not decisions_file("alice").exists()
