from __future__ import annotations

from argis.normalize import normalize_scan_result, profile_evidence_to_dict


def _media(raw, platform, username="mohilisop", verification="VERIFIED"):
    pe = normalize_scan_result(platform, "social", raw, username)
    pe.verification = verification
    return profile_evidence_to_dict(pe)["media"]


def test_github_api_avatar_is_profile_avatar():
    raw = {
        "status": "FOUND",
        "url": "https://github.com/mohilisop",
        "avatar_url": "https://avatars.githubusercontent.com/u/158265614?v=4",
        "title": "MOHIL",
    }
    media = _media(raw, "github")
    assert media, "expected one media item"
    assert media[0]["classification"] == "PROFILE_AVATAR"
    assert media[0]["validated"] is True
    assert media[0]["confidence"] >= 80


def test_platform_logo_is_not_profile_avatar():
    raw = {
        "status": "FOUND",
        "url": "https://dlive.tv/mohilisop",
        "avatar_url": "https://dlive.tv/logo.png",
        "title": "DLive",
    }
    media = _media(raw, "dlive", verification="PROBABLE")
    assert media[0]["classification"] != "PROFILE_AVATAR"
    assert media[0]["validated"] is False


def test_favicon_is_not_profile_avatar():
    raw = {
        "status": "FOUND",
        "url": "https://podcastindex.org/podcaster/mohilisop",
        "avatar_url": "https://podcastindex.org/android-chrome-256x256.png",
        "title": "Podcast Index",
    }
    media = _media(raw, "podcast index", verification="PROBABLE")
    assert media[0]["classification"] != "PROFILE_AVATAR"
    assert media[0]["validated"] is False


def test_generic_og_image_without_username_is_demoted():
    raw = {
        "status": "FOUND",
        "url": "https://zwift.com/athlete/mohilisop",
        "avatar_url": "https://www.zwift.com/meta-image-default.jpg",
        "title": "Zwift",
    }
    media = _media(raw, "zwift", verification="PROBABLE")
    assert media[0]["classification"] != "PROFILE_AVATAR"
    assert media[0]["validated"] is False


def test_profile_without_avatar_has_no_media():
    raw = {"status": "FOUND", "url": "https://example.com/u", "title": "x"}
    media = _media(raw, "unknownplatform")
    assert media == []
