"""Tests for the dossier pipeline: models, normalize, verify, media, and HTML generation."""
import json
import re

from argis.models import ProfileEvidence, EvidenceItem
from argis.normalize import (
    normalize_scan_result,
    normalize_scan_results,
    adapt_v05_record,
    adapt_v07_record,
    profile_evidence_to_dict,
    profiles_to_dossier_dicts,
)
from argis.verify import determine_verification
from argis.dossier import (
    generate_dossier_html,
    is_valid_name,
    is_valid_email,
    calculate_risk_score,
    extract_identity,
)


# ── models ────────────────────────────────────────────────────────

def test_profile_evidence_defaults():
    pe = ProfileEvidence(
        platform="GitHub", category="development",
        username="testuser", url="https://github.com/testuser", status="FOUND",
    )
    assert pe.platform == "GitHub"
    assert pe.display_name is None
    assert pe.emails == []
    assert pe.verification == "UNVERIFIED"


def test_evidence_item_defaults():
    ei = EvidenceItem(field="email", value="a@b.com", source="scan", confidence=80)
    assert ei.category == "identity"


# ── normalization ─────────────────────────────────────────────────

def test_normalize_v07_record_to_platform_and_category():
    raw = {
        "status": "FOUND",
        "url": "https://soundcloud.com/testuser",
        "title": "Stream TestUser music | Listen to songs...",
        "description": "Play TestUser and discover followers on SoundCloud",
        "emails": [],
        "confidence": 95,
    }
    pe = normalize_scan_result("SoundCloud", "music", raw, "testuser")
    assert pe.platform == "SoundCloud"
    assert pe.category == "music"
    assert pe.status == "FOUND"
    assert pe.url == "https://soundcloud.com/testuser"
    assert pe.confidence == 95


def test_normalize_emails_list_correctly():
    raw = {
        "status": "FOUND",
        "url": "https://example.com/u",
        "title": "Test User - Example",
        "description": "Profile page",
        "emails": ["user@example.com"],
        "confidence": 90,
    }
    pe = normalize_scan_result("Example", "social", raw, "testuser")
    assert "user@example.com" in pe.emails


def test_rejects_avif_filename_as_email():
    raw = {
        "status": "FOUND",
        "url": "https://example.com/u",
        "title": "Test",
        "description": None,
        "emails": ["Error_Lock_SP@2x.avif"],
        "confidence": 90,
    }
    pe = normalize_scan_result("Example", "social", raw, "testuser")
    # The @2x pattern in a filename without valid domain should be rejected
    assert not any("Error_Lock_SP" in e for e in pe.emails)


def test_rejects_corporate_support_email():
    raw = {
        "status": "FOUND",
        "url": "https://example.com/u",
        "title": "Test",
        "description": None,
        "emails": ["support@example.com"],
        "confidence": 90,
    }
    pe = normalize_scan_result("Example", "social", raw, "testuser")
    assert "support@example.com" not in pe.emails


def test_generic_title_not_accepted_as_name_in_extract_identity():
    # is_valid_name should reject generic page titles
    assert not is_valid_name("Welcome to GitHub", "testuser")
    assert not is_valid_name("Sign up for free now", "testuser")
    assert not is_valid_name("testuser", "testuser")  # same as username
    assert not is_valid_name("platform", "testuser")
    # Real names should pass
    assert is_valid_name("Test User", "testuser")


def test_extract_identity_with_title_based_names():
    """Verify that extract_identity correctly uses normalized data."""
    records = [
        {"p": "GitHub", "name": "Test User", "mail": "", "bio": "", "img": "",
         "cat": "development", "url": "", "links": [], "avatar_hash": "",
         "status": "FOUND", "confidence": 95, "verification": "VERIFIED", "warnings": []},
        {"p": "SoundCloud", "name": "", "mail": "", "bio": "music producer",
         "img": "", "cat": "music", "url": "", "links": [], "avatar_hash": "",
         "status": "FOUND", "confidence": 80, "verification": "VERIFIED", "warnings": []},
    ]
    identity = extract_identity(records, "testuser")
    assert "Test User" in identity["names"]
    assert len(identity["bios"]) == 1


# ── verification ──────────────────────────────────────────────────

def test_username_in_title_is_verified():
    state, warns = determine_verification("FOUND", "testuser (Test) - GitHub", None, username="testuser")
    assert state == "VERIFIED"
    assert len(warns) == 0


def test_generic_marketing_page_is_ambiguous():
    state, warns = determine_verification("FOUND", "Welcome to GitHub: Let's build from here", None, username="testuser")
    assert state == "AMBIGUOUS"


def test_discontinued_service_is_ambiguous():
    state, warns = determine_verification(
        "FOUND", "DLive - This service has been discontinued", None, username="testuser"
    )
    assert state == "AMBIGUOUS"


def test_not_found_status():
    state, warns = determine_verification("NOT_FOUND", None, None, username="testuser")
    assert state == "NOT_FOUND"


def test_empty_title_is_ambiguous():
    state, warns = determine_verification("FOUND", None, None, username="testuser")
    assert state == "AMBIGUOUS"


def test_title_without_username_is_probable():
    state, warns = determine_verification(
        "FOUND", "SoundCloud - Stream Music", "Listen to testuser tracks", username="testuser"
    )
    assert state in ("VERIFIED", "PROBABLE")


def test_blocked_status_is_ambiguous():
    state, warns = determine_verification("BLOCKED", None, None, username="testuser")
    assert state == "AMBIGUOUS"


# ── risk scoring ──────────────────────────────────────────────────

def test_45_verified_cannot_be_low_risk():
    records = [
        {"p": f"P{i}", "name": "", "mail": "", "bio": "", "img": "",
         "cat": "social", "url": "", "links": [], "avatar_hash": "",
         "status": "FOUND", "confidence": 90, "verification": "VERIFIED", "warnings": []}
        for i in range(45)
    ]
    identity = extract_identity(records, "testuser")
    risk = calculate_risk_score(records, identity)
    assert risk["rating"] != "LOW", f"Score {risk['score']} should not be LOW with 45 accounts"


def test_empty_scan_is_low_risk():
    risk = calculate_risk_score([], {"names": [], "emails": [], "links": [], "bios": [], "avatars": [], "correlations": []})
    assert risk["rating"] == "LOW"
    assert risk["score"] == 0


# ── HTML generation ───────────────────────────────────────────────

def test_html_contains_categories_not_all_uncategorized():
    records = [
        {"p": "GitHub", "name": "Test", "mail": "", "bio": "", "img": "",
         "cat": "development", "url": "https://github.com/u", "links": [],
         "avatar_hash": "", "status": "FOUND", "confidence": 95,
         "verification": "VERIFIED", "warnings": []},
        {"p": "SoundCloud", "name": "", "mail": "", "bio": "", "img": "",
         "cat": "music", "url": "https://sc.com/u", "links": [],
         "avatar_hash": "", "status": "FOUND", "confidence": 80,
         "verification": "VERIFIED", "warnings": []},
    ]
    html = generate_dossier_html(records, "testuser")
    assert "development" in html
    assert "music" in html
    # "uncategorized" should not appear as a displayed category label
    # (the word appears in the JS color map constant but that's fine)
    import re
    cat_labels = re.findall(r'<span class="lbl">([^<]+)</span>', html)
    assert "uncategorized" not in cat_labels


def test_html_contains_platform_names():
    records = [
        {"p": "GitHub", "name": "", "mail": "", "bio": "", "img": "",
         "cat": "development", "url": "https://github.com/u", "links": [],
         "avatar_hash": "", "status": "FOUND", "confidence": 95,
         "verification": "VERIFIED", "warnings": []},
        {"p": "Instagram", "name": "", "mail": "", "bio": "", "img": "",
         "cat": "social", "url": "https://instagram.com/u", "links": [],
         "avatar_hash": "", "status": "FOUND", "confidence": 85,
         "verification": "VERIFIED", "warnings": []},
    ]
    html = generate_dossier_html(records, "testuser")
    assert "GitHub" in html
    assert "Instagram" in html


def test_html_contains_media_section_when_avatars_exist():
    records = [
        {"p": "GitHub", "name": "", "mail": "", "bio": "", "img": "https://avatars.githubusercontent.com/u/123",
         "cat": "development", "url": "https://github.com/u", "links": [],
         "avatar_hash": "abc123", "status": "FOUND", "confidence": 95,
         "verification": "VERIFIED", "warnings": []},
    ]
    html = generate_dossier_html(records, "testuser")
    assert "avatars" in html.lower() or "faces" in html


def test_html_no_corporate_email_via_normalize():
    """Corporate emails should not appear in dossier output after normalization."""
    from argis.normalize import normalize_scan_result, profile_evidence_to_dict
    from argis.verify import determine_verification
    raw = {
        "status": "FOUND", "url": "https://github.com/u",
        "title": "testuser - GitHub", "description": "dev",
        "emails": ["noreply@github.com", "support@github.com"],
        "confidence": 95,
    }
    pe = normalize_scan_result("GitHub", "development", raw, "testuser")
    assert len(pe.emails) == 0  # both filtered by corporate domain check
    d = profile_evidence_to_dict(pe)
    assert d["mail"] == ""


def test_html_riskscore_banner_present():
    records = [
        {"p": "P1", "name": "", "mail": "", "bio": "", "img": "",
         "cat": "social", "url": "", "links": [], "avatar_hash": "",
         "status": "FOUND", "confidence": 90, "verification": "VERIFIED", "warnings": []},
    ]
    html = generate_dossier_html(records, "testuser")
    assert "RISK" in html or "risk" in html


def test_html_no_asset_filename_as_email_via_normalize():
    """Asset filenames with @ character should not survive normalization."""
    from argis.normalize import normalize_scan_result, profile_evidence_to_dict
    raw = {
        "status": "FOUND", "url": "https://example.com/u",
        "title": "Test", "description": None,
        "emails": ["Error_Lock_SP@2x.avif"],
        "confidence": 90,
    }
    pe = normalize_scan_result("Test", "social", raw, "testuser")
    assert len(pe.emails) == 0
    d = profile_evidence_to_dict(pe)
    assert d["mail"] == ""


# ── adapters ──────────────────────────────────────────────────────

def test_adapt_v05_record():
    v05 = {"p": "GitHub", "cat": "development", "name": "Test User",
           "bio": "A developer", "mail": "test@example.com", "img": ""}
    pe = adapt_v05_record(v05, "testuser")
    assert pe.platform == "GitHub"
    assert pe.category == "development"
    assert pe.display_name == "Test User"
    assert "test@example.com" in pe.emails


def test_adapt_v07_record():
    v07 = {
        "status": "FOUND", "url": "https://github.com/u",
        "title": "testuser (Test User) - GitHub",
        "description": "A developer profile", "emails": ["test@example.com"],
        "confidence": 95,
    }
    pe = adapt_v07_record(v07, "GitHub", "development", "testuser")
    assert pe.platform == "GitHub"
    assert pe.category == "development"
    assert pe.title == "testuser (Test User) - GitHub"


def test_profile_evidence_to_dict_roundtrip():
    pe = ProfileEvidence(
        platform="GitHub", category="development",
        username="testuser", url="https://github.com/u",
        status="FOUND", confidence=95,
        display_name="Test User",
        bio="Developer",
        emails=["test@example.com"],
        avatar_url="https://avatars.example.com/img.jpg",
        avatar_hash="abc123",
        verification="VERIFIED",
        warnings=[],
    )
    d = profile_evidence_to_dict(pe)
    assert d["p"] == "GitHub"
    assert d["cat"] == "development"
    assert d["name"] == "Test User"
    assert d["bio"] == "Developer"
    assert d["mail"] == "test@example.com"
    assert d["img"] == "https://avatars.example.com/img.jpg"
    assert d["avatar_hash"] == "abc123"
    assert d["verification"] == "VERIFIED"


# ── full pipeline integration ─────────────────────────────────────

def test_full_normalize_verify_html_pipeline():
    raw_results = {
        "GitHub": {
            "status": "FOUND", "url": "https://github.com/testuser",
            "title": "testuser (Test User) - GitHub",
            "description": "Developer profile", "emails": ["test@example.com"],
            "confidence": 95,
        },
        "SoundCloud": {
            "status": "FOUND", "url": "https://soundcloud.com/testuser",
            "title": "SoundCloud - Stream Music", "description": "Listen to testuser tracks",
            "emails": [], "confidence": 80,
        },
        "SomeGeneric": {
            "status": "FOUND", "url": "https://generic.com/testuser",
            "title": "Welcome to Generic Platform",
            "description": "Sign up for free today", "emails": [], "confidence": 50,
        },
    }
    cats = {"GitHub": "development", "SoundCloud": "music", "SomeGeneric": "social"}
    profiles = normalize_scan_results(raw_results, cats, "testuser")

    from argis.verify import determine_verification
    for pe in profiles:
        state, warns = determine_verification(
            pe.status, pe.title, pe.bio, username="testuser",
        )
        pe.verification = state
        pe.warnings.extend(warns)

    dossier_dicts = profiles_to_dossier_dicts(profiles)
    html = generate_dossier_html(dossier_dicts, "testuser")

    # GitHub should be VERIFIED (username in title)
    github = [d for d in dossier_dicts if d["p"] == "GitHub"][0]
    assert github["verification"] == "VERIFIED"

    # Generic should be AMBIGUOUS
    generic = [d for d in dossier_dicts if d["p"] == "SomeGeneric"][0]
    assert generic["verification"] == "AMBIGUOUS"

    # HTML should contain platform names
    assert "GitHub" in html
    assert "SoundCloud" in html
    assert "development" in html
    assert "music" in html
