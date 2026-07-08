from __future__ import annotations

import json
from pathlib import Path

import pytest

from argis import diff as diffmod


@pytest.fixture(autouse=True)
def fake_history_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    yield fake_home


def _make_result(platform: str, status: str, url: str = "") -> dict:
    return {
        platform: {"status": status, "url": url or f"https://{platform}.com/user"}
    }


class TestSearchHistory:
    @pytest.fixture(autouse=True)
    def setup_history(self):
        diffmod.save_scan(
            "alice",
            {
                "GitHub": {
                    "status": "FOUND",
                    "url": "https://github.com/alice",
                },
                "Reddit": {
                    "status": "FOUND",
                    "url": "https://reddit.com/user/alice",
                },
            },
        )
        diffmod.save_scan(
            "bob",
            {
                "GitHub": {
                    "status": "NOT_FOUND",
                    "url": "https://github.com/bob",
                },
                "Twitter": {
                    "status": "FOUND",
                    "url": "https://x.com/bob",
                },
            },
        )

    def test_search_by_platform(self):
        results = diffmod.search_history("GitHub", field="platform")
        assert len(results) == 2
        assert all(r["platform"] == "GitHub" for r in results)

    def test_search_by_url(self):
        results = diffmod.search_history("reddit.com", field="url")
        assert len(results) == 1
        assert results[0]["platform"] == "Reddit"

    def test_filter_by_status(self):
        results = diffmod.search_history("GitHub", field="platform", status_filter="FOUND")
        assert len(results) == 1
        assert results[0]["username"] == "alice"

    def test_no_matches(self):
        results = diffmod.search_history("NonExistentPlatform", field="platform")
        assert results == []

    def test_case_insensitive_search(self):
        results = diffmod.search_history("github", field="platform")
        assert len(results) == 2


class TestAggregateStats:
    @pytest.fixture(autouse=True)
    def setup_history(self):
        diffmod.save_scan(
            "alice",
            {
                "GitHub": {"status": "FOUND", "url": "https://github.com/alice", "emails": ["alice@example.com"]},
                "Reddit": {"status": "NOT_FOUND", "url": "https://reddit.com/user/alice", "emails": []},
            },
        )
        diffmod.save_scan(
            "bob",
            {
                "GitHub": {"status": "FOUND", "url": "https://github.com/bob", "emails": []},
                "Twitter": {"status": "FOUND", "url": "https://x.com/bob", "emails": ["bob@example.com"]},
            },
        )
        diffmod.save_scan("alice", {"GitHub": {"status": "FOUND", "url": "https://github.com/alice", "emails": []}})

    def test_total_users(self):
        stats = diffmod.aggregate_stats()
        assert stats["total_users"] == 2

    def test_total_scans(self):
        stats = diffmod.aggregate_stats()
        assert stats["total_scans"] == 3

    def test_top_platforms(self):
        stats = diffmod.aggregate_stats()
        platforms = [p["platform"] for p in stats["top_platforms"]]
        assert "GitHub" in platforms

    def test_emails_collected(self):
        stats = diffmod.aggregate_stats()
        assert stats["total_emails_collected"] == 2

    def test_user_stats(self):
        stats = diffmod.aggregate_stats()
        assert "alice" in stats["users"]
        assert "bob" in stats["users"]
        assert stats["users"]["alice"]["scans"] == 2


class TestListAllUsers:
    def test_returns_empty_when_no_history(self):
        users = diffmod.list_all_users()
        assert users == []

    def test_returns_known_users(self):
        diffmod.save_scan("testuser", {"P": {"status": "FOUND", "url": "https://p.com/u"}})
        users = diffmod.list_all_users()
        assert "testuser" in users

    def test_returns_all_users(self):
        diffmod.save_scan("user_a", {"P": {"status": "FOUND", "url": "https://p.com/a"}})
        diffmod.save_scan("user_b", {"P": {"status": "FOUND", "url": "https://p.com/b"}})
        users = diffmod.list_all_users()
        assert "user_a" in users
        assert "user_b" in users
