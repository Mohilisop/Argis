from __future__ import annotations

import json
from pathlib import Path

import pytest

from argis.utils.export import (
    to_csv,
    to_html,
    to_json,
    to_json_stream,
    to_markdown,
)


@pytest.fixture
def sample_results() -> dict[str, dict]:
    return {
        "GitHub": {"status": "FOUND", "url": "https://github.com/test", "title": "test", "emails": []},
        "Reddit": {
            "status": "NOT_FOUND",
            "url": "https://reddit.com/user/test",
            "title": None,
            "emails": ["test@example.com"],
        },
        "X": {"status": "FOUND", "url": "https://x.com/test", "title": "X Profile", "emails": []},
    }


class TestToJson:
    def test_returns_valid_json(self, sample_results):
        result = to_json(sample_results)
        parsed = json.loads(result)
        assert parsed["GitHub"]["status"] == "FOUND"

    def test_includes_all_platforms(self, sample_results):
        result = json.loads(to_json(sample_results))
        assert set(result.keys()) == {"GitHub", "Reddit", "X"}


class TestToCsv:
    def test_returns_csv_string(self, sample_results):
        result = to_csv(sample_results)
        assert result.startswith("platform,status,url,title,emails")

    def test_includes_email_column(self, sample_results):
        result = to_csv(sample_results)
        assert "test@example.com" in result

    def test_all_rows_present(self, sample_results):
        result = to_csv(sample_results)
        lines = result.strip().splitlines()
        assert len(lines) == 4  # header + 3 platforms


class TestToMarkdown:
    def test_contains_table_header(self, sample_results):
        result = to_markdown(sample_results, "testuser")
        assert "| Platform | Status | URL |" in result

    def test_includes_username(self, sample_results):
        result = to_markdown(sample_results, "testuser")
        assert "@testuser" in result


class TestToHtml:
    def test_contains_html_structure(self, sample_results):
        result = to_html(sample_results, "testuser")
        assert "<!DOCTYPE html>" in result
        assert "</html>" in result

    def test_includes_results_table(self, sample_results):
        result = to_html(sample_results, "testuser")
        assert "<table>" in result
        assert "GitHub" in result
        assert "FOUND" in result

    def test_includes_email_links(self, sample_results):
        result = to_html(sample_results, "testuser")
        assert 'href="mailto:test@example.com"' in result


class TestToJsonStream:
    def test_returns_newline_separated_json(self, sample_results):
        result = to_json_stream(sample_results)
        lines = result.strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "platform" in parsed
            assert "status" in parsed
