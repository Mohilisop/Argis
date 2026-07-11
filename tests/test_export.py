from __future__ import annotations

import json
from pathlib import Path

import pytest

from argis.utils.export import (
    to_csv,
    to_graphml,
    to_html,
    to_json,
    to_json_stream,
    to_markdown,
    to_ndjson,
    to_neo4j,
    to_txt,
    to_xmind,
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


class TestToTxt:
    def test_includes_username(self, sample_results):
        result = to_txt(sample_results, "testuser")
        assert "@testuser" in result

    def test_includes_found_platforms(self, sample_results):
        result = to_txt(sample_results, "testuser")
        assert "GitHub" in result
        assert "X" in result

    def test_excludes_not_found(self, sample_results):
        result = to_txt(sample_results, "testuser")
        assert "Reddit" not in result


class TestToNdjson:
    def test_newline_separated(self, sample_results):
        result = to_ndjson(sample_results, "testuser")
        lines = result.strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert parsed["username"] == "testuser"
            assert "platform" in parsed

    def test_includes_status(self, sample_results):
        lines = to_ndjson(sample_results, "testuser").strip().splitlines()
        assert json.loads(lines[0])["status"] == "FOUND"


class TestToXmind:
    def test_returns_zip_bytes(self, sample_results):
        result = to_xmind(sample_results, "testuser")
        import zipfile
        zf = zipfile.ZipFile(__import__("io").BytesIO(result))
        assert "content.xml" in zf.namelist()
        assert "META-INF/manifest.xml" in zf.namelist()

    def test_contains_username_in_content(self, sample_results):
        result = to_xmind(sample_results, "testuser")
        import zipfile
        zf = zipfile.ZipFile(__import__("io").BytesIO(result))
        content = zf.read("content.xml").decode()
        assert "testuser" in content


class TestToGraphml:
    def test_valid_graphml_xml(self, sample_results):
        result = to_graphml(sample_results, "testuser")
        assert 'xmlns="http://graphml.graphdrawing.org/xmlns"' in result
        assert "<graphml" in result
        assert "</graphml>" in result

    def test_includes_seed_node(self, sample_results):
        result = to_graphml(sample_results, "testuser")
        assert 'id="testuser"' in result

    def test_includes_edges(self, sample_results):
        result = to_graphml(sample_results, "testuser")
        assert 'source="testuser"' in result
        assert 'target="GitHub"' in result


class TestToNeo4j:
    def test_contains_cypher_queries(self, sample_results):
        result = to_neo4j(sample_results, "testuser")
        assert "CREATE (u:Person {handle: 'testuser'});" in result
        assert "HAS_ACCOUNT" in result

    def test_creates_account_nodes(self, sample_results):
        result = to_neo4j(sample_results, "testuser")
        assert "CREATE (n:Account {platform: 'GitHub'" in result
