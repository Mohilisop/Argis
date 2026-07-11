from __future__ import annotations

import os

import pytest

from argis.ai_analyze import analyze


@pytest.fixture
def sample_results() -> dict[str, dict]:
    return {
        "GitHub": {"status": "FOUND", "url": "https://github.com/test", "title": "test", "emails": []},
        "Reddit": {"status": "NOT_FOUND", "url": "https://reddit.com/user/test", "title": None, "emails": ["test@example.com"]},
        "X": {"status": "FOUND", "url": "https://x.com/test", "title": "X Profile", "emails": []},
    }


class TestAnalyze:
    def test_returns_error_when_no_key(self, sample_results):
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = analyze(sample_results, "testuser")
        assert "ERROR" in result
        assert "OPENAI_API_KEY" in result
        assert "ANTHROPIC_API_KEY" in result

    def test_prefers_anthropic_when_only_anthropic_key(self, sample_results):
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test123"
        result = analyze(sample_results, "testuser", model="claude-sonnet-4-20250514")
        assert "Anthropic API error" in result

    def test_prefers_openai_when_both_keys(self, sample_results):
        os.environ["OPENAI_API_KEY"] = "sk-test123"
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test123"
        result = analyze(sample_results, "testuser", model="gpt-4o")
        assert "OpenAI API error" in result
