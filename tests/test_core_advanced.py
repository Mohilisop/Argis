from __future__ import annotations

import json
import pathlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from argis.core import ArgisEngine, build_email_map, extract_categories, _categorize_error
from argis.exceptions import SiteConfigError


@pytest.fixture
def sample_sites(tmp_path: pathlib.Path) -> pathlib.Path:
    sites = {
        "GitHub": {
            "url": "https://github.com/{}",
            "error_type": "status_code",
            "error_criteria": 404,
            "category": "coding",
        },
        "Reddit": {
            "url": "https://reddit.com/user/{}",
            "error_type": "status_code",
            "error_criteria": 404,
            "category": "social",
        },
        "Twitter": {
            "url": "https://x.com/{}",
            "error_type": "status_code",
            "error_criteria": 404,
            "category": "social",
        },
    }
    path = tmp_path / "sites.json"
    path.write_text(json.dumps(sites))
    return path


class TestCategoryFilter:
    def test_filters_to_single_category(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, categories=("social",))
        filtered = engine._filter_sites()
        assert "Reddit" in filtered
        assert "Twitter" in filtered
        assert "GitHub" not in filtered

    def test_filters_to_multiple_categories(self, sample_sites):
        engine = ArgisEngine(
            "test", sites_path=sample_sites, categories=("coding", "social")
        )
        filtered = engine._filter_sites()
        assert len(filtered) == 3

    def test_no_filter_returns_all(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites)
        filtered = engine._filter_sites()
        assert len(filtered) == 3

    def test_empty_filter_returns_none(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, categories=("gaming",))
        filtered = engine._filter_sites()
        assert filtered == {}

    def test_case_insensitive_category(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, categories=("SOCIAL",))
        filtered = engine._filter_sites()
        assert "Reddit" in filtered
        assert "Twitter" in filtered


class TestExtractCategories:
    def test_returns_sorted_list(self, sample_sites):
        cats = extract_categories(sample_sites)
        assert cats == ["coding", "social"]

    def test_includes_all_categories(self, sample_sites):
        cats = extract_categories(sample_sites)
        assert "coding" in cats
        assert "social" in cats


class TestRetryOnBlocked:
    @pytest.mark.asyncio
    async def test_retries_on_429(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, retry_blocked=True, retry_max_attempts=3)

        sites_data = json.loads(sample_sites.read_text())

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 429
        mock_response.text = ""

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await engine.check_platform(mock_client, "GitHub", sites_data["GitHub"])
        assert result["status"] == "BLOCKED"
        assert mock_client.get.call_count == 3


class TestBuildEmailMap:
    def test_returns_email_map(self):
        results = {
            "GitHub": {
                "status": "FOUND",
                "url": "https://github.com/test",
                "emails": ["test@github.com"],
            },
            "Reddit": {
                "status": "NOT_FOUND",
                "url": "https://reddit.com/user/test",
                "emails": [],
            },
            "X": {
                "status": "FOUND",
                "url": "https://x.com/test",
                "emails": ["test@x.com", "admin@x.com"],
            },
        }
        email_map = build_email_map(results)
        assert "GitHub" in email_map
        assert "Reddit" not in email_map
        assert "X" in email_map
        assert email_map["X"] == ["test@x.com", "admin@x.com"]


class TestHttp2Support:
    def test_http2_passed_to_config(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, http2=True)
        assert engine.http2 is True

    def test_http2_defaults_to_false(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites)
        assert engine.http2 is False


class TestExcludeFilter:
    def test_exclude_removes_platforms(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, exclude={"twitter"})
        filtered = engine._filter_sites()
        assert "Twitter" not in filtered
        assert "Reddit" in filtered

    def test_exclude_multiple(self, sample_sites):
        engine = ArgisEngine(
            "test", sites_path=sample_sites, exclude={"twitter", "github"}
        )
        filtered = engine._filter_sites()
        assert "Twitter" not in filtered
        assert "GitHub" not in filtered
        assert len(filtered) == 1
        assert "Reddit" in filtered

    def test_exclude_case_insensitive(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, exclude={"TWITTER"})
        filtered = engine._filter_sites()
        assert "Twitter" not in filtered

    def test_exclude_none_returns_all(self, sample_sites):
        engine = ArgisEngine("test", sites_path=sample_sites, exclude=None)
        filtered = engine._filter_sites()
        assert len(filtered) == 3

    def test_exclude_with_category_filter(self, sample_sites):
        engine = ArgisEngine(
            "test",
            sites_path=sample_sites,
            categories=("social",),
            exclude={"twitter"},
        )
        filtered = engine._filter_sites()
        assert "Reddit" in filtered
        assert "Twitter" not in filtered
        assert "GitHub" not in filtered


class TestErrorCategorization:
    def test_categorize_dns_error(self):
        import httpx
        exc = httpx.ConnectError("[Errno 11001] getaddrinfo failed")
        assert _categorize_error(exc) == "DNS_ERROR"

    def test_categorize_connection_refused(self):
        import httpx
        exc = httpx.ConnectError("[Errno 10061] Connection refused")
        assert _categorize_error(exc) == "CONNECTION_REFUSED"

    def test_categorize_connection_reset(self):
        import httpx
        exc = httpx.ConnectError("Connection reset by peer")
        assert _categorize_error(exc) == "CONNECTION_RESET"

    def test_categorize_ssl_error(self):
        import httpx
        exc = httpx.ConnectError("SSL certificate verify failed")
        assert _categorize_error(exc) == "SSL_ERROR"

    def test_categorize_timeout(self):
        import httpx
        exc = httpx.ConnectTimeout("timed out")
        assert _categorize_error(exc) == "CONNECT_TIMEOUT"

    def test_categorize_read_timeout(self):
        import httpx
        exc = httpx.ReadTimeout("read timed out")
        assert _categorize_error(exc) == "READ_TIMEOUT"

    def test_categorize_too_many_redirects(self):
        import httpx
        exc = httpx.TooManyRedirects("too many redirects")
        assert _categorize_error(exc) == "TOO_MANY_REDIRECTS"

    def test_categorize_generic_connect_error(self):
        import httpx
        exc = httpx.ConnectError("something else went wrong")
        assert _categorize_error(exc) == "CONNECT_ERROR"

    def test_categorize_generic_exception(self):
        exc = ValueError("foo")
        assert _categorize_error(exc) == "UNKNOWN_ERROR"

    def test_categorize_protocol_error(self):
        import httpx
        exc = httpx.RemoteProtocolError("protocol error")
        assert _categorize_error(exc) == "PROTOCOL_ERROR"


class TestCheckPlatformErrors:
    @pytest.mark.asyncio
    async def test_timeout_returns_error_type(self, sample_sites):
        from unittest.mock import AsyncMock, MagicMock
        import httpx

        engine = ArgisEngine("test", sites_path=sample_sites)
        sites_data = json.loads(sample_sites.read_text())

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.ReadTimeout("read timed out"))

        result = await engine.check_platform(mock_client, "GitHub", sites_data["GitHub"])
        assert result["status"] == "TIMEOUT"
        assert result["error"] == "READ_TIMEOUT"

    @pytest.mark.asyncio
    async def test_connect_error_returns_error_type(self, sample_sites):
        from unittest.mock import AsyncMock, MagicMock
        import httpx

        engine = ArgisEngine("test", sites_path=sample_sites)
        sites_data = json.loads(sample_sites.read_text())

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(
            side_effect=httpx.ConnectError("[Errno 11001] getaddrinfo failed")
        )

        result = await engine.check_platform(mock_client, "GitHub", sites_data["GitHub"])
        assert result["status"] == "UNKNOWN"
        assert result["error"] == "DNS_ERROR"
