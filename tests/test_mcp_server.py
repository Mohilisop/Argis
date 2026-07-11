from unittest.mock import AsyncMock, patch, MagicMock, PropertyMock

import pytest

from argis.mcp_server import (
    _HAS_MCP, _handle_scan, _handle_breach, _handle_exposure,
    _handle_guard, _handle_locate, _handle_recon, _handle_me,
)


def test_mcp_not_available():
    assert _HAS_MCP is False


class FakeEngine:
    def __init__(self, *args, **kwargs):
        pass
    async def run_scan(self, quiet=True):
        return {}
    def _filter_sites(self):
        return {}


@pytest.mark.asyncio
async def test_handle_scan_no_results():
    with patch("argis.mcp_server.ArgisEngine", FakeEngine):
        result = await _handle_scan({"username": "ghost"})
    text = result[0].text
    assert "ghost" in text
    assert "0 found" in text


@pytest.mark.asyncio
async def test_handle_scan_with_hits():
    class Engine:
        def __init__(self, *args, **kwargs):
            pass
        async def run_scan(self, quiet=True):
            return {
                "GitHub": {"status": "FOUND", "url": "https://github.com/test", "title": "Test User"},
                "Reddit": {"status": "FOUND", "url": "https://reddit.com/u/test", "emails": ["test@x.com"]},
                "Unknown": {"status": "NOT_FOUND", "url": ""},
            }
        def _filter_sites(self):
            return {}

    with patch("argis.mcp_server.ArgisEngine", Engine):
        result = await _handle_scan({"username": "test"})
    text = result[0].text
    assert "2 found / 3 scanned" in text
    assert "GitHub" in text
    assert "Reddit" in text
    assert "emails: test@x.com" in text


@pytest.mark.asyncio
async def test_handle_breach_clean():
    mock_report = MagicMock()
    mock_report.email = "clean@x.com"
    mock_report.compromised = False
    mock_report.error = None

    with patch("argis.breach.check_all", AsyncMock(return_value=[mock_report])):
        result = await _handle_breach({"emails": ["clean@x.com"]})
    assert "clean" in result[0].text


@pytest.mark.asyncio
async def test_handle_breach_compromised():
    mock_breach = MagicMock()
    mock_breach.name = "TestBreach"

    mock_report = MagicMock()
    mock_report.email = "hacked@x.com"
    mock_report.compromised = True
    mock_report.error = None
    mock_report.breaches = [mock_breach]

    with patch("argis.breach.check_all", AsyncMock(return_value=[mock_report])):
        result = await _handle_breach({"emails": ["hacked@x.com"]})
    text = result[0].text
    assert "hacked" in text
    assert "TestBreach" in text


@pytest.mark.asyncio
async def test_handle_exposure_no_accounts():
    with patch("argis.mcp_server.ArgisEngine", FakeEngine):
        result = await _handle_exposure({"username": "ghost"})
    text = result[0].text
    assert "ghost" in text


@pytest.mark.asyncio
async def test_handle_guard_no_impersonators():
    mock_match = MagicMock()
    mock_match.variant = "test_"
    mock_match.platform = "GitHub"
    mock_match.score = 0.3
    mock_match.url = "https://github.com/test_"

    mock_guard = MagicMock()
    mock_guard.variants_scanned = 10
    mock_guard.hits = 1
    mock_guard.impersonators = []
    mock_guard.matches = [mock_match]

    with patch("argis.impersonate.guard", AsyncMock(return_value=mock_guard)):
        result = await _handle_guard({"username": "test", "max_variants": 10})
    text = result[0].text
    assert "Clean" in text


@pytest.mark.asyncio
async def test_handle_locate_no_signals():
    with patch("argis.mcp_server.ArgisEngine", FakeEngine):
        result = await _handle_locate({"username": "ghost"})
    assert "Not enough signals" in result[0].text


@pytest.mark.asyncio
async def test_handle_recon_error():
    with patch("argis.recon.run_recon", AsyncMock(side_effect=Exception("timeout"))):
        result = await _handle_recon({"target": "example.com"})
    assert "timeout" in result[0].text.lower()


@pytest.mark.asyncio
async def test_handle_me_empty():
    mock_report = MagicMock()
    mock_report.handle = "ghost"
    mock_report.risk_level = "LOW"
    mock_report.exposure_score = 0.0
    mock_report.exposure_grade = "A"
    mock_report.accounts_found = 0
    mock_report.platforms_scanned = 0
    mock_report.emails_breached = 0
    mock_report.impersonators_found = 0
    mock_report.geo_signals = []
    mock_report.breaches = []
    mock_report.impersonators = []
    mock_report.actions = []

    with patch("argis.me.run_me", AsyncMock(return_value=mock_report)):
        result = await _handle_me({"username": "ghost"})
    text = result[0].text
    assert "LOW" in text
    assert "ghost" in text
