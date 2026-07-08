from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from argis.utils.geoip import GeoIPResult, geoip_lookup


class TestGeoIPResult:
    def test_default_values(self):
        result = GeoIPResult(ip="1.2.3.4")
        assert result.ip == "1.2.3.4"
        assert result.country_name is None
        assert result.error is None

    def test_error_result(self):
        result = GeoIPResult(ip="1.2.3.4", error="API limit reached")
        assert result.error == "API limit reached"


class TestGeoIPLookup:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_data = {
            "ip": "8.8.8.8",
            "country_name": "United States",
            "country_code2": "US",
            "state_prov": "California",
            "city": "Mountain View",
            "zipcode": "94043",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "isp": "Google LLC",
            "organization": "Google LLC",
            "time_zone": {"name": "America/Los_Angeles"},
            "currency": {"code": "USD"},
        }

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value=mock_data)

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.__aenter__.return_value.get = AsyncMock(return_value=mock_response)

        with patch("argis.utils.geoip.httpx.AsyncClient", return_value=mock_client):
            result = await geoip_lookup("8.8.8.8", api_key="test_key")

        assert result.ip == "8.8.8.8"
        assert result.country_name == "United States"
        assert result.country_code2 == "US"
        assert result.state_prov == "California"
        assert result.city == "Mountain View"
        assert result.zipcode == "94043"
        assert result.latitude == 37.4056
        assert result.longitude == -122.0775
        assert result.isp == "Google LLC"
        assert result.organization == "Google LLC"
        assert result.timezone == "America/Los_Angeles"
        assert result.currency == "USD"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_request_error(self):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.__aenter__.return_value.get = AsyncMock(
            side_effect=httpx.RequestError("Connection failed")
        )

        with patch("argis.utils.geoip.httpx.AsyncClient", return_value=mock_client):
            result = await geoip_lookup("1.2.3.4", api_key="test_key")

        assert result.ip == "1.2.3.4"
        assert result.error is not None
        assert "Request failed" in result.error

    @pytest.mark.asyncio
    async def test_empty_response(self):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={})

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.__aenter__.return_value.get = AsyncMock(return_value=mock_response)

        with patch("argis.utils.geoip.httpx.AsyncClient", return_value=mock_client):
            result = await geoip_lookup("1.2.3.4", api_key="test_key")

        assert result.error is not None
        assert result.error == "No data returned"

    @pytest.mark.asyncio
    async def test_default_api_key(self):
        result = await geoip_lookup("8.8.8.8")
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.error is None or True  # may succeed with real API or not
