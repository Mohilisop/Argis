import json

import httpx
import pytest

from argis.core import ArgisEngine


@pytest.fixture
def sites_file(tmp_path):
    sites = {
        "StatusSite": {
            "url": "https://status.example/{}",
            "error_type": "status_code",
            "error_criteria": 404,
        },
        "MessageSite": {
            "url": "https://message.example/{}",
            "error_type": "message",
            "error_criteria": "User not found",
        },
        "RedirectSite": {
            "url": "https://redirect.example/{}",
            "error_type": "response_url",
            "error_criteria": "https://redirect.example/404",
        },
    }
    path = tmp_path / "sites.json"
    path.write_text(json.dumps(sites))
    return path


def make_handler():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "status.example" in url:
            if "ghost" in url:
                return httpx.Response(404)
            return httpx.Response(200, text="<title>realuser</title>")
        if "message.example" in url:
            if "ghost" in url:
                return httpx.Response(200, text="Sorry, User not found here.")
            return httpx.Response(200, text="<title>realuser</title>")
        if "redirect.example" in url:
            if "ghost" in url:
                return httpx.Response(200, text="gone", request=request)
            return httpx.Response(200, text="<title>realuser</title>")
        return httpx.Response(500)

    return handler


@pytest.mark.asyncio
async def test_check_platform_status_code_rule(sites_file):
    engine = ArgisEngine("realuser", sites_path=sites_file)
    transport = httpx.MockTransport(make_handler())
    async with httpx.AsyncClient(transport=transport) as client:
        result = await engine.check_platform(
            client, "StatusSite", engine.sites["StatusSite"]
        )
    assert result["status"] == "FOUND"


@pytest.mark.asyncio
async def test_check_platform_status_code_not_found(sites_file):
    engine = ArgisEngine("ghost", sites_path=sites_file)
    transport = httpx.MockTransport(make_handler())
    async with httpx.AsyncClient(transport=transport) as client:
        result = await engine.check_platform(
            client, "StatusSite", engine.sites["StatusSite"]
        )
    assert result["status"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_check_platform_message_rule(sites_file):
    engine = ArgisEngine("ghost", sites_path=sites_file)
    transport = httpx.MockTransport(make_handler())
    async with httpx.AsyncClient(transport=transport) as client:
        result = await engine.check_platform(
            client, "MessageSite", engine.sites["MessageSite"]
        )
    assert result["status"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_check_platform_blocked_status(sites_file, monkeypatch):
    engine = ArgisEngine("realuser", sites_path=sites_file)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await engine.check_platform(
            client, "StatusSite", engine.sites["StatusSite"]
        )
    assert result["status"] == "BLOCKED"


def test_invalid_sites_config_raises(tmp_path):
    from argis.exceptions import SiteConfigError

    bad_path = tmp_path / "bad_sites.json"
    bad_path.write_text("{ not valid json")

    with pytest.raises(SiteConfigError):
        ArgisEngine("someone", sites_path=bad_path)
