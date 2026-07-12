from __future__ import annotations

import json

import pytest

from argis.media_runtime import (
    _check_platform_with_media,
    _github_profile,
    _instagram_profile,
)


class Response:
    def __init__(self, status_code=200, payload=None, content=b"image-bytes", url="https://cdn.example/avatar.jpg"):
        self.status_code = status_code
        self._payload = payload
        self.content = content
        self.url = url
        self.text = ""

    def json(self):
        if self._payload is None:
            raise json.JSONDecodeError("bad", "", 0)
        return self._payload


class Client:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_github_profile_uses_public_api():
    client = Client([Response(payload={
        "login": "alice",
        "name": "Alice Example",
        "bio": "Developer",
        "html_url": "https://github.com/alice",
        "avatar_url": "https://avatars.githubusercontent.com/u/123?v=4",
    })])
    result = await _github_profile(client, "alice")
    assert result["status"] == "FOUND"
    assert result["avatar_url"].startswith("https://avatars.githubusercontent.com/")
    assert result["display_name"] == "Alice Example"
    assert client.calls[0][0] == "https://api.github.com/users/alice"


@pytest.mark.asyncio
async def test_github_profile_rejects_mismatched_login():
    client = Client([Response(payload={
        "login": "someone-else",
        "avatar_url": "https://avatars.githubusercontent.com/u/1",
    })])
    assert await _github_profile(client, "alice") is None


@pytest.mark.asyncio
async def test_instagram_profile_uses_web_profile_info():
    client = Client([Response(payload={
        "data": {"user": {
            "username": "alice",
            "full_name": "Alice Example",
            "biography": "Photographer",
            "profile_pic_url_hd": "https://scontent.cdninstagram.com/alice.jpg",
            "is_private": False,
            "is_verified": True,
        }}
    })])
    result = await _instagram_profile(client, "alice")
    assert result["status"] == "FOUND"
    assert result["avatar_url"].endswith("alice.jpg")
    assert result["display_name"] == "Alice Example"
    assert client.calls[0][1]["headers"]["X-IG-App-ID"]


@pytest.mark.asyncio
async def test_instagram_profile_rejects_missing_user():
    client = Client([Response(payload={"data": {"user": None}})])
    assert await _instagram_profile(client, "alice") is None


@pytest.mark.asyncio
async def test_platform_api_runs_before_generic_scanner(monkeypatch):
    api_result = {
        "status": "FOUND",
        "url": "https://github.com/alice",
        "avatar_url": "https://avatars.githubusercontent.com/u/123?v=4",
        "confidence": 100,
        "media_source": "GitHub public user API",
    }

    async def fake_api(client, platform, username):
        return dict(api_result)

    async def fake_attach(client, result):
        result["media_validated"] = True
        return result

    monkeypatch.setattr("argis.media_runtime._profile_api_result", fake_api)
    monkeypatch.setattr("argis.media_runtime._attach_validated_image", fake_attach)

    class Engine:
        username = "alice"

    result = await _check_platform_with_media(
        Engine(), object(), "GitHub", {"url": "https://github.com/{}"}
    )
    assert result["avatar_url"].startswith("https://avatars.githubusercontent.com/")
    assert result["media_validated"] is True
