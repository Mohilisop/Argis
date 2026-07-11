import httpx
import pytest

from argis.mentions import Mention, MentionReport, scan_mentions, _generate_dorks


@pytest.mark.asyncio
async def test_scan_mentions_no_results():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": []})
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await scan_mentions("ghost_user_12345", timeout=5.0)
    assert report.query == "ghost_user_12345"
    assert len(report.mentions) == 0


@pytest.mark.asyncio
async def test_scan_mentions_github_hits():
    data = {
        "items": [
            {
                "repository": {"full_name": "user/repo"},
                "html_url": "https://github.com/user/repo/blob/main/file.py",
                "text_matches": [{"fragment": "snippet of code containing handle"}],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=data)
    transport = httpx.MockTransport(handler)
    from argis.mentions import _github_code
    async with httpx.AsyncClient(transport=transport) as client:
        mentions = await _github_code(client, "testuser")
    assert len(mentions) == 1
    assert mentions[0].source == "github"
    assert mentions[0].title == "user/repo"


@pytest.mark.asyncio
async def test_scan_mentions_github_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "rate limit"})
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await scan_mentions("testuser", timeout=5.0)
    assert len(report.mentions) == 0


def test_generate_dorks():
    dorks = _generate_dorks("johndoe", ["john@example.com"])
    assert any('"johndoe" site:pastebin.com' in d for d in dorks)
    assert any('"john@example.com" -site:example.com' in d for d in dorks)


def test_generate_dorks_no_emails():
    dorks = _generate_dorks("johndoe", [])
    paste_dorks = [d for d in dorks if "pastebin" in d]
    assert len(paste_dorks) == 1


@pytest.mark.asyncio
async def test_mention_report_defaults():
    r = MentionReport(query="test")
    assert r.query == "test"
    assert r.mentions == []
    assert r.dorks == []


def test_mention_dataclass():
    m = Mention(source="github", title="repo", url="https://example.com", snippet="code")
    assert m.source == "github"
    assert m.snippet == "code"
