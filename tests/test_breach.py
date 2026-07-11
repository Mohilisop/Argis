import httpx
import pytest

from argis.breach import Breach, BreachReport, check_email, check_all


def make_hibp_response(breaches: list[dict] | None, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=breaches or [])
    return handler


@pytest.mark.asyncio
async def test_check_email_clean():
    handler = make_hibp_response(None, 404)
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await check_email(client, "clean@example.com")
    assert report.email == "clean@example.com"
    assert report.compromised is False
    assert report.error is None


@pytest.mark.asyncio
async def test_check_email_compromised():
    data = [{
        "Name": "TestBreach", "Domain": "example.com",
        "BreachDate": "2020-01-01", "DataClasses": ["Emails", "Passwords"],
        "PwnCount": 100000, "IsVerified": True,
    }]
    handler = make_hibp_response(data, 200)
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await check_email(client, "hacked@example.com")
    assert report.compromised is True
    assert len(report.breaches) == 1
    assert report.breaches[0].name == "TestBreach"


@pytest.mark.asyncio
async def test_check_email_rate_limited():
    handler = make_hibp_response(None, 429)
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await check_email(client, "rate@example.com")
    assert report.error == "rate-limited"


@pytest.mark.asyncio
async def test_check_email_http_error():
    handler = make_hibp_response(None, 500)
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await check_email(client, "error@example.com")
    assert report.error == "HTTP 500"


@pytest.mark.asyncio
async def test_check_email_connection_error():
    async def boom(request):
        raise httpx.ConnectError("connection refused")
    transport = httpx.MockTransport(boom)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await check_email(client, "fail@example.com")
    assert report.error is not None


@pytest.mark.asyncio
async def test_check_all_multiple():
    async def fake_check(client, email):
        if email == "clean@x.com":
            return BreachReport(email)
        return BreachReport(email, breaches=[Breach("B1", "x.com", "2021-01-01", ["Emails"], 10, True)])

    import argis.breach as breach_mod
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(breach_mod, "check_email", fake_check)
        reports = await breach_mod.check_all(["clean@x.com", "hacked@x.com"])
    assert len(reports) == 2
    assert reports[0].compromised is False
    assert reports[1].compromised is True


@pytest.mark.asyncio
async def test_breach_worst_data_classes():
    b = BreachReport("test@x.com", breaches=[
        Breach("A", "x.com", "2020-01-01", ["Emails", "Passwords"], 100, True),
        Breach("B", "y.com", "2020-02-01", ["Emails", "IPs"], 50, True),
    ])
    worst = b.worst
    assert "Emails" in worst
    assert "Passwords" in worst or "IPs" in worst
