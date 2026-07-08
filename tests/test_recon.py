import asyncio

import httpx
import pytest

from argis import recon
from argis.recon import (
    OSMatch,
    PortResult,
    ReconError,
    TracerouteHop,
    apply_timing,
    banner_grab,
    detect_os_from_banners,
    detect_os_from_ttl,
    discover_hosts,
    merge_os_guesses,
    port_scan,
    run_recon,
    traceroute,
    web_probe,
)


@pytest.mark.asyncio
async def test_port_scan_rejects_url_like_target():
    with pytest.raises(ReconError):
        await port_scan("https://example.com/path")


@pytest.mark.asyncio
async def test_port_scan_open_and_closed(monkeypatch):
    """Fake asyncio.open_connection so no real network I/O happens."""

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port):
        if port == 22:
            return None, FakeWriter()
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    results = await port_scan("testhost", ports=(22, 80), timeout=0.5, concurrency=5)
    by_port = {r.port: r for r in results}

    assert by_port[22].open is True
    assert by_port[22].service_guess == "ssh"
    assert by_port[80].open is False


@pytest.mark.asyncio
async def test_web_probe_extracts_title_and_server(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"server": "nginx"},
            text="<html><head><title>Example Site</title></head><body></body></html>",
        )

    async def fake_client_get(self, url, *args, **kwargs):
        req = httpx.Request("GET", url)
        return handler(req)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_client_get)

    results = await web_probe(
        "testhost", open_ports=[PortResult(port=80, open=True)], ports=(80,)
    )

    assert len(results) == 1
    assert results[0].status_code == 200
    assert results[0].server == "nginx"
    assert results[0].title == "Example Site"


@pytest.mark.asyncio
async def test_web_probe_skips_ports_not_confirmed_open():
    results = await web_probe(
        "testhost",
        open_ports=[PortResult(port=80, open=False)],
        ports=(80, 443),
    )
    assert results == []


@pytest.mark.asyncio
async def test_web_probe_handles_request_errors(monkeypatch):
    async def failing_get(self, url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "get", failing_get)

    results = await web_probe(
        "testhost", open_ports=[PortResult(port=80, open=True)], ports=(80,)
    )
    assert len(results) == 1
    assert results[0].error == "ConnectError"
    assert results[0].status_code is None


@pytest.mark.asyncio
async def test_run_recon_skips_web_when_disabled(monkeypatch):
    async def fake_port_scan(target, **kwargs):
        return [PortResult(port=80, open=True, service_guess="http")]

    monkeypatch.setattr(recon, "port_scan", fake_port_scan)

    report = await run_recon("testhost", do_web=False, do_banners=False)
    assert report.target == "testhost"
    assert report.open_ports[0].port == 80
    assert report.web_results == []
    assert report.banners == []


@pytest.mark.asyncio
async def test_banner_grab_reads_greeting(monkeypatch):
    class FakeReader:
        async def read(self, n):
            return b"SSH-2.0-OpenSSH_8.9\r\n"

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port):
        return FakeReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    results = await banner_grab(
        "testhost", open_ports=[PortResult(port=22, open=True)], ports=(22,)
    )
    assert len(results) == 1
    assert results[0].banner == "SSH-2.0-OpenSSH_8.9"
    assert results[0].error is None


@pytest.mark.asyncio
async def test_banner_grab_skips_closed_ports():
    results = await banner_grab(
        "testhost", open_ports=[PortResult(port=22, open=False)], ports=(22,)
    )
    assert results == []


@pytest.mark.asyncio
async def test_banner_grab_handles_connection_refused(monkeypatch):
    async def fake_open_connection(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    results = await banner_grab(
        "testhost", open_ports=[PortResult(port=21, open=True)], ports=(21,)
    )
    assert results[0].error == "ConnectionRefusedError"
    assert results[0].banner is None


@pytest.mark.asyncio
async def test_discover_hosts_rejects_invalid_cidr():
    with pytest.raises(ReconError):
        await discover_hosts("not-a-cidr")


@pytest.mark.asyncio
async def test_discover_hosts_rejects_oversized_range():
    with pytest.raises(ReconError):
        await discover_hosts("10.0.0.0/16")  # far more than the 256-host cap


@pytest.mark.asyncio
async def test_discover_hosts_reports_alive_and_dead(monkeypatch):
    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port):
        if host.endswith(".1"):
            return None, FakeWriter()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    results = await discover_hosts("192.168.50.0/30", probe_ports=(80,), timeout=0.1)
    by_ip = {r.ip: r.alive for r in results}

    assert by_ip["192.168.50.1"] is True
    assert by_ip["192.168.50.2"] is False


class TestOSTTLDetection:
    def test_detect_linux(self):
        guesses = detect_os_from_ttl(64)
        names = [g.name for g in guesses]
        assert "Linux/Unix" in names

    def test_detect_windows(self):
        guesses = detect_os_from_ttl(128)
        names = [g.name for g in guesses]
        assert "Windows" in names

    def test_detect_cisco(self):
        guesses = detect_os_from_ttl(255)
        names = [g.name for g in guesses]
        assert "Cisco/Network Equipment" in names

    def test_unknown_ttl(self):
        guesses = detect_os_from_ttl(99)
        assert len(guesses) == 0

    def test_ttl_accuracy_values(self):
        guesses = detect_os_from_ttl(64)
        for g in guesses:
            assert 1 <= g.accuracy <= 100
            assert "TTL=64" in (g.detail or "")


class TestOSBannerDetection:
    def test_detect_ubuntu_openssh(self):
        from argis.recon import BannerResult

        banners = [BannerResult(port=22, banner="SSH-2.0-OpenSSH_8.9 Ubuntu-3")]
        matches = detect_os_from_banners(banners)
        names = [m.name for m in matches]
        assert "Ubuntu Linux" in names

    def test_detect_windows_iis(self):
        from argis.recon import BannerResult

        banners = [BannerResult(port=80, banner="HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0")]
        matches = detect_os_from_banners(banners)
        names = [m.name for m in matches]
        assert "Windows Server" in names

    def test_no_banners_returns_empty(self):
        from argis.recon import BannerResult

        banners = [BannerResult(port=22, banner=None)]
        matches = detect_os_from_banners(banners)
        assert matches == []


class TestMergeOSGuesses:
    def test_merge_boosts_accuracy(self):
        ttl_guesses = [OSMatch(name="Linux/Unix", accuracy=70, detail="TTL=64")]
        banner_guesses = [OSMatch(name="Linux/Unix", accuracy=90, detail="port 22: OpenSSH Ubuntu")]
        merged = merge_os_guesses(ttl_guesses, banner_guesses)
        linux = [m for m in merged if m.name == "Linux/Unix"]
        assert linux
        assert linux[0].accuracy >= 85

    def test_merge_different_os(self):
        ttl_guesses = [OSMatch(name="Linux/Unix", accuracy=70, detail="TTL=64")]
        banner_guesses = [OSMatch(name="Windows Server", accuracy=70, detail="port 80: IIS")]
        merged = merge_os_guesses(ttl_guesses, banner_guesses)
        assert len(merged) >= 2


class TestTraceroute:
    @pytest.mark.asyncio
    async def test_returns_list(self, monkeypatch):
        async def fake_resolve(target):
            return "8.8.8.8"
        monkeypatch.setattr(
            "argis.recon._resolve_target",
            fake_resolve,
        )

        async def fake_probe(dest_ip, ttl, port, timeout):
            return TracerouteHop(ttl=ttl, ip=dest_ip if ttl >= 3 else None, alive=ttl >= 3)

        monkeypatch.setattr("argis.recon._probe_hop", fake_probe)

        hops = await traceroute("example.com", max_hops=5, timeout=1)
        assert isinstance(hops, list)
        assert len(hops) > 0
        assert all(isinstance(h, TracerouteHop) for h in hops)


class TestTimingTemplates:
    def test_paranoid_timing(self):
        cfg = apply_timing(0)
        assert cfg["timeout"] == 300
        assert cfg["concurrency"] == 1

    def test_insane_timing(self):
        cfg = apply_timing(5)
        assert cfg["timeout"] == 0.5
        assert cfg["concurrency"] == 500

    def test_normal_default(self):
        cfg = apply_timing(3)
        assert cfg["timeout"] == 2
        assert cfg["concurrency"] == 100

    def test_invalid_fallback(self):
        cfg = apply_timing(99)
        assert cfg["timeout"] == 2
        assert cfg["concurrency"] == 100
