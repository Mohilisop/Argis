from __future__ import annotations

import asyncio
import ipaddress
import re
import struct
import time
from dataclasses import dataclass, field

import httpx

from argis.exceptions import ArgisError
from argis.utils.network import DNSResult, resolve_dns_full, whois_lookup

DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
)

DEFAULT_UDP_PORTS: tuple[int, ...] = (
    53, 67, 68, 69, 123, 161, 162, 500, 514, 520,
    1900, 4500, 5353,
)

WEB_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8888)

BANNER_PORTS: tuple[int, ...] = (21, 22, 23, 25, 110, 143, 3306)

SERVICE_PROBE_PORTS: dict[int, bytes] = {
    21: b"",
    22: b"",
    23: b"",
    25: b"EHLO\r\n",
    110: b"",
    143: b"",
    3306: b"",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    6379: b"PING\r\n",
}

MAX_DISCOVERY_HOSTS = 256

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SSH_VERSION_RE = re.compile(r"SSH-\d+\.\d+[-_](\S+)")
_FTP_BANNER_RE = re.compile(r"220[- ](.+)")
_SMTP_BANNER_RE = re.compile(r"220[- ](.+)")
_SERVER_HEADER_RE = re.compile(r"Server:\s*(.+)", re.IGNORECASE)


class ReconError(ArgisError):
    pass


@dataclass
class PortResult:
    port: int
    open: bool
    service_guess: str | None = None
    protocol: str = "tcp"


@dataclass
class WebResult:
    port: int
    scheme: str
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    error: str | None = None
    tech_stack: list[str] | None = None


_TECH_PATTERNS: list[tuple[str, str, str | None, str | None]] = [
    ("wordpress", r"wp-content|wp-includes|wordpress", "header", "x-powered-by"),
    ("drupal", r"Drupal|drupal.js", "header", "x-drupal-cache"),
    ("joomla", r"joomla", "header", "x-content-encoded-by"),
    ("laravel", r"laravel", "header", "x-powered-by"),
    ("symfony", r"symfony", "header", "x-symfony"),
    ("django", r"django|csrftoken", "header", "x-powered-by"),
    ("rails", r"rails|ruby on rails", "header", "x-powered-by"),
    ("express", r"express", "header", "x-powered-by"),
    ("next.js", r"next.js", "header", "x-powered-by"),
    ("nuxt", r"nuxt", "header", "x-powered-by"),
    ("gatsby", r"gatsby", "header", "x-powered-by"),
    ("react", r"react|reactjs", "body", None),
    ("vue", r"vuejs|vue.js", "body", None),
    ("angular", r"angular|ng-", "body", None),
    ("jquery", r"jquery", "body", None),
    ("bootstrap", r"bootstrap", "body", None),
    ("tailwind", r"tailwind", "body", None),
    ("cloudflare", r"cloudflare", "header", "server"),
    ("nginx", r"nginx", "header", "server"),
    ("apache", r"apache", "header", "server"),
    ("iis", r"iis", "header", "server"),
    ("caddy", r"caddy", "header", "server"),
    ("python", r"python", "header", "x-powered-by"),
    ("php", r"php", "header", "x-powered-by"),
    ("perl", r"perl", "header", "x-powered-by"),
    ("openresty", r"openresty", "header", "server"),
    ("varnish", r"varnish", "header", "x-varnish"),
    ("google analytics", r"google-analytics|gtag|ga\(", "body", None),
    ("hotjar", r"hotjar", "body", None),
    ("intercom", r"intercom", "body", None),
    ("stripe", r"stripe\.com", "body", None),
    ("shopify", r"shopify", "header", "x-powered-by"),
    ("woocommerce", r"woocommerce", "body", None),
    ("magento", r"magento", "header", "x-powered-by"),
]


def detect_tech_stack(headers: dict, body: str) -> list[str]:
    found: list[str] = []
    body_lower = body[:10000].lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for name, pattern, source, header_name in _TECH_PATTERNS:
        if source == "header" and header_name:
            val = headers_lower.get(header_name, "")
            if re.search(pattern, val, re.IGNORECASE):
                found.append(name)
        elif source == "body":
            if re.search(pattern, body_lower):
                if name not in found:
                    found.append(name)
        else:
            if re.search(pattern, body_lower, re.IGNORECASE) or any(
                re.search(pattern, v, re.IGNORECASE) for v in headers_lower.values()
            ):
                if name not in found:
                    found.append(name)

    return found


@dataclass
class BannerResult:
    port: int
    banner: str | None = None
    version: str | None = None
    error: str | None = None


@dataclass
class HostResult:
    ip: str
    alive: bool


@dataclass
class ReconReport:
    target: str
    open_ports: list[PortResult] = field(default_factory=list)
    web_results: list[WebResult] = field(default_factory=list)
    banners: list[BannerResult] = field(default_factory=list)
    dns: DNSResult | None = None
    whois: str | None = None
    os_guesses: list[OSMatch] = field(default_factory=list)
    traceroute_hops: list[TracerouteHop] = field(default_factory=list)


@dataclass
class UdpResult:
    port: int
    open: bool
    service_guess: str | None = None
    response: str | None = None


@dataclass
class OSMatch:
    name: str
    accuracy: int
    detail: str | None = None


@dataclass
class TracerouteHop:
    ttl: int
    ip: str | None
    hostname: str | None = None
    rtt: float | None = None
    alive: bool = False


DEFAULT_PROBE_PORT = 33434

_OS_TTL_SIGNATURES: list[tuple[int, str, int]] = [
    (64, "Linux/Unix", 70),
    (128, "Windows", 80),
    (255, "Cisco/Network Equipment", 60),
    (60, "FreeBSD", 50),
    (254, "Solaris", 40),
]

_OS_BANNER_SIGNATURES: list[tuple[str, str, int]] = [
    (r"OpenSSH.*Ubuntu", "Ubuntu Linux", 90),
    (r"OpenSSH.*Debian", "Debian Linux", 85),
    (r"OpenSSH.*FreeBSD", "FreeBSD", 80),
    (r"OpenSSH.*OpenBSD", "OpenBSD", 80),
    ("OpenSSH", "OpenSSH (generic)", 40),
    ("PuTTY", "Windows (PuTTY)", 50),
    (r"Apache/2\.4\.\d+ \(Ubuntu", "Ubuntu Linux", 75),
    (r"Apache/2\.4\.\d+ \(Debian", "Debian Linux", 75),
    (r"Apache/2\.4\.\d+ \(CentOS", "CentOS Linux", 75),
    (r"Apache/2\.4\.\d+ \(Red Hat", "Red Hat Linux", 75),
    (r"Apache/2\.4\.\d+ \(Win", "Windows", 60),
    (r"Apache/2\.4\.\d+ \(FreeBSD", "FreeBSD", 70),
    ("Microsoft-IIS", "Windows Server", 70),
    (r"nginx/\d+\.\d+\.\d+ \(Ubuntu", "Ubuntu Linux", 65),
    (r"nginx/\d+\.\d+\.\d+ \(Debian", "Debian Linux", 65),
    (r"nginx/\d+\.\d+\.\d+ \(CentOS", "CentOS Linux", 65),
    (r"nginx/\d+\.\d+\.\d+ \(FreeBSD", "FreeBSD", 65),
]


def detect_os_from_ttl(ttl: int) -> list[OSMatch]:
    guesses: list[OSMatch] = []
    for sig_ttl, name, accuracy in _OS_TTL_SIGNATURES:
        if abs(ttl - sig_ttl) <= 5:
            guesses.append(OSMatch(name=name, accuracy=accuracy, detail=f"TTL={ttl}"))
    return guesses


def detect_os_from_banners(banners: list[BannerResult]) -> list[OSMatch]:
    matches: list[OSMatch] = []
    for b in banners:
        if not b.banner:
            continue
        for pattern, name, accuracy in _OS_BANNER_SIGNATURES:
            if re.search(pattern, b.banner, re.IGNORECASE):
                matches.append(
                    OSMatch(name=name, accuracy=accuracy, detail=f"port {b.port}: {b.banner[:80]}")
                )
    return matches


def merge_os_guesses(ttl_guesses: list[OSMatch], banner_guesses: list[OSMatch]) -> list[OSMatch]:
    combined: dict[str, OSMatch] = {}
    for g in ttl_guesses:
        combined[g.name] = g
    for g in banner_guesses:
        if g.name in combined:
            combined[g.name].accuracy = min(100, combined[g.name].accuracy + 15)
        else:
            combined[g.name] = g
    return sorted(combined.values(), key=lambda x: x.accuracy, reverse=True)


async def traceroute(
    target: str,
    *,
    max_hops: int = 30,
    timeout: float = 2.0,
    probe_port: int = DEFAULT_PROBE_PORT,
) -> list[TracerouteHop]:
    hops: list[TracerouteHop] = []
    dest_ip = await _resolve_target(target)
    if not dest_ip:
        return hops

    for ttl in range(1, max_hops + 1):
        start = time.monotonic()
        hop = await _probe_hop(dest_ip, ttl, probe_port, timeout)
        if hop.alive:
            hop.rtt = (time.monotonic() - start) * 1000
        hops.append(hop)
        if hop.alive and hop.ip == dest_ip:
            break

    return hops


async def _resolve_target(target: str) -> str | None:
    try:
        info = await asyncio.get_event_loop().getaddrinfo(target, 80)
        if info:
            return info[0][4][0]
    except Exception:
        return None


async def _probe_hop(dest_ip: str, ttl: int, probe_port: int, timeout: float) -> TracerouteHop:
    try:
        loop = asyncio.get_event_loop()
        conn = asyncio.open_connection(dest_ip, probe_port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return TracerouteHop(ttl=ttl, ip=dest_ip, alive=True)
    except ConnectionRefusedError:
        return TracerouteHop(ttl=ttl, ip=dest_ip, alive=True)
    except (asyncio.TimeoutError, OSError):
        return TracerouteHop(ttl=ttl, ip=None, alive=False)


ALL_TCP_PORTS: tuple[int, ...] = tuple(range(1, 65536))

ALL_UDP_PORTS: tuple[int, ...] = tuple(range(1, 65536))

TIMING_TEMPLATES: dict[int, dict] = {
    0: {"timeout": 300, "concurrency": 1, "label": "Paranoid"},
    1: {"timeout": 15, "concurrency": 5, "label": "Sneaky"},
    2: {"timeout": 5, "concurrency": 10, "label": "Polite"},
    3: {"timeout": 2, "concurrency": 100, "label": "Normal"},
    4: {"timeout": 1, "concurrency": 200, "label": "Aggressive"},
    5: {"timeout": 0.5, "concurrency": 500, "label": "Insane"},
}


def apply_timing(timing: int) -> dict:
    return TIMING_TEMPLATES.get(timing, TIMING_TEMPLATES[3])


_COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

_UDP_SERVICES: dict[int, str] = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    123: "ntp", 161: "snmp", 162: "snmptrap", 500: "isakmp",
    514: "syslog", 520: "rip", 1900: "ssdp", 4500: "ipsec-nat-t",
    5353: "mdns",
}


def _extract_version(port: int, banner_text: str) -> str | None:
    if port == 22:
        m = _SSH_VERSION_RE.search(banner_text)
        if m:
            return m.group(1)
    if port == 21:
        m = _FTP_BANNER_RE.search(banner_text)
        if m:
            return m.group(1).strip()
    if port in (25, 587):
        m = _SMTP_BANNER_RE.search(banner_text)
        if m:
            return m.group(1).strip()
    return None


async def _check_port(host: str, port: int, timeout: float) -> PortResult:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(port=port, open=True, service_guess=_COMMON_SERVICES.get(port))
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False)


async def port_scan(
    target: str,
    *,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 2.0,
    concurrency: int = 100,
) -> list[PortResult]:
    if not target or "/" in target:
        raise ReconError(
            f"'{target}' does not look like a single host. Provide a "
            "hostname or IP, not a URL or CIDR range."
        )

    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_check(port: int) -> PortResult:
        async with semaphore:
            return await _check_port(target, port, timeout)

    results = await asyncio.gather(*(bounded_check(p) for p in ports))
    return sorted(results, key=lambda r: r.port)


async def _probe_web_port(client: httpx.AsyncClient, host: str, port: int) -> WebResult:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/" if port not in (80, 443) else f"{scheme}://{host}/"

    try:
        response = await client.get(url)
    except httpx.RequestError as exc:
        return WebResult(port=port, scheme=scheme, error=str(exc.__class__.__name__))

    title_match = _TITLE_RE.search(response.text[:5000])
    title = title_match.group(1).strip() if title_match else None

    tech_stack = None
    try:
        tech_stack = detect_tech_stack(dict(response.headers), response.text[:10000])
    except Exception:
        pass

    return WebResult(
        port=port,
        scheme=scheme,
        status_code=response.status_code,
        server=response.headers.get("server"),
        title=title,
        tech_stack=tech_stack,
    )


async def web_probe(
    target: str,
    *,
    ports: tuple[int, ...] = WEB_PORTS,
    open_ports: list[PortResult] | None = None,
    timeout: float = 5.0,
) -> list[WebResult]:
    candidate_ports = ports
    if open_ports is not None:
        open_set = {r.port for r in open_ports if r.open}
        candidate_ports = tuple(p for p in ports if p in open_set)

    if not candidate_ports:
        return []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=True, verify=False
    ) as client:
        results = await asyncio.gather(
            *(_probe_web_port(client, target, p) for p in candidate_ports)
        )
    return list(results)


async def _grab_one_banner(
    host: str, port: int, timeout: float, read_bytes: int, send_probe: bool = False
) -> BannerResult:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        probe = SERVICE_PROBE_PORTS.get(port, b"")
        if probe and send_probe:
            try:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=timeout)
            except Exception:
                pass

        try:
            data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not data:
            return BannerResult(port=port, banner=None)
        text = data.decode("utf-8", errors="replace").strip()
        version = _extract_version(port, text)
        return BannerResult(port=port, banner=text[:200] if text else None, version=version)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        return BannerResult(port=port, error=str(exc.__class__.__name__))


async def banner_grab(
    target: str,
    *,
    open_ports: list[PortResult] | None = None,
    ports: tuple[int, ...] = BANNER_PORTS,
    timeout: float = 3.0,
    read_bytes: int = 1024,
    send_probes: bool = True,
) -> list[BannerResult]:
    candidate_ports = ports
    if open_ports is not None:
        open_set = {r.port for r in open_ports if r.open}
        candidate_ports = tuple(p for p in ports if p in open_set)

    if not candidate_ports:
        return []

    results = await asyncio.gather(
        *(_grab_one_banner(target, p, timeout, read_bytes, send_probes) for p in candidate_ports)
    )
    return list(results)


async def udp_port_scan(
    target: str,
    *,
    ports: tuple[int, ...] = DEFAULT_UDP_PORTS,
    timeout: float = 2.0,
    concurrency: int = 50,
) -> list[UdpResult]:
    results: list[UdpResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def _udp_probe(port: int) -> UdpResult:
        async with semaphore:
            service = _UDP_SERVICES.get(port)
            try:
                transport, protocol = await asyncio.wait_for(
                    _create_udp_connection(target, port),
                    timeout=timeout,
                )
                transport.close()
                return UdpResult(port=port, open=True, service_guess=service)
            except (asyncio.TimeoutError, OSError):
                return UdpResult(port=port, open=False, service_guess=service)

    probes = await asyncio.gather(*(_udp_probe(p) for p in ports))
    results = list(probes)
    return [r for r in results if r.open or True]


async def _create_udp_connection(host: str, port: int):
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(host, port),
    )
    return transport, protocol


async def dns_enum(hostname: str) -> DNSResult:
    return await asyncio.to_thread(resolve_dns_full, hostname)


def run_whois(domain: str) -> str:
    return whois_lookup(domain)


async def _probe_host_alive(ip: str, probe_ports: tuple[int, ...], timeout: float) -> HostResult:
    for port in probe_ports:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return HostResult(ip=ip, alive=True)
        except ConnectionRefusedError:
            return HostResult(ip=ip, alive=True)
        except (asyncio.TimeoutError, OSError):
            continue
    return HostResult(ip=ip, alive=False)


async def discover_hosts(
    cidr: str,
    *,
    probe_ports: tuple[int, ...] = (80, 443, 22),
    timeout: float = 1.0,
    concurrency: int = 100,
) -> list[HostResult]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ReconError(f"'{cidr}' is not a valid CIDR range: {exc}") from exc

    hosts = list(network.hosts()) or [network.network_address]
    if len(hosts) > MAX_DISCOVERY_HOSTS:
        raise ReconError(
            f"'{cidr}' contains {len(hosts)} hosts, which exceeds the "
            f"{MAX_DISCOVERY_HOSTS}-host discovery cap. Narrow the range "
            "(e.g. a /24 or smaller)."
        )

    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_probe(ip: str) -> HostResult:
        async with semaphore:
            return await _probe_host_alive(ip, probe_ports, timeout)

    results = await asyncio.gather(*(bounded_probe(str(ip)) for ip in hosts))
    return results


async def run_recon(
    target: str,
    *,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    do_web: bool = True,
    do_banners: bool = True,
    do_dns: bool = False,
    do_whois: bool = False,
    do_udp: bool = False,
    do_os_detection: bool = False,
    do_traceroute: bool = False,
    do_syn_scan: bool = False,
    timing: int = 3,
    port_timeout: float = 2.0,
    port_concurrency: int = 100,
) -> ReconReport:
    tmpl = apply_timing(timing)
    timeout = port_timeout or tmpl["timeout"]
    concurrency = port_concurrency or tmpl["concurrency"]

    open_ports: list[PortResult] = []
    if not do_syn_scan:
        open_ports = await port_scan(
            target, ports=ports, timeout=timeout, concurrency=concurrency
        )
    else:
        open_ports = await port_scan(
            target, ports=ports, timeout=timeout, concurrency=concurrency
        )

    web_results: list[WebResult] = []
    if do_web:
        web_results = await web_probe(target, open_ports=open_ports)

    banners: list[BannerResult] = []
    if do_banners:
        banners = await banner_grab(target, open_ports=open_ports)

    dns_result: DNSResult | None = None
    if do_dns:
        dns_result = await dns_enum(target)

    whois_text: str | None = None
    if do_whois:
        whois_text = await asyncio.to_thread(run_whois, target)

    os_guesses: list[OSMatch] = []
    if do_os_detection and banners:
        ttl_guesses = detect_os_from_ttl(64)
        banner_guesses = detect_os_from_banners(banners)
        os_guesses = merge_os_guesses(ttl_guesses, banner_guesses)

    traceroute_hops: list[TracerouteHop] = []
    if do_traceroute:
        traceroute_hops = await traceroute(target, timeout=min(timeout, 2.0))

    return ReconReport(
        target=target,
        open_ports=open_ports,
        web_results=web_results,
        banners=banners,
        dns=dns_result,
        whois=whois_text,
        os_guesses=os_guesses,
        traceroute_hops=traceroute_hops,
    )
