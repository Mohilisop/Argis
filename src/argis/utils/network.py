from __future__ import annotations

import random
import socket
from dataclasses import dataclass, field

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
    "Safari/604.1",
]

TOR_PROXY_URL = "socks5://127.0.0.1:9050"


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def build_client(
    *,
    proxy: str | None = None,
    use_tor: bool = False,
    timeout: float = 7.0,
    http2: bool = False,
) -> httpx.AsyncClient:
    proxy_url = proxy or (TOR_PROXY_URL if use_tor else None)

    kwargs: dict = {
        "http2": http2,
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": True,
    }
    if proxy_url:
        kwargs["proxy"] = proxy_url

    return httpx.AsyncClient(**kwargs)


@dataclass
class DNSRecord:
    type: str
    value: str
    ttl: int | None = None


@dataclass
class DNSResult:
    hostname: str
    records: list[DNSRecord] = field(default_factory=list)
    error: str | None = None


_DEFAULT_WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "dev": "whois.nic.dev",
    "app": "whois.nic.app",
    "cloud": "whois.nic.cloud",
}


def resolve_dns(hostname: str) -> DNSResult:
    records: list[DNSRecord] = []
    try:
        info = socket.getaddrinfo(hostname, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = set()
        for res in info:
            ip = res[4][0]
            if ip not in seen:
                seen.add(ip)
                family = "IPv4" if res[0] == socket.AF_INET else "IPv6"
                records.append(DNSRecord(type=family, value=ip))
        return DNSResult(hostname=hostname, records=records)
    except socket.gaierror as exc:
        return DNSResult(hostname=hostname, error=str(exc))


def resolve_dns_full(
    hostname: str,
    timeout: float = 3.0,
) -> DNSResult:
    result = resolve_dns(hostname)
    if result.error:
        return result

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        try:
            canon = socket.getnameinfo((result.records[0].value, 0), socket.NI_NAMEREQD)
            result.records.append(
                DNSRecord(type="PTR", value=canon[0])
            )
        except (OSError, socket.gaierror):
            pass

        try:
            host = socket.gethostbyname_ex(hostname)
            if host[0] and host[0] != hostname:
                result.records.append(DNSRecord(type="CNAME", value=host[0]))
        except socket.gaierror:
            pass
    finally:
        socket.setdefaulttimeout(old_timeout)

    return result


def whois_lookup(domain: str, timeout: float = 10.0) -> str:
    def _get_tld(domain: str) -> str:
        parts = domain.rsplit(".", 2)
        if len(parts) >= 2 and len(parts[-1]) <= 3:
            return parts[-1]
        return parts[-1] if len(parts) >= 2 else "com"

    tld = _get_tld(domain)
    server = _DEFAULT_WHOIS_SERVERS.get(tld, "whois.verisign-grs.com")

    try:
        sock = socket.create_connection((server, 43), timeout=timeout)
        sock.sendall(f"{domain}\r\n".encode("utf-8"))
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        text = response.decode("utf-8", errors="replace")
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("%") and not stripped.startswith(">>>"):
                lines.append(stripped)
        return "\n".join(lines[:60])
    except (socket.timeout, OSError) as exc:
        return f"Error: {exc}"
