from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

import httpx

GEOIP_API_BASE = "https://api.ipgeolocation.io/ipgeo"
PUBLIC_IP_PROVIDERS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
]

GEOIP_KEY_ENV_VAR = "ARGIS_GEOIP_KEY"


def resolve_geoip_key(cli_key: str | None = None) -> str | None:
    if cli_key:
        return cli_key
    env_key = os.environ.get(GEOIP_KEY_ENV_VAR)
    if env_key:
        return env_key
    try:
        from argis.utils.config import load_config

        cfg = load_config()
        cfg_key = cfg.get("geoip_key")
        if cfg_key:
            return cfg_key
    except Exception:
        pass
    return None


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


@dataclass
class GeoIPResult:
    ip: str
    country_name: str | None = None
    country_code2: str | None = None
    state_prov: str | None = None
    city: str | None = None
    zipcode: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    organization: str | None = None
    timezone: str | None = None
    currency: str | None = None
    error: str | None = None


async def geoip_lookup(
    ip: str,
    *,
    api_key: str | None = None,
    timeout: float = 10.0,
) -> GeoIPResult:
    key = resolve_geoip_key(api_key)
    if not key:
        return GeoIPResult(
            ip=ip,
            error="No API key found. Set ARGIS_GEOIP_KEY env var, add geoip_key to ~/.argis/config.json, or pass --geo-key",
        )

    if _is_private_ip(ip):
        return GeoIPResult(
            ip=ip,
            country_name="Private/Reserved IP",
            error=f"{ip} is a private or reserved IP address and cannot be geolocated",
        )

    params = {
        "apiKey": key,
        "ip": ip,
        "fields": "geo,time_zone,currency,isp,organization",
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        try:
            resp = await client.get(GEOIP_API_BASE, params=params)
            if resp.status_code in (423, 403, 429):
                return GeoIPResult(
                    ip=ip,
                    error=f"API key rejected ({resp.status_code}). Set ARGIS_GEOIP_KEY env var or pass --geo-key",
                )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            return GeoIPResult(ip=ip, error=f"HTTP {exc.response.status_code}: {exc.response.text[:100]}")
        except httpx.RequestError as exc:
            return GeoIPResult(ip=ip, error=f"Request failed: {exc}")
        except Exception as exc:
            return GeoIPResult(ip=ip, error=str(exc))

    if not data or data.get("ip") is None:
        return GeoIPResult(ip=ip, error="No data returned")

    return GeoIPResult(
        ip=data.get("ip", ip),
        country_name=data.get("country_name"),
        country_code2=data.get("country_code2"),
        state_prov=data.get("state_prov"),
        city=data.get("city"),
        zipcode=data.get("zipcode"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        isp=data.get("isp"),
        organization=data.get("organization"),
        timezone=data.get("time_zone", {}).get("name") if isinstance(data.get("time_zone"), dict) else None,
        currency=data.get("currency", {}).get("code") if isinstance(data.get("currency"), dict) else None,
    )


async def geoip_bulk(
    ips: list[str],
    *,
    api_key: str | None = None,
    timeout: float = 15.0,
) -> list[GeoIPResult]:
    results: list[GeoIPResult] = []
    for ip in ips:
        result = await geoip_lookup(ip, api_key=api_key, timeout=timeout)
        results.append(result)
    return results


async def get_public_ip(timeout: float = 5.0) -> str | None:
    for provider in PUBLIC_IP_PROVIDERS:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                resp = await client.get(provider)
                if resp.is_success:
                    ip = resp.text.strip()
                    if ip:
                        return ip
        except Exception:
            continue
    return None
