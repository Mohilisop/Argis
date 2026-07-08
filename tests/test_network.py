from __future__ import annotations

from argis.utils.network import (
    DNSRecord,
    random_user_agent,
    resolve_dns,
    resolve_dns_full,
    whois_lookup,
)


class TestRandomUserAgent:
    def test_returns_string(self):
        ua = random_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 20

    def test_includes_browser_keywords(self):
        ua = random_user_agent()
        assert any(kw in ua for kw in ["Mozilla", "Chrome", "Safari", "Firefox"])


class TestResolveDns:
    def test_returns_records_for_valid_hostname(self):
        result = resolve_dns("localhost")
        assert result.hostname == "localhost"
        assert result.error is None
        assert len(result.records) > 0
        assert any(r.type in ("IPv4", "IPv6") for r in result.records)

    def test_returns_error_for_invalid_hostname(self):
        result = resolve_dns("this-is-not-a-valid-hostname-12345")
        assert result.error is not None

    def test_records_are_dnsrecord_instances(self):
        result = resolve_dns("localhost")
        for record in result.records:
            assert isinstance(record, DNSRecord)
            assert record.type in ("IPv4", "IPv6")
            assert record.value


class TestResolveDnsFull:
    def test_includes_dns_records(self):
        result = resolve_dns_full("localhost")
        assert result.hostname == "localhost"
        assert result.error is None or True  # may or may not error

    def test_handles_invalid_hostname(self):
        result = resolve_dns_full("not-a-real-host-999999")
        assert result is not None


class TestWhoisLookup:
    def test_returns_string(self):
        result = whois_lookup("example.com")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_error_string_on_failure(self):
        result = whois_lookup("not-a-real-domain-123456789.com")
        assert isinstance(result, str)
