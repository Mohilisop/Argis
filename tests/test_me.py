import pytest

from argis.me import ThreatReport, FixAction, run_me


def test_threat_report_defaults():
    r = ThreatReport(handle="testuser")
    assert r.handle == "testuser"
    assert r.risk_level == "LOW"
    assert r.generated_at is not None


def test_threat_report_risk_high_score():
    r = ThreatReport(handle="testuser")
    r.exposure_score = 75
    assert r.risk_level == "HIGH"


def test_threat_report_risk_high_breaches():
    r = ThreatReport(handle="testuser")
    r.exposure_score = 20
    r.emails_breached = 2
    assert r.risk_level == "HIGH"


def test_threat_report_risk_high_impersonators():
    r = ThreatReport(handle="testuser")
    r.exposure_score = 20
    r.impersonators_found = 1
    assert r.risk_level == "HIGH"


def test_threat_report_risk_medium_score():
    r = ThreatReport(handle="testuser")
    r.exposure_score = 45
    assert r.risk_level == "MEDIUM"


def test_threat_report_risk_medium_breach():
    r = ThreatReport(handle="testuser")
    r.exposure_score = 20
    r.emails_breached = 1
    assert r.risk_level == "MEDIUM"


def test_fix_action_defaults():
    a = FixAction()
    assert a.priority == 0
    assert a.points_saved == 0.0
    assert a.what == ""
    assert a.where == []


def test_fix_action_full():
    a = FixAction(priority=1, points_saved=20.0, what="Fix it", where=["email@x.com"])
    assert a.priority == 1
    assert a.points_saved == 20.0
    assert a.what == "Fix it"
    assert a.where == ["email@x.com"]


@pytest.mark.asyncio
async def test_run_me_empty_scan():
    """run_me gracefully handles an empty scan (no found accounts)."""
    from unittest.mock import patch

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        async def run_scan(self, quiet=True):
            return {}

        def _filter_sites(self):
            return {}

    with patch("argis.core.ArgisEngine", FakeEngine):
        report = await run_me("ghost", timeout=5.0, concurrency=5)
        assert report.handle == "ghost"
        assert report.accounts_found == 0
        assert report.platforms_scanned == 0
        assert report.risk_level == "LOW"
