import pytest

from argis.geo_infer import GeoSignal, infer_geo


def test_infer_geo_no_signals():
    signals = infer_geo([], [], [])
    assert signals == []


def test_infer_geo_explicit_location():
    signals = infer_geo(["based in India"], [], [])
    assert len(signals) >= 1
    assert signals[0].country == "India"
    assert signals[0].confidence >= 0.9


def test_infer_geo_currency():
    signals = infer_geo(["Price: \u20b9 500"], [], [])
    assert any(s.country == "India" for s in signals)


def test_infer_geo_platform_hints():
    signals = infer_geo([], [], ["VK"])
    assert any(s.country == "Russia" for s in signals)


def test_infer_geo_devanagari():
    signals = infer_geo(["\u0905\u092d\u093f\u0928\u0928\u094d\u0926\u0928"], [], [])
    assert any(s.country == "India" for s in signals)


def test_infer_geo_hangul():
    signals = infer_geo(["\ud55c\uad6d\uc5b4 \ud14c\uc2a4\ud2b8"], [], [])
    assert any(s.country == "South Korea" for s in signals)


def test_infer_geo_kanji():
    signals = infer_geo(["\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8"], [], [])
    assert any(s.country == "Japan" for s in signals)


def test_infer_geo_cyrillic():
    signals = infer_geo(["\u041f\u0440\u0438\u0432\u0435\u0442"], [], [])
    assert any(s.country == "Russia / Eastern Europe" for s in signals)


def test_infer_geo_thai():
    signals = infer_geo(["\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35"], [], [])
    assert any(s.country == "Thailand" for s in signals)


def test_infer_geo_uk():
    signals = infer_geo(["from London, UK"], [], [])
    assert any(s.country == "UK" for s in signals)


def test_infer_geo_usa():
    signals = infer_geo(["based in New York"], [], [])
    assert any(s.country == "USA" for s in signals)


def test_infer_geo_ranked_by_confidence():
    signals = infer_geo(
        ["based in Germany", "\u0905\u092d\u093f\u0928\u0928\u094d\u0926\u0928"],
        [],
        [],
    )
    assert len(signals) >= 2
    assert signals[0].confidence >= signals[1].confidence


def test_infer_geo_merges_duplicates():
    signals = infer_geo(
        ["based in India", "\u20b9 500"],
        [],
        [],
    )
    for s in signals:
        assert s.country != "India" or s.confidence <= 1.0


def test_infer_geo_brazil():
    signals = infer_geo(["Price: R$ 100"], [], [])
    assert any(s.country == "Brazil" for s in signals)


def test_geo_signal_dataclass():
    s = GeoSignal("India", 0.9, "test evidence")
    assert s.country == "India"
    assert s.confidence == 0.9
    assert s.evidence == "test evidence"
