"""Impersonation early-warning: generate lookalike handles, scan them, and
correlate the hits against the user's real identity.

Given a handle you own, this builds the space of confusable variants a
squatter/impersonator would plausibly register -- separators, affixes, digit
leetspeak, and Unicode homoglyphs -- scans every variant across all platforms,
then uses the correlation engine to score how much each *registered* lookalike
resembles YOUR reference profile. High resemblance on a handle that isn't yours
= a likely impersonator.

Ethics: this surfaces accounts impersonating the operator. It compares public
profile signals against a reference the operator supplies; it does not identify
or deanonymize third parties.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from argis.core import ArgisEngine
from argis.correlate import Signals, similarity, _fetch_signals
from argis.utils.network import build_client

_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430", "\u03b1"],
    "c": ["\u0441"],
    "e": ["\u0435", "\u04bd"],
    "i": ["\u0456", "1", "l"],
    "o": ["\u043e", "0"],
    "p": ["\u0440"],
    "s": ["\u0455", "5"],
    "x": ["\u0445"],
    "y": ["\u0443"],
    "l": ["1", "i"],
    "g": ["9"],
    "b": ["6"],
    "t": ["7"],
}
_SEPARATORS = ["", "_", ".", "-"]
_SUFFIXES = [
    "1", "01", "_", ".", "official", "real", "hq", "team", "tv", "yt",
    "x", "xo", "_official", "_real", "2", "123",
]
_PREFIXES = ["the", "real", "official", "im", "its", "mr", "iam"]


def generate_variants(handle: str, *, max_variants: int = 120) -> list[str]:
    """Build confusable variants of `handle`, most-plausible first."""
    h = handle.lower()
    out: list[str] = []
    seen: set[str] = {h}

    def add(v: str) -> None:
        if v and v != h and v not in seen and len(v) <= 40:
            seen.add(v)
            out.append(v)

    core = h.replace("_", " ").replace(".", " ").replace("-", " ")
    words = core.split()
    if len(words) > 1:
        for sep in _SEPARATORS:
            add(sep.join(words))

    for suf in _SUFFIXES:
        add(h + suf)
        add(f"{h}_{suf}" if not suf.startswith("_") else h + suf)
    for pre in _PREFIXES:
        add(pre + h)
        add(f"{pre}_{h}")

    for i, ch in enumerate(h):
        for repl in _HOMOGLYPHS.get(ch, []):
            add(h[:i] + repl + h[i + 1:])

    add(h + h[-1])
    for i in range(len(h)):
        add(h[:i] + h[i + 1:])

    return out[:max_variants]


@dataclass
class Match:
    variant: str
    platform: str
    url: str
    score: float
    display_name: str = ""
    detail: dict = field(default_factory=dict)


@dataclass
class GuardReport:
    handle: str
    reference: Signals | None
    variants_scanned: int
    hits: int
    matches: list[Match]
    warn_threshold: float

    @property
    def impersonators(self) -> list[Match]:
        return [m for m in self.matches if m.score >= self.warn_threshold]

    @property
    def lookalikes(self) -> list[Match]:
        return [m for m in self.matches if m.score < self.warn_threshold]


async def _reference_signals(
    client, handle: str, ref_url: str | None, found: dict[str, dict],
) -> Signals | None:
    if ref_url:
        return await _fetch_signals(client, "reference", ref_url, handle, True)
    best: Signals | None = None
    for platform, info in found.items():
        s = await _fetch_signals(client, platform, info["url"], handle, True)
        if s.error:
            continue
        score = (
            (1 if s.avatar_hash is not None else 0) * 3
            + (1 if s.display_name else 0)
            + (1 if s.bio else 0)
        )
        cur = (
            (1 if best.avatar_hash is not None else 0) * 3
            + (1 if best.display_name else 0)
            + (1 if best.bio else 0)
        ) if best else -1
        if best is None or score > cur:
            best = s
    return best


async def guard(
    handle: str,
    *,
    reference_url: str | None = None,
    max_variants: int = 120,
    warn_threshold: float = 0.55,
    category: tuple[str, ...] | None = None,
    timeout: float = 12.0,
    concurrency: int = 20,
    proxy: str | None = None,
    use_tor: bool = False,
) -> GuardReport:
    exact = ArgisEngine(handle, timeout=timeout, concurrency=concurrency,
                        categories=category, proxy=proxy, use_tor=use_tor)
    exact_results = await exact.run_scan(quiet=True)
    exact_found = {p: r for p, r in exact_results.items()
                   if r.get("status") == "FOUND" and r.get("url")}

    async with build_client(proxy=proxy, use_tor=use_tor, timeout=timeout) as client:
        reference = await _reference_signals(
            client, handle, reference_url, exact_found)

    variants = generate_variants(handle, max_variants=max_variants)
    sem = asyncio.Semaphore(max(2, concurrency // 4))

    async def scan_variant(v: str) -> tuple[str, dict]:
        async with sem:
            eng = ArgisEngine(v, timeout=timeout, concurrency=concurrency,
                              categories=category, proxy=proxy, use_tor=use_tor)
            return v, await eng.run_scan(quiet=True)

    scanned = await asyncio.gather(*(scan_variant(v) for v in variants))

    variant_hits: list[tuple[str, str, str]] = []
    for v, res in scanned:
        for platform, info in res.items():
            if info.get("status") == "FOUND" and info.get("url"):
                variant_hits.append((v, platform, info["url"]))

    matches: list[Match] = []
    if reference is not None:
        sem2 = asyncio.Semaphore(concurrency)
        async with build_client(proxy=proxy, use_tor=use_tor,
                                timeout=timeout) as client:
            async def score_hit(v: str, platform: str, url: str) -> Match:
                async with sem2:
                    s = await _fetch_signals(client, platform, url, v, True)
                sc, detail = similarity(reference, s) if s.error is None else (0.0, {})
                return Match(v, platform, url, round(sc, 3),
                             s.display_name, detail)
            matches = list(await asyncio.gather(
                *(score_hit(v, p, u) for v, p, u in variant_hits)))
    else:
        matches = [Match(v, p, u, 0.0) for v, p, u in variant_hits]

    matches.sort(key=lambda m: -m.score)
    return GuardReport(
        handle=handle, reference=reference, variants_scanned=len(variants),
        hits=len(variant_hits), matches=matches, warn_threshold=warn_threshold,
    )