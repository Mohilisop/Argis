"""Turn a raw Argis scan into a full person-dossier: rich CLI output plus a
self-contained HTML report (found accounts + extracted identity info + an
embedded footprint graph), in the spirit of Maigret's reports.

Enrichment (name/bio/avatar/links/emails per profile) reuses correlate.
_fetch_signals when available; without it, the dossier still renders from the
base scan (status + url + any emails core.py already found).
"""

from __future__ import annotations

import asyncio
import html
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Account:
    platform: str
    url: str
    category: str = "uncategorized"
    display_name: str = ""
    bio: str = ""
    avatar_url: str = ""
    emails: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class Dossier:
    username: str
    accounts: list[Account]
    total_scanned: int
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"))

    @property
    def emails(self) -> list[str]:
        return sorted({e for a in self.accounts for e in a.emails})

    @property
    def names(self) -> list[str]:
        seen: dict[str, int] = defaultdict(int)
        for a in self.accounts:
            if a.display_name:
                seen[a.display_name] += 1
        return [n for n, _ in sorted(seen.items(), key=lambda x: -x[1])]

    @property
    def external_links(self) -> list[str]:
        return sorted({l for a in self.accounts for l in a.links})

    @property
    def by_category(self) -> dict[str, list[Account]]:
        groups: dict[str, list[Account]] = defaultdict(list)
        for a in sorted(self.accounts, key=lambda a: a.platform):
            groups[a.category].append(a)
        return dict(sorted(groups.items()))


async def build_dossier(
    username: str,
    results: dict[str, dict],
    *,
    site_categories: dict[str, str] | None = None,
    enrich: bool = True,
    timeout: float = 12.0,
    concurrency: int = 15,
    proxy: str | None = None,
    use_tor: bool = False,
    render: bool = False,
) -> Dossier:
    found = {p: r for p, r in results.items()
             if r.get("status") == "FOUND" and r.get("url")}
    cats = site_categories or {}

    accounts: list[Account] = []
    enriched = False
    if enrich:
        try:
            from argis.correlate import _fetch_signals, _OG_IMAGE
            from argis.intel_http import AsyncFetcher
            enriched = True
        except Exception:
            enriched = False

    if enriched:
        sem = asyncio.Semaphore(concurrency)
        async with AsyncFetcher(
            timeout=timeout, concurrency=concurrency, proxy=proxy,
            use_tor=use_tor, render=render,
        ) as fetcher:
            async def one(platform: str, info: dict) -> Account:
                async with sem:
                    s = await _fetch_signals(fetcher, platform, info["url"],
                                             username, True)
                return Account(
                    platform=platform, url=info["url"],
                    category=cats.get(platform, "uncategorized"),
                    display_name=getattr(s, "display_name", "") or "",
                    bio=getattr(s, "bio", "") or "",
                    avatar_url=getattr(s, "avatar_url", "") or "",
                    emails=list(getattr(s, "emails", []) or []),
                    links=sorted(getattr(s, "links", set()) or set()),
                )
            accounts = list(await asyncio.gather(
                *(one(p, i) for p, i in found.items())))
    else:
        for p, i in found.items():
            accounts.append(Account(
                platform=p, url=i["url"],
                category=cats.get(p, "uncategorized"),
                display_name=i.get("title") or "",
                bio=i.get("description") or "",
                emails=list(i.get("emails") or []),
            ))

    return Dossier(username=username, accounts=accounts,
                   total_scanned=len(results))


def print_dossier(dossier: Dossier, console) -> None:
    from rich.panel import Panel
    from rich.table import Table

    n = len(dossier.accounts)
    console.print(Panel.fit(
        f"[bold cyan]@{dossier.username}[/bold cyan]\n"
        f"[green]{n}[/green] accounts found across "
        f"{dossier.total_scanned} platforms scanned\n"
        f"[dim]{dossier.generated_at}[/dim]",
        title="\U0001f5c2 Argis dossier", border_style="cyan"))

    if dossier.names or dossier.emails or dossier.external_links:
        idt = Table(show_header=False, box=None, padding=(0, 2))
        idt.add_column(style="bold magenta")
        idt.add_column()
        if dossier.names:
            idt.add_row("Names", ", ".join(dossier.names[:5]))
        if dossier.emails:
            idt.add_row("Emails", ", ".join(dossier.emails))
        if dossier.external_links:
            idt.add_row("Ext. links", ", ".join(dossier.external_links[:8]))
        console.print(Panel(idt, title="Extracted identity",
                            border_style="magenta"))

    for cat, accts in dossier.by_category.items():
        t = Table(title=f"{cat}  ({len(accts)})", title_style="bold")
        t.add_column("Platform", style="cyan")
        t.add_column("Name")
        t.add_column("URL", style="dim")
        for a in accts:
            t.add_row(a.platform, a.display_name or "\u2014", a.url)
        console.print(t)


_CAT_ICON = {
    "coding": "\U0001f4bb", "social": "\U0001f4ac", "gaming": "\U0001f3ae",
    "media": "\U0001f3ac", "professional": "\U0001f454", "creative": "\U0001f3a8",
    "blogging": "\u270d\ufe0f", "finance": "\U0001f4b0", "lifestyle": "\U0001f31f",
    "messaging": "\U0001f4e8", "funding": "\U0001f91d", "identity": "\U0001faaa",
    "security": "\U0001f510", "docs": "\U0001f4c4", "startup": "\U0001f680",
    "uncategorized": "\U0001f517",
}


def _esc(x: str) -> str:
    return html.escape(str(x or ""), quote=True)


def to_html_report(dossier: Dossier, *, graph_payload: dict | None = None) -> str:
    d = dossier
    n = len(d.accounts)

    chips = ""
    for label, vals in [("name", d.names[:5]), ("email", d.emails),
                        ("link", d.external_links[:10])]:
        for v in vals:
            chips += (f'<span class="chip chip-{label}">'
                      f'{_esc(v)}</span>')
    if not chips:
        chips = '<span class="muted">No identity signals extracted.</span>'

    sections = ""
    for cat, accts in d.by_category.items():
        cards = ""
        for a in accts:
            avatar = (f'<img class="av" src="{_esc(a.avatar_url)}" '
                      f'alt="" loading="lazy">' if a.avatar_url
                      else '<div class="av av-ph"></div>')
            emails_html = "".join(
                f'<span class="chip chip-email">{_esc(e)}</span>'
                for e in a.emails)
            bio = f'<p class="bio">{_esc(a.bio)}</p>' if a.bio else ""
            cards += f"""<a class="card" href="{_esc(a.url)}" target="_blank" rel="noopener">
              {avatar}
              <div class="cbody">
                <div class="cplat">{_esc(a.platform)}</div>
                <div class="cname">{_esc(a.display_name) or '&mdash;'}</div>
                {bio}
                <div class="cchips">{emails_html}</div>
              </div></a>"""
        icon = _CAT_ICON.get(cat, "\U0001f517")
        sections += (f'<section><h2>{icon} {_esc(cat)} '
                   f'<span class="count">{len(accts)}</span></h2>\n'
                   f'<div class="grid">{cards}</div></section>\n')

    graph_block = ""
    if graph_payload:
        graph_block = f"""<section><h2>\U0001f578\ufe0f Footprint graph</h2>
          <div id="net"></div>
          <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
          <script>var gd={json.dumps(graph_payload)};
          new vis.Network(document.getElementById('net'),
            {{nodes:new vis.DataSet(gd.nodes),edges:new vis.DataSet(gd.edges)}},
            {{nodes:{{shape:'dot',font:{{color:'#c0caf5'}}}},
              physics:{{stabilization:true}},interaction:{{hover:true}}}});</script>
        </section>\n"""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argis dossier -- @{_esc(d.username)}</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--line:#334155;--ink:#e2e8f0;--mut:#64748b;--acc:#38bdf8;--ok:#22c55e}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--ink);line-height:1.5}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px 20px 60px}}
header.hero{{display:flex;justify-content:space-between;align-items:flex-end;
  border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:8px}}
h1{{color:var(--acc);margin:0;font-size:1.8rem}}
.sub{{color:var(--mut);font-size:.9rem}}
.cards-top{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:22px 0}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}}
.stat .big{{font-size:2rem;font-weight:700;color:var(--ok)}}
.stat .lbl{{color:var(--mut);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
.idpanel{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:26px}}
.idpanel h3{{margin:0 0 10px;color:var(--acc);font-size:1rem}}
.chip{{display:inline-block;padding:3px 10px;margin:3px;border-radius:999px;font-size:.82rem;
  background:#0b1220;border:1px solid var(--line)}}
.chip-email{{border-color:#e0af68;color:#f2c88f}}
.chip-name{{border-color:#bb9af7;color:#cbb6ff}}
.chip-link{{border-color:#7aa2f7;color:#a9c1ff}}
.muted{{color:var(--mut)}}
section{{margin:26px 0}}
section h2{{font-size:1.15rem;border-left:3px solid var(--acc);padding-left:10px;margin:0 0 12px}}
.count{{background:var(--card);border:1px solid var(--line);border-radius:999px;
  padding:1px 9px;font-size:.8rem;color:var(--mut);margin-left:6px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}}
.card{{display:flex;gap:12px;background:var(--card);border:1px solid var(--line);
  border-radius:12px;padding:12px;text-decoration:none;color:inherit;transition:.15s}}
.card:hover{{border-color:var(--acc);transform:translateY(-2px)}}
.av{{width:46px;height:46px;border-radius:10px;object-fit:cover;flex:0 0 auto;background:#0b1220}}
.av-ph{{background:linear-gradient(135deg,#334155,#1e293b)}}
.cplat{{font-weight:600;color:var(--acc)}}
.cname{{font-size:.92rem}}
.bio{{font-size:.8rem;color:var(--mut);margin:4px 0 0;max-height:3.2em;overflow:hidden}}
.cchips{{margin-top:6px}}
#net{{width:100%;height:520px;background:var(--card);border:1px solid var(--line);border-radius:12px}}
footer{{margin-top:40px;text-align:center;color:var(--mut);font-size:.82rem}}
</style></head><body><div class="wrap">
<header class="hero"><div><h1>\U0001f5c2 Argis dossier</h1>
  <div class="sub">Target handle: <b>@{_esc(d.username)}</b></div></div>
  <div class="sub">{_esc(d.generated_at)}</div></header>
<div class="cards-top">
  <div class="stat"><div class="big">{n}</div><div class="lbl">accounts found</div></div>
  <div class="stat"><div class="big">{len(d.by_category)}</div><div class="lbl">life-areas</div></div>
  <div class="stat"><div class="big">{d.total_scanned}</div><div class="lbl">platforms scanned</div></div>
</div>
<div class="idpanel"><h3>Extracted identity</h3>{chips}</div>
{graph_block}
{sections}
<footer>Generated by Argis -- the all-seeing OSINT scanner</footer>
</div></body></html>"""


async def build_dossier_graph(username: str, *, timeout=12.0, concurrency=15,
                               proxy=None, use_tor=False) -> dict | None:
    try:
        from argis.graph import build_graph
        g = await build_graph(username, expand_hops=0, timeout=timeout,
                             concurrency=concurrency, proxy=proxy, use_tor=use_tor)
        nodes = [{"id": nid, "label": n.label, "color": "#7aa2f7"}
                 for nid, n in g.nodes.items()]
        edges = [{"from": e.source, "to": e.target} for e in g.edges]
        return {"nodes": nodes, "edges": edges}
    except Exception:
        return None