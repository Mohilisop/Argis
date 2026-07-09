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
    email_count = len(d.emails)
    top_name = d.names[0] if d.names else "\u2014"
    with_avatar = sum(1 for a in d.accounts if a.avatar_url)

    cat_order = ["coding", "social", "media", "creative", "blogging", "gaming", "funding", "professional", "uncategorized"]
    accounts_json = []
    for a in d.accounts:
        accounts_json.append({
            "p": a.platform,
            "cat": a.category if a.category in cat_order else "uncategorized",
            "name": a.display_name,
            "bio": a.bio,
            "mail": a.emails[0] if a.emails else "",
            "url": a.url,
            "img": a.avatar_url,
        })

    json_data = json.dumps(accounts_json, ensure_ascii=False)
    cat_counts = {}
    for a in d.accounts:
        c = a.category if a.category in cat_order else "uncategorized"
        cat_counts[c] = cat_counts.get(c, 0) + 1
    cats_json = json.dumps([c for c in cat_order if c in cat_counts], ensure_ascii=False)

    id_tokens = ""
    for label, vals in [("name", d.names[:5]), ("mail", d.emails),
                        ("link", d.external_links[:10])]:
        cls = "name" if label == "name" else label
        for v in vals:
            id_tokens += f'<span class="tok {_esc(cls)}">{_esc(v)}</span>'
    if not id_tokens:
        id_tokens = '<span style="color:var(--dim)">No identity signals extracted.</span>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGIS // dossier @{_esc(d.username)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:oklch(16% 0.02 265); --bg-2:oklch(19% 0.025 265); --panel:oklch(21% 0.03 265);
  --line:oklch(30% 0.035 265); --line-hot:oklch(38% 0.05 265);
  --dim:oklch(58% 0.03 210); --txt:oklch(88% 0.03 175); --txt-hi:oklch(94% 0.02 160);
  --green:oklch(84% 0.19 148); --green-d:oklch(62% 0.17 150);
  --cyan:oklch(82% 0.14 200); --amber:oklch(83% 0.15 82); --red:oklch(70% 0.2 25);
  --magenta:oklch(74% 0.17 330); --violet:oklch(75% 0.13 285);
  --c-coding:var(--cyan); --c-social:var(--magenta); --c-media:var(--red);
  --c-creative:var(--violet); --c-blogging:var(--green); --c-gaming:var(--amber);
  --c-funding:oklch(80% 0.13 55);
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;--sp-7:48px;--sp-8:72px;
  --ease:cubic-bezier(0.22,1,0.36,1); --glow:0 0 12px oklch(84% 0.19 148 / .35);
}}
*{{box-sizing:border-box;}} html{{-webkit-text-size-adjust:100%;}}
body{{margin:0; background:var(--bg); color:var(--txt);
  font-family:"JetBrains Mono",ui-monospace,monospace; font-size:14px; line-height:1.6;
  letter-spacing:.01em; -webkit-font-smoothing:antialiased;}}
body::before{{content:""; position:fixed; inset:0; pointer-events:none; z-index:999;
  background:repeating-linear-gradient(oklch(16% 0.02 265 / 0) 0 2px, oklch(10% 0.02 265 / .22) 2px 3px);
  mix-blend-mode:multiply;}}
body::after{{content:""; position:fixed; inset:0; pointer-events:none; z-index:998;
  background:radial-gradient(120% 90% at 50% 0%, transparent 55%, oklch(10% 0.02 265 / .55));}}
a{{color:inherit; text-decoration:none;}}
h1,h2,h3{{margin:0; font-weight:700;}} p{{margin:0;}}
::selection{{background:var(--green); color:var(--bg);}}
.wrap{{max-width:1060px; margin:0 auto; padding:0 var(--sp-5);}}
.cur{{display:inline-block; width:.6em; height:1.05em; background:var(--green);
  transform:translateY(.16em); margin-left:2px; animation:blink 1.1s steps(1) infinite; box-shadow:var(--glow);}}
@keyframes blink{{50%{{opacity:0;}}}}
.boot{{padding:var(--sp-7) 0 var(--sp-5); border-bottom:1px solid var(--line);}}
.boot .line{{color:var(--dim); font-size:12.5px; white-space:pre; overflow:hidden;}}
.boot .line b{{color:var(--green); font-weight:500;}}
.boot .line .ok{{color:var(--green);}} .boot .line .warn{{color:var(--amber);}}
.logo{{margin:var(--sp-5) 0 var(--sp-4); color:var(--green); font-weight:800;
  font-size:clamp(10px,2.4vw,15px); line-height:1.1; text-shadow:var(--glow); white-space:pre; overflow-x:auto;}}
.tagline{{display:flex; gap:var(--sp-4); flex-wrap:wrap; align-items:baseline; color:var(--dim); font-size:12.5px;}}
.tagline .tgt{{color:var(--txt-hi);}} .tagline .tgt b{{color:var(--green); font-weight:700;}}
.prompt{{display:flex; align-items:center; gap:var(--sp-3); padding:var(--sp-4) 0;
  color:var(--dim); font-size:13px; border-bottom:1px solid var(--line); flex-wrap:wrap;}}
.prompt .usr{{color:var(--green);}} .prompt .path{{color:var(--cyan);}} .prompt .cmd{{color:var(--txt-hi);}}
.strip{{display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line);
  border:1px solid var(--line); margin:var(--sp-6) 0;}}
.stat{{background:var(--bg-2); padding:var(--sp-4);}}
.stat .k{{color:var(--dim); font-size:11px; letter-spacing:.12em; text-transform:uppercase;}}
.stat .v{{font-size:1.9rem; font-weight:800; margin-top:var(--sp-1); font-variant-numeric:tabular-nums; line-height:1;}}
.stat .v.g{{color:var(--green); text-shadow:var(--glow);}} .stat .v.c{{color:var(--cyan);}}
.stat .v.a{{color:var(--amber);}} .stat .v.r{{color:var(--red);}}
.stat .sub{{color:var(--dim); font-size:11.5px; margin-top:var(--sp-2);}}
.sec{{padding:var(--sp-6) 0;}}
.sec-h{{display:flex; align-items:center; gap:var(--sp-3); margin-bottom:var(--sp-5);
  color:var(--green); font-size:12.5px; letter-spacing:.14em; text-transform:uppercase;}}
.sec-h::before{{content:"[";color:var(--dim);}} .sec-h::after{{content:"]";color:var(--dim);}}
.sec-h .fill{{flex:1; height:1px; background:repeating-linear-gradient(90deg,var(--line) 0 6px,transparent 6px 12px);}}
.sec-note{{color:var(--dim); font-size:11.5px; margin:-14px 0 var(--sp-5); text-transform:none; letter-spacing:0;}}
.faces{{display:grid; grid-template-columns:repeat(auto-fill,minmax(112px,1fr)); gap:var(--sp-3);}}
.face{{position:relative; border:1px solid var(--line-hot); background:var(--bg-2); overflow:hidden;
  aspect-ratio:1; animation:flick .5s var(--ease) both; animation-delay:calc(var(--i,0)*40ms);}}
.face img{{width:100%; height:100%; object-fit:cover; display:block;
  filter:grayscale(.35) contrast(1.05); transition:filter .25s var(--ease), transform .4s var(--ease);}}
.face:hover img{{filter:none; transform:scale(1.05);}}
.face .scan{{position:absolute; inset:0; pointer-events:none;
  background:linear-gradient(oklch(84% 0.19 148 / 0) 0 2px, oklch(84% 0.19 148 / .06) 2px 4px);}}
.face .cap{{position:absolute; left:0; right:0; bottom:0; padding:5px 7px;
  background:linear-gradient(transparent, oklch(12% 0.02 265 / .92));
  font-size:10.5px; color:var(--txt-hi); display:flex; justify-content:space-between; align-items:center; gap:4px;}}
.face .cap .pf{{font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}}
.face .badge{{position:absolute; top:5px; left:5px; font-size:8.5px; letter-spacing:.08em;
  background:oklch(12% 0.02 265 / .8); color:var(--cyan); padding:2px 5px; text-transform:uppercase;}}
.dist{{display:grid; gap:var(--sp-2); max-width:660px;}}
.drow{{display:grid; grid-template-columns:120px 1fr 46px; gap:var(--sp-4); align-items:center;
  cursor:pointer; padding:2px 0; transition:opacity .2s var(--ease);}}
.drow .lbl{{font-size:12.5px; text-transform:uppercase; letter-spacing:.06em; display:flex; gap:8px; align-items:center;}}
.drow .lbl::before{{content:""; width:8px; height:8px; background:var(--cc); box-shadow:0 0 8px var(--cc);}}
.bar{{color:var(--cc); white-space:pre; font-size:13px; letter-spacing:-1px; overflow:hidden;}}
.drow .n{{color:var(--txt-hi); text-align:right; font-variant-numeric:tabular-nums; font-weight:700;}}
.drow[aria-pressed="false"]{{opacity:.32;}} .drow[aria-pressed="false"] .lbl::before{{box-shadow:none;}}
.idgrid{{display:grid; gap:var(--sp-3);}}
.idrow{{display:grid; grid-template-columns:110px 1fr; gap:var(--sp-4); align-items:start;}}
.idrow .tag{{color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.1em; padding-top:4px;}}
.idrow .vals{{display:flex; flex-wrap:wrap; gap:var(--sp-2);}}
.tok{{border:1px solid var(--line-hot); background:var(--bg-2); padding:3px 10px; font-size:12.5px;
  color:var(--txt); display:inline-flex; align-items:center; gap:6px;
  transition:border-color .18s var(--ease), color .18s var(--ease), box-shadow .18s var(--ease);}}
.tok:hover{{border-color:var(--green-d); color:var(--txt-hi); box-shadow:var(--glow);}}
.tok.mail{{color:var(--amber);}} .tok.mail::before{{content:"@"; color:var(--dim);}}
.tok.link::before{{content:"\u2197"; color:var(--cyan);}}
.tok.name{{color:var(--green); border-color:var(--green-d);}}
.controls{{display:flex; gap:var(--sp-3); align-items:center; flex-wrap:wrap; margin-bottom:var(--sp-5);}}
.grep{{flex:1 1 240px; min-width:190px; display:flex; align-items:center; gap:var(--sp-2);
  border:1px solid var(--line-hot); background:var(--bg-2); padding:0 var(--sp-3);}}
.grep .sig{{color:var(--green);}}
.grep input{{flex:1; background:transparent; border:none; outline:none; color:var(--txt-hi);
  font-family:inherit; font-size:13px; padding:9px 0;}}
.grep input::placeholder{{color:var(--dim);}}
.grep:focus-within{{border-color:var(--green-d); box-shadow:var(--glow);}}
.flag{{font-family:inherit; font-size:12px; padding:6px 11px; cursor:pointer; border:1px solid var(--line-hot);
  background:var(--bg-2); color:var(--dim); text-transform:lowercase; transition:all .18s var(--ease);}}
.flag::before{{content:"--"; opacity:.6; margin-right:2px;}}
.flag:hover{{color:var(--txt);}}
.flag[aria-pressed="true"]{{color:var(--bg); background:var(--green); border-color:var(--green); font-weight:700;}}
.grp{{margin-bottom:var(--sp-5);}} .grp.hidden{{display:none;}}
.grp-h{{display:flex; align-items:center; gap:var(--sp-3); color:var(--cc); font-size:12px;
  letter-spacing:.08em; text-transform:uppercase; margin-bottom:var(--sp-2); padding-bottom:6px;
  border-bottom:1px dashed var(--line-hot);}}
.grp-h .cnt{{margin-left:auto; color:var(--dim); font-variant-numeric:tabular-nums;}}
.row{{display:grid; grid-template-columns:38px 26px 140px 1fr 20px; gap:var(--sp-3); align-items:center;
  padding:8px var(--sp-3); border-left:2px solid transparent; position:relative;
  transition:background .16s var(--ease), border-color .16s var(--ease);
  animation:flick .5s var(--ease) both; animation-delay:calc(var(--i,0)*26ms);}}
@keyframes flick{{from{{opacity:0; transform:translateX(-6px);}}to{{opacity:1; transform:none;}}}}
.row:hover{{background:var(--bg-2);}} .row:hover{{border-left-color:var(--cc);}}
.pfp{{width:34px; height:34px; border:1px solid var(--line-hot); object-fit:cover; display:block;
  filter:grayscale(.4) contrast(1.05); transition:filter .2s var(--ease);}}
.row:hover .pfp{{filter:none;}}
.pfp-ph{{width:34px; height:34px; border:1px solid var(--line-hot); display:grid; place-items:center;
  font-weight:800; font-size:13px; color:var(--bg);}}
.row .st{{color:var(--green); font-size:12px; font-weight:700;}}
.row .plat{{color:var(--txt-hi); font-weight:700; font-size:13px;}}
.row .meta{{color:var(--dim); font-size:12.5px; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}}
.row .meta b{{color:var(--txt); font-weight:500;}} .row .meta .m{{color:var(--amber);}}
.row .go{{color:var(--line-hot); text-align:right; transition:color .16s var(--ease), transform .2s var(--ease);}}
.row:hover .go{{color:var(--cc); transform:translateX(2px);}}
.empty{{display:none; padding:var(--sp-7); text-align:center; border:1px dashed var(--line-hot); color:var(--dim);}}
.empty.show{{display:block;}} .empty b{{color:var(--red);}}
.foot{{padding:var(--sp-6) 0 var(--sp-8); border-top:1px solid var(--line); color:var(--dim); font-size:12px;
  display:flex; justify-content:space-between; gap:var(--sp-4); flex-wrap:wrap;}}
.foot .ok{{color:var(--green);}}
@media (max-width:680px){{
  .strip{{grid-template-columns:repeat(2,1fr);}}
  .row{{grid-template-columns:34px 1fr 18px; row-gap:2px;}}
  .row .st{{display:none;}} .row .plat{{grid-column:2/4;}} .row .meta{{grid-column:2/4;}}
  .drow{{grid-template-columns:96px 1fr 34px;}} .bar{{font-size:11px;}}
}}
@media (prefers-reduced-motion:reduce){{*{{animation:none!important;}}.cur{{animation:none;}}}}
</style>
</head><body><div class="wrap">

<header class="boot">
  <div class="line"><span class="ok">\u2713</span> argis engine <b>v0.5.0</b> online \u00b7 http/2 \u00b7 30 workers</div>
  <div class="line"><span class="ok">\u2713</span> sites.json loaded \u00b7 <b>133</b> rules \u00b7 integrity <span class="ok">verified</span></div>
  <div class="line"><span class="ok">\u2713</span> media pipeline \u00b7 <b>{with_avatar}</b> avatars fetched \u00b7 perceptual-hashed</div>
  <pre class="logo">
 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588
\u2588\u2588\u2595\u2595\u2595\u2595\u2588\u2588\u2588\u2588\u2595\u2595\u2595\u2595\u2588\u2588\u2588\u2588\u2595\u2595\u2595\u2595\u2595 \u2588\u2588\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2595\u2595\u2588\u2588\u2588\u2588  \u2588\u2588\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595
\u2588\u2588\u2595\u2595\u2595\u2595\u2588\u2588\u2588\u2588\u2595\u2595\u2595\u2595\u2588\u2588\u2588\u2588   \u2588\u2588\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595
\u2588\u2588  \u2588\u2588\u2588\u2588  \u2588\u2588  \u2595\u2595\u2588\u2588\u2588\u2588\u2588\u2588\u2595\u2595\u2588\u2588\u2588\u2588\u2588\u2588\u2588
\u2595\u2595  \u2595\u2595\u2595\u2595  \u2595\u2595  \u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595 \u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595\u2595</pre>
  <div class="tagline">
    <span>the all-seeing osint scanner</span>
    <span class="tgt">target \u27f6 <b>@{_esc(d.username)}</b><span class="cur"></span></span>
  </div>
</header>

<div class="prompt">
  <span class="usr">root@argis</span><span>:</span><span class="path">~/scans</span><span>$</span>
  <span class="cmd">argis scan {_esc(d.username)} --dossier --grab-avatars --all</span>
</div>

<div class="strip">
  <div class="stat"><div class="k">Hits</div><div class="v g">{n}</div><div class="sub">/ {d.total_scanned} scanned</div></div>
  <div class="stat"><div class="k">Avatars</div><div class="v c">{with_avatar}</div><div class="sub">images captured</div></div>
  <div class="stat"><div class="k">Emails</div><div class="v a">{email_count}</div><div class="sub">leaked in profiles</div></div>
  <div class="stat"><div class="k">Real name</div><div class="v r">{len(d.names)}\u00d7</div><div class="sub">{_esc(top_name)}</div></div>
</div>

<section class="sec">
  <div class="sec-h">captured_media<span class="fill"></span></div>
  <div class="sec-note">profile photos pulled from each hit and perceptual-hashed. matching hashes = same image reused across platforms (a hard cross-link).</div>
  <div class="faces" id="faces"></div>
</section>

<section class="sec">
  <div class="sec-h">distribution<span class="fill"></span></div>
  <div class="dist" id="dist"></div>
</section>

<section class="sec">
  <div class="sec-h">extracted_identity<span class="fill"></span></div>
  <div class="idgrid">
    <div class="idrow"><span class="tag">names</span><span class="vals">{id_tokens}</span></div>
  </div>
</section>

<section class="sec">
  <div class="sec-h">accounts_found<span class="fill"></span></div>
  <div class="controls">
    <label class="grep"><span class="sig">grep&gt;</span>
      <input id="q" type="text" placeholder="filter platform / name / bio\u2026" aria-label="Filter accounts"></label>
    <button class="flag" data-cat="all" aria-pressed="true">all</button>
    {"".join(f'<button class="flag" data-cat="{_esc(c)}" aria-pressed="true">{_esc(c)}</button>' for c in cat_order if c in cat_counts)}
  </div>
  <div id="groups"></div>
  <div class="empty" id="empty">no matches &mdash; <b>0 results</b>. clear grep or re-enable a flag.</div>
</section>

<footer class="foot">
  <span><span class="ok">\u2713</span> scan complete \u00b7 {_esc(d.generated_at)}</span>
  <span>public signals only \u00b7 defensive / self-osint \u00b7 no deanonymization</span>
</footer>

</div>

<script>
const DATA = {json_data};
const CAT = {cats_json};
const VAR = {{"coding":"--c-coding","social":"--c-social","media":"--c-media","creative":"--c-creative","blogging":"--c-blogging","gaming":"--c-gaming","funding":"--c-funding"}};
const cssv=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function initials(str){{const c=str.replace(/^u\\//,"").replace(/[@_.]/g," ").trim().split(/\\s+/);
  return c.length>=2?(c[0][0]+c[1][0]).toUpperCase():c[0].slice(0,2).toUpperCase();}}

/* captured faces gallery */
const faces=document.getElementById("faces"); let fi=0;
DATA.filter(d=>d.img).forEach(d=>{{
  const col=cssv(VAR[d.cat]);
  const el=document.createElement("a");
  el.className="face"; el.href=d.url; el.target="_blank"; el.rel="noopener"; el.style.setProperty("--i",fi++);
  el.innerHTML=`<img src="${{d.img}}" alt="${{d.p}} avatar" loading="lazy">
    <div class="scan"></div>
    <div class="badge">${{d.p}}</div>
    <div class="cap"><span class="pf">${{d.name||d.p}}</span></div>`;
  faces.appendChild(el);
}});

/* distribution */
const counts={{}}; CAT.forEach(c=>counts[c]=DATA.filter(d=>d.cat===c).length);
const maxc=Math.max(...Object.values(counts),1);
const dist=document.getElementById("dist");
CAT.forEach(c=>{{const col=cssv(VAR[c]); const u=Math.round(counts[c]/maxc*22);
  const bar="\\u2588".repeat(u)+"\\u2591".repeat(22-u);
  const row=document.createElement("div"); row.className="drow"; row.dataset.cat=c;
  row.setAttribute("role","button"); row.setAttribute("aria-pressed","true"); row.style.setProperty("--cc",col);
  row.innerHTML=`<span class="lbl">${{c}}</span><span class="bar">${{bar}}</span><span class="n">${{counts[c]}}</span>`;
  row.addEventListener("click",()=>toggle(c)); dist.appendChild(row);}});

/* account rows w/ pfp */
const groupsEl=document.getElementById("groups"); let gi=0;
CAT.forEach(c=>{{const items=DATA.filter(d=>d.cat===c); if(!items.length) return;
  const col=cssv(VAR[c]); let rows="";
  items.forEach(d=>{{
    const nm=d.name?`<b>${{d.name}}</b>`:""; const bio=d.bio?` \\u00b7 ${{d.bio}}`:"";
    const mail=d.mail?` \\u00b7 <span class="m">${{d.mail}}</span>`:"";
    const pfp=d.img?`<img class="pfp" src="${{d.img}}" alt="" loading="lazy">`
      :`<span class="pfp-ph" style="background:${{col}}">${{initials(d.name||d.p)}}</span>`;
    rows+=`<a class="row" href="${{d.url}}" target="_blank" rel="noopener" style="--i:${{gi++}};--cc:${{col}}"
        data-hay="${{(d.p+' '+d.name+' '+d.bio).toLowerCase()}}">
        ${{pfp}}<span class="st">200</span><span class="plat">${{d.p}}</span>
        <span class="meta">${{nm}}${{bio}}${{mail}}</span><span class="go">\u2192</span></a>`;}});
  const g=document.createElement("div"); g.className="grp"; g.dataset.cat=c;
  g.innerHTML=`<div class="grp-h" style="--cc:${{col}};color:${{col}}">${{c}}<span class="cnt">${{items.length}} found</span></div>${{rows}}`;
  groupsEl.appendChild(g);}});

/* interactivity */
const active=new Set(CAT); const flags=[...document.querySelectorAll(".flag")];
const q=document.getElementById("q"); const empty=document.getElementById("empty");
function toggle(c){{active.has(c)?active.delete(c):active.add(c); sync(); render();}}
function sync(){{flags.forEach(f=>{{if(f.dataset.cat==="all") f.setAttribute("aria-pressed",active.size===CAT.length);
    else f.setAttribute("aria-pressed",active.has(f.dataset.cat));}});
  document.querySelectorAll(".drow").forEach(r=>r.setAttribute("aria-pressed",active.has(r.dataset.cat)));}}
flags.forEach(f=>f.addEventListener("click",()=>{{const c=f.dataset.cat;
  if(c==="all"){{active.size===CAT.length?active.clear():CAT.forEach(x=>active.add(x));}} else toggle(c);
  sync(); render();}}));
function render(){{const term=q.value.trim().toLowerCase(); let vis=0;
  document.querySelectorAll(".grp").forEach(g=>{{const on=active.has(g.dataset.cat); let shown=0;
    g.querySelectorAll(".row").forEach(a=>{{const m=on&&(!term||a.dataset.hay.includes(term));
      a.style.display=m?"":"none"; if(m) shown++;}});
    g.classList.toggle("hidden",shown===0); vis+=shown;}});
  empty.classList.toggle("show",vis===0);}}
q.addEventListener("input",render); sync();
</script>
</body></html>"""


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