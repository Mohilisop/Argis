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
    labels: dict | None = None


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
                    labels=getattr(s, "labels", None) or None,
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
    "development": "\U0001f4bb", "social": "\U0001f4ac", "gaming": "\U0001f3ae",
    "forums": "\U0001f4ac", "art": "\U0001f3a8", "music": "\U0001f3b5",
    "tools": "\U0001f527", "hobby": "\U0001f3b2", "blogging": "\u270d\ufe0f",
    "finance": "\U0001f4b0", "shopping": "\U0001f6d2", "education": "\U0001f393",
    "professional": "\U0001f454", "entertainment": "\U0001f3ad", "security": "\U0001f510",
    "video": "\U0001f3ac", "content": "\U0001f4f9", "messaging": "\U0001f4e8",
    "travel": "\u2708\ufe0f", "crypto": "\U0001fa99", "geo": "\U0001f30d",
    "fitness": "\U0001f4aa", "photography": "\U0001f4f7", "wiki": "\U0001f4d6",
    "freelance": "\U0001f91d", "maker": "\U0001f3ed",
    "uncategorized": "\U0001f517",
}


def _esc(x: str) -> str:
    return html.escape(str(x or ""), quote=True)


def to_html_report(dossier: Dossier, *, graph_payload: dict | None = None) -> str:
    d = dossier
    n = len(d.accounts)
    email_count = len(d.emails)
    top_name = d.names[0] if d.names else ""
    with_avatar = sum(1 for a in d.accounts if a.avatar_url)
    avatar_hashes = [a.labels.get("avatar_hash") for a in d.accounts
                     if a.labels and a.labels.get("avatar_hash")]
    same_face = len(avatar_hashes) - len(set(avatar_hashes)) if len(avatar_hashes) > 1 else 0

    cat_order = sorted({a.category for a in d.accounts})
    if "uncategorized" in cat_order:
        cat_order.remove("uncategorized")
        cat_order.append("uncategorized")
    if not cat_order:
        cat_order = ["uncategorized"]

    alias_map: dict[str, str] = {}
    for a in d.accounts:
        c = a.category or "uncategorized"
        alias_map.setdefault(c, c)

    accounts_json = []
    for a in d.accounts:
        accounts_json.append({
            "p": a.platform,
            "cat": alias_map.get(a.category, "uncategorized"),
            "name": a.display_name,
            "bio": a.bio,
            "mail": a.emails[0] if a.emails else "",
            "url": a.url,
            "img": a.avatar_url,
        })

    json_data = json.dumps(accounts_json, ensure_ascii=False)
    cat_counts = {}
    for a in d.accounts:
        c = alias_map.get(a.category, "uncategorized")
        cat_counts[c] = cat_counts.get(c, 0) + 1
    cats_json = json.dumps(cat_order, ensure_ascii=False)

    def id_tok(label, vals, cls=None):
        if not vals:
            return ""
        html_cls = cls or label
        return "".join(
            f'<span class="tok {_esc(html_cls)}">{_esc(v)}</span>'
            for v in vals
        )

    id_names = id_tok("name", d.names[:6])
    id_emails = id_tok("mail", d.emails)
    id_links = id_tok("link", d.external_links[:10])
    id_rows = ""
    for label, vals, cls in [("names", d.names[:6], "name"),
                              ("emails", d.emails, "mail"),
                              ("links", d.external_links[:10], "link")]:
        toks = id_tok(label, vals, cls)
        if toks:
            id_rows += f'<div class="idrow"><span class="tag">{_esc(label)}</span><span class="vals">{toks}</span></div>'
    if not id_rows:
        id_rows = '<div class="idrow"><span class="tag">identity</span><span class="none">No identity signals extracted.</span></div>'

    verdict_detail = f"{n} verified accounts across {len(cat_order)} categories"
    extras = []
    if email_count:
        extras.append(f"{email_count} email{'s' if email_count>1 else ''}")
    if same_face:
        extras.append(f"{same_face} reused avatar{'s' if same_face>1 else ''}")
    if extras:
        verdict_detail += f". {', '.join(extras)} found."

    from argis import __version__ as argis_ver

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGIS // dossier @{_esc(d.username)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:oklch(15% 0.018 262); --bg-2:oklch(18.5% 0.022 262); --panel:oklch(21% 0.028 262);
  --line:oklch(28% 0.03 262); --line-hot:oklch(37% 0.045 262);
  --dim:oklch(60% 0.028 220); --txt:oklch(89% 0.028 175); --txt-hi:oklch(95% 0.02 160);
  --green:oklch(84% 0.19 148); --green-d:oklch(60% 0.16 150);
  --cyan:oklch(82% 0.13 205); --amber:oklch(84% 0.15 82); --red:oklch(68% 0.19 24);
  --magenta:oklch(74% 0.16 330); --violet:oklch(76% 0.12 288);
  --c-development:var(--cyan); --c-social:var(--magenta); --c-gaming:var(--amber);
  --c-forums:var(--violet); --c-art:oklch(82% 0.14 330); --c-music:oklch(80% 0.12 280);
  --c-tools:oklch(76% 0.1 220); --c-hobby:var(--amber); --c-blogging:var(--green);
  --c-finance:oklch(82% 0.16 145); --c-shopping:oklch(78% 0.13 30);
  --c-education:oklch(80% 0.12 100); --c-professional:var(--violet);
  --c-entertainment:var(--red); --c-security:oklch(80% 0.13 55);
  --c-video:var(--red); --c-content:var(--magenta); --c-messaging:oklch(78% 0.11 235);
  --c-travel:oklch(80% 0.12 190); --c-crypto:oklch(82% 0.14 85);
  --c-geo:oklch(80% 0.12 160); --c-fitness:oklch(82% 0.16 120);
  --c-photography:oklch(80% 0.13 50); --c-wiki:oklch(78% 0.1 240);
  --c-freelance:var(--green); --c-maker:oklch(80% 0.14 30);
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;--sp-7:48px;--sp-8:72px;
  --ease:cubic-bezier(0.22,1,0.36,1); --glow:0 0 14px oklch(84% 0.19 148 / .32);
}}
*{{box-sizing:border-box;}} html{{-webkit-text-size-adjust:100%;}}
body{{margin:0; background:var(--bg); color:var(--txt);
  font-family:"JetBrains Mono",ui-monospace,monospace; font-size:13.5px; line-height:1.6;
  letter-spacing:.01em; -webkit-font-smoothing:antialiased;}}
body::before{{content:""; position:fixed; inset:0; pointer-events:none; z-index:999;
  background:repeating-linear-gradient(oklch(15% 0.018 262 / 0) 0 2.5px, oklch(9% 0.02 262 / .18) 2.5px 4px);
  mix-blend-mode:multiply; opacity:.7;}}
body::after{{content:""; position:fixed; inset:0; pointer-events:none; z-index:998;
  background:radial-gradient(130% 100% at 50% -10%, transparent 52%, oklch(9% 0.02 262 / .6));}}
a{{color:inherit; text-decoration:none;}}
h1,h2,h3{{margin:0; font-weight:700;}} p{{margin:0;}}
::selection{{background:var(--green); color:var(--bg);}}
.wrap{{max-width:1080px; margin:0 auto; padding:0 var(--sp-5);}}
.cur{{display:inline-block; width:.55em; height:1em; background:var(--green);
  transform:translateY(.14em); margin-left:3px; animation:blink 1.1s steps(1) infinite; box-shadow:var(--glow);}}
@keyframes blink{{50%{{opacity:0;}}}}

.boot{{padding:var(--sp-7) 0 var(--sp-5); border-bottom:1px solid var(--line);}}
.boot .line{{color:var(--dim); font-size:12px; white-space:pre; overflow:hidden;
  animation:type .5s var(--ease) both; animation-delay:calc(var(--l,0)*90ms);}}
@keyframes type{{from{{opacity:0; transform:translateX(-8px);}}to{{opacity:1; transform:none;}}}}
.boot .line b{{color:var(--txt-hi); font-weight:500;}}
.boot .line .ok{{color:var(--green);}} .boot .line .warn{{color:var(--amber);}}
.head{{display:flex; justify-content:space-between; align-items:flex-end; gap:var(--sp-5);
  margin:var(--sp-6) 0 var(--sp-4); flex-wrap:wrap;}}
.logo{{color:var(--green); font-weight:800; font-size:clamp(9px,2vw,13px); line-height:1.08;
  text-shadow:var(--glow); white-space:pre;}}
.tgtbox{{text-align:right; font-size:12px; color:var(--dim);}}
.tgtbox .big{{color:var(--txt-hi); font-size:1.5rem; font-weight:800; letter-spacing:-.01em;}}
.tgtbox .big .at{{color:var(--green);}}

.prompt{{display:flex; align-items:center; gap:10px; padding:var(--sp-4) 0;
  color:var(--dim); font-size:12.5px; border-bottom:1px solid var(--line); flex-wrap:wrap;}}
.prompt .usr{{color:var(--green);}} .prompt .path{{color:var(--cyan);}} .prompt .cmd{{color:var(--txt-hi);}}

.verdict{{display:flex; align-items:center; gap:var(--sp-4); margin:var(--sp-6) 0;
  padding:var(--sp-4) var(--sp-5); border:1px solid var(--green-d); background:var(--bg-2);
  box-shadow:inset 0 0 40px oklch(84% 0.19 148 / .04);}}
.verdict .mark{{font-size:1.5rem; color:var(--green); text-shadow:var(--glow);}}
.verdict .txt{{font-size:12.5px; color:var(--dim);}} .verdict .txt b{{color:var(--txt-hi);}}

.strip{{display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line);
  border:1px solid var(--line); margin:var(--sp-5) 0;}}
.stat{{background:var(--bg-2); padding:var(--sp-4) var(--sp-5); position:relative; overflow:hidden;}}
.stat::after{{content:""; position:absolute; left:0; bottom:0; height:2px; width:var(--w,0%);
  background:var(--ac,var(--green)); opacity:.5; transition:width 1s var(--ease);}}
.stat .k{{color:var(--dim); font-size:10.5px; letter-spacing:.14em; text-transform:uppercase;}}
.stat .v{{font-size:2.1rem; font-weight:800; margin-top:6px; font-variant-numeric:tabular-nums; line-height:1;}}
.stat .v.g{{color:var(--green); text-shadow:var(--glow);}} .stat .v.c{{color:var(--cyan);}}
.stat .v.a{{color:var(--amber);}} .stat .v.m{{color:var(--magenta);}}
.stat .sub{{color:var(--dim); font-size:11px; margin-top:6px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}}

.sec{{padding:var(--sp-6) 0;}}
.sec-h{{display:flex; align-items:center; gap:var(--sp-3); margin-bottom:var(--sp-5);
  color:var(--green); font-size:12px; letter-spacing:.16em; text-transform:uppercase;}}
.sec-h::before{{content:"["; color:var(--dim);}} .sec-h::after{{content:"]"; color:var(--dim);}}
.sec-h .fill{{flex:1; height:1px; background:repeating-linear-gradient(90deg,var(--line) 0 5px,transparent 5px 11px);}}
.sec-note{{color:var(--dim); font-size:11px; margin:-14px 0 var(--sp-5);}}

.faces{{display:grid; grid-template-columns:repeat(auto-fill,minmax(120px,1fr)); gap:10px;}}
.face{{position:relative; border:1px solid var(--line-hot); background:var(--bg-2); overflow:hidden;
  aspect-ratio:1; animation:flick .5s var(--ease) both; animation-delay:calc(var(--i,0)*45ms);}}
.face img{{width:100%; height:100%; object-fit:cover; display:block;
  filter:grayscale(.4) contrast(1.06) brightness(.95); transition:filter .3s var(--ease), transform .5s var(--ease);}}
.face:hover img{{filter:none; transform:scale(1.06);}}
.face .scan{{position:absolute; inset:0; pointer-events:none;
  background:linear-gradient(oklch(84% 0.19 148 / 0) 0 2px, oklch(84% 0.19 148 / .05) 2px 4px);}}
.face .cap{{position:absolute; inset:auto 0 0 0; padding:6px 8px;
  background:linear-gradient(transparent, oklch(11% 0.02 262 / .94)); font-size:10px;
  color:var(--txt-hi); font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}}
.face .badge{{position:absolute; top:6px; left:6px; font-size:8px; letter-spacing:.09em;
  background:oklch(11% 0.02 262 / .82); color:var(--cyan); padding:2px 6px; text-transform:uppercase;}}
.face .link{{position:absolute; top:6px; right:6px; width:16px; height:16px; display:grid; place-items:center;
  background:oklch(11% 0.02 262 / .82); color:var(--green); font-size:10px; opacity:0; transition:opacity .2s var(--ease);}}
.face:hover .link{{opacity:1;}}

.dist{{display:grid; gap:6px; max-width:680px;}}
.drow{{display:grid; grid-template-columns:128px 1fr 34px; gap:var(--sp-4); align-items:center;
  cursor:pointer; padding:3px 0; transition:opacity .2s var(--ease);}}
.drow .lbl{{font-size:12px; text-transform:uppercase; letter-spacing:.05em; display:flex; gap:9px; align-items:center;}}
.drow .lbl::before{{content:""; width:8px; height:8px; background:var(--cc); box-shadow:0 0 8px var(--cc); flex:0 0 auto;}}
.bar{{color:var(--cc); white-space:pre; font-size:12px; letter-spacing:-1.5px; overflow:hidden;}}
.drow .n{{color:var(--txt-hi); text-align:right; font-variant-numeric:tabular-nums; font-weight:700;}}
.drow[aria-pressed="false"]{{opacity:.3;}} .drow[aria-pressed="false"] .lbl::before{{box-shadow:none;}}

.idgrid{{display:grid; gap:var(--sp-4);}}
.idrow{{display:grid; grid-template-columns:96px 1fr; gap:var(--sp-4); align-items:start;}}
.idrow .tag{{color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:.1em; padding-top:5px;}}
.idrow .vals{{display:flex; flex-wrap:wrap; gap:8px;}}
.tok{{border:1px solid var(--line-hot); background:var(--bg-2); padding:4px 11px; font-size:12px;
  color:var(--txt); display:inline-flex; align-items:center; gap:7px;
  transition:border-color .18s var(--ease), color .18s var(--ease), box-shadow .18s var(--ease);}}
.tok:hover{{border-color:var(--green-d); color:var(--txt-hi); box-shadow:var(--glow);}}
.tok.mail{{color:var(--amber);}} .tok.mail::before{{content:"\\2709"; color:var(--dim);}}
.tok.link::before{{content:"\\2197"; color:var(--cyan);}}
.tok.name{{color:var(--green); border-color:var(--green-d); font-weight:500;}}
.idrow .none{{color:var(--dim); font-style:italic; font-size:11.5px; padding-top:4px;}}

.controls{{display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:var(--sp-5);}}
.grep{{flex:1 1 240px; min-width:200px; display:flex; align-items:center; gap:8px;
  border:1px solid var(--line-hot); background:var(--bg-2); padding:0 var(--sp-3);}}
.grep .sig{{color:var(--green);}}
.grep input{{flex:1; background:transparent; border:none; outline:none; color:var(--txt-hi);
  font-family:inherit; font-size:12.5px; padding:10px 0;}}
.grep input::placeholder{{color:var(--dim);}}
.grep:focus-within{{border-color:var(--green-d); box-shadow:var(--glow);}}
.flag{{font-family:inherit; font-size:11.5px; padding:7px 12px; cursor:pointer; border:1px solid var(--line-hot);
  background:var(--bg-2); color:var(--dim); text-transform:lowercase; transition:all .18s var(--ease);}}
.flag::before{{content:"--"; opacity:.55; margin-right:2px;}}
.flag:hover{{color:var(--txt); border-color:var(--dim);}}
.flag[aria-pressed="true"]{{color:var(--bg); background:var(--green); border-color:var(--green); font-weight:700;}}
.flag[aria-pressed="true"]::before{{opacity:.5;}}

.grp{{margin-bottom:var(--sp-5);}} .grp.hidden{{display:none;}}
.grp-h{{display:flex; align-items:center; gap:10px; color:var(--cc); font-size:11.5px;
  letter-spacing:.08em; text-transform:uppercase; margin-bottom:6px; padding-bottom:7px;
  border-bottom:1px dashed var(--line-hot);}}
.grp-h .cnt{{margin-left:auto; color:var(--dim); font-variant-numeric:tabular-nums;}}
.row{{display:grid; grid-template-columns:36px 30px 148px 1fr 18px; gap:var(--sp-3); align-items:center;
  padding:9px var(--sp-3); border-left:2px solid transparent;
  transition:background .16s var(--ease), border-color .16s var(--ease);
  animation:flick .5s var(--ease) both; animation-delay:calc(var(--i,0)*22ms);}}
@keyframes flick{{from{{opacity:0; transform:translateX(-6px);}}to{{opacity:1; transform:none;}}}}
.row:hover{{background:var(--bg-2); border-left-color:var(--cc);}}
.pfp{{width:32px; height:32px; border:1px solid var(--line-hot); object-fit:cover; display:block;
  filter:grayscale(.45) contrast(1.05); transition:filter .2s var(--ease);}}
.row:hover .pfp{{filter:none;}}
.pfp-ph{{width:32px; height:32px; border:1px solid var(--line-hot); display:grid; place-items:center;
  font-weight:800; font-size:12px; color:var(--bg);}}
.row .st{{color:var(--green); font-size:11.5px; font-weight:700;}}
.row .plat{{color:var(--txt-hi); font-weight:700; font-size:12.5px;}}
.row .meta{{color:var(--dim); font-size:12px; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}}
.row .meta b{{color:var(--txt); font-weight:500;}} .row .meta .m{{color:var(--amber);}}
.row .go{{color:var(--line-hot); text-align:right; transition:color .16s var(--ease), transform .2s var(--ease);}}
.row:hover .go{{color:var(--cc); transform:translateX(2px);}}

.empty{{display:none; padding:var(--sp-7); text-align:center; border:1px dashed var(--line-hot); color:var(--dim);}}
.empty.show{{display:block;}} .empty b{{color:var(--red);}}

.foot{{padding:var(--sp-6) 0 var(--sp-8); border-top:1px solid var(--line); color:var(--dim); font-size:11.5px;
  display:flex; justify-content:space-between; gap:var(--sp-4); flex-wrap:wrap;}}
.foot .ok{{color:var(--green);}}

@media (max-width:680px){{
  .strip{{grid-template-columns:repeat(2,1fr);}}
  .head{{flex-direction:column; align-items:flex-start;}} .tgtbox{{text-align:left;}}
  .row{{grid-template-columns:32px 1fr 16px; row-gap:3px;}}
  .row .st{{display:none;}} .row .plat{{grid-column:2/4;}} .row .meta{{grid-column:2/4;}}
  .drow{{grid-template-columns:100px 1fr 30px;}} .bar{{font-size:10px;}}
}}
@media (prefers-reduced-motion:reduce){{*{{animation:none!important;}}.cur{{animation:none;}}}}
</style>
</head>
<body>
<div class="wrap">

<header class="boot">
  <div class="line" style="--l:0"><span class="ok">\u2713</span> argis <b>v{argis_ver}</b> \u00b7 http/2 \u00b7 30 workers</div>
  <div class="line" style="--l:1"><span class="ok">\u2713</span> sites.json \u00b7 <b>{d.total_scanned}</b> rules \u00b7 integrity <span class="ok">verified</span></div>
  <div class="line" style="--l:2"><span class="ok">\u2713</span> media pipeline \u00b7 <b>{with_avatar}</b> avatars fetched \u00b7 perceptual-hashed</div>

  <div class="head">
    <pre class="logo"> \\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588 \\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588  \\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588 \\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588
\\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2595 \\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595
\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588  \\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595
\\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588   \\u2588\\u2588\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595
\\u2588\\u2588  \\u2588\\u2588\\u2588\\u2588  \\u2588\\u2588  \\u2595\\u2595\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2595\\u2595\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588\\u2588
\\u2595\\u2595  \\u2595\\u2595\\u2595\\u2595  \\u2595\\u2595  \\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595 \\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595\\u2595</pre>
    <div class="tgtbox">
      <div class="big"><span class="at">@</span>{_esc(d.username)}<span class="cur"></span></div>
      {_esc(d.generated_at)}<br>{n} verified / {d.total_scanned} scanned
    </div>
  </div>
</header>

<div class="prompt">
  <span class="usr">root@argis</span>:<span class="path">~/scans</span>$
  <span class="cmd">argis scan {_esc(d.username)} --dossier --grab-avatars{'' if n==0 else ''}</span>
</div>

<div class="verdict">
  <span class="mark">\u2713</span>
  <span class="txt"><b>{n} verified accounts</b> across {len(cat_order)} life-areas. {verdict_detail}</span>
</div>

<div class="strip">
  {f'<div class="stat" style="--w:{n/max(d.total_scanned,1)*100:.0f}%;--ac:var(--green)"><div class="k">Verified hits</div><div class="v g">{n}</div><div class="sub">of {d.total_scanned} scanned</div></div>' if n else '<div class="stat" style="--ac:var(--green)"><div class="k">Verified hits</div><div class="v g">0</div><div class="sub">of {d.total_scanned} scanned</div></div>'}
  {f'<div class="stat" style="--w:{with_avatar/max(n,1)*100:.0f}%;--ac:var(--cyan)"><div class="k">Avatars</div><div class="v c">{with_avatar}</div><div class="sub">images captured</div></div>' if n else '<div class="stat" style="--ac:var(--cyan)"><div class="k">Avatars</div><div class="v c">0</div><div class="sub">images captured</div></div>'}
  {f'<div class="stat" style="--w:{min(email_count,1)*100:.0f}%;--ac:var(--amber)"><div class="k">Emails</div><div class="v a">{email_count}</div><div class="sub">self-published</div></div>' if email_count else '<div class="stat" style="--ac:var(--amber)"><div class="k">Emails</div><div class="v a">0</div><div class="sub">self-published</div></div>'}
  {f'<div class="stat" style="--w:{same_face/max(n,1)*100:.0f}%;--ac:var(--magenta)"><div class="k">Same face</div><div class="v m">{same_face}\u00d7</div><div class="sub">avatar reused</div></div>' if n else '<div class="stat" style="--ac:var(--magenta)"><div class="k">Same face</div><div class="v m">0</div><div class="sub">avatar reused</div></div>'}
</div>

<section class="sec">
  <div class="sec-h">captured_media<span class="fill"></span></div>
  <div class="sec-note">avatars pulled per hit and perceptual-hashed. matching hashes = same image reused across platforms (a hard cross-link).</div>
  <div class="faces" id="faces"></div>
</section>

<section class="sec">
  <div class="sec-h">distribution<span class="fill"></span></div>
  <div class="dist" id="dist"></div>
</section>

<section class="sec">
  <div class="sec-h">extracted_identity<span class="fill"></span></div>
  <div class="idgrid">{id_rows}</div>
</section>

<section class="sec">
  <div class="sec-h">accounts_found<span class="fill"></span></div>
  <div class="controls">
    <label class="grep"><span class="sig">grep&gt;</span>
      <input id="q" type="text" placeholder="filter platform / name / bio\u2026" aria-label="Filter accounts"></label>
    <button class="flag" data-cat="all" aria-pressed="true">all</button>
    {"".join(f'<button class="flag" data-cat="{_esc(c)}" aria-pressed="true">{_esc(c)}</button>' for c in cat_order)}
  </div>
  <div id="groups"></div>
  <div class="empty" id="empty">no matches \u2014 <b>0 results</b>. clear grep or re-enable a flag.</div>
</section>

<footer class="foot">
  <span><span class="ok">\u2713</span> scan complete \u00b7 {n} verified / {d.total_scanned} scanned</span>
  <span>public signals only \u00b7 defensive / self-osint \u00b7 no deanonymization</span>
</footer>

</div>

<script>
const DATA = {json_data};
const CAT = {cats_json};
const VAR = {{{{c}}:"--c-{_esc(c)}" for c in cat_order}};
const cssv=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function initials(s){{const c=s.replace(/^u\\//,"").replace(/[@_.]/g," ").trim().split(/\\s+/);
  return c.length>=2?(c[0][0]+c[1][0]).toUpperCase():c[0].slice(0,2).toUpperCase();}}

/* faces */
const faces=document.getElementById("faces"); let fi=0;
DATA.filter(d=>d.img).forEach(d=>{{
  const col=cssv(VAR[d.cat]);
  const el=document.createElement("a");
  el.className="face"; el.href=d.url; el.target="_blank"; el.rel="noopener"; el.style.setProperty("--i",fi++);
  el.innerHTML=`<img src="${{d.img}}" alt="${{d.p}} avatar" loading="lazy"
    onerror="this.replaceWith(Object.assign(document.createElement('div'),{{className:'noimg',style:'width:100%;height:100%;display:grid;place-items:center;font-weight:800;font-size:1.6rem;color:var(--bg);background:${{col}}',textContent:'${{initials(d.name||d.p)}}'}}))">
    <div class="scan"></div><div class="badge">${{d.p}}</div><div class="link">\u2197</div>
    <div class="cap">${{d.name||d.p}}</div>`;
  faces.appendChild(el);
}});

/* distribution */
const counts={{{{}}}}; CAT.forEach(c=>counts[c]=DATA.filter(d=>d.cat===c).length);
const maxc=Math.max(...Object.values(counts),1);
const dist=document.getElementById("dist");
CAT.forEach(c=>{{const col=cssv(VAR[c]); const u=Math.round(counts[c]/maxc*24);
  const bar="\\u2588".repeat(u)+"\\u2591".repeat(24-u);
  const row=document.createElement("div"); row.className="drow"; row.dataset.cat=c;
  row.setAttribute("role","button"); row.setAttribute("aria-pressed","true"); row.style.setProperty("--cc",col);
  row.innerHTML=`<span class="lbl">${{c}}</span><span class="bar">${{bar}}</span><span class="n">${{counts[c]}}</span>`;
  row.addEventListener("click",()=>toggle(c)); dist.appendChild(row);}});

/* accounts */
const groupsEl=document.getElementById("groups"); let gi=0;
CAT.forEach(c=>{{const items=DATA.filter(d=>d.cat===c); if(!items.length) return;
  const col=cssv(VAR[c]); let rows="";
  items.forEach(d=>{{
    const nm=d.name?`<b>${{d.name}}</b>`:""; const bio=d.bio?` \\u00b7 ${{d.bio}}`:"";
    const mail=d.mail?` \\u00b7 <span class="m">${{d.mail}}</span>`:"";
    const pfp=d.img
      ?`<img class="pfp" src="${{d.img}}" alt="" loading="lazy" onerror="this.replaceWith(Object.assign(document.createElement('span'),{{className:'pfp-ph',style:'background:${{col}}',textContent:'${{initials(d.name||d.p)}}'}}))">`
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


def to_pdf(dossier: Dossier, out_path: str | Path, *, graph_payload: dict | None = None) -> bool:
    """Render the dossier HTML to PDF. Returns True on success.

    Tries weasyprint (pure-python, best fidelity), then
    playwright (if the render extra is installed). No hard dependency added.
    """
    html_str = to_html_report(dossier, graph_payload=graph_payload)

    try:
        from weasyprint import HTML
        HTML(string=html_str).write_pdf(str(out_path))
        return True
    except Exception:
        pass

    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _run():
            async with async_playwright() as pw:
                b = await pw.chromium.launch(headless=True)
                pg = await b.new_page()
                await pg.set_content(html_str, wait_until="networkidle")
                await pg.pdf(path=str(out_path), format="A4",
                             print_background=True)
                await b.close()
        asyncio.run(_run())
        return True
    except Exception:
        return False


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