"""Interactive media confidence review dashboard for Argis.

The dashboard consumes a saved scan, scores captured media, and lets an analyst
accept or reject each candidate before using it as identity evidence.
"""
from __future__ import annotations

import json
import re
import webbrowser
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

import typer

from argis.diff import load_history
from argis.exceptions import HistoryError
from argis.utils.display import console


_SUSPICIOUS = re.compile(
    r"(?i)(favicon|logo|brand|banner|cover|thumbnail|android-chrome|"
    r"apple-touch|letterbox|default|placeholder|product|marketing|ogimage)"
)
_PROFILE_HINT = re.compile(r"(?i)(avatar|profile|userpic|headshot|portrait)")


@dataclass
class MediaCandidate:
    id: int
    platform: str
    category: str
    profile_url: str
    image_url: str
    confidence: int
    source: str
    avatar_hash: str
    suspicious: bool
    signals: list[str]
    state: str = "review"


def score_media(platform: str, profile_url: str, image_url: str, source: str = "") -> tuple[int, list[str]]:
    """Return a conservative confidence score and human-readable signals."""
    score = 45
    signals: list[str] = []
    low_url = image_url.lower()
    image_host = urlparse(image_url).netloc.lower()
    profile_host = urlparse(profile_url).netloc.lower()

    if _SUSPICIOUS.search(low_url):
        score -= 42
        signals.append("Filename or path looks like a site asset")
    if _PROFILE_HINT.search(low_url):
        score += 18
        signals.append("URL contains a profile-image marker")
    if image_host and profile_host and (
        image_host == profile_host or image_host.endswith("." + profile_host)
    ):
        score += 8
        signals.append("Image is hosted by the profile platform")
    if platform.lower() == "github" and "github.com/" in low_url and ".png" in low_url:
        score = max(score, 96)
        signals.append("Username-specific GitHub avatar endpoint")
    if source:
        source_low = source.lower()
        if "validated" in source_low or "api" in source_low:
            score += 16
            signals.append("Captured by a validated or API-backed source")
        elif "og" in source_low:
            score -= 8
            signals.append("Open Graph media may be generic page artwork")
    if not any(ch.isdigit() for ch in low_url) and platform.lower() not in low_url:
        score -= 6
        signals.append("Image URL has no obvious profile-specific identifier")

    if not signals:
        signals.append("No strong positive or negative signal")
    return max(0, min(100, score)), signals


def collect_media_candidates(results: Mapping[str, Mapping[str, Any]]) -> list[MediaCandidate]:
    """Collect and score media candidates from one saved scan result map."""
    candidates: list[MediaCandidate] = []
    seen: set[str] = set()

    for platform, result in results.items():
        if result.get("status") != "FOUND":
            continue
        image_url = ""
        for key in (
            "avatar_url", "avatar", "profile_image_url", "profile_image",
            "image", "img", "picture", "photo_url",
        ):
            value = result.get(key)
            if isinstance(value, dict):
                value = value.get("url") or value.get("contentUrl")
            if isinstance(value, str) and value.startswith(("http://", "https://", "//")):
                image_url = "https:" + value if value.startswith("//") else value
                break
        if not image_url or image_url in seen:
            continue
        seen.add(image_url)
        source = str(result.get("media_source") or result.get("avatar_source") or "scan result")
        confidence, signals = score_media(
            str(platform), str(result.get("url") or ""), image_url, source
        )
        candidates.append(MediaCandidate(
            id=len(candidates) + 1,
            platform=str(platform),
            category=str(result.get("category") or "uncategorized"),
            profile_url=str(result.get("url") or ""),
            image_url=image_url,
            confidence=confidence,
            source=source,
            avatar_hash=str(result.get("avatar_hash") or ""),
            suspicious=confidence < 50,
            signals=signals,
        ))

    return sorted(candidates, key=lambda item: (item.confidence, item.platform.lower()))


def render_media_review_dashboard(
    username: str,
    candidates: list[MediaCandidate],
    *,
    scanned_at: str = "unknown",
) -> str:
    """Render a self-contained interactive review dashboard."""
    payload = json.dumps([asdict(item) for item in candidates], ensure_ascii=False).replace("</", "<\\/")
    safe_user = json.dumps(username, ensure_ascii=False)
    safe_time = json.dumps(scanned_at, ensure_ascii=False)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argis media review</title>
<style>
:root{{--paper:#f6f1e8;--surface:#fffaf0;--ink:#29231f;--muted:#73685f;--line:#d9cfc2;--accent:#c8582c;--good:#25805d;--warn:#b87814;--bad:#b83b36}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,sans-serif}}button,input,select{{font:inherit}}button{{cursor:pointer}}header{{height:68px;padding:0 24px;display:flex;align-items:center;gap:22px;border-bottom:1px solid var(--line);background:var(--surface)}}.brand{{font:700 16px ui-monospace,monospace}}.brand b{{color:var(--accent)}}.run{{color:var(--muted);font:12px ui-monospace,monospace}}.actions{{margin-left:auto;display:flex;gap:8px}}.btn{{min-height:40px;border:1px solid var(--line);background:var(--surface);padding:8px 13px;border-radius:7px;font-weight:700}}.btn.primary{{background:var(--ink);color:var(--surface);border-color:var(--ink)}}.layout{{display:grid;grid-template-columns:230px minmax(0,1fr) 330px;min-height:calc(100vh - 68px)}}aside{{background:var(--surface);padding:24px 18px}}.left{{border-right:1px solid var(--line)}}.right{{border-left:1px solid var(--line);position:sticky;top:0;height:calc(100vh - 68px);overflow:auto}}.eyebrow{{font:700 10px ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}}h1{{font-size:40px;line-height:1;margin:5px 0 10px;letter-spacing:-.05em}}h2{{margin:5px 0 10px;letter-spacing:-.03em}}.intro{{color:var(--muted);max-width:58ch}}.filters{{display:grid;gap:5px;margin-top:20px}}.filter{{border:0;background:transparent;padding:10px;border-radius:6px;text-align:left;font-weight:700;color:var(--muted)}}.filter.active,.filter:hover{{background:var(--paper);color:var(--ink)}}main{{padding:28px 30px 70px;min-width:0}}.toolbar{{display:grid;grid-template-columns:1fr auto auto;gap:8px;margin:24px 0 14px}}.control{{min-height:42px;border:1px solid var(--line);background:var(--surface);border-radius:7px;padding:0 11px}}.list{{border-top:1px solid var(--ink)}}.row{{display:grid;grid-template-columns:66px minmax(140px,1fr) minmax(160px,1.25fr) 100px 85px;gap:14px;align-items:center;padding:12px 4px;border-bottom:1px solid var(--line);cursor:pointer}}.row:hover,.row.selected{{background:#ede2d3}}.thumb{{width:58px;height:58px;object-fit:cover;border:1px solid var(--line);border-radius:5px;background:#e8dfd2}}.platform{{font-weight:800}}.meta,.reason{{font-size:11px;color:var(--muted)}}.score{{font:700 14px ui-monospace,monospace}}.meter{{height:5px;background:#e6dccf;margin-top:6px;border-radius:3px;overflow:hidden}}.meter i{{display:block;height:100%;width:var(--w);background:var(--c)}}.state{{font:700 9px ui-monospace,monospace;text-transform:uppercase;text-align:center;padding:5px;border:1px solid currentColor;border-radius:999px}}.state.review{{color:var(--warn)}}.state.accepted{{color:var(--good)}}.state.rejected{{color:var(--bad)}}.preview{{aspect-ratio:1;border:1px solid var(--line);background:var(--paper);border-radius:7px;overflow:hidden;margin:10px 0 16px}}.preview img{{width:100%;height:100%;object-fit:cover}}.url{{font:11px ui-monospace,monospace;color:#365e86;overflow-wrap:anywhere}}dl{{margin:18px 0}}.fact{{display:grid;grid-template-columns:92px 1fr;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:11px}}dt{{color:var(--muted)}}dd{{margin:0;font-family:ui-monospace,monospace;overflow-wrap:anywhere}}.signals{{display:grid;gap:7px;margin:14px 0 20px;font-size:12px}}.decision{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}.decision button{{min-height:44px;border-radius:7px;font-weight:800}}.accept{{border:1px solid var(--good);background:#e2f0e8;color:#145e42}}.reject{{border:1px solid var(--bad);background:#f4e2de;color:#8d2928}}.empty{{padding:60px 0;text-align:center;color:var(--muted)}}@media(max-width:1000px){{.layout{{grid-template-columns:200px 1fr}}.right{{display:none}}.row{{grid-template-columns:60px 1fr 1fr 90px}}.state{{display:none}}}}@media(max-width:680px){{header{{padding:0 14px}}.run{{display:none}}.layout{{display:block}}.left{{border:0;border-bottom:1px solid var(--line)}}.filters{{display:flex;overflow:auto;margin-top:8px}}main{{padding:22px 14px}}.toolbar{{grid-template-columns:1fr}}.row{{grid-template-columns:54px 1fr 68px}}.reason{{display:none}}h1{{font-size:32px}}}}
</style></head><body>
<header><div class="brand"><b>ARGIS</b> / media review</div><div class="run" id="run"></div><div class="actions"><button class="btn" id="reset">Reset</button><button class="btn primary" id="export">Export JSON</button></div></header>
<div class="layout"><aside class="left"><div class="eyebrow">Review queue</div><div class="filters"><button class="filter active" data-filter="all">All media</button><button class="filter" data-filter="review">Needs review</button><button class="filter" data-filter="high">High confidence</button><button class="filter" data-filter="suspicious">Likely site assets</button></div></aside>
<main><div class="eyebrow">Evidence control</div><h1>Media confidence</h1><div class="intro">Approve profile images. Reject logos, favicons, marketing artwork, and generic Open Graph media before treating them as identity evidence.</div><div class="toolbar"><input class="control" id="search" placeholder="Search platform or signal"><select class="control" id="sort"><option value="risk">Most suspicious</option><option value="score">Highest confidence</option><option value="platform">Platform A-Z</option></select><select class="control" id="threshold"><option value="0">Any confidence</option><option value="50">50%+</option><option value="70">70%+</option><option value="85">85%+</option></select></div><section class="list" id="list"></section><div class="empty" id="empty">No media matches these filters.</div></main>
<aside class="right"><div class="eyebrow">Selected evidence</div><div class="preview"><img id="detailImage" alt="Selected media"></div><h2 id="detailPlatform">Nothing selected</h2><div class="url" id="detailUrl"></div><dl id="facts"></dl><div class="eyebrow">Signals</div><div class="signals" id="signals"></div><div class="decision"><button class="accept" id="accept">Accept PFP</button><button class="reject" id="reject">Reject asset</button></div></aside></div>
<script>
const target={safe_user}, scannedAt={safe_time}, items={payload};let selected=items[0]||null,filter='all';
const E=s=>String(s).replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const C=n=>n>=80?'var(--good)':n>=50?'var(--warn)':'var(--bad)';
document.getElementById('run').textContent='@'+target+' · '+scannedAt;
function counts(){{return{{accepted:items.filter(x=>x.state==='accepted').length,review:items.filter(x=>x.state==='review').length,rejected:items.filter(x=>x.state==='rejected').length}}}}
function render(){{const q=document.getElementById('search').value.toLowerCase(),min=+document.getElementById('threshold').value,sort=document.getElementById('sort').value;let rows=items.filter(x=>(filter==='all'||filter==='review'&&x.state==='review'||filter==='high'&&x.confidence>=80||filter==='suspicious'&&x.suspicious)&&x.confidence>=min&&(x.platform+' '+x.source+' '+x.signals.join(' ')).toLowerCase().includes(q));rows.sort((a,b)=>sort==='score'?b.confidence-a.confidence:sort==='platform'?a.platform.localeCompare(b.platform):a.confidence-b.confidence);const list=document.getElementById('list');list.innerHTML=rows.map(x=>`<article class="row ${{selected&&x.id===selected.id?'selected':''}}" data-id="${{x.id}}"><img class="thumb" src="${{E(x.image_url)}}" alt="${{E(x.platform)}} media"><div><div class="platform">${{E(x.platform)}}</div><div class="meta">${{E(x.category)}} · ${{E(x.source)}}</div></div><div class="reason">${{E(x.signals.join(' · '))}}</div><div><div class="score">${{x.confidence}}%</div><div class="meter"><i style="--w:${{x.confidence}}%;--c:${{C(x.confidence)}}"></i></div></div><span class="state ${{x.state}}">${{x.state}}</span></article>`).join('');document.getElementById('empty').style.display=rows.length?'none':'block';list.querySelectorAll('.row').forEach(row=>row.onclick=()=>{{selected=items.find(x=>x.id===+row.dataset.id);render();inspect()}})}}
function inspect(){{if(!selected)return;document.getElementById('detailImage').src=selected.image_url;document.getElementById('detailPlatform').textContent=selected.platform;document.getElementById('detailUrl').textContent=selected.image_url;document.getElementById('facts').innerHTML=[['Confidence',selected.confidence+'%'],['Source',selected.source],['Hash',selected.avatar_hash||'not available'],['Decision',selected.state]].map(v=>`<div class="fact"><dt>${{v[0]}}</dt><dd>${{E(v[1])}}</dd></div>`).join('');document.getElementById('signals').innerHTML=selected.signals.map(s=>`<div>• ${{E(s)}}</div>`).join('')}}
document.querySelectorAll('.filter').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.filter').forEach(x=>x.classList.remove('active'));b.classList.add('active');filter=b.dataset.filter;render()}});['search','sort','threshold'].forEach(id=>document.getElementById(id).addEventListener(id==='search'?'input':'change',render));document.getElementById('accept').onclick=()=>{{if(selected)selected.state='accepted';render();inspect()}};document.getElementById('reject').onclick=()=>{{if(selected)selected.state='rejected';render();inspect()}};document.getElementById('reset').onclick=()=>{{items.forEach(x=>x.state='review');render();inspect()}};document.getElementById('export').onclick=()=>{{const data={{target,scanned_at:scannedAt,summary:counts(),media:items}},blob=new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=target+'-media-review.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0)}};render();inspect();
</script></body></html>'''


def write_media_review_dashboard(
    username: str,
    history_entry: Mapping[str, Any],
    output: Path,
) -> tuple[Path, int]:
    results = history_entry.get("results") or {}
    candidates = collect_media_candidates(results)
    output = output.expanduser().resolve()
    if output.suffix.lower() != ".html":
        output = output / f"{username}-media-review.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_media_review_dashboard(
        username, candidates, scanned_at=str(history_entry.get("timestamp") or "unknown")
    ), encoding="utf-8")
    return output, len(candidates)


def register_media_review_command(app: typer.Typer) -> None:
    @app.command("media-review", rich_help_panel="ANALYSIS")
    def media_review_command(
        username: str = typer.Argument(..., help="Username whose latest saved scan should be reviewed."),
        output: Path = typer.Option(Path("."), "--output", "-o", help="HTML file or output directory."),
        open_browser: bool = typer.Option(False, "--open", help="Open the dashboard after generation."),
    ) -> None:
        """Build an interactive confidence dashboard for captured profile media.

        Uses the most recent saved scan for the given username. If the scan
        predates the media-capture feature, re-run the scan first:

            argis scan <username>
        """
        try:
            history = load_history(username)
        except HistoryError as exc:
            console.print(f"[bold red]History error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        if not history:
            console.print(f"[yellow]No saved scan found for @{username}.[/yellow]")
            raise typer.Exit(code=1)

        entry = history[-1]
        results = entry.get("results") or {}
        found = sum(1 for r in results.values() if r.get("status") == "FOUND")
        with_media = sum(1 for r in results.values()
                         if any(k in r for k in ("avatar_url", "avatar", "img", "image", "profile_image")))

        path, count = write_media_review_dashboard(username, entry, output)
        if count:
            console.print(f"[green]Media review dashboard ({count} candidates) -> [underline]{path}[/underline][/green]")
        elif found and not with_media:
            console.print(f"[yellow]Latest scan found {found} accounts but none have captured media.[/yellow]")
            console.print(f"[dim]Re-run [green]argis scan {username}[/green] with the latest version to capture profile images.[/dim]")
        elif not found:
            console.print(f"[yellow]Latest scan for @{username} found no accounts.[/yellow]")
        else:
            console.print(f"[yellow]Dashboard created, but the latest scan has no captured media: {path}[/yellow]")
        if open_browser:
            webbrowser.open(path.as_uri())
