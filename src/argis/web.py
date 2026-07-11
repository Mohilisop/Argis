"""Local web UI for Argis (Maigret-style browser mode).

Run:  argis web           # then open http://127.0.0.1:8000
Features: live streaming results, category-grouped cards, inline dossier.
No data leaves the box.
"""

from __future__ import annotations

import asyncio
import json

try:
    from fastapi import FastAPI, Query, Request
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
except Exception:
    FastAPI = None


_PAGE = """<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Argis</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel=stylesheet>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--surface:#111827;--surface2:#1e293b;--border:#1e293b;--fg:#e2e8f0;--dim:#64748b;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--blue:#38bdf8;--pink:#ec4899;--cyan:#22d3ee}
body{background:var(--bg);color:var(--fg);font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;flex-direction:column}
.scanlines{position:fixed;inset:0;pointer-events:none;z-index:9999;background:repeating-linear-gradient(0deg,rgba(0,0,0,.03) 0,rgba(0,0,0,.03) 1px,transparent 1px,transparent 3px)}
.container{max-width:900px;margin:0 auto;padding:32px 20px;width:100%;flex:1}
header{margin-bottom:32px;text-align:center}
header h1{font-size:28px;font-weight:700;letter-spacing:-.5px;animation:flickIn .6s ease-out}
header h1 .green{color:var(--green)}header h1 .dim{color:var(--dim)}
header p{color:var(--dim);font-size:13px;margin-top:6px}
@keyframes flickIn{0%{opacity:0;transform:translateY(-8px)}60%{opacity:.7}to{opacity:1;transform:translateY(0)}}
.scan-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px}
.scan-form{display:flex;gap:12px;flex-wrap:wrap}
.scan-form input{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--border);color:var(--fg);padding:12px 16px;border-radius:8px;font:inherit;font-size:15px;outline:none;transition:border-color .2s}
.scan-form input:focus{border-color:var(--green)}
.scan-form button{background:var(--green);color:#0a0e1a;border:0;padding:12px 24px;border-radius:8px;font:inherit;font-weight:700;font-size:15px;cursor:pointer;transition:opacity .2s}
.scan-form button:hover{opacity:.85}.scan-form button:disabled{opacity:.4;cursor:not-allowed}
.status-bar{display:flex;gap:16px;flex-wrap:wrap;margin-top:16px;padding-top:16px;border-top:1px solid var(--border);font-size:13px;min-height:36px}
.stat{display:flex;align-items:center;gap:6px}
.stat .num{font-weight:700}.stat .num.green{color:var(--green)}.stat .num.red{color:var(--red)}.stat .num.yellow{color:var(--yellow)}.stat .num.blue{color:var(--blue)}
.progress-wrap{width:100%;height:4px;background:var(--surface2);border-radius:2px;overflow:hidden;margin-top:12px;display:none}
.progress-bar{height:100%;width:0%;background:linear-gradient(90deg,var(--green),var(--cyan));border-radius:2px;transition:width .3s ease}
.results{margin-top:24px;display:none}
.results.show{display:block}
.results-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
.results-header h2{font-size:16px;color:var(--dim)}
.results-actions{display:flex;gap:8px;flex-wrap:wrap}
.results-actions a,.results-actions button{background:var(--surface2);border:1px solid var(--border);color:var(--fg);padding:6px 14px;border-radius:6px;font:inherit;font-size:12px;cursor:pointer;text-decoration:none;transition:background .2s}
.results-actions a:hover,.results-actions button:hover{background:var(--border)}
.cat-group{margin-bottom:20px}
.cat-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface2);border-radius:8px 8px 0 0;cursor:pointer;user-select:none;font-size:13px;font-weight:600;transition:background .2s}
.cat-head:hover{filter:brightness(1.1)}
.cat-head .arrow{transition:transform .2s;font-size:10px;color:var(--dim)}
.cat-head.open .arrow{transform:rotate(90deg)}
.cat-count{background:var(--bg);border-radius:10px;padding:1px 8px;font-size:11px;color:var(--dim)}
.cat-body{display:none;border:1px solid var(--surface2);border-top:0;border-radius:0 0 8px 8px;overflow:hidden}
.cat-body.open{display:block}
.platform-row{display:grid;grid-template-columns:32px 1fr auto;gap:10px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--surface2);font-size:13px;transition:background .2s}
.platform-row:last-child{border-bottom:0}
.platform-row:hover{background:var(--surface2)}
.platform-row .status{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.platform-row .status.found{background:var(--green);box-shadow:0 0 6px var(--green)}
.platform-row .status.not_found{background:var(--dim)}
.platform-row .status.blocked{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}
.platform-row .status.timeout{background:var(--red);box-shadow:0 0 6px var(--red)}
.platform-row .status.unknown{background:#6b7280}
.platform-row .name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.platform-row .url{color:var(--dim);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.platform-row .url a{color:var(--blue);text-decoration:none}
.platform-row .url a:hover{text-decoration:underline}
.empty-state{text-align:center;padding:48px 20px;color:var(--dim)}
.empty-state .icon{font-size:40px;margin-bottom:12px;opacity:.3}
.filter-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.filter-btn{padding:4px 12px;border-radius:12px;border:1px solid var(--border);background:transparent;color:var(--dim);font:inherit;font-size:11px;cursor:pointer;transition:all .2s}
.filter-btn:hover{color:var(--fg);border-color:var(--fg)}
.filter-btn.active{background:var(--green);color:#0a0e1a;border-color:var(--green);font-weight:700}
.error-msg{padding:16px;background:rgba(239,68,68,.1);border:1px solid var(--red);border-radius:8px;color:var(--red);font-size:13px;margin-top:12px;display:none}
footer{margin-top:32px;text-align:center;color:var(--dim);font-size:11px;padding:16px 0}
@media(max-width:600px){.container{padding:16px 12px}.scan-form input{min-width:100%}.results-actions{width:100%}.results-actions a,.results-actions button{flex:1;text-align:center}}
</style></head>
<body>
<div class=scanlines></div>
<div class=container>
<header>
<h1><span class=green>argis</span><span class=dim> scan</span></h1>
<p>username reconnaissance &middot; 509 platforms</p>
</header>
<div class=scan-box>
<form class=scan-form id=form>
<input id=u type=text placeholder="enter username" autofocus spellcheck=false autocomplete=off>
<button id=go>scan</button>
</form>
<div class=status-bar id=statusBar>
<div class=stat id=sProgress><span class=num id=progressNum>0</span><span>/<span id=totalNum>0</span> <span class=dim>checked</span></span></div>
<div class=stat><span class="num green" id=foundNum>0</span> <span class=dim>found</span></div>
<div class=stat><span class="num red" id=notFoundNum>0</span> <span class=dim>not found</span></div>
<div class=stat><span class="num yellow" id=blockedNum>0</span> <span class=dim>blocked</span></div>
</div>
<div class=progress-wrap id=progressWrap><div class=progress-bar id=progressBar></div></div>
<div class=error-msg id=errorMsg></div>
</div>
<div class=results id=results>
<div class=results-header>
<h2 id=resultTitle>results</h2>
<div class=results-actions>
<button id=toggleAll onclick="toggleAll()">toggle all</button>
<a id=dossierLink href="#" target=_blank style="display:none">open dossier &nearr;</a>
</div>
</div>
<div class=filter-bar id=filterBar></div>
<div id=resultBody></div>
</div>
</div>
<footer>argis v0.6 &middot; open source on github &middot; all scanning runs locally</footer>
<script>
const CAT_COLORS={coding:'#22c55e',social:'#38bdf8',creative:'#ec4899',gaming:'#eab308',professional:'#a855f7',blogging:'#f97316',security:'#ef4444',lifestyle:'#14b8a6',learning:'#06b6d4',finance:'#10b981',funding:'#f59e0b',media:'#8b5cf6',messaging:'#22d3ee',docs:'#64748b',startup:'#ec4899',identity:'#6b7280',uncategorized:'#64748b'}
let allResults=null,activeFilter=null,resultsVisible=false
document.getElementById('form').addEventListener('submit',async e=>{e.preventDefault()
const u=document.getElementById('u').value.trim();if(!u)return
const go=document.getElementById('go');go.disabled=true;go.textContent='scanning...'
document.getElementById('errorMsg').style.display='none'
document.getElementById('results').classList.remove('show')
document.getElementById('dossierLink').style.display='none'
allResults=null
document.getElementById('progressWrap').style.display='block'
document.getElementById('progressBar').style.width='0%'
try{
const r=await fetch('/api/scan/stream?username='+encodeURIComponent(u))
if(!r.ok){const e=await r.json();showError(e.detail||'scan failed');return}
const reader=r.body.getReader(),dec=new TextDecoder()
let buf=''
while(true){const{done,value}=await reader.read();if(done)break
buf+=dec.decode(value,{stream:true})
for(const m of buf.split('\\n')){if(!m.startsWith('data:'))continue
const line=m.slice(5).trim()
if(line==='[DONE]')continue
try{const d=JSON.parse(line)
if(d.type==='progress')updateProgress(d)
else if(d.type==='result')addResult(d)
else if(d.type==='done')onScanDone(d)
else if(d.type==='error')showError(d.message)}
catch(e){}}}}
catch(e){showError(e.message||'connection failed')}
finally{go.disabled=false;go.textContent='scan'}})
function updateProgress(d){document.getElementById('progressNum').textContent=d.done
document.getElementById('totalNum').textContent=d.total
const pct=d.total>0?(d.done/d.total*100):0
document.getElementById('progressBar').style.width=pct+'%'}
function updateCounts(){if(!allResults)return
let f=0,nf=0,b=0
for(const r of Object.values(allResults)){if(r.status==='FOUND')f++
else if(r.status==='NOT_FOUND')nf++
else if(r.status==='BLOCKED')b++}
document.getElementById('foundNum').textContent=f
document.getElementById('notFoundNum').textContent=nf
document.getElementById('blockedNum').textContent=b}
function addResult(d){if(!allResults)allResults={}
allResults[d.platform]=d;updateCounts()}
function onScanDone(d){allResults=d.results||allResults
document.getElementById('progressWrap').style.display='none'
updateCounts()
buildResults()
document.getElementById('results').classList.add('show')
const total=Object.keys(allResults).length
const found=Object.values(allResults).filter(r=>r.status==='FOUND').length
document.getElementById('resultTitle').textContent=found+'/'+total+' found'
if(found>0){const link=document.getElementById('dossierLink')
link.href='/report?username='+encodeURIComponent(d.username)
link.style.display='inline-block'}}
function showError(msg){const el=document.getElementById('errorMsg')
el.textContent=msg;el.style.display='block'}
function buildResults(){if(!allResults)return
const cats={}
for(const[name,r]of Object.entries(allResults)){const c=r.category||'uncategorized'
if(!cats[c])cats[c]={}
cats[c][name]=r}
const body=document.getElementById('resultBody');body.innerHTML=''
const filterBar=document.getElementById('filterBar');filterBar.innerHTML=''
let hasFilter=false
const allBtn=document.createElement('button')
allBtn.className='filter-btn active';allBtn.textContent='all'
allBtn.onclick=()=>{activeFilter=null;document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));allBtn.classList.add('active');rebuild()}
filterBar.appendChild(allBtn)
for(const[cat,members]of Object.entries(cats)){const count=Object.keys(members).length
if(count===0)continue;hasFilter=true
const btn=document.createElement('button')
btn.className='filter-btn';btn.textContent=cat+' ('+count+')'
const color=CAT_COLORS[cat]||'#64748b';btn.style.setProperty('--accent',color)
btn.onclick=()=>{activeFilter=cat
document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'))
btn.classList.add('active');rebuild()}
filterBar.appendChild(btn)}
rebuild()
function rebuild(){body.innerHTML='';let any=!1
for(const[cat,members]of Object.entries(cats)){if(activeFilter&&activeFilter!==cat)continue
const entries=Object.entries(members)
if(entries.length===0)continue;any=!0
const group=document.createElement('div');group.className='cat-group'
const head=document.createElement('div');head.className='cat-head open'
const color=CAT_COLORS[cat]||'#64748b'
head.style.borderLeft='3px solid '+color
head.innerHTML='<span class=arrow>&#9654;</span><span style=color:'+color+'>'+cat+'</span><span class=cat-count>'+entries.length+'</span>'
head.onclick=()=>{head.classList.toggle('open');bodyEl.classList.toggle('open')}
const bodyEl=document.createElement('div');bodyEl.className='cat-body open'
for(const[name,r]of entries){const row=document.createElement('div');row.className='platform-row'
const dot=document.createElement('div');dot.className='status '+r.status.toLowerCase()
const nm=document.createElement('div');nm.className='name';nm.textContent=name
const u=document.createElement('div');u.className='url'
if(r.url){const a=document.createElement('a');a.href=r.url;a.target='_blank';a.textContent=r.url;u.appendChild(a)}
row.appendChild(dot);row.appendChild(nm);row.appendChild(u)
bodyEl.appendChild(row)}
group.appendChild(head);group.appendChild(bodyEl);body.appendChild(group)}
if(!any){body.innerHTML='<div class=empty-state><div class=icon>&#128269;</div><p>no results match this filter</p></div>'}}}
function toggleAll(){document.querySelectorAll('.cat-head,.cat-body').forEach(el=>el.classList.toggle('open'))}
</script>
</body></html>"""


def _scan_stats(results: dict) -> dict:
    return {
        "total": len(results),
        "found": sum(1 for r in results.values() if r.get("status") == "FOUND"),
        "not_found": sum(1 for r in results.values() if r.get("status") == "NOT_FOUND"),
        "blocked": sum(1 for r in results.values() if r.get("status") == "BLOCKED"),
    }


def create_app():
    if FastAPI is None:
        raise RuntimeError("web UI needs fastapi+uvicorn: pip install \"argis[web]\"")

    app = FastAPI(title="Argis")

    @app.get("/", response_class=HTMLResponse)
    def home():
        return _PAGE

    @app.get("/api/scan/stream")
    async def scan_stream(username: str = Query(...)):
        from argis.core import ArgisEngine

        results: dict = {}
        total = 0

        async def event_stream():
            nonlocal results, total
            eng = ArgisEngine(username)
            sites = eng._filter_sites()
            total = len(sites)

            yield f"data: {json.dumps({'type': 'progress', 'done': 0, 'total': total})}\n\n"

            from argis.utils.network import build_client

            async with build_client(
                proxy=eng.proxy, use_tor=eng.use_tor,
                timeout=eng.timeout, http2=eng.http2,
            ) as client:
                done = 0
                for name, rules in sites.items():
                    out = await eng.check_platform(client, name, rules)
                    results[name] = out
                    done += 1
                    yield f"data: {json.dumps({'type': 'result', 'platform': name, 'status': out['status'], 'url': out.get('url', ''), 'category': rules.get('category', 'uncategorized')})}\n\n"
                    yield f"data: {json.dumps({'type': 'progress', 'done': done, 'total': total})}\n\n"

            yield f"data: {json.dumps({'type': 'done', 'username': username, 'results': results})}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.get("/api/scan")
    async def scan(username: str = Query(...)):
        from argis.core import ArgisEngine

        eng = ArgisEngine(username)
        res = await eng.run_scan(quiet=True)
        hits = [{"platform": p, "r": r}
                for p, r in res.items() if r.get("status") == "FOUND"]
        return JSONResponse({
            "username": username,
            "stats": _scan_stats(res),
            "hits": [
                {"platform": h["platform"], "url": h["r"]["url"],
                 "title": h["r"].get("title")}
                for h in hits
            ],
        })

    @app.get("/report", response_class=HTMLResponse)
    async def report(username: str = Query(...)):
        from argis.dossier import build_dossier, to_html_report
        from argis.core import ArgisEngine

        eng = ArgisEngine(username)
        res = await eng.run_scan(quiet=True)
        cats = {n: r.get("category", "uncategorized")
                for n, r in eng.sites.items()}
        dsr = await build_dossier(username, res, site_categories=cats)
        return to_html_report(dsr)

    return app
