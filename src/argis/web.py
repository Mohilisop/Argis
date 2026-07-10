"""Minimal local web UI for Argis (Maigret-style browser mode).

Run:  argis web           # then open http://127.0.0.1:8000
One endpoint scans, one streams the dossier HTML back. No data leaves the box.
"""

from __future__ import annotations

import asyncio

try:
    from fastapi import FastAPI, Query
    from fastapi.responses import HTMLResponse, JSONResponse
except Exception:
    FastAPI = None

_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>Argis</title><style>
body{background:#0f172a;color:#e2e8f0;font-family:ui-monospace,monospace;
  max-width:760px;margin:0 auto;padding:48px 20px}
h1{color:#22c55e}input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;
  padding:10px 14px;border-radius:8px;font:inherit;width:280px}
button{background:#22c55e;color:#0f172a;border:0;padding:10px 18px;border-radius:8px;
  font:inherit;font-weight:700;cursor:pointer;margin-left:8px}
#out{margin-top:24px;white-space:pre-wrap}a{color:#38bdf8}
</style></head><body>
<h1>&#128065; Argis</h1>
<form onsubmit="go(event)">
  <input id=u placeholder="username" autofocus>
  <button>scan</button>
</form>
<div id=out></div>
<script>
async function go(e){e.preventDefault();
  const u=document.getElementById('u').value.trim(); if(!u)return;
  const out=document.getElementById('out'); out.textContent='scanning @'+u+'...';
  const r=await fetch('/api/scan?username='+encodeURIComponent(u));
  const d=await r.json();
  out.innerHTML='<b>'+d.found+'/'+d.total+' found</b> &middot; '
    +'<a href="/report?username='+encodeURIComponent(u)+'" target=_blank>open full dossier</a><br><br>'
    + d.hits.map(h=>'&#10003; '+h.platform+' &rarr; <a href="'+h.url+'" target=_blank>'+h.url+'</a>').join('<br>');
}
</script></body></html>"""


def create_app():
    if FastAPI is None:
        raise RuntimeError("web UI needs fastapi+uvicorn: pip install \"argis[web]\"")

    app = FastAPI(title="Argis")

    @app.get("/", response_class=HTMLResponse)
    def home():
        return _PAGE

    @app.get("/api/scan")
    async def scan(username: str = Query(...)):
        from argis.core import ArgisEngine
        eng = ArgisEngine(username)
        res = await eng.run_scan(quiet=True)
        hits = [{"platform": p, "url": r["url"]}
                for p, r in res.items() if r.get("status") == "FOUND"]
        return JSONResponse({"username": username, "total": len(res),
                             "found": len(hits), "hits": hits})

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
