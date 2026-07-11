"""Argis MCP Server.

Exposes Argis's core capabilities as Model Context Protocol tools so any
MCP-compatible AI client (Claude Desktop, Cursor, Windsurf, etc.) can call
them directly.

Run:
  argis mcp                          # stdio transport (default)
  argis mcp --transport sse --port 8080  # SSE transport for web clients

Add to claude_desktop_config.json:
  {
    "mcpServers": {
      "argis": {
        "command": "argis",
        "args": ["mcp"]
      }
    }
  }
"""

from __future__ import annotations

import json

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    _HAS_MCP = True
except Exception:
    _HAS_MCP = False

    class TextContent:
        def __init__(self, type: str = "text", text: str = ""):
            self.type = type
            self.text = text

from argis.core import ArgisEngine, build_email_map


def create_server() -> Server:
    server = Server("argis")

    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="scan",
                description=(
                    "Scan a username across 130+ platforms and return which "
                    "accounts exist. Returns verified hits with titles and emails."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "The handle to scan."},
                        "category": {
                            "type": "string",
                            "description": "Comma-separated category filter (coding, social, media, gaming, etc.). Optional.",
                        },
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="me",
                description=(
                    "Full self-assessment: scan, exposure score, breach check, "
                    "impersonation hunt, geo inference, and a ranked fix-list. "
                    "Answers 'how exposed am I and what do I fix first?'"
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "The handle to assess (should be the user's own)."},
                        "skip_impersonation": {
                            "type": "boolean",
                            "description": "Skip lookalike scan for speed. Default false.",
                        },
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="breach",
                description=(
                    "Check one or more email addresses against Have I Been Pwned "
                    "to see if they appear in known data breaches."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "emails": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Email addresses to check.",
                        },
                    },
                    "required": ["emails"],
                },
            ),
            Tool(
                name="exposure",
                description=(
                    "Score how exposed/linkable a handle is (0-100) and return "
                    "a ranked list of actions to reduce exposure."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "The handle to assess."},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="guard",
                description=(
                    "Hunt for accounts impersonating a handle on lookalike "
                    "variants (typos, leet, homoglyphs). Returns scored matches."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "The handle to protect."},
                        "max_variants": {"type": "integer", "description": "Max lookalike variants to scan (default 60)."},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="locate",
                description=(
                    "Infer probable geographic region from public profile metadata "
                    "(language, script, location fields, currency, platform usage)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "The handle to geolocate."},
                    },
                    "required": ["username"],
                },
            ),
            Tool(
                name="recon",
                description=(
                    "Network reconnaissance: port scan, service detection, "
                    "OS fingerprinting, DNS, WHOIS, and geolocation for a host."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Hostname or IP to scan."},
                        "ports": {"type": "string", "description": "Ports to scan, e.g. '22,80,443'. Optional."},
                    },
                    "required": ["target"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "scan":
            return await _handle_scan(arguments)
        elif name == "me":
            return await _handle_me(arguments)
        elif name == "breach":
            return await _handle_breach(arguments)
        elif name == "exposure":
            return await _handle_exposure(arguments)
        elif name == "guard":
            return await _handle_guard(arguments)
        elif name == "locate":
            return await _handle_locate(arguments)
        elif name == "recon":
            return await _handle_recon(arguments)
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    return server


async def _handle_scan(args: dict) -> list:
    username = args["username"]
    cats = tuple(c.strip() for c in args.get("category", "").split(",")) if args.get("category") else None
    engine = ArgisEngine(username, categories=cats)
    results = await engine.run_scan(quiet=True)
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    blocked = sum(1 for r in results.values() if r.get("status") == "BLOCKED")

    lines = [f"## Scan: @{username}", f"{len(found)} found / {len(results)} scanned / {blocked} blocked", ""]
    for p, r in sorted(found.items()):
        title = r.get("title") or ""
        emails = r.get("emails", [])
        line = f"- **{p}**: {r['url']}"
        if title:
            line += f" ({title})"
        if emails:
            line += f" [emails: {', '.join(emails)}]"
        lines.append(line)
    return [TextContent(type="text", text="\n".join(lines))]


async def _handle_me(args: dict) -> list:
    username = args["username"]
    skip = args.get("skip_impersonation", False)
    try:
        from argis.me import run_me
        report = await run_me(username, skip_impersonation=skip, max_variants=60)
        lines = [
            f"## Self-Assessment: @{username}",
            f"**Risk: {report.risk_level}** | Exposure: {report.exposure_score:.0f}/100 ({report.exposure_grade})",
            f"Accounts: {report.accounts_found} | Breached emails: {report.emails_breached} | Impersonators: {report.impersonators_found}",
            "",
        ]
        if report.geo_signals:
            top = report.geo_signals[0]
            lines.append(f"**Location inference:** {top.country} ({top.confidence:.0%}, {top.evidence})")
            lines.append("")
        if report.breaches:
            comp = [b for b in report.breaches if b.compromised]
            if comp:
                lines.append("**Breached emails:**")
                for b in comp:
                    names = ", ".join(br.name for br in b.breaches[:5])
                    lines.append(f"- {b.email}: {len(b.breaches)} breach(es) ({names})")
                lines.append("")
        if report.impersonators:
            lines.append("**Impersonators:**")
            for imp in report.impersonators[:5]:
                lines.append(f"- {imp.variant} on {imp.platform} ({imp.score:.0%} match)")
            lines.append("")
        if report.actions:
            lines.append("**Fix list (ranked by impact):**")
            for a in report.actions[:7]:
                lines.append(f"{a.priority}. {a.what} (-{a.points_saved:.0f} pts)")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error running self-assessment: {e}")]


async def _handle_breach(args: dict) -> list:
    emails = args["emails"]
    try:
        from argis.breach import check_all
        reports = await check_all(emails)
        lines = ["## Breach Check", ""]
        for r in reports:
            if r.error:
                lines.append(f"- {r.email}: error ({r.error})")
            elif r.compromised:
                names = ", ".join(b.name for b in r.breaches[:6])
                lines.append(f"- **{r.email}**: {len(r.breaches)} breach(es) ({names})")
            else:
                lines.append(f"- {r.email}: clean")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Breach check failed: {e}")]


async def _handle_exposure(args: dict) -> list:
    username = args["username"]
    try:
        from argis.exposure import assess
        from argis.core import ArgisEngine
        engine = ArgisEngine(username)
        results = await engine.run_scan(quiet=True)
        found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
        emails = sorted({e for r in found.values() for e in r.get("emails", [])})
        display_names = {p: r["display_name"] for p, r in found.items() if r.get("display_name")}
        sites = engine._filter_sites()
        cats_map = {p: rules.get("category", "forums") for p, rules in sites.items()}
        rep = assess(username, found, emails=emails, display_names=display_names, categories=cats_map)
        lines = [
            f"## Exposure: @{username}",
            f"**Score: {rep.overall:.0f}/100** ({rep.grade})",
            f"{rep.found} accounts | {len(rep.category_breakdown)} categories | {len(rep.emails_leaked)} emails exposed",
            "", "**Factors:**",
        ]
        for f in rep.factors:
            lines.append(f"- {f.name} ({f.score:.0%}) weight {f.weight}: {f.detail}")
        if rep.shrink_plan:
            lines.append("")
            lines.append("**Shrink plan (high impact first):**")
            for i, a in enumerate(rep.shrink_plan[:8], 1):
                lines.append(f"{i}. {a.platform} ({a.impact:.0%}): {a.reason} {a.url}")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Exposure assessment failed: {e}")]


async def _handle_guard(args: dict) -> list:
    username = args["username"]
    max_v = args.get("max_variants", 60)
    try:
        from argis.impersonate import guard
        g = await guard(username, max_variants=max_v)
        lines = [
            f"## Impersonation Check: @{username}",
            f"{g.variants_scanned} variants scanned | {g.hits} registered | {len(g.impersonators)} flagged",
            "",
        ]
        if g.impersonators:
            lines.append("**Likely impersonators:**")
            for m in g.impersonators[:10]:
                lines.append(f"- {m.variant} on {m.platform} ({m.score:.0%} match) {m.url}")
        else:
            lines.append("No impersonators above threshold. Clean.")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Guard failed: {e}")]


async def _handle_locate(args: dict) -> list:
    username = args["username"]
    try:
        from argis.geo_infer import infer_geo
        engine = ArgisEngine(username)
        results = await engine.run_scan(quiet=True)
        found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
        bios = [r.get("description", "") for r in found.values() if r.get("description")]
        titles = [r.get("title", "") for r in found.values() if r.get("title")]
        signals = infer_geo(bios, titles, list(found.keys()))
        lines = [f"## Geo Inference: @{username}", ""]
        if signals:
            for s in signals[:5]:
                lines.append(f"- **{s.country}** ({s.confidence:.0%}): {s.evidence}")
        else:
            lines.append("Not enough signals to infer location.")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Locate failed: {e}")]


async def _handle_recon(args: dict) -> list:
    target = args["target"]
    ports_str = args.get("ports")
    try:
        from argis.recon import run_recon
        port_list = tuple(int(p.strip()) for p in ports_str.split(",")) if ports_str else None
        report = await run_recon(target, ports=port_list)
        lines = [f"## Recon: {target}", ""]
        if report.open_ports:
            lines.append(f"**Open ports ({len(report.open_ports)}):**")
            for p in report.open_ports[:20]:
                svc = p.service_guess or "unknown"
                lines.append(f"- {p.port}/tcp ({svc})")
        else:
            lines.append("No open ports found.")
        if report.dns and not report.dns.error:
            lines.append("", "**DNS:**")
            for r in report.dns.records[:10]:
                lines.append(f"- {r.type} {r.value}")
        if report.os_guesses:
            lines.append("", "**OS detection:**")
            for g in report.os_guesses:
                lines.append(f"- {g.name} ({g.accuracy}%)")
        return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Recon failed: {e}")]


async def run_stdio():
    server = create_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def run_sse(host: str = "127.0.0.1", port: int = 8080):
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route
    import uvicorn

    server = create_server()
    sse = SseServerTransport("/messages")

    async def handle_sse(request):
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())

    app = Starlette(routes=[
        Route("/sse", endpoint=handle_sse),
        Route("/messages", endpoint=sse.handle_post_message, methods=["POST"]),
    ])
    uvicorn.run(app, host=host, port=port)
