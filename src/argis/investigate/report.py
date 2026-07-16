import json
from datetime import datetime
from typing import Any
from argis.investigate.base import AgentContext, FindingCategory


class InvestigationReport:
    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        self.generated_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        findings = self.ctx.get_findings()
        meta = self.ctx.shared_data.get("investigation_metadata", {})
        scan_total = self.ctx.shared_data.get("scan_total_count", 0)
        scan_found = self.ctx.shared_data.get("scan_found_count", 0)
        emails = self.ctx.shared_data.get("discovered_emails", [])
        profile = self.ctx.shared_data.get("unified_profile", {})
        domains = self.ctx.shared_data.get("domain_info", [])
        breach_reports = self.ctx.shared_data.get("breach_reports", [])
        exposure = self.ctx.shared_data.get("exposure_report", None)
        interests = self.ctx.shared_data.get("detected_interests", [])
        skills = self.ctx.shared_data.get("detected_skills", [])
        orgs = self.ctx.shared_data.get("detected_organizations", [])
        communities = self.ctx.shared_data.get("detected_communities", [])
        wallets = self.ctx.shared_data.get("crypto_wallets", [])
        real_names = self.ctx.shared_data.get("real_names", [])
        by_cat = self.ctx.shared_data.get("platforms_by_category", {})
        geo = self.ctx.shared_data.get("geo_signals", [])
        wayback = self.ctx.shared_data.get("wayback_data", None)
        linguistic = self.ctx.shared_data.get("linguistic_profile", {})
        traits = self.ctx.shared_data.get("personality_traits", [])

        return {
            "report": {
                "generated_at": self.generated_at,
                "target": {
                    "username": self.ctx.target.username,
                    "aliases": self.ctx.target.aliases,
                    "emails": self.ctx.target.known_emails,
                },
                "metadata": meta,
                "scan": {
                    "total_platforms": scan_total,
                    "platforms_found": scan_found,
                    "platforms_by_category": {k: len(v) for k, v in by_cat.items()},
                    "discovered_emails": emails,
                },
                "summary": {
                    "total_findings": len(findings),
                    "high_confidence": len([f for f in findings if f.confidence >= 0.8]),
                    "medium_confidence": len([f for f in findings if 0.5 <= f.confidence < 0.8]),
                    "low_confidence": len([f for f in findings if f.confidence < 0.5]),
                    "by_category": {cat.value: len([f for f in findings if f.category == cat]) for cat in FindingCategory},
                    "by_squad": self._findings_by_squad(findings),
                },
                "findings": [f.to_dict() for f in sorted(findings, key=lambda x: -x.confidence)],
                "errors": self.ctx.errors,
                "intel": {
                    "real_names": real_names,
                    "interests": interests,
                    "skills": skills,
                    "organizations": orgs,
                    "communities": communities,
                    "crypto_wallets": wallets,
                    "personality_traits": traits,
                    "linguistic_profile": linguistic,
                    "geo_signals": [{"country": g.country, "confidence": g.confidence, "evidence": g.evidence} for g in geo] if geo else [],
                    "wayback_snapshots": [{"timestamp": s.timestamp, "url": s.url, "status": s.status_code} for s in wayback.snapshots[:15]] if wayback and wayback.snapshots else [],
                },
                "security": {
                    "breach_reports": [{"email": r.email, "compromised": r.compromised, "breaches": [{"name": b.name, "domain": b.domain, "date": b.date, "data_classes": b.data_classes} for b in r.breaches]} for r in breach_reports] if breach_reports else [],
                    "exposure_score": getattr(exposure, "overall", None) if exposure else None,
                    "exposure_grade": getattr(exposure, "grade", None) if exposure else None,
                },
                "domains": [{"domain": d["domain"], "has_dns": bool(d.get("dns")), "dns_records": d.get("dns"), "has_whois": bool(d.get("whois"))} for d in domains] if domains else [],
                "scores": self._generate_scores(findings),
            }
        }

    def to_html(self) -> str:
        d = self.to_dict()["report"]
        s = d["summary"]
        target = d["target"]
        scan = d["scan"]
        scores = d["scores"]
        intel = d["intel"]
        sec = d["security"]
        domains = d["domains"]

        def bar(val: int, maxv: int = 100, color: str = "#22c55e") -> str:
            pct = min(100, int(val / maxv * 100)) if maxv else 0
            return f'<div class="bar"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'

        def confidence_badge(c: float) -> str:
            p = int(c * 100)
            cls = "high" if p >= 80 else "med" if p >= 50 else "low"
            return f'<span class="conf {cls}">{p}%</span>'

        def section(title: str, body: str, icon: str = "") -> str:
            return f'<div class="section"><h2>{icon} {title}</h2>{body}</div>'

        cat_counts = scan.get("platforms_by_category", {})
        findings_by_cat = s.get("by_category", {})

        cat_rows = "".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in sorted(cat_counts.items()))
        squad_rows = "".join(f'<tr><td>{k.upper()}</td><td>{v}</td></tr>' for k, v in sorted(s.get("by_squad", {}).items()))

        score_rows = ""
        score_colors = {"exposure_score": "#ef4444", "risk_score": "#f59e0b", "profile_completeness": "#22c55e", "intelligence_confidence": "#3b82f6"}
        for k, v in scores.items():
            lbl = k.replace("_", " ").title()
            c = score_colors.get(k, "#64748b")
            score_rows += f'<div class="score-item"><span class="score-label">{lbl}</span><span class="score-val">{v}/100</span>{bar(v, color=c)}</div>'

        finding_rows = ""
        for f in d["findings"]:
            pct = int(f["confidence"] * 100)
            ev = "".join(f'<li>{e}</li>' for e in f.get("evidence", [])[:4])
            finding_rows += f'''
            <div class="finding">
              <div class="finding-hdr">
                <span class="finding-agent">#{f["agent_id"]:02d} {f["agent_name"]}</span>
                {confidence_badge(f["confidence"])}
                <span class="finding-cat">{f["category"]}</span>
              </div>
              <div class="finding-title">{f["title"]}</div>
              <div class="finding-desc">{f["description"]}</div>
              {"<ul class='finding-ev'>" + ev + "</ul>" if ev else ""}
            </div>'''

        intel_rows = ""
        if intel.get("real_names"):
            intel_rows += f'<p><strong>Real Names:</strong> {" | ".join(intel["real_names"][:8])}</p>'
        if intel.get("interests"):
            intel_rows += f'<p><strong>Interests:</strong> {", ".join(intel["interests"][:12])}</p>'
        if intel.get("skills"):
            intel_rows += f'<p><strong>Skills:</strong> {", ".join(intel["skills"][:15])}</p>'
        if intel.get("organizations"):
            intel_rows += f'<p><strong>Organizations:</strong> {", ".join(intel["organizations"][:8])}</p>'
        if intel.get("communities"):
            intel_rows += f'<p><strong>Communities:</strong> {", ".join(intel["communities"][:12])}</p>'
        if intel.get("personality_traits"):
            intel_rows += f'<p><strong>Personality Traits:</strong> {", ".join(intel["personality_traits"][:10])}</p>'
        if intel.get("crypto_wallets"):
            intel_rows += f'<p><strong>Crypto Wallets:</strong><br/>{"<br/>".join(intel["crypto_wallets"][:5])}</p>'
        if intel.get("linguistic_profile"):
            lp = intel["linguistic_profile"]
            intel_rows += f'<p><strong>Linguistic Profile:</strong> {lp.get("word_count",0)} words, avg sentence {lp.get("avg_sentence_length","?")} chars</p>'

        breach_rows = ""
        for r in sec.get("breach_reports", []):
            for b in r.get("breaches", []):
                breach_rows += f'<tr><td>{b["name"]}</td><td>{b["date"]}</td><td>{", ".join(b.get("data_classes",[]))}</td></tr>'

        domain_rows = ""
        for dm in domains:
            status = "✅" if dm["has_dns"] else "❌"
            domain_rows += f'<tr><td>{dm["domain"]}</td><td>{status}</td><td>{(dm.get("dns_records") or ["-"])[0]}</td></tr>'

        geo_rows = ""
        for g in intel.get("geo_signals", []):
            geo_rows += f'<tr><td>{g.get("country","?")}</td><td>{int(g.get("confidence",0)*100)}%</td><td>{g.get("evidence","")}</td></tr>'

        wayback_list = ""
        for snap in intel.get("wayback_snapshots", []):
            wayback_list += f'<li>{snap.get("timestamp","?")} — <a href="{snap.get("url","#")}">{snap.get("url","")}</a> (HTTP {snap.get("status","?")})</li>'

        risk_color = "#22c55e"
        if sec.get("exposure_score") is not None:
            es = sec["exposure_score"]
            risk_color = "#ef4444" if es >= 60 else "#f59e0b" if es >= 30 else "#22c55e"

        return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argis Investigation Report — @{target["username"]}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0a0e1a;--surface:#111827;--surface2:#1e293b;--border:#1e293b;--fg:#e2e8f0;--dim:#64748b;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--blue:#38bdf8;--pink:#ec4899;--cyan:#22d3ee;--orange:#f97316}}
body{{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;padding:0}}
.container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
h1{{font-size:28px;font-weight:700;margin-bottom:4px}}
h2{{font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border);color:var(--cyan)}}
h3{{font-size:15px;font-weight:600;margin:12px 0 8px;color:var(--fg)}}
.meta{{color:var(--dim);font-size:13px;margin-bottom:24px}}
.section{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px}}
.score-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}}
.score-item{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px}}
.score-label{{font-size:12px;color:var(--dim);display:block}}
.score-val{{font-size:24px;font-weight:700;display:block;margin:4px 0 8px}}
.bar{{height:4px;background:var(--surface2);border-radius:2px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:2px;transition:width .5s}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--surface2)}}
th{{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
tr:hover td{{background:var(--surface2)}}
.finding{{background:var(--surface2);border-radius:8px;padding:14px;margin-bottom:10px}}
.finding-hdr{{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}}
.finding-agent{{font-size:12px;font-weight:600;color:var(--cyan)}}
.finding-title{{font-weight:600;font-size:14px;margin-bottom:4px}}
.finding-desc{{font-size:13px;color:var(--dim);margin-bottom:4px}}
.finding-cat{{font-size:10px;text-transform:uppercase;color:var(--dim);background:var(--surface);padding:2px 8px;border-radius:4px}}
.finding-ev{{margin:8px 0 0 16px;font-size:12px;color:var(--dim)}}
.conf{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
.conf.high{{background:rgba(34,197,94,.15);color:var(--green)}}
.conf.med{{background:rgba(250,204,21,.15);color:var(--yellow)}}
.conf.low{{background:rgba(100,116,139,.15);color:var(--dim)}}
.risk-banner{{padding:16px 20px;border-radius:10px;margin-bottom:20px;color:#fff;font-weight:700;font-size:18px;text-align:center}}
.header-strip{{display:flex;gap:24px;flex-wrap:wrap;margin:16px 0 24px}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;flex:1;min-width:120px;text-align:center}}
.stat-card .num{{font-size:28px;font-weight:700;display:block}}
.stat-card .lbl{{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr}}}}
a{{color:var(--blue)}}
ul{{margin:4px 0 4px 16px}}
li{{font-size:13px;margin:2px 0}}
</style>
</head>
<body>
<div class="container">
<div style="text-align:center;margin-bottom:24px">
<h1>Argis <span style="color:var(--green)">Investigation Report</span></h1>
<p class="meta">@{target["username"]} · {self.generated_at[:10]} · {s["total_findings"]} findings · agents: 50</p>
</div>

<div class="risk-banner" style="background:{risk_color}">
  {sec.get("exposure_grade","N/A")} — Exposure Score: {sec.get("exposure_score","?")}/100
</div>

<div class="header-strip">
  <div class="stat-card"><span class="num" style="color:var(--cyan)">{scan["platforms_found"]}</span><span class="lbl">Platforms Found</span></div>
  <div class="stat-card"><span class="num" style="color:var(--blue)">{scan["total_platforms"]}</span><span class="lbl">Total Scanned</span></div>
  <div class="stat-card"><span class="num" style="color:var(--green)">{s["high_confidence"]}</span><span class="lbl">High Conf Findings</span></div>
  <div class="stat-card"><span class="num" style="color:var(--yellow)">{len(scan.get("discovered_emails",[]))}</span><span class="lbl">Emails Discovered</span></div>
  <div class="stat-card"><span class="num" style="color:var(--pink)">{len(domains)}</span><span class="lbl">Domains Checked</span></div>
</div>

{section("Score Dashboard", f'<div class="score-row">{score_rows}</div>', "📊")}

<div class="two-col">
{section("Platforms by Category", f'<table>{"".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in sorted(cat_counts.items()))}</table>', "🌐")}
{section("Squad Performance", f'<table>{"".join(f"<tr><td>{k.upper()}</td><td>{v}</td></tr>" for k,v in sorted(s.get("by_squad",{}).items()))}</table>', "🤖")}
</div>

{section("Intelligence Summary", intel_rows if intel_rows else "<p class=meta>No intelligence data extracted</p>", "🧠")}

<div class="two-col">
{section("Domain Intelligence", f'''<table><tr><th>Domain</th><th>DNS</th><th>Record</th></tr>{domain_rows}</table>''' if domain_rows else "<p class=meta>No domain data</p>", "🌍")}
{section("Geolocation Signals", f'''<table><tr><th>Country</th><th>Confidence</th><th>Evidence</th></tr>{geo_rows}</table>''' if geo_rows else "<p class=meta>No geolocation data</p>", "📍")}
</div>

{section("Breach Intelligence", f'''<table><tr><th>Breach</th><th>Date</th><th>Data Exposed</th></tr>{breach_rows}</table>''' if breach_rows else "<p class=meta>No breaches detected. All clear.</p>", "🔓")}

{section("Wayback Machine", f'<ul>{wayback_list}</ul>' if wayback_list else "<p class=meta>No Wayback snapshots found</p>", "📜")}

{section("All Findings ({s['total_findings']} total)", finding_rows, "🔍")}

<div class="section">
  <p class="meta" style="text-align:center">
    Generated by Argis Deep Investigation System · 50 agents · 5 squads<br>
    {d["metadata"].get("duration_seconds",0):.1f}s · {d.get("errors","") and f"Errors: {len(d['errors'])}" or "No errors"}
  </p>
</div>
</div>
</body>
</html>'''

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        d = self.to_dict()["report"]
        s = d["summary"]
        lines = []
        lines.append(f"# Investigation Report: @{d['target']['username']}")
        lines.append(f"*Generated: {d['generated_at']}*\n")
        lines.append("## Summary")
        lines.append(f"- **Total Findings**: {s['total_findings']}")
        lines.append(f"- **High Confidence** (≥80%): {s['high_confidence']}")
        lines.append(f"- **Medium Confidence** (50-79%): {s['medium_confidence']}")
        lines.append(f"- **Low Confidence** (<50%): {s['low_confidence']}")
        lines.append(f"- **Duration**: {d['metadata'].get('duration_seconds', 'N/A')}s")
        lines.append(f"- **Agents Executed**: {d['metadata'].get('total_agents', 'N/A')}\n")
        sc = d.get("scan", {})
        lines.append("## Scan Results")
        lines.append(f"- **Platforms Found**: {sc.get('platforms_found',0)} / {sc.get('total_platforms',0)}")
        lines.append(f"- **Emails Discovered**: {len(sc.get('discovered_emails',[]))}")
        by_cat = sc.get("platforms_by_category", {})
        for k, v in sorted(by_cat.items()):
            lines.append(f"  - {k}: {v}")
        lines.append("\n## Scores")
        for k, v in d.get("scores", {}).items():
            lines.append(f"- **{k.replace('_',' ').title()}**: {v}/100")
        intel = d.get("intel", {})
        if intel.get("real_names"):
            lines.append(f"\n## Intelligence")
            lines.append(f"- **Real Names**: {' | '.join(intel['real_names'][:5])}")
        if intel.get("skills"):
            lines.append(f"- **Skills**: {', '.join(intel['skills'][:10])}")
        if intel.get("interests"):
            lines.append(f"- **Interests**: {', '.join(intel['interests'][:8])}")
        if intel.get("organizations"):
            lines.append(f"- **Organizations**: {', '.join(intel['organizations'][:5])}")
        if intel.get("personality_traits"):
            lines.append(f"- **Traits**: {', '.join(intel['personality_traits'][:8])}")
        if intel.get("geo_signals"):
            lines.append("### Geolocation")
            for g in intel["geo_signals"][:3]:
                lines.append(f"- {g.get('country','?')} ({int(g.get('confidence',0)*100)}%): {g.get('evidence','')}")
        sec = d.get("security", {})
        if sec.get("breach_reports"):
            lines.append("\n## Breaches")
            for r in sec["breach_reports"]:
                if r.get("compromised"):
                    for b in r["breaches"]:
                        lines.append(f"- {b['name']} ({b['date']}): {', '.join(b.get('data_classes',[]))}")
        if sec.get("exposure_score") is not None:
            lines.append(f"\n## Threat Assessment")
            lines.append(f"- **Exposure Score**: {sec['exposure_score']}/100 (Grade: {sec.get('exposure_grade','N/A')})")
        lines.append(f"\n## Key Findings")
        for f in d["findings"]:
            if f["confidence"] >= 0.8:
                lines.append(f"\n### {f['title']}")
                lines.append(f"- Agent: {f['agent_name']} #{f['agent_id']} | Confidence: {int(f['confidence']*100)}%")
                lines.append(f"- {f['description']}")
                for e in f.get("evidence", [])[:5]:
                    lines.append(f"  - {e}")
        lines.append("\n## All Findings ({s['total_findings']} total)")
        for f in d["findings"]:
            lines.append(f"\n- **{f['title']}** ({int(f['confidence']*100)}%) — {f['agent_name']}")
            lines.append(f"  {f['description'][:100]}")
        if d["errors"]:
            lines.append("\n## Errors")
            for err in d["errors"]:
                lines.append(f"- {err}")
        return "\n".join(lines)

    def _findings_by_squad(self, findings) -> dict:
        squad_map = {
            FindingCategory.IDENTITY: "alpha",
            FindingCategory.SOCIAL: "beta",
            FindingCategory.PROFESSIONAL: "gamma",
            FindingCategory.DEEP_WEB: "delta",
            FindingCategory.SPECIALIST: "epsilon",
        }
        counts = {}
        for f in findings:
            squad = squad_map.get(f.category, "unknown")
            counts[squad] = counts.get(squad, 0) + 1
        return counts

    def _get_shared_summary(self) -> dict:
        keys = ["unified_profile", "platform_candidates", "real_name_candidates",
                "email_candidates", "inferred_interests", "inferred_skills",
                "threat_assessment", "likely_communities", "psychological_traits"]
        return {k: self.ctx.shared_data.get(k) for k in keys if self.ctx.shared_data.get(k)}

    def _generate_scores(self, findings) -> dict:
        exposure = min(100, len(findings) * 3)
        high_conf = len([f for f in findings if f.confidence >= 0.8])
        deep_web_hits = len([f for f in findings if f.category == FindingCategory.DEEP_WEB and f.confidence >= 0.5])
        risk = min(100, deep_web_hits * 25 + (1 if high_conf > 5 else 0) * 20)
        prof_completeness = min(100, len([f for f in findings if f.category == FindingCategory.IDENTITY]) * 12)
        return {
            "exposure_score": exposure,
            "risk_score": risk,
            "profile_completeness": prof_completeness,
            "intelligence_confidence": min(100, int(sum(f.confidence for f in findings) / max(len(findings), 1) * 100)),
        }
