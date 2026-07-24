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
                "dork_findings": self.ctx.shared_data.get("dork_findings", []),
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
        errors = d.get("errors", [])
        meta = d.get("metadata", {})
        dork_findings = d.get("dork_findings", [])

        cat_counts = scan.get("platforms_by_category", {})
        total_found = scan.get("platforms_found", 0)
        total_scanned = scan.get("total_platforms", 0)
        email_count = len(scan.get("discovered_emails", []))
        domain_count = len(domains)
        high_count = s.get("high_confidence", 0)
        total_findings = s.get("total_findings", 0)

        exposure_score = sec.get("exposure_score")
        exposure_grade = sec.get("exposure_grade", "N/A")
        if exposure_score is not None:
            if exposure_score >= 60: risk_cls = "high"; grade_color = "#ef4444"; risk_text = "High Exposure"
            elif exposure_score >= 30: risk_cls = "medium"; grade_color = "#f59e0b"; risk_text = "Moderate Exposure"
            else: risk_cls = "low"; grade_color = "#22c55e"; risk_text = "Low Exposure"
        else:
            risk_cls = "low"; grade_color = "#22c55e"; risk_text = "Unknown"; exposure_score = 0

        cat_rows = "".join(f'<tr class="hover:bg-cyber-cyan/5 transition-colors duration-200"><td class="py-3.5 flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-cyber-cyan"></span> {k}</td><td class="py-3.5 text-right font-extrabold text-slate-200">{v} Profiles</td><td class="py-3.5 text-right"><span class="text-cyber-cyan font-bold uppercase">MAPPED</span></td></tr>' for k, v in sorted(cat_counts.items()))

        squad_map_names = {"alpha": "Alpha Squad (Identity)", "beta": "Beta Squad (Social)", "gamma": "Gamma Squad (Professional)", "delta": "Delta Squad (Deep Web)", "epsilon": "Epsilon Squad (Specialist)"}
        squad_colors = {"alpha": "#22d3ee", "beta": "#eab308", "gamma": "#a855f7", "delta": "#ec4899", "epsilon": "#10b981"}
        sq = s.get("by_squad", {})
        total_squad = sum(sq.values()) or 1
        sq_rows = "".join(f'<tr class="hover:bg-cyber-accentGreen/5 transition-colors duration-200"><td class="py-3.5 flex items-center gap-2.5"><span class="w-2.5 h-2.5 rounded-full" style="background:{squad_colors.get(k, "#64748b")}"></span> {squad_map_names.get(k, k.upper())}</td><td class="py-3.5 text-right font-extrabold" style="color:{squad_colors.get(k, "#64748b")}">{v} Entries</td><td class="py-3.5 text-right text-slate-400">{v / total_squad * 100:.1f}% System Cap</td></tr>' for k, v in sorted(sq.items()))

        score_bars = ""
        score_items = [
            ("exposure_score", "Exposure Intensity", "#ef4444", "#f97316"),
            ("risk_score", "Risk Vector Assessment", "#f59e0b", "#ec4899"),
            ("profile_completeness", "Profile Integrity Scope", "#22d3ee", "#a855f7"),
            ("intelligence_confidence", "Security Confidence", "#10b981", "#22d3ee"),
        ]
        for key, label, c1, c2 in score_items:
            val = scores.get(key, 0)
            pct = min(100, val)
            if key == "exposure_score" and exposure_score:
                if exposure_score >= 60: c1, c2 = "#ef4444", "#f97316"
                elif exposure_score >= 30: c1, c2 = "#f59e0b", "#f97316"
            score_bars += f'''
            <div>
              <div class="flex justify-between text-xs font-mono text-slate-300 mb-1.5">
                <span class="font-bold">{label}</span>
                <span class="font-extrabold font-mono" style="color:{c1}">{pct}%</span>
              </div>
              <div class="w-full h-3.5 bg-cyber-gray/40 rounded-full overflow-hidden border relative shadow-inner" style="border-color:rgba({int(c1[1:3],16)},{int(c1[3:5],16)},{int(c1[5:7],16)},0.2)">
                <div class="h-full rounded-full relative transition-all duration-1000" style="width:{pct}%;background:linear-gradient(90deg,{c1},{c2})">
                  <div class="absolute inset-0" style="background:linear-gradient(45deg,rgba(255,255,255,0.15) 25%,transparent 25%,transparent 50%,rgba(255,255,255,0.15) 50%,rgba(255,255,255,0.15) 75%,transparent 75%,transparent);background-size:15px 15px"></div>
                </div>
              </div>
            </div>'''

        def tag(text, cls=""):
            if not text: return ""
            return f'<span class="intel-tag {cls}">{str(text)[:50]}</span>'

        intel_html = ""
        if dork_findings:
            dork_items = "".join(
                f'<li class="flex items-start gap-2"><i class="fa-solid fa-link text-cyber-cyan mt-1"></i><span><a href="{f.get("evidence", [""])[0]}" target="_blank" class="text-cyber-cyan underline">{f.get("title", "?")[:60]}</a> <span class="text-slate-500">({f.get("platform", "deep_web")})</span></span></li>'
                for f in dork_findings[:10]
            )
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-link"></i> Surface Exposure</h3><ul class="text-[11px] font-mono text-slate-300 space-y-2">{dork_items}</ul></div>'

        if intel.get("real_names"):
            tags = "".join(tag(n) for n in intel["real_names"][:8])
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-fingerprint"></i> Extracted Names / Aliases</h3><div class="flex flex-wrap gap-2 pt-1">{tags}</div></div>'
        if intel.get("interests"):
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-heart"></i> Psychographic Interests</h3><div class="flex flex-wrap gap-2 pt-1">{"".join(tag(i, "green") for i in intel["interests"][:12])}</div></div>'
        if intel.get("skills"):
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-code"></i> Identified Skill Vectors</h3><div class="flex flex-wrap gap-2 pt-1">{"".join(tag(sk, "purple") for sk in intel["skills"][:12])}</div></div>'
        if intel.get("organizations"):
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-building"></i> Affiliated Organizations</h3><div class="flex flex-wrap gap-2 pt-1">{"".join(tag(o, "pink") for o in intel["organizations"][:8])}</div></div>'
        if intel.get("communities"):
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-users"></i> Communities & Circles</h3><div class="flex flex-wrap gap-2 pt-1">{"".join(tag(c, "orange") for c in intel["communities"][:8])}</div></div>'
        if intel.get("crypto_wallets"):
            wtags = " | ".join(f'<code style="font-size:11px;background:rgba(255,255,255,0.05);padding:2px 8px;border-radius:4px;color:var(--orange)">{w[:30]}...</code>' for w in intel["crypto_wallets"][:5])
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-coins"></i> Crypto Wallets</h3><div class="flex flex-wrap gap-2 pt-1">{wtags}</div></div>'
        if intel.get("personality_traits"):
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-brain"></i> Traits & Linguistic Fingerprint</h3><div class="flex flex-wrap gap-2 pt-1">{"".join(tag(t) for t in intel["personality_traits"][:8])}</div></div>'
        if intel.get("linguistic_profile"):
            lp = intel["linguistic_profile"]
            wc = lp.get("word_count", 0) if isinstance(lp, dict) else getattr(lp, "word_count", 0)
            asl = lp.get("avg_sentence_length", "?") if isinstance(lp, dict) else getattr(lp, "avg_sentence_length", "?")
            intel_html += f'<div class="intel-section"><h3><i class="fa-solid fa-chart-simple"></i> Linguistic Metrics</h3><div class="flex flex-wrap gap-2 pt-1"><span class="intel-tag purple">{wc} words</span><span class="intel-tag purple">avg {asl} chars/sent</span></div></div>'

        breach_rows = ""
        for r in sec.get("breach_reports", []):
            breaches = r.get("breaches", []) if isinstance(r, dict) else getattr(r, "breaches", [])
            for b in breaches:
                name = b.get("name", "?") if isinstance(b, dict) else getattr(b, "name", "?")
                date = str(b.get("date", "")) if isinstance(b, dict) else str(getattr(b, "date", ""))
                classes = ", ".join(b.get("data_classes", [])) if isinstance(b, dict) else ", ".join(getattr(b, "data_classes", []))
                breach_rows += f'<tr class="hover:bg-cyber-pink/5 transition-colors duration-200"><td class="py-3.5 text-cyber-pink font-semibold">{name}</td><td class="py-3.5">{date}</td><td class="py-3.5 text-slate-400">{classes}</td></tr>'
        breach_count = len(sec.get("breach_reports", []))

        domain_rows = ""
        for dm in domains:
            dom = dm.get("domain", "?")
            has_dns = dm.get("has_dns", False)
            ip = (dm.get("dns_records") or ["-"])[0]
            if has_dns:
                domain_rows += f'<tr class="hover:bg-cyber-cyan/5 transition-colors duration-200"><td class="py-3.5 text-cyber-cyan font-bold">{dom}</td><td class="py-3.5 text-center"><span class="px-2.5 py-1 rounded bg-cyber-accentGreen/10 text-cyber-accentGreen border border-cyber-accentGreen/25 text-[10px] font-bold">ACTIVE</span></td><td class="py-3.5 text-right text-cyber-accentGreen font-bold">{ip[:50]}</td></tr>'
            else:
                domain_rows += f'<tr class="hover:bg-cyber-cyan/5 transition-colors duration-200"><td class="py-3.5 text-cyber-pink font-semibold">{dom}</td><td class="py-3.5 text-center"><span class="px-2.5 py-1 rounded bg-cyber-accentRed/10 text-cyber-accentRed border border-cyber-accentRed/25 text-[10px] font-bold">INACTIVE</span></td><td class="py-3.5 text-right text-slate-500">-</td></tr>'

        geo_rows = ""
        for g in intel.get("geo_signals", []):
            country = g.get("country", "?") if isinstance(g, dict) else getattr(g, "country", "?")
            conf = int((g.get("confidence", 0) if isinstance(g, dict) else getattr(g, "confidence", 0)) * 100)
            ev = (g.get("evidence", "") if isinstance(g, dict) else str(getattr(g, "evidence", "")))[:60]
            geo_rows += f'<tr class="hover:bg-cyber-pink/5 transition-colors duration-200"><td class="py-3.5 text-slate-100 font-bold flex items-center gap-2"><i class="fa-solid fa-location-crosshairs text-cyber-accentRed"></i> {country}</td><td class="py-3.5 text-center font-extrabold" style="color:{grade_color if conf > 50 else "#f59e0b"}">{conf}% Confidence</td><td class="py-3.5 text-right text-slate-400">{ev}</td></tr>'

        wayback_rows = ""
        for snap in intel.get("wayback_snapshots", []):
            ts = snap.get("timestamp", "?")[:10]
            url = snap.get("url", "")[:80]
            wayback_rows += f'<tr class="hover:bg-cyber-cyan/5 transition-colors"><td class="py-3 font-mono text-xs">{ts}</td><td class="py-3 text-xs text-cyber-cyan" style="max-width:300px;overflow:hidden">{url}</td></tr>'

        high_f = [x for x in d["findings"] if x["confidence"] >= 0.8]
        high_rows = ""
        for finding in high_f[:6]:
            pct = int(finding["confidence"] * 100)
            cat = finding.get("category", "unknown")
            cat_icon = {"identity": "fa-fingerprint", "social": "fa-comments", "professional": "fa-briefcase", "deep_web": "fa-user-secret", "specialist": "fa-brain"}.get(cat, "fa-circle")
            ev = "".join(f'<li class="flex items-start gap-2"><i class="fa-solid fa-chevron-right text-cyber-cyan mt-1"></i><span>{e}</span></li>' for e in finding.get("evidence", [])[:3])
            high_rows += f'''
            <div class="border border-cyber-cyan/20 rounded-xl p-5 bg-[#030612] relative flex flex-col justify-between hover:border-cyber-cyan transition duration-300">
              <div>
                <div class="flex justify-between items-center mb-3">
                  <span class="text-[10px] font-mono font-bold text-cyber-cyan bg-cyber-cyan/10 px-2 py-1 rounded">#{finding["agent_id"]:02d} {finding["agent_name"]}</span>
                  <span class="text-xs font-mono font-bold text-cyber-accentGreen">{pct}% ACCURACY</span>
                </div>
                <h3 class="text-sm font-bold text-slate-200 font-mono mb-2">{finding["title"][:80]}</h3>
                <p class="text-xs text-slate-400 font-mono mb-4 leading-relaxed">{finding["description"][:120]}</p>
                {"<ul class=\"text-[11px] font-mono text-slate-300 space-y-2 border-t border-slate-900 pt-3\">" + ev + "</ul>" if ev else ""}
              </div>
            </div>'''

        all_findings_js = []
        for finding in d["findings"]:
            pct = int(finding["confidence"] * 100)
            cat = finding.get("category", "unknown")
            all_findings_js.append({
                "id": finding["agent_id"],
                "agent": finding["agent_name"],
                "accuracy": pct,
                "category": cat,
                "title": finding["title"][:80],
                "desc": finding["description"][:150],
                "details": (finding.get("evidence") or ["No additional details"])[0][:200],
            })

        import json as _json
        findings_json = _json.dumps(all_findings_js)

        duration = meta.get("duration_seconds", 0)
        target_upper = target["username"].upper()
        grade_display = exposure_grade
        exposure_val = exposure_score

        radar_signal = {"high": "ELEVATED", "medium": "MODERATE", "low": "STABLE"}.get(risk_cls, "SCANNING")
        scan_ratio = total_found / max(total_scanned, 1)
        radar_angle = f"{scan_ratio * 360:.2f}°"
        radar_pct = scores.get("profile_completeness", 0) or 0
        signal_color = {"high": "#ef4444", "medium": "#f59e0b", "low": "#22d3ee"}.get(risk_cls, "#22d3ee")
        radar_pulse = "animate-ping" if risk_cls == "high" else ""

        return f'''<!doctype html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ARGIS ● DEEP INVESTIGATION — @{target["username"]}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {{
  darkMode: 'class',
  theme: {{
    extend: {{
      colors: {{
        cyber: {{
          bg: '#050711', surface: '#0d1122', cyan: '#00f0ff', purple: '#a855f7',
          pink: '#ec4899', turquoise: '#22d3ee', gray: '#1e293b',
          accentRed: '#ef4444', accentGreen: '#10b981', accentYellow: '#f59e0b',
        }}
      }},
      fontFamily: {{ sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] }}
    }}
  }}
}}
</script>
<style>
:root {{ --cyan-glow: 0 0 15px rgba(0,240,255,0.35); --purple-glow: 0 0 15px rgba(168,85,247,0.3); --pink-glow: 0 0 15px rgba(236,72,153,0.3); }}
.crt-overlay {{ position:fixed;top:0;left:0;width:100vw;height:100vh;background:linear-gradient(rgba(18,16,16,0) 50%,rgba(0,0,0,0.25) 50%),linear-gradient(90deg,rgba(255,0,0,0.03),rgba(0,255,0,0.01),rgba(0,0,255,0.03));background-size:100% 3px,3px 100%;z-index:9999;pointer-events:none;opacity:0.65 }}
body {{ overflow-x:hidden; font-size:15px; line-height:1.65; letter-spacing:0.01em; }}
.dark body {{ color:#e2e8f0; }}
.glow-gradient-text {{ background:linear-gradient(135deg,#00f0ff 10%,#a855f7 50%,#ec4899 90%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text }}
.glass-panel {{ backdrop-filter:blur(25px) saturate(1.4);-webkit-backdrop-filter:blur(25px) saturate(1.4);transition:all 0.3s cubic-bezier(0.16,1,0.3,1) }}
.laser-scan-container {{ position:relative;overflow:hidden }}
.laser-scan-container::after {{ content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#00f0ff 50%,transparent);box-shadow:0 0 12px #00f0ff;animation:laser-sweep 5s infinite linear;z-index:10;pointer-events:none }}
@keyframes laser-sweep {{ 0%{{transform:translateY(-10%)}}50%{{transform:translateY(1500%)}}100%{{transform:translateY(-10%)}} }}
@keyframes sweep {{ from{{transform:rotate(0deg)}}to{{transform:rotate(360deg)}} }}
.radar-beam {{ animation:sweep 4s linear infinite;transform-origin:50px 50px }}
::-webkit-scrollbar {{ width:7px;height:7px }}
::-webkit-scrollbar-track {{ background:#050711 }}
::-webkit-scrollbar-thumb {{ background:#1e293b;border-radius:99px;border:1px solid rgba(0,240,255,0.15) }}
::-webkit-scrollbar-thumb:hover {{ background:#00f0ff }}
.intel-tag {{ transition:all 0.2s cubic-bezier(0.16,1,0.3,1);display:inline-block;padding:4px 12px;margin:3px 4px 3px 0;border-radius:20px;font-size:12px;font-weight:500;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.15);color:#38bdf8;cursor:pointer }}
.intel-tag:hover {{ transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,240,255,0.2) }}
.intel-tag.green {{ background:rgba(16,185,129,0.1);border-color:rgba(16,185,129,0.15);color:#10b981 }}
.intel-tag.purple {{ background:rgba(168,85,247,0.1);border-color:rgba(168,85,247,0.15);color:#a855f7 }}
.intel-tag.pink {{ background:rgba(236,72,153,0.1);border-color:rgba(236,72,153,0.15);color:#ec4899 }}
.intel-tag.orange {{ background:rgba(245,158,11,0.1);border-color:rgba(245,158,11,0.15);color:#f59e0b }}
.intel-section {{ margin-bottom:16px }}
.intel-section h3 {{ font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.3px;margin-bottom:8px;display:flex;align-items:center;gap:6px }}
.neon-border-cyan {{ box-shadow:0 0 10px rgba(0,240,255,0.15) }}
</style>
</head>
<body class="bg-cyber-bg text-slate-200 min-h-screen relative font-sans overflow-x-hidden">

<canvas id="particlesCanvas" class="fixed top-0 left-0 w-full h-full pointer-events-none z-0 opacity-40"></canvas>
<div class="crt-overlay"></div>

<div id="systemPreloader" class="fixed inset-0 bg-[#03050c] z-[99999] flex flex-col items-center justify-center font-mono text-cyber-cyan p-6 transition-all duration-700">
  <div class="max-w-xl w-full border border-cyber-cyan/30 rounded-xl p-6 bg-cyber-surface/90 shadow-[0_0_60px_rgba(0,240,255,0.15)] relative laser-scan-container">
    <div class="flex items-center justify-between border-b border-cyber-cyan/20 pb-4 mb-4">
      <div class="flex items-center gap-2">
        <i class="fa-solid fa-triangle-exclamation text-cyber-pink animate-pulse"></i>
        <span class="text-xs tracking-widest font-bold uppercase text-cyber-pink">System Decryption Sequence Active</span>
      </div>
      <div class="flex space-x-1.5">
        <span class="w-3 h-3 rounded-full bg-cyber-pink"></span>
        <span class="w-3 h-3 rounded-full bg-cyber-accentYellow"></span>
        <span class="w-3 h-3 rounded-full bg-cyber-cyan"></span>
      </div>
    </div>
    <div id="preloaderTerminal" class="h-44 overflow-y-auto mb-4 text-xs space-y-1.5 text-slate-300 pr-2 leading-relaxed font-mono"></div>
    <div class="space-y-2">
      <div class="flex justify-between text-xs font-semibold"><span>EXTRACTING IDENTITY RECORDS</span><span id="preloadPercent" class="text-cyber-cyan font-mono">0%</span></div>
      <div class="w-full bg-cyber-gray/40 h-2.5 rounded-full overflow-hidden border border-cyber-cyan/20 relative">
        <div id="preloadProgressBar" class="h-full bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-pink transition-all duration-100" style="width:0%"></div>
      </div>
    </div>
  </div>
</div>

<div id="dashboardContainer" class="relative z-10 max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8 opacity-0 transition-opacity duration-1000">

<header class="flex flex-col lg:flex-row items-center justify-between border border-cyber-cyan/20 bg-cyber-surface/70 backdrop-blur-md rounded-2xl p-6 mb-8 shadow-xl relative laser-scan-container">
  <div class="flex items-center space-x-5 mb-5 lg:mb-0 w-full lg:w-auto">
    <div class="relative w-14 h-14 flex-shrink-0">
      <div class="absolute inset-0 border-2 border-dashed border-cyber-pink rounded-full animate-[spin_15s_linear_infinite] opacity-75"></div>
      <div class="absolute inset-1 border-2 border-double border-cyber-cyan rounded-full animate-[spin_8s_linear_infinite] opacity-50"></div>
      <div class="absolute inset-3 bg-cyber-cyan/10 border border-cyber-cyan rounded-full flex items-center justify-center">
        <i class="fa-solid fa-crosshairs text-cyber-cyan text-base animate-pulse"></i>
      </div>
    </div>
    <div>
      <h2 class="text-xs text-cyber-cyan font-mono font-bold tracking-[0.25em] uppercase">ARGIS DEEP INVESTIGATION</h2>
      <h1 class="text-2xl sm:text-3.5xl font-black font-mono tracking-wider flex items-center">
        TARGET: <span class="glow-gradient-text ml-2 drop-shadow-[0_0_10px_rgba(0,240,255,0.2)]">@{target["username"]}</span>
      </h1>
    </div>
  </div>
  <div class="flex flex-wrap items-center justify-center lg:justify-end gap-5 w-full lg:w-auto border-t lg:border-t-0 border-slate-800/60 pt-4 lg:pt-0">
    <div class="text-right font-mono text-xs text-slate-400 border-r border-slate-800/80 pr-5 hidden sm:block leading-tight">
      <div>AGENTS: <span class="text-cyber-cyan font-bold">50</span></div>
      <div class="text-cyber-pink font-semibold mt-1">5 SQUADS ACTIVE</div>
    </div>
    <button id="themeSwitcher" class="w-11 h-11 border border-cyber-cyan/30 hover:border-cyber-cyan rounded-xl flex items-center justify-center bg-cyber-surface/40 hover:bg-cyber-surface transition-all duration-300"><i class="fa-solid fa-moon text-cyber-cyan text-sm" id="themeIcon"></i></button>
    <span class="border border-cyber-pink/40 bg-cyber-pink/10 text-cyber-pink px-4 py-2 rounded-xl font-mono text-xs font-extrabold tracking-widest animate-pulse shadow-[0_0_15px_rgba(236,72,153,0.1)]">CLASSIFIED · LEVEL 4</span>
  </div>
</header>

<section class="border border-cyber-cyan/30 rounded-2xl p-6 bg-gradient-to-br from-cyber-surface/80 to-[#030610] shadow-[0_0_40px_rgba(0,240,255,0.05)] mb-8 relative">
  <div class="absolute top-0 right-0 bg-cyber-cyan/15 text-cyber-cyan font-mono text-[10px] uppercase font-bold tracking-widest px-3.5 py-1.5 rounded-bl-xl rounded-tr-xl border-l border-b border-cyber-cyan/25">Tactical Briefing Panel</div>
  <div class="flex items-center gap-3.5 border-b border-slate-800/80 pb-4 mb-4">
    <div class="w-2.5 h-2.5 rounded-full bg-cyber-cyan animate-ping"></div>
    <h2 class="text-sm font-mono text-cyber-cyan tracking-wider font-extrabold uppercase flex items-center gap-2"><i class="fa-solid fa-scroll text-sm"></i> Executive Summary & Tactical Intel Debrief</h2>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs text-slate-300 leading-relaxed">
    <div class="lg:col-span-2 space-y-4">
      <p><strong class="text-slate-100 font-bold">OVERVIEW:</strong> Subject <span class="text-cyber-cyan font-semibold">@{target["username"]}</span> presents a multi-disciplinary digital surface area. Cross-referencing nodes mapped exactly <strong class="text-cyber-pink">{total_found} active configurations</strong> spanning {total_scanned} platform registries. {f"No verified data leaks detected." if breach_count == 0 else f"{breach_count} breach records identified during scanning."}</p>
      <p><strong class="text-slate-100 font-bold">TACTICAL FOCUS:</strong> Key interest groups and skill vectors mapped across {len(cat_counts)} platform categories. {f"Primary domains: {', '.join(sorted(cat_counts.keys())[:5])}." if cat_counts else ""}</p>
    </div>
    <div class="bg-cyber-bg/80 border border-slate-800/80 rounded-xl p-4 space-y-3 flex flex-col justify-between">
      <div>
        <div class="text-[10px] text-slate-400 font-bold uppercase tracking-widest mb-1.5">Intelligence Status Feed</div>
        <div class="space-y-2">
          <div class="flex justify-between items-center border-b border-slate-900 pb-1.5"><span>Threat Rating:</span><span class="text-cyber-accentYellow font-bold">{risk_text.upper()}</span></div>
          <div class="flex justify-between items-center border-b border-slate-900 pb-1.5"><span>Information Density:</span><span class="text-cyber-cyan font-bold">HIGH</span></div>
          <div class="flex justify-between items-center"><span>System Health:</span><span class="text-cyber-accentGreen font-bold flex items-center gap-1"><i class="fa-solid fa-circle-check"></i>{' SECURE' if len(errors) == 0 else f' {len(errors)} ERRORS'}</span></div>
        </div>
      </div>
      <div class="text-[10px] text-slate-500 italic mt-3 leading-tight">Intelligence gathered through Argis 50-agent investigation. Generated: {self.generated_at[:10]}</div>
    </div>
  </div>
</section>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
  <div class="lg:col-span-1 border border-cyber-accentYellow/30 rounded-2xl p-6 bg-gradient-to-br from-cyber-accentYellow/10 via-cyber-surface/90 to-[#03050a] backdrop-blur-md relative overflow-hidden glass-panel shadow-[0_0_30px_rgba(245,158,11,0.05)] hover:shadow-[0_0_40px_rgba(245,158,11,0.15)] cursor-pointer" id="riskMetricCard">
    <div class="absolute top-0 right-0 p-4"><span class="flex h-3 w-3 relative"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-accentYellow opacity-75"></span><span class="relative inline-flex rounded-full h-3 w-3 bg-cyber-accentYellow"></span></span></div>
    <div class="flex justify-between items-start mb-5">
      <div><h3 class="text-xs text-cyber-accentYellow tracking-wider font-mono font-bold uppercase">Risk Rating Framework</h3><p class="text-lg font-bold text-slate-100 font-mono mt-0.5">{risk_text.upper()} SIGNAL</p></div>
      <i class="fa-solid fa-shield-halved text-cyber-accentYellow text-2xl animate-pulse"></i>
    </div>
    <div class="flex items-center justify-around my-6">
      <div class="relative w-28 h-28 flex items-center justify-center">
        <svg class="absolute inset-0 w-full h-full transform -rotate-90">
          <circle cx="56" cy="56" r="46" stroke="rgba(30,41,59,0.6)" stroke-width="6" fill="transparent"/>
          <circle cx="56" cy="56" r="46" stroke="{grade_color}" stroke-width="8" stroke-dasharray="289" stroke-dashoffset="{max(0, 289 - 289 * exposure_val / 100)}" fill="transparent" class="transition-all duration-1000"/>
        </svg>
        <div class="text-center z-10"><span class="text-5xl font-black font-mono tracking-tighter drop-shadow-[0_0_12px_rgba(245,158,11,0.4)]" style="color:{grade_color}">{grade_display}</span><p class="text-[10px] text-slate-400 font-mono font-bold mt-0.5">GRADE</p></div>
      </div>
      <div class="space-y-3.5">
        <div><div class="text-[10px] text-slate-400 font-mono uppercase tracking-wide">Exposure Index</div><div class="text-3xl font-extrabold font-mono" style="color:{grade_color}">{exposure_val}<span class="text-sm text-slate-400">/100</span></div></div>
        <div><div class="text-[10px] text-slate-400 font-mono uppercase tracking-wide">Leak Verification</div><div class="text-xs font-mono text-cyber-accentGreen font-bold flex items-center gap-1.5"><i class="fa-solid fa-circle-check animate-pulse"></i>{' NO LEAKS' if breach_count == 0 else f' {breach_count} BREACHES'}</div></div>
      </div>
    </div>
    <div class="border-t border-slate-800/80 pt-4 flex justify-between text-xs text-slate-400 font-mono"><span>PROBED SITES: {total_found} PORTALS</span><span class="text-cyber-accentYellow flex items-center gap-1 hover:underline"><i class="fa-solid fa-triangle-exclamation animate-pulse"></i> {risk_text.upper()}</span></div>
  </div>

  <div class="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
    <div class="border border-cyber-cyan/15 rounded-2xl p-5 bg-cyber-surface/60 backdrop-blur-md flex flex-col justify-between hover:border-cyber-cyan transition-all duration-300 glass-panel cursor-pointer group shadow-lg">
      <div class="flex justify-between items-center mb-4"><span class="text-xs text-cyber-cyan font-mono font-bold tracking-wider uppercase">Platforms Mapped</span><div class="w-9 h-9 rounded-xl bg-cyber-cyan/10 flex items-center justify-center group-hover:bg-cyber-cyan/20"><i class="fa-solid fa-network-wired text-cyber-cyan text-sm"></i></div></div>
      <div><span class="text-4.5xl font-black font-mono tracking-tighter text-slate-100 stat-counter" data-target="{total_found}">0</span><div class="text-[11px] text-slate-400 font-mono tracking-wide mt-1 uppercase">Active Profiles</div></div>
    </div>
    <div class="border border-cyber-accentGreen/15 rounded-2xl p-5 bg-cyber-surface/60 backdrop-blur-md flex flex-col justify-between hover:border-cyber-accentGreen transition-all duration-300 glass-panel cursor-pointer group shadow-lg">
      <div class="flex justify-between items-center mb-4"><span class="text-xs text-cyber-accentGreen font-mono font-bold tracking-wider uppercase">Total Findings</span><div class="w-9 h-9 rounded-xl bg-cyber-accentGreen/10 flex items-center justify-center group-hover:bg-cyber-accentGreen/20"><i class="fa-solid fa-magnifying-glass-chart text-cyber-accentGreen text-sm"></i></div></div>
      <div><span class="text-4.5xl font-black font-mono tracking-tighter text-slate-100 stat-counter" data-target="{total_findings}">0</span><div class="text-[11px] text-slate-400 font-mono tracking-wide mt-1 uppercase">Evaluated Incidents</div></div>
    </div>
    <div class="border border-cyber-pink/15 rounded-2xl p-5 bg-cyber-surface/60 backdrop-blur-md flex flex-col justify-between hover:border-cyber-pink transition-all duration-300 glass-panel cursor-pointer group shadow-lg">
      <div class="flex justify-between items-center mb-4"><span class="text-xs text-cyber-pink font-mono font-bold tracking-wider uppercase">Emails Found</span><div class="w-9 h-9 rounded-xl bg-cyber-pink/10 flex items-center justify-center group-hover:bg-cyber-pink/20"><i class="fa-solid fa-envelope text-cyber-pink text-sm"></i></div></div>
      <div><span class="text-4.5xl font-black font-mono tracking-tighter text-slate-100 stat-counter" data-target="{email_count}">0</span><div class="text-[11px] text-slate-400 font-mono tracking-wide mt-1 uppercase">Mailboxes Mapped</div></div>
    </div>
    <div class="border border-cyber-purple/15 rounded-2xl p-5 bg-cyber-surface/60 backdrop-blur-md flex flex-col justify-between hover:border-cyber-purple transition-all duration-300 glass-panel cursor-pointer group shadow-lg">
      <div class="flex justify-between items-center mb-4"><span class="text-xs text-cyber-purple font-mono font-bold tracking-wider uppercase">Domains Probed</span><div class="w-9 h-9 rounded-xl bg-cyber-purple/10 flex items-center justify-center group-hover:bg-cyber-purple/20"><i class="fa-solid fa-globe text-cyber-purple text-sm"></i></div></div>
      <div><span class="text-4.5xl font-black font-mono tracking-tighter text-slate-100 stat-counter" data-target="{domain_count}">0</span><div class="text-[11px] text-slate-400 font-mono tracking-wide mt-1 uppercase">DNS Hostpoints</div></div>
    </div>
  </div>
</div>

<section class="border border-cyber-pink/20 rounded-2xl p-6 bg-cyber-surface/50 backdrop-blur-md mb-8">
  <div class="flex items-center gap-3 border-b border-slate-800/85 pb-4 mb-6">
    <i class="fa-solid fa-bullseye text-cyber-pink text-lg"></i>
    <h2 class="text-sm font-mono text-cyber-pink tracking-wider font-extrabold uppercase">Tactical Spotlight: Top High-Confidence Findings</h2>
  </div>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    {high_rows if high_rows else '<div class="md:col-span-3 text-center text-slate-500 font-mono text-xs p-8 border border-dashed border-slate-800 rounded-xl">No high-confidence findings to spotlight</div>'}
  </div>
</section>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
  <div class="lg:col-span-2 border border-cyber-cyan/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-cyan mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-bars-progress text-base"></i> Target Footprint Indicators</h2>
    <div class="space-y-6">{score_bars}</div>
    <div class="flex flex-wrap items-center justify-between mt-6 pt-5 border-t border-slate-800/80 text-xs font-mono text-slate-400 gap-4">
      <div class="flex items-center gap-2"><span class="inline-block w-2 h-2 rounded-full bg-cyber-cyan animate-pulse"></span>50-AGENT INVESTIGATION PROTOCOL v1.0</div>
      <div>{duration:.1f}s SCAN DURATION</div>
    </div>
  </div>
  <div class="lg:col-span-1 border border-cyber-pink/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-pink mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-satellite-dish text-base"></i> Active Risk Radar</h2>
    <div class="flex justify-center items-center relative py-2">
      <svg class="w-52 h-52 border border-cyber-cyan/10 rounded-full bg-[#070b16]/60 shadow-inner" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="42" fill="none" stroke="#22d3ee" stroke-opacity="0.1" stroke-width="0.5"/>
        <circle cx="50" cy="50" r="32" fill="none" stroke="#22d3ee" stroke-opacity="0.15" stroke-width="0.5"/>
        <circle cx="50" cy="50" r="22" fill="none" stroke="#22d3ee" stroke-opacity="0.2" stroke-width="0.5"/>
        <circle cx="50" cy="50" r="12" fill="none" stroke="#22d3ee" stroke-opacity="0.25" stroke-width="0.5"/>
        <line x1="50" y1="8" x2="50" y2="92" stroke="#22d3ee" stroke-opacity="0.2" stroke-width="0.5" stroke-dasharray="1 1"/>
        <line x1="8" y1="50" x2="92" y2="50" stroke="#22d3ee" stroke-opacity="0.2" stroke-width="0.5" stroke-dasharray="1 1"/>
        <polygon points="50,8 78,42 68,78 32,72 22,38" fill="rgba(236,72,153,0.22)" stroke="#ec4899" stroke-width="1.5" class="animate-pulse"/>
        <line x1="50" y1="50" x2="50" y2="8" stroke="#00f0ff" stroke-width="1" class="radar-beam"/>
      </svg>
    </div>
    <div class="mt-4 space-y-2 text-xs font-mono text-slate-400 border-t border-slate-800/80 pt-4">
      <div class="flex justify-between items-center"><span class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full" style="background:{signal_color};{('animation: ping 1s cubic-bezier(0,0,0.2,1) infinite' if risk_cls == 'high' else '')}"></span>SIGNAL: {radar_signal}</span><span class="text-cyber-cyan">SCAN RADIAN: {radar_angle}</span></div>
      <div class="w-full bg-cyber-gray/40 h-1.5 rounded-full overflow-hidden"><div class="h-full" style="width:{radar_pct}%;background:linear-gradient(90deg,{signal_color},#22d3ee)"></div></div>
    </div>
  </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
  <div class="border border-cyber-cyan/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-cyan mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-server animate-pulse"></i> Platform Categories Mapped</h2>
    <div class="overflow-x-auto"><table class="w-full font-mono text-xs text-slate-300"><thead><tr class="border-b border-slate-800/80 text-slate-400 font-bold"><th class="py-3 text-left font-semibold uppercase tracking-wider">Category</th><th class="py-3 text-right font-semibold uppercase tracking-wider">Accounts</th><th class="py-3 text-right font-semibold uppercase tracking-wider">Status</th></tr></thead><tbody class="divide-y divide-slate-800/50">{cat_rows if cat_rows else '<tr><td class="py-3.5 text-slate-500" colspan="3">No categories mapped</td></tr>'}</tbody></table></div>
  </div>
  <div class="border border-cyber-accentGreen/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-accentGreen mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-users-viewfinder animate-pulse"></i> Squad Performance Log</h2>
    <div class="overflow-x-auto"><table class="w-full font-mono text-xs text-slate-300"><thead><tr class="border-b border-slate-800/80 text-slate-400 font-bold"><th class="py-3 text-left font-semibold uppercase tracking-wider">Squad</th><th class="py-3 text-right font-semibold uppercase tracking-wider">Findings</th><th class="py-3 text-right font-semibold uppercase tracking-wider">Load</th></tr></thead><tbody class="divide-y divide-slate-800/50">{sq_rows if sq_rows else '<tr><td class="py-3.5 text-slate-500" colspan="3">No squad data</td></tr>'}</tbody></table></div>
  </div>
</div>

<div class="border border-cyber-pink/25 rounded-2xl p-6 bg-cyber-surface/70 backdrop-blur-md shadow-2xl mb-8 relative laser-scan-container">
  <h2 class="text-base font-mono glow-gradient-text mb-6 flex items-center gap-2.5 tracking-wider font-extrabold uppercase"><i class="fa-solid fa-brain text-lg animate-pulse"></i> Target Intelligence Mapping</h2>
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    {intel_html if intel_html else '<div class="md:col-span-3 text-center text-slate-500 font-mono text-xs p-8">No intelligence data extracted</div>'}
  </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
  <div class="border border-cyber-cyan/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-cyan mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-server"></i> Domain DNS & Active Beacons</h2>
    <div class="overflow-x-auto font-mono"><table class="w-full text-xs text-slate-300"><thead><tr class="border-b border-slate-800/80 text-slate-400 font-bold"><th class="py-3 text-left font-semibold uppercase tracking-wider">Domain</th><th class="py-3 text-center font-semibold uppercase tracking-wider">Status</th><th class="py-3 text-right font-semibold uppercase tracking-wider">IP Route</th></tr></thead><tbody class="divide-y divide-slate-800/50">{domain_rows if domain_rows else '<tr><td class="py-3.5 text-slate-500" colspan="3">No domain data</td></tr>'}</tbody></table></div>
  </div>
  <div class="border border-cyber-pink/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl">
    <h2 class="text-sm font-mono text-cyber-pink mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase"><i class="fa-solid fa-map-location-dot animate-pulse"></i> Signal Triangulation</h2>
    <div class="overflow-x-auto font-mono"><table class="w-full text-xs text-slate-300"><thead><tr class="border-b border-slate-800/80 text-slate-400 font-bold"><th class="py-3 text-left font-semibold uppercase tracking-wider">Region</th><th class="py-3 text-center font-semibold uppercase tracking-wider">Confidence</th><th class="py-3 text-right font-semibold uppercase tracking-wider">Evidence</th></tr></thead><tbody class="divide-y divide-slate-800/50">{geo_rows if geo_rows else '<tr><td class="py-3.5 text-slate-500" colspan="3">No geolocation data</td></tr>'}</tbody></table></div>
  </div>
</div>

{"<div class=\"border border-cyber-pink/20 rounded-2xl p-6 bg-cyber-surface/50 backdrop-blur-md mb-8\"><h2 class=\"text-sm font-mono text-cyber-pink mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase\"><i class=\"fa-solid fa-shield-halved\"></i> Breach Intelligence</h2><div class=\"overflow-x-auto\"><table class=\"w-full font-mono text-xs text-slate-300\"><thead><tr class=\"border-b border-slate-800/80 text-slate-400 font-bold\"><th class=\"py-3 text-left\">Breach</th><th class=\"py-3 text-left\">Date</th><th class=\"py-3 text-right\">Data Exposed</th></tr></thead><tbody class=\"divide-y divide-slate-800/50\">" + breach_rows + "</tbody></table></div></div>" if breach_rows else ""}

{"<div class=\"border border-cyber-cyan/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-xl mb-8\"><h2 class=\"text-sm font-mono text-cyber-cyan mb-5 flex items-center gap-2.5 tracking-wider font-bold uppercase\"><i class=\"fa-solid fa-clock-rotate-left\"></i> Wayback Snapshots</h2><div class=\"overflow-x-auto\"><table class=\"w-full font-mono text-xs text-slate-300\"><thead><tr class=\"border-b border-slate-800/80 text-slate-400 font-bold\"><th class=\"py-3 text-left\">Date</th><th class=\"py-3 text-left\">URL</th></tr></thead><tbody class=\"divide-y divide-slate-800/50\">" + wayback_rows + "</tbody></table></div></div>" if wayback_rows else ""}

<div class="border border-cyber-cyan/15 rounded-2xl p-6 bg-cyber-surface/60 backdrop-blur-md shadow-2xl mb-8 relative">
  <div class="flex flex-col xl:flex-row justify-between items-start xl:items-center border-b border-slate-800 pb-5 mb-6 gap-4">
    <div>
      <h2 class="text-base font-mono text-cyber-cyan tracking-wider font-extrabold uppercase flex items-center gap-2.5"><i class="fa-solid fa-box-open"></i> Findings Repository</h2>
       <p class="text-xs text-slate-400 font-mono mt-1">TOTAL INCIDENTS: {total_findings} | {meta.get("total_agents", 50)} AGENTS PROCESSED</p>
    </div>
    <div class="flex flex-wrap items-center gap-3.5 w-full xl:w-auto">
      <div class="relative flex-1 md:w-64">
        <i class="fa-solid fa-magnifying-glass absolute left-3 top-3 text-slate-400 text-xs"></i>
        <input type="text" id="findingsSearch" placeholder="Filter findings..." class="w-full bg-cyber-bg border border-cyber-cyan/25 rounded-xl py-2 pl-9 pr-4 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-pink focus:ring-1 focus:ring-cyber-pink transition-all duration-300">
      </div>
      <select id="findingsCategory" class="bg-cyber-bg border border-cyber-cyan/25 text-slate-300 text-xs font-mono rounded-xl px-4 py-2 focus:outline-none focus:border-cyber-pink transition-all duration-300">
        <option value="all">ALL CATEGORIES</option>
        <option value="identity">IDENTITY</option>
        <option value="social">SOCIAL</option>
        <option value="professional">PROFESSIONAL</option>
        <option value="deep_web">DEEP WEB</option>
        <option value="specialist">SPECIALIST</option>
      </select>
    </div>
  </div>
  <div class="space-y-4 max-h-[640px] overflow-y-auto pr-2" id="findingsContainer"></div>
</div>

<div class="border border-cyber-pink/25 rounded-2xl p-6 bg-[#03050c]/95 shadow-2xl mb-8 relative">
  <div class="absolute top-0 right-0 p-4"><span class="inline-block w-2.5 h-2.5 rounded-full bg-cyber-accentGreen animate-pulse"></span></div>
  <div class="flex items-center space-x-2 border-b border-slate-800 pb-4 mb-4 text-xs text-slate-300 font-mono uppercase tracking-wider font-bold"><i class="fa-solid fa-terminal text-cyber-pink animate-pulse"></i><span>ARGIS COMMAND INTERFACE // v1.0</span></div>
  <div id="terminalOutput" class="h-44 overflow-y-auto font-mono text-xs text-cyber-cyan p-4 bg-cyber-bg/90 rounded-xl space-y-1.5 mb-4 leading-relaxed border border-slate-800/80">
    <div>ARGIS DEEP INVESTIGATION SYSTEM v1.0</div>
    <div>TARGET: @{target["username"]} | AGENTS: 50 | SQUADS: 5</div>
    <div>STATUS: ONLINE. Type 'help' for commands.</div>
  </div>
  <div class="flex flex-wrap gap-2.5 mb-4">
    <button onclick="runCmd('status')" class="px-3 py-1.5 bg-slate-900 hover:bg-cyber-pink/10 border border-cyber-pink/25 rounded-lg text-[10px] font-mono text-slate-300 font-bold uppercase transition-all duration-200">Status</button>
    <button onclick="runCmd('scan')" class="px-3 py-1.5 bg-slate-900 hover:bg-cyber-cyan/10 border border-cyber-cyan/25 rounded-lg text-[10px] font-mono text-slate-300 font-bold uppercase transition-all duration-200">Re-scan</button>
    <button onclick="runCmd('breach')" class="px-3 py-1.5 bg-slate-900 hover:bg-cyber-accentYellow/10 border border-cyber-accentYellow/25 rounded-lg text-[10px] font-mono text-slate-300 font-bold uppercase transition-all duration-200">Breach</button>
    <button onclick="runCmd('clear')" class="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-[10px] font-mono text-slate-400 font-bold uppercase transition-all duration-200">Clear</button>
  </div>
  <form id="cmdForm" class="flex gap-3 items-center" onsubmit="handleCmd(event)">
    <span class="text-cyber-pink font-extrabold font-mono text-xs">guest@argis:~$</span>
    <input type="text" id="cmdInput" placeholder="Enter command..." class="flex-1 bg-transparent border-b border-cyber-pink/30 font-mono text-xs text-slate-200 py-1.5 focus:outline-none focus:border-cyber-pink transition duration-150">
    <button type="submit" class="bg-cyber-pink hover:bg-cyber-pink/80 text-white font-mono text-xs font-bold px-5 py-2 rounded-xl transition duration-300 shadow-[0_0_15px_rgba(236,72,153,0.3)]">SUBMIT</button>
  </form>
</div>

<footer class="flex flex-col sm:flex-row items-center justify-between border border-slate-800/80 bg-cyber-surface/40 backdrop-blur-md rounded-2xl p-5 text-xs font-mono text-slate-400 gap-4">
  <div class="flex items-center gap-2.5"><i class="fa-solid fa-microchip text-cyber-cyan animate-pulse text-sm"></i><span>POWERED BY <strong class="text-cyber-cyan font-bold">ARGIS 50-AGENT SYSTEM</strong></span></div>
  <div class="text-center sm:text-right font-medium">RUNTIME: <strong class="text-cyber-pink font-bold">{duration:.1f}s</strong></div>
  <button onclick="exportReport()" class="flex items-center space-x-2 px-4 py-2.5 bg-gradient-to-r from-cyber-cyan via-cyber-turquoise to-cyber-purple text-white font-bold rounded-xl shadow-lg hover:brightness-110 active:scale-95 transition-all duration-300">
    <i class="fa-solid fa-file-export animate-bounce"></i><span>EXPORT DOSSIER</span>
  </button>
</footer>

</div>

<script>
const findings = {findings_json};

// Preloader
const logs = [
  "[SEC-CONN] STAGE 2: ACCESSING DATA VAULTS...",
  "[DECRYPT] RESOLVING IDENTITY SCHEMAS...",
  "[ANALYSIS] CORRELATING FOOTPRINT PATTERNS...",
  "[INTELLIGENCE] PARSING VECTOR GRID MATRIX...",
  "[SUCCESS] COMPILING CLASS IV REPORT...",
  "[COMPLETED] COGNITIVE INTERFACE LOADED."
];

function bootReport() {{
  initParticles();
  renderFindings(findings);
  let pct = 0, logIdx = 0;
  const preloader = document.getElementById('systemPreloader');
  const term = document.getElementById('preloaderTerminal');
  const bar = document.getElementById('preloadProgressBar');
  const pctEl = document.getElementById('preloadPercent');
  const dash = document.getElementById('dashboardContainer');

  const logTimer = setInterval(() => {{
    if (logIdx < logs.length) {{
      const d = document.createElement('div'); d.textContent = logs[logIdx]; term.appendChild(d); term.scrollTop = term.scrollHeight; logIdx++;
    }}
  }}, 350);

  const pctTimer = setInterval(() => {{
    pct += Math.random() * 8 + 3;
    if (pct >= 100) {{
      pct = 100; clearInterval(pctTimer); clearInterval(logTimer);
      setTimeout(() => {{
        preloader.classList.add('opacity-0');
        setTimeout(() => {{ preloader.remove(); dash.classList.remove('opacity-0'); animateCounters(); }}, 600);
      }}, 350);
    }}
    bar.style.width = pct + '%'; pctEl.textContent = Math.ceil(pct) + '%';
  }}, 70);
}}
if (document.readyState === 'loading') {{
  document.addEventListener('DOMContentLoaded', bootReport);
}} else {{
  bootReport();
}}

function animateCounters() {{
  document.querySelectorAll('.stat-counter').forEach(el => {{
    const target = parseInt(el.dataset.target);
    let cur = 0; const step = target / 30;
    const t = setInterval(() => {{ cur += step; if (cur >= target) {{ el.textContent = target; clearInterval(t); }} else el.textContent = Math.ceil(cur); }}, 40);
  }});
}}

function renderFindings(list) {{
  const c = document.getElementById('findingsContainer'); c.innerHTML = '';
  list.forEach(f => {{
    const pct = f.accuracy;
    let badge = 'border-slate-700 text-slate-300 bg-slate-800/60';
    if (pct >= 80) badge = 'border-cyber-accentGreen/30 text-cyber-accentGreen bg-cyber-accentGreen/10';
    else if (pct >= 50) badge = 'border-cyber-accentYellow/30 text-cyber-accentYellow bg-cyber-accentYellow/10';
    const icon = {{identity:'fa-fingerprint',social:'fa-comments',professional:'fa-briefcase',deep_web:'fa-user-secret',specialist:'fa-brain'}}[f.category]||'fa-circle';
    c.innerHTML += `
    <div class="border border-slate-800 rounded-xl bg-cyber-surface/30 hover:bg-cyber-surface/60 hover:border-cyber-cyan/35 transition-all duration-300 shadow-md">
      <div onclick="toggleFind(this.nextElementSibling,this)" class="flex flex-wrap items-center justify-between p-4 cursor-pointer gap-2 select-none">
        <div class="flex items-center space-x-3.5">
          <span class="font-mono text-xs text-cyber-pink font-extrabold">#${{f.id < 10 ? "0" + f.id : f.id}}</span>
          <span class="text-xs text-slate-400 font-mono font-bold flex items-center gap-1.5"><i class="fa-solid ${{icon}} text-cyber-cyan"></i> ${{f.agent}}</span>
          <h3 class="text-xs sm:text-sm font-bold font-mono text-slate-200 ml-1">${{f.title}}</h3>
        </div>
        <div class="flex items-center space-x-3">
          <span class="px-2.5 py-1 rounded-lg border text-[10px] font-mono font-extrabold tracking-wide ${{badge}}">${{pct}}% ACCURACY</span>
          <i class="fa-solid fa-chevron-down text-slate-500 text-xs transition-transform duration-300"></i>
        </div>
      </div>
      <div class="hidden border-t border-slate-800/60 bg-[#070b16]/90 p-5 text-sm font-mono text-slate-300 space-y-3 leading-relaxed rounded-b-xl">
        <div><strong class="text-cyber-cyan uppercase tracking-wider block text-[11px] mb-1">Summary:</strong> ${{f.desc}}</div>
        <div class="border-t border-slate-800/80 pt-3"><strong class="text-cyber-pink uppercase tracking-wider block text-[11px] mb-1">Metadata:</strong> ${{f.details}}</div>
      </div>
    </div>`;
  }});
}}

function toggleFind(panel, hdr) {{
  panel.classList.toggle('hidden');
  hdr.querySelector('.fa-chevron-down').classList.toggle('rotate-180');
}}

document.getElementById('findingsSearch').addEventListener('input', filterFindings);
document.getElementById('findingsCategory').addEventListener('change', filterFindings);

function filterFindings() {{
  const q = document.getElementById('findingsSearch').value.toLowerCase();
  const cat = document.getElementById('findingsCategory').value;
  const filtered = findings.filter(f => (cat === 'all' || f.category === cat) && (f.title.toLowerCase().includes(q) || f.agent.toLowerCase().includes(q) || f.desc.toLowerCase().includes(q)));
  renderFindings(filtered);
}}

// Terminal
const termOut = document.getElementById('terminalOutput');
function appendTerm(text, cls = '') {{ const d = document.createElement('div'); if(cls) d.className=cls; d.textContent=text; termOut.appendChild(d); termOut.scrollTop=termOut.scrollHeight; }}

function runCmd(cmd) {{
  appendTerm('guest@argis:~$ ' + cmd, 'text-cyber-accentYellow font-bold');
  setTimeout(() => {{
    if (cmd === 'help') {{ appendTerm('Commands: status, scan, breach, clear, help'); }}
    else if (cmd === 'status') {{ appendTerm('Target: @{target["username"]} | Findings: {total_findings} | Platforms: {total_found} | Grade: {grade_display}'); }}
    else if (cmd === 'scan') {{ appendTerm('Re-scanning 508 platforms...', 'text-cyber-accentGreen'); setTimeout(() => appendTerm('Complete: {total_found} profiles found.', 'text-cyber-accentGreen'), 800); }}
    else if (cmd === 'breach') {{ appendTerm('Checking breach databases...', 'text-cyber-accentYellow'); setTimeout(() => appendTerm('{"All clear - no breaches" if breach_count==0 else str(breach_count)+" breach records found"}', '{"text-cyber-accentGreen" if breach_count==0 else "text-cyber-pink"}'), 1000); }}
    else if (cmd === 'clear') {{ termOut.innerHTML = '<div>[CLEARED]</div>'; }}
    else {{ appendTerm('Unknown command: ' + cmd + '. Type help.', 'text-cyber-pink'); }}
  }}, 200);
}}

function handleCmd(e) {{
  e.preventDefault(); const inp = document.getElementById('cmdInput'); if(!inp.value) return; runCmd(inp.value); inp.value = '';
}}

function exportReport() {{
  let txt = 'ARGIS INVESTIGATION REPORT\\n';
  txt += 'Target: @{target["username"]}\\nFindings: {total_findings}\\nPlatforms: {total_found}\\nGrade: {grade_display}\\n\\n';
  findings.forEach(f => {{ txt += `[${{f.id < 10 ? "0" + f.id : f.id}}] ${{f.agent}} (${{f.accuracy}}%): ${{f.title}}\\n`; }});
  const blob = new Blob([txt], {{type:'text/plain'}});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'argis_report_{target["username"]}.txt'; a.click();
}}

// Particles
function initParticles() {{
  const canvas = document.getElementById('particlesCanvas');
  const ctx = canvas.getContext('2d');
  let w = canvas.width = window.innerWidth, h = canvas.height = window.innerHeight;
  const particles = [];
  for(let i=0;i<75;i++) particles.push({{ x:Math.random()*w, y:Math.random()*h, vx:Math.random()*0.4-0.2, vy:Math.random()*0.4-0.2, s:Math.random()*2+1 }});
  function anim() {{
    ctx.clearRect(0,0,w,h);
    particles.forEach(p => {{ p.x+=p.vx; p.y+=p.vy; if(p.x<0||p.x>w)p.vx=-p.vx; if(p.y<0||p.y>h)p.vy=-p.vy; ctx.fillStyle='#00f0ff'; ctx.beginPath(); ctx.arc(p.x,p.y,p.s,0,Math.PI*2); ctx.fill(); }});
    for(let i=0;i<particles.length;i++) for(let j=i+1;j<particles.length;j++) {{
      const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y, d=Math.hypot(dx,dy);
      if(d<110) {{ ctx.strokeStyle='rgba(0,240,255,'+(0.12-d/110)+')'; ctx.lineWidth=0.5; ctx.beginPath(); ctx.moveTo(particles[i].x,particles[i].y); ctx.lineTo(particles[j].x,particles[j].y); ctx.stroke(); }}
    }}
    requestAnimationFrame(anim);
  }}
  anim();
  window.addEventListener('resize', () => {{ w=canvas.width=window.innerWidth; h=canvas.height=window.innerHeight; }});
}}

// Dark/light mode
document.getElementById('themeSwitcher').addEventListener('click', () => {{
  const h = document.documentElement; const icon = document.getElementById('themeIcon');
  h.classList.toggle('dark'); h.classList.toggle('light');
  icon.classList.toggle('fa-moon'); icon.classList.toggle('fa-sun');
}});
</script>

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
