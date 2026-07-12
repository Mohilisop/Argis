"""Argis Dossier Generator.

Generates comprehensive intelligence reports from normalized ProfileEvidence.
Only renders data — normalization, verification, and enrichment happen upstream.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from argis.normalize import (
    normalize_scan_results,
    profiles_to_dossier_dicts,
    CORPORATE_EMAIL_DOMAINS,
)


# ═══════════════════════════════════════════════════════════════════
#  INTELLIGENCE FILTERS
# ═══════════════════════════════════════════════════════════════════

GARBAGE_NAME_PATTERNS = [
    r"(?i)^(the |a |an )",
    r"(?i)\b(platform|challenges?|programming|community|blog|official|invite|website)\b",
    r"(?i)\b(sign up|log in|join|profile|view|welcome to|powered by)\b",
    r"(?i)\b(top |best |free |online |your )\b",
    r"\.\.\.",
    r"(?i)^(home|index|about|error|404|not found)",
    r"(?i)(technology|talent|company|service|solution)s?\b",
    r"&(amp|apos|quot|lt|gt);",
    r"(?i)\b(cookie|privacy|terms|copyright)\b",
]

GARBAGE_LINK_DOMAINS = {
    "cloudflare.com", "cloudflareinsights.com", "cloudfront.net",
    "googleapis.com", "gstatic.com", "google-analytics.com",
    "googletagmanager.com", "googlesyndication.com", "doubleclick.net",
    "facebook.net", "fbcdn.net", "twitter.com", "ads-twitter.com",
    "amazon-adsystem.com", "akamai.net", "akamaihd.net",
    "fastly.net", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "maxcdn.com", "bootstrapcdn.com", "fontawesome.com",
    "fonts.googleapis.com", "sentry.io", "hotjar.com", "mouseflow.com",
    "fullstory.com", "amplitude.com", "mixpanel.com", "segment.io",
    "segment.com", "intercom.io", "intercomcdn.com", "crisp.chat",
    "zendesk.com", "zdassets.com", "hcaptcha.com", "recaptcha.net",
    "googlerecaptcha.com", "coinzilla.com", "coinzilla.io",
    "coingecko.com", "bizible.com", "ethers can.io", "bscscan.com",
    "w3.org", "schema.org", "ogp.me", "opengraphprotocol.org",
    "archive.org",
}

_CAT_COLORS = {
    "development": "#4ecdc4", "social": "#c77dff", "gaming": "#ffd166",
    "forums": "#9b5de5", "art": "#ff6b9d", "music": "#a78bfa",
    "tools": "#64b5f6", "hobby": "#ffd166", "blogging": "#4ade80",
    "finance": "#4ade80", "shopping": "#ff8a65", "education": "#a5d6a7",
    "professional": "#9b5de5", "entertainment": "#ef5350",
    "security": "#ffb74d", "video": "#ef5350", "content": "#c77dff",
    "messaging": "#64b5f6", "travel": "#4dd0e1", "crypto": "#ffd54f",
    "geo": "#66bb6a", "fitness": "#81c784", "photography": "#ffab40",
    "wiki": "#90a4ae", "freelance": "#4ade80", "maker": "#ff8a65",
    "uncategorized": "#6a6a80",
}

_RISK_COLORS = {
    "CRITICAL": "#ef5350", "HIGH": "#ffa726",
    "MEDIUM": "#ffd54f", "LOW": "#4ade80",
}


def is_valid_name(name: str, username: str) -> bool:
    if not name or len(name) < 2:
        return False
    if len(name) > 40:
        return False
    if name.lower() == username.lower():
        return False
    for pat in GARBAGE_NAME_PATTERNS:
        if re.search(pat, name):
            return False
    words = name.split()
    if len(words) > 5:
        return False
    if not any(w[0].isupper() for w in words if w):
        return False
    return True


_IMAGE_EXT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
                    "bmp", "tiff", "tif"}


def is_valid_email(email: str, username: str) -> bool:
    if not email or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    if domain in CORPORATE_EMAIL_DOMAINS:
        return False
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _IMAGE_EXT_TLDS:
        return False
    if any(x in local.lower() for x in ["noreply", "no-reply", "support", "admin",
                                          "info@", "help", "billing", "sales",
                                          "marketing", "team", "contact",
                                          "feedback", "abuse", "postmaster",
                                          "webmaster", "security", "privacy",
                                          "legal", "compliance", "hr@",
                                          "careers", "jobs", "press"]):
        return False
    return True


def is_valid_link(domain: str, username: str, found_platforms: set) -> bool:
    domain = domain.lower().strip(".")
    if not domain:
        return False
    if domain in GARBAGE_LINK_DOMAINS:
        return False
    clean = domain.removeprefix("www.")
    if clean in GARBAGE_LINK_DOMAINS:
        return False
    return True


# ═══════════════════════════════════════════════════════════════════
#  RISK SCORING
# ═══════════════════════════════════════════════════════════════════

def calculate_risk_score(results: list[dict], identity: dict) -> dict:
    """Evidence-based risk scoring. Uses only verified/probable accounts."""
    score = 0
    factors = []

    verified = [r for r in results if r.get("verification", "") in ("VERIFIED", "PROBABLE")]
    n_verified = len(verified)

    if n_verified >= 30:
        score += 25
        factors.append(f"{n_verified} verified accounts (very high exposure)")
    elif n_verified >= 15:
        score += 15
        factors.append(f"{n_verified} verified accounts (high exposure)")
    elif n_verified >= 5:
        score += 8
        factors.append(f"{n_verified} verified accounts (moderate exposure)")

    n_emails = len(identity.get("emails", []))
    if n_emails >= 3:
        score += 20
        factors.append(f"{n_emails} personal emails exposed")
    elif n_emails >= 1:
        score += 10
        factors.append(f"{n_emails} personal email(s) exposed")

    names = identity.get("names", [])
    if names:
        score += 15
        factors.append(f"Real name exposed on {len(names)} platform(s)")

    categories = set(r.get("cat", "") for r in verified)
    if len(categories) >= 8:
        score += 15
        factors.append(f"Active across {len(categories)} different categories")
    elif len(categories) >= 4:
        score += 8

    finance_accounts = [r for r in verified if r.get("cat") in ("finance", "crypto")]
    if finance_accounts:
        score += 10
        factors.append(f"{len(finance_accounts)} financial platform(s) exposed")

    avatar_hashes = [r.get("avatar_hash") for r in verified if r.get("avatar_hash")]
    hash_counts = Counter(avatar_hashes)
    reused = sum(1 for c in hash_counts.values() if c > 1)
    if reused:
        score += 15
        factors.append(f"Same avatar reused across {reused} platform groups")

    # Hard consistency rule: 30+ verified cannot be LOW
    if n_verified >= 30 and score < 40:
        score = 40
    # 3+ strong correlations cannot be LOW
    n_correlations = len(identity.get("correlations", []))
    if n_correlations >= 3 and score < 40:
        score = 40

    score = min(100, max(0, score))

    if score >= 70:
        rating = "CRITICAL"
    elif score >= 50:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return {"score": score, "rating": rating, "factors": factors}


# ═══════════════════════════════════════════════════════════════════
#  IDENTITY EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def extract_identity(results: list[dict], username: str) -> dict:
    """Extract and deduplicate identity info from normalized dossier dicts."""
    names = set()
    emails = set()
    links = set()
    bios = []
    avatars = []

    found_platforms = set()

    for r in results:
        platform = r.get("p", "")
        found_platforms.add(platform.lower())

        name = r.get("name", "").strip()
        if is_valid_name(name, username):
            names.add(name)

        raw_mail = r.get("mail", "")
        if raw_mail:
            for email in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_mail):
                if is_valid_email(email, username):
                    emails.add(email.lower())

        bio = r.get("bio", "").strip()
        if bio and len(bio) > 10 and len(bio) < 500:
            if not re.search(r"(?i)(is a (platform|website|service|community)|sign up|join (for )?free)", bio):
                bios.append({"platform": platform, "text": bio})

        img = r.get("img", "").strip()
        if img and not any(x in img.lower() for x in ["default", "placeholder", "avatar_default", "1x1", "pixel"]):
            avatars.append({"platform": platform, "url": img, "hash": r.get("avatar_hash", "")})

        for link in r.get("links", []):
            try:
                domain = urlparse(link if "://" in link else f"https://{link}").netloc
                domain = domain.removeprefix("www.")
                if is_valid_link(domain, username, found_platforms):
                    links.add(domain)
            except Exception:
                pass

    return {
        "names": sorted(names),
        "emails": sorted(emails),
        "links": sorted(links)[:20],
        "bios": bios[:10],
        "avatars": avatars,
    }


# ═══════════════════════════════════════════════════════════════════
#  CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════

def find_correlations(results: list[dict], identity: dict) -> list[dict]:
    """Find cross-platform links and correlations."""
    correlations = []

    # Shared emails
    email_platforms = defaultdict(list)
    for r in results:
        raw_mail = r.get("mail", "")
        if raw_mail:
            for email in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_mail):
                if is_valid_email(email, r.get("p", "")):
                    email_platforms[email.lower()].append(r.get("p", ""))

    for email, platforms in email_platforms.items():
        if len(platforms) > 1:
            correlations.append({
                "type": "shared_email",
                "value": email,
                "platforms": platforms,
                "strength": "strong",
                "desc": f"Same email visible on {len(platforms)} platforms",
            })

    # Shared avatar hashes
    hash_platforms = defaultdict(list)
    for r in results:
        h = r.get("avatar_hash", "")
        if h:
            hash_platforms[h].append(r.get("p", ""))

    for h, platforms in hash_platforms.items():
        if len(platforms) > 1:
            correlations.append({
                "type": "shared_avatar",
                "value": h[:12],
                "platforms": platforms,
                "strength": "strong",
                "desc": f"Identical avatar on {len(platforms)} platforms",
            })

    # Same display name
    name_platforms = defaultdict(list)
    for r in results:
        name = r.get("name", "").strip()
        if is_valid_name(name, ""):
            name_platforms[name.lower()].append(r.get("p", ""))

    for name, platforms in name_platforms.items():
        if len(platforms) > 1:
            correlations.append({
                "type": "shared_name",
                "value": name.title(),
                "platforms": platforms,
                "strength": "moderate",
                "desc": f"Same display name on {len(platforms)} platforms",
            })

    identity["correlations"] = correlations
    return correlations


# ═══════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_dossier_html(results: list[dict], username: str) -> str:
    """Generate the full dossier HTML report.

    Expects results as a list of normalized dicts with keys:
      p, cat, url, name, mail, bio, img, avatar_hash, links,
      status, confidence, verification, warnings
    """
    # Phase the accounts by verification state
    verified = [r for r in results if r.get("verification") in ("VERIFIED", "PROBABLE")]
    ambiguous = [r for r in results if r.get("verification") == "AMBIGUOUS"]
    rejected = [r for r in results if r.get("verification") in ("NOT_FOUND", "ERROR")]

    identity = extract_identity(verified, username)
    correlations = find_correlations(results, identity)
    risk = calculate_risk_score(results, identity)

    cat_counts = Counter(r.get("cat", "uncategorized") for r in verified)
    n_verified = len(verified)
    n_ambiguous = len(ambiguous)
    n_rejected = len(rejected)
    n_categories = len(cat_counts)
    n_avatars = len(identity["avatars"])
    n_emails = len(identity["emails"])
    n_names = len(identity["names"])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    esc = html.escape
    data_json = json.dumps(verified, ensure_ascii=False, default=str)
    risk_color = _RISK_COLORS.get(risk["rating"], "#4ade80")

    # Category distribution bars
    dist_html = ""
    max_count = max(cat_counts.values()) if cat_counts else 1
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        bar_len = int((count / max_count) * 28)
        bar = "\u2588" * bar_len
        color = _CAT_COLORS.get(cat, "#64b5f6")
        dist_html += (
            f'<div class="drow" style="--cc:{color}">'
            f'<span class="lbl">{esc(cat)}</span>'
            f'<span class="bar">{bar}</span>'
            f'<span class="n">{count}</span></div>\n'
        )

    # Identity section
    names_html = "".join(
        f'<span class="tok name">{esc(n)}</span>' for n in identity["names"]
    ) or '<span class="none name">not established</span>'

    emails_html = "".join(
        f'<span class="tok mail">{esc(e)}</span>' for e in identity["emails"]
    ) or '<span class="none">no personal emails found</span>'

    links_html = "".join(
        f'<span class="tok link">{esc(l)}</span>' for l in identity["links"]
    ) or '<span class="none">no external links found</span>'

    # Bios
    bios_html = ""
    if identity["bios"]:
        for b in identity["bios"][:5]:
            bios_html += (
                f'<div class="bio-item">'
                f'<span class="bio-src">{esc(b["platform"])}</span>'
                f'<span class="bio-text">{esc(b["text"][:200])}</span></div>\n'
            )

    # Correlations
    corr_html = ""
    if correlations:
        for c in correlations:
            platforms_str = ", ".join(c["platforms"][:5])
            corr_html += (
                f'<div class="corr-item {c["strength"]}">'
                f'<span class="corr-type">{esc(c["type"].replace("_", " "))}</span>'
                f'<span class="corr-val">{esc(c["value"])}</span>'
                f'<span class="corr-plats">{esc(platforms_str)}</span></div>\n'
            )
    else:
        corr_html = '<div class="none">no cross-platform correlations detected</div>'

    # Risk factors
    risk_factors_html = "".join(f"<li>{esc(f)}</li>" for f in risk["factors"])

    # Ambiguous account rows (collapsible)
    amb_html = ""
    if ambiguous:
        for r in ambiguous:
            pfp = _pfp_html(r)
            meta = r.get("bio", "") or r.get("url", "")
            warnings_str = "; ".join(r.get("warnings", []))
            amb_html += (
                f'<div class="row" data-search="{esc((r.get("p","")+" "+meta).lower())}">'
                f'<a href="{esc(r.get("url",""))}" target="_blank" rel="noopener">'
                f"{pfp}"
                f'<div class="row-info">'
                f'<div class="row-plat">{esc(r.get("p",""))}</div>'
                f'<div class="row-meta">{esc(meta[:80])}</div>'
                f'</div>'
                f'<span class="row-go warned" title="{esc(warnings_str)}">\u26a0</span>'
                f"</a></div>\n"
            )

    # Verified accounts render in JS
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGIS // dossier @{esc(username)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #0a0a0f;
  --bg-2: #12121a;
  --bg-3: #1a1a25;
  --border: #2a2a3a;
  --border-hot: #3a3a4f;
  --text: #e8e8f0;
  --text-hi: #ffffff;
  --text-dim: #6a6a80;
  --text-muted: #4a4a5f;
  --green: #4ade80;
  --green-dim: #22c55e;
  --green-glow: 0 0 20px rgba(74, 222, 128, 0.2);
  --cyan: #22d3ee;
  --amber: #fbbf24;
  --red: #ef4444;
  --magenta: #c77dff;
  --font-mono: 'JetBrains Mono', monospace;
  --font-sans: 'Inter', system-ui, sans-serif;
  --ease: cubic-bezier(0.22, 1, 0.36, 1);
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ font-size: 14px; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}}
::selection {{ background: var(--green); color: var(--bg); }}
a {{ color: inherit; text-decoration: none; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 0 24px; }}

/* Header */
.header {{
  padding: 48px 0 32px;
  border-bottom: 1px solid var(--border);
}}
.header-top {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
  margin-bottom: 24px;
}}
.brand {{
  font-size: 11px;
  color: var(--green);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 700;
}}
.meta-info {{
  text-align: right;
  font-size: 11px;
  color: var(--text-dim);
}}
.target {{
  font-size: clamp(2rem, 5vw, 3.5rem);
  font-weight: 800;
  letter-spacing: -0.03em;
  color: var(--text-hi);
}}
.target .at {{ color: var(--green); }}
.subtitle {{ color: var(--text-dim); font-size: 12px; margin-top: 8px; }}

/* Risk Banner */
.risk-banner {{
  margin: 32px 0;
  padding: 20px 24px;
  background: var(--bg-2);
  border: 1px solid var(--border);
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 20px;
  align-items: center;
}}
.risk-score {{
  font-size: 2.5rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  line-height: 1;
}}
.risk-details {{ font-size: 12px; }}
.risk-rating {{ font-weight: 700; font-size: 13px; letter-spacing: 0.05em; margin-bottom: 4px; }}
.risk-factors {{ color: var(--text-dim); list-style: none; display: flex; flex-wrap: wrap; gap: 4px 16px; }}
.risk-factors li::before {{ content: "\\2022 "; color: var(--text-muted); }}
.risk-meter {{ width: 120px; height: 6px; background: var(--bg-3); border-radius: 3px; overflow: hidden; }}
.risk-meter-fill {{ height: 100%; border-radius: 3px; transition: width 1s var(--ease); }}

/* Stats Strip */
.stats {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
  margin: 24px 0;
}}
.stat {{ background: var(--bg-2); padding: 16px 20px; }}
.stat-label {{ font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.12em; }}
.stat-value {{ font-size: 1.75rem; font-weight: 800; margin-top: 4px; font-variant-numeric: tabular-nums; line-height: 1; }}
.stat-sub {{ font-size: 11px; color: var(--text-dim); margin-top: 6px; }}

/* Sections */
.section {{ padding: 40px 0; border-bottom: 1px solid var(--border); }}
.section:last-child {{ border-bottom: none; }}
.sec-title {{
  font-size: 11px;
  color: var(--green);
  letter-spacing: 0.14em;
  text-transform: uppercase;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 12px;
}}
.sec-title::after {{ content: ""; flex: 1; height: 1px; background: var(--border); }}

/* Evidence Quality Summary */
.eq-grid {{ display: grid; gap: 8px; }}
.eq-row {{
  display: grid;
  grid-template-columns: 120px 1fr;
  gap: 12px;
  padding: 8px 0;
  align-items: center;
  font-size: 12px;
}}
.eq-label {{ color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; }}
.eq-bar-bg {{ height: 6px; background: var(--bg-3); border-radius: 3px; overflow: hidden; }}
.eq-bar {{ height: 100%; border-radius: 3px; }}

/* Distribution */
.dist {{ display: grid; gap: 6px; max-width: 700px; }}
.drow {{
  display: grid;
  grid-template-columns: 120px 1fr 32px;
  gap: 12px;
  align-items: center;
  padding: 4px 0;
}}
.drow .lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--cc); }}
.drow .bar {{ color: var(--cc); font-size: 11px; letter-spacing: -1px; overflow: hidden; opacity: 0.7; }}
.drow .n {{ font-size: 12px; font-weight: 700; color: var(--text-hi); text-align: right; font-variant-numeric: tabular-nums; }}

/* Identity */
.idgrid {{ display: grid; gap: 16px; }}
.idrow {{ display: grid; grid-template-columns: 80px 1fr; gap: 16px; align-items: start; }}
.idrow .tag {{ font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; padding-top: 6px; }}
.idrow .vals {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.tok {{
  padding: 4px 10px;
  font-size: 11.5px;
  background: var(--bg-3);
  border: 1px solid var(--border);
  color: var(--text);
  transition: border-color 0.2s var(--ease);
}}
.tok:hover {{ border-color: var(--border-hot); }}
.tok.name {{ color: var(--green); border-color: rgba(74, 222, 128, 0.3); }}
.tok.mail {{ color: var(--amber); }}
.tok.mail::before {{ content: "\\2709 "; color: var(--text-muted); }}
.tok.link {{ color: var(--cyan); }}
.tok.link::before {{ content: "\\2197 "; color: var(--text-muted); }}
.none {{ color: var(--text-muted); font-size: 11.5px; font-style: italic; padding: 4px 0; }}
.none.name {{ color: var(--text-dim); }}

/* Bios */
.bio-item {{
  padding: 12px 16px;
  background: var(--bg-2);
  border: 1px solid var(--border);
  margin-bottom: 8px;
}}
.bio-src {{ display: block; font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; }}
.bio-text {{ font-size: 12px; color: var(--text-dim); font-family: var(--font-sans); line-height: 1.5; }}

/* Correlations */
.corr-item {{
  display: grid;
  grid-template-columns: 120px 1fr auto;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  align-items: center;
}}
.corr-type {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }}
.corr-val {{ font-size: 12px; color: var(--amber); font-weight: 500; }}
.corr-plats {{ font-size: 11px; color: var(--text-dim); text-align: right; }}
.corr-item.strong .corr-type {{ color: var(--red); }}
.corr-item.moderate .corr-type {{ color: var(--amber); }}

/* Avatars */
.faces {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(90px, 1fr));
  gap: 8px;
}}
.face {{
  aspect-ratio: 1;
  position: relative;
  border: 1px solid var(--border);
  overflow: hidden;
  background: var(--bg-2);
}}
.face img {{ width: 100%; height: 100%; object-fit: cover; filter: grayscale(0.3) contrast(1.05); transition: filter 0.3s var(--ease), transform 0.4s var(--ease); }}
.face:hover img {{ filter: none; transform: scale(1.05); }}
.face .cap {{ position: absolute; bottom: 0; left: 0; right: 0; padding: 4px 6px; background: linear-gradient(transparent, rgba(10,10,15,0.9)); font-size: 9px; color: var(--text-hi); font-weight: 600; }}

/* Accounts table */
.controls {{
  display: flex; gap: 8px; flex-wrap: wrap;
  margin-bottom: 20px; align-items: center;
}}
.grep {{
  flex: 1 1 220px;
  display: flex; align-items: center; gap: 8px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  padding: 0 10px;
}}
.grep .sig {{ color: var(--green); font-size: 12px; }}
.grep input {{
  flex: 1; background: transparent; border: none; outline: none;
  color: var(--text-hi); font-family: inherit; font-size: 12px; padding: 10px 0;
}}
.grep input::placeholder {{ color: var(--text-muted); }}
.grep:focus-within {{ border-color: var(--green-dim); box-shadow: var(--green-glow); }}

.flag {{
  font-family: inherit; font-size: 10px; padding: 6px 10px;
  cursor: pointer; border: 1px solid var(--border);
  background: var(--bg-2); color: var(--text-dim);
  text-transform: uppercase; letter-spacing: 0.04em;
  transition: all 0.15s var(--ease);
}}
.flag:hover {{ color: var(--text); border-color: var(--text-muted); }}
.flag[aria-pressed="true"] {{ color: var(--bg); background: var(--green); border-color: var(--green); font-weight: 700; }}

.grp {{ margin-bottom: 24px; }}
.grp.hidden {{ display: none; }}
.grp-h {{
  font-size: 11px; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--cc);
  padding-bottom: 8px; margin-bottom: 8px;
  border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between;
}}
.grp-h .cnt {{ color: var(--text-muted); }}

.row {{
  display: grid;
  grid-template-columns: 32px 1fr auto;
  gap: 12px;
  align-items: center;
  padding: 8px 8px;
  border-left: 2px solid transparent;
  transition: background 0.15s var(--ease), border-color 0.15s var(--ease);
}}
.row:hover {{ background: var(--bg-2); border-left-color: var(--cc); }}
.row a {{ display: contents; }}

.pfp {{ width: 28px; height: 28px; border: 1px solid var(--border); object-fit: cover; filter: grayscale(0.4); transition: filter 0.2s var(--ease); }}
.row:hover .pfp {{ filter: none; }}
.pfp-ph {{ width: 28px; height: 28px; border: 1px solid var(--border); display: grid; place-items: center; font-size: 10px; font-weight: 800; color: var(--text-muted); background: var(--bg-3); }}

.row-info {{ min-width: 0; }}
.row-plat {{ font-size: 12px; font-weight: 600; color: var(--text-hi); }}
.row-meta {{ font-size: 11px; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.row-go {{ font-size: 11px; color: var(--text-muted); transition: color 0.15s var(--ease); }}
.row:hover .row-go {{ color: var(--green); }}
.row-go.warned {{ color: var(--amber); }}
.row:hover .row-go.warned {{ color: var(--red); }}

.collapse-toggle {{
  cursor: pointer;
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 12px 0;
  transition: color 0.15s;
}}
.collapse-toggle:hover {{ color: var(--text); }}
.collapse-body {{ overflow: hidden; transition: max-height 0.3s var(--ease); }}
.collapse-body.hidden {{ max-height: 0 !important; }}

.empty {{ display: none; padding: 40px; text-align: center; border: 1px dashed var(--border); color: var(--text-muted); }}
.empty.show {{ display: block; }}

/* Footer */
.footer {{ padding: 32px 0 48px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px; font-size: 11px; color: var(--text-muted); }}
.footer .ok {{ color: var(--green); }}

@media (max-width: 680px) {{
  .header-top {{ flex-direction: column; }}
  .meta-info {{ text-align: left; }}
  .risk-banner {{ grid-template-columns: 1fr; gap: 12px; }}
  .stats {{ grid-template-columns: repeat(2, 1fr); }}
  .idrow {{ grid-template-columns: 1fr; gap: 4px; }}
  .corr-item {{ grid-template-columns: 1fr; gap: 4px; }}
  .drow {{ grid-template-columns: 90px 1fr 28px; }}
  .row {{ grid-template-columns: 28px 1fr; }}
  .row-go {{ display: none; }}
}}
</style>
</head>
<body>
<div class="wrap">

<header class="header">
  <div class="header-top">
    <div>
      <div class="brand">Argis Intelligence Report</div>
      <div class="target"><span class="at">@</span>{esc(username)}</div>
      <div class="subtitle">{n_verified} verified accounts across {n_categories} categories</div>
    </div>
    <div class="meta-info">
      Generated {timestamp}<br>
      argis v0.7.0 // public signals only
    </div>
  </div>
</header>

<div class="risk-banner">
  <div class="risk-score" style="color:{risk_color}">{risk['score']}</div>
  <div class="risk-details">
    <div class="risk-rating" style="color:{risk_color}">RISK: {risk['rating']}</div>
    <ul class="risk-factors">{risk_factors_html}</ul>
  </div>
  <div>
    <div class="risk-meter">
      <div class="risk-meter-fill" style="width:{risk['score']}%;background:{risk_color}"></div>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">Verified</div><div class="stat-value" style="color:var(--green)">{n_verified}</div><div class="stat-sub">confirmed hits</div></div>
  <div class="stat"><div class="stat-label">Categories</div><div class="stat-value" style="color:var(--cyan)">{n_categories}</div><div class="stat-sub">life areas</div></div>
  <div class="stat"><div class="stat-label">Avatars</div><div class="stat-value" style="color:var(--magenta)">{n_avatars}</div><div class="stat-sub">captured</div></div>
  <div class="stat"><div class="stat-label">Emails</div><div class="stat-value" style="color:var(--amber)">{n_emails}</div><div class="stat-sub">personal</div></div>
  <div class="stat"><div class="stat-label">Names</div><div class="stat-value" style="color:var(--text-hi)">{n_names}</div><div class="stat-sub">display names</div></div>
  {f'<div class="stat"><div class="stat-label">Review</div><div class="stat-value" style="color:var(--amber)">{n_ambiguous}</div><div class="stat-sub">need review</div></div>' if n_ambiguous else ''}
</div>

<section class="section">
  <div class="sec-title">Distribution</div>
  <div class="dist">{dist_html}</div>
</section>

<section class="section">
  <div class="sec-title">Extracted Identity</div>
  <div class="idgrid">
    <div class="idrow"><span class="tag">Names</span><span class="vals">{names_html}</span></div>
    <div class="idrow"><span class="tag">Emails</span><span class="vals">{emails_html}</span></div>
    <div class="idrow"><span class="tag">Links</span><span class="vals">{links_html}</span></div>
  </div>
</section>

{f'''<section class="section">
  <div class="sec-title">Bio Excerpts</div>
  {bios_html}
</section>''' if bios_html else ''}

<section class="section">
  <div class="sec-title">Cross-Platform Correlations</div>
  {corr_html}
</section>

{f'''<section class="section">
  <div class="sec-title">Captured Avatars</div>
  <div class="faces" id="faces"></div>
</section>''' if identity['avatars'] else ''}

{f'''<section class="section">
  <div class="sec-title collapse-toggle" onclick="toggleCollapse('amb')">
    Accounts Needing Review ({n_ambiguous}) <span id="amb-arrow">\u25bc</span>
  </div>
  <div class="collapse-body" id="amb-body">
    {amb_html}
  </div>
</section>''' if ambiguous else ''}

<section class="section">
  <div class="sec-title">Verified Accounts</div>
  <div class="controls">
    <label class="grep"><span class="sig">grep&gt;</span>
      <input id="q" type="text" placeholder="filter platform / name / bio..." aria-label="Filter"></label>
    <button class="flag" data-cat="all" aria-pressed="true">all</button>
  </div>
  <div id="groups"></div>
  <div class="empty" id="empty">no matches found</div>
</section>

<footer class="footer">
  <span><span class="ok">\u2713</span> scan complete // {n_verified} verified / {n_ambiguous} review / public signals only</span>
  <span>defensive OSINT // no deanonymization</span>
</footer>

</div>

<script>
const DATA = {data_json};
const COLORS = {json.dumps(_CAT_COLORS)};

// Toggle collapse
function toggleCollapse(id) {{
  const body = document.getElementById(id+'-body');
  const arrow = document.getElementById(id+'-arrow');
  const hidden = body.classList.toggle('hidden');
  if (arrow) arrow.textContent = hidden ? '\\25b2' : '\\25bc';
}}

// Render avatars
const facesEl = document.getElementById('faces');
if (facesEl) {{
  DATA.filter(d => d.img && !d.img.includes('default')).forEach(d => {{
    const div = document.createElement('div');
    div.className = 'face';
    div.innerHTML = '<img src="' + d.img + '" alt="' + d.p + '" loading="lazy" onerror="this.parentElement.remove()"><div class="cap">' + d.p + '</div>';
    facesEl.appendChild(div);
  }});
}}

// Render accounts grouped by category
const groupsEl = document.getElementById('groups');
const cats = {{}};
DATA.forEach(d => {{ (cats[d.cat] = cats[d.cat] || []).push(d); }});

Object.entries(cats).sort((a,b) => b[1].length - a[1].length).forEach(([cat, items]) => {{
  const grp = document.createElement('div');
  grp.className = 'grp';
  grp.dataset.cat = cat;
  const color = COLORS[cat] || '#64b5f6';
  grp.style.setProperty('--cc', color);

  let html = '<div class="grp-h"><span>' + cat + '</span><span class="cnt">' + items.length + '</span></div>';
  items.forEach(d => {{
    const img = d.img
      ? '<img class="pfp" src="' + d.img + '" loading="lazy" onerror="this.outerHTML=\'<div class=pfp-ph>\' + d.p[0].toUpperCase() + \'</div>\'">'
      : '<div class="pfp-ph">' + d.p[0].toUpperCase() + '</div>';
    const meta = d.bio ? d.bio.slice(0, 80) : d.url;
    const search = (d.p + ' ' + (d.name||'') + ' ' + (d.bio||'') + ' ' + (d.mail||'')).toLowerCase();
    const w = d.warnings && d.warnings.length ? d.warnings.join('; ') : '';
    html += '<div class="row" data-search="' + search + '">'
      + '<a href="' + d.url + '" target="_blank" rel="noopener">'
      + img
      + '<div class="row-info">'
      + '<div class="row-plat">' + d.p + '</div>'
      + '<div class="row-meta">' + meta + '</div>'
      + '</div>'
      + (w ? '<span class="row-go warned" title="' + w + '">\\u26a0</span>' : '<span class="row-go">\\u2197</span>')
      + '</a></div>';
  }});
  grp.innerHTML = html;
  groupsEl.appendChild(grp);

  const btn = document.createElement('button');
  btn.className = 'flag';
  btn.dataset.cat = cat;
  btn.setAttribute('aria-pressed', 'true');
  btn.textContent = cat;
  document.querySelector('.controls').appendChild(btn);
}});

// Filter logic
const q = document.getElementById('q');
const empty = document.getElementById('empty');

function applyFilters() {{
  const term = q.value.toLowerCase();
  const activeFlags = new Set(
    [...document.querySelectorAll('.flag[aria-pressed="true"]')].map(b => b.dataset.cat)
  );
  const showAll = activeFlags.has('all');

  let visible = 0;
  document.querySelectorAll('.grp').forEach(grp => {{
    const cat = grp.dataset.cat;
    const catVisible = showAll || activeFlags.has(cat);
    if (!catVisible) {{ grp.classList.add('hidden'); return; }}
    let grpVisible = 0;
    grp.querySelectorAll('.row').forEach(row => {{
      const match = !term || row.dataset.search.includes(term);
      row.style.display = match ? '' : 'none';
      if (match) grpVisible++;
    }});
    grp.classList.toggle('hidden', grpVisible === 0);
    visible += grpVisible;
  }});
  empty.classList.toggle('show', visible === 0);
}}

q.addEventListener('input', applyFilters);
document.querySelectorAll('.flag').forEach(btn => {{
  btn.addEventListener('click', () => {{
    if (btn.dataset.cat === 'all') {{
      const allOn = btn.getAttribute('aria-pressed') === 'true';
      document.querySelectorAll('.flag').forEach(b => b.setAttribute('aria-pressed', allOn ? 'false' : 'true'));
    }} else {{
      const cur = btn.getAttribute('aria-pressed') === 'true';
      btn.setAttribute('aria-pressed', cur ? 'false' : 'true');
      const allBtn = document.querySelector('.flag[data-cat="all"]');
      const allActive = [...document.querySelectorAll('.flag:not([data-cat="all"])')].every(b => b.getAttribute('aria-pressed') === 'true');
      allBtn.setAttribute('aria-pressed', allActive ? 'true' : 'false');
    }}
    applyFilters();
  }});
}});
</script>
</body>
</html>"""


def generate_dossier(results: list[dict], username: str, output: Optional[Path] = None) -> str:
    """Generate dossier and optionally write to file. Returns HTML string."""
    html_content = generate_dossier_html(results, username)
    if output:
        output.write_text(html_content, encoding="utf-8")
    return html_content


# ═══════════════════════════════════════════════════════════════════
#  BACKWARD-COMPATIBLE ALIASES
# ═══════════════════════════════════════════════════════════════════

def _pfp_html(r: dict) -> str:
    img = r.get("img", "")
    p = r.get("p", "")
    initial = p[0].upper() if p else "?"
    if img:
        return f'<img class="pfp" src="{html.escape(img)}" loading="lazy" onerror="this.outerHTML=\'<div class=pfp-ph>{initial}</div>\'">'
    return f'<div class="pfp-ph">{initial}</div>'


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
) -> dict:
    """Normalize scan results, enrich with avatars, verify, and generate dossier HTML.

    This is the main entry point used by the CLI. Enrichment fetches profile
    pages to extract avatar images (og:image / twitter:image / JSON-LD).
    """
    from argis.verify import determine_verification
    from argis.intel_http import AsyncFetcher

    site_categories = site_categories or {}

    # Normalize all results into ProfileEvidence objects
    profiles = normalize_scan_results(results, site_categories, username)
    found_profiles = [p for p in profiles if p.status == "FOUND"]

    # ── Media enrichment: fetch pages + extract avatars ──────────
    if enrich and found_profiles:
        async with AsyncFetcher(
            timeout=timeout, concurrency=concurrency,
            proxy=proxy, use_tor=use_tor, render=render,
        ) as fetcher:
            from argis.media import enrich_avatar, extract_avatar_candidates

            sem = asyncio.Semaphore(concurrency)

            async def enrich_one(pe: ProfileEvidence) -> ProfileEvidence:
                async with sem:
                    resp = await fetcher.get(pe.url)
                    if resp.error or not resp.text:
                        return pe
                    return await enrich_avatar(pe, html=resp.text, fetcher=fetcher)

            enriched = await asyncio.gather(
                *(enrich_one(p) for p in found_profiles)
            )
            # Replace profiles with enriched versions
            enriched_by_platform = {p.platform: p for p in enriched}
            profiles = [
                enriched_by_platform.get(p.platform, p) for p in profiles
            ]

    # ── Verification ─────────────────────────────────────────────
    verified_profiles = []
    for pe in profiles:
        state, warnings = determine_verification(
            status=pe.status,
            title=pe.title,
            description=pe.bio,
            url=pe.url,
            platform=pe.platform,
            username=username,
        )
        pe.verification = state
        pe.warnings.extend(warnings)
        verified_profiles.append(pe)

    # Convert to dossier dicts and generate HTML
    dossier_dicts = profiles_to_dossier_dicts(verified_profiles)
    html_str = generate_dossier_html(dossier_dicts, username)

    found: dict[str, dict] = {}
    for pe in verified_profiles:
        if pe.status == "FOUND":
            found[pe.platform] = {
                "status": pe.status,
                "url": pe.url,
                "p": pe.platform,
                "cat": pe.category,
                "name": pe.display_name or pe.title or "",
                "bio": pe.bio or "",
                "mail": "; ".join(pe.emails),
                "img": pe.avatar_url or "",
                "avatar_hash": pe.avatar_hash or "",
                "verification": pe.verification,
                "warnings": pe.warnings,
            }

    return {
        "username": username,
        "results": found,
        "found": found,
        "html": html_str,
        "total_scanned": len(results),
    }


def print_dossier(dossier: dict, console) -> None:
    """Print dossier summary to console."""
    n = len(dossier.get("found", {}))
    console.print(f"[bold cyan]@{dossier['username']}[/bold cyan] — {n} accounts found")


def to_html_report(dossier_or_results, *, graph_payload: dict | None = None) -> str:
    """Backward-compatible report extraction."""
    if isinstance(dossier_or_results, dict):
        if "results" in dossier_or_results:
            return dossier_or_results.get("html", "")
        return generate_dossier_html(dossier_or_results, "")
    return generate_dossier_html(dossier_or_results, "")


def to_pdf(dossier_or_results, out_path: str | Path, *, graph_payload: dict | None = None) -> bool:
    """Render dossier HTML to PDF."""
    html_str = to_html_report(dossier_or_results, graph_payload=graph_payload)
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
                await pg.pdf(path=str(out_path), format="A4", print_background=True)
                await b.close()
        asyncio.run(_run())
        return True
    except Exception:
        return False


async def build_dossier_graph(username: str, *, timeout=12.0, concurrency=15,
                               proxy=None, use_tor=False) -> dict | None:
    """Backward-compatible stub — graph feature removed."""
    return None
