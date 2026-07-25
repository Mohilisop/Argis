"""Email Pattern Generator — generates plausible email addresses from target data."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from argis.utils.extract_utils import clean_emails

_SPLIT_RE = re.compile(r"[-_.]+")
_DOMAIN_EXTRACTION_RE = re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

COMMON_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
    "protonmail.com", "proton.me", "icloud.com", "aol.com",
    "mail.com", "fastmail.com", "zoho.com", "yandex.com",
    "tutanota.com", "gmx.com", "live.com", "msn.com",
]

PATTERNS: list[tuple[str, str]] = [
    ("firstname@domain", "{first}@{domain}"),
    ("firstname.lastname@domain", "{first}.{last}@{domain}"),
    ("f.lastname@domain", "{f}.{last}@{domain}"),
    ("firstname_lastname@domain", "{first}_{last}@{domain}"),
    ("firstname-lastname@domain", "{first}-{last}@{domain}"),
    ("firstname+alias@domain", "{first}+{alias}@{domain}"),
    ("lastname+keyword@domain", "{last}+{keyword}@{domain}"),
    ("username@domain", "{username}@{domain}"),
    ("firstname_initials@domain", "{fi}@{domain}"),
    ("firstname_initials_lastname@domain", "{f}{last}@{domain}"),
    ("alias@domain", "{alias}@{domain}"),
]

ROLES = ["admin", "dev", "contact", "hello", "hi", "info", "mail", "support", "webmaster", "team"]


def _extract_name_parts(text: str) -> list[list[str]]:
    """Attempt to split text into first/last name candidates."""
    text = text.strip().lower()
    parts = _SPLIT_RE.split(text)
    if len(parts) >= 2:
        return [parts[:2]]
    candidates = []
    for split_at in range(1, len(text)):
        first, last = text[:split_at], text[split_at:]
        if len(first) >= 2 and len(last) >= 2:
            candidates.append([first, last])
    return candidates


def _extract_domains(emails: list[str]) -> list[str]:
    domains = set()
    for e in emails:
        m = _DOMAIN_EXTRACTION_RE.search(e)
        if m:
            domains.add(m.group(1).lower())
    return sorted(domains)


def _year_candidates() -> list[str]:
    now = datetime.utcnow().year
    years = [str(now - i) for i in range(5)]
    years.extend([str(y) for y in range(1990, 2006)])
    return years


class EmailPatternGenerator:
    def __init__(self):
        self._agent_id = 96

    def generate(
        self,
        username: str,
        aliases: list[str] | None = None,
        known_emails: list[str] | None = None,
        known_domains: list[str] | None = None,
        discovered_emails: list[str] | None = None,
        real_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        aliases = aliases or []
        known_emails = known_emails or []
        discovered_emails = discovered_emails or []
        real_names = real_names or []

        domains = list(COMMON_DOMAINS)
        domains.extend(_extract_domains(known_emails + discovered_emails))
        if known_domains:
            domains.extend(known_domains)
        domains = list(set(domains))[:20]

        name_sources = [username]
        name_sources.extend(aliases)
        found_emails_set = set(known_emails + discovered_emails)

        candidates: list[dict] = []
        seen: set[str] = set()

        for source in name_sources:
            name_parts_list = _extract_name_parts(source)
            for name_parts in name_parts_list:
                first, last = name_parts

                for domain in domains:
                    for pattern_name, template in PATTERNS:
                        local_parts = {
                            "first": first,
                            "last": last,
                            "f": first[0] if first else "",
                            "fi": f"{first[0]}{last[0]}" if first and last else "",
                            "username": username,
                            "alias": source,
                            "domain": domain,
                            "keyword": source,
                        }

                        base = template.format(**local_parts)
                        if base in seen:
                            continue
                        seen.add(base)

                        email_addr = base
                        if email_addr in found_emails_set:
                            confidence_base = 0.95
                        elif domain in COMMON_DOMAINS:
                            confidence_base = 0.45
                        else:
                            confidence_base = 0.30

                        candidates.append({
                            "email": email_addr,
                            "pattern": pattern_name,
                            "confidence": confidence_base,
                            "in_breach": False,
                            "breach_count": 0,
                            "found_on_platforms": [],
                            "rationale": f"Generated from pattern '{pattern_name}' using source '{source}' on domain '{domain}'",
                        })

                    for year in _year_candidates()[:4]:
                        year_email = f"{first}{last}{year}@{domain}"
                        if year_email not in seen:
                            seen.add(year_email)
                            candidates.append({
                                "email": year_email,
                                "pattern": "firstname+lastname+year",
                                "confidence": 0.35,
                                "in_breach": False,
                                "breach_count": 0,
                                "found_on_platforms": [],
                                "rationale": f"Name concatenation with year {year} on {domain}",
                            })

                for role in ROLES:
                    role_email = f"{role}.{username}@{domain}"
                    if role_email not in seen:
                        seen.add(role_email)
                        candidates.append({
                            "email": role_email,
                            "pattern": "role_username@domain",
                            "confidence": 0.25,
                            "rationale": f"Role-based prefix '{role}' with username on {domain}",
                        })

        candidates.sort(key=lambda c: -c["confidence"])
        return candidates

    def enrich_with_breach_data(self, candidates: list[dict], breach_reports: list) -> list[dict]:
        for c in candidates:
            email = c["email"]
            for report in breach_reports:
                r_email = getattr(report, "email", "") if not isinstance(report, dict) else report.get("email", "")
                if r_email == email:
                    breaches = getattr(report, "breaches", []) if not isinstance(report, dict) else report.get("breaches", [])
                    c["in_breach"] = True
                    c["breach_count"] = len(breaches)
                    break
        return candidates

    def enrich_with_platforms(self, candidates: list[dict], found_platforms: list[str]) -> list[dict]:
        local_parts = [e.split("@")[0].lower() for e in [c["email"] for c in candidates]]
        for i, lp in enumerate(local_parts):
            if lp and any(lp in plat.lower() for plat in found_platforms):
                candidates[i]["found_on_platforms"].append("cross-platform")
        return candidates

    def to_findings(self, candidates: list[dict], target_username: str) -> list[dict[str, Any]]:
        findings: list[dict] = []
        top = [c for c in candidates if c["confidence"] >= 0.5][:5]
        breach_hits = [c for c in candidates if c["in_breach"]]
        stats = {
            "total_candidates": len(candidates),
            "already_discovered": sum(1 for c in candidates if c["confidence"] >= 0.9),
            "in_breach": len(breach_hits),
        }

        finding = {
            "agent_id": self._agent_id,
            "agent_name": "Email Pattern Generator",
            "category": "identity",
            "title": f"Generated {len(candidates)} email candidates from {len(set(c['email'].split('@')[1] for c in candidates))} domains",
            "description": f"Top patterns: {', '.join(c['pattern'] for c in top[:3])}. Found {stats['in_breach']} breached emails.",
            "evidence": [c["email"] for c in top[:10]],
            "confidence": 0.85 if breach_hits else 0.65,
            "platform": "email",
            "metadata": {
                "candidates": candidates[:50],
                "stats": stats,
            },
        }
        findings.append(finding)
        self._agent_id += 1

        if breach_hits:
            findings.append({
                "agent_id": self._agent_id,
                "agent_name": "Email Pattern Generator",
                "category": "deep_web",
                "title":                 f"{len(breach_hits)} generated email addresses already in known breaches",
                "description": f"Email addresses matching known breach data found among generated candidates",
                "evidence": [f"{c['email']} — {c['breach_count']} breaches" for c in breach_hits[:5]],
                "confidence": 0.95,
                "platform": "breach_db",
            })

        return findings

    @staticmethod
    def generate_email_list(
        username: str,
        aliases: list[str] | None = None,
        emails: list[str] | None = None,
        discovered_emails: list[str] | None = None,
    ) -> str:
        gen = EmailPatternGenerator()
        candidates = gen.generate(
            username=username,
            aliases=aliases,
            known_emails=emails,
            discovered_emails=discovered_emails,
        )
        result = {
            "target": username,
            "generated_at": datetime.utcnow().isoformat(),
            "candidates": candidates[:50],
            "stats": {
                "total_candidates": len(candidates),
            },
        }
        return json.dumps(result, indent=2, ensure_ascii=False)
