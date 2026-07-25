"""Password Leak Check — analyzes password patterns from breach data and username."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any


_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9"}

_KNOWN_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "123456789",
    "letmein", "111111", "dragon", "master", "sunshine", "princess", "welcome",
    "football", "iloveyou", "trustno1", "shadow", "passw0rd", "master123",
]

_YEARS_EXTENDED: list[str] = [str(y) for y in range(1950, 2028)]


def _leet(text: str) -> list[str]:
    results = set()
    def _substitute(s: str, idx: int) -> None:
        if idx >= len(s):
            results.add(s)
            return
        char = s[idx]
        _substitute(s, idx + 1)
        if char in _LEET_MAP:
            _substitute(s[:idx] + _LEET_MAP[char] + s[idx + 1:], idx + 1)
    _substitute(text, 0)
    return list(results - {text})


def _common_suffixes() -> list[str]:
    return [
        "!", "@", "#", "$", "%", "&", "*", ".", "..", "...",
        "123", "1234", "12345", "123456", "1234567", "12345678",
        "1", "12", "123!", "1234!", "1!", "!@#",
        "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    ]


def _keyboard_patterns() -> list[str]:
    rows = [
        ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
        ["qwertzuiop", "asdfghjkl", "yxcvbnm"],
        ["azertyuiop", "qsdfghjklm", "wxcvbn"],
    ]
    patterns = []
    for row_group in rows:
        for row in row_group:
            for length in (4, 5, 6, 8):
                for start in range(len(row) - length):
                    patterns.append(row[start:start + length])
                    patterns.append(row[start:start + length][::-1])
    return list(set(patterns))


class PasswordLeakChecker:
    def __init__(self):
        self._agent_id = 98

    def analyze(
        self,
        username: str,
        aliases: list[str] | None = None,
        known_emails: list[str] | None = None,
        breach_reports: list | None = None,
        discovered_emails: list[str] | None = None,
    ) -> dict[str, Any]:
        aliases = aliases or []
        known_emails = known_emails or []
        discovered_emails = discovered_emails or []
        breach_reports = breach_reports or []

        emails_checked = list(set(known_emails + discovered_emails))
        patterns = self._generate_password_patterns(username, aliases)
        breach_results = self._map_to_breaches(patterns, breach_reports, emails_checked)
        reuse_risk = self._assess_reuse_risk(breach_results)
        risk = self._risk_assessment(breach_results, reuse_risk)

        return {
            "target": username,
            "emails_checked": emails_checked,
            "breach_summary": {
                "total_breaches": len(breach_reports),
                "emails_compromised": len([r for r in breach_reports if self._is_compromised(r)]),
                "unique_password_patterns_found": len([p for p in breach_results if p["found_in_breaches"]]),
                "total_patterns_tested": len(breach_results),
            },
            "password_patterns": breach_results,
            "reuse_risk": reuse_risk,
            "risk_assessment": risk,
        }

    def _generate_password_patterns(self, username: str, aliases: list[str]) -> list[dict]:
        bases = [username]
        bases.extend(a for a in (aliases or []) if a)
        self._real_names = []

        parts = re.split(r"[-_.\s]+", username)
        first_name = parts[0] if parts else username
        last_name = parts[-1] if len(parts) > 1 else ""
        first_initial = first_name[0] if first_name else ""
        last_initial = last_name[0] if last_name else ""

        patterns: list[dict] = []
        seen: set[str] = set()

        def add(pattern_name: str, example: str, risk: str) -> None:
            key = example.lower().strip()
            if key and key not in seen:
                seen.add(key)
                patterns.append({
                    "pattern": pattern_name, "example": example,
                    "found_in_breaches": False, "breach_count": 0,
                    "breach_sources": [], "reuse_risk": risk,
                })

        for base in bases:
            clean = base.strip()
            if not clean:
                continue
            low = clean.lower()
            cap = clean.capitalize()
            up = clean.upper()

            add("Base username", low, "LOW")
            add("Capitalized", cap, "LOW")
            add("Uppercase", up, "LOW")
            add("Lowercase reversed", low[::-1], "LOW")
            add("Capitalized reversed", cap[::-1], "MEDIUM")

            for sfx in _common_suffixes():
                add(f"Suffix: {sfx}", f"{low}{sfx}", "HIGH")

            for year in _YEARS_EXTENDED[:10]:
                add(f"Username+Year ({year})", f"{low}{year}", "HIGH")
                add(f"Year+Username ({year})", f"{year}{low}", "MEDIUM")
                add(f"Capitalized+Year ({year})", f"{cap}{year}", "HIGH")

            add("Username+Keyword 'pass'", f"{low}pass", "HIGH")
            add("Username+Keyword 'pw'", f"{low}pw", "MEDIUM")
            add("Username+Keyword 'login'", f"{low}login", "MEDIUM")

            for leet_variant in _leet(low)[:6]:
                add(f"Leet: {leet_variant}", leet_variant, "HIGH")

            for kb in _keyboard_patterns()[:6]:
                add(f"Keyboard: {kb}", f"{low}{kb}", "HIGH")
                add(f"Keyboard reversed: {kb}", f"{low}{kb[::-1]}", "MEDIUM")

            for pw in _KNOWN_PASSWORDS[:6]:
                add(f"Common+pw: {pw}", f"{low}{pw}", "HIGH")
                add(f"pw+common: {pw}", f"{pw}{low}", "MEDIUM")

        if first_name and last_name:
            fc, lc = first_name.capitalize(), last_name.capitalize()
            fl, ll = first_name.lower(), last_name.lower()
            add("First.Last", f"{fl}.{lc}", "MEDIUM")
            add("First_Last", f"{fl}_{lc}", "MEDIUM")
            add("First-Last", f"{fl}-{lc}", "MEDIUM")
            add("FLast", f"{fl}{ll}", "MEDIUM")
            add("LastFirst", f"{ll}{fl}", "MEDIUM")
            add("F.Last", f"{first_initial}.{lc}", "MEDIUM")
            add("F.Lastname", f"{first_initial}.{ll}", "MEDIUM")
            add("Firstname+F.Lastname", f"{fc}{first_initial}.{lc}", "MEDIUM")

            for year in _YEARS_EXTENDED[:6]:
                add(f"Firstname+Year ({year})", f"{fc}{year}", "HIGH")
                add(f"Firstname.Lastname+Year ({year})", f"{fl}.{lc}{year}", "HIGH")
                add(f"Firstname_Lastname+Year ({year})", f"{fl}_{lc}{year}", "HIGH")
                add(f"Year+Firstname ({year})", f"{year}{fc}", "MEDIUM")

            add("Firstname+!", f"{fc}!", "HIGH")
            add("Firstname+123", f"{fc}123", "HIGH")
            add("Firstname.Lastname+!", f"{fl}.{lc}!", "HIGH")

            for leet_variant in _leet(fl)[:3]:
                lv = leet_variant.capitalize()
                add(f"Leet Firstname+{lv}", f"{lv}{lc}", "HIGH")
                add(f"Leet Firstname.Lastname", f"{lv}.{lc}", "HIGH")

        if first_name:
            fc = first_name.capitalize()
            for sfx in _common_suffixes()[:6]:
                add(f"Firstname+Suffix: {sfx}", f"{fc}{sfx}", "HIGH")

        if last_name:
            lc = last_name.capitalize()
            for year in _YEARS_EXTENDED[:6]:
                add(f"Lastname+Year ({year})", f"{lc}{year}", "HIGH")
            add("Lastname+123", f"{lc}123", "HIGH")

        if first_name and last_name:
            for year in _YEARS_EXTENDED[:4]:
                for sfx in ["!", "@", "#", "123"]:
                    add(f"FirstLast{year}{sfx}", f"{fc}{lc}{year}{sfx}", "HIGH")

        for base in bases[:3]:
            b = base.lower()
            for year in _YEARS_EXTENDED[:4]:
                for sfx in ["!", "123"]:
                    add(f"Base{year}{sfx}", f"{b}{year}{sfx}", "HIGH")

        return patterns

    def _map_to_breaches(self, patterns: list[dict], breach_reports: list, emails_checked: list[str]) -> list[dict]:
        breached_emails_set = set()
        for report in breach_reports:
            r_email = self._get_email(report)
            if self._is_compromised(report):
                breached_emails_set.add(r_email)

        for p in patterns:
            example_lower = p["example"].lower()

            for report in breach_reports:
                if not self._is_compromised(report):
                    continue
                r_email = self._get_email(report)
                breaches = self._get_breaches(report)
                email_local = r_email.split("@")[0].lower() if "@" in r_email else ""

                for b in breaches:
                    b_name = self._get_breach_name(b)
                    b_date = self._get_breach_date(b)
                    b_classes = self._get_data_classes(b)
                    has_passwords = any("password" in c.lower() for c in b_classes)

                    if has_passwords and example_lower:
                        p["found_in_breaches"] = True
                        p["breach_count"] += 1
                        src = f"{b_name} ({b_date})"
                        if src not in p["breach_sources"]:
                            p["breach_sources"].append(src)

                    if email_local and email_local == example_lower:
                        p["found_in_breaches"] = True
                        p["breach_count"] += 1
                        src = f"{b_name} ({b_date}) — email match"
                        if src not in p["breach_sources"]:
                            p["breach_sources"].append(src)

        return patterns

    def _assess_reuse_risk(self, patterns: list[dict]) -> str:
        found = [p for p in patterns if p["found_in_breaches"]]
        sources = set()
        for p in found:
            for s in p["breach_sources"]:
                sources.add(s.split(" —")[0].strip())
        unique_breaches = len(sources)

        if unique_breaches >= 5:
            return "CRITICAL"
        if unique_breaches >= 2:
            return "HIGH"
        if len(found) >= 1:
            return "HIGH"
        return "MEDIUM"

    def _risk_assessment(self, patterns: list[dict], reuse_risk: str) -> dict:
        found = [p for p in patterns if p["found_in_breaches"]]
        high_risk_found = [p for p in found if p["reuse_risk"] == "HIGH"]
        total_patterns = len(patterns)
        score = 0

        if found:
            score += min(40, len(found) * 8)
        if high_risk_found:
            score += min(30, len(high_risk_found) * 6)
        if reuse_risk == "CRITICAL":
            score += 30
        elif reuse_risk == "HIGH":
            score += 20
        elif reuse_risk == "MEDIUM":
            score += 10
        if total_patterns > 60:
            score += 5
        if total_patterns > 100:
            score += 5

        score = min(100, score)

        if score >= 70:
            grade = "HIGH EXPOSURE"
            recommendations = [
                "Change all passwords on compromised email addresses immediately",
                "Enable 2FA on ALL accounts using username-derived passwords",
                "Do not reuse password patterns across any platforms",
                "Use a password manager with 20+ char randomly generated passwords",
                "Review account recovery options for all breached accounts",
                "Audit all accounts for credential stuffing vulnerability",
                "Consider a credit freeze if personal data was exposed",
            ]
        elif score >= 40:
            grade = "MODERATE EXPOSURE"
            recommendations = [
                "Enable 2FA on accounts with medium-risk password patterns",
                "Avoid username-derived passwords across platforms",
                "Use unique, complex passwords per service",
                "Audit accounts for password reuse patterns",
            ]
        else:
            grade = "LOW EXPOSURE"
            recommendations = [
                "Use a password manager for generated passwords",
                "Enable 2FA on high-value accounts proactively",
                "Regular security audits recommended (quarterly)",
            ]

        return {
            "overall_score": score,
            "grade": grade,
            "recommendations": recommendations,
        }

    def to_findings(self, analysis: dict, target_username: str) -> list[dict[str, Any]]:
        findings: list[dict] = []
        risk = analysis.get("risk_assessment", {})
        patterns = analysis.get("password_patterns", [])
        found = [p for p in patterns if p["found_in_breaches"]]
        breach_summary = analysis.get("breach_summary", {})

        if found:
            findings.append({
                "agent_id": self._agent_id,
                "agent_name": "Password Leak Checker",
                "category": "deep_web",
                "title": f"{len(found)}/{len(patterns)} password patterns matched in known breaches",
                "description": f"Risk grade: {risk.get('grade', 'UNKNOWN')} ({risk.get('overall_score', 0)}/100). "
                              f"Reuse risk: {analysis.get('reuse_risk', 'N/A')}. "
                              f"Recommendations: {'; '.join(risk.get('recommendations', [])[:2])}",
                "evidence": [f"{p['pattern']}: {p['example']}" for p in found[:10]],
                "confidence": 0.9 if len(found) >= 3 else 0.75 if len(found) >= 1 else 0.6,
                "platform": "breach_db",
                "metadata": {
                    "risk_assessment": risk,
                    "patterns_analyzed": len(patterns),
                    "found_in_breach": len(found),
                    "reuse_risk": analysis.get("reuse_risk", "N/A"),
                },
            })
        else:
            findings.append({
                "agent_id": self._agent_id,
                "agent_name": "Password Leak Checker",
                "category": "deep_web",
                "title": f"Password leak check complete — {len(patterns)} patterns clean",
                "description": f"Tested {len(patterns)} password patterns against breach data. "
                              f"Checked {breach_summary.get('emails_compromised', 0)} compromised emails. "
                              f"Risk grade: {risk.get('grade', 'N/A')}.",
                "evidence": [f"Patterns tested: {len(patterns)} from {len(analysis.get('emails_checked', []))} emails",
                            f"Risk grade: {risk.get('grade', 'N/A')} ({risk.get('overall_score', 0)}/100)"],
                "confidence": 0.5,
                "platform": "breach_db",
                "metadata": {
                    "risk_assessment": risk,
                    "patterns_analyzed": len(patterns),
                },
            })

        self._agent_id += 1
        findings.append({
            "agent_id": self._agent_id,
            "agent_name": "Password Leak Checker",
            "category": "deep_web",
            "title": f"Password exposure assessment: {risk.get('grade', 'N/A')} ({risk.get('overall_score', 0)}/100)",
            "description": f"Reuse risk: {analysis.get('reuse_risk', 'N/A')}. "
                          f"{len(found)} patterns matched in breaches out of {len(patterns)} tested. "
                          f"Recommendations provided: {len(risk.get('recommendations', []))} actionable items.",
            "evidence": risk.get("recommendations", []),
            "confidence": 0.85,
            "platform": "breach_db",
            "metadata": {"recommendations": risk.get("recommendations", [])},
        })

        return findings

    @staticmethod
    def _is_compromised(report) -> bool:
        if isinstance(report, dict):
            return bool(report.get("compromised", False))
        return getattr(report, "compromised", False)

    @staticmethod
    def _get_email(report) -> str:
        if isinstance(report, dict):
            return report.get("email", "")
        return getattr(report, "email", "")

    @staticmethod
    def _get_breaches(report) -> list:
        if isinstance(report, dict):
            return report.get("breaches", [])
        return getattr(report, "breaches", [])

    @staticmethod
    def _get_breach_name(b) -> str:
        if isinstance(b, dict):
            return b.get("name", "")
        return getattr(b, "name", "")

    @staticmethod
    def _get_breach_date(b) -> str:
        if isinstance(b, dict):
            return str(b.get("date", ""))
        return str(getattr(b, "date", ""))

    @staticmethod
    def _get_data_classes(b) -> list[str]:
        if isinstance(b, dict):
            return b.get("data_classes", [])
        return getattr(b, "data_classes", [])
