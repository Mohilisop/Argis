"""Squad Delta - Deep Web (Agents 31-40) - Real breach, paste, DNS, WHOIS, Wayback lookups"""

import asyncio
from argis.investigate.base import BaseAgent, AgentContext, FindingCategory
from argis.breach import check_all as breach_check_all
from argis.mentions import scan_mentions
from argis.utils.wayback import check_wayback
from argis.utils.network import resolve_dns_full, whois_lookup
from argis.recon import dns_enum


class Agent031_DataBreachScanner(BaseAgent):
    def __init__(self):
        super().__init__(31, "DataBreachScanner", FindingCategory.DEEP_WEB,
                         "Check discovered emails against known data breaches")

    async def _run(self, ctx: AgentContext) -> None:
        all_emails = ctx.shared_data.get("discovered_emails", []) + ctx.target.known_emails
        if not all_emails:
            all_emails = [f"{ctx.target.username}@gmail.com"]

        try:
            reports = await breach_check_all(all_emails)
            ctx.shared_data["breach_reports"] = [r for r in reports if r.compromised]
            ctx.shared_data["all_breach_checks"] = reports

            compromised = [r for r in reports if r.compromised]
            if compromised:
                total_breaches = sum(len(r.breaches) for r in compromised)
                worst_classes = set()
                for r in compromised:
                    worst_classes.update(r.worst)
                evidence = []
                for r in compromised:
                    for b in r.breaches:
                        evidence.append(f"{b.name} ({b.date}) — {', '.join(b.data_classes)}")
                self._emit(ctx, f"{len(compromised)} emails compromised in {total_breaches} breaches",
                           f"Data classes exposed: {', '.join(sorted(worst_classes)[:8])}",
                           0.9, evidence=evidence[:15],
                           metadata={"breach_count": total_breaches, "emails_affected": len(compromised)})
            else:
                self._emit(ctx, "Breach check complete — no compromises found",
                           f"Checked {len(all_emails)} emails against HIBP breach database. No records found.",
                           0.7, evidence=[f"Email checked: {e}" for e in all_emails])
        except Exception as e:
            ctx.add_error(self.agent_id, f"Breach API error: {e}")
            self._emit(ctx, "Breach check attempted",
                       f"Breach database query attempted but encountered an error: {e}",
                       0.2, evidence=[f"Error: {e}"])


class Agent032_PasteBinMonitor(BaseAgent):
    def __init__(self):
        super().__init__(32, "PasteBinMonitor", FindingCategory.DEEP_WEB,
                         "Search paste sites for username/email mentions")

    async def _run(self, ctx: AgentContext) -> None:
        emails = ctx.shared_data.get("discovered_emails", []) + ctx.target.known_emails
        try:
            report = await scan_mentions(ctx.target.username, emails if emails else None)
            ctx.shared_data["mention_report"] = report
            mentions = report.mentions
            if mentions:
                self._emit(ctx, f"Found {len(mentions)} mentions on paste/code sites",
                           f"Sources: {', '.join(set(m.source for m in mentions[:8]))}",
                           0.7, evidence=[f"{m.source}: {m.title}" for m in mentions[:10]],
                           urls=[m.url for m in mentions[:10]])
            else:
                dork_count = len(report.dorks)
                self._emit(ctx, "Paste/code search complete — no direct mentions",
                           f"Generated {dork_count} search queries. No public paste results returned.",
                           0.3, evidence=report.dorks[:5])
        except Exception as e:
            self._emit(ctx, "Paste search attempted",
                       f"Paste site search encountered an issue: {e}",
                       0.15)


class Agent033_DarkWebScout(BaseAgent):
    def __init__(self):
        super().__init__(33, "DarkWebScout", FindingCategory.DEEP_WEB,
                         "Assess dark web exposure potential")

    async def _run(self, ctx: AgentContext) -> None:
        breach_data = ctx.shared_data.get("breach_reports", [])
        risk_level = "LOW"
        if breach_data:
            risk_level = "MEDIUM"
            total_breaches = sum(len(r.breaches) for r in breach_data)
            if total_breaches > 3:
                risk_level = "HIGH"

        self._emit(ctx, f"Dark web exposure risk: {risk_level}",
                   f"Risk assessment based on {len(breach_data)} breach records. "
                   f"Dark web scanning requires Tor proxy (--tor flag) and .onion crawler integration.",
                   0.3 if risk_level == "LOW" else 0.6,
                   evidence=[f"Breach data available: {len(breach_data)} records",
                             "Dark web scan requires: pip install argis[all], use --tor flag"])


class Agent034_LeakedCredentialFinder(BaseAgent):
    def __init__(self):
        super().__init__(34, "LeakedCredentialFinder", FindingCategory.DEEP_WEB,
                         "Correlate breach data for credential exposure assessment")

    async def _run(self, ctx: AgentContext) -> None:
        breaches = ctx.shared_data.get("all_breach_checks", [])
        compromised = [r for r in breaches if r.compromised]
        exposed_passwords = 0
        for r in compromised:
            for b in r.breaches:
                if "passwords" in [dc.lower() for dc in b.data_classes]:
                    exposed_passwords += 1

        if exposed_passwords:
            self._emit(ctx, f"Password exposure detected in {exposed_passwords} breaches",
                       "Credentials may be compromised. Change passwords on affected services immediately.",
                       0.9, evidence=[f"Breaches with password exposure: {exposed_passwords}"])
        elif compromised:
            self._emit(ctx, "Email exposed but no password leaks detected",
                       "Emails found in breaches but credential data not confirmed exposed.",
                       0.5)
        else:
            self._emit(ctx, "Credential leak check",
                       "No leaked credentials found for associated emails.",
                       0.2)


class Agent035_ExposedDocumentScanner(BaseAgent):
    def __init__(self):
        super().__init__(35, "ExposedDocumentScanner", FindingCategory.DEEP_WEB,
                         "Generate targeted search queries for exposed documents")

    async def _run(self, ctx: AgentContext) -> None:
        u = ctx.target.username
        dorks = [
            f'site:docs.google.com "{u}"',
            f'site:amazonaws.com "{u}"',
            f'site:blob.core.windows.net "{u}"',
            f'site:dropbox.com "{u}"',
            f'site:pastebin.com "{u}"',
            f'site:github.com "{u}" in:file',
            f'site:notion.site "{u}"',
            f'intitle:"{u}" filetype:pdf',
            f'intitle:"{u}" filetype:xlsx',
        ]
        ctx.shared_data["exposure_dorks"] = dorks
        self._emit(ctx, f"Generated {len(dorks)} document discovery queries",
                   "Google dork queries for exposed document hunting. Requires search API or manual execution.",
                   0.45, evidence=dorks)


class Agent036_CloudStorageDiscovery(BaseAgent):
    def __init__(self):
        super().__init__(36, "CloudStorageDiscovery", FindingCategory.DEEP_WEB,
                         "Check for exposed cloud storage buckets")

    async def _run(self, ctx: AgentContext) -> None:
        u = ctx.target.username
        candidates = [
            f"https://{u}.s3.amazonaws.com",
            f"https://storage.googleapis.com/{u}",
            f"https://{u}.blob.core.windows.net",
            f"https://{u}.dropbox.com",
            f"https://drive.google.com/drive/u/0/{u}",
        ]
        accessible = []
        for url in candidates:
            code, _, _ = await self._fetch(ctx, url, timeout=5.0)
            if code and code < 500:
                accessible.append(f"{url} (HTTP {code})")

        if accessible:
            self._emit(ctx, f"Found {len(accessible)} accessible cloud storage endpoints",
                       "Cloud storage buckets may expose public data",
                       0.6, evidence=accessible)
        else:
            self._emit(ctx, f"Checked {len(candidates)} cloud storage locations",
                       "No publicly accessible cloud storage found via URL enumeration.",
                       0.3, evidence=candidates)


class Agent037_PublicRecordDigger(BaseAgent):
    def __init__(self):
        super().__init__(37, "PublicRecordDigger", FindingCategory.DEEP_WEB,
                         "Aggregate public record search leads")

    async def _run(self, ctx: AgentContext) -> None:
        u = ctx.target.username
        resources = [
            f"https://www.familysearch.org/search/record/results?q={u}",
            f"https://search.ancestry.com/cgi-bin/sse.dll?name={u}",
            f"https://www.whitepages.com/name/{u}",
        ]
        self._emit(ctx, f"Public record resources: {len(resources)} sources",
                   "Government records vary by jurisdiction. These resources may yield results with full name.",
                   0.2, evidence=resources)


class Agent038_CourtRecordFinder(BaseAgent):
    def __init__(self):
        super().__init__(38, "CourtRecordFinder", FindingCategory.DEEP_WEB,
                         "Search for legal record references")

    async def _run(self, ctx: AgentContext) -> None:
        self._emit(ctx, "Court record search",
                   "Legal document discovery requires full legal name and jurisdiction. "
                   "PACER (US federal) and state court databases require registered access.",
                   0.1, evidence=["pacer.uscourts.gov", "case.law"])


class Agent039_DomainWhoisAgent(BaseAgent):
    def __init__(self):
        super().__init__(39, "DomainWhoisAgent", FindingCategory.DEEP_WEB,
                         "Resolve DNS and WHOIS for associated domains")

    async def _run(self, ctx: AgentContext) -> None:
        u = ctx.target.username
        domains_to_check = [f"{u}.com", f"{u}.io", f"{u}.net", f"{u}.org", f"{u}.dev"]
        results = []

        for domain in domains_to_check:
            info = {"domain": domain, "dns": None, "whois": None}
            try:
                dns_result = resolve_dns_full(domain)
                if dns_result and dns_result.records:
                    info["dns"] = [f"{r.type} {r.value}" for r in dns_result.records[:5]]
            except Exception:
                pass
            try:
                whois = whois_lookup(domain)
                if whois:
                    lines = whois.split("\n")[:8]
                    info["whois"] = [l.strip() for l in lines if l.strip()]
            except Exception:
                pass
            results.append(info)

        live_domains = [r for r in results if r["dns"]]
        ctx.shared_data["domain_info"] = results
        if live_domains:
            evidence = []
            for r in live_domains:
                evidence.append(f"{r['domain']}: DNS records present")
                if r.get("whois"):
                    evidence.extend(r["whois"][:3])
            self._emit(ctx, f"{len(live_domains)}/{len(domains_to_check)} domains have DNS records",
                       f"Domains with DNS: {', '.join(r['domain'] for r in live_domains)}",
                       0.75, evidence=evidence[:12])
        else:
            self._emit(ctx, "Domain/DNS check complete",
                       f"None of the {len(domains_to_check)} candidate domains resolve.",
                       0.25, evidence=[f"Checked: {d}" for d in domains_to_check])


class Agent040_WaybackHistorian(BaseAgent):
    def __init__(self):
        super().__init__(40, "WaybackHistorian", FindingCategory.DEEP_WEB,
                         "Archive.org historical snapshot analysis")

    async def _run(self, ctx: AgentContext) -> None:
        u = ctx.target.username
        try:
            result = await check_wayback(u, limit=30)
            ctx.shared_data["wayback_data"] = result
            if result.snapshots:
                earliest = result.first_seen or "N/A"
                latest = result.last_seen or "N/A"
                total = result.total or len(result.snapshots)
                self._emit(ctx, f"Wayback Machine: {total} snapshots ({earliest} to {latest})",
                           f"Historical profile data available for content recovery and change tracking",
                           0.8, evidence=[f"{s.timestamp}: {s.url} (HTTP {s.status_code})" for s in result.snapshots[:10]])
            else:
                self._emit(ctx, "Wayback Machine check complete",
                           f"No archived snapshots found for username '{u}'.",
                           0.2)
        except Exception as e:
            self._emit(ctx, "Wayback Machine query attempted",
                       f"Archive.org query: {e}",
                       0.1)


class DeltaSquad:
    def __init__(self):
        self.agents = [cls() for cls in [
            Agent031_DataBreachScanner, Agent032_PasteBinMonitor,
            Agent033_DarkWebScout, Agent034_LeakedCredentialFinder,
            Agent035_ExposedDocumentScanner, Agent036_CloudStorageDiscovery,
            Agent037_PublicRecordDigger, Agent038_CourtRecordFinder,
            Agent039_DomainWhoisAgent, Agent040_WaybackHistorian,
        ]]

    async def run_all(self, ctx: AgentContext) -> None:
        await asyncio.gather(*[a.investigate(ctx) for a in self.agents])