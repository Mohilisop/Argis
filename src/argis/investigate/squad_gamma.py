"""Squad Gamma - Professional Intel (Agents 21-30) - Real professional data extraction"""

import asyncio
import re
from argis.investigate.base import BaseAgent, AgentContext, FindingCategory


SITES = {
    "github": "https://github.com/{}", "gitlab": "https://gitlab.com/{}",
    "linkedin": "https://linkedin.com/in/{}", "stackoverflow": "https://stackoverflow.com/users/{}",
    "medium": "https://medium.com/@{}", "dev.to": "https://dev.to/{}",
    "keybase": "https://keybase.io/{}", "hackernews": "https://news.ycombinator.com/user?id={}",
}


class Agent021_CareerPathTracker(BaseAgent):
    def __init__(self):
        super().__init__(21, "CareerPathTracker", FindingCategory.PROFESSIONAL,
                         "Reconstruct employment history from professional profiles")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        career_hints = []
        prof_platforms = [p for p in found if p.lower() in ("linkedin", "crunchbase",
                          "wellfound", "angel", "xing", "upwork", "toptal")]
        if prof_platforms:
            career_hints.append(f"Professional platforms: {', '.join(prof_platforms)}")
        for p in found:
            r = results.get(p, {})
            desc = (r.get("description") or "")
            for kw in ["engineer", "developer", "manager", "designer", "founder",
                       "analyst", "scientist", "consultant", "director", "lead"]:
                if kw in desc.lower():
                    career_hints.append(f"{p}: {desc[:100]}")
                    break

        ctx.shared_data["career_hints"] = career_hints
        if career_hints:
            self._emit(ctx, f"Career signals: {len(career_hints)} indicators",
                       f"Employment hints from {len(prof_platforms)} professional platforms",
                       0.55, evidence=career_hints[:8])
        else:
            self._emit(ctx, "Career path tracking",
                       "No career indicators found. LinkedIn or professional profiles needed.",
                       0.1)


class Agent022_EducationVerifier(BaseAgent):
    def __init__(self):
        super().__init__(22, "EducationVerifier", FindingCategory.PROFESSIONAL,
                         "Find educational background from profiles")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        edu_hints = []
        for p in found:
            r = results.get(p, {})
            desc = (r.get("description") or "").lower()
            for kw in ["university", "college", "institute", "school", "b.s.", "m.s.", "phd",
                       "bachelor", "master", "alumni", "student"]:
                if kw in desc:
                    edu_hints.append(f"{p}: {desc[:120]}")
                    break

        ctx.shared_data["education_hints"] = edu_hints
        if edu_hints:
            self._emit(ctx, f"Education references: {len(edu_hints)} signals",
                       "Education background detected in profile data",
                       0.5, evidence=edu_hints)
        else:
            self._emit(ctx, "Education verification",
                       "No education data in scanned profiles. Check LinkedIn or ResearchGate.",
                       0.1)


class Agent023_SkillExtractor(BaseAgent):
    def __init__(self):
        super().__init__(23, "SkillExtractor", FindingCategory.PROFESSIONAL,
                         "Extract professional skills from profile descriptions")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        skill_db = {
            "python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
            "react": "React", "node": "Node.js", "docker": "Docker", "aws": "AWS",
            "kubernetes": "Kubernetes", "sql": "SQL", "machine learning": "Machine Learning",
            "data science": "Data Science", "devops": "DevOps", "rust": "Rust",
            "golang": "Go", "java": "Java", "c++": "C++", "ruby": "Ruby",
            "swift": "Swift", "kotlin": "Kotlin", "tensorflow": "TensorFlow",
            "pytorch": "PyTorch", "blockchain": "Blockchain", "security": "Cybersecurity",
            "cloud": "Cloud Computing", "api": "API Design", "linux": "Linux",
        }
        skills = set()
        for p in found:
            r = results.get(p, {})
            text = f"{r.get('title', '')} {r.get('description', '')} {p}".lower()
            for kw, skill in skill_db.items():
                if kw in text:
                    skills.add(skill)

        ctx.shared_data["detected_skills"] = sorted(skills)
        if skills:
            self._emit(ctx, f"Skills identified: {', '.join(sorted(skills)[:10])}",
                       f"Extracted from {len(found)} platform profiles — {len(skills)} total skills",
                       0.6, evidence=[f"Skill: {s}" for s in sorted(skills)])
        else:
            self._emit(ctx, "Skill extraction",
                       "No technical skills detected. GitHub or coding platform profiles needed.",
                       0.1)


class Agent024_PortfolioDiscovery(BaseAgent):
    def __init__(self):
        super().__init__(24, "PortfolioDiscovery", FindingCategory.PROFESSIONAL,
                         "Locate work portfolios and project hosting")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        portfolios = []
        code_platforms = [p for p in found if p.lower() in
                         ("github", "gitlab", "bitbucket", "codepen", "dev.to", "replit")]
        for p in code_platforms:
            url = results.get(p, {}).get("url", "")
            if url:
                portfolios.append(f"{p}: {url}")

        static_urls = [
            f"https://{ctx.target.username}.github.io",
            f"https://{ctx.target.username}.dev",
            f"https://{ctx.target.username}.portfolio.com",
        ]
        ctx.shared_data["portfolio_urls"] = portfolios + static_urls
        if portfolios:
            self._emit(ctx, f"Found {len(portfolios)} active portfolios/projects",
                       f"Code platforms: {', '.join(code_platforms)}",
                       0.7, evidence=portfolios + static_urls)
        elif code_platforms:
            self._emit(ctx, f"Code platforms: {', '.join(code_platforms)}",
                       "Portfolio URLs available but no project pages resolved",
                       0.4, evidence=static_urls)
        else:
            self._emit(ctx, "Portfolio discovery",
                       "No code platforms found. Run scan with development category.",
                       0.1)


class Agent025_ColleagueNetwork(BaseAgent):
    def __init__(self):
        super().__init__(25, "ColleagueNetwork", FindingCategory.PROFESSIONAL,
                         "Map professional connections from org references")

    async def _run(self, ctx: AgentContext) -> None:
        conn = ctx.shared_data.get("connection_hints", [])
        if conn:
            self._emit(ctx, f"Professional connections: {len(conn)} org references",
                       f"Organizations: {', '.join(conn[:6])}",
                       0.4, evidence=conn)
        else:
            self._emit(ctx, "Colleague network",
                       "Professional connections require LinkedIn/Xing data or mutual follows.",
                       0.1)


class Agent026_PatentResearcher(BaseAgent):
    def __init__(self):
        super().__init__(26, "PatentResearcher", FindingCategory.PROFESSIONAL,
                         "Search patent databases for inventor matches")

    async def _run(self, ctx: AgentContext) -> None:
        self._emit(ctx, "Patent database search",
                   "Patent search requires full legal name. Search Google Patents or USPTO "
                   "with known names for inventor records.",
                   0.1, evidence=["google.com/patents", "uspto.gov/patents"])


class Agent027_ResearchPaperFinder(BaseAgent):
    def __init__(self):
        super().__init__(27, "ResearchPaperFinder", FindingCategory.PROFESSIONAL,
                         "Find academic publications")

    async def _run(self, ctx: AgentContext) -> None:
        found = ctx.shared_data.get("found_platforms", [])
        results = ctx.shared_data.get("scan_results", {})
        academic_platforms = [p for p in found if p.lower() in
                             ("googlescholar", "researchgate", "academia", "orcid",
                              "paperswithcode", "arxiv")]
        if academic_platforms:
            self._emit(ctx, f"Academic presence on {len(academic_platforms)} platforms",
                       f"Academic platforms: {', '.join(academic_platforms)}",
                       0.7, evidence=[f"{p}: {results.get(p, {}).get('url', '')}" for p in academic_platforms])
        else:
            self._emit(ctx, "Academic publication search",
                       "No academic platforms found. Search Google Scholar with real name.",
                       0.1)


class Agent028_CertificationValidator(BaseAgent):
    def __init__(self):
        super().__init__(28, "CertificationValidator", FindingCategory.PROFESSIONAL,
                         "Check for professional certification references")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        certs = set()
        cert_keywords = ["aws certified", "pmp", "cissp", "ceh", "comptia",
                         "google certified", "mcse", "ccna", "cfe", "cfa",
                         "chfi", "oscp", "gcih", "gsoc"]
        for p in found:
            desc = (results.get(p, {}).get("description") or "").lower()
            for cert in cert_keywords:
                if cert in desc:
                    certs.add(cert.upper())

        if certs:
            self._emit(ctx, f"Certifications: {', '.join(sorted(certs))}",
                       "Professional certifications referenced in profile data",
                       0.65, evidence=[f"Cert: {c}" for c in sorted(certs)])
        else:
            self._emit(ctx, "Certification validation",
                       "No certifications found in profile data. LinkedIn certification section needed.",
                       0.1)


class Agent029_ConferenceTracker(BaseAgent):
    def __init__(self):
        super().__init__(29, "ConferenceTracker", FindingCategory.PROFESSIONAL,
                         "Find conference speaking/attendance from profiles")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        events = []
        for p in found:
            desc = (results.get(p, {}).get("description") or "").lower()
            for kw in ["speaker", "talk", "conference", "keynote", "presented",
                       "workshop", "session", "meetup"]:
                if kw in desc:
                    events.append(f"{p}: {desc[:100]}")
                    break

        if events:
            self._emit(ctx, f"Conference/event references: {len(events)} found",
                       "Speaking or attendance at professional events indicated",
                       0.5, evidence=events[:5])
        else:
            self._emit(ctx, "Conference tracking",
                       "No event data found. Speaker listings require deeper profile scraping.",
                       0.1)


class Agent030_CorporateAffiliation(BaseAgent):
    def __init__(self):
        super().__init__(30, "CorporateAffiliation", FindingCategory.PROFESSIONAL,
                         "Map company affiliations from profile data")

    async def _run(self, ctx: AgentContext) -> None:
        results = ctx.shared_data.get("scan_results", {})
        found = ctx.shared_data.get("found_platforms", [])
        orgs = set()
        for p in found:
            desc = (results.get(p, {}).get("description") or "")
            for org in re.findall(r'(?:at|@|works?\s*(?:at|for)|employed\s*(?:by|at))\s+([A-Z][A-Za-z0-9\s&.]+)', desc):
                orgs.add(org.strip().rstrip(". "))
        orgs = {o for o in orgs if len(o) > 2 and len(o) < 60}
        ctx.shared_data["detected_organizations"] = list(orgs)
        if orgs:
            self._emit(ctx, f"Organizations: {', '.join(list(orgs)[:6])}",
                       f"Corporate affiliations detected from {len(orgs)} references",
                       0.6, evidence=[f"Org: {o}" for o in orgs])
        else:
            self._emit(ctx, "Corporate affiliation analysis",
                       "No corporate affiliations found. LinkedIn profile required.",
                       0.1)


class GammaSquad:
    def __init__(self):
        self.agents = [cls() for cls in [
            Agent021_CareerPathTracker, Agent022_EducationVerifier,
            Agent023_SkillExtractor, Agent024_PortfolioDiscovery,
            Agent025_ColleagueNetwork, Agent026_PatentResearcher,
            Agent027_ResearchPaperFinder, Agent028_CertificationValidator,
            Agent029_ConferenceTracker, Agent030_CorporateAffiliation,
        ]]

    async def run_all(self, ctx: AgentContext) -> None:
        await asyncio.gather(*[a.investigate(ctx) for a in self.agents])