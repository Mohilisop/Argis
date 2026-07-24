import asyncio
import json
import time
from pathlib import Path

from argis.investigate.base import AgentContext, InvestigationTarget
from argis.investigate.squad_alpha import AlphaSquad
from argis.investigate.squad_beta import BetaSquad
from argis.investigate.squad_gamma import GammaSquad
from argis.investigate.squad_delta import DeltaSquad
from argis.investigate.squad_epsilon import EpsilonSquad
from argis.investigate.report import InvestigationReport
from argis.core import ArgisEngine, build_email_map
from argis.normalize import normalize_scan_results
from argis.utils.extract_utils import clean_emails
from argis.utils.network import build_client
from argis.geo_infer import infer_geo


CHECKPOINT_DIR = Path.home() / ".argis" / "checkpoints"


class InvestigationOrchestrator:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.squads = {
            "alpha": AlphaSquad(),
            "beta": BetaSquad(),
            "gamma": GammaSquad(),
            "delta": DeltaSquad(),
            "epsilon": EpsilonSquad(),
        }

    def _checkpoint_path(self, username: str) -> Path:
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        return CHECKPOINT_DIR / f"{username}.json"

    def _build_shared_data(self, ctx: AgentContext, target: InvestigationTarget, eng: ArgisEngine, results: dict) -> None:
        ctx.shared_data["target_username"] = target.username
        sites = eng._filter_sites()
        ctx.shared_data["sites_db"] = sites
        ctx.shared_data["scan_results"] = results

        found = [(p, r) for p, r in results.items() if r.get("status") == "FOUND"]
        found_plats = [p for p, _ in found]
        ctx.shared_data["found_platforms"] = found_plats
        ctx.shared_data["scan_found_count"] = len(found_plats)
        ctx.shared_data["scan_total_count"] = len(results)

        emails = set(target.known_emails)
        for e in build_email_map(results).values():
            for addr in e:
                emails.add(addr)
        clean = clean_emails(list(emails))
        ctx.shared_data["discovered_emails"] = clean

        titles = [r.get("title", "") or "" for _, r in found]
        descs = [r.get("description", "") or "" for _, r in found]
        ctx.shared_data["profile_titles"] = titles
        ctx.shared_data["profile_descriptions"] = descs

        geo_signals = infer_geo(descs, titles, found_plats)
        ctx.shared_data["geo_signals"] = geo_signals

        by_cat: dict[str, list[str]] = {}
        for p in found_plats:
            rules = sites.get(p, {})
            cat = rules.get("category", "uncategorized")
            by_cat.setdefault(cat, []).append(p)
        ctx.shared_data["platforms_by_category"] = by_cat

        ctx.shared_data["unified_profile"] = {
            "username": target.username,
            "platforms_found": len(found_plats),
            "platforms_total": len(results),
            "found_platforms": found_plats,
            "discovered_emails": clean,
            "profile_completeness": min(100, len(found_plats) * 2 + len(clean) * 10),
        }

    def _save_checkpoint(self, username: str, results: dict) -> None:
        path = self._checkpoint_path(username)
        payload = {
            "username": username,
            "timestamp": time.time(),
            "scan_results": results,
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def _load_checkpoint(username: str) -> dict | None:
        path = CHECKPOINT_DIR / f"{username}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("username") != username:
                return None
            return data.get("scan_results")
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _clear_checkpoint(username: str) -> None:
        path = CHECKPOINT_DIR / f"{username}.json"
        if path.exists():
            path.unlink()

    async def investigate(self, target: InvestigationTarget, *, resume: bool = False) -> AgentContext:
        async with build_client(timeout=self.timeout, http2=True) as client:
            ctx = AgentContext(target=target, client=client)

            if not target.known_emails:
                target.known_emails.append(f"{target.username}@gmail.com")
            if not target.known_domains and target.username.count(".") > 0:
                target.known_domains.append(target.username)

            eng = ArgisEngine(target.username, timeout=self.timeout)

            if resume:
                saved = self._load_checkpoint(target.username)
                if saved is not None:
                    console.print("[dim]Resuming from checkpoint (scan results already cached)[/dim]")
                    results = saved
                else:
                    console.print("[yellow]No checkpoint found — running full scan[/yellow]")
                    results = await self._scan_phase(eng)
            else:
                results = await self._scan_phase(eng)

            self._build_shared_data(ctx, target, eng, results)

            console.print(f"[green]Scan complete: {ctx.shared_data['scan_found_count']} found / {ctx.shared_data['scan_total_count']} total[/green]")

            start = time.time()
            async with asyncio.TaskGroup() as tg:
                for squad_name, squad in self.squads.items():
                    tg.create_task(self._run_squad(squad_name, squad, ctx))
            elapsed = time.time() - start

            self._clear_checkpoint(target.username)

            findings = ctx.get_findings()
            ctx.shared_data["investigation_metadata"] = {
                "duration_seconds": round(elapsed, 2),
                "scan_duration": 0,
                "squads_executed": list(self.squads.keys()),
                "total_agents": 50,
                "total_findings": len(findings),
            }
            return ctx

    async def _scan_phase(self, eng: ArgisEngine) -> dict:
        console.print("[dim]Running platform scan across all 500+ sites...[/dim]")
        results = await eng.run_scan(quiet=True)
        self._save_checkpoint(eng.username, results)
        return results

    async def _run_squad(self, name: str, squad, ctx: AgentContext) -> None:
        try:
            await squad.run_all(ctx)
        except Exception as e:
            ctx.add_error(0, f"Squad {name} failed: {e}")

    def generate_report(self, ctx: AgentContext) -> InvestigationReport:
        return InvestigationReport(ctx)

    def investigate_sync(self, target: InvestigationTarget, *, resume: bool = False) -> AgentContext:
        return asyncio.run(self.investigate(target, resume=resume))


from argis.utils.display import console
