#!/usr/bin/env python3
"""De-duplicate sites.json, keeping the higher-quality rule on each collision.

JSON silently keeps the LAST duplicate key, which in argis means lazy
`status_code: 404` copies were overwriting good `message`/`response_url`
detectors. This re-reads the file preserving ALL duplicate pairs, then for
each name keeps the best rule by this preference:

    response_url  >  message  >  status_code (non-404)  >  status_code: 404

Usage:
  python scripts/dedupe_sites.py src/argis/sites.json            # writes in place (+ .bak)
  python scripts/dedupe_sites.py src/argis/sites.json --dry-run  # just report
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def _quality(rule: dict) -> int:
    et = rule.get("error_type")
    ec = rule.get("error_criteria")
    if et == "response_url":
        return 3
    if et == "message":
        return 2
    if et == "status_code":
        try:
            return 1 if int(ec) == 404 else 2
        except (TypeError, ValueError):
            return 0
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    path = Path(args.path)

    pairs: list[tuple[str, dict]] = []

    def hook(items):
        for k, v in items:
            if isinstance(v, dict) and "url" in v:
                pairs.append((k, v))
        return dict(items)

    json.loads(path.read_text("utf-8"), object_pairs_hook=hook)

    grouped: dict[str, list[dict]] = defaultdict(list)
    for name, rule in pairs:
        grouped[name].append(rule)

    winners: dict[str, dict] = {}
    report: list[str] = []
    for name, rules in grouped.items():
        if len(rules) == 1:
            winners[name] = rules[0]
            continue
        best = max(rules, key=_quality)
        winners[name] = best
        kept = f"{best.get('error_type')}:{best.get('error_criteria')}"
        dropped = [f"{r.get('error_type')}:{r.get('error_criteria')}"
                   for r in rules if r is not best]
        report.append(f"  {name}: kept [{kept}] \u00b7 dropped {dropped}")

    print(f"{len(pairs)} rules read \u00b7 {len(winners)} unique \u00b7 "
          f"{len(pairs) - len(winners)} duplicates resolved")
    if report:
        print("resolved collisions (kept the stronger detector):")
        print("\n".join(sorted(report)))

    if args.dry_run:
        print("\n[dry-run] nothing written.")
        return 0

    path.with_suffix(".json.bak").write_text(path.read_text("utf-8"), "utf-8")
    path.write_text(json.dumps(winners, indent=2, ensure_ascii=False) + "\n",
                    "utf-8")
    print(f"\nwrote {len(winners)} unique rules -> {path} (backup: {path}.bak)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
