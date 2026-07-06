"""Serialize scan results to csv, json, or markdown."""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path


def to_json(results: dict[str, dict]) -> str:
    return json.dumps(results, indent=2)


def to_csv(results: dict[str, dict]) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["platform", "status", "url"])
    for name, info in sorted(results.items()):
        writer.writerow([name, info["status"], info["url"]])
    return buffer.getvalue()


def to_markdown(results: dict[str, dict], username: str) -> str:
    lines = [f"# Argis scan results for `@{username}`", "", "| Platform | Status | URL |", "|---|---|---|"]
    for name, info in sorted(results.items()):
        lines.append(f"| {name} | {info['status']} | {info['url']} |")
    return "\n".join(lines) + "\n"


FORMATTERS = {
    "json": lambda results, username: to_json(results),
    "csv": lambda results, username: to_csv(results),
    "markdown": to_markdown,
}


def export_results(results: dict[str, dict], username: str, fmt: str, out_path: Path) -> Path:
    formatter = FORMATTERS.get(fmt)
    if formatter is None:
        raise ValueError(f"Unsupported export format: {fmt}")
    content = formatter(results, username)
    out_path.write_text(content, encoding="utf-8")
    return out_path
