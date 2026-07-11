"""AI-powered analysis of scan results.

Supports OpenAI (gpt-4o, etc.) and Anthropic (Claude) models.
Requires OPENAI_API_KEY or ANTHROPIC_API_KEY env var.
"""

from __future__ import annotations

import json
import os


def analyze(results: dict, username: str, *, model: str = "gpt-4o") -> str:
    """Send scan results to an LLM for analysis. Returns the analysis text."""
    found = {p: r for p, r in results.items() if r.get("status") == "FOUND"}
    prompt = f"""You are a cybersecurity OSINT analyst. Analyze the following scan results for the username @{username}.

Provide:
1. A risk assessment (HIGH / MEDIUM / LOW) with justification
2. Key findings: what's most exposed, what's surprising
3. Cross-linking risks: which accounts can be tied together and how
4. Specific, actionable recommendations ranked by impact

Scan results ({len(found)} accounts found across {len(results)} platforms):
{json.dumps(found, indent=2, default=str)}

Be concise, direct, and specific to THIS person's footprint. No generic advice."""

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key and ("claude" in model.lower() or not os.environ.get("OPENAI_API_KEY")):
        return _call_anthropic(prompt, model, anthropic_key)

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return _call_openai(prompt, model, openai_key)

    return "ERROR: Set OPENAI_API_KEY or ANTHROPIC_API_KEY to use --ai analysis."


def _call_openai(prompt: str, model: str, api_key: str) -> str:
    import httpx
    r = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}],
              "temperature": 0.3, "max_tokens": 2000},
        timeout=60.0,
    )
    if r.status_code != 200:
        return f"OpenAI API error: {r.status_code} {r.text[:200]}"
    return r.json()["choices"][0]["message"]["content"]


def _call_anthropic(prompt: str, model: str, api_key: str) -> str:
    import httpx
    if "claude" not in model.lower():
        model = "claude-sonnet-4-20250514"
    r = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"},
        json={"model": model, "max_tokens": 2000,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=60.0,
    )
    if r.status_code != 200:
        return f"Anthropic API error: {r.status_code} {r.text[:200]}"
    return r.json()["content"][0]["text"]
