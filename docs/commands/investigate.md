# Investigate

Deep multi-agent investigation across 50 specialized AI agents organized into 5 squads.

```bash
argis investigate <username>
argis investigate <username> --email user@example.com
argis investigate <username> --alias alt_handle --verbose
argis investigate <username> --html report.html
argis investigate <username> --json report.json -m report.md
```

## How it works

50 agents run in parallel across 5 squads, each specializing in a different intelligence domain:

| Squad | Agents | Focus |
|-------|--------|-------|
| **Alpha** | 1–10 | Core Identity — name resolution, email discovery, phone, geo, age, gender, language, timezone |
| **Beta** | 11–20 | Social Intelligence — social graph, content analysis, engagement, media, influence |
| **Gamma** | 21–30 | Professional Intel — career, education, skills, patents, research, certifications |
| **Delta** | 31–40 | Deep Web — breaches, paste dumps, creds, exposed docs, WHOIS, Wayback, court records |
| **Epsilon** | 41–50 | Specialists — crypto wallets, geo deep dive, image forensics, linguistic/psychological profiling, threat assessment |

## Flags

| Flag | Description |
|------|-------------|
| `--email`, `-e` | Known email(s) to cross-reference against breaches |
| `--alias`, `-a` | Known alias(es) to include in the search |
| `--verbose`, `-v` | Show per-agent findings in the terminal |
| `--output`, `-o` | Write report as JSON |
| `--markdown`, `-m` | Write report as Markdown |
| `--html`, `-h` | Write report as HTML (advanced visual report) |

## Output

The investigation produces a rich report with:

- **Score dashboard** — exposure, risk, profile completeness, intelligence confidence
- **Intelligence summary** — real names, interests, skills, orgs, communities, crypto wallets, personality traits
- **Platform scan results** — which of 508 platforms the username was found on
- **Breach intelligence** — compromised emails, breach names, exposed data classes
- **Domain & DNS info** — resolved domains with DNS record summaries
- **Geolocation signals** — inferred country/region with confidence and evidence
- **Wayback Machine snapshots** — historical profile captures
- **All findings** — every agent's output sorted by confidence

### Example

```bash
argis investigate johndoe --html johndoe-report.html
# Opens a dark-theme dashboard in the browser with all intelligence data
```
