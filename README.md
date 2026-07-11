# Argis

<p align="center">
  <img src="assets/logo.png" alt="Argis logo" width="320"/>
</p>

<p align="center">
  <b>The all-seeing OSINT scanner</b><br>
  Username reconnaissance · identity correlation · impersonation detection · port scanning · service detection · OS fingerprinting · geolocation · change tracking
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/>
  <img src="https://img.shields.io/github/actions/workflow/status/Mohilisop/argis/.github/workflows/ci.yml?branch=main" alt="CI"/>
  <img src="https://img.shields.io/github/license/Mohilisop/argis" alt="License"/>
</p>

Named after **Argus Panoptes**, the hundred-eyed giant of Greek myth — every platform, every port, watched at once.

---

## Features

- :mag: **133+ platforms** — social, coding, gaming, creative, professional, and more
- :zap: **Async engine** — concurrent scanning with HTTP/2 support
- :computer: **Nmap-style recon** — port scan, service version detection, OS detection, UDP scan, traceroute
- :globe_with_meridians: **DNS & WHOIS** — resolve records, lookup domain ownership
- :earth_americas: **Geolocation** — IP geolocation via ipgeolocation.io
- :clock: **History & diff** — track changes to a username's footprint over time
- :satellite: **Change monitoring** — continuously watch usernames and report changes
- :left_right_arrow: **Side-by-side comparison** — compare two usernames
- :movie_camera: **Wayback Machine** — historical snapshots of profiles
- :file_folder: **Multiple outputs** — JSON, CSV, HTML, Markdown, TXT, NDJSON, XMind, GraphML, Neo4j, PDF, webhooks
- :brain: **AI analysis** — LLM-powered risk assessment via OpenAI or Anthropic
- :gear: **Configurable** — config file, env vars, CLI flags
- :robot: **OCR** — extract usernames from screenshots
- :camera: **Face detection** — detect faces and reverse-search via browser
- :broom: **Self-healing** — auto-verify site rules and flag silent rot
- :link: **Identity correlation** — cluster accounts into real identities vs impersonators
- :shield: **Impersonation guard** — hunt lookalike handles wearing your face
- :lock: **Breach checker** — check if emails were compromised in known breaches
- :speech_balloon: **Web mentions** — Google dork search for username/email mentions
- :earth_asia: **Geo inference** — infer geographic region from profile signals
- :bust_in_silhouette: **Unified threat report** — `argis me` consolidates your entire footprint
- :electric_plug: **MCP server** — connect Argis to any MCP-compatible AI assistant

---

## Quick Start

```bash
pip install argis
argis scan johndoe
```

---

## Documentation

Full docs at **[mohilisop.github.io/argis](https://mohilisop.github.io/argis)**

---

## Intelligence

Every username scanner ever shipped answers one question: _does this handle exist here?_ **Argis Intelligence** answers the questions they never could.

| Command | What it answers | Unique to Argis? |
|---------|----------------|------------------|
| `doctor` | Are my detection rules still correct, or have they silently rotted? | ✅ First to auto-verify |
| `link` | Of everywhere this handle exists, which accounts are the SAME person — and which are impostors? | ✅ First identity resolution |
| `guard` | Is anyone impersonating me on a lookalike handle right now? | ✅ First impersonation early-warning |

All three are **defensive / self-OSINT**: they verify your data, disambiguate accounts that already share a public handle, and surface people impersonating **you**. No deanonymization, no anti-bot bypassing.

### doctor — self-healing site database

`sites.json` rots silently: a platform tweaks its markup or 404 behaviour, a rule breaks, and nobody notices for months. `doctor` re-runs every rule against a **known-real** and a **known-fake** username and flags what's broken.

```bash
argis doctor                                   # health-check every rule
argis doctor --only GitHub,Reddit,Steam        # spot-check a few
argis doctor --report health.md --json health.json --exit-code
```

Ships with a weekly GitHub Action. Also flags **duplicate rule names** in `sites.json` (JSON silently keeps only the last, so earlier ones are dead rules).

### link — identity correlation

Runs a scan, pulls each found profile's avatar, display name, bio, outbound links, and emails, then clusters the accounts into **identity groups**. The biggest cluster is you; anything sharing the handle but scoring below threshold is flagged as a **namesake or impersonator**.

```bash
argis link johndoe
argis link johndoe --threshold 0.7 --category social,media
argis link johndoe --no-avatar
```

Scoring blends avatar perceptual-hash (dHash), name/bio Jaccard similarity, shared links, and shared emails.

### guard — impersonation early-warning

Nobody impersonates you with your _exact_ handle — they register `john_doe`, `j0hndoe`, `johndoe_official`, or the homoglyph `jоhndoe` (Cyrillic o). `guard` generates the confusable space around your handle, scans every variant across all platforms, and scores each registered hit against **your** real profile.

```bash
argis guard johndoe --list                     # preview the variant space
argis guard johndoe --reference https://github.com/johndoe
argis guard johndoe --threshold 0.65 --category social
```

Variant generation covers separators, affixes, digit-leet, Unicode homoglyphs, and fat-finger typos.

---

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Search username across 133+ platforms |
| `scan-image` | OCR a screenshot for usernames/URLs |
| `scan-face` | Detect faces and reverse-search |
| `doctor` | Health-check every site rule and flag rot |
| `link` | Cluster accounts into real identities vs impostors |
| `guard` | Hunt lookalike handles impersonating you |
| `breach` | Check emails for known breaches (HIBP-style) |
| `mentions` | Web-mention search via Google dorks |
| `geo` | Infer geographic region from profile signals |
| `me` | Unified self-assessment: scan + breach + mentions + geo + impersonation |
| `recon` | Port scan, service detection, OS fingerprinting, DNS, WHOIS, geo |
| `discover` | Sweep a subnet to find live hosts |
| `domain` | DNS resolution, WHOIS, port scan |
| `myip` | Show public IP + geolocation |
| `mcp` | Run Argis as an MCP server (Model Context Protocol) |
| `history` | Show past scan history |
| `clear-history` | Delete scan history |
| `monitor` | Continuously watch username for changes |
| `search` | Search across all history |
| `stats` | Aggregate statistics |
| `compare` | Compare two usernames |
| `wayback` | Wayback Machine snapshots |
| `categories` | List platform categories |
| `setup-celebrity-db` | Download celebrity face data for offline matching |

### scan

```bash
argis scan johndoe
argis scan johndoe --category coding,social
argis scan johndoe --site GitHub                # just one platform
argis scan --file usernames.txt --export csv
argis scan johndoe -T report.txt -X mindmap.xmind  # individual format exports
argis scan johndoe -G graph.graphml --neo4j import.cypher  # graph exports
argis scan johndoe -P report.pdf               # PDF report
argis scan johndoe --ai                         # AI-powered risk analysis
argis scan johndoe --min-confidence 60          # only high-confidence hits
```

### scan-image

```bash
argis scan-image screenshot.png
argis scan-image screenshot.png --scan
```

### scan-face

```bash
argis scan-face photo.jpg --search --engine google
argis scan-face photo.jpg --identify --offline
```

### recon

```bash
argis recon example.com
argis recon example.com -sv -os -df -tr
argis recon example.com -ax -pt '*'
```

### domain

```bash
argis domain example.com --whois --geo --scan-ports
```

### monitor

```bash
argis monitor johndoe --interval 30
argis monitor --file users.txt --webhook https://hooks.slack.com/...
```

### wayback

```bash
argis wayback johndoe --limit 5
```

---

## Installation

```bash
pip install argis                     # base install
pip install "argis[intel]"            # + avatar matching for link/guard
pip install "argis[screenshots]"     # + OCR and screenshots
pip install "argis[vision]"          # + face detection
pip install "argis[insightface]"     # + offline face matching
pip install "argis[dev]"            # + test suite
```

Requires **Python 3.10+**. Supports Windows, Linux, and macOS.

---

## License

MIT