# Argis

[![PyPI version](https://img.shields.io/pypi/v/argis?color=ea7233)](https://pypi.org/project/argis/)
[![Python versions](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/argis/)
[![License](https://img.shields.io/github/license/Mohilisop/argis)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-22%20suites-brightgreen)](#)
[![GitHub stars](https://img.shields.io/github/stars/Mohilisop/argis?style=flat&color=gold)](https://github.com/Mohilisop/argis)

**The all-seeing OSINT scanner.** Map any username across 500+ platforms with media enrichment, identity correlation, breach checks, impersonation detection, and footprint drift tracking.

Named after **Argus Panoptes**, the hundred-eyed giant of Greek myth: every platform, every port, watched at once.

---

> **What makes Argis different?**
>
> Sherlock and Maigret answer _does this handle exist here?_ Argis answers everything after that.
> It correlates identities, detects impersonators, tracks drift over time, auto-heals its own rules, does Nmap-style recon, captures profile photos, and exports to HTML/PDF/Neo4j/XMind.
> **One tool. An entire OSINT pipeline.**

---

## Quick comparison

| Feature | Argis | Sherlock | Maigret |
|---------|-------|----------|---------|
| Platforms scanned | **509** | ~400 | ~350 |
| Identity correlation (link) | ✅ | ❌ | ❌ |
| Impersonation detection (guard) | ✅ | ❌ | ❌ |
| Identity drift tracking (echo) | ✅ | ❌ | ❌ |
| Self-healing site rules (doctor) | ✅ | ❌ | ❌ |
| HTML / PDF / XMind / Neo4j exports | ✅ | ❌ | ❌ |
| Media enrichment + avatar classifier | ✅ | ❌ | ❌ |
| Nmap-style recon (ports, DNS, WHOIS) | ✅ | ❌ | ❌ |
| OCR from screenshots | ✅ | ❌ | ❌ |
| Face detection + reverse search | ✅ | ❌ | ❌ |
| Breach checking | ✅ | ❌ | ❌ |
| Web mentions / dork search | ✅ | ❌ | ❌ |
| Change monitoring | ✅ | ❌ | ❌ |
| LLM risk analysis | ✅ | ❌ | ❌ |
| MCP server (AI integration) | ✅ | ❌ | ❌ |
| Web browser UI | ✅ | ❌ | ❌ |
| Docker support | ✅ | ✅ | ✅ |

---

## Demo

![Argis scan demo](assets/demo.gif)

> *`argis scan johndoe` in action — 500+ platforms, async, with live streaming results.*

(Replace `assets/demo.gif` with a screen recording of a real scan — tools like [Terminalizer](https://github.com/faressoft/terminalizer) or [asciinema](https://asciinema.org) work great.)

---

## Use Cases

### Personal security audit
Run `argis me you` to see everywhere your handle exists, check for breached emails, impersonators, and generate a privacy risk score with a ranked shrink plan.

### Continuous monitoring
`argis monitor johndoe --interval 86400 --webhook https://hooks.slack.com/...` watches a username daily and alerts you on any change.

### SOC investigation
Scan a suspect handle, pipe results to Neo4j, correlate with other tools via the MCP server, and generate a PDF report for case documentation.

### Brand impersonation hunting
`argis guard yourbrand` generates the entire homoglyph/typo-squat space around your handle, scans every variant, and flags lookalike accounts wearing your logo.

### Open-source intelligence gathering
Resolve a handle's identity groups, find outbound links, emails, and geo-hints — then pivot from a single username to a full graph of connected accounts.

### Reconnaissance
`argis recon example.com` runs Nmap-style port scanning, service detection, DNS resolution, WHOIS lookups, and geolocation from a single CLI.

---

## Quick Start

```bash
pip install argis
argis --version                          # verify installation (should print 0.9.0)
argis scan johndoe                       # surface every account
argis scan johndoe --dossier report.html # build the full HTML dossier
argis scan johndoe -P report.pdf         # PDF report
argis me johndoe                         # full self-assessment
argis echo johndoe                       # track identity drift over time
argis web                                # launch the browser UI
```

---

## Documentation

Full docs at **[mohilisop.github.io/argis](https://mohilisop.github.io/argis)**

---

## Features

- :mag: **509 platforms**: social, coding, gaming, creative, professional, and more
- :zap: **Async engine**: concurrent scanning with HTTP/2 support, retry with backoff
- :framed_picture: **Media enrichment**: capture real profile photos (GitHub and Instagram via first-party APIs) with an evidence-based classifier that separates true avatars from logos, favicons, and generic Open Graph art
- :bar_chart: **HTML dossier**: risk banner, distribution, identity, correlations, captured media, and a filterable account list; also PDF, TXT, CSV, Markdown, XMind, GraphML, Neo4j exports
- :repeat: **Echo identity drift**: detect coordinated rebrands, avatar migrations, contact pivots, and account expansion or retreat across saved scans
- :computer: **Nmap-style recon**: port scan, service version detection, OS detection, UDP scan, traceroute, host discovery
- :globe_with_meridians: **DNS & WHOIS**: resolve records, look up domain ownership
- :earth_americas: **Geolocation**: IP geolocation via ipgeolocation.io
- :clock3: **History & diff**: track changes to a username's footprint over time
- :satellite: **Change monitoring**: continuously watch usernames and report changes
- :left_right_arrow: **Side-by-side comparison**: compare two usernames
- :movie_camera: **Wayback Machine**: historical snapshots of profiles
- :file_folder: **Multiple outputs**: JSON, CSV, HTML, Markdown, TXT, NDJSON, XMind, GraphML, Neo4j, PDF, webhooks (Slack / Discord)
- :brain: **AI analysis**: LLM-powered risk assessment via OpenAI or Anthropic
- :robot: **OCR**: extract usernames from screenshots, auto-scan found handles
- :camera: **Face detection**: detect faces and reverse-search via multiple engines (Google, TinEye, Bing, Yandex, SauceNAO, IQDB, ImgOps); offline DeepFace lookalike matching
- :broom: **Self-healing**: auto-verify site rules and flag silent rot
- :link: **Identity correlation**: cluster accounts into real identities vs impersonators
- :shield: **Impersonation guard**: hunt lookalike handles wearing your face
- :lock: **Breach checker**: check if emails were compromised in known breaches
- :speech_balloon: **Web mentions**: search pastes, code, and dorks for a handle
- :bust_in_silhouette: **Unified threat report**: `argis me` consolidates your entire footprint
- :electric_plug: **MCP server**: connect Argis to any MCP-compatible AI assistant
- :globe_with_meridians: **Web UI**: browser mode with live streaming results, category-grouped cards, inline dossier
- :camera_flash: **Screenshots**: capture profile page screenshots via Playwright, render as ANSI art in terminal
- :desktop: **Desktop notifications**: push notifications on scan completion

---

## Intelligence

Every username scanner ever shipped answers one question: _does this handle exist here?_ **Argis Intelligence** answers the questions they never could.

| Command | What it answers | Unique to Argis? |
|---------|----------------|------------------|
| `doctor` | Are my detection rules still correct, or have they silently rotted? | ✅ First to auto-verify |
| `link` | Of everywhere this handle exists, which accounts are the SAME person, and which are impostors? | ✅ First identity resolution |
| `guard` | Is anyone impersonating me on a lookalike handle right now? | ✅ First impersonation early-warning |
| `echo` | Did this identity rebrand, migrate avatars, or retreat across platforms together? | ✅ Coordinated identity drift |

All four are **defensive / self-OSINT**: they verify your data, disambiguate accounts that already share a public handle, track changes in saved public observations, and surface people impersonating **you**. No deanonymization, no anti-bot bypassing.

### doctor: self-healing site database

`sites.json` rots silently: a platform tweaks its markup or 404 behaviour, a rule breaks, and nobody notices for months. `doctor` re-runs every rule against a **known-real** and a **known-fake** username and flags what's broken.

```bash
argis doctor                                   # health-check every rule
argis doctor --only GitHub,Reddit,Steam        # spot-check a few
argis doctor --report health.md --json health.json --exit-code
```

Ships with a weekly GitHub Action. Also flags **duplicate rule names** in `sites.json`.

### link: identity correlation

Runs a scan, pulls each found profile's avatar, display name, bio, outbound links, and emails, then clusters the accounts into **identity groups**. The biggest cluster is you; anything sharing the handle but scoring below threshold is flagged as a **namesake or impersonator**.

```bash
argis link johndoe
argis link johndoe --threshold 0.7 --category social,media
argis link johndoe --no-avatar
```

Scoring blends avatar perceptual-hash (dHash), name/bio similarity, shared links, and shared emails.

### guard: impersonation early-warning

Nobody impersonates you with your _exact_ handle: they register `john_doe`, `j0hndoe`, `johndoe_official`, or the homoglyph `jоhndoe` (Cyrillic o). `guard` generates the confusable space around your handle, scans every variant, and scores each hit against **your** real profile.

```bash
argis guard johndoe --list                     # preview the variant space
argis guard johndoe --reference https://github.com/johndoe
argis guard johndoe --threshold 0.65 --category social
```

### echo: coordinated identity drift

A normal diff compares two scans. `echo` analyzes the full saved history and groups changes that happened in the same window, surfacing rebrands, avatar migrations, contact pivots, and multi-platform account expansion or retreat.

```bash
argis scan johndoe        # baseline, then scan again later
argis echo johndoe
argis echo johndoe --window 24 --min-confidence 70
argis echo johndoe --json -o johndoe-echo.json
```

Reports an identity stability score, identity epochs, event confidence, affected platforms, and full before/after evidence in JSON.

---

## Media pipeline

Argis captures profile photos and classifies each image so the dossier shows real avatars, not platform chrome.

```bash
argis scan johndoe --dossier report.html   # dossier with captured media
argis media-review johndoe                 # interactive confidence dashboard (opens browser)
argis media-apply johndoe-media-review.json # save your accept/reject decisions
argis scan johndoe --dossier final.html     # dossier now uses only approved media
argis media-clear                           # reset all decisions to automatic
```

Each image is classified as `PROFILE_AVATAR`, `PROFILE_BANNER`, `PLATFORM_LOGO`, `GENERIC_THUMBNAIL`, `DEFAULT_AVATAR`, `UNKNOWN_MEDIA`, or `REJECTED`. Only validated profile avatars count toward stats, correlation, and risk.

---

## Commands

### SURVEILLANCE

| Command | Description |
|---------|-------------|
| `scan` | Search a username across 509 platforms (add `--dossier` for the HTML report) |
| `scan-image` | OCR a screenshot for usernames/URLs |
| `scan-face` | Detect faces and reverse-search across multiple engines |
| `setup-celebrity-db` | Download celebrity face data for offline DeepFace matching |

### INTELLIGENCE

| Command | Description |
|---------|-------------|
| `me` | Unified self-assessment: scan + breach + mentions + geo + impersonation |
| `breach` | Check emails for known breaches |
| `mentions` | Search pastes, code, and dorks for a handle |
| `locate` | Infer geographic region from profile signals |
| `link` | Cluster accounts into real identities vs impostors |
| `guard` | Hunt lookalike handles impersonating you |
| `doctor` | Health-check every site rule and flag rot |

### RECONNAISSANCE

| Command | Description |
|---------|-------------|
| `recon` | Port scan, service detection, OS fingerprinting, DNS, WHOIS, geo |
| `discover` | Sweep a subnet to find live hosts |
| `domain` | DNS resolution, WHOIS, port scan |
| `myip` | Show public IP + geolocation |

### TRACKING

| Command | Description |
|---------|-------------|
| `history` | Show past scan timestamps and found-profile counts |
| `clear-history` | Delete saved scan history for a username |
| `monitor` | Continuously watch a username for changes |
| `echo` | Detect coordinated identity drift across saved scans |

### ANALYSIS

| Command | Description |
|---------|-------------|
| `exposure` | Privacy risk score (0-100), grade (A-F), ranked shrink plan |
| `timeline` | Chronological timeline of when accounts were created |
| `graph` | Interactive pivot graph from a seed handle |
| `compare` | Compare two usernames side by side |
| `wayback` | Wayback Machine snapshots of profiles |
| `media-review` | Interactive media confidence dashboard |
| `media-apply` | Save media approvals for future dossiers |
| `media-clear` | Reset saved media decisions |

### UTILITIES

| Command | Description |
|---------|-------------|
| `web` | Launch the local Argis web UI (browser mode) |
| `mcp` | Run Argis as an MCP server |
| `search` | Full-text search across scan history |
| `stats` | Aggregate scan statistics across tracked users |
| `categories` | List all platform categories with counts |
| `import-sites` | Import Sherlock/Maigret site databases |

---

### scan

```bash
argis scan johndoe                           # basic scan
argis scan johndoe --category coding,social  # filter by category
argis scan johndoe --site GitHub             # just one platform
argis scan johndoe --exclude Facebook,Twitter # skip specific platforms
argis scan johndoe --status FOUND            # show found only
argis scan johndoe --min-confidence 60       # only high-confidence hits
argis scan --file usernames.txt --export csv # batch scan
argis scan johndoe --diff                    # compare vs last scan
argis scan johndoe --emails                  # extract emails
argis scan johndoe --notify                  # desktop notification
argis scan johndoe --proxy socks5://127.0.0.1:9050
argis scan johndoe --tor --timeout 15 --concurrency 10
argis scan johndoe --http2                   # HTTP/2 multiplexing
argis scan johndoe --retry --no-retry        # control retry behaviour
argis scan johndoe --json-stream             # JSON lines output
argis scan johndoe --screenshots             # capture profile page screenshots
argis scan johndoe --screenshots --show      # render in terminal
argis scan johndoe --list                    # list platforms to scan (dry)
argis scan johndoe --dossier report.html     # full HTML dossier
argis scan johndoe -P report.pdf             # PDF report
argis scan johndoe -T report.txt             # TXT report
argis scan johndoe -C report.csv             # CSV report
argis scan johndoe -H report.html            # HTML report
argis scan johndoe -M report.md              # Markdown report
argis scan johndoe -X report.xmind           # XMind mindmap
argis scan johndoe -G graph.graphml          # GraphML export
argis scan johndoe --neo4j import.cypher     # Neo4j import script
argis scan johndoe -J ndjson                 # NDJSON export
argis scan johndoe --ai                      # AI-powered risk analysis
argis scan johndoe --ai-model claude-3-opus  # custom AI model
argis scan johndoe --webhook https://discord.com/api/webhooks/...
```

### scan-image

```bash
argis scan-image screenshot.png              # OCR for usernames/URLs
argis scan-image screenshot.png --scan       # auto-scan extracted handles
```

### scan-face

```bash
argis scan-face photo.jpg                          # detect faces
argis scan-face photo.jpg --search                 # open reverse search in browser
argis scan-face photo.jpg --search --engine tineye # pick search engine
argis scan-face photo.jpg --identify               # auto-identify + scan
argis scan-face photo.jpg --identify --offline     # DeepFace offline only
argis scan-face photo.jpg --crop                   # save face crops
```

### setup-celebrity-db

```bash
argis setup-celebrity-db                     # download reference images
argis setup-celebrity-db --force             # redownload if cached
```

### me

```bash
argis me johndoe                             # full assessment
argis me johndoe --skip-impersonation        # skip lookalike scan
argis me johndoe --max-variants 30
```

### echo

```bash
argis echo johndoe
argis echo johndoe --window 24 --min-confidence 70
argis echo johndoe --json -o johndoe-echo.json
```

### recon

```bash
argis recon example.com                      # basic scan
argis recon example.com -sv -os -df -tr      # version + OS + scripts + traceroute
argis recon example.com -ax -pt '*'          # aggressive, all ports
argis recon example.com -gl                  # geolocation
argis recon -ag 192.168.1.0/24               # ping sweep
argis recon -ud example.com                  # UDP scan
argis recon -ox scan.xml -on scan.txt example.com
```

### monitor

```bash
argis monitor johndoe --interval 30          # check every 30 seconds
argis monitor --file users.txt --webhook https://hooks.slack.com/...
```

### web

```bash
argis web                                    # launch on http://127.0.0.1:8000
argis web --host 0.0.0.0 --port 8080
```

### mcp

```bash
argis mcp                                    # stdio (Claude Desktop / Claude Code)
argis mcp --transport sse --port 8080        # SSE (web clients)
```

---

## Installation

```bash
pip install argis                          # base install
pip install "argis[web]"                   # + web UI (uvicorn)
pip install "argis[intel]"                 # + avatar matching for link/guard
pip install "argis[screenshots]"           # + OCR and screenshots
pip install "argis[vision]"                # + face detection
pip install "argis[insightface]"           # + offline DeepFace matching
pip install "argis[render]"                # + headless browser for JS-gated profiles
pip install "argis[mcp]"                   # + MCP server
pip install "argis[pdf]"                   # + PDF generation
pip install "argis[dev]"                   # + test suite
pip install "argis[all]"                   # everything
```

Requires **Python 3.10+**. Supports Windows, Linux, and macOS.

```bash
argis --version    # verify installation — should print the current version immediately
```

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Mohilisop/argis&type=Date)](https://star-history.com/#Mohilisop/argis&Date)

*Star history chart will populate as the repository gains traction.*

---

## Security

Argis is designed for **defensive / self-OSINT only**. If you discover a security vulnerability, please refer to the [security policy](.github/SECURITY.md) or contact the maintainer directly.

See [`SECURITY.md`](SECURITY.md) and [`security.txt`](.well-known/security.txt) for responsible disclosure guidelines.

---

## License

MIT
