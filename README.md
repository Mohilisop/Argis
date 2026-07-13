# Argis

**The all-seeing OSINT scanner.** Map any username across 500+ platforms with media enrichment, identity correlation, breach checks, impersonation detection, and footprint drift tracking.

Named after **Argus Panoptes**, the hundred-eyed giant of Greek myth: every platform, every port, watched at once.

[github.com/Mohilisop/argis](https://github.com/Mohilisop/argis) · MIT · Python 3.10+ · defensive / self-OSINT only

---

## Features

- :mag: **509 platforms**: social, coding, gaming, creative, professional, and more
- :zap: **Async engine**: concurrent scanning with HTTP/2 support
- :framed_picture: **Media enrichment**: capture real profile photos (GitHub and Instagram via first-party APIs) with an evidence-based classifier that separates true avatars from logos, favicons, and generic Open Graph art
- :bar_chart: **HTML dossier**: risk banner, distribution, identity, correlations, captured media, and a filterable account list
- :repeat: **Echo identity drift**: detect coordinated rebrands, avatar migrations, contact pivots, and account expansion or retreat across saved scans
- :computer: **Nmap-style recon**: port scan, service version detection, OS detection, UDP scan, traceroute
- :globe_with_meridians: **DNS & WHOIS**: resolve records, look up domain ownership
- :earth_americas: **Geolocation**: IP geolocation via ipgeolocation.io
- :clock3: **History & diff**: track changes to a username's footprint over time
- :satellite: **Change monitoring**: continuously watch usernames and report changes
- :left_right_arrow: **Side-by-side comparison**: compare two usernames
- :movie_camera: **Wayback Machine**: historical snapshots of profiles
- :file_folder: **Multiple outputs**: JSON, CSV, HTML, Markdown, TXT, NDJSON, XMind, GraphML, Neo4j, PDF, webhooks
- :brain: **AI analysis**: LLM-powered risk assessment via OpenAI or Anthropic
- :robot: **OCR**: extract usernames from screenshots
- :camera: **Face detection**: detect faces and reverse-search via browser
- :broom: **Self-healing**: auto-verify site rules and flag silent rot
- :link: **Identity correlation**: cluster accounts into real identities vs impersonators
- :shield: **Impersonation guard**: hunt lookalike handles wearing your face
- :lock: **Breach checker**: check if emails were compromised in known breaches
- :speech_balloon: **Web mentions**: search pastes, code, and dorks for a handle
- :bust_in_silhouette: **Unified threat report**: `argis me` consolidates your entire footprint
- :electric_plug: **MCP server**: connect Argis to any MCP-compatible AI assistant

---

## Quick Start

```bash
pip install argis
argis scan johndoe                       # surface every account
argis scan johndoe --dossier report.html # build the full HTML dossier
argis me johndoe                         # full self-assessment
argis echo johndoe                       # track identity drift over time
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
argis media-review johndoe --open          # interactive confidence dashboard
argis media-apply johndoe-media-review.json # save your accept/reject decisions
argis scan johndoe --dossier final.html     # dossier now uses only approved media
```

Each image is classified as `PROFILE_AVATAR`, `PROFILE_BANNER`, `PLATFORM_LOGO`, `GENERIC_THUMBNAIL`, `DEFAULT_AVATAR`, `UNKNOWN_MEDIA`, or `REJECTED`. Only validated profile avatars count toward stats, correlation, and risk.

---

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Search a username across 509 platforms (add `--dossier` for the HTML report) |
| `scan-image` | OCR a screenshot for usernames/URLs |
| `scan-face` | Detect faces and reverse-search |
| `me` | Unified self-assessment: scan + breach + mentions + geo + impersonation |
| `breach` | Check emails for known breaches |
| `mentions` | Search pastes, code, and dorks for a handle |
| `locate` | Infer geographic region from profile signals |
| `link` | Cluster accounts into real identities vs impostors |
| `guard` | Hunt lookalike handles impersonating you |
| `doctor` | Health-check every site rule and flag rot |
| `echo` | Detect coordinated identity drift across saved scans |
| `media-review` | Interactive media confidence dashboard |
| `media-apply` | Save media approvals for future dossiers |
| `media-clear` | Reset saved media decisions |
| `recon` | Port scan, service detection, OS fingerprinting, DNS, WHOIS, geo |
| `discover` | Sweep a subnet to find live hosts |
| `domain` | DNS resolution, WHOIS, port scan |
| `myip` | Show public IP + geolocation |
| `mcp` | Run Argis as an MCP server |
| `history` / `clear-history` | Show or delete saved scan history |
| `monitor` | Continuously watch a username for changes |
| `search` / `stats` | Search or aggregate scan history |
| `compare` | Compare two usernames side by side |
| `wayback` | Wayback Machine snapshots |
| `categories` | List platform categories |
| `setup-celebrity-db` | Download celebrity face data for offline matching |

### scan

```bash
argis scan johndoe
argis scan johndoe --category coding,social
argis scan johndoe --site GitHub                   # just one platform
argis scan --file usernames.txt --export csv
argis scan johndoe --dossier report.html           # full HTML dossier
argis scan johndoe -T report.txt -X mindmap.xmind  # individual formats
argis scan johndoe -G graph.graphml --neo4j import.cypher
argis scan johndoe -P report.pdf                   # PDF report
argis scan johndoe --ai                            # AI risk analysis
argis scan johndoe --min-confidence 60             # only high-confidence hits
```

### echo

```bash
argis echo johndoe
argis echo johndoe --window 24 --min-confidence 70
argis echo johndoe --json -o johndoe-echo.json
```

### recon

```bash
argis recon example.com
argis recon example.com -sv -os -df -tr
argis recon example.com -ax -pt '*'
```

### monitor

```bash
argis monitor johndoe --interval 30
argis monitor --file users.txt --webhook https://hooks.slack.com/...
```

---

## Installation

```bash
pip install argis                     # base install
pip install "argis[intel]"            # + avatar matching for link/guard
pip install "argis[screenshots]"      # + OCR and screenshots
pip install "argis[vision]"           # + face detection
pip install "argis[insightface]"      # + offline face matching
pip install "argis[dev]"              # + test suite
```

Requires **Python 3.10+**. Supports Windows, Linux, and macOS.

---

## License

MIT
