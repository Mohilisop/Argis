# Argis

<p align="center">
  <img src="assets/logo.jpeg" alt="Argis logo" width="320"/>
</p>

<p align="center">
  <b>The all-seeing OSINT scanner</b><br>
  Username reconnaissance · port scanning · service detection · OS fingerprinting · geolocation · change tracking
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/>
  <img src="https://img.shields.io/github/actions/workflow/status/Mohilisop/Argis/.github/workflows/ci.yml?branch=main" alt="CI"/>
  <img src="https://img.shields.io/github/license/Mohilisop/argis" alt="License"/>
</p>

Named after **Argus Panoptes**, the hundred-eyed giant of Greek myth — every platform, every port, watched at once.

---

## Features

### Username scanning
- **133+ platforms** — social media, coding, gaming, forums, and more
- **Async** — checks all platforms concurrently via `httpx` + `asyncio`
- **Smart detection** — per-site rules (status code, text match, redirect URL)
- **Category filter** — `--category social,gaming` to narrow the search
- **Exclude platforms** — `--exclude twitter,facebook` to skip specific sites
- **Email extraction** — `--emails` scrapes email addresses from profile pages
- **Retry with backoff** — automatically retries on 429/503/connection errors
- **HTTP/2 support** — `--http2` for multiplexed connections
- **Diff tracking** — `--diff` compares against the last scan to show changes

### Reconnaissance 
| Flag | Purpose |
|------|---------|
| `-pt 22,80,443` | Port scan specific ports |
| `-pt -` | Scan all 65535 ports |
| `-sv` | Service version detection |
| `-os` | OS detection (TTL + banner analysis) |
| `-ag` | Ping sweep / host discovery |
| `-df` | Default scripts (web + banners + DNS + WHOIS + geo) |
| `-ud` | UDP scan |
| `-tr` | Traceroute |
| `-ax` | Aggressive mode (all of the above) |
| `-tm0` to `-tm5` | Timing templates (Paranoid → Insane) |
| `-gl` | IP geolocation |
| `-sc web,banners` | Run specific modules |

### Output
- **Multiple formats** — JSON, CSV, Markdown, HTML (or all at once: `--export json,html`)
- **XML & grepable** — `-ox scan.xml -og scan.grepable`
- **JSON streaming** — `--json-stream` for real-time output
- **Webhook notifications** — Slack / Discord
- **Desktop notifications** — `--notify`
- **Config file** — `~/.argis/config.json` with `--save-config`

### Analysis
- **Compare users** — `compare alice bob` shows shared/unique platforms
- **Wayback Machine** — `wayback user` checks historical profile snapshots
- **Search history** — `search twitter` across all past scans
- **Stats** — aggregate statistics across all users
- **Monitor** — `monitor user` watches for changes over time

### History
- **Per-user history** — stored in `~/.argis/history/<user>.json`
- **Diff engine** — highlights newly registered or deleted profiles
- **Clear history** — `clear-history <user>` to wipe data

---

## Install

```bash
pip install argis
```

Requires Python 3.10+.

### From source

```bash
git clone https://github.com/Mohilisop/argis.git
cd argis
pip install -e ".[dev]"
```

### Linux system deps (optional)

| Feature | Ubuntu/Debian/Kali | Arch |
|---------|-------------------|------|
| Desktop notifications | `sudo apt install libnotify-bin` | `sudo pacman -S libnotify` |
| Tor proxy | `sudo apt install tor` | `sudo pacman -S tor` |

---

## Usage

### Username scanning

```bash
# Basic scan
argis scan johndoe

# Filter by category
argis scan johndoe --category social,coding

# Skip platforms
argis scan johndoe --exclude twitter,facebook

# Only show FOUND results
argis scan johndoe --status FOUND

# Export multiple formats
argis scan johndoe --export json,html

# Show error details
argis scan johndoe --verbose

# Preview platforms that would be scanned
argis scan johndoe --list

# Extract emails
argis scan johndoe --emails

# Compare against last scan
argis scan johndoe --diff

# Batch scan from file
argis scan --file users.txt --export csv

# Route through Tor
argis scan johndoe --tor
```

### Reconnaissance

```bash
# Quick port scan (default ports)
argis recon example.com

# Scan specific ports with service version
argis recon -pt 22,80,443 -sv example.com

# Aggressive scan (all features)
argis recon -ax -gl github.com

# Ping sweep (host discovery)
argis recon -ag 192.168.1.0/24

# Full port scan with fast timing
argis recon -pt - -tm4 10.0.0.1

# OS detection + traceroute
argis recon -tr -os example.com

# Output to XML and text
argis recon -ox scan.xml -on scan.txt example.com

# Run only specific modules
argis recon -sc dns,whois example.com
```

### Other commands

```bash
# Domain info (DNS + WHOIS + port scan + geo)
argis domain example.com

# Geolocate your public IP
argis myip

# Discover live hosts on a subnet
argis discover 192.168.1.0/24

# Compare two usernames
argis compare alice bob

# Historical profile snapshots
argis wayback johndoe

# Search scan history
argis search github

# View aggregate stats
argis stats

# Monitor for changes
argis monitor johndoe --interval 3600
```

---

## Project layout

```
argis/
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── .github/
│   ├── workflows/ci.yml
│   └── ISSUE_TEMPLATE/site_rule.md
├── assets/logo.png
├── src/argis/
│   ├── cli.py            # 13 typer commands
│   ├── core.py            # async username scanning engine
│   ├── diff.py             # history storage + diff computation
│   ├── recon.py            # port scan, OS detection, traceroute
│   ├── sites.json          # 133 platforms + detection rules
│   ├── exceptions.py
│   └── utils/
│       ├── display.py      # Rich terminal UI
│       ├── network.py      # HTTP client, DNS, WHOIS
│       ├── export.py       # JSON/CSV/MD/HTML/XML exporters
│       ├── config.py       # config file management
│       ├── geoip.py        # ipgeolocation.io API client
│       ├── notify.py       # desktop notifications
│       └── wayback.py      # Wayback Machine CDX API
└── tests/
    ├── test_core.py
    ├── test_core_advanced.py
    ├── test_recon.py
    ├── test_diff.py
    ├── test_diff_advanced.py
    ├── test_export.py
    ├── test_geoip.py
    └── test_network.py
```

---

## Tests

```bash
pytest -v    # 103 tests, all passing
```

---

## Adding platforms

Edit `src/argis/sites.json` — each entry needs a `url` template and an `error_type`:

| `error_type` | Meaning |
|-------------|---------|
| `status_code` | Account missing if HTTP status matches `error_criteria` |
| `message` | Account missing if `error_criteria` text appears in page |
| `response_url` | Account missing if final URL matches |

No code changes needed — just add the entry and it's picked up automatically.

---

## Disclaimer

Use responsibly. Only scan usernames or hosts you have authorization to investigate. Respect platform terms of service. Argis performs **reconnaissance only** — it reads HTTP responses, scans ports, and checks DNS. No exploitation.
