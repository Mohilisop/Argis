# Argis 👁️

<p align="center">
  <img src="assets/logo.jpeg" alt="Argis logo" width="220"/>
</p>

**The all-seeing username scanner.**

Argis hunts down a username across dozens of platforms concurrently, tells
you where it's registered, and — unlike most tools in this space — tracks
how that footprint *changes* over time.

Named after Argus, the hundred-eyed giant of Greek myth: one scan, every
platform, watched at once.

## Features

- **Async everything.** Built on `httpx` + `asyncio`; scans 80+ sites in
  parallel instead of one at a time.
- **Diff engine.** `--diff` compares the current scan against your last
  saved run and shows exactly what got registered or deleted.
- **False-positive resistant.** Detection rules per site (status code,
  page-text match, or redirect-URL match) instead of blindly trusting a
  200 OK.
- **Pretty terminal UI.** Live progress bar and color-coded results via
  `rich`.
- **Exportable.** `--export csv|json|markdown` for piping into other tools.
- **Proxy / Tor support.** Route scans through a proxy or local Tor.
- **Attack-surface recon.** `argis recon` maps open ports on a host,
  fingerprints web services (status, `Server` header, page title), and
  reads unprompted service banners (SSH/FTP/SMTP/etc.) — information
  gathering only, no exploitation.
- **Host discovery.** `argis discover <cidr>` sweeps a subnet (capped at
  256 hosts) to find which hosts respond, via TCP probes rather than
  raw ICMP.

## Install

```bash
pip install argis
```

Requires Python 3.10+.

For development (editable install from source):

```bash
git clone https://github.com/Mohilisop/argis.git
cd argis
pip install -e .
```

## Usage

```bash
# Basic scan
argis scan john_doe

# Scan and compare against the last saved run
argis scan john_doe --diff

# Don't save this run to history
argis scan john_doe --no-save

# Export results
argis scan john_doe --export markdown -o john_doe_report.md

# Route through Tor
argis scan john_doe --tor

# View past scans
argis history john_doe

# Wipe saved history
argis clear-history john_doe

# Recon a host: scan common ports + fingerprint web services
argis recon example.com

# Recon with a custom port list, no web fingerprinting
argis recon 10.0.0.5 --ports 22,80,443,3306 --no-web

# Export recon results
argis recon example.com --export json -o example_recon.json

# Recon without service banners
argis recon example.com --no-banners

# Discover live hosts on a local subnet (max 256 hosts)
argis discover 192.168.1.0/24

# Discover with custom probe ports
argis discover 10.0.0.0/28 --ports 22,80,443,3389
```

## How detection works

Each entry in `src/argis/sites.json` defines a URL template plus a rule for
recognizing a "not found" response:

| `error_type`   | Meaning                                                          |
|----------------|-------------------------------------------------------------------|
| `status_code`  | Account doesn't exist if the response status matches `error_criteria` |
| `message`      | Account doesn't exist if `error_criteria` text appears in the HTML |
| `response_url` | Account doesn't exist if the final (post-redirect) URL matches    |

Add your own targets by editing `sites.json` — no code changes required.

## History storage

Scan history is stored per-username as JSON at
`~/.argis/history/<username>.json`. Each file holds a bounded list of past
snapshots (newest last), which is what `--diff` and `argis history` read
from.

## Project layout

```
argis/
├── pyproject.toml
├── src/argis/
│   ├── cli.py          # typer commands
│   ├── core.py          # async scanning engine
│   ├── diff.py           # history storage + diff computation
│   ├── recon.py          # async port scan + web fingerprinting
│   ├── exceptions.py
│   ├── sites.json        # target platforms + detection rules
│   └── utils/
│       ├── display.py    # rich UI
│       ├── network.py    # httpx client, UA rotation, proxy/Tor
│       └── export.py      # csv/json/markdown export
└── tests/
```

## Disclaimer

Use responsibly. Only look up usernames or scan hosts you have a
legitimate reason to investigate — for `recon`, that means explicit
authorization to scan the target. Respect the terms of service of the
sites you query. Argis performs reconnaissance only: it reports what it
finds (open ports, HTTP responses) and does not attempt to identify or
exploit vulnerabilities.
