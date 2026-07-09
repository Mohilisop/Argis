# Argis

<p align="center">
  <img src="assets/logo.png" alt="Argis logo" width="320"/>
</p>

<p align="center">
  <b>The all-seeing OSINT scanner</b><br>
  Username reconnaissance · port scanning · service detection · OS fingerprinting · geolocation · change tracking
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
- :file_folder: **Multiple outputs** — JSON, CSV, HTML, Markdown, XML, grepable, webhooks
- :gear: **Configurable** — config file, env vars, CLI flags

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

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Search username across 133+ platforms |
| `recon` | Port scan, service detection, OS fingerprinting, DNS, WHOIS, geo |
| `discover` | Sweep a subnet to find live hosts |
| `domain` | DNS resolution, WHOIS, port scan |
| `myip` | Show public IP + geolocation |
| `history` | Show past scan history |
| `clear-history` | Delete scan history |
| `monitor` | Continuously watch username for changes |
| `search` | Search across all history |
| `stats` | Aggregate statistics |
| `compare` | Compare two usernames |
| `wayback` | Wayback Machine snapshots |
| `categories` | List platform categories |

### scan

```bash
argis scan johndoe
argis scan johndoe --category coding,social
argis scan johndoe --export json,html
argis scan --file usernames.txt --export csv
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
pip install argis
```

Requires **Python 3.10+**. Supports Windows, Linux, and macOS.

---

## License

MIT