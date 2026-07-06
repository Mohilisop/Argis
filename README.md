# Argis 👁️

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
│   ├── exceptions.py
│   ├── sites.json        # target platforms + detection rules
│   └── utils/
│       ├── display.py    # rich UI
│       ├── network.py    # httpx client, UA rotation, proxy/Tor
│       └── export.py      # csv/json/markdown export
└── tests/
```

## Disclaimer

Use responsibly. Only look up usernames you have a legitimate reason to
investigate, and respect the terms of service of the sites you query.
