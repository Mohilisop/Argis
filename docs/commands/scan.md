# scan

Search for a target username across all configured platforms.

## Usage

```bash
argis scan [OPTIONS] USERNAME
```

## Options

| Option | Description |
|--------|-------------|
| `--file` | Scan multiple usernames from a file (one per line) |
| `--category` | Comma-separated categories (e.g. `coding,social`) |
| `--exclude` | Comma-separated categories to exclude |
| `--status` | Filter: `found`, `not_found`, `unknown`, `timeout`, `blocked`, or number |
| `--verbose` | Show per-platform error details and summary |
| `--list` | List all platforms without scanning |
| `--export` | Export formats: `json`, `csv`, `md`, `html` |
| `--emails` | Extract emails from found profile pages |
| `--diff` | Show diff compared to last scan |
| `--http2` | Enable HTTP/2 support |
| `--retry` | Max retries per platform (default: 2) |
| `--webhook` | Send results to Slack/Discord webhook URL |
| `--json-stream` | Stream results as JSON lines |
| `--notify` | Send desktop notification when done |
| `--config` | Path to config file |
| `--save-config` | Save current options as defaults |
| `--tor` | Route traffic through Tor |
| `--proxy` | HTTP proxy URL |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--quiet` | Suppress output (useful with --export) |

## Examples

```bash
# Basic scan
argis scan johndoe

# Scan specific categories
argis scan johndoe --category coding,gaming

# Export results
argis scan johndoe --export json,html

# With diff from last scan
argis scan johndoe --diff

# Scan from file
argis scan --file usernames.txt --export csv

# Desktop notification when done
argis scan johndoe --notify

# Extract emails from found profiles
argis scan johndoe --emails

# Stream JSON output
argis scan johndoe --json-stream | jq '.'
```