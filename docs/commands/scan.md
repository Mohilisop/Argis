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
| `-T`, `--txt` | Export plain text report |
| `-C`, `--csv` | Export CSV report |
| `-H`, `--html` | Export HTML report |
| `-M`, `--md` | Export Markdown report |
| `-X`, `--xmind` | Generate XMind 8 mindmap |
| `-G`, `--graph` | Generate GraphML graph |
| `--neo4j` | Generate Neo4j Cypher import script |
| `-J`, `--json` | JSON type: `simple` or `ndjson` |
| `-P`, `--pdf` | Generate PDF report (weasyprint or playwright) |
| `--ai` | AI-powered risk analysis (needs `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) |
| `--ai-model` | Model for AI analysis (default: `gpt-4o`) |
| `--min-confidence` | Minimum confidence score (0-100) to show |

## Examples

```bash
# Basic scan
argis scan johndoe

# Scan specific categories
argis scan johndoe --category coding,gaming

# Export results
argis scan johndoe --export json,html

# Single-format exports
argis scan johndoe -T report.txt -X mindmap.xmind -P report.pdf

# Graph exports
argis scan johndoe -G graph.graphml --neo4j import.cypher

# AI risk analysis
export OPENAI_API_KEY=sk-...
argis scan johndoe --ai

# Only high-confidence hits
argis scan johndoe --min-confidence 60

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