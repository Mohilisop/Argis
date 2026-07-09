# Output Formats

## Export Formats

Use `--export` with comma-separated formats:

```bash
argis scan johndoe --export json,csv,md,html
```

| Format | Extension | Description |
|--------|-----------|-------------|
| `json` | `.json` | Structured data, machine-readable |
| `csv` | `.csv` | Spreadsheet-friendly, includes emails column |
| `md` | `.md` | Markdown table |
| `html` | `.html` | Dark-themed HTML report with all results |
| `xml` | `.xml` | Nmap-style XML output (recon only) |
| `grepable` | `.gnmap` | Grepable output (recon only) |

## Recon Output Flags

For the `recon` command:

```bash
argis recon example.com -ox scan.xml -og scan.gnmap -oa scan
```

| Flag | Description |
|------|-------------|
| `-on` | Normal text output |
| `-ox` | XML output |
| `-og` | Grepable output |
| `-oa` | All formats |

## JSON Streaming

```bash
argis scan johndoe --json-stream | jq 'select(.status == "FOUND")'
```

## Webhooks

```bash
argis scan johndoe --webhook https://hooks.slack.com/services/...
argis scan johndoe --webhook https://discord.com/api/webhooks/...
```