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
| `txt` | `.txt` | Plain text report |
| `ndjson` | `.ndjson` | Newline-delimited JSON (one platform per line) |
| `xmind` | `.xmind` | XMind 8 mindmap (ZIP with content.xml inside) |
| `graphml` | `.graphml` | GraphML XML graph with username as seed node |
| `neo4j` | `.cypher` | Neo4j Cypher CREATE / MATCH statements |
| `pdf` | `.pdf` | PDF report via weasyprint (fallback: playwright) |
| `xml` | `.xml` | Nmap-style XML output (recon only) |
| `grepable` | `.gnmap` | Grepable output (recon only) |

## Individual Format Flags

For `argis scan`, each format also has a dedicated flag that writes directly to a file path:

```bash
argis scan johndoe -T report.txt                   # TXT
argis scan johndoe -C results.csv                  # CSV
argis scan johndoe -H report.html                  # HTML
argis scan johndoe -M summary.md                   # Markdown
argis scan johndoe -X mindmap.xmind                # XMind
argis scan johndoe -G graph.graphml                # GraphML
argis scan johndoe --neo4j import.cypher           # Neo4j
argis scan johndoe -J ndjson                       # JSON type (simple/ndjson)
argis scan johndoe -P report.pdf                   # PDF
```

| Flag | Description |
|------|-------------|
| `-T`, `--txt` | Export plain text report |
| `-C`, `--csv` | Export CSV report |
| `-H`, `--html` | Export HTML report |
| `-M`, `--md` | Export Markdown report |
| `-X`, `--xmind` | Generate XMind 8 mindmap |
| `-G`, `--graph` | Generate GraphML graph |
| `--neo4j` | Generate Neo4j Cypher import script |
| `-J`, `--json` | JSON type: `simple` or `ndjson` |
| `-P`, `--pdf` | Generate PDF report |

## AI Analysis

```bash
export OPENAI_API_KEY=sk-...   # or ANTHROPIC_API_KEY=sk-ant-...
argis scan johndoe --ai        # uses gpt-4o by default
argis scan johndoe --ai --ai-model claude-sonnet-4-20250514
```

The analysis includes:
1. **Risk assessment** (HIGH / MEDIUM / LOW) with justification
2. **Key findings** — what's most exposed, what's surprising
3. **Cross-linking risks** — which accounts can be tied together
4. **Actionable recommendations** ranked by impact

## PDF Requirements

```bash
pip install weasyprint          # primary engine
pip install "argis[pdf]"        # or install playwright fallback
```

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