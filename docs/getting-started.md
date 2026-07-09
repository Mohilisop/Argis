# Getting Started

## Your First Scan

Scan a username across all 133+ platforms:

```bash
argis scan johndoe
```

This runs concurrent checks against every platform and shows results grouped by status.

## Scan Specific Categories

Only scan coding and social platforms:

```bash
argis scan johndoe --category coding,social
```

List available categories:

```bash
argis categories
```

## Limit Results

Show only found profiles:

```bash
argis scan johndoe --status found
```

Show top 5 results:

```bash
argis scan johndoe --status 5
```

## Save Results

Export to multiple formats:

```bash
argis scan johndoe --export json,html
```

## Basic Reconnaissance

Port scan a host:

```bash
argis recon example.com
```

Full recon with service detection, OS detection, and default scripts:

```bash
argis recon example.com -sv -os -df
```

## Domain Info

```bash
argis domain example.com --whois --geo
```

## Next Steps

- Browse all [commands](commands/scan.md)
- Learn about [output formats](guides/output-formats.md)
- Set up [configuration](guides/configuration.md)
- Enable [webhook notifications](guides/webhooks.md)