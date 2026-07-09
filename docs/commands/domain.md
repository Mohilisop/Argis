# domain

DNS resolution, WHOIS, and optional port scan for a domain.

## Usage

```bash
argis domain [OPTIONS] DOMAIN
```

## Options

| Option | Description |
|--------|-------------|
| `--whois` | Perform WHOIS lookup |
| `--geo` | IP geolocation (requires API key or `ARGIS_GEOIP_KEY`) |
| `--scan-ports` | Scan common ports on resolved IP |
| `--timeout` | Lookup timeout in seconds (default: 3.0) |

## Examples

```bash
# Basic DNS lookup
argis domain example.com

# DNS + WHOIS
argis domain example.com --whois

# Full info
argis domain example.com --whois --geo --scan-ports
```