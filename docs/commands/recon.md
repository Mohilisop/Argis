# recon

Map open ports and fingerprint web services on a target host. Fully async nmap-style reconnaissance.

## Usage

```bash
argis recon [OPTIONS] TARGET
```

## Scan Types

| Flag | Description |
|------|-------------|
| `-tc`, `--tcp-connect` | TCP connect scan (default) |
| `-ud`, `--udp` | UDP scan on common ports |
| `-sv`, `--service-version` | Service version detection on open ports |
| `-os`, `--os-detection` | Attempt OS detection via TTL and banner analysis |
| `-df`, `--default-scripts` | Run all default scripts (web + banners + DNS + WHOIS + geo) |
| `-ax`, `--aggressive` | Aggressive: `-sv -os -df --traceroute` |
| `-ag`, `--ping-scan` | Alive/host discovery only (skip port scan) |

## Port Specification

| Flag | Description |
|------|-------------|
| `-pt`, `--ports` | Ports to scan (e.g. `22,80,443`). Use `-` or `*` for all 65535 ports |

## Timing

| Flag | Description |
|------|-------------|
| `-tm`, `--timing` | Timing template `0`–`5` (default: 3) |

| Template | Name | Description |
|----------|------|-------------|
| 0 | Paranoid | Serial scan, very slow |
| 1 | Sneaky | Serial scan, slow |
| 2 | Polite | 2 concurrent, moderate |
| 3 | Normal | 10 concurrent (default) |
| 4 | Aggressive | 50 concurrent, fast |
| 5 | Insane | 200 concurrent, may drop probes |

## Other

| Flag | Description |
|------|-------------|
| `-sc`, `--script` | Comma-separated: `web,banners,dns,whois,geo,all` |
| `-tr`, `--traceroute` | Trace network path to target |
| `-on` | Write normal text output to file |
| `-ox` | Write XML output to file |
| `-og` | Write grepable output to file |
| `-oa` | Write all formats to file (base name) |
| `-gl`, `--geolocate` | IP geolocation (requires API key) |

## Examples

```bash
# Simple port scan
argis recon example.com

# Full recon
argis recon example.com -sv -os -df -tr

# Aggressive scan all ports
argis recon example.com -ax -pt '*'

# UDP scan
argis recon example.com -ud

# Timing templates
argis recon example.com -tm 5  # Insane speed
argis recon example.com -tm 0  # Paranoid stealth

# Output to file
argis recon example.com -ox results.xml -og results.gnmap

# Trace route only
argis recon example.com -tr
```