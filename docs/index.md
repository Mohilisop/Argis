# Argis

**The all-seeing OSINT scanner.** Hunt down accounts across 133+ platforms and track how a username's footprint changes over time.

<div class="grid cards" markdown>

-   :material-magnify-scan: **Username Scanning**

    ---

    Search 133+ social, coding, gaming, and creative platforms for a username in seconds.

    [:octicons-arrow-right-24: Scan command](commands/scan.md)

-   :material-server: **Nmap-style Recon**

    ---

    Port scanning, service detection, OS fingerprinting, DNS, WHOIS, traceroute, and geolocation.

    [:octicons-arrow-right-24: Recon command](commands/recon.md)

-   :material-history: **Historical Tracking**

    ---

    Track username changes over time with diff monitoring and searchable history.

    [:octicons-arrow-right-24: Monitor command](commands/monitor.md)

-   :material-file-download: **Multiple Outputs**

    ---

    Export to JSON, CSV, HTML, Markdown, XML, grepable format. Slack & Discord webhooks.

    [:octicons-arrow-right-24: Output formats](guides/output-formats.md)

</div>

## Quick Start

```bash
# Install
pip install argis

# Scan a username across all platforms
argis scan johndoe

# Check categories
argis categories

# Scan only coding platforms
argis scan johndoe --category coding

# Re-map a host
argis recon example.com -sv -os -df
```

## Features

- :material-account-search: **133+ Platforms** — social media, coding forums, gaming, creative, professional, and more
- :material-lightning-bolt: **Async Engine** — concurrent checks with HTTP/2 support, retry with backoff
- :material-web: **Nmap-style Recon** — port scan, service version detection, OS detection, UDP scan, traceroute
- :material-dns: **DNS & WHOIS** — resolve records, lookup domain ownership
- :material-earth: **Geolocation** — IP geolocation via ipgeolocation.io
- :material-history: **History & Diff** — track changes to a username's footprint over time
- :material-chart-bell-curve: **Change Monitoring** — continuously watch usernames and report changes
- :material-compare: **Side-by-side Comparison** — compare two usernames to find shared/unique profiles
- :material-web: **Wayback Machine** — historical snapshots of profiles
- :material-file-delivery: **Multiple Outputs** — JSON, CSV, HTML, Markdown, XML, grepable, webhooks
- :material-tune: **Configurable** — config file, environment variables, CLI flags