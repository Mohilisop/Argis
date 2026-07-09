# Changelog

## 0.4.2

- **Fix:** `domain` command now strips URL schemes (`https://`, `http://`) before DNS lookup
- **Fix:** Windows cp1252 encoding crash — ASCII logo replaces Unicode block chars

## 0.4.0

- :tada: 133 platforms (up from 84)
- :tada: Nmap-style `recon` command with full scanning
- :tada: Geolocation via ipgeolocation.io
- :tada: Wayback Machine integration
- :tada: 103 tests, all passing
- History tracking with `history`, `search`, `stats`, `compare`
- Change monitoring with `monitor`
- Multiple export formats: JSON, CSV, Markdown, HTML, XML, grepable
- Webhook notifications (Slack & Discord)
- Config file system
- Error categorization (10+ error types)
- UI polish with Rich tables, panels, badges

## 0.3.0

- Async scanning engine
- Site detection rules
- Category filtering
- Retry with exponential backoff
- Email extraction
- Page title/meta extraction

## 0.1.0

- Initial release with basic username scanning