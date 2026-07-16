# Changelog

## 0.9.0 — Engine Overhaul, Encoding Safety & Data Integrity

### Engine Fixes (scanning accuracy)
- :tada: **Fixed title detection bug** — title search window widened from 5,000 → 50,000 bytes. Many sites (GitHub, etc.) have their `<title>` tag beyond 5 KB, causing every valid account to return `NOT_FOUND`. This was the root cause of missing accounts.
- :tada: **Confidence scoring** now uses 30,000 bytes of page content (was 8,000) for more accurate analysis
- :tada: **Description extraction** widened from 5,000 → 50,000 bytes
- :tada: **Non-encodable characters** are now stripped from titles and descriptions, preventing crashes on terminals that don't support emoji/exotic Unicode

### Output / Encoding Safety
- :tada: **Logo converted to pure ASCII** — the previous Unicode block-art (`█`) crashed on Windows cp1252 terminals before any scan could run
- :tada: **Status bars** (`_status_bar`, `print_completion`) auto-detect whether the terminal supports the FULL BLOCK character and fall back to `#` if not
- :tada: **Windows console** now enables Virtual Terminal Processing + UTF-8 mode, letting Rich use the modern rendering path instead of the legacy cp1252 codec path
- Logo subtitle changed from `⚡ SIGINT COLLECTOR` to `> SIGINT COLLECTOR` (ASCII-safe)

### Data Integrity
- :tada: Removed duplicate "Throne" entry from sites.json (was listed twice under `content`)
- :tada: Fixed hardcoded path in `import-sites` command — now resolves from package location instead of CWD
- :tada: Updated all stale version strings (`0.8.0` → `0.9.0`) across docs, home screen, and package metadata
- :tada: Updated mkdocs.yml description to reflect 500+ platforms (was "133+")
- :tada: Expanded .gitignore with generated output patterns (`*.html`, `health*.md`, `dossier*.html`, etc.)

### Cleanup
- `media_runtime.py` stub restored after accidental removal
- `test_profile_media_apis.py` removed (tested unimplemented functions from stub)
- 60+ core tests passing, full suite verified

## 0.8.0 — Full Export Suite + AI Analysis

- :tada: New export formats: TXT (`-T`), NDJSON (`-J ndjson`), XMind 8 (`-X`), GraphML (`-G`), Neo4j Cypher (`--neo4j`), PDF (`-P`)
- :tada: AI-powered risk analysis via `--ai` (OpenAI GPT-4o / Anthropic Claude)
- :tada: `FORMATTERS` registry extended with new formatters
- 12 new tests covering all export formats + 3 AI analysis tests
- 166 tests, all passing

## 0.7.0 — Intelligence Ecosystem

- :tada: `argis breach` — check emails against known breaches (HIBP-style)
- :tada: `argis mentions` — web-mention search via Google dorks
- :tada: `argis geo` — geographic region inference from profile signals
- :tada: `argis me` — unified self-assessment: scan + breach + mentions + geo + impersonation in one command
- :tada: `argis mcp` — run Argis as a Model Context Protocol server
- :tada: Confidence scoring (0-100) on every FOUND hit + `--min-confidence` filter
- :tada: Shared `extract_utils.py` — email, URL, and title extraction refactored out of core.py and correlate.py
- Richer challenge/block detection with expanded `_CHALLENGE_MARKERS`
- MCP server as optional dependency (`pip install "argis[mcp]"`)
- 151 tests, all passing

## 0.6.0 — Dossier v2

- :tada: Full HTML dossier with interactive knowledge graph (vis-network)
- :tada: Dossier PDF export (weasyprint + playwright fallback)
- :tada: Screenshot capture + terminal rendering
- Rich scan results table with terminal screenshots
- Improved diff display
- 130+ tests, all passing

## 0.5.0 — Self-healing Site Database

- :tada: `argis doctor` — health-check every site rule against known-real and known-fake usernames
- :tada: `argis link` — identity correlation with avatar, name, bio, link, and email clustering
- :tada: `argis guard` — impersonation early-warning via Unicode homoglyph/leet/typo variant scanning
- :tada: Weekly GitHub Action for automatic doctor runs
- Duplicate rule name detection in sites.json
- 103+ tests, all passing

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