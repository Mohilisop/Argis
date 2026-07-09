# Configuration

## Config File

Argis reads from `~/.argis/config.json` by default.

### Location

| OS | Path |
|----|------|
| Linux/macOS | `~/.argis/config.json` |
| Windows | `%USERPROFILE%\.argis\config.json` |

### Example

```json
{
  "geo_key": "your_ipgeolocation_api_key",
  "timeout": 10,
  "retry": 2,
  "http2": true,
  "export": ["json", "html"],
  "notify": true
}
```

## Save Current Options

```bash
argis scan johndoe --http2 --retry 3 --save-config
```

## Use Custom Config

```bash
argis scan johndoe --config /path/to/config.json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ARGIS_GEOIP_KEY` | ipgeolocation.io API key |

## Proxies

```bash
argis scan johndoe --proxy http://127.0.0.1:8080
argis scan johndoe --tor
```