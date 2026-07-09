# myip

Show your public IP address and optionally geolocate it.

## Usage

```bash
argis myip [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--geo / --no-geo` | Geolocate your public IP (default: enabled) |
| `--geo-key` | ipgeolocation.io API key |
| `--timeout` | Lookup timeout in seconds (default: 5.0) |

## Examples

```bash
argis myip
argis myip --no-geo
argis myip --geo-key YOUR_API_KEY
```