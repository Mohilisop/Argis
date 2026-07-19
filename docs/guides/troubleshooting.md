# Troubleshooting

## DNS Lookup Failed

**Error:** `[Errno 11001] getaddrinfo failed`

**Fix:** Make sure you pass a domain, not a URL. `argis domain example.com` works, not `argis domain https://example.com/path`.

## Windows cp1252 Encoding

**Error:** `UnicodeEncodeError: 'charmap' codec can't encode character`

**Fix:** Update to argis 0.4.1+ which uses ASCII-safe `#` characters instead of Unicode block chars.

## No Output / Nothing Found

- The target username may genuinely not exist on any platform
- Try `--verbose` to see per-platform errors
- Check your internet connection
- Some platforms may block automated requests

## Rate Limiting / Blocks

- Use `--retry 0` to disable retries
- Some platforms return 429 (Too Many Requests) — these show as `BLOCKED`
- Use `--tor` or `--proxy` for IP rotation

## Geolocation Returns 423

Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x) cannot be geolocated. Argis detects these early and returns a clear message.

## Install Issues

```bash
# Fresh install
pip install --upgrade argis

# With dev dependencies
pip install "argis[dev]"
```

## Report Issues

Open an issue at [github.com/Mohilisop/Argis/issues](https://github.com/Mohilisop/Argis/issues).