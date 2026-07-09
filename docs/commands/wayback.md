# wayback

Check the Wayback Machine for historical snapshots of a username's profiles.

## Usage

```bash
argis wayback [OPTIONS] USERNAME
```

## Options

| Option | Description |
|--------|-------------|
| `--limit` | Max snapshots per platform (default: 5) |
| `--from` | Start date (YYYYMMDD) |
| `--to` | End date (YYYYMMDD) |

## Example

```bash
argis wayback johndoe --limit 3
argis wayback johndoe --from 20230101 --to 20231231
```