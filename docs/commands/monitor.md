# monitor

Continuously watch usernames in a loop and report changes.

## Usage

```bash
argis monitor [OPTIONS] [USERNAMES]...
```

## Options

| Option | Description |
|--------|-------------|
| `--file` | File with usernames (one per line) |
| `--interval` | Minutes between scans (default: 60) |
| `--iterations` | Number of scan cycles (default: infinite) |
| `--export` | Export format on changes: `json`, `csv`, `md`, `html` |
| `--webhook` | Webhook URL for change notifications |
| `--quiet` | Suppress output |

## Examples

```bash
argis monitor johndoe
argis monitor johndoe janedoe --interval 30 --iterations 4
argis monitor --file users.txt --webhook https://hooks.slack.com/...
```