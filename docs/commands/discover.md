# discover

Sweep a subnet to find which hosts respond. TCP-probe based host discovery.

## Usage

```bash
argis discover [OPTIONS] NETWORK
```

## Options

| Option | Description |
|--------|-------------|
| `--timeout` | Probe timeout in seconds (default: 2.0) |
| `--concurrency` | Concurrent probes (default: 50) |

## Examples

```bash
argis discover 192.168.1.0/24
argis discover 10.0.0.0/24 --timeout 1
```