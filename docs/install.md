# Installation

## Prerequisites

- Python **3.10** or higher

## Install from PyPI

```bash
pip install argis
```

### Optional dependencies

```bash
# Everything needed for development
pip install argis[dev]
```

## Docker

```bash
docker pull ghcr.io/mohilisop/argis:latest
docker run --rm ghcr.io/mohilisop/argis scan username
```

## Verify

```bash
argis --version
```

You should see:

```
Argis v0.9.0
```

!!! tip "Updating"

    ```bash
    pip install --upgrade argis
    ```

## Platform Support

Argis runs on **Windows**, **Linux** (Arch, Kali, Ubuntu), and **macOS** — zero platform-specific code.

## Development Install

```bash
git clone https://github.com/Mohilisop/Argis.git
cd argis
python -m venv .venv
.venv\Scripts\activate   # Windows
source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```