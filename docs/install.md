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

## Verify

```bash
argis --version
```

You should see:

```
Argis v0.4.2
```

!!! tip "Updating"

    ```bash
    pip install --upgrade argis
    ```

## Platform Support

Argis runs on **Windows**, **Linux** (Arch, Kali, Ubuntu), and **macOS** — zero platform-specific code.

## Development Install

```bash
git clone https://github.com/Mohilisop/argis.git
cd argis
python -m venv .venv
.venv\Scripts\activate   # Windows
source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```