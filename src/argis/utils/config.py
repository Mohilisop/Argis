from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_DEFAULT_CONFIG: dict[str, Any] = {
    "proxy": None,
    "tor": False,
    "timeout": 7.0,
    "concurrency": 30,
    "http2": False,
    "retry": True,
    "export": None,
    "quiet": False,
    "notify": False,
    "geoip_key": None,
    "recon": {
        "timeout": 2.0,
        "concurrency": 100,
        "web": True,
        "banners": True,
        "dns": False,
        "whois": False,
        "udp": False,
    },
    "monitor": {
        "interval": 300,
        "diff": True,
    },
}


def config_dir() -> Path:
    directory = Path.home() / ".argis"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def config_file() -> Path:
    return config_dir() / "config.json"


def load_config() -> dict[str, Any]:
    path = config_file()
    if not path.exists():
        return _DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user_config = json.load(fh)
        merged = _DEFAULT_CONFIG.copy()
        merged.update(user_config)
        return merged
    except (json.JSONDecodeError, OSError):
        return _DEFAULT_CONFIG.copy()


def save_config(config: dict[str, Any]) -> None:
    path = config_file()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)


def update_config(key: str, value: Any) -> dict[str, Any]:
    config = load_config()
    config[key] = value
    save_config(config)
    return config


def reset_config() -> dict[str, Any]:
    save_config(_DEFAULT_CONFIG.copy())
    return _DEFAULT_CONFIG.copy()


def get_config(key: str, default: Any = None) -> Any:
    config = load_config()
    return config.get(key, default)


def init_config() -> None:
    if not config_file().exists():
        save_config(_DEFAULT_CONFIG.copy())
