from __future__ import annotations

import json
from typing import Any


def install_media_capture():
    pass


async def media_runtime(args: Any) -> str:
    return json.dumps({"error": "media_runtime not implemented in this build"}, indent=2)
