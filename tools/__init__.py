"""Bootstrap installed tool entrypoints for repo-style absolute imports."""

from __future__ import annotations

import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TOOLS_DIR.parent
API_DIR = ROOT_DIR / "api"

for _path in (TOOLS_DIR, API_DIR):
    _path_str = str(_path)
    if _path.exists() and _path_str not in sys.path:
        sys.path.insert(0, _path_str)
